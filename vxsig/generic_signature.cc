// Copyright 2011-2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "vxsig/generic_signature.h"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <string>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/internal/endian.h"
#include "absl/container/flat_hash_set.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "vxsig/common_subsequence.h"
#include "vxsig/subsequence_regex.h"

namespace security::vxsig {
namespace {

// A byte with extra information. This is used to differentiate between regular
// instruction bytes and signature wildcards. It also helps to keep the
// association with basic block weights used for weighted signature trimming.
struct ByteWithExtra {
  uint8_t value;  // The actual raw byte value
  enum { kRegularByte, kWildcard, kSingleWildcard } type;
  int weight;  // See MatchedBasicBlock and RawSignature::Piece::weight.
  // Keep the association with the disassembly.
  const MatchedInstruction* origin;
};

bool operator==(const ByteWithExtra& lhs, const ByteWithExtra& rhs) {
  // Intentionally ignore the weight.
  return lhs.value == rhs.value && lhs.type == rhs.type;
}

// Marked as live to avoid potential later surprises.
ABSL_ATTRIBUTE_UNUSED bool operator!=(const ByteWithExtra& lhs,
                                      const ByteWithExtra& rhs) {
  return !(lhs == rhs);
}

constexpr ByteWithExtra kWildcardByte = {
    /*value=*/0, ByteWithExtra::kWildcard, /*weight=*/0};

using ByteWithExtraString = std::vector<ByteWithExtra>;
using ByteWithExtraStringBackInserter =
    std::back_insert_iterator<ByteWithExtraString>;

}  // namespace

int GetSignatureSize(const Signature& signature) {
  int size = 0;
  for (const auto& piece : signature.raw_signature().piece()) {
    size += piece.bytes().size();
  }
  return size;
}

RawSignature ToRawSignatureProto(const ByteWithExtraString& regex) {
  // Convert to Protobuf based signature.
  RawSignature signature_regex;
  auto* cur_piece = signature_regex.add_piece();
  bool add_new_piece = false;
  const MatchedInstruction* last_instruction = nullptr;
  int i = 0;
  for (const auto& byte_with_extra : regex) {
    if (byte_with_extra.type != ByteWithExtra::kWildcard) {
      if (add_new_piece) {
        cur_piece = signature_regex.add_piece();
        i = 0;
      }
      add_new_piece = false;

      if (byte_with_extra.type == ByteWithExtra::kSingleWildcard) {
        if (cur_piece->bytes().empty()) {
          // Never add single wildcards to the start of a signature piece.
          continue;
        }

        cur_piece->add_masked_nibble(i * 2);
        cur_piece->add_masked_nibble(i * 2 + 1);
      }
      *cur_piece->mutable_bytes() += byte_with_extra.value;
      ++i;
      // Each group of consecutive bytes should have the same weight.
      if (!cur_piece->has_weight()) {
        cur_piece->set_weight(byte_with_extra.weight);
      }
      const auto* origin = byte_with_extra.origin;
      if (origin != last_instruction) {
        if (origin != nullptr && !origin->disassembly.empty()) {
          cur_piece->add_origin_disassembly(
              absl::StrCat(absl::Hex(origin->match.address, absl::kZeroPad8),
                           ": ", origin->disassembly));
        }
        last_instruction = origin;
      }
    } else {
      // The last byte_with_wildcard was a wildcard so we need to add a new
      // piece to the signature. We only want to add a single piece for multiple
      // consecutive wildcards or we'd end up with empty pieces.
      add_new_piece = !cur_piece->bytes().empty();
    }
  }

  if (cur_piece->bytes().empty()) {
    // Last added piece was empty, most likely due to a piece that started with
    // a single wildcard ('?').
    signature_regex.mutable_piece()->RemoveLast();
  }
  return signature_regex;
}

void AddInstructionBytes(const MatchedBasicBlock& bb,
                         const MatchedInstruction& instr,
                         bool disable_nibble_masking,
                         ByteWithExtraString* bb_sequence) {
  CHECK(bb_sequence);

  absl::flat_hash_set<int> immediate_pos;
  immediate_pos.reserve(instr.immediates.size());
  if (!disable_nibble_masking) {
    std::string immediate(4, '\0');
    for (const auto& immediate_value : instr.immediates) {
      if (immediate_value.second !=
          kDWord) {  // Only look at 32-bit immediates.
        continue;
      }
      // Only look for little endian encoded immediates.
      absl::little_endian::Store32(&immediate[0], immediate_value.first);
      const auto found = instr.raw_instruction_bytes.rfind(immediate);
      if (found != std::string::npos) {
        immediate_pos.insert(found);
      }
    }
  }

  for (int i = 0; i < instr.raw_instruction_bytes.size();) {
    const auto& raw_bytes = instr.raw_instruction_bytes;
    if (disable_nibble_masking ||
        immediate_pos.find(i) == immediate_pos.end()) {
      bb_sequence->push_back(
          {raw_bytes[i++], ByteWithExtra::kRegularByte, bb.weight, &instr});
    } else {
      bb_sequence->push_back(
          {raw_bytes[i++], ByteWithExtra::kSingleWildcard, bb.weight, &instr});
      bb_sequence->push_back(
          {raw_bytes[i++], ByteWithExtra::kSingleWildcard, bb.weight, &instr});
      bb_sequence->push_back(
          {raw_bytes[i++], ByteWithExtra::kSingleWildcard, bb.weight, &instr});
      bb_sequence->push_back(
          {raw_bytes[i++], ByteWithExtra::kSingleWildcard, bb.weight, &instr});
    }
  }
}

void PenalizeShortAtoms(int min_piece_length, ByteWithExtraString* regex) {
  CHECK_GE(min_piece_length, 1) << "Need a minimum piece length of at least 1";
  int i = 0;
  const int regex_size = regex->size();
  int num_regular = 0;
  int piece_start = 0;
  while (i < regex_size) {
    while (i < regex_size && (*regex)[i].type == ByteWithExtra::kRegularByte) {
      ++i;
      ++num_regular;
    }
    if (i < regex_size && (*regex)[i].type == ByteWithExtra::kWildcard) {
      ++i;
      piece_start = i;
      num_regular = 0;
      continue;
    }
    // Current byte must be ? wildcard, penalize short atom and consecutive runs
    // of the wildcard.
    bool penalize_piece = num_regular < min_piece_length;
    if (penalize_piece) {
      for (int j = piece_start; j < i; ++j) {
        (*regex)[j].weight = 0;
      }
    }
    ++i;
    while (i < regex_size &&
           (*regex)[i].type == ByteWithExtra::kSingleWildcard) {
      if (penalize_piece) {
        (*regex)[i].weight = 0;
      }
      ++i;
    }
  }
}

absl::StatusOr<RawSignature> GenericSignatureFromMatches(
    const MatchChainTable& table, const IdentSequence& bb_candidate_ids,
    bool disable_nibble_masking, int min_piece_length) {
  if (bb_candidate_ids.empty()) {
    return absl::InvalidArgumentError("Empty basic block candidate list");
  }
  if (min_piece_length < 1) {
    return absl::InvalidArgumentError(
        "Minimum piece length must be at least 1");
  }

  ByteWithExtraString regex;

  // Helper function to insert bounded inter-basic-block wildcards into the raw
  // signature. Currently, bounded wildcards are not used.
  WildcardInserter<ByteWithExtraStringBackInserter> insert_wildcard([](
      size_t /*min_qualifier*/, size_t /*max_qualifier*/,
      ByteWithExtraStringBackInserter result) { *result++ = kWildcardByte; });

  // Iterate over all basic block candidates.
  for (const auto& bb_id : bb_candidate_ids) {
    std::vector<ByteWithExtraString> bb_sequences;
    bb_sequences.reserve(table.size());

    // Iterate over all columns of the table.
    for (const auto& column : table) {
      const auto& bb = *ABSL_DIE_IF_NULL(column->FindBasicBlockById(bb_id));

      ByteWithExtraString bb_sequence;
      MemoryAddress last_address = 0;
      size_t last_size = 0;

      // Gather the instruction bytes for the current basic block.
      for (const auto& instr : bb.instructions) {
        DCHECK_LE(last_address + last_size, instr->match.address);

        // Count non-continuous instructions and insert inter-instruction
        // wildcards.
        if (!bb_sequence.empty() &&
            bb_sequence.back().type != ByteWithExtra::kWildcard &&
            last_address + last_size < instr->match.address) {
          // We need to insert a wildcard here, since otherwise we generate
          // signatures containing non-consecutive bytes.
          bb_sequence.push_back(kWildcardByte);
        }

        if (instr->raw_instruction_bytes.empty()) {
          return absl::InternalError(absl::StrCat(
              "No bytes for instruction in ", column->filename(), " at ",
              absl::Hex(instr->match.address, absl::kZeroPad8),
              " (from basic block at ",
              absl::Hex(bb.match.address, absl::kZeroPad8), ")"));
        }
        AddInstructionBytes(bb, *instr, disable_nibble_masking, &bb_sequence);

        last_address = instr->match.address;
        last_size = instr->raw_instruction_bytes.size();
      }
      bb_sequences.push_back(bb_sequence);
    }

    ByteWithExtraString bb_cs;
    CommonSubsequence(bb_sequences, std::back_inserter(bb_cs));

    ByteWithExtraString per_bb_regex;
    RegexFromSubsequence(bb_cs.begin(), bb_cs.end(), bb_sequences,
                         insert_wildcard, std::back_inserter(per_bb_regex));

    if (!regex.empty() && regex.back().type != ByteWithExtra::kWildcard) {
      regex.push_back(kWildcardByte);
    }

    // Append per-basic block candidates to result.
    regex.insert(regex.end(), per_bb_regex.begin(), per_bb_regex.end());
  }

  PenalizeShortAtoms(min_piece_length, &regex);
  return ToRawSignatureProto(regex);
}

}  // namespace security::vxsig
