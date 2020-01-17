// Copyright 2011-2019 Google LLC
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

#include <cstdint>
#include <utility>

#include "absl/memory/memory.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "third_party/zynamics/binexport/util/status_matchers.h"
#include "vxsig/vxsig.pb.h"

using not_absl::IsOk;
using testing::Eq;
using testing::SizeIs;

namespace security {
namespace vxsig {

class GenericSignatureTest : public ::testing::Test {
 protected:
  enum {
    kNumSimpleMatches = 5,
    kNumFakeBinaries = 3,
    kNumFakeInstructionsPerBasicBlock = 4,
    kBasicBlockWeight = 1000 /* Arbitrary weight */,
  };

  GenericSignatureTest() : table_() {
    table_.reserve(kNumFakeBinaries);
    for (int i = 0; i < kNumFakeBinaries; ++i) {
      table_.push_back(absl::make_unique<MatchChainColumn>());
    }

    // Current instruction byte, beginning at ASCII 0x21 ("!"), so we always
    // have a printable character range.
    uint8_t cur_instr_byte = 0x21;

    // Insert simple matches into column. This results in a match chain column
    // equivalent to a binary with functions that consist of basic blocks
    // that in turn consist of kNumFakeInstructions instructions. This is a
    // similar construction as in match_chain_table_test.cc.
    for (int i = 0; i < kNumFakeBinaries * kNumSimpleMatches;
         i += kNumFakeBinaries) {
      auto col_it = table_.begin();
      for (int j = 0; j < kNumFakeBinaries - 1; ++j, ++col_it) {
        MemoryAddressPair match(kSimpleChains[i + j], kSimpleChains[i + j + 1]);
        auto* new_func =
            ABSL_DIE_IF_NULL((*col_it)->InsertFunctionMatch(match));
        auto* new_bb = (*col_it)->InsertBasicBlockMatch(new_func, match);
        new_bb->weight = kBasicBlockWeight;
        InsertFakeInstructionData(match, col_it->get(), new_bb,
                                  &cur_instr_byte);
      }
      // Create a mapping to address 0, like FinishChain() would do.
      MemoryAddressPair match(kSimpleChains[i + kNumFakeBinaries - 1], 0);
      MatchChainColumn* column = table_.back().get();
      auto* new_func = ABSL_DIE_IF_NULL(column->InsertFunctionMatch(match));
      auto* new_bb = column->InsertBasicBlockMatch(new_func, match);
      new_bb->weight = kBasicBlockWeight;
      InsertFakeInstructionData(match, col_it->get(), new_bb, &cur_instr_byte);
    }

    PropagateIds(&table_);
    BuildIdIndices(&table_);
  }

  void InsertFakeInstructionData(const MemoryAddressPair& match,
                                 MatchChainColumn* col, MatchedBasicBlock* bb,
                                 uint8_t* cur_instr_byte) {
    // Start all basic blocks with the same instruction that consists of
    // two Xs and using the same "immediate".
    auto* new_instr = col->InsertInstructionMatch(bb, match);
    new_instr->raw_instruction_bytes = "XX0000";
    new_instr->immediates.emplace_back(0x30303030 /* Four zeroes */, kDWord);

    // We just inserted six instruction bytes, so we add additional bytes
    // starting at this offset.
    int address_offset = 6;

    // Insert a few more instructions.
    for (int i = 0; i < kNumFakeInstructionsPerBasicBlock - 1; ++i) {
      new_instr = col->InsertInstructionMatch(
          bb, {match.first + address_offset, match.second + address_offset});
      ++address_offset;
      // Each instruction gets filled with a unique value as its raw
      // instruction byte string, so we can test more easily later.
      new_instr->raw_instruction_bytes.push_back(*cur_instr_byte);
      ++*cur_instr_byte;
    }
  }

  static constexpr MemoryAddress kSimpleChains[] = {
      0x00001000, 0x10001000, 0x20001000,  // 1
      0x00002000, 0x10002000, 0x20002000,  // 2
      0x00003000, 0x10003000, 0x20003000,  // 3
      0x00004000, 0x10004000, 0x20004000,  // 4
      0x00005000, 0x10005000, 0x20005000,  // 5
  };

  MatchChainTable table_;
};

constexpr MemoryAddress GenericSignatureTest::kSimpleChains[];

TEST_F(GenericSignatureTest,
       GenericSignatureFromMatchesWithFakeInstructionsAndMasking) {
  IdentSequence bb_cand_ids{1, 2, 3, 4, 5};
  auto signature_or = GenericSignatureFromMatches(
      table_, bb_cand_ids, /*disable_nibble_masking=*/false,
      /*min_piece_length=*/4);
  ASSERT_THAT(signature_or, IsOk());
  auto signature_regex(std::move(signature_or).ValueOrDie());

  // We expect 5 pieces consisting of "XX".
  ASSERT_THAT(signature_regex.piece(), SizeIs(5));
  for (const auto& piece : signature_regex.piece()) {
    EXPECT_THAT(piece.bytes(), Eq("XX0000"));
    EXPECT_THAT(piece.masked_nibble_size(), Eq(8 /* 4 bytes == 8 nibbles */));
    // Make sure that this construct is penalized.
    EXPECT_THAT(piece.weight(), Eq(0));
  }
}

TEST_F(GenericSignatureTest,
       GenericSignatureFromMatchesWithFakeInstructionsAndNoMasking) {
  IdentSequence bb_cand_ids{1, 2, 3, 4, 5};
  auto signature_or = GenericSignatureFromMatches(
      table_, bb_cand_ids, /*disable_nibble_masking=*/true,
      /*min_piece_length=*/4);
  ASSERT_THAT(signature_or, IsOk());
  auto signature_regex(std::move(signature_or).ValueOrDie());

  // We expect 5 pieces consisting of "XX".
  ASSERT_THAT(signature_regex.piece_size(), Eq(5));
  for (const auto& piece : signature_regex.piece()) {
    EXPECT_THAT(piece.bytes(), Eq("XX0000"));
    EXPECT_THAT(piece.masked_nibble_size(), Eq(0));
    // Expect unchanged weight
    EXPECT_THAT(piece.weight(), Eq(kBasicBlockWeight));
  }
}

}  // namespace vxsig
}  // namespace security
