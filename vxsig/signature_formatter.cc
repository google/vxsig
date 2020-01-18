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

#include "vxsig/signature_formatter.h"

#include <algorithm>
#include <random>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "third_party/zynamics/binexport/util/canonical_errors.h"
#include "third_party/zynamics/binexport/util/status_macros.h"
#include "vxsig/clamav_signature_formatter.h"
#include "vxsig/generic_signature.h"
#include "vxsig/yara_signature_formatter.h"

namespace security {
namespace vxsig {

std::unique_ptr<SignatureFormatter> SignatureFormatter::Create(
    SignatureType type) {
  switch (type) {
    case SignatureType::CLAMAV:
      return absl::make_unique<ClamAvSignatureFormatter>();
    case SignatureType::YARA:
      return absl::make_unique<YaraSignatureFormatter>();
    default:
      ABSL_RAW_LOG(FATAL, "Invalid signature type");
      return nullptr;  // Not reached
  }
}

not_absl::Status SignatureFormatter::Format(Signature* signature) const {
  if (!signature) {
    return not_absl::InvalidArgumentError("Signature must not be nullptr");
  }
  return DoFormat(signature);
}

not_absl::Status SignatureFormatter::FormatDatabase(
    const Signatures& signatures, std::string* database) const {
  return DoFormatDatabase(signatures, ABSL_DIE_IF_NULL(database));
}

namespace {

not_absl::Status SolveKnapsack(const int64 max_byte_len,
                               const RawSignature& raw_signature,
                               std::vector<int>* piece_indices) {
  if (!piece_indices) {
    return not_absl::InvalidArgumentError("Piece indices must be non-nullptr");
  }
  // The code below is disabled for now, as piece weights need a function
  // corpus.
  // When enabling, include "ortools/linear_solver/linear_solver.h".
#if 0
  MPSolver solver("SolverSiggen", MPSolver::SCIP_MIXED_INTEGER_PROGRAMMING);
  solver.SetSolverSpecificParametersAsString(
      absl::StrCat("limits/memory = ", 8ULL << 30 /* 8 GiB */,
                   "\nlimits/time = ", 1800 /* 30min */, "\n"));
  solver.MutableObjective()->SetMaximization();
  MPConstraint* contraint = solver.MakeRowConstraint(0.0, max_byte_len);

  // Gather maximum weight and size values to scale later.
  double max_weight = 0;
  double max_size = 0;
  for (const auto& piece : raw_signature.piece()) {
    max_weight = std::max(static_cast<double>(piece.weight()), max_weight);
    max_size = std::max(static_cast<double>(piece.bytes().size()), max_size);
  }

  std::vector<MPVariable*> vars(piece_indices->size());
  const double log_max_weight = log(max_weight);
  for (int i = 0; i < vars.size(); ++i) {
    const auto& piece = raw_signature.piece((*piece_indices)[i]);
    auto& var = vars[i];
    var = solver.MakeBoolVar(/*name=*/"");
    double weight = piece.weight();
    if (weight > 0) {
      // Log scale the weight and map into a (0, 100] range. The "+ 1" ensures
      // that we never end up with zero weights. The log scale is useful since
      // we're ultimately dealing with function frequencies.
      const double scaled_log_weight =
          (1 + log(weight)) / (1 + log_max_weight) * 100;
      // Scale the piece length into (0, 100] range. Since the pieces are not
      // allowed to be empty, we cannot end up with a zero size.
      const double scaled_size = piece.bytes().size() / max_size * 100;
      // Set the weight used for solving the implicit Knapsack problem. By
      // scaling down the per-piece weight and multiplying with the scaled
      // per-piece length, we prefer including longer pieces in the final
      // signature.
      weight = scaled_log_weight * scaled_size;
    }
    solver.MutableObjective()->SetCoefficient(var, weight);
    contraint->SetCoefficient(var, piece.bytes().size());
  }
  const auto solver_result = solver.Solve();
  if (solver_result != MPSolver::OPTIMAL) {
    return not_absl::InternalError(
        absl::StrCat("Solver failed with code: ", solver_result));
  }
  RawSignature result;
  for (int i = 0; i < vars.size(); ++i) {
    if (vars[i]->solution_value() == 0.0) {
      (*piece_indices)[i] = -1;
    }
  }
  piece_indices->erase(
      std::remove_if(piece_indices->begin(), piece_indices->end(),
                     [](int i) { return i < 0; }),
      piece_indices->end());
#endif
  return not_absl::OkStatus();
}

void TrimLast(const int64 max_length, const RawSignature& raw_sig,
              std::vector<int>* piece_indices) {
  int current_length = 0;
  int j = 0;
  for (; j < piece_indices->size(); ++j) {
    const int i = (*piece_indices)[j];
    int64 new_length = current_length + raw_sig.piece(i).bytes().size();
    if (new_length > max_length) {
      break;
    }
    current_length = new_length;
  }
  piece_indices->resize(j);
}

void TrimLowWeight(const int64 max_length, const RawSignature& raw_sig,
                   std::vector<int>* piece_indices) {
  std::sort(
      piece_indices->begin(), piece_indices->end(), [&raw_sig](int a, int b) {
        // Prefer higher weight.
        int compare = raw_sig.piece(a).weight() - raw_sig.piece(b).weight();
        if (compare == 0) {
          // Prefer longer pieces.
          compare =
              raw_sig.piece(a).bytes().size() - raw_sig.piece(b).bytes().size();
        }
        return compare > 0;
      });

  std::vector<int> keep_indices;
  int current_length = 0;
  for (const auto& i : *piece_indices) {
    int64 new_length = current_length + raw_sig.piece(i).bytes().size();
    if (new_length > max_length) {
      // Don't give up yet, shorter pieces may follow.
      continue;
    }
    keep_indices.push_back(i);
    current_length = new_length;
  }
  piece_indices->swap(keep_indices);
}

}  // namespace

not_absl::Status GetRelevantSignatureSubset(const Signature& input,
                                            int engine_min_piece_len,
                                            RawSignature* output) {
  CHECK(output);
  const auto& raw_sig = input.raw_signature();
  const auto& definition = input.definition();

  // Gather all signature pieces of a minimum length.
  const int min_piece_len =
      std::max(engine_min_piece_len, definition.min_piece_length());
  std::vector<int> piece_indices;
  piece_indices.reserve(raw_sig.piece_size());
  const auto algorithm = definition.trim_algorithm();
  for (int i = 0; i < raw_sig.piece_size(); ++i) {
    const auto& piece = raw_sig.piece(i);
    if ((algorithm == SignatureDefinition::TRIM_WEIGHTED ||
         algorithm == SignatureDefinition::TRIM_WEIGHTED_GREEDY) &&
        piece.weight() == 0) {
      continue;
    }
    if (piece.bytes().size() >= min_piece_len) {
      piece_indices.push_back(i);
    }
  }

  int max_length = definition.trim_length();
  if (max_length < 0 &&
      definition.trim_algorithm() != SignatureDefinition::TRIM_NONE) {
    return not_absl::InvalidArgumentError(
        "Unbounded signature trimming requested");
  }
  switch (definition.trim_algorithm()) {
    case SignatureDefinition::TRIM_NONE:
      break;
    case SignatureDefinition::TRIM_LAST:
      TrimLast(max_length, raw_sig, &piece_indices);
      break;
    case SignatureDefinition::TRIM_FIRST:
      std::reverse(piece_indices.begin(), piece_indices.end());
      TrimLast(max_length, raw_sig, &piece_indices);
      break;
    case SignatureDefinition::TRIM_RANDOM: {
      // Mix the signature variant into the PRNG's seed.
      std::string seed = absl::StrCat(
          definition.variant() ^ 0x1599C98B /* Random number to mask 0 */,
          "369ea79bcded92881284" /* Random bytes */);
      std::mt19937 random(
          absl::hash_internal::CityHash64(seed.c_str(), seed.size()));
      std::shuffle(piece_indices.begin(), piece_indices.end(), random);
      TrimLast(max_length, raw_sig, &piece_indices);
      break;
    }
    case SignatureDefinition::TRIM_WEIGHTED:
      NA_RETURN_IF_ERROR(SolveKnapsack(max_length, raw_sig, &piece_indices));
      break;
    case SignatureDefinition::TRIM_WEIGHTED_GREEDY:
      TrimLowWeight(max_length, raw_sig, &piece_indices);
      break;
    default:
      return not_absl::InvalidArgumentError(
          "Unknown signature trimming algorithm");
      break;
  }

  if (piece_indices.empty()) {
    return not_absl::InvalidArgumentError("No byte piece to create signature");
  }

  std::sort(piece_indices.begin(), piece_indices.end());
  for (const auto& i : piece_indices) {
    *output->add_piece() = raw_sig.piece(i);
  }
  return not_absl::OkStatus();
}

}  // namespace vxsig
}  // namespace security
