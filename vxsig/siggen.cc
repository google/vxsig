// Copyright 2011-2022 Google LLC
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

#include "vxsig/siggen.h"

#include <cmath>
#include <cstddef>
#include <iterator>
#include <limits>
#include <memory>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "third_party/zynamics/binexport/util/status_macros.h"
#include "vxsig/candidates.h"
#include "vxsig/generic_signature.h"
#include "vxsig/match_chain_table.h"

namespace security::vxsig {
namespace {

// Debugging utility. It outputs a table of function matches. Each column
// corresponds to one input binary. Primary functions are annotated with their
// identifier and their sequence number (if any) in the longest common
// subsequence. Example output (with shortened addresses):
// sshd.korg sshd.trojan1 sshd.trojan2
// 058360 (001 001)->095860 095860 (001 001)->449f80 449f80 (001 001)->000000
// 0583a0 (002    )->095890 095890 (002    )->44cd70 44a030 (012    )->000000
// 058410 (003    )->0958f0 0958f0 (003    )->44cd20 44a760 (010    )->000000
// 058460 (004    )->095930 095930 (004    )->44bae0 44acc0 (008    )->000000
// 0584e0 (005 002)->0959a0 0959a0 (005 002)->44af40 44ad90 (007    )->000000
// ^       ^   ^     ^
// |       |   |     \ Address in sshd.trojan1
// |       |   \ LCS sequence number
// |       \ Function Id
// \ Address in sshd.korg
void DumpMatchChainTable(const MatchChainTable& table,
                         const IdentSequence& candidates) {
  size_t max_rows = 0;
  for (const auto& column : table) {
    max_rows = std::max(column->functions_by_address().size(), max_rows);
  }

  std::vector<std::vector<std::string>> print_columns(
      max_rows + 1,
      std::vector<std::string>(table.size()));  // Indexed by row, column
  int column_index = 0;
  for (const auto& column : table) {
    print_columns[0][column_index] = column->filename();
    int row_index = 1;
    int candidate_id = 0;
    for (const auto& function : column->functions_by_address()) {
      std::string candidate_string("   ");
      if (std::binary_search(candidates.begin(), candidates.end(),
                             function.second->match.id)) {
        ++candidate_id;
        candidate_string = absl::StrFormat("%03u", candidate_id);
      }
      absl::StrAppendFormat(
          &print_columns[row_index][column_index], "%08x (%03u %s) -> %08x",
          function.second->match.address, function.second->match.id,
          candidate_string, function.second->match.address_in_next);
      ++row_index;
    }
    column_index++;
  }

  for (const auto& print_column : print_columns) {
    std::string line;
    for (const auto& column : print_column) {
      absl::StrAppendFormat(&line, "%30s | ", column);
    }
    absl::PrintF("%s\n", line);
  }
}

void FillSignatureMetadata(Signature* signature) {
  CHECK(signature);
  auto& signature_definition = *signature->mutable_definition();

  // Add the build date in order to associcate signatures with the vxsig
  // version.
  auto& cl_number = *signature_definition.add_meta();
  cl_number.set_key("vxsig_build");
  cl_number.set_string_value(__DATE__);

  if (!signature_definition.unique_signature_id().empty()) {
    auto& task_id = *signature_definition.add_meta();
    task_id.set_key("vxsig_taskid");
    task_id.set_string_value(signature_definition.unique_signature_id());
  }

  // Add a list of "representative samples".
  for (int i = 0; i < signature_definition.item_id_size(); ++i) {
    auto& sample = *signature_definition.add_meta();
    sample.set_key(absl::StrCat("rs", i + 1));
    sample.set_string_value(signature_definition.item_id(i));
  }
}

}  // namespace

void AvSignatureGenerator::AddDiffResultsFromCommandLineArguments(
    int argc, char* argv[]) {
  AddDiffResults(&argv[0], &argv[argc]);
}

void AvSignatureGenerator::AddDiffResults(absl::Span<const std::string> files) {
  AddDiffResults(files.begin(), files.end());
}

absl::Status AvSignatureGenerator::LoadColumnData() {
  absl::PrintF("Loading function metadata and instruction data\n");
  for (const auto& column : match_chain_table_) {
    NA_RETURN_IF_ERROR(
        AddFunctionData(JoinPath(column->diff_directory(), column->filename())
                            .append(".BinExport"),
                        column.get()));
  }
  return absl::OkStatus();
}

absl::Status AvSignatureGenerator::ParseDiffResults() {
  const auto num_diffs = diff_results_.size();

  absl::PrintF("Parsing diff results\n");
  std::vector<std::pair<std::string, std::string>> diff_file_pairs;
  auto column = match_chain_table_.begin();
  for (int i = 0; i < num_diffs; ++i, ++column) {
    auto next = column + 1;
    NA_RETURN_IF_ERROR(
        AddDiffResult(diff_results_[i], i == num_diffs - 1 /* Last column */,
                      column->get(), next->get(), &diff_file_pairs));
  }
  for (int i = 0; i < diff_file_pairs.size(); ++i) {
    const auto& pair = diff_file_pairs[i];
    if (match_chain_table_[i]->filename() != pair.first ||
        match_chain_table_[i + 1]->filename() != pair.second) {
      return absl::FailedPreconditionError(
          "Input files do not form a chain of diffs");
    }
  }
  return absl::OkStatus();
}

absl::Status AvSignatureGenerator::SetFunctionWeights(
    const IdentSequence& func_candidate_ids) {
  // TODO(cblichmann): Query for function occurrence counts and fill the map.
  using FunctionId = std::pair<std::string, Address>;
  absl::flat_hash_map<FunctionId, uint32_t> occurrence_counts;
  if (occurrence_counts.size() == 0) {
    return absl::OkStatus();
  }
  for (int i = 0; i < func_candidate_ids.size(); ++i) {
    for (const auto& column : match_chain_table_) {
      auto* function = column->FindFunctionById(func_candidate_ids[i]);

      auto found = occurrence_counts.find(
          FunctionId{column->sha256(), function->match.address});
      if (found == occurrence_counts.end()) {
        continue;
      }
      for (auto& basic_block : function->basic_blocks) {
        basic_block->weight =
            std::numeric_limits<uint32_t>::max() - found->second;
      }
    }
  }
  return absl::OkStatus();
}

absl::Status AvSignatureGenerator::ComputeCandidates() {
  absl::PrintF("Building id chains and indices\n");
  PropagateIds(&match_chain_table_);
  BuildIdIndices(&match_chain_table_);

  absl::PrintF("Computing function candidates\n");
  IdentSequence func_candidate_ids;
  ComputeFunctionCandidates(match_chain_table_, &func_candidate_ids);
  if (func_candidate_ids.empty()) {
    if (debug_match_chain_) {
      // Report if we couldn't find any function candidates. This won't help the
      // user directly, but it'll at least allow to examine the logs to figure
      // out what was wrong.
      DumpMatchChainTable(match_chain_table_, func_candidate_ids);
    }
    return absl::FailedPreconditionError("No function candidates found");
  }
  absl::PrintF("  Function candidates found: %d\n", func_candidate_ids.size());
  if (debug_match_chain_) {
    DumpMatchChainTable(match_chain_table_, func_candidate_ids);
  }

  absl::PrintF("  Querying for function prevalence per candidate\n");
  NA_RETURN_IF_ERROR(SetFunctionWeights(func_candidate_ids));

  absl::PrintF("Computing basic block candidates\n");
  ComputeBasicBlockCandidates(match_chain_table_, func_candidate_ids,
                              &bb_candidate_ids_);
  if (bb_candidate_ids_.empty()) {
    return absl::FailedPreconditionError("No basic block candidates found");
  }
  absl::PrintF("  Basic block candidates found: %d\n",
               bb_candidate_ids_.size());
  return absl::OkStatus();
}

absl::Status AvSignatureGenerator::Generate(Signature* signature) {
  if (!signature) {
    return absl::InvalidArgumentError("Need non-null signature object");
  }
  const auto& signature_definition = signature->definition();

  if (diff_results_.empty()) {
    return absl::FailedPreconditionError(
        "Need to call one of the methods from the AddDiffResults*() family "
        "first");
  }

  match_chain_table_.clear();
  auto num_diffs = diff_results_.size();
  // One more binary than there are diffs.
  match_chain_table_.reserve(num_diffs + 1);
  for (int i = 0; i < num_diffs + 1; ++i) {
    match_chain_table_.emplace_back(absl::make_unique<MatchChainColumn>());
  }

  // Apply function filter
  auto* column = match_chain_table_[0].get();
  column->set_function_filter(signature_definition.function_filter());
  for (const auto& address : signature_definition.filtered_function_address()) {
    column->AddFilteredFunction(address);
  }

  NA_RETURN_IF_ERROR(ParseDiffResults());
  NA_RETURN_IF_ERROR(LoadColumnData());
  NA_RETURN_IF_ERROR(ComputeCandidates());

  absl::PrintF("Filtering basic block overlaps and removing gaps\n");
  size_t size_before = bb_candidate_ids_.size();
  FilterBasicBlockOverlaps(match_chain_table_, &bb_candidate_ids_);
  absl::PrintF("  Removed %d, %d remain\n",
               size_before - bb_candidate_ids_.size(),
               bb_candidate_ids_.size());
  if (bb_candidate_ids_.empty()) {
    return absl::FailedPreconditionError(
        "All basic blocks overlap, input data is probably bad");
  }

  absl::PrintF("Constructing regular expression\n");
  NA_ASSIGN_OR_RETURN(
      auto raw_signature,
      GenericSignatureFromMatches(match_chain_table_, bb_candidate_ids_,
                                  signature_definition.disable_nibble_masking(),
                                  signature_definition.min_piece_length()));

  signature->clear_clam_av_signature();
  signature->clear_yara_signature();
  *signature->mutable_raw_signature() = std::move(raw_signature);
  absl::PrintF("  Regex: %d raw bytes (not counting wildcards)\n",
               GetSignatureSize(*signature));

  FillSignatureMetadata(signature);
  return absl::OkStatus();
}

}  // namespace security::vxsig
