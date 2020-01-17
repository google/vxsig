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

#include "vxsig/candidates.h"

#include <algorithm>
#include <iterator>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "absl/base/internal/raw_logging.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "vxsig/common_subsequence.h"
#include "vxsig/types.h"

namespace security {
namespace vxsig {
namespace {

bool IsCandidateFunction(const MatchedFunction& func) {
  return func.type == BinExport2::CallGraph::Vertex::NORMAL &&
         !func.basic_blocks.empty();
}

bool IsCandidateBasicBlock(const MatchedBasicBlock& bb) {
  if(bb.instructions.empty()) {
    ABSL_RAW_LOG(FATAL, "%s",
                 absl::StrFormat("Basic block at 0x%08X has no instructions",
                                 bb.match.address)
                     .c_str());
  }
  // If we ever implement a refcount, add a check whether it is > 0 (using
  // CHECK_GT).
  return bb.match.id != 0;
}

}  // namespace

void ComputeFunctionCandidates(const MatchChainTable& match_chain_table,
                               IdentSequence* func_candidate_ids) {
  std::vector<IdentSequence> func_ids;
  func_ids.reserve(match_chain_table.size());

  for (const auto& column : match_chain_table) {
    func_ids.emplace_back();
    auto& column_ids = func_ids.back();

    for (const auto& func_index_entry : column->functions_by_address()) {
      const auto& func = *func_index_entry.second;
      if (IsCandidateFunction(func)) {
        column_ids.push_back(func.match.id);
      }
    }
  }

  // Solve k-LCS on resulting permutations to obtain a stable function order.
  CommonSubsequence(func_ids, back_inserter(*func_candidate_ids));
}

void ComputeBasicBlockCandidates(const MatchChainTable& match_chain_table,
                                 const IdentSequence& func_candidate_ids,
                                 IdentSequence* bb_candidate_ids) {
  using MatchedBasicBlockWord = std::vector<MatchedBasicBlock*>;
  std::vector<IdentSequence> bb_ids;
  bb_ids.reserve(match_chain_table.size());

  for (const auto& column : match_chain_table) {
    MatchedBasicBlockWord bb_word;
    IdentSequence bb_word_ids;

    // Build a basic block "word" consisting of per-binary basic block ids of
    // the respective candidate function.
    for (const auto& func_candidate : func_candidate_ids) {
      auto* func = column->FindFunctionById(func_candidate);
      ABSL_RAW_CHECK(func, "No function for candidate");

      bb_word.insert(bb_word.end(), func->basic_blocks.begin(),
                     func->basic_blocks.end());
    }

    // Due to potential basic block sharing and function overlaps the basic
    // block word must be sorted again.
    std::sort(bb_word.begin(), bb_word.end(),
              MatchCompare<MatchedBasicBlock>());

    for (const auto& bb : bb_word) {
      if (IsCandidateBasicBlock(*bb)) {
        bb_word_ids.push_back(bb->match.id);
      }
    }
    bb_ids.push_back(bb_word_ids);
  }

  // Solve k-LCS on resulting permutations to obtain a stable basic block order.
  CommonSubsequence(bb_ids, back_inserter(*bb_candidate_ids));
}

void FilterBasicBlockOverlaps(const MatchChainTable& match_chain_table,
                              IdentSequence* bb_candidate_ids) {
  // TODO(cblichmann): Given the basic block match chain below (assume one
  // instruction per basic block), it is a priori unclear what the best
  // filtering strategy is.
  //   1. 0x00001000--+/->0x10002000-\+-->0x20001000
  //   2. 0x00002000-/|/->0x10003000-\|\->0x20002000
  //   3. 0x00003000-/|/->0x20004000-\|\->0x20003000
  //   4. 0x00004000-/|/->0x30005000-\|\->0x20004000
  //   5. 0x00005000-/+-->0x40001000--+\->0x20005000
  // Candidates should be either {2, 3, 4, 5} or {1} in this case, depending on
  // whether we want to filter out less or more basic blocks. As implemented,
  // the code results in the latter set ({1}) for consistency with the original
  // siggen prototype. A possible quality improvement would be to calculate all
  // combinations of filtered basic block id sets and select the one with the
  // maximal cardinality.

  for (const auto& column : match_chain_table) {
    MemoryAddress last_addr = 0;
    for (auto it = bb_candidate_ids->begin(); it != bb_candidate_ids->end();) {
      const auto* bb = column->FindBasicBlockById(*it);
      ABSL_RAW_CHECK(bb, "No basic block for candidate");

      bool skip_bb = false;
      for (const auto instr : bb->instructions) {
        skip_bb = instr->match.address <= last_addr;
        if (skip_bb) {
          break;
        }
        last_addr = instr->match.address;
      }

      if (skip_bb) {
        it = bb_candidate_ids->erase(it);
      } else {
        ++it;
      }
    }
  }
}

}  // namespace vxsig
}  // namespace security
