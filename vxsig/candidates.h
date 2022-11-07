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

// Provides functions to compute function and basic block candidates from a
// match chain table.

#ifndef VXSIG_CANDIDATES_H_
#define VXSIG_CANDIDATES_H_

#include "vxsig/match_chain_table.h"
#include "vxsig/types.h"

namespace security::vxsig {

// Computes function candidates filtered by the specified predicate callback.
void ComputeFunctionCandidates(const MatchChainTable& match_chain_table,
                               IdentSequence* func_candidate_ids);

// Computes basic block candidates for the basic blocks of the given candidate
// functions.
void ComputeBasicBlockCandidates(const MatchChainTable& match_chain_table,
                                 const IdentSequence& func_candidate_ids,
                                 IdentSequence* bb_candidate_ids);

// Filters overlapping basic blocks from a list of basicblock candidates.
// Overlapping basic blocks mean basicblocks that share common instructions.
void FilterBasicBlockOverlaps(const MatchChainTable& match_chain_table,
                              IdentSequence* bb_candidate_ids);

}  // namespace security::vxsig

#endif  // VXSIG_CANDIDATES_H_
