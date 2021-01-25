// Copyright 2011-2021 Google LLC
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

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::AnyOf;
using testing::ElementsAre;
using testing::IsNull;
using testing::Not;

namespace security::vxsig {

// The fixture for testing function/basic block computation.
class CandidatesTest : public ::testing::Test {
 protected:
  enum { kNumSimpleMatches = 5, kNumFakeBinaries = 3 };

  CandidatesTest();

  static const MemoryAddress
      kSimpleChains[kNumFakeBinaries * kNumSimpleMatches];

  MatchChainTable table_;
};

CandidatesTest::CandidatesTest() : table_() {
  for (int i = 0; i < kNumFakeBinaries; ++i) {
    table_.emplace_back(new MatchChainColumn());
  }

  // Insert simple matches into column. This results in a match chain column
  // are equivalent to a binary with functions that consist of basic blocks
  // that in turn consist of a single instruction. This is a similar
  // construction as in match_chain_table_test.cc.
  for (int i = 0; i < kNumFakeBinaries * kNumSimpleMatches;
       i += kNumFakeBinaries) {
    MatchChainTable::iterator col_it = table_.begin();
    for (int j = 0; j < kNumFakeBinaries - 1; ++j, ++col_it) {
      MemoryAddressPair match(kSimpleChains[i + j], kSimpleChains[i + j + 1]);
      auto* new_func = (*col_it)->InsertFunctionMatch(match);
      new_func->type = BinExport2::CallGraph::Vertex::NORMAL;
      auto* new_bb = (*col_it)->InsertBasicBlockMatch(new_func, match);
      (*col_it)->InsertInstructionMatch(new_bb, match);
    }
    // Create a mapping to address 0, like FinishChain() would do.
    MemoryAddressPair match(kSimpleChains[i + kNumFakeBinaries - 1], 0);
    auto* column = table_.back().get();
    auto* new_func = column->InsertFunctionMatch(match);
    auto* new_bb = column->InsertBasicBlockMatch(new_func, match);
    column->InsertInstructionMatch(new_bb, match);
  }

  PropagateIds(&table_);
  BuildIdIndices(&table_);
}

const MemoryAddress CandidatesTest::kSimpleChains[] = {
    0x00001000, 0x40001000, 0x20001000,  // 1
    0x00002000, 0x10002000, 0x20002000,  // 2
    0x00003000, 0x10003000, 0x20003000,  // 3
    0x00004000, 0x20004000, 0x20004000,  // 4
    0x00005000, 0x30005000, 0x20005000,  // 5
};

TEST_F(CandidatesTest, ComputeFunctionCandidates) {
  IdentSequence func_candidate_ids;
  ComputeFunctionCandidates(table_, &func_candidate_ids);
  // 0x40001000 breaks the order of functions here, so 1 is not a candidate.
  EXPECT_THAT(func_candidate_ids, ElementsAre(2, 3, 4, 5));
}

TEST_F(CandidatesTest, ComputeBasicBlockCandidates) {
  // All functions are candidates here.
  IdentSequence func_candidate_ids;
  for (int i = 1; i <= kNumSimpleMatches; ++i) {
    func_candidate_ids.push_back(i);
  }

  IdentSequence bb_candidate_ids;
  ComputeBasicBlockCandidates(table_, func_candidate_ids, &bb_candidate_ids);
  // Like with the functions, 1 is not a candidate basic block because of
  // 0x40001000.
  EXPECT_THAT(bb_candidate_ids, ElementsAre(2, 3, 4, 5));
}

TEST_F(CandidatesTest, FilterBasicBlockOverlaps) {
  // Insert an overlapping instruction into an existing basic block.
  auto* bb = table_[1]->FindBasicBlockByAddress(0x10003000);
  ASSERT_THAT(bb, Not(IsNull()));
  table_[1]->InsertInstructionMatch(bb, {0x10002000, 0});

  // All basic blocks are candidates here.
  IdentSequence bb_candidate_ids;
  for (int i = 1; i <= kNumSimpleMatches; ++i) {
    bb_candidate_ids.push_back(i);
  }

  // Filter out overlaps in basic blocks.
  FilterBasicBlockOverlaps(table_, &bb_candidate_ids);
  // As it is currently implemented in FilterBasicBlockOverlaps(), the
  // 0x40001000 leads us to remove most of the candidates. The second variant,
  // however, might represent a better result, so we also allow it.
  EXPECT_THAT(bb_candidate_ids, AnyOf(ElementsAre(1), ElementsAre(3, 4, 5)));
}

}  // namespace security::vxsig
