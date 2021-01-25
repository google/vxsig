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

#include "vxsig/match_chain_table.h"

#include <utility>

#include "absl/memory/memory.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::Contains;
using testing::Eq;
using testing::NotNull;
using testing::SizeIs;

namespace security::vxsig {
namespace {

enum { kNumSimpleMatches = 5 };

constexpr MemoryAddress kSimpleMatches[2 * kNumSimpleMatches] = {
    0x00001000, 0x50001000,  // 1
    0x00002000, 0x40002000,  // 2
    0x00003000, 0x10003000,  // 3
    0x00004000, 0x20004000,  // 4
    0x00005000, 0x30005000,  // 5
};

void InsertSimpleMatches(MatchChainColumn* column) {
  // Insert simple matches into column. This results in a match chain column
  // equivalent to a binary with functions that consist of basic blocks that
  // in turn consist of a single instruction.
  for (int i = 0; i < 2 * kNumSimpleMatches; i += 2) {
    MemoryAddressPair match(kSimpleMatches[i], kSimpleMatches[i + 1]);

    auto* new_func = column->InsertFunctionMatch(match);
    if (new_func == nullptr) {  // Filtered
      continue;
    }
    auto* new_bb = column->InsertBasicBlockMatch(new_func, match);
    column->InsertInstructionMatch(new_bb, match);
  }
}

TEST(MatchChainColumnTest, ValidateInsertion) {
  MatchChainColumn column;
  InsertSimpleMatches(&column);

  auto* functions = MatchChainColumn::GetFunctionIndexFromColumn(&column);
  EXPECT_THAT(*functions, SizeIs(kNumSimpleMatches));

  int i = 0;
  for (const auto& entry : *functions) {
    const auto& func = entry.second;

    // Check if the primary function address is internally consistent.
    EXPECT_THAT(func->match.address, Eq(entry.first));

    // Check if the function address in primary and secondary equals those in
    // kSimpleMatches.
    EXPECT_THAT(func->match.address, Eq(kSimpleMatches[i]));
    ++i;
    EXPECT_THAT(func->match.address_in_next, Eq(kSimpleMatches[i]));
    ++i;

    // We've inserted exactly one basic block at the same address, check if
    // that is true.
    ASSERT_THAT(func->basic_blocks, SizeIs(1));
    const MatchedBasicBlock* bb = *func->basic_blocks.begin();
    EXPECT_THAT(func->match.address, Eq(bb->match.address));

    // The inserted basic block should contain exactly one instruction at the
    // same address.
    ASSERT_THAT(bb->instructions, SizeIs(1));
    const MatchedInstruction* instr = *bb->instructions.begin();
    EXPECT_THAT(bb->match.address, Eq(instr->match.address));
  }
}

TEST(MatchChainColumnTest, FilteredInsertion) {
  MatchChainColumn column;
  auto& index = *MatchChainColumn::GetFunctionIndexFromColumn(&column);
  std::set<MemoryAddress> filtered_functions{0x00002000, 0x0004000};
  for (const auto& address : filtered_functions) {
    column.AddFilteredFunction(address);
  }

  // Test inclusion
  column.set_function_filter(SignatureDefinition::FILTER_INCLUDE);
  InsertSimpleMatches(&column);
  EXPECT_THAT(index, SizeIs(2));
  for (const auto& entry : index) {
    EXPECT_THAT(filtered_functions, Contains(entry.first));
  }

  // Test exclusion
  index.clear();
  column.set_function_filter(SignatureDefinition::FILTER_EXCLUDE);
  InsertSimpleMatches(&column);
  EXPECT_THAT(index, SizeIs(3));
  for (const auto& entry : index) {
    EXPECT_THAT(filtered_functions.find(entry.first),
                Eq(filtered_functions.end()));
  }
}

TEST(MatchChainColumnTest, FinishChain) {
  MatchChainColumn column;
  InsertSimpleMatches(&column);

  MatchChainColumn last_column;
  last_column.FinishChain(&column);

  auto* col_funcs = MatchChainColumn::GetFunctionIndexFromColumn(&column);
  EXPECT_THAT(
      col_funcs->size(),
      Eq(MatchChainColumn::GetFunctionIndexFromColumn(&last_column)->size()));
  EXPECT_THAT(
      MatchChainColumn::GetBasicBlockIndexFromColumn(&column)->size(),
      Eq(MatchChainColumn::GetBasicBlockIndexFromColumn(&last_column)->size()));

  for (const auto& entry : *col_funcs) {
    // Check if the mapping was set up correctly from the next-to-last column
    // to the last column.
    const auto& func =
        last_column.FindFunctionByAddress(entry.second->match.address_in_next);
    ASSERT_THAT(func, NotNull());

    // All chains should end with a mapping to address zero.
    EXPECT_THAT(func->match.address_in_next, Eq(0));
  }
}

TEST(MatchChainColumnTest, PropagateIdsAndBuildIndices) {
  MatchChainTable table;
  table.emplace_back(absl::make_unique<MatchChainColumn>());
  auto* column = table.back().get();
  InsertSimpleMatches(column);
  table.emplace_back(absl::make_unique<MatchChainColumn>());
  auto* last_column = table.back().get();

  last_column->FinishChain(column);
  PropagateIds(&table);

  auto* col_funcs = MatchChainColumn::GetFunctionIndexFromColumn(column);
  for (auto it = col_funcs->cbegin(); it != col_funcs->cend(); ++it) {
    auto* last_func =
        last_column->FindFunctionByAddress(it->second->match.address_in_next);
    ASSERT_THAT(last_func, NotNull());

    // Ids should be properly propagated.
    EXPECT_THAT(it->second->match.id, Eq(last_func->match.id));
  }

  BuildIdIndices(&table);

  auto* last_funcs = MatchChainColumn::GetFunctionIndexFromColumn(last_column);
  for (auto it = col_funcs->cbegin(), last_it = last_funcs->cbegin();
       it != col_funcs->cend(); ++it, ++last_it) {
    // If id indices are properly constructed, lookups should not return
    // nullptr.
    EXPECT_THAT(column->FindFunctionById(it->second->match.id), NotNull());
    EXPECT_THAT(last_column->FindFunctionById(last_it->second->match.id),
                NotNull());
  }
}

}  // namespace
}  // namespace security::vxsig
