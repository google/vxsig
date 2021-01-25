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

#include <memory>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "base/logging.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "third_party/zynamics/binexport/util/status_macros.h"
#include "vxsig/binexport_reader.h"
#include "vxsig/diff_result_reader.h"

namespace security::vxsig {

MatchedMemoryAddress::MatchedMemoryAddress(const MemoryAddressPair& from_match)
    : address(from_match.first), address_in_next(from_match.second) {}

MatchedInstruction::MatchedInstruction(const MemoryAddressPair& from_match)
    : match(from_match) {}

MatchedBasicBlock::MatchedBasicBlock(const MemoryAddressPair& from_match)
    : match(from_match) {}

MatchedFunction::MatchedFunction(const MemoryAddressPair& from_match)
    : match(from_match) {}

MatchedFunction* MatchChainColumn::InsertFunctionMatch(
    const MemoryAddressPair& match) {
  if (function_filter_ != SignatureDefinition::FILTER_NONE) {
    bool address_in_filter =
        filtered_functions_.find(match.first) != filtered_functions_.end();
    if ((function_filter_ == SignatureDefinition::FILTER_INCLUDE &&
         !address_in_filter) ||
        (function_filter_ == SignatureDefinition::FILTER_EXCLUDE &&
         address_in_filter)) {
      return nullptr;
    }
  }

  // Insert into index, id mappings will be propagated later by calling
  // PropagateIds().
  auto function = functions_by_address_.find(match.first);
  if (function == functions_by_address_.end()) {
    function = functions_by_address_.emplace_hint(
        function, match.first, absl::make_unique<MatchedFunction>(match));
  }
  return function->second.get();
}

MatchedBasicBlock* MatchChainColumn::InsertBasicBlockMatch(
    MatchedFunction* function, const MemoryAddressPair& match) {
  CHECK(function);

  // If the basic block address is already present in this column, it is shared
  // in multiple functions.
  // Note: See comments in insert_instruction_match() for a discussion of
  //       instruction sharing. The statements there are also valid for basic
  //       blocks.
  // Insert into index, id mappings will be propagated later by calling
  // PropagateIds().
  auto basic_block = basic_blocks_by_address_.find(match.first);
  if (basic_block == basic_blocks_by_address_.end()) {
    basic_block = basic_blocks_by_address_.emplace_hint(
        basic_block, match.first, absl::make_unique<MatchedBasicBlock>(match));
  }

  // Add basic block to function
  function->basic_blocks.insert(basic_block->second.get());

  return basic_block->second.get();
}

MatchedInstruction* MatchChainColumn::InsertInstructionMatch(
    MatchedBasicBlock* basic_block, const MemoryAddressPair& match) {
  CHECK(basic_block);

  // If the instruction address is already present in this column, it is shared
  // across multiple basic blocks.
  // Note: Instructions are shared often. Consider two functions f1 and f2
  //       with these instruction sequences:
  //       f1: push 200
  //           push 0
  //           push eax
  //           call memset
  //           push 200       f2: push 200
  //           push 0             push 0
  //           push ebx           push ebx
  //           call memset        call memset
  //           mov esp, ebp       mov esp, ebp
  //           pop ebp            pop ebp
  //           retn               retn
  //
  //       Those can legitimately be rewritten to jump to a shared block of
  //       code. Thus, the instructions of the second call to memset are part
  //       of both functions.
  auto instruction = instructions_by_address_.find(match.first);
  if (instruction == instructions_by_address_.end()) {
    instruction = instructions_by_address_.emplace_hint(
        instruction, match.first, absl::make_unique<MatchedInstruction>(match));
  }

  // Add instruction to basic block
  basic_block->instructions.insert(instruction->second.get());

  return instruction->second.get();
}

template <typename IndexT>
typename IndexT::value_type::second_type::pointer FindByAddress(
    IndexT* index, MemoryAddress address) {
  auto found = index->find(address);
  return found != index->end() ? found->second.get() : nullptr;
}

MatchedFunction* MatchChainColumn::FindFunctionByAddress(
    MemoryAddress address) {
  return FindByAddress(&functions_by_address_, address);
}

MatchedBasicBlock* MatchChainColumn::FindBasicBlockByAddress(
    MemoryAddress address) {
  return FindByAddress(&basic_blocks_by_address_, address);
}

MatchedInstruction* MatchChainColumn::FindInstructionByAddress(
    MemoryAddress address) {
  return FindByAddress(&instructions_by_address_, address);
}

MatchedFunction* MatchChainColumn::FindFunctionById(Ident id) {
  auto it = functions_by_id_.find(id);
  return it == functions_by_id_.end() ? nullptr : it->second;
}

MatchedBasicBlock* MatchChainColumn::FindBasicBlockById(Ident id) {
  auto it = basic_blocks_by_id_.find(id);
  return it == basic_blocks_by_id_.end() ? nullptr : it->second;
}

class MatchChainInserter {
 public:
  explicit MatchChainInserter(MatchChainColumn* column) : column_(column) {}

  MatchChainInserter(const MatchChainInserter&) = delete;
  MatchChainInserter& operator=(const MatchChainInserter&) = delete;

  void AddFunctionMatch(const MemoryAddressPair& match);
  void AddBasicBlockMatch(const MemoryAddressPair& match);
  void AddInstructionMatch(const MemoryAddressPair& match);

 private:
  MatchChainColumn* column_;
  MatchedFunction* current_function_ = nullptr;
  MatchedBasicBlock* current_basic_block_ = nullptr;
};

void MatchChainInserter::AddFunctionMatch(const MemoryAddressPair& match) {
  current_function_ = column_->InsertFunctionMatch(match);
}

void MatchChainInserter::AddBasicBlockMatch(const MemoryAddressPair& match) {
  if (current_function_) {
    current_basic_block_ =
        column_->InsertBasicBlockMatch(current_function_, match);
  }
}

void MatchChainInserter::AddInstructionMatch(const MemoryAddressPair& match) {
  if (current_basic_block_) {
    column_->InsertInstructionMatch(current_basic_block_, match);
  }
}

void MatchChainColumn::FinishChain(MatchChainColumn* prev) {
  auto& functions = prev->functions_by_address_;
  for (const auto& function_match : functions) {
    CHECK(function_match.second);
    const MatchedFunction& func = *function_match.second;
    // Add a mapping to address zero to properly finalize the match chain.
    // The zero value is never used and is just there to avoid undefined
    // values in the match chain table.
    auto* new_function = InsertFunctionMatch({func.match.address_in_next, 0});
    CHECK(new_function);

    for (const auto* bb : func.basic_blocks) {
      // Add zero value like for functions.
      auto* new_basic_block =
          InsertBasicBlockMatch(new_function, {bb->match.address_in_next, 0});
      CHECK(new_basic_block);

      for (const auto* instr : bb->instructions) {
        // Add zero value like for functions and basic blocks.
        InsertInstructionMatch(new_basic_block,
                               {instr->match.address_in_next, 0});
      }
    }
  }
}

template<typename AddressIndexT, typename IdentIndexT>
void BuildIdIndexFromAddressIndex(const AddressIndexT& address_index,
                                  IdentIndexT* id_index) {
  for (const auto& match : address_index) {
    id_index->emplace(match.second->match.id, match.second.get());
  }
}

void MatchChainColumn::BuildIdIndices() {
  BuildIdIndexFromAddressIndex(functions_by_address_, &functions_by_id_);
  BuildIdIndexFromAddressIndex(basic_blocks_by_address_, &basic_blocks_by_id_);
}

absl::Status AddDiffResult(
    absl::string_view filename, bool last, MatchChainColumn* column,
    MatchChainColumn* next,
    std::vector<std::pair<std::string, std::string>>* diffs) {
  namespace arg = ::std::placeholders;

  MatchChainInserter match_inserter(column);
  std::pair<FileMetaData, FileMetaData> metadata;

  NA_RETURN_IF_ERROR(
      ParseBinDiff(filename,
                   std::bind(&MatchChainInserter::AddFunctionMatch,
                             &match_inserter, arg::_1),
                   std::bind(&MatchChainInserter::AddBasicBlockMatch,
                             &match_inserter, arg::_1),
                   std::bind(&MatchChainInserter::AddInstructionMatch,
                             &match_inserter, arg::_1),
                   &metadata));

  const std::string diff_directory = Dirname(filename);
  column->set_filename(metadata.first.filename);
  column->set_diff_directory(diff_directory);
  if (last) {
    next->set_filename(metadata.second.filename);
    next->set_diff_directory(diff_directory);
    next->FinishChain(column);
  }
  diffs->emplace_back(metadata.first.filename, metadata.second.filename);
  return absl::OkStatus();
}

absl::Status AddFunctionData(absl::string_view filename,
                             MatchChainColumn* column) {
  auto metadata_callback(
      [column](const std::string& sha256, MemoryAddress address,
               BinExport2::CallGraph::Vertex::Type type, double /*md_index*/) {
        auto* func = column->FindFunctionByAddress(address);
        if (!func) {
          // Function was not found in this column. This happens if the function
          // was not matched by the differ or has been filtered. Do not insert
          // metadata.
          return;
        }
        func->type = type;

        auto& column_sha256 = column->sha256();
        if (column_sha256.empty()) {
          column->set_sha256(sha256);
        } else {
          QCHECK_EQ(column_sha256, sha256) << "Inconsistent SHA256 in column";
        }
      });

  auto basic_block_callback([column](MemoryAddress bb_address,
                                     MemoryAddress instr_address,
                                     const std::string& instr_bytes,
                                     const std::string& disassembly,
                                     const Immediates& immediates) {
    // Note: We used to check whether the instruction's parent basic block was
    // present in this column. However, loading all instruction bytes makes the
    // logic a bit simpler and also gracefully handles instructions that are
    // shared with unmatched basic blocks. This fixes b/26509651.
    auto* instr = column->FindInstructionByAddress(instr_address);
    if (!instr) {
      // Instruction not found in this column, because it was not matched.
      return;
    }

    if (instr->raw_instruction_bytes.empty()) {
      instr->raw_instruction_bytes = instr_bytes;
      instr->disassembly = disassembly;
      instr->immediates = immediates;
    } else {
      // Make sure that if the instruction is added multiple times, the
      // instruction bytes stay the same.
      DCHECK_EQ(instr->raw_instruction_bytes, instr_bytes)
          << "Instruction bytes differ: "
          << absl::StrFormat("%08x %08x %d", bb_address, instr_address,
                             instr_bytes.size());
    }
  });

  return ParseBinExport(filename, metadata_callback, basic_block_callback);
}

template <typename IndexT>
void PropagateIds(MatchChainTable* table,
                  std::function<IndexT*(MatchChainColumn*)> index_from_column) {
  auto* first_column_idx = index_from_column(table->begin()->get());
  Ident chain_id = 1;  // Ids start at 1.
  for (auto first_col_it = first_column_idx->begin();
       first_col_it != first_column_idx->end(); ++first_col_it, ++chain_id) {
    // Set ids of matches in the first column in ascending order of their
    // memory addresses.
    first_col_it->second->match.id = chain_id;

    // Once a match has been assigned an id, the corresponding matches in the
    // other columns have to be assigned the same id.

    MemoryAddress match_address_in_next =
        first_col_it->second->match.address_in_next;
    for (auto column_it = table->begin() + 1; column_it != table->end();
         ++column_it) {
      auto* index = index_from_column(column_it->get());
      auto found = index->find(match_address_in_next);
      if (found == index->end()) {  // Match chain broken.
        break;
      }

      // Continuous chain, set id on current item and follow.
      found->second->match.id = chain_id;
      match_address_in_next = found->second->match.address_in_next;
    }
  }
}

void PropagateIds(MatchChainTable* table) {
  PropagateIds(
      table,
      std::function<MatchChainColumn::FunctionAddressIndex*(MatchChainColumn*)>(
          MatchChainColumn::GetFunctionIndexFromColumn));
  PropagateIds(table, std::function<MatchChainColumn::BasicBlockAddressIndex*(
                          MatchChainColumn*)>(
                          MatchChainColumn::GetBasicBlockIndexFromColumn));
}

void BuildIdIndices(MatchChainTable* table) {
  CHECK(table);
  for (auto& column : *table) {
    column->BuildIdIndices();
  }
}

}  // namespace security::vxsig
