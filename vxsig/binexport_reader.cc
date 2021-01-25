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

#include "vxsig/binexport_reader.h"

#include "base/logging.h"

#include <cstddef>
#include <fstream>
#include <memory>

#include "absl/memory/memory.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "third_party/zynamics/binexport/binexport.h"
#include "third_party/zynamics/binexport/util/status_macros.h"
#include "vxsig/types.h"

using security::binexport::GetInstructionAddress;

namespace security::vxsig {
namespace {

enum { kNoMdIndex = -1 };

// TODO(cblichmann): Use BinExport's variant of this code
void RenderExpression(const BinExport2& proto,
                      const BinExport2::Operand& operand, int index,
                      ImmediateSize immediate_size, std::string* output,
                      Immediates* immediates) {
  const auto& expression = proto.expression(operand.expression_index(index));
  const auto& symbol = expression.symbol();
  switch (expression.type()) {
    case BinExport2::Expression::OPERATOR: {
      std::vector<int> children;
      children.reserve(4);  // Default maximum on x86
      for (int i = index + 1;
           i < operand.expression_index_size() &&
           proto.expression(operand.expression_index(i)).parent_index() ==
               operand.expression_index(index);
           i++) {
        children.push_back(operand.expression_index(i));
      }
      auto num_children = children.size();
      if (symbol == "{") {  // ARM Register lists
        absl::StrAppend(output, "{");
        for (int i = 0; i < num_children; i++) {
          RenderExpression(proto, operand, index + 1 + i, immediate_size,
                           output, immediates);
          if (i != num_children - 1) {
            absl::StrAppend(output, ",");
          }
        }
        absl::StrAppend(output, "}");
      } else if (num_children == 1) {
        // Only a single child, treat expression as prefix operator (for
        // example: 'ss:').
        absl::StrAppend(output, symbol);
        RenderExpression(proto, operand, index + 1, immediate_size, output,
                         immediates);
      } else if (num_children > 1) {
        // Multiple children, treat expression as infix operator ('+' or '*').
        RenderExpression(proto, operand, index + 1, immediate_size, output,
                         immediates);
        for (int i = 1; i < num_children; i++) {
          absl::StrAppend(output, symbol);
          RenderExpression(proto, operand, index + 1 + i, immediate_size,
                           output, immediates);
        }
      }
      break;
    }
    case BinExport2::Expression::SYMBOL:
    case BinExport2::Expression::REGISTER:
      absl::StrAppend(output, symbol);
      break;
    case BinExport2::Expression::SIZE_PREFIX: {
      absl::string_view architecture_name(
          proto.meta_information().architecture_name());
      const bool long_mode = absl::EndsWith(architecture_name, "64");
      if ((long_mode && symbol != "b8") || (!long_mode && symbol != "b4")) {
        absl::StrAppend(output, symbol, " ");
      }

      if (symbol == "b8") {
        immediate_size = kQWord;
      } else if (symbol == "b4") {
        immediate_size = kDWord;
      } else if (symbol == "b2") {
        immediate_size = kWord;
      } else if (symbol == "b1") {
        immediate_size = kByte;
      }

      RenderExpression(proto, operand, index + 1, immediate_size, output,
                       immediates);
      break;
    }
    case BinExport2::Expression::DEREFERENCE:
      absl::StrAppend(output, "[");
      if (index + 1 < operand.expression_index_size()) {
        RenderExpression(proto, operand, index + 1, immediate_size, output,
                         immediates);
      }
      absl::StrAppend(output, "]");
      break;
    case BinExport2::Expression::IMMEDIATE_INT:
    case BinExport2::Expression::IMMEDIATE_FLOAT:
    default:
      absl::StrAppend(output, "0x", absl::Hex(expression.immediate()));
      immediates->emplace_back(expression.immediate(), immediate_size);
      break;
  }
}

}  // namespace

absl::Status ParseBinExport(
    absl::string_view filename,
    const FunctionReceiverCallback& function_receiver,
    const InstructionReceiverCallback& instruction_receiver) {
  std::ifstream file(std::string(filename), std::ios_base::binary);
  BinExport2 proto;
  if (!proto.ParseFromIstream(&file)) {
    return absl::InternalError(absl::StrCat("failed parsing ", filename));
  }

  // TODO(cblichmann): Read MD indices if we have them.
  std::map<MemoryAddress, double> md_index_map;

  // Push function metadata to receiver.
  const std::string& hash = proto.meta_information().executable_id();
  for (const auto& vertex : proto.call_graph().vertex()) {
    const auto address = vertex.address();
    const auto md_index = md_index_map.find(address);
    function_receiver(
        /*sha256=*/hash.size() == 64 ? hash : "", address, vertex.type(),
        md_index != md_index_map.end() ? md_index->second : kNoMdIndex);
  }

  for (const auto& flow_graph : proto.flow_graph()) {
    MemoryAddress computed_instruction_address = 0;
    int last_instruction_index = 0;
    for (const auto& basic_block_index : flow_graph.basic_block_index()) {
      const auto& basic_block = proto.basic_block(basic_block_index);
      CHECK(basic_block.instruction_index_size());

      for (const auto& instruction_index_range :
           basic_block.instruction_index()) {
        MemoryAddress basic_block_address = 0;
        const int begin_index = instruction_index_range.begin_index();
        const int end_index = instruction_index_range.has_end_index()
                                  ? instruction_index_range.end_index()
                                  : begin_index + 1;
        for (int i = begin_index; i < end_index; ++i) {
          const auto& instruction = proto.instruction(i);
          MemoryAddress instruction_address = computed_instruction_address;
          if (last_instruction_index != i - 1 || instruction.has_address()) {
            instruction_address = GetInstructionAddress(proto, i);
          }

          if (i == begin_index) {
            basic_block_address = instruction_address;
          }

          std::string disassembly(absl::StrCat(
              proto.mnemonic(instruction.mnemonic_index()).name(), " "));
          Immediates immediates;
          for (int i = 0; i < instruction.operand_index_size(); i++) {
            const auto& operand = proto.operand(instruction.operand_index(i));
            for (int j = 0; j < operand.expression_index_size(); j++) {
              const auto& expression =
                  proto.expression(operand.expression_index(j));
              if (!expression.has_parent_index()) {
                RenderExpression(proto, operand, j, kByte, &disassembly,
                                 &immediates);
              }
            }
            if (i != instruction.operand_index_size() - 1) {
              absl::StrAppend(&disassembly, ", ");
            }
          }

          const auto& raw_bytes = instruction.raw_bytes();
          instruction_receiver(basic_block_address, instruction_address,
                               raw_bytes, disassembly, immediates);

          computed_instruction_address = instruction_address + raw_bytes.size();
          last_instruction_index = i;
        }
      }
    }
  }
  return absl::OkStatus();
}

}  // namespace security::vxsig
