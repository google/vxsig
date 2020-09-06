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

// A reader for the Protobuf based .BinExport file format (v2). Callbacks are
// used to notify the caller about encountered functions and metadata.

#ifndef VXSIG_BINEXPORT_READER_H_
#define VXSIG_BINEXPORT_READER_H_

#include <functional>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "third_party/zynamics/binexport/binexport2.pb.h"
#include "vxsig/types.h"

namespace security::vxsig {

// Each time a function is encountered, this callback gets called with the
// function's address and type.
using FunctionReceiverCallback = std::function<void(
    const std::string& sha256, MemoryAddress function_address,
    BinExport2::CallGraph::Vertex::Type type, double md_index)>;

enum ImmediateSize {
  kByte,
  kWord,
  kDWord,
  kQWord
};

using Immediates = std::vector<std::pair<MemoryAddress, ImmediateSize>>;

// Each time an instruction is encountered, this callback gets called with
// the instruction's basic block address, its address, the raw instruction
// bytes as well as the instruction's immediates and their widths.
using InstructionReceiverCallback = std::function<void(
    MemoryAddress basic_block_address, MemoryAddress instruction_address,
    const std::string& raw_bytes, const std::string& disassembly,
    const Immediates& immediates)>;

// Parses the specified .BinExport file and calls the specified callback
// function for all encountered functions.
absl::Status ParseBinExport(
    absl::string_view filename,
    const FunctionReceiverCallback& function_receiver,
    const InstructionReceiverCallback& instruction_receiver);

}  // namespace security::vxsig

#endif  // VXSIG_BINEXPORT_READER_H_
