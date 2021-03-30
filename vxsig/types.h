// Copyright 2019-2021 Google LLC
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

// Defines types and enums that are used througout the signature generator.

#ifndef VXSIG_TYPES_H_
#define VXSIG_TYPES_H_

#include <cstdint>
#include <utility>
#include <vector>

namespace security::vxsig {

// Type used for representing memory addresses.
using MemoryAddress = uint64_t;

// A pair of memory addresses, used for matches.
using MemoryAddressPair = std::pair<MemoryAddress, MemoryAddress>;

// An identifier type, used to provide monotonically increasing identifiers for
// functions and basic blocks.
using Ident = uint32_t;

// A random accessible sequence of identifiers.
using IdentSequence = std::vector<Ident>;

enum MatchType {
  kFunctionMatch = 0,
  kBasicBlockMatch,
  kInstructionMatch
};

}  // namespace security::vxsig

#endif  // VXSIG_TYPES_H_
