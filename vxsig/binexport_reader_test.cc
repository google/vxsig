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

#include "vxsig/binexport_reader.h"

#include <cstddef>
#include <string>
#include <utility>
#include <map>

#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "third_party/zynamics/binexport/util/status.h"
#include "third_party/zynamics/binexport/util/status_matchers.h"

using testing::Eq;
using testing::Ne;
using not_absl::IsOk;

namespace security {
namespace vxsig {

class BinExportReaderTest : public testing::Test {
 protected:
  size_t num_functions_ = 0;
  size_t num_instructions_ = 0;
};

TEST_F(BinExportReaderTest, ParseBinExport2) {
  std::string file_name =
      JoinPath(getenv("TEST_SRCDIR"),
               "com_google_vxsig/vxsig/testdata/"
               "0000050d2efbd0602bed34669e2f2cb01f6e91e35014fafd35d80ada62d6169"
               "a-PID_2192_-Name_LoadDLL.exe_.BinExport");
  ASSERT_THAT(
      ParseBinExport(
          file_name,
          [this](const std::string& /* sha256 */, MemoryAddress,
                 BinExport2::CallGraph::Vertex::Type,
                 double /* md_index */) { ++num_functions_; },
          [this](MemoryAddress /* basic_block_address */,
                 MemoryAddress /* instruction_address */,
                 const std::string& /* instruction_bytes */,
                 const std::string& /* disassembly */,
                 const Immediates& /* immediates */) { ++num_instructions_; }),
      IsOk());
  EXPECT_THAT(num_functions_, Eq(73));
  EXPECT_THAT(num_instructions_, Eq(29847));
}

TEST_F(BinExportReaderTest, ParseBinExport2Complex) {
  std::string file_name = JoinPath(
      getenv("TEST_SRCDIR"),
      "com_google_vxsig/vxsig/testdata/"
      "6d661e63d51d2b38c40d7a16d0cd957a125d397e13b1e50280c3d06bc26bb315."
      "BinExport");

  std::map<MemoryAddress, string> instructions;
  ASSERT_THAT(
      ParseBinExport(
          file_name,
          [this](const string& /* sha256 */, MemoryAddress,
                 BinExport2::CallGraph::Vertex::Type,
                 double /* md_index */) { ++num_functions_; },
          [this, &instructions](MemoryAddress /* basic_block_address */,
                                MemoryAddress instruction_address,
                                const string& instruction_bytes,
                                const string& /* disassembly */,
                                const Immediates& /* immediates */) {
            ++num_instructions_;
            ASSERT_FALSE(instruction_bytes.empty());
            instructions.insert({instruction_address, instruction_bytes});
          }),
      IsOk());
  EXPECT_THAT(num_functions_, Eq(624));
  EXPECT_THAT(num_instructions_, Eq(30244));  // Unique instructions

  auto found = instructions.find(0x004015D6);
  ASSERT_THAT(found, Ne(instructions.end()));
  EXPECT_THAT("\x83\x7D\xFC\x10", Eq(found->second));  // cmp ss:[ebp-4], 10h
}

}  // namespace vxsig
}  // namespace security
