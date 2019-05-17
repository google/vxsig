// Copyright 2011-2019 Google LLC. All Rights Reserved.
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

#include "vxsig/hamming.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::Eq;

namespace security {
namespace vxsig {
namespace {

TEST(HammingTest, OperateOnContainers) {
  EXPECT_THAT(HammingDistance(std::string(""), std::string("")), Eq(0));
  EXPECT_THAT(HammingDistance(std::string("abc"), std::string("")), Eq(3));
  EXPECT_THAT(HammingDistance(std::string("abc"), std::string("abc")), Eq(0));
  EXPECT_THAT(HammingDistance(std::string(""), std::string("abc")), Eq(3));
  EXPECT_THAT(HammingDistance(std::string("abc"), std::string("ABC")), Eq(3));
  EXPECT_THAT(HammingDistance(std::string("abc"), std::string("abcdef")),
              Eq(3));
  EXPECT_THAT(HammingDistance(std::string("abcdef"), std::string("abc")),
              Eq(3));
  EXPECT_THAT(HammingDistance(std::string("abcdef"), std::string("def")),
              Eq(6));
}

TEST(HammingTest, OperateOnIterators) {
  std::string empty;
  std::string abc("abc");
  std::string abc_upper("ABC");
  std::string abcdef("abcdef");
  std::string def("def");

  EXPECT_THAT(
      HammingDistance(empty.begin(), empty.end(), empty.begin(), empty.end()),
      Eq(0));
  EXPECT_THAT(
      HammingDistance(abc.begin(), abc.end(), empty.begin(), empty.end()),
      Eq(3));
  EXPECT_THAT(HammingDistance(abc.begin(), abc.end(), abc.begin(), abc.end()),
              Eq(0));
  EXPECT_THAT(
      HammingDistance(empty.begin(), empty.end(), abc.begin(), abc.end()),
      Eq(3));
  EXPECT_THAT(HammingDistance(abc.begin(), abc.end(), abc_upper.begin(),
                              abc_upper.end()),
              Eq(3));
  EXPECT_THAT(
      HammingDistance(abc.begin(), abc.end(), abcdef.begin(), abcdef.end()),
      Eq(3));
  EXPECT_THAT(
      HammingDistance(abcdef.begin(), abcdef.end(), abc.begin(), abc.end()),
      Eq(3));
  EXPECT_THAT(
      HammingDistance(abcdef.begin(), abcdef.end(), def.begin(), def.end()),
      Eq(6));
}

}  // namespace
}  // namespace vxsig
}  // namespace security
