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

#include "vxsig/subsequence_regex.h"

#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using ::testing::AnyOf;
using ::testing::Eq;
using ::testing::IsEmpty;

namespace security {
namespace vxsig {

struct StringWildcardInserter {
  static WildcardInserter<std::back_insert_iterator<std::string>> get() {
    // Helper function to insert simple, unbounded wildcards. We can thus ignore
    // the first two arguments here.
    return [](size_t, size_t, std::back_insert_iterator<std::string> result) {
      result = '*';
    };
  }
};

TEST(BuildRegexTest, EmptyCommonEmptySequences) {
  std::string result;
  std::string empty;
  std::vector<std::string> seqs;
  RegexFromSubsequence(empty.begin(), empty.end(), seqs,
                       StringWildcardInserter::get(),
                       std::back_inserter(result));
  EXPECT_THAT(result, IsEmpty());
}

TEST(BuildRegexTest, EmptyCommon) {
  std::string result;
  std::string empty;
  std::vector<std::string> seqs{"ABCDEF", "GHIJKL", "MNOPQR"};
  RegexFromSubsequence(empty.begin(), empty.end(), seqs,
                       StringWildcardInserter::get(),
                       std::back_inserter(result));
  EXPECT_THAT(result, IsEmpty());
}

TEST(BuildRegexTest, RepeatedLCSDifferentLens) {
  std::string result;
  std::string common("common");
  std::vector<std::string> seqs{"ABCcommonDEF", "DEFccoommmmoonnGHI",
                                "GHIcccooommmmmmooonnnJKL",
                                "JKLccccoooommmmmmmmoooonnnnMNO"};
  RegexFromSubsequence(common.begin(), common.end(), seqs,
                       StringWildcardInserter::get(),
                       std::back_inserter(result));
  EXPECT_THAT(result, AnyOf("c*o*mm*o*n", "c*o*mmo*n", "co*mmo*n", "c*omm*on",
                            "co*mm*on"));
}

TEST(BuildRegexTest, InterspersedAtPos2SameLength) {
  std::string result;
  std::string common("abc");
  std::vector<std::string> seqs{"aBbc", "aCbc", "aDbc"};
  RegexFromSubsequence(common.begin(), common.end(), seqs,
                       StringWildcardInserter::get(),
                       std::back_inserter(result));
  EXPECT_THAT(result, Eq("a*bc"));
}

}  // namespace vxsig
}  // namespace security
