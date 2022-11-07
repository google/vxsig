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

#include "vxsig/longest_common_subsequence.h"

#include <cstdint>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::Eq;
using testing::IsEmpty;
using testing::ElementsAre;

namespace security::vxsig {

TEST(LongestCommonSubsequenceTest, OperateOnStrings) {
  EXPECT_THAT(LongestCommonSubsequence("", ""), IsEmpty());
  EXPECT_THAT(LongestCommonSubsequence("", "somestr"), IsEmpty());
  EXPECT_THAT(LongestCommonSubsequence("somestr", ""), IsEmpty());
  EXPECT_THAT(LongestCommonSubsequence("samestr", "samestr"), Eq("samestr"));
  EXPECT_THAT(LongestCommonSubsequence("sameprefixABC", "sameprefixDEF"),
              Eq("sameprefix"));
  EXPECT_THAT(LongestCommonSubsequence("ABCDcommonEFGH", "IJKLcommonMNOP"),
              Eq("common"));
  EXPECT_THAT(LongestCommonSubsequence("ABCDEFGHcommonIJKL", "MNOPcommonQRST"),
              Eq("common"));
  EXPECT_THAT(LongestCommonSubsequence("ABCDcommonEFGH", "IJKLMNOPcommonQRST"),
              Eq("common"));
  EXPECT_THAT(
      LongestCommonSubsequence("ABcoCDmmEFonGH", "IJKLcoMNmmOPonQRSTUV"),
      Eq("common"));
}

TEST(LongestCommonSubsequenceTest, TestOrder) {
  EXPECT_THAT(LongestCommonSubsequence("pcs", "pAcBCDEFGHJIKs"), Eq("pcs"));
  EXPECT_THAT(LongestCommonSubsequence("pAcBCDEFGHIJKs", "pcs"), Eq("pcs"));
}

template <typename IntT>
void TestLongestCommonSubsequenceOnVectors() {
  {
    const std::vector<IntT> empty;
    std::vector<IntT> result;
    // Both empty
    LongestCommonSubsequence(empty.begin(), empty.end(), empty.begin(),
                             empty.end(), std::back_inserter(result));
    EXPECT_THAT(result, IsEmpty());
  }
  {
    const std::vector<IntT> empty;
    const std::vector<IntT> seq{1, 2, 3, 4};
    std::vector<IntT> result;

    // First empty
    LongestCommonSubsequence(empty.begin(), empty.end(), seq.begin(), seq.end(),
                             std::back_inserter(result));
    EXPECT_THAT(result, IsEmpty());
    result.clear();

    // Second empty
    LongestCommonSubsequence(seq.begin(), seq.end(), empty.begin(), empty.end(),
                             std::back_inserter(result));
    EXPECT_THAT(result, IsEmpty());
    result.clear();

    // Same sequence
    LongestCommonSubsequence(seq.begin(), seq.end(), seq.begin(), seq.end(),
                             std::back_inserter(result));
    EXPECT_THAT(result, ElementsAre(1, 2, 3, 4));
  }
  {
    const std::vector<IntT> empty;
    const std::vector<IntT> first_seq{1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<IntT> second_seq{1, 2, 3, 4, 9, 10, 11, 12};
    std::vector<IntT> result;

    // Same prefix
    LongestCommonSubsequence(first_seq.begin(), first_seq.end(),
                             second_seq.begin(), second_seq.end(),
                             std::back_inserter(result));
    EXPECT_THAT(result, ElementsAre(1, 2, 3, 4));
  }
  {
    const std::vector<IntT> empty;
    const std::vector<IntT> first_seq{1,   2,   3, 4, 100, 101,
                                      102, 103, 5, 6, 7,   8};
    const std::vector<IntT> second_seq{9,   10,  11, 12, 100, 101,
                                       102, 103, 13, 14, 15,  16};
    std::vector<IntT> result;

    // Same length
    LongestCommonSubsequence(first_seq.begin(), first_seq.end(),
                             second_seq.begin(), second_seq.end(),
                             std::back_inserter(result));
    EXPECT_THAT(result, ElementsAre(100, 101, 102, 103));
  }
  {
    const std::vector<IntT> empty;
    const std::vector<IntT> first_seq{1,   2,   3,   4,   5, 6,  7,  8,
                                      100, 101, 102, 103, 9, 10, 11, 12};
    const std::vector<IntT> second_seq{13,  14,  15, 16, 100, 101,
                                       102, 103, 17, 18, 19,  20};
    std::vector<IntT> result;

    // First longer
    LongestCommonSubsequence(first_seq.begin(), first_seq.end(),
                             second_seq.begin(), second_seq.end(),
                             std::back_inserter(result));
    EXPECT_THAT(result, ElementsAre(100, 101, 102, 103));
    result.clear();

    // Second longer
    LongestCommonSubsequence(second_seq.begin(), second_seq.end(),
                             first_seq.begin(), first_seq.end(),
                             std::back_inserter(result));
    EXPECT_THAT(result, ElementsAre(100, 101, 102, 103));
  }
  {
    const std::vector<IntT> empty;
    const std::vector<IntT> first_seq{1,   2, 100, 101, 3,   4, 102,
                                      102, 5, 6,   103, 104, 7, 8};
    const std::vector<IntT> second_seq{9,  10,  11,  12, 100, 101, 13,
                                       14, 102, 102, 15, 16,  103, 104,
                                       15, 16,  17,  18, 19,  20};
    std::vector<IntT> result;

    // Interspersed, different length
    LongestCommonSubsequence(first_seq.begin(), first_seq.end(),
                             second_seq.begin(), second_seq.end(),
                             std::back_inserter(result));
    EXPECT_THAT(result, ElementsAre(100, 101, 102, 102, 103, 104));
  }
}

TEST(LongestCommonSubsequenceTest, OperateOnVectors) {
  // TODO(cblichmann): Use parametrized tests instead.
  TestLongestCommonSubsequenceOnVectors<uint8_t>();
  TestLongestCommonSubsequenceOnVectors<int8_t>();
  TestLongestCommonSubsequenceOnVectors<uint16_t>();
  TestLongestCommonSubsequenceOnVectors<int16_t>();
  TestLongestCommonSubsequenceOnVectors<uint32_t>();
  TestLongestCommonSubsequenceOnVectors<int32_t>();
  TestLongestCommonSubsequenceOnVectors<uint64_t>();
  TestLongestCommonSubsequenceOnVectors<int64_t>();
}

}  // namespace security::vxsig
