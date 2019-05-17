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

#include "vxsig/common_subsequence.h"

#include <cstdint>
#include <iterator>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::ElementsAre;
using testing::Eq;
using testing::IsEmpty;
using testing::SizeIs;

namespace security {
namespace vxsig {

TEST(PruneSequenceTest, OperateOnStrings) {
  std::string keep;
  std::string result;

  // Empty string and alphabet.
  result.erase(
      PruneSequence(result.begin(), result.end(), keep.begin(), keep.end()),
      result.end());
  EXPECT_THAT(result, IsEmpty());

  // Empty alphabet.
  result = "stringthatgetspruned";
  result.erase(
      PruneSequence(result.begin(), result.end(), keep.begin(), keep.end()),
      result.end());
  EXPECT_THAT(result, IsEmpty());

  // Empty string.
  keep = "abcdefgh";
  result.erase(
      PruneSequence(result.begin(), result.end(), keep.begin(), keep.end()),
      result.end());
  EXPECT_THAT(result, IsEmpty());

  // Alphabet used in string.
  keep = "defimnot";
  result = "notmodified";
  result.erase(
      PruneSequence(result.begin(), result.end(), keep.begin(), keep.end()),
      result.end());
  EXPECT_THAT(result, Eq("notmodified"));
  result.clear();

  // Non-empty alphabet and string.
  keep = "abcdefgh";
  result = "abcdGETSREMOVEDefgh";
  result.erase(
      PruneSequence(result.begin(), result.end(), keep.begin(), keep.end()),
      result.end());
  EXPECT_THAT(result, Eq("abcdefgh"));
  result.clear();
}

template <typename IntT>
void TestPruneSubsequenceOnVectors() {
  std::vector<IntT> keep;
  std::vector<IntT> result;

  // Empty string and alphabet
  result.erase(
      PruneSequence(result.begin(), result.end(), keep.begin(), keep.end()),
      result.end());
  EXPECT_THAT(result, IsEmpty());

  {
    // Empty alphabet
    result = {1, 2, 3, 4};
    result.erase(
        PruneSequence(result.begin(), result.end(), keep.begin(), keep.end()),
        result.end());
    EXPECT_THAT(result, IsEmpty());
  }
  {
    // Empty string
    keep = {1, 2, 3, 4};
    result.erase(
        PruneSequence(result.begin(), result.end(), keep.begin(), keep.end()),
        result.end());
    EXPECT_THAT(result, IsEmpty());
  }
  {
    // Alphabet used in string.
    keep = {1, 2, 3, 4, 5, 6, 7, 8};
    result = {6, 7, 8, 5, 7, 1, 4, 3, 4, 2};
    result.erase(
        PruneSequence(result.begin(), result.end(), keep.begin(), keep.end()),
        result.end());
    EXPECT_THAT(result, ElementsAre(6, 7, 8, 5, 7, 1, 4, 3, 4, 2));
    result.clear();
  }
  {
    // Non-empty alphabet and string.
    keep = {1, 2, 3, 4, 5, 6, 7, 8};
    result = {1, 2, 3, 4, 100, 101, 102, 103, 5, 6, 7, 8};
    result.erase(
        PruneSequence(result.begin(), result.end(), keep.begin(), keep.end()),
        result.end());
    EXPECT_THAT(result, ElementsAre(1, 2, 3, 4, 5, 6, 7, 8));
  }
}

TEST(PruneSequenceTest, OperateOnVectors) {
  // TODO(cblichmann): Use parametrized tests.
  TestPruneSubsequenceOnVectors<uint8_t>();
  TestPruneSubsequenceOnVectors<int8_t>();
  TestPruneSubsequenceOnVectors<uint16_t>();
  TestPruneSubsequenceOnVectors<int16_t>();
  TestPruneSubsequenceOnVectors<uint32_t>();
  TestPruneSubsequenceOnVectors<int32_t>();
  TestPruneSubsequenceOnVectors<uint64_t>();
  TestPruneSubsequenceOnVectors<int64_t>();
}

std::string TestCommonSubsequence2(absl::string_view one,
                                   absl::string_view two) {
  std::string result;
  std::vector<std::string> seqs{std::string(one), std::string(two)};
  CommonSubsequence(seqs, std::back_inserter(result));
  return result;
}

TEST(CommonSubsequence, OperateOnTwoStrings) {
  EXPECT_THAT(TestCommonSubsequence2("", ""), IsEmpty());
  EXPECT_THAT(TestCommonSubsequence2("", "somestr"), IsEmpty());
  EXPECT_THAT(TestCommonSubsequence2("somestr", ""), IsEmpty());
  EXPECT_THAT(TestCommonSubsequence2("samestr", "samestr"), Eq("samestr"));
  EXPECT_THAT(TestCommonSubsequence2("sameprefixABC", "sameprefixDEF"),
              Eq("sameprefix"));
  EXPECT_THAT(TestCommonSubsequence2("ABCDcommonEFGH", "IJKLcommonMNOP"),
              Eq("common"));
  EXPECT_THAT(TestCommonSubsequence2("ABCDEFGHcommonIJKL", "MNOPcommonQRST"),
              Eq("common"));
  EXPECT_THAT(TestCommonSubsequence2("ABCDcommonEFGH", "IJKLMNOPcommonQRST"),
              Eq("common"));
  EXPECT_THAT(TestCommonSubsequence2("ABcoCDmmEFonGH", "IJKLcoMNmmOPonQRSTUV"),
              Eq("common"));
}

TEST(CommonSubSequence, OperateOnStrings) {
  {
    std::string result;
    std::vector<std::string> many_empty(10);
    CommonSubsequence(many_empty, std::back_inserter(result));
    EXPECT_THAT(result, IsEmpty());
  }
  {
    std::string result;
    std::vector<std::string> seqs;
    for (int i = 0; i < 10; ++i) {
      seqs.push_back("samestr");
    }
    CommonSubsequence(seqs, std::back_inserter(result));
    EXPECT_THAT(result, Eq("samestr"));
  }
  {
    std::string result;
    CommonSubsequence(
        std::vector<std::string>{
            "sameprefixABC", "sameprefixDEF", "sameprefixGHI", "sameprefixJKL",
            "sameprefixMNO", "sameprefixPQR", "sameprefixSTU", "sameprefixVWX",
            "sameprefixZYA", "sameprefixBCD"},
        std::back_inserter(result));
    EXPECT_THAT(result, Eq("sameprefix"));
  }
  {
    std::string result;
    CommonSubsequence(
        std::vector<std::string>{
            "AcommonB", "BCcommonDE", "DEFcommonGHI", "GHIJcommonKLMN",
            "KLMNOcommonPQRST", "PQRSTUcommonVWXYZA", "VWXYZABcommonCDEFGHI",
            "CDEFGHIJcommonKLMNOPQR", "KLMNOPQRScommonTUVWXYZAB",
            "TUVWXYZABCcommonDEFGHIJKLM"},
        std::back_inserter(result));
    EXPECT_THAT(result, Eq("common"));
  }
  {
    std::string result;
    CommonSubsequence(
        std::vector<std::string>{
            "AcoBmmConD", "DEcoFmmGonHI", "HIJcoKmmLonMNO", "MNOPcoQmmRonSTUV",
            "STUVWcoXmmYonZABCD", "ZABCDEcoFmmGonHIJKLM",
            "HIJKLMNcoOmmPonQRSTUVW", "QRSTUVWXcoYmmZonABCDEFGH",
            "ABCDEFGHIcoJmmKonLMNOPQRST", "LMNOPQRSTUcoVmmWonXYZABCDEFG"},
        std::back_inserter(result));
    EXPECT_THAT(result, Eq("common"));
  }
  {
    std::string result;
    CommonSubsequence(
        std::vector<std::string>{"ABCcommonDEF", "DEFccoommmmoonnGHI",
                                 "GHIcccooommmmmmooonnnJKL",
                                 "JKLccccoooommmmmmmmoooonnnnMNO"},
        std::back_inserter(result));
    EXPECT_THAT(result, Eq("common"));
  }
  {
    // Check kill set traversal
    std::string result;
    std::vector<std::string> seqs{"abcdef", "fabcde", "efabcd"};
    CommonSubsequence(seqs, std::back_inserter(result));
    EXPECT_THAT(result, Eq("abcd"));
  }
}

TEST(CommonSubsequence, PermutedTable) {
  enum { kNumCols = 100, kNumFunc = 1000 };

  // Create a kNumCols x kNumFunc table like so:
  // 0 1 2 3 4 5 6 7 8 9
  // 1 2 3 4 5 6 7 8 9 0
  // 2 3 4 5 6 7 8 9 0 1
  // 3 4 5 6 7 8 9 0 1 2
  // 4 5 6 7 8 9 0 1 2 3
  // ===================
  // 4 5 6 7 8 9         <- Common subsequence
  std::vector<std::vector<int>> seqs(kNumCols);
  int idx = 0;
  for (int i = 0; i < kNumCols; ++i) {
    seqs[i].resize(kNumFunc);
    for (int j = 0; j < kNumFunc; ++j) {
      seqs[i][j] = (j + idx) % kNumFunc;
    }
    ++idx;
  }

  std::vector<int> result;
  CommonSubsequence(seqs, std::back_inserter(result));
  EXPECT_THAT(result.size(), Eq(kNumFunc - kNumCols + 1));
  EXPECT_THAT(result.front(), Eq(kNumCols - 1));
  EXPECT_THAT(result.back(), Eq(kNumFunc - 1));
}

TEST(CommonSubsequence, SingleCandidate) {
  enum { kNumCols = 10, kNumFunc = 100 };

  // Create a kNumCols x kNumFunc table like so:
  // 1
  // 0 1 0 0 0 0 0 0 0 0
  // 0 0 1 0 0 0 0 0 0 0
  // 0 0 0 1 0 0 0 0 0 0
  // 0 0 0 0 1 0 0 0 0 0
  // ===================
  // 1                   <- Common subsequence
  std::vector<std::vector<int>> seqs(kNumCols);
  seqs[0].push_back(1);
  for (int i = 1; i < kNumCols; ++i) {
    for (int j = 0; j < kNumFunc; ++j) {
      seqs[i].push_back(i == j ? 1 : 0);
    }
  }
  std::vector<int> result;
  CommonSubsequence(seqs, std::back_inserter(result));
  EXPECT_THAT(result, SizeIs(1));
}

}  // namespace vxsig
}  // namespace security
