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

#include "vxsig/signature_formatter.h"

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "third_party/zynamics/binexport/util/status_matchers.h"
#include "vxsig/signature_test_util.h"
#include "vxsig/vxsig.pb.h"

using not_absl::IsOk;
using testing::Eq;
using testing::IsTrue;

namespace security::vxsig {
namespace {

class SignatureFormatterTest : public ::testing::Test {
 protected:
  SignatureFormatterTest()
      : signature_(), sig_def_(signature_.mutable_definition()) {
    sig_def_->clear_signature_group();
    sig_def_->add_signature_group("test");
    sig_def_->set_variant(5678);
  }

  Signature signature_;
  SignatureDefinition* sig_def_;
  RawSignature raw_signature_;
};

TEST_F(SignatureFormatterTest, EmptyPiece) {
  *signature_.mutable_raw_signature() = *MakeRawSignature({});
  raw_signature_.Clear();
  auto status = GetRelevantSignatureSubset(signature_, 0, &raw_signature_);
  EXPECT_FALSE(status.ok());
}

TEST_F(SignatureFormatterTest, TrimFirst) {
  *signature_.mutable_raw_signature() =
      *MakeRawSignature({"00", "11", "22", "33", "44", "55", "66", "77"});
  raw_signature_.Clear();
  sig_def_->set_min_piece_length(2);
  sig_def_->set_trim_algorithm(SignatureDefinition::TRIM_FIRST);
  sig_def_->set_trim_length(8);
  ASSERT_THAT(GetRelevantSignatureSubset(signature_, /*engine_min_piece_len=*/0,
                                         &raw_signature_),
              IsOk());
  EXPECT_THAT(raw_signature_.piece_size(), Eq(4));
  EXPECT_THAT(EquivRawSignature(raw_signature_,
                                *MakeRawSignature({"44", "55", "66", "77"})),
              IsTrue());
}

TEST_F(SignatureFormatterTest, TrimLast) {
  *signature_.mutable_raw_signature() =
      *MakeRawSignature({"00", "11", "22", "33", "44", "55", "66", "77"});
  raw_signature_.Clear();
  sig_def_->set_min_piece_length(2);
  sig_def_->set_trim_algorithm(SignatureDefinition::TRIM_LAST);
  sig_def_->set_trim_length(8);
  ASSERT_THAT(GetRelevantSignatureSubset(signature_, /*engine_min_piece_len=*/0,
                                         &raw_signature_),
              IsOk());
  EXPECT_THAT(raw_signature_.piece_size(), Eq(4));
  EXPECT_THAT(EquivRawSignature(raw_signature_,
                                *MakeRawSignature({"00", "11", "22", "33"})),
              IsTrue());
}

TEST_F(SignatureFormatterTest, TrimRandom) {
  *signature_.mutable_raw_signature() =
      *MakeRawSignature({"00", "11", "22", "33", "44", "55", "66", "77"});
  {
    raw_signature_.Clear();
    sig_def_->set_min_piece_length(2);
    sig_def_->set_trim_algorithm(SignatureDefinition::TRIM_RANDOM);
    sig_def_->set_trim_length(8);
    ASSERT_THAT(GetRelevantSignatureSubset(
                    signature_, /*engine_min_piece_len=*/0, &raw_signature_),
                IsOk());
    EXPECT_THAT(raw_signature_.piece_size(), Eq(4));
    EXPECT_THAT(EquivRawSignature(raw_signature_,
                                  *MakeRawSignature({"33", "44", "55", "66"})),
                IsTrue());
  }
  {
    raw_signature_.Clear();
    sig_def_->set_min_piece_length(2);
    sig_def_->set_trim_algorithm(SignatureDefinition::TRIM_RANDOM);
    sig_def_->set_trim_length(8);
    sig_def_->set_variant(4242);
    ASSERT_THAT(GetRelevantSignatureSubset(
                    signature_, /*engine_min_piece_len=*/0, &raw_signature_),
                IsOk());
    EXPECT_THAT(raw_signature_.piece_size(), Eq(4));
    EXPECT_THAT(EquivRawSignature(raw_signature_,
                                  *MakeRawSignature({"22", "33", "55", "66"})),
                IsTrue());
  }
}

TEST_F(SignatureFormatterTest, DISABLED_TrimWeighted) {
  auto& raw_signature = *signature_.mutable_raw_signature();
  raw_signature =
      *MakeRawSignature({"00", "11", "22", "33", "44", "55", "66", "77"});
  for (int i = 0; i < raw_signature.piece_size(); ++i) {
    raw_signature.mutable_piece(i)->set_weight(i % 2 == 0 ? 1000 : 10);
  }

  sig_def_->set_min_piece_length(2);
  sig_def_->set_trim_algorithm(SignatureDefinition::TRIM_WEIGHTED);
  sig_def_->set_trim_length(8);
  ASSERT_THAT(GetRelevantSignatureSubset(signature_, /*engine_min_piece_len=*/0,
                                         &raw_signature_),
              IsOk());
  EXPECT_THAT(raw_signature_.piece_size(), Eq(4));

  auto expected(MakeRawSignature({"00", "22", "44", "66"}));
  for (auto& piece : *expected->mutable_piece()) {
    piece.set_weight(1000);
  }
  EXPECT_THAT(EquivRawSignature(raw_signature_, *expected), IsTrue());
}

TEST_F(SignatureFormatterTest, DISABLED_TrimWeightOrder) {
  auto& raw_signature = *signature_.mutable_raw_signature();
  raw_signature =
      *MakeRawSignature({"00", "11", "22", "33", "44", "55", "66", "77"});
  for (int i = 0; i < raw_signature.piece_size(); ++i) {
    raw_signature.mutable_piece(i)->set_weight(i % 2 == 0 ? 1000 : 10);
  }

  sig_def_->set_min_piece_length(2);
  sig_def_->set_trim_algorithm(SignatureDefinition::TRIM_WEIGHTED_GREEDY);
  sig_def_->set_trim_length(8);
  ASSERT_THAT(GetRelevantSignatureSubset(signature_, /*engine_min_piece_len=*/0,
                                         &raw_signature_),
              IsOk());
  EXPECT_THAT(raw_signature_.piece_size(), Eq(4));

  auto expected(MakeRawSignature({"00", "22", "44", "66"}));
  for (auto& piece : *expected->mutable_piece()) {
    piece.set_weight(1000);
  }
  EXPECT_THAT(EquivRawSignature(raw_signature_, *expected), IsTrue());
}

TEST_F(SignatureFormatterTest, DISABLED_TrimWeightOrderPreferLongerPieces) {
  auto& raw_signature = *signature_.mutable_raw_signature();
  raw_signature = *MakeRawSignature({"00000", "111", "222"});
  for (int i = 0; i < raw_signature.piece_size(); ++i) {
    raw_signature.mutable_piece(i)->set_weight(10);
  }

  sig_def_->set_min_piece_length(2);
  sig_def_->set_trim_algorithm(SignatureDefinition::TRIM_WEIGHTED_GREEDY);
  sig_def_->set_trim_length(6);
  ASSERT_THAT(GetRelevantSignatureSubset(signature_, /*engine_min_piece_len=*/0,
                                         &raw_signature_),
              IsOk());
  EXPECT_THAT(raw_signature_.piece_size(), Eq(1));

  auto expected(MakeRawSignature({"00000"}));
  for (auto& piece : *expected->mutable_piece()) {
    piece.set_weight(10);
  }
  EXPECT_THAT(EquivRawSignature(raw_signature_, *expected), IsTrue());
}

}  // namespace
}  // namespace security::vxsig
