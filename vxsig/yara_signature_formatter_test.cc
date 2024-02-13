// Copyright 2011-2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

#include <fstream>
#include <memory>

#include "absl/log/die_if_null.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_join.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "third_party/zynamics/binexport/util/status_matchers.h"
#include "vxsig/signature_formatter.h"
#include "vxsig/yara_signature_test_util.h"

using not_absl::IsOk;
using testing::Eq;
using testing::IsTrue;

namespace security::vxsig {

class YaraSignatureFormatterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    definition_ = signature_.mutable_definition();
    formatter_ = SignatureFormatter::Create(SignatureType::YARA);
  }

  Signature signature_;
  SignatureDefinition* definition_;
  std::unique_ptr<SignatureFormatter> formatter_;
};

namespace {

enum { kYaraMaxHexStringTokens = 5000 };

void AddSignaturePieces(const std::vector<std::string>& pieces,
                        Signature* signature) {
  auto* raw = ABSL_DIE_IF_NULL(signature)->mutable_raw_signature();
  for (const auto& piece : pieces) {
    raw->add_piece()->set_bytes(piece);
  }
}

}  // namespace

TEST_F(YaraSignatureFormatterTest, TestEmpty) {
  definition_->set_detection_name("test");
  EXPECT_FALSE(formatter_->Format(&signature_).ok());
}

TEST_F(YaraSignatureFormatterTest, TestFirstSingleByte) {
  definition_->set_detection_name("test");
  definition_->set_min_piece_length(2);
  AddSignaturePieces({"0", "12", "34"}, &signature_);
  EXPECT_THAT(formatter_->Format(&signature_), IsOk());
  EXPECT_THAT(
      MakeComparableYaraSignature(signature_.yara_signature().data()),
      Eq("rule test {\nstrings:$ = {3132[-]3334}condition:all of them}"));
}

TEST_F(YaraSignatureFormatterTest, TestStripSingleByte) {
  definition_->set_detection_name("test");
  AddSignaturePieces({"1234", "0", "5678"}, &signature_);
  EXPECT_THAT(formatter_->Format(&signature_), IsOk());
  EXPECT_THAT(MakeComparableYaraSignature(signature_.yara_signature().data()),
              Eq("rule test {\nstrings:$ = {31323334[-]35363738}condition:all "
                 "of them}"));
}

TEST_F(YaraSignatureFormatterTest, TestDatabaseSingleSignature) {
  Signatures signatures;
  auto* signature = signatures.add_signature();
  signature->mutable_definition()->set_detection_name("one");
  signature->mutable_definition()->set_min_piece_length(2);
  AddSignaturePieces({"12", "34"}, signature);
  std::string database;
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  EXPECT_THAT(
      MakeComparableYaraSignature(database),
      Eq("rule one {\nstrings:$ = {3132[-]3334}condition:all of them}"));
}

TEST_F(YaraSignatureFormatterTest, TestDatabaseMultipleSignatures) {
  Signatures signatures;
  {
    auto* signature = signatures.add_signature();
    signature->mutable_definition()->set_detection_name("one");
    signature->mutable_definition()->set_min_piece_length(2);
    AddSignaturePieces({"12", "34"}, signature);
  }
  {
    auto* signature = signatures.add_signature();
    signature->mutable_definition()->set_detection_name("two");
    signature->mutable_definition()->set_min_piece_length(2);
    AddSignaturePieces({"56", "78"}, signature);
  }
  std::string database;
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  EXPECT_THAT(
      MakeComparableYaraSignature(database),
      Eq("rule one {\nstrings:$ = {3132[-]3334}condition:all of them}"
         "rule two {\nstrings:$ = {3536[-]3738}condition:all of them}"));
}

TEST_F(YaraSignatureFormatterTest, TestMaxHexStringTokensOnePiece) {
  Signatures signatures;
  {
    auto* signature = signatures.add_signature();
    signature->mutable_definition()->set_detection_name("one");
    *signature->mutable_raw_signature()->add_piece()->mutable_bytes() =
        std::string(
            2 /* Hex byte */ * (kYaraMaxHexStringTokens +
                                50 /* Arbitrary over-size of 50 bytes */),
            '1');
  }
  std::string database;
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  EXPECT_THAT(MakeComparableYaraSignature(database),
              Eq(absl::StrCat("rule one {\nstrings:$ = {",
                              absl::BytesToHexString(
                                  std::string(kYaraMaxHexStringTokens, '1')),
                              "}condition:all of them}")));
}

TEST_F(YaraSignatureFormatterTest, TestMaxHexStringTokensTwoPiece) {
  Signatures signatures;
  {
    auto* signature = signatures.add_signature();
    signature->mutable_definition()->set_detection_name("two");
    *signature->mutable_raw_signature()->add_piece()->mutable_bytes() =
        std::string(kYaraMaxHexStringTokens / 2, '1');
    *signature->mutable_raw_signature()->add_piece()->mutable_bytes() =
        std::string(kYaraMaxHexStringTokens / 2 - 1, '2');
  }
  std::string database;
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  EXPECT_THAT(MakeComparableYaraSignature(database),
              Eq(absl::StrCat("rule two {\nstrings:$ = {",
                              absl::BytesToHexString(std::string(
                                  kYaraMaxHexStringTokens / 2, '1')),
                              "[-]",
                              absl::BytesToHexString(std::string(
                                  kYaraMaxHexStringTokens / 2 - 1, '2')),
                              "}condition:all of them}")));
}

TEST_F(YaraSignatureFormatterTest, TestRealSignature) {
  Signatures signatures;
  std::ifstream file("vxsig/testdata/livid1.db", std::ios_base::binary);
  google::protobuf::io::IstreamInputStream from(&file);
  ASSERT_THAT(google::protobuf::TextFormat::Parse(&from, &signatures),
              IsTrue());

  std::string database;
  // Force reformatting.
  signatures.mutable_signature(0)->clear_yara_signature();
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
}

TEST_F(YaraSignatureFormatterTest, TestSingleTag) {
  Signatures signatures;
  {
    auto* signature = signatures.add_signature();
    auto* definition = signature->mutable_definition();
    definition->set_detection_name("has_tags");
    definition->add_tag("one");
    *signature->mutable_raw_signature()->add_piece()->mutable_bytes() = "1234";
  }
  std::string database;
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  EXPECT_THAT(MakeComparableYaraSignature(database),
              Eq(absl::StrCat(
                  "rule has_tags : one {\nstrings:$ = {31323334}condition:all "
                  "of them}")));
}

TEST_F(YaraSignatureFormatterTest, TestMultipleTags) {
  Signatures signatures;
  {
    auto* signature = signatures.add_signature();
    auto* definition = signature->mutable_definition();
    definition->set_detection_name("has_tags");
    definition->add_tag("one");
    definition->add_tag("two");
    *signature->mutable_raw_signature()->add_piece()->mutable_bytes() = "1234";
  }
  std::string database;
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  EXPECT_THAT(MakeComparableYaraSignature(database),
              Eq("rule has_tags : one two {\nstrings:$ = "
                 "{31323334}condition:all of them}"));
}

TEST_F(YaraSignatureFormatterTest, TestMetaSingleStringValue) {
  Signatures signatures;
  {
    auto* signature = signatures.add_signature();
    auto* definition = signature->mutable_definition();
    definition->set_detection_name("with_meta");
    auto* value = definition->add_meta();
    value->set_key("one");
    value->set_string_value("string");
    *signature->mutable_raw_signature()->add_piece()->mutable_bytes() = "1234";
  }
  std::string database;
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  EXPECT_THAT(MakeComparableYaraSignature(database),
              Eq("rule with_meta {meta:one = \"string\"\nstrings:$ = "
                 "{31323334}condition:all of them}"));
}

TEST_F(YaraSignatureFormatterTest, TestMetaSingleMultiValue) {
  Signatures signatures;
  {
    auto* signature = signatures.add_signature();
    auto* definition = signature->mutable_definition();
    definition->set_detection_name("with_meta");
    auto* value = definition->add_meta();
    value->set_key("one");
    value->set_int_value(42);
    value->set_bool_value(false);
    *signature->mutable_raw_signature()->add_piece()->mutable_bytes() = "1234";
  }
  std::string database;
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  EXPECT_THAT(MakeComparableYaraSignature(database),
              Eq("rule with_meta {meta:one = false\nstrings:$ = "
                 "{31323334}condition:all of them}"));
}

TEST_F(YaraSignatureFormatterTest, TestMetaMultipleValues) {
  Signatures signatures;
  {
    auto* signature = signatures.add_signature();
    auto* definition = signature->mutable_definition();
    definition->set_detection_name("with_meta");
    auto* value = definition->add_meta();
    value->set_key("one");
    value->set_string_value("first");
    value = definition->add_meta();
    value->set_key("two");
    value->set_string_value("second");
    *signature->mutable_raw_signature()->add_piece()->mutable_bytes() = "1234";
  }
  std::string database;
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  EXPECT_THAT(MakeComparableYaraSignature(database),
              Eq("rule with_meta {meta:one = \"first\"two = \"second\"\n"
                 "strings:$ = {31323334}condition:all of them}"));
}

}  // namespace security::vxsig
