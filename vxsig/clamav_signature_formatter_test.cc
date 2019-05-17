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

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "third_party/zynamics/binexport/util/status_matchers.h"
#include "vxsig/signature_formatter.h"
#include "vxsig/signature_test_util.h"

using not_absl::IsOk;
using testing::Eq;

namespace security {
namespace vxsig {

class ClamAvSignatureFormatterTest : public ::testing::Test {
 protected:
  ClamAvSignatureFormatterTest()
      : formatter_(SignatureFormatter::Create(SignatureType::CLAMAV)) {}

  Signature signature_;
  std::unique_ptr<SignatureFormatter> formatter_;
};

TEST_F(ClamAvSignatureFormatterTest, TestEmpty) {
  auto* definition = signature_.mutable_definition();
  definition->set_detection_name("test");
  EXPECT_FALSE(formatter_->Format(&signature_).ok());
}

TEST_F(ClamAvSignatureFormatterTest, TestFirstSingleByte) {
  auto* definition = signature_.mutable_definition();
  definition->set_detection_name("test");
  definition->set_min_piece_length(2);
  AddSignaturePieces({"0", "12", "34"}, signature_.mutable_raw_signature());
  ASSERT_THAT(formatter_->Format(&signature_), IsOk());
  EXPECT_THAT(signature_.clam_av_signature().data(), Eq("test:0:*:3132*3334"));
}

TEST_F(ClamAvSignatureFormatterTest, TestStripSingleByte) {
  auto* definition = signature_.mutable_definition();
  definition->set_detection_name("test");
  AddSignaturePieces({"1234", "0", "5678"}, signature_.mutable_raw_signature());
  ASSERT_THAT(formatter_->Format(&signature_), IsOk());
  EXPECT_THAT(signature_.clam_av_signature().data(),
              Eq("test:0:*:31323334*35363738"));
}

TEST_F(ClamAvSignatureFormatterTest, TestDatabaseSingleSignature) {
  Signatures signatures;
  auto* signature = signatures.add_signature();
  signature->mutable_definition()->set_detection_name("one");
  signature->mutable_definition()->set_min_piece_length(2);
  AddSignaturePieces({"12", "34"}, signature->mutable_raw_signature());
  string database;
  EXPECT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  ASSERT_THAT(database, Eq("one:0:*:3132*3334\n"));
}

TEST_F(ClamAvSignatureFormatterTest, TestDatabaseMultipleSignatures) {
  Signatures signatures;
  {
    auto* signature = signatures.add_signature();
    signature->mutable_definition()->set_detection_name("one");
    signature->mutable_definition()->set_min_piece_length(2);
    AddSignaturePieces({"12", "34"}, signature->mutable_raw_signature());
  }
  {
    auto* signature = signatures.add_signature();
    signature->mutable_definition()->set_detection_name("two");
    signature->mutable_definition()->set_min_piece_length(2);
    AddSignaturePieces({"56", "78"}, signature->mutable_raw_signature());
  }
  string database;
  ASSERT_THAT(formatter_->FormatDatabase(signatures, &database), IsOk());
  EXPECT_THAT(database, Eq("one:0:*:3132*3334\ntwo:0:*:3536*3738\n"));
}

}  // namespace vxsig
}  // namespace security
