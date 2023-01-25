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

#include "vxsig/signature_definition_hash.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::Eq;

namespace security::vxsig {

class SignatureDefinitionHashTest : public ::testing::Test {
 protected:
  SignatureDefinitionHashTest() : sig_def_() {
    sig_def_.add_signature_group("tag");
    sig_def_.set_timestamp(1234);
    // Do not set unique_signature_id.
    sig_def_.set_detection_name("a_virus");
    // sha256("one")
    sig_def_.add_item_id(
        "2c8b08da5ce60398e1f19af0e5dccc744df274b826abe585eaba68c525434806");
    // sha256("two")
    sig_def_.add_item_id(
        "27dd8ed44a83ff94d557f9fd0412ed5a8cbca69ea04922d88c01184a07300a5a");
    // sha256("three")
    sig_def_.add_item_id(
        "f6936912184481f5edd4c304ce27c5a1a827804fc7f329f43d273b8621870776");
    sig_def_.set_trim_algorithm(SignatureDefinition::TRIM_RANDOM);
    sig_def_.set_variant(5678);
  }

  SignatureDefinition sig_def_;
};

TEST_F(SignatureDefinitionHashTest, EmptyDefinition) {
  const SignatureDefinition empty_def;
  const SignatureDefinitionHasher hasher(empty_def);
  // Check default hashes for empty signature definition.
  EXPECT_THAT(hasher.GetSignatureIdPrefixUpToGroup(), Eq("sig_404f"));
  EXPECT_THAT(hasher.GetItemIdsHash(), Eq(0));
  EXPECT_THAT(hasher.GetSignatureIdPrefixUpToItemIdsHash(), Eq("sig_404f0000"));
  EXPECT_THAT(hasher.GetSignatureIdPrefixUpToVariant(), Eq("sig_404f00000000"));
  EXPECT_THAT(hasher.GetSignatureIdPrefixUpToParamsHash(),
              Eq("sig_404f00000000_404f"));
  EXPECT_THAT(hasher.GetSignatureId(0), Eq("sig_404f00000000_404f0000"));
}

TEST_F(SignatureDefinitionHashTest, ValidSignatureDefinition) {
  SignatureDefinitionHasher hasher(sig_def_);
  EXPECT_THAT(hasher.GetSignatureIdPrefixUpToGroup(), Eq("sig_63ad"));
  EXPECT_THAT(hasher.GetItemIdsHash(), Eq(6437905883382247082L));
  EXPECT_THAT(hasher.GetSignatureIdPrefixUpToItemIdsHash(), Eq("sig_63ad6eaa"));
  EXPECT_THAT(hasher.GetSignatureIdPrefixUpToVariant(), Eq("sig_63ad6eaa162e"));
  EXPECT_THAT(hasher.GetSignatureIdPrefixUpToParamsHash(),
              Eq("sig_63ad6eaa162e_0751"));
  EXPECT_THAT(hasher.GetSignatureId(0), Eq("sig_63ad6eaa162e_07510000"));
}

}  // namespace security::vxsig
