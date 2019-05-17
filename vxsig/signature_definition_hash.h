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

#ifndef VXSIG_SIGNATURE_DEFINITION_HASH_H_
#define VXSIG_SIGNATURE_DEFINITION_HASH_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/strings/string_view.h"
#include "vxsig/vxsig.pb.h"

namespace security {
namespace vxsig {

// A utility class to generate unique signature id prefixes out of a given
// signature definition.
// Signature ids have the following form (all numbers are in hex):
//  +------------------------- Prefix string
//  |   +--------------------- Hash of signature group name
//  |   |   +----------------- Hash over item ids
//  |   |   |   +------------- Signature variant
//  |   |   |   |   +--------- Separator
//  |   |   |   |   |+-------- Hash of serialized signature parameters
//  |   |   |   |   ||   +---- Random signature id
//  v   v   v   v   vv   v
//  sig_735d162eb0c6_31540000
//
// This way, a query for related signatures from a signature group is a
// prefix query. Same goes for a query for variants of a signature for the
// purposes of distributing randomized signatures.
class SignatureDefinitionHasher {
 public:
  explicit SignatureDefinitionHasher(const SignatureDefinition& sig_def);
  SignatureDefinitionHasher(absl::string_view group, int32_t variant);

  SignatureDefinitionHasher() = delete;
  SignatureDefinitionHasher(const SignatureDefinitionHasher&) = delete;

  SignatureDefinitionHasher& operator=(const SignatureDefinitionHasher&) =
      delete;

  std::string GetSignatureIdPrefixUpToGroup() const;

  size_t GetItemIdsHash() const;

  std::string GetSignatureIdPrefixUpToItemIdsHash() const;
  std::string GetSignatureIdPrefixUpToVariant() const;
  std::string GetSignatureIdPrefixUpToParamsHash() const;
  std::string GetSignatureId(int32_t rand) const;

 private:
  SignatureDefinition sig_def_;
};

}  // namespace vxsig
}  // namespace security

#endif  // VXSIG_SIGNATURE_DEFINITION_HASH_H_
