// Copyright 2011-2021 Google LLC
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

#include "vxsig/signature_definition_hash.h"

#include "absl/hash/hash.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"

namespace security::vxsig {
namespace {

constexpr char kSignatureItemPrefix[] = "sig_";

// Utility function that appends a truncated 4 hex character representation of
// the specified value to a string. If the hex representation of value is
// shorter than 4 characters, it is left-padded with zeroes.
template <typename IntT>
void StringAppendShortenedHexInt(std::string* result, IntT value) {
  absl::StrAppendFormat(result, "%04x", static_cast<size_t>(value) % 0x10000);
}

}  // namespace

SignatureDefinitionHasher::SignatureDefinitionHasher(
    const SignatureDefinition& sig_def)
    : sig_def_(sig_def) {}

SignatureDefinitionHasher::SignatureDefinitionHasher(absl::string_view group,
                                                     int32_t variant)
    : SignatureDefinitionHasher(SignatureDefinition()) {
  sig_def_.clear_signature_group();
  sig_def_.add_signature_group(std::string(group));
  sig_def_.set_variant(variant);
}

std::string SignatureDefinitionHasher::GetSignatureIdPrefixUpToGroup() const {
  std::string result(kSignatureItemPrefix);
  std::string group(
      sig_def_.signature_group_size() > 0 ? sig_def_.signature_group(0) : "");
  StringAppendShortenedHexInt(
      &result, absl::hash_internal::CityHash64(group.c_str(), group.size()));
  return result;
}

size_t SignatureDefinitionHasher::GetItemIdsHash() const {
  size_t result = 0;
  for (const auto& item_id : sig_def_.item_id()) {
    result ^= absl::hash_internal::CityHash64(item_id.c_str(), item_id.size());
  }
  return result;
}

std::string SignatureDefinitionHasher::GetSignatureIdPrefixUpToItemIdsHash()
    const {
  std::string result(GetSignatureIdPrefixUpToGroup());
  StringAppendShortenedHexInt(&result, GetItemIdsHash());
  return result;
}

std::string SignatureDefinitionHasher::GetSignatureIdPrefixUpToVariant() const {
  std::string result(GetSignatureIdPrefixUpToItemIdsHash());
  StringAppendShortenedHexInt(&result, sig_def_.variant());
  return result;
}

std::string SignatureDefinitionHasher::GetSignatureIdPrefixUpToParamsHash()
    const {
  std::string result(GetSignatureIdPrefixUpToVariant());
  SignatureDefinition def_copy(sig_def_);
  def_copy.clear_unique_signature_id();
  def_copy.clear_item_id();  // Those have been included in the hash already.
  result.append("_");
  std::string copy = def_copy.SerializeAsString();
  StringAppendShortenedHexInt(
      &result, absl::hash_internal::CityHash64(copy.c_str(), copy.size()));
  return result;
}

std::string SignatureDefinitionHasher::GetSignatureId(int32_t rand) const {
  std::string result(GetSignatureIdPrefixUpToParamsHash());
  StringAppendShortenedHexInt(&result, rand);
  return result;
}

}  // namespace security::vxsig
