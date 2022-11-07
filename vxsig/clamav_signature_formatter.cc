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

#include "vxsig/clamav_signature_formatter.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "third_party/zynamics/binexport/util/status_macros.h"

namespace security::vxsig {
namespace {

enum {
  kClamAvMinBytes = 2,
  // ClamAV's line buffer for reading .ndb signatures appears to be 8192 bytes
  // long, but this includes the trailing newline character.
  kClamAvMaxLineLen = 8191
};

static constexpr char kClamAvWildcard[] = "*";

}  // namespace

absl::Status ClamAvSignatureFormatter::DoFormat(Signature* signature) const {
  std::string* signature_data =
      signature->mutable_clam_av_signature()->mutable_data();

  // Avoid too many reallocations.
  signature_data->clear();
  signature_data->reserve(static_cast<int>(kClamAvMaxLineLen));

  absl::StrAppend(signature_data, signature->definition().detection_name(),
                  ":0:*:");

  RawSignature subset_regex;
  NA_RETURN_IF_ERROR(
      GetRelevantSignatureSubset(*signature, kClamAvMinBytes, &subset_regex));

  int max_copy_bytes = 0;
  bool needs_wildcard = false;
  for (const auto& piece : subset_regex.piece()) {
    // Append wildcard and hexadecimal signature piece.
    max_copy_bytes = (kClamAvMaxLineLen - signature_data->size() -
                      (needs_wildcard ? ABSL_ARRAYSIZE(kClamAvWildcard) : 0)) /
                     2 /* Two hex bytes per byte */;
    if (max_copy_bytes < kClamAvMinBytes) {
      // Break if the signature would become longer than 8191 bytes (including
      // signature name), this is a ClamAV limitation.
      break;
    }
    if (needs_wildcard) {
      absl::StrAppend(signature_data, kClamAvWildcard);
    }
    const auto piece_bytes(piece.bytes().substr(0, max_copy_bytes));
    int start_mask = signature_data->size();
    absl::StrAppend(signature_data, absl::BytesToHexString(piece_bytes));
    for (const auto& masked_nibble : piece.masked_nibble()) {
      if (masked_nibble / 2 < max_copy_bytes) {
        (*signature_data)[start_mask + masked_nibble] = '?';
      }
    }
    needs_wildcard = true;
  }
  // A return value of false can only happen if the detection name is overly
  // long.
  if (signature_data->size() > kClamAvMaxLineLen) {
    return absl::OutOfRangeError(
        absl::StrCat("Signature data size too long: ", signature_data->size(),
                     " > ", kClamAvMaxLineLen));
  }
  return absl::OkStatus();
}

absl::Status ClamAvSignatureFormatter::DoFormatDatabase(
    const Signatures& signatures, std::string* database) const {
  if (!database) {
    return absl::InvalidArgumentError("Database must not be nullptr");
  }
  Signature format_signature;
  for (const auto& signature : signatures.signature()) {
    const auto* signature_data = &signature.clam_av_signature().data();
    if (signature_data->empty()) {
      format_signature = signature;
      NA_RETURN_IF_ERROR(Format(&format_signature));
      signature_data = &format_signature.clam_av_signature().data();
    }
    absl::StrAppend(database, *signature_data, "\n");
  }
  return absl::OkStatus();
}

}  // namespace security::vxsig
