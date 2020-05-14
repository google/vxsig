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

#include "vxsig/yara_signature_formatter.h"

#include <algorithm>
#include <cstddef>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "third_party/zynamics/binexport/util/status_macros.h"
#include "vxsig/signature_formatter.h"
#include "vxsig/vxsig.pb.h"

ABSL_FLAG(bool, siggen_yara_debug_masking, false,
            "Include unmasked hex bytes in signature output");
ABSL_FLAG(bool, siggen_yara_debug_weights, false,
            "Include signature piece weights in output");

namespace security::vxsig {
namespace {

enum {
  kYaraMaxIdentLen = 128,  // Maximum length of an identifier

  kYaraMinTokens = 2,
  // See yara/limits.h, Yara has a hard limit of tokens per hexstring. Yara
  // considers two-digit hex numbers (a byte) and wildcards ([-]) as tokens.
  kYaraMaxHexStringTokens = 5000,
};

static constexpr char kYaraHexWildcard[] = "[-]";

std::string MakeValidIdentifier(absl::string_view identifier) {
  return absl::StrReplaceAll(identifier.substr(0, kYaraMaxIdentLen),
                             {{"-", "_"}});
}

}  // namespace

absl::Status YaraSignatureFormatter::DoFormat(Signature* signature) const {
  std::string* signature_data =
      signature->mutable_yara_signature()->mutable_data();
  // Avoid too many reallocations.
  signature_data->clear();
  signature_data->reserve(2 * signature->ByteSizeLong());

  auto signature_definition = signature->definition();

  // Rule name and tags
  std::string name = signature_definition.detection_name();
  if (name.empty()) {
    name = signature_definition.unique_signature_id();
  }
  absl::StrAppend(signature_data, "rule ", MakeValidIdentifier(name));
  if (signature_definition.tag_size() > 0) {
    bool first = true;
    for (const auto& tag : signature_definition.tag()) {
      absl::StrAppend(signature_data, first ? " : " : " ",
                      MakeValidIdentifier(tag));
      first = false;
    }
  }
  absl::StrAppend(signature_data, " {\n");

  if (signature_definition.meta_size() > 0) {
    // Metadata dictionary
    absl::StrAppend(signature_data, "  meta:\n");
    for (const auto& meta : signature_definition.meta()) {
      std::string value;
      switch (meta.value_case()) {
        case SignatureDefinition::Meta::kStringValue:
          value = absl::StrCat("\"", MakeValidIdentifier(meta.string_value()),
                               "\"");
          break;
        case SignatureDefinition::Meta::kIntValue:
          value = std::to_string(meta.int_value());
          break;
        case SignatureDefinition::Meta::kBoolValue:
          value = meta.bool_value() ? "true" : "false";
          break;
        case SignatureDefinition::Meta::VALUE_NOT_SET:
          continue;
      }
      absl::StrAppend(signature_data, "    ", meta.key(), " = ", value, "\n");
    }
  }

  // The actual regex signature.
  absl::StrAppend(signature_data, "  strings:\n    $ = {\n");

  RawSignature subset_regex;
  NA_RETURN_IF_ERROR(
      GetRelevantSignatureSubset(*signature, kYaraMinTokens, &subset_regex));

  int num_hex_string_tokens = 0;
  int max_copy_bytes = 0;
  bool needs_wildcard = false;
  for (const auto& piece : subset_regex.piece()) {
    if (num_hex_string_tokens > kYaraMaxHexStringTokens) {
      break;
    }
    // Append wildcard and hexadecimal signature piece.
    max_copy_bytes = kYaraMaxHexStringTokens - num_hex_string_tokens -
                     (needs_wildcard ? 1 : 0);
    if (max_copy_bytes < kYaraMinTokens) {
      // Break if the signature would become too long.
      break;
    }

    absl::StrAppend(signature_data, "      ");
    if (needs_wildcard) {
      absl::StrAppend(signature_data, kYaraHexWildcard);
      ++num_hex_string_tokens;  // Current wildcard
    } else {
      absl::StrAppend(signature_data,
                      std::string(strlen(kYaraHexWildcard), ' '));
    }

    const auto piece_bytes(piece.bytes().substr(0, max_copy_bytes));
    int start_mask = signature_data->size();
    absl::StrAppend(signature_data, absl::BytesToHexString(piece_bytes), "\n");
    for (const auto& masked_nibble : piece.masked_nibble()) {
      if (masked_nibble / 2 < max_copy_bytes) {
        (*signature_data)[start_mask + masked_nibble] = '?';
      }
    }
    if (absl::GetFlag(FLAGS_siggen_yara_debug_masking)) {
      // Align with masked hex bytes.
      absl::StrAppend(signature_data, "      // ",
                      absl::BytesToHexString(piece_bytes), "\n");
    }
    if (absl::GetFlag(FLAGS_siggen_yara_debug_weights)) {
      absl::StrAppend(signature_data, "         // Weight: ", piece.weight(),
                      "\n");
    }

    for (const auto& disassembly : piece.origin_disassembly()) {
      absl::StrAppend(signature_data, "         // ", disassembly, "\n");
    }

    needs_wildcard = true;
    num_hex_string_tokens += piece_bytes.size();
  }

  absl::StrAppend(signature_data, "\n  }\n  condition:\n    all of them\n}\n");
  return absl::OkStatus();
}

absl::Status YaraSignatureFormatter::DoFormatDatabase(
    const Signatures& signatures, std::string* database) const {
  database->clear();
  Signature format_signature;
  for (const auto& signature : signatures.signature()) {
    const auto* signature_data = &signature.yara_signature().data();
    Signature format_signature;
    if (signature_data->empty()) {
      format_signature = signature;
      NA_RETURN_IF_ERROR(Format(&format_signature));
      signature_data = &format_signature.yara_signature().data();
    }
    absl::StrAppend(database, *signature_data);
  }
  return absl::OkStatus();
}

}  // namespace security::vxsig
