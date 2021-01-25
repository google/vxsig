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

// A program that implements AV signature generation from sets of binaries.
// Siggen operates on similar binaries that have been bindiffed pairwise.

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <limits>
#include <memory>
#include <string>

#include "absl/base/internal/raw_logging.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/memory/memory.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "vxsig/siggen.h"
#include "vxsig/signature_formatter.h"
#include "vxsig/types.h"
#include "vxsig/vxsig.pb.h"

ABSL_FLAG(std::string, detection_name, "VxSig_Signature",
          "Detection name of the signature");
ABSL_FLAG(int32_t, trim_length, std::numeric_limits<int32_t>::max(),
          "Maximum length of the signature, subject to truncation of due to "
          "limitations of the target format");
ABSL_FLAG(std::string, trim_algorithm, "TRIM_RANDOM",
          "Signature trimming algorithm to use");
ABSL_FLAG(bool, disable_nibble_masking, false,
          "Whether or not to disable masking of instruction immediate bytes");
ABSL_FLAG(std::string, function_includes, "",
          "List of (hex) addresses of functions in the first binary to "
          "consider for the signature. Mutually exclusive with "
          "function_excludes.");
ABSL_FLAG(std::string, function_excludes, "", "Inverse of function_includes");

namespace security::vxsig {
namespace {

void SiggenMain(int argc, char* argv[]) {
  ABSL_RAW_CHECK(argc >= 2, "Need at least one .BinDiff file");

  auto trim_algorithm = SignatureDefinition::TRIM_NONE;
  if (!SignatureDefinition::SignatureTrimAlgorithm_Parse(
          absl::GetFlag(FLAGS_trim_algorithm), &trim_algorithm)) {
    ABSL_RAW_LOG(FATAL, "Invalid signature trimming algorithm: %s",
                 absl::GetFlag(FLAGS_trim_algorithm).c_str());
  }

  ABSL_RAW_CHECK(
      absl::GetFlag(FLAGS_function_includes).empty() ||
          absl::GetFlag(FLAGS_function_excludes).empty(),
      "function_includes and function_excludes are mutually exclusive");

  Signature signature;
  auto& signature_definition = *signature.mutable_definition();
  signature_definition.set_detection_name(absl::GetFlag(FLAGS_detection_name));
  signature_definition.set_trim_length(absl::GetFlag(FLAGS_trim_length));
  signature_definition.set_trim_algorithm(trim_algorithm);
  signature_definition.set_disable_nibble_masking(
      absl::GetFlag(FLAGS_disable_nibble_masking));
  signature_definition.set_function_filter(SignatureDefinition::FILTER_NONE);

  std::string filter_list = absl::GetFlag(FLAGS_function_includes);
  if (!filter_list.empty()) {
    signature_definition.set_function_filter(
        SignatureDefinition::FILTER_INCLUDE);
  } else {
    signature_definition.set_function_filter(
        SignatureDefinition::FILTER_EXCLUDE);
    filter_list = absl::GetFlag(FLAGS_function_excludes);
  }
  if (!filter_list.empty()) {
    uint64_t address = 0;
    for (const auto& function :
         absl::StrSplit(filter_list, ',', absl::SkipWhitespace())) {
      ABSL_RAW_CHECK(
          absl::numbers_internal::safe_strtou64_base(function, &address, 16),
          "Failed to parse hex address in function filter");
      signature_definition.add_filtered_function_address(address);
    }
  }

  AvSignatureGenerator siggen;
  siggen.AddDiffResultsFromCommandLineArguments(--argc, ++argv);
  absl::Status status(siggen.Generate(&signature));
  ABSL_RAW_CHECK(
      status.ok(),
      absl::StrCat("Failed to generate signature: ", status.message()).c_str());

  // Output the signature itself to stdout, so we can use redirected output
  // from this tool in scripts.
  std::cout << "----8<--------8<---- Signature ----8<--------8<----\n";
  status = SignatureFormatter::Create(YARA)->Format(&signature);
  ABSL_RAW_CHECK(
      status.ok(),
      absl::StrCat("Failed to format signature: ", status.message()).c_str());
  printf("%s\n", signature.yara_signature().data().c_str());
  std::cout << "---->8-------->8---- Signature ---->8-------->8----\n";
}

}  // namespace
}  // namespace security::vxsig

int main(int argc, char* argv[]) {
  absl::SetProgramUsageMessage(absl::StrCat(
      "Automatically generate byte-signature for sets of binaires.\n"
      "usage:\n",
      argv[0], " [OPTION] BINDIFF..."));
  std::vector<char*> args = absl::ParseCommandLine(argc, argv);
  security::vxsig::SiggenMain(args.size(), &args[0]);
  return EXIT_SUCCESS;
}
