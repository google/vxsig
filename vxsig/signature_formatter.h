// Copyright 2011-2019 Google LLC
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

// This header contains a class that allows to convert raw signatures into
// concrete AV signature formats.

#ifndef VXSIG_SIGNATURE_FORMATTER_H_
#define VXSIG_SIGNATURE_FORMATTER_H_

#include <map>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "third_party/zynamics/binexport/util/status.h"
#include "vxsig/types.h"
#include "vxsig/vxsig.pb.h"

namespace security {
namespace vxsig {

// The SignatureFormatter class allows to convert raw signatures into a target
// signature format. It follows the factory pattern to instantiate formatters
// for specific formats.
class SignatureFormatter {
 public:
  SignatureFormatter(const SignatureFormatter&) = delete;
  SignatureFormatter& operator=(const SignatureFormatter&) = delete;

  // Empty destructor for deriving classes.
  virtual ~SignatureFormatter() = default;

  // Creates a new SignatureFormatter for the specified signature format, as
  // defined in //security/vxclass/proto/siggen.proto.
  static std::unique_ptr<SignatureFormatter> Create(SignatureType type);

  // Formats the specified raw signature into an engine-specific signature
  // Will fill the type specific fields of "signature". Returns false on error.
  // The content of "signature" is undefined at that point.
  not_absl::Status Format(Signature* signature) const;

  // Like above, but combine multiple signatures into one signature database of
  // the target format.
  not_absl::Status FormatDatabase(const Signatures& signatures,
                                  std::string* database) const;

 protected:
  // Make constructor accessible from the deriving formatter classes.
  SignatureFormatter() = default;

 private:
  // These perform the actual formatting.
  virtual not_absl::Status DoFormat(Signature* signature) const = 0;
  virtual not_absl::Status DoFormatDatabase(const Signatures& signatures,
                                            std::string* database) const = 0;
};

// Checks the truncation strategy and fills the relevant signature subset into
// an output RawSignature.
not_absl::Status GetRelevantSignatureSubset(const Signature& input,
                                        int engine_min_piece_len,
                                        RawSignature* output);

}  // namespace vxsig
}  // namespace security

#endif  // VXSIG_SIGNATURE_FORMATTER_H_
