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

#include <string>

#include "absl/status/status.h"
#include "vxsig/signature_formatter.h"
#include "vxsig/vxsig.pb.h"

namespace security::vxsig {

// This class inherits from SignatureFormatter to implement the ClamAV AV
// signature format. See http://www.clamav.net/doc/latest/signatures.pdf for
// details.
class ClamAvSignatureFormatter : public SignatureFormatter {
 private:
  absl::Status DoFormat(Signature* signature) const override;

  absl::Status DoFormatDatabase(const Signatures& signatures,
                                std::string* database) const override;
};

}  // namespace security::vxsig
