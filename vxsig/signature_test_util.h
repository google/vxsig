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

#ifndef VXSIG_SIGNATURE_TEST_UTIL_H_
#define VXSIG_SIGNATURE_TEST_UTIL_H_

#include <memory>
#include <string>

#include "absl/types/span.h"

namespace security {
namespace vxsig {

class RawSignature;

void AddSignaturePieces(absl::Span<const std::string> pieces,
                        RawSignature* raw_signature);

std::unique_ptr<RawSignature> MakeRawSignature(
    absl::Span<const std::string> pieces);

bool EquivRawSignature(const RawSignature& actual,
                       const RawSignature& expected);

}  // namespace vxsig
}  // namespace security

#endif  // VXSIG_SIGNATURE_TEST_UTIL_H_
