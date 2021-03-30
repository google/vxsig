// Copyright 2019-2021 Google LLC
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

#ifndef VXSIG_YARA_SIGNATURE_TEST_UTIL_H_
#define VXSIG_YARA_SIGNATURE_TEST_UTIL_H_

#include <string>

namespace security::vxsig {

std::string MakeComparableYaraSignature(const std::string& data);

}  // namespace security::vxsig

#endif  // VXSIG_YARA_SIGNATURE_TEST_UTIL_H_
