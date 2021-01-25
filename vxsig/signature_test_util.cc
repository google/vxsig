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

#include "vxsig/signature_test_util.h"

#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "vxsig/vxsig.pb.h"

namespace security::vxsig {

void AddSignaturePieces(absl::Span<const std::string> pieces,
                        RawSignature* raw_signature) {
  for (const auto& piece : pieces) {
    raw_signature->add_piece()->set_bytes(piece);
  }
}

std::unique_ptr<RawSignature> MakeRawSignature(
    absl::Span<const std::string> pieces) {
  auto raw_signature(absl::make_unique<RawSignature>());
  AddSignaturePieces(pieces, raw_signature.get());
  return raw_signature;
}

bool EquivRawSignature(const RawSignature& actual,
                       const RawSignature& expected) {
  bool result = expected.piece_size() == actual.piece_size();
  if (result) {
    for (int i = 0; i < expected.piece_size(); ++i) {
      result = expected.piece(i).bytes() == actual.piece(i).bytes();
      if (!result) {
        break;
      }
    }
  }
  if (!result) {
    std::string expected_pieces;
    for (const auto& piece : expected.piece()) {
      absl::StrAppend(&expected_pieces, absl::BytesToHexString(piece.bytes()),
                      " ");
    }
    std::string actual_pieces;
    for (const auto& piece : actual.piece()) {
      absl::StrAppend(&actual_pieces, absl::BytesToHexString(piece.bytes()),
                      " ");
    }
    absl::PrintF("EquivRawSignature Expected: %s\n", expected_pieces);
    absl::PrintF("                  Actual:   %s\n", actual_pieces);
  }
  return result;
}

}  // namespace security::vxsig
