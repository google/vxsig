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

// Provides a function to build a generic (format-independent) byte signature 
// from a set of basic block candidates.

#ifndef VXSIG_GENERIC_SIGNATURE_H_
#define VXSIG_GENERIC_SIGNATURE_H_

#include "absl/status/statusor.h"
#include "vxsig/match_chain_table.h"
#include "vxsig/types.h"
#include "vxsig/vxsig.pb.h"

namespace security::vxsig {

// Builds a "proto signature" from a list of overlap-free basic block
// candidates. "Proto signature" in this context means a sequence of bytes
// augmented with generic, possibly bounded, wildcards. The
// disable_nibble_masking controls the handling of instruction immediate values.
// If false, immediate values are replaced with a fixed number of single-byte
// wildcards. Note that this relies on disassembly information being available
// in the input data.
// Runs of regular bytes shorter than min_piece_length will be penalized by
// setting their respective weights to zero. This is done, so that constructs
// like "[-] XX ?? ?? ?? ??" (Yara syntax) are less likely to be included in the
// final signature.
absl::StatusOr<RawSignature> GenericSignatureFromMatches(
    const MatchChainTable& table, const IdentSequence& bb_candidate_ids,
    bool disable_nibble_masking, int min_piece_length);

// Returns the size of the signature in bytes. It is defined as the sum of the
// sizes of all signature pieces in the raw signature data.
int GetSignatureSize(const Signature& signature);

}  // namespace security::vxsig

#endif  // VXSIG_GENERIC_SIGNATURE_H_
