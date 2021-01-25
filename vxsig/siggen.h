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

// The AvSignatureGenerator class encapsulates the whole workflow of generating
// AV signatures from a set of BinDiff result files and associated BinExport
// files.
// Use like this:
//  vxsig::AvSignatureGenerator siggen;
//  QCHECK_OK(siggen.AddDiffResultsFromCommandLineArguments(--argc, ++argv));
//  QCHECK_OK(siggen.Generate());
//  // Format and print signature, write to file, etc.
//  // Use the SignatureFormatter class for further processing.

#ifndef VXSIG_SIGGEN_H_
#define VXSIG_SIGGEN_H_

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/types/span.h"
#include "vxsig/generic_signature.h"
#include "vxsig/match_chain_table.h"
#include "vxsig/types.h"
#include "vxsig/vxsig.pb.h"

namespace security::vxsig {

// This class provides methods to conveniently create AV signatures from
// BinDiff result files and associated BinExport files.
// For the signature generation to work, the binaries that have been bindiffed
// should form a chain. For example, given this set of binaries
//   sshd.trojan1  sshd.trojan2  sshd.trojan3
// and their associated BinExport files
//   sshd.trojan1.BinExport  sshd.trojan2.BinExport  sshd.trojan3.BinExport
// bindiffing in a chain gives
//   sshd.trojan1_vs_sshd.trojan2.BinDiff  sshd.trojan2_vs_sshd.trojan3.BinDiff
class AvSignatureGenerator {
 public:
  AvSignatureGenerator() = default;

  AvSignatureGenerator(const AvSignatureGenerator&) = delete;
  AvSignatureGenerator& operator=(const AvSignatureGenerator&) = delete;

  AvSignatureGenerator& set_debug_match_chain(bool value) {
    debug_match_chain_ = value;
    return *this;
  }

  // Adds the matches of the BinDiff result files specified to the table. For
  // convenience, this method takes the same arguments as the main function. It
  // expects, however, that the argument zero has already been processed, like
  // this:
  //    AddDiffResultsFromCommandLineArguments(--argc, ++argv)
  // Overwrites the existing diff results.
  void AddDiffResultsFromCommandLineArguments(int argc, char* argv[]);

  // Adds the matches of the specified BinDiff result files to the table.
  // Overwrites the existing diff results.
  void AddDiffResults(absl::Span<const std::string> files);
  template <typename IteratorT>
  void AddDiffResults(IteratorT first, IteratorT last) {
    diff_results_.clear();
    diff_results_.insert(diff_results_.end(), first, last);
  }

  // Generates the actual AV signature. Parses BinDiff result files, loads
  // metadata and computes a generic regular expression suitable for formatting
  // to the requested output format. One of the methods from the AddDiffResult*
  // family of methods must have been called before calling this method.
  absl::Status Generate(Signature* signature);

 private:
  // Reads and parses the BinExport data for the BinDiff results in the match
  // chain table.
  absl::Status LoadColumnData();

  // Parses BinDiff result files and adds matches to the table. Returns true on
  // success.
  absl::Status ParseDiffResults();

  // Placeholder function that should query the occurrence count of the
  // specified function candidate ids and convert them into weights.
  absl::Status SetFunctionWeights(const IdentSequence& func_candidate_ids);

  // Computes a list of function and basic block candidates for the signature
  // generation. Function/basic block candidates are functions/basic blocks
  // that appear in all matched binaries in the same order.
  absl::Status ComputeCandidates();

  // Filenames of the BinDiff result files to work on
  std::vector<std::string> diff_results_;

  // Siggen's core data structure that holds all loaded function, basic block
  // and instruction matches
  MatchChainTable match_chain_table_;

  // A sequence of basic block ids that are to be considered for inclusion in
  // the final signature
  IdentSequence bb_candidate_ids_;

  // Whether to output debug information about the internal state of the match
  // chain table.
  bool debug_match_chain_ = false;
};

}  // namespace security::vxsig

#endif  // VXSIG_SIGGEN_H_
