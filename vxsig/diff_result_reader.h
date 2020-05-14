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

// A reader for the SQLite based .BinDiff result file format.

#ifndef VXSIG_DIFF_RESULT_READER_H_
#define VXSIG_DIFF_RESULT_READER_H_

#include <functional>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "absl/status/status.h"
#include "vxsig/types.h"

namespace security::vxsig {

// A POD with metadata for one of the matched files that comprise a BinDiff
// result file.
struct FileMetaData {
  std::string filename;
  std::string original_filename;
  std::string original_hash;
};

// Whenever a match is encountered, this callback gets called with its
// corresponding addresses in both binaries.
using MatchReceiverCallback = std::function<void(const MemoryAddressPair&)>;

// Parses the specified .BinDiff file and calls the specified callback
// functions for all encountered matches. If the metadata parameter is
// non-null, it is filled with metadata that is stored in the BinDiff result
// file.
// Requires the callbacks to be a permanent ones and takes ownership.
absl::Status ParseBinDiff(
    absl::string_view filename,
    const MatchReceiverCallback& function_match_receiver,
    const MatchReceiverCallback& basic_block_match_receiver,
    const MatchReceiverCallback& instruction_match_receiver,
    std::pair<FileMetaData, FileMetaData>* metadata);

}  // namespace security::vxsig

#endif  // VXSIG_DIFF_RESULT_READER_H_
