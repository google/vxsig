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

#include "vxsig/diff_result_reader.h"

#include <cstring>
#include <memory>

#include "absl/base/internal/raw_logging.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "third_party/sqlite/sqlite3.h"
#include "third_party/zynamics/binexport/util/canonical_errors.h"

namespace security {
namespace vxsig {

struct Sqlite3Closer {
 public:
  Sqlite3Closer();
  ~Sqlite3Closer();

  sqlite3* handle;
};

Sqlite3Closer::Sqlite3Closer() : handle(nullptr) {}

Sqlite3Closer::~Sqlite3Closer() {
  if (!handle) {
    return;
  }

  // Log if there was an error.
  if (sqlite3_errcode(handle) != SQLITE_OK) {
    ABSL_RAW_LOG(WARNING, "%s", sqlite3_errmsg(handle));
  }

  sqlite3_close(handle);
}

not_absl::Status ParseBinDiff(
    absl::string_view filename,
    const MatchReceiverCallback& function_match_receiver,
    const MatchReceiverCallback& basic_block_match_receiver,
    const MatchReceiverCallback& instruction_match_receiver,
    std::pair<FileMetaData, FileMetaData>* metadata) {
  if (filename.empty()) {
    return not_absl::InvalidArgumentError("Empty BinDiff filename");
  }

  const char* query =
      "SELECT file1, file2 FROM \"metadata\";"
      "SELECT filename, exefilename, hash FROM \"file\" WHERE id=:file;"
      "SELECT"
      " f.id, f.address1, f.address2,"
      " b.id, b.address1, b.address2,"
      " i.address1, i.address2 "
      "FROM"
      " \"function\" AS f,"
      " \"basicblock\" AS b,"
      " \"instruction\" AS i "
      "WHERE"
      " f.id = b.functionid AND"
      " b.id = i.basicblockid "
      "ORDER BY"
      " f.id, f.address1, f.address2,"
      " b.id, b.address1, b.address2,"
      " i.address1, i.address2;";
  enum { kNumMatchCols = 8 };

  // Open database file without VFS (last argument of sqlite_open_v2).
  Sqlite3Closer db;
  if (sqlite3_open_v2(std::string(filename).c_str(), &db.handle,
                      SQLITE_OPEN_READONLY, nullptr)) {
    return not_absl::FailedPreconditionError(
        absl::StrCat("SQLite open failed for ", filename));
  }

  // Get file IDs.
  sqlite3_stmt* stmt;
  if (sqlite3_prepare_v2(db.handle, query, strlen(query), &stmt, &query) !=
          SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_ROW) {
    return not_absl::InternalError(absl::StrCat(
        "SQLite prepare statement failed for file metadata in ", filename));
  }

  int file1_id = sqlite3_column_int(stmt, 0);
  int file2_id = sqlite3_column_int(stmt, 1);
  if (sqlite3_finalize(stmt) != SQLITE_OK) {
    return not_absl::InternalError(
        absl::StrCat("SQLite finalize statement failed, file: ", filename));
  }

  // Query metadata for primary and secondary file.
  if (sqlite3_prepare_v2(db.handle, query, strlen(query), &stmt, &query) !=
          SQLITE_OK ||
      sqlite3_bind_int(stmt, 1, file1_id) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_ROW) {
    return not_absl::InternalError(absl::StrCat(
        "SQLite result error querying file ids, file: ", filename));
  }

  if (metadata != nullptr) {
    metadata->first.filename.assign(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    metadata->first.original_filename.assign(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
    metadata->first.original_hash.assign(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
    sqlite3_reset(stmt);
    if (sqlite3_bind_int(stmt, 1, file2_id) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_ROW) {
      sqlite3_finalize(stmt);
      return not_absl::InternalError(absl::StrCat(
          "SQLite result error querying file metadata, file: ", filename));
    }

    metadata->second.filename.assign(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    metadata->second.original_filename.assign(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
    metadata->second.original_hash.assign(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)));
  }
  if (sqlite3_finalize(stmt) != SQLITE_OK) {
    return not_absl::InternalError(
        absl::StrCat("SQLite finalize statement failed for ", filename));
  }

  // Query function matches.
  if (sqlite3_prepare_v2(db.handle, query, strlen(query), &stmt, nullptr)) {
    return not_absl::InternalError(absl::StrCat(
        "SQLite prepare statement failed querying function matches, file: ",
        filename));
  }

  int32 last_function_id = -1;
  int32 last_basic_block_id = -1;
  MemoryAddressPair function_match, basic_block_match, instruction_match;
  int32 col = 0;
  while (true) {
    int result = sqlite3_step(stmt);
    if (result == SQLITE_DONE) {
      break;
    }
    if (result != SQLITE_ROW) {
      sqlite3_finalize(stmt);
      return not_absl::FailedPreconditionError(absl::Substitute(
          "SQLite result error: $0, file $1", result, filename));
    }

    int32 function_id = sqlite3_column_int(stmt, col++ % kNumMatchCols);
    function_match.first = sqlite3_column_int64(stmt, col++ % kNumMatchCols);
    function_match.second = sqlite3_column_int64(stmt, col++ % kNumMatchCols);
    int32 basic_block_id = sqlite3_column_int(stmt, col++ % kNumMatchCols);
    basic_block_match.first = sqlite3_column_int64(stmt, col++ % kNumMatchCols);
    basic_block_match.second =
        sqlite3_column_int64(stmt, col++ % kNumMatchCols);
    instruction_match.first = sqlite3_column_int64(stmt, col++ % kNumMatchCols);
    instruction_match.second =
        sqlite3_column_int64(stmt, col++ % kNumMatchCols);

    if (function_id != last_function_id) {
      function_match_receiver(function_match);
      last_function_id = function_id;
    }
    if (basic_block_id != last_basic_block_id) {
      basic_block_match_receiver(basic_block_match);
      last_basic_block_id = basic_block_id;
    }
    if (instruction_match_receiver) {
      instruction_match_receiver(instruction_match);
    }
  }
  if (sqlite3_finalize(stmt) != SQLITE_OK) {
    return not_absl::InternalError(
        absl::StrCat("SQLite finalize statement failed, file: ", filename));
  }

  return not_absl::OkStatus();
}

}  // namespace vxsig
}  // namespace security
