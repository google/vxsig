# Copyright 2019 Google LLC. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

workspace(name = "com_google_vxsig")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Abseil
http_archive(
    name = "com_google_absl",
    sha256 = "b7b5fbd2e0b727ef156e73f184aac7edbeeea413ebd81c45b2aae6f9bda125a0",
    strip_prefix = "abseil-cpp-master",
    urls = ["https://github.com/abseil/abseil-cpp/archive/8a394b19c149cab50534b04c5e21d42bc2217a7d.zip"],
)

# gflags
http_archive(
    name = "com_github_gflags_gflags",
    sha256 = "53b16091efa386ab11e33f018eef0ed489e0ab63554455293cbb0cc2a5f50e98",
    strip_prefix = "gflags-28f50e0fed19872e0fd50dd23ce2ee8cd759338e",
    urls = ["https://github.com/gflags/gflags/archive/28f50e0fed19872e0fd50dd23ce2ee8cd759338e.zip"],  # 2019-01-25
)

# GoogleTest/GoogleMock
http_archive(
    name = "com_google_googletest",
    sha256 = "70404b4a887fd8efce2179e9918e58cdac03245e575408ed87799696e816ecb8",
    strip_prefix = "googletest-f80d6644d4b451f568a2e7aea1e01e842eb242dc",
    urls = ["https://github.com/google/googletest/archive/f80d6644d4b451f568a2e7aea1e01e842eb242dc.zip"],  # 2019-02-05
)

# Google Benchmark
http_archive(
    name = "com_google_benchmark",
    strip_prefix = "benchmark-master",
    urls = ["https://github.com/google/benchmark/archive/master.zip"],
)

# Protobuf
http_archive(
    name = "com_google_protobuf",
    sha256 = "9510dd2afc29e7245e9e884336f848c8a6600a14ae726adb6befdb4f786f0be2",
    strip_prefix = "protobuf-3.6.1.3",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.6.1.3.zip"],
)

# Google OR tools
http_archive(
    name = "com_google_ortools",
    sha256 = "3978fef757fb2f6030b49590ba21955cd710a2df5e74aa1d4cb4d6aed4823965",
    strip_prefix = "or-tools-7.0",
    urls = ["https://github.com/google/or-tools/archive/v7.0.zip"],
)

# SQLite
http_archive(
    name = "org_sqlite",
    build_file = "//vxsig:bazel/external/sqlite.BUILD",
    sha256 = "d02fc4e95cfef672b45052e221617a050b7f2e20103661cda88387349a9b1327",
    strip_prefix = "sqlite-amalgamation-3280000",
    urls = ["https://www.sqlite.org/2019/sqlite-amalgamation-3280000.zip"],
)

# BinExport
http_archive(
    name = "com_google_binexport",
    build_file = "//vxsig:bazel/external/binexport.BUILD",
    patch_cmds = [
        "find . -path ./third_party -prune -o -\\( -name '*.cc' -o -name '*.h' -\\) -print0 |" +
        "xargs -0 -P8 -n1 sed -i 's,^\\(#include \"\\)third_party/\\(absl\\),\\1\\2,g'",
    ],
    sha256 = "a6532112802c1f75b1aeb0b2fdbd26532a069aa0b0e5432dd5592d8cb84d56ed",
    strip_prefix = "binexport-10",
    urls = ["https://github.com/google/binexport/archive/v10.zip"],
)
