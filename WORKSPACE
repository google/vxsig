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
    sha256 = "d1c9f51f933f0cd45fd5af3ce05593b8956bfa0538a7c55c7a617d067ca38cc0",
    strip_prefix = "abseil-cpp-lts_2019_08_08",
    urls = ["https://github.com/abseil/abseil-cpp/archive/lts_2019_08_08.zip"],
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
    sha256 = "33cba8b89be6c81b1461f1c438424f7a1aa4e31998dbe9ed6f8319583daac8c7",
    strip_prefix = "protobuf-3.10.0",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.10.0.zip"],
)

http_archive(
    name = "bazel_skylib",
    sha256 = "bbccf674aa441c266df9894182d80de104cabd19be98be002f6d478aaa31574d",
    strip_prefix = "bazel-skylib-2169ae1c374aab4a09aa90e65efe1a3aad4e279b",
    urls = ["https://github.com/bazelbuild/bazel-skylib/archive/2169ae1c374aab4a09aa90e65efe1a3aad4e279b.tar.gz"],
)

http_archive(
    name = "rules_python",
    sha256 = "e5470e92a18aa51830db99a4d9c492cc613761d5bdb7131c04bd92b9834380f6",
    strip_prefix = "rules_python-4b84ad270387a7c439ebdccfd530e2339601ef27",
    urls = ["https://github.com/bazelbuild/rules_python/archive/4b84ad270387a7c439ebdccfd530e2339601ef27.tar.gz"],
)

http_archive(
    name = "zlib",
    build_file = "@com_google_protobuf//:third_party/zlib.BUILD",
    sha256 = "629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff",
    strip_prefix = "zlib-1.2.11",
    urls = ["https://github.com/madler/zlib/archive/v1.2.11.tar.gz"],
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
