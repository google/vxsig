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
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("//vxsig/bazel:vxsig_deps.bzl", "vxsig_deps")

# Load common dependencies, then Protobuf's
vxsig_deps()

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

# GoogleTest/GoogleMock
maybe(
    http_archive,
    name = "com_google_googletest",
    sha256 = "ba5b04a4849246e7c16ba94227eed46486ef942f61dc8b78609732543c19c9f4",  # 2019-11-21
    strip_prefix = "googletest-200ff599496e20f4e39566feeaf2f6734ca7570f",
    urls = ["https://github.com/google/googletest/archive/200ff599496e20f4e39566feeaf2f6734ca7570f.zip"],
)

# Google Benchmark
maybe(
    http_archive,
    name = "com_google_benchmark",
    sha256 = "9067442aa447e54cc144160420daf37fcd0663ccf3057ce2d87b9d7f6ad45d3f",  # 2019-11-05
    strip_prefix = "benchmark-c50ac68c50ff8da3827cd6720792117910d85666",
    urls = ["https://github.com/google/benchmark/archive/c50ac68c50ff8da3827cd6720792117910d85666.zip"],
)

#http_archive(
#    name = "rules_python",
#    sha256 = "e5470e92a18aa51830db99a4d9c492cc613761d5bdb7131c04bd92b9834380f6",
#    strip_prefix = "rules_python-4b84ad270387a7c439ebdccfd530e2339601ef27",
#    urls = ["https://github.com/bazelbuild/rules_python/archive/4b84ad270387a7c439ebdccfd530e2339601ef27.tar.gz"],
#)

maybe(
    http_archive,
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
