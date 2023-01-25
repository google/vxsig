# Copyright 2011-2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
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

maybe(
    http_archive,
    name = "zlib",
    build_file = "@com_google_protobuf//:third_party/zlib.BUILD",
    sha256 = "b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30",  # 2022-10-13
    strip_prefix = "zlib-1.2.13",
    urls = [
        "https://mirror.bazel.build/zlib.net/zlib-1.2.13.tar.gz",
        "https://www.zlib.net/zlib-1.2.13.tar.gz",
    ],
)

# SQLite
http_archive(
    name = "org_sqlite",
    build_file = "//vxsig:bazel/external/sqlite.BUILD",
    sha256 = "9c99955b21d2374f3a385d67a1f64cbacb1d4130947473d25c77ad609c03b4cd",  # 2022-09-29
    strip_prefix = "sqlite-amalgamation-3390400",
    urls = ["https://www.sqlite.org/2022/sqlite-amalgamation-3390400.zip"],
)

# BinExport
http_archive(
    name = "com_google_binexport",
    build_file = "//vxsig:bazel/external/binexport.BUILD",
    patch_cmds = [
        "find . -path ./third_party -prune -o \\( -name '*.cc' -o -name '*.h' \\) -print0 |" +
        "xargs -0 -P8 -n1 sed -i.bak 's,^\\(#include \"\\)third_party/\\(absl\\),\\1\\2,g'",
        "find . -path ./third_party -name '*.bak' -delete",
    ],
    sha256 = "d5dd1a34b118f1c1140f1426cdef5edf01f4405f6c286262d9cce30245a3c4ac",  # 2020-09-03
    strip_prefix = "binexport-f56c8b0a5fa4977dea032ef0143697a40c893783",
    urls = ["https://github.com/google/binexport/archive/f56c8b0a5fa4977dea032ef0143697a40c893783.zip"],
)
