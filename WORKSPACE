# Copyright 2019-2020 Google LLC
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

maybe(
    http_archive,
    name = "zlib",
    build_file = "@com_google_protobuf//:third_party/zlib.BUILD",
    sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",  # 2020-04-23
    strip_prefix = "zlib-1.2.11",
    urls = [
        "https://mirror.bazel.build/zlib.net/zlib-1.2.11.tar.gz",
        "https://www.zlib.net/zlib-1.2.11.tar.gz",
    ],
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
    sha256 = "8c3df9877f54fcdf6ffaa4291db8e0805ebe917baef969aa931bdc6f5e319b6a",
    strip_prefix = "binexport-64b18c303e26558224b980274780fa4b455d7518",
    urls = ["https://github.com/google/binexport/archive/64b18c303e26558224b980274780fa4b455d7518.zip"],
)
