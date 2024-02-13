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

# Google OR tools
maybe(
    http_archive,
    name = "com_google_ortools",
    sha256 = "",  # 2022-08-11
    strip_prefix = "or-tools-9.4",
    urls = ["https://github.com/google/or-tools/archive/v9.4.zip"],
)
