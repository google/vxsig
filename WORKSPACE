# Copyright 2011-2024 Google LLC
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
    sha256 = "f8a270f990529caf9ad2969337a02b9232b25d6ae69a06346e3f9e2cee8e5502",  # 2024-02-13
    strip_prefix = "binexport-5795afc727e7ab66072ea12b38f3e9c978bfa046",
    urls = ["https://github.com/google/binexport/archive/5795afc727e7ab66072ea12b38f3e9c978bfa046.zip"],
)

# Google OR tools
maybe(
    http_archive,
    name = "com_google_ortools",
    sha256 = "751d2f7399f3290a90e893bc6be5e57181a17545dd18c00b16dfd3933d2cc05d",  # 2023-11-15
    strip_prefix = "or-tools-9.8",
    urls = ["https://github.com/google/or-tools/archive/v9.8.zip"],
)
