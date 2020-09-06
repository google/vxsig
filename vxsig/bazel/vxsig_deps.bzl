# Copyright 2020 Google LLC
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

"""Loads dependencies needed to compile VxSig for 3rd-party consumers."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def vxsig_deps():
    """Loads common dependencies needed to compile VxSig."""

    # Bazel Skylib, needed by newer Protobuf builds
    maybe(
        http_archive,
        name = "bazel_skylib",
        urls = [
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.0.3/bazel-skylib-1.0.3.tar.gz",
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.0.3/bazel-skylib-1.0.3.tar.gz",
        ],
        sha256 = "1c531376ac7e5a180e0237938a2536de0c54d93f5c278634818e0efc952dd56c",  # 2020-08-27
    )

    # Abseil
    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "10a83730ea1a0fdd3d9f17c06d6e3ca0b3d90d20874d81fdf1adec97c154d590",  # 2020-09-04
        strip_prefix = "abseil-cpp-7ba8cdb56df3bf4fe4ab4606f3fe4b2ab825afac",
        urls = ["https://github.com/abseil/abseil-cpp/archive/7ba8cdb56df3bf4fe4ab4606f3fe4b2ab825afac.zip"],
    )

    # Protobuf
    maybe(
        http_archive,
        name = "com_google_protobuf",
        sha256 = "1c744a6a1f2c901e68c5521bc275e22bdc66256eeb605c2781923365b7087e5f",  # 2020-08-15
        strip_prefix = "protobuf-3.13.0",
        urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.13.0.zip"],
    )

    # Google OR tools
    maybe(
        http_archive,
        name = "com_google_ortools",
        sha256 = "3978fef757fb2f6030b49590ba21955cd710a2df5e74aa1d4cb4d6aed4823965",
        strip_prefix = "or-tools-7.0",
        urls = ["https://github.com/google/or-tools/archive/v7.0.zip"],
    )

    # GoogleTest/GoogleMock
    maybe(
        http_archive,
        name = "com_google_googletest",
        sha256 = "e89104fc9b7c6e93004909d619b8e9f5f7543f9e34a9cc967a745eefae941018",  # 2020-09-01
        strip_prefix = "googletest-7b1cf6dd5fbe0c22c5e638fce8caf7f0f5c1abbf",
        urls = ["https://github.com/google/googletest/archive/7b1cf6dd5fbe0c22c5e638fce8caf7f0f5c1abbf.zip"],
    )

    # Google Benchmark
    maybe(
        http_archive,
        name = "com_google_benchmark",
        sha256 = "",  # 2020-09-03
        strip_prefix = "benchmark-4751550871a4765c027d39680b842f590e1192b2",
        urls = ["https://github.com/google/benchmark/archive/4751550871a4765c027d39680b842f590e1192b2.zip"],
    )
