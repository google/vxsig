# Copyright 2020-2021 Google LLC
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
        sha256 = "595a502009b3f97f9407ff0557abc0fc4a9d9a574662353ccb2971c539ddb2e3",  # 2021-03-25
        strip_prefix = "abseil-cpp-a09b5de0d57d7b2179210989ab63361c3c1894f5",
        urls = ["https://github.com/abseil/abseil-cpp/archive/a09b5de0d57d7b2179210989ab63361c3c1894f5.zip"],
    )

    # Protobuf
    maybe(
        http_archive,
        name = "com_google_protobuf",
        sha256 = "985bb1ca491f0815daad825ef1857b684e0844dc68123626a08351686e8d30c9",  # 2021-03-10
        strip_prefix = "protobuf-3.15.6",
        urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.15.6.zip"],
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
        sha256 = "4d6bb52c23b6c590fd0f8bea90bed9a1f263c61a1ac0e2d66dadb9213fbe4b1c",  # 2021-03-29
        strip_prefix = "googletest-6c5c4554ac218a8e19168edc121b1ad232015185",
        urls = ["https://github.com/google/googletest/archive/6c5c4554ac218a8e19168edc121b1ad232015185.zip"],
    )

    # Google Benchmark
    maybe(
        http_archive,
        name = "com_google_benchmark",
        sha256 = "bc60957389e8d9e37d1a40fad22da7a1950e382850cec80b0133fcbfa7d41016",  # 2021-03-08
        strip_prefix = "benchmark-cc9abfc8f12577ea83b2d093693ba70c3c0fd2c7",
        urls = ["https://github.com/google/benchmark/archive/cc9abfc8f12577ea83b2d093693ba70c3c0fd2c7.zip"],
    )
