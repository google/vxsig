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
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.3.0/bazel-skylib-1.3.0.tar.gz",
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.3.0/bazel-skylib-1.3.0.tar.gz",
        ],
        sha256 = "74d544d96f4a5bb630d465ca8bbcfe231e3594e5aae57e1edbf17a6eb3ca2506",  # 2022-09-01
    )

    # Abseil
    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "479abe26015eabecd428b50c5f821599b0275f150c4ea5cbb314c8fd263e7034",  # 2022-11-06
        strip_prefix = "abseil-cpp-1ee0ea84893e7d1edfc4fdaf192a0551a46e20b4",
        urls = ["https://github.com/abseil/abseil-cpp/archive/1ee0ea84893e7d1edfc4fdaf192a0551a46e20b4.zip"],
    )

    # Protobuf
    maybe(
        http_archive,
        name = "com_google_protobuf",
        sha256 = "f66073dee0bc159157b0bd7f502d7d1ee0bc76b3c1eac9836927511bdc4b3fc1",  # 2022-10-26
        strip_prefix = "protobuf-3.21.9",
        urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.21.9.zip"],
    )

    # Google OR tools
    maybe(
        http_archive,
        name = "com_google_ortools",
        sha256 = "",  # 2022-08-11
        strip_prefix = "or-tools-9.4",
        urls = ["https://github.com/google/or-tools/archive/v9.4.zip"],
    )

    # GoogleTest/GoogleMock
    maybe(
        http_archive,
        name = "com_google_googletest",
        sha256 = "96d30b9f6ffbafe9541c2f755c88199951162d4aea4f3d617f76070bfb70ff2c",  # 2022-11-05
        strip_prefix = "googletest-a4f02ef38981350c9d673b9909559c7a86420d7a",
        urls = ["https://github.com/google/googletest/archive/a4f02ef38981350c9d673b9909559c7a86420d7a.zip"],
    )

    # Google Benchmark
    maybe(
        http_archive,
        name = "com_google_benchmark",
        sha256 = "",  # 2022-10-31
        strip_prefix = "benchmark-398a8ac2e8e0b852fa1568dc1c8ebdfc743a380a",
        urls = ["https://github.com/google/benchmark/archive/398a8ac2e8e0b852fa1568dc1c8ebdfc743a380a.zip"],
    )
