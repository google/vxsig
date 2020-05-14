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
        sha256 = "154f4063d96a4e47b17a917108eaabdfeb4ef08383795cf936b3be6f8179c9fc",  # 2020-04-15
        strip_prefix = "bazel-skylib-560d7b2359aecb066d81041cb532b82d7354561b",
        url = "https://github.com/bazelbuild/bazel-skylib/archive/560d7b2359aecb066d81041cb532b82d7354561b.zip",
    )

    # Abseil
    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "6668ada01192e2b95b42bb3668cfa5282c047de5176f5e567028e12f8bfb8aef",  # 2020-04-28
        strip_prefix = "abseil-cpp-6e18c7115df9b7ca0987cc346b1b1d4b3cc829b3",
        urls = ["https://github.com/abseil/abseil-cpp/archive/6e18c7115df9b7ca0987cc346b1b1d4b3cc829b3.zip"],
    )

    # Protobuf
    maybe(
        http_archive,
        name = "com_google_protobuf",
        sha256 = "9748c0d90e54ea09e5e75fb7fac16edce15d2028d4356f32211cfa3c0e956564",  # 2020-02-14
        strip_prefix = "protobuf-3.11.4",
        urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.11.4.zip"],
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
        sha256 = "a6ab7c7d6fd4dd727f6012b5d85d71a73d3aa1274f529ecd4ad84eb9ec4ff767",  # 2020-04-16
        strip_prefix = "googletest-dcc92d0ab6c4ce022162a23566d44f673251eee4",
        urls = ["https://github.com/google/googletest/archive/dcc92d0ab6c4ce022162a23566d44f673251eee4.zip"],
    )

    # Google Benchmark
    maybe(
        http_archive,
        name = "com_google_benchmark",
        sha256 = "7f45be0bff07d787d75c3864212e9ea5ebba57593b2e487c783d11da70ef6857",  # 2020-04-23
        strip_prefix = "benchmark-56898e9a92fba537671d5462df9c5ef2ea6a823a",
        urls = ["https://github.com/google/benchmark/archive/56898e9a92fba537671d5462df9c5ef2ea6a823a.zip"],
    )
