# Copyright 2020 Google LLC. All Rights Reserved.
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
        sha256 = "1dde365491125a3db70731e25658dfdd3bc5dbdfd11b840b3e987ecf043c7ca0",  # 2019-07-12
        url = "https://github.com/bazelbuild/bazel-skylib/releases/download/0.9.0/bazel_skylib-0.9.0.tar.gz",
    )

    # Abseil
    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "d8bc776c9702c7875c64410d1380cf3f3c0f75d5df9be08218589579604c539e",  # 2019-11-19
        strip_prefix = "abseil-cpp-8ba96a8244bbe334d09542e92d566673a65c1f78",
        urls = ["https://github.com/abseil/abseil-cpp/archive/8ba96a8244bbe334d09542e92d566673a65c1f78.zip"],
    )

    # Protobuf
    maybe(
        http_archive,
        name = "com_google_protobuf",
        sha256 = "678d91d8a939a1ef9cb268e1f20c14cd55e40361dc397bb5881e4e1e532679b1",  # 2019-10-29
        strip_prefix = "protobuf-3.10.1",
        urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.10.1.zip"],
    )
