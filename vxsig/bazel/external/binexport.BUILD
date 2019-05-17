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

# Defines the protocol message used in the .BinExport v2 file format.
proto_library(
    name = "binexport2_proto",
    srcs = ["binexport2.proto"],
)

cc_proto_library(
    name = "binexport2_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":binexport2_proto"],
)

BINEXPORT_DEFAULT_COPTS = [
    "-fexceptions",  # This code throws on error
]

cc_library(
    name = "stubs",
    hdrs = [
        "stubs/base/integral_types.h",
        "stubs/base/logging.h",
    ],
    copts = BINEXPORT_DEFAULT_COPTS,
    includes = ["stubs"],
    visibility = ["//visibility:public"],
    deps = ["@com_google_protobuf//:protobuf"],
)

cc_library(
    name = "types",
    hdrs = ["types.h"],
    copts = BINEXPORT_DEFAULT_COPTS,
    include_prefix = "third_party/zynamics/binexport",
    visibility = ["//visibility:public"],
    deps = [":stubs"],
)

# Custom fork of util::Status to be used until absl::Status is open source.
cc_library(
    name = "status",
    srcs = [
        "util/canonical_errors.cc",
        "util/status.cc",
    ],
    hdrs = [
        "util/canonical_errors.h",
        "util/status.h",
        "util/status_macros.h",
        "util/statusor.h",
    ],
    copts = BINEXPORT_DEFAULT_COPTS,
    include_prefix = "third_party/zynamics/binexport",
    visibility = ["//visibility:public"],
    deps = [
        ":types",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/meta:type_traits",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:variant",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "status_matchers",
    testonly = 1,
    hdrs = ["util/status_matchers.h"],
    copts = BINEXPORT_DEFAULT_COPTS,
    include_prefix = "third_party/zynamics/binexport",
    visibility = ["//visibility:public"],
    deps = [
        ":status",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
    ],
)

# Utility library with portable filesystem functions.
cc_library(
    name = "filesystem",
    srcs = ["util/filesystem.cc"],
    hdrs = ["util/filesystem.h"],
    copts = BINEXPORT_DEFAULT_COPTS,
    include_prefix = "third_party/zynamics/binexport",
    visibility = ["//visibility:public"],
    deps = [
        ":status",
        "@com_google_absl//absl/strings",
    ],
)

# BinExport utility routines
cc_library(
    name = "binexport_util",
    srcs = ["binexport.cc"],
    hdrs = ["binexport.h"],
    copts = BINEXPORT_DEFAULT_COPTS,
    include_prefix = "third_party/zynamics/binexport",
    visibility = ["//visibility:public"],
    deps = [
        ":types",
        "@//vxsig:binexport2_cc_proto",  # TODO(cblichmann): HACK
        "@com_google_protobuf//:protobuf",
    ],
)
