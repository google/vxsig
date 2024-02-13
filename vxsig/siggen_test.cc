// Copyright 2011-2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "vxsig/siggen.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "third_party/zynamics/binexport/util/status_matchers.h"
#include "vxsig/generic_signature.h"
#include "vxsig/signature_formatter.h"
#include "vxsig/yara_signature_test_util.h"

using not_absl::IsOk;
using testing::HasSubstr;
using testing::IsEmpty;
using testing::IsTrue;
using testing::Not;
using testing::StrEq;

namespace security::vxsig {

class SiggenTest : public testing::Test {
 protected:
  void SetupDefaultSignature(AvSignatureGenerator* siggen);

  Signature signature_;
};

void SiggenTest::SetupDefaultSignature(AvSignatureGenerator* siggen) {
  std::vector<std::string> files;
  for (
      const auto& diff_result : {
          "1794a0afbfc38411dec87fa2660d6dd6515cf8d03cb32bb24a1d7a8e1ecf30fa_vs_"
          "1b0a84953909816c1945c2153605c2ddeb3b138fb4c262c7262cd9689ed25f82."
          "BinDiff",
          "1b0a84953909816c1945c2153605c2ddeb3b138fb4c262c7262cd9689ed25f82_vs_"
          "1d3949acb5eb175af3cbc5f448ece50669a44743faec91e3d574dad9596a9d83."
          "BinDiff",
      }) {
    const std::string file_name(JoinPath("vxsig/testdata/", diff_result));
    ASSERT_THAT(FileExists(file_name), IsTrue());
    files.push_back(file_name);
  }

  siggen->AddDiffResults(files);
  EXPECT_THAT(siggen->Generate(&signature_), IsOk());
}

TEST_F(SiggenTest, GenerateClamAVSignature) {
  AvSignatureGenerator siggen;
  SetupDefaultSignature(&siggen);
  // Expect this ClamAV signature to be generated. This obviously needs to be
  // changed should the algorithm change significantly.
  auto formatter(SignatureFormatter::Create(CLAMAV));
  constexpr char kExpectedSignature[] =
      "test_malware:0:*:8bc38bde99f7fe8bf285d275f3*558bec56578bf1e8*"
      "2bc78bce5fd1f85052e8*8b06b9????????2b48fc8b40f82bc20bc87d08*"
      "8b49f83bce7d37*81f9????????7e19*85c97406*8b56088bd82bdf3bca753c*"
      "8b06894604ff15????*c745b4????????e8*8d4dcc348b8845db8d45db50e8*"
      "fcff6a008d8d*fbff8bc885c9746e*f9ff8d85*f8ff85c00f8489010000*"
      "8d45f4c745f4????*720000595985c07431*6a0259cd29*8d4508a3*6100006a16*"
      "85ff5f5b0f857bffffff";
  Signature signature(signature_);
  auto* definition = signature.mutable_definition();
  definition->set_detection_name("test_malware");
  definition->set_trim_algorithm(SignatureDefinition::TRIM_RANDOM);
  definition->set_trim_length(200);
  EXPECT_THAT(formatter->Format(&signature), IsOk());
  EXPECT_THAT(signature.clam_av_signature().data(), StrEq(kExpectedSignature));
}

TEST_F(SiggenTest, GenerateYaraSignatureWithMetadata) {
  AvSignatureGenerator siggen;
  auto& signature_definition = *signature_.mutable_definition();
  signature_definition.set_unique_signature_id("testtask");
  signature_definition.add_item_id("item0");
  signature_definition.add_item_id("item1");
  signature_definition.add_item_id("item3");
  SetupDefaultSignature(&siggen);
  // Expect this Yara signature to be generated.
  auto formatter(SignatureFormatter::Create(YARA));
  constexpr char kExpectedSignature[] = R"(rule test_malware {
  meta:
    vxsig_build = "redacted"
    vxsig_taskid = "testtask"
    rs1 = "item0"
    rs2 = "item1"
    rs3 = "item3"
  strings:
    $ = {
         8bc38bde99f7fe8bf285d275f3
         // 00216258: mov eax, ebx
         // 0021625a: mov ebx, esi
         // 0021625c: cdq
         // 0021625d: idiv esi
         // 0021625f: mov esi, edx
         // 00216261: test edx, edx
         // 00216263: jnz 0x216258
      [-]558bec56578bf1e8
         // 00216c90: push ebp
         // 00216c91: mov ebp, esp
         // 00216c93: push esi
         // 00216c94: push edi
         // 00216c95: mov esi, ecx
         // 00216c97: call 0x218590
      [-]2bc78bce5fd1f85052e8
         // 0021784e: sub eax, edi
         // 00217850: mov ecx, esi
         // 00217852: pop edi
         // 00217853: sar eax, b1 0x1
         // 00217855: push eax
         // 00217856: push edx
         // 00217857: call 0x218a50
      [-]8b06b9????????2b48fc8b40f82bc20bc87d08
         // 0021855d: mov eax, ds:[esi]
         // 0021855f: mov ecx, 0x1
         // 00218564: sub ecx, ds:[eax+0xfffffffffffffffc]
         // 00218567: mov eax, ds:[eax+0xfffffffffffffff8]
         // 0021856a: sub eax, edx
         // 0021856c: or ecx, eax
         // 0021856e: jge 0x218578
      [-]8b49f83bce7d37
         // 00218797: mov ecx, ds:[ecx+0xfffffffffffffff8]
         // 0021879a: cmp ecx, esi
         // 0021879c: jge 0x2187d5
      [-]81f9????????7e19
         // 0021880e: cmp ecx, 0x40000000
         // 00218814: jle 0x21882f
      [-]85c97406
         // 0022def0: test ecx, ecx
         // 0022def2: jz 0x22defa
      [-]8b56088bd82bdf3bca753c
         // 0022e7b8: mov edx, ds:[esi+0x8]
         // 0022e7bb: mov ebx, eax
         // 0022e7bd: sub ebx, edi
         // 0022e7bf: cmp ecx, edx
         // 0022e7c1: jnz 0x22e7ff
      [-]8b06894604ff15????
         // 013827fb: mov eax, ds:[esi]
         // 013827fd: mov ds:[esi+0x4], eax
         // 01382800: call ds:[0x1470250]
      [-]c745b4????????e8
         // 00c340f5: mov ss:[ebp+0xffffffffffffffb4], 0x0
         // 00c340fc: call 0xc3d2a0
      [-]8d4dcc348b8845db8d45db50e8
         // 013a5333: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 013a5336: xor b1 al, b1 0x8b
         // 013a5338: mov b1 ss:[ebp+0xffffffffffffffdb], b1 al
         // 013a533b: lea eax, ss:[ebp+0xffffffffffffffdb]
         // 013a533e: push eax
         // 013a533f: call 0x136e3c0
      [-]fcff6a008d8d
         // 013a794b: push b1 0x0
         // 013a794d: lea ecx, ss:[ebp+0xffffffffffffdde1]
      [-]fbff8bc885c9746e
         // 013ae5ec: mov ecx, eax
         // 013ae5ee: test ecx, ecx
         // 013ae5f0: jz 0x13ae660
      [-]f9ff8d85
         // 013ccc1b: lea eax, ss:[ebp+0xfffffffffffffa78]
      [-]f8ff85c00f8489010000
         // 00c77583: test eax, eax
         // 00c77585: jz 0xc77714
      [-]8d45f4c745f4????
         // 014374a3: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 014374a6: mov ss:[ebp+0xfffffffffffffff4], 0x1472d5c
      [-]720000595985c07431
         // 002e74b3: pop ecx
         // 002e74b4: pop ecx
         // 002e74b5: test eax, eax
         // 002e74b7: jz 0x2e74ea
      [-]6a0259cd29
         // 002e7559: push b1 0x2
         // 002e755b: pop ecx
         // 002e755c: int b1 0x29
      [-]8d4508a3
         // 014389d2: lea eax, ss:[ebp+0x8]
         // 014389d5: mov ds:[0x14962ec], eax
      [-]6100006a16
         // 002e93e2: push b1 0x16
      [-]85ff5f5b0f857bffffff
         // 002e94a9: test edi, edi
         // 002e94ab: pop edi
         // 002e94ac: pop ebx
         // 002e94ad: jnz 0x2e942e

  }
  condition:
    all of them
}
)";
  Signature signature(signature_);
  auto* definition = signature.mutable_definition();
  definition->set_detection_name("test_malware");
  definition->set_trim_algorithm(SignatureDefinition::TRIM_RANDOM);
  definition->set_trim_length(200);
  EXPECT_THAT(formatter->Format(&signature), IsOk());
  EXPECT_THAT(MakeComparableYaraSignature(signature.yara_signature().data()),
              StrEq(MakeComparableYaraSignature(kExpectedSignature)));
}

TEST_F(SiggenTest, EmptyRawSignaturePieces) {
  AvSignatureGenerator siggen;
  const std::string file_name =
      "vxsig/testdata/"
      "592fb377afa9f93670a23159aa585e0eca908b97571ab3218e026fea3598cc16_vs_"
      "65d25a86feb6d15527e398d7b5d043e7712b00e674bc6e8cf2a709a0c6f9b97b."
      "BinDiff";
  ASSERT_THAT(FileExists(file_name), IsTrue());
  siggen.AddDiffResults(std::vector<std::string>(1 /* size */, file_name));
  Signature signature;
  ASSERT_THAT(siggen.Generate(&signature), IsOk());
  for (const auto& piece : signature.raw_signature().piece()) {
    EXPECT_THAT(piece.bytes(), Not(IsEmpty()))
        << "Signature contains empty pieces: \n"
        << signature.DebugString();
  }
}

TEST_F(SiggenTest, NotADiffChain) {
  AvSignatureGenerator siggen;
  // Intentionally add diffs in the wrong order.
  siggen.AddDiffResults(
      {"vxsig/testdata/"
       "61971471cedcb4daed8d07ad79297568ffdaa17eb4ff301dc953cfafa91a4507_vs_"
       "8433c9a6345d210d2196096461804d7137bbf2a6b71b20cc21f4ecf7d15ef6c2."
       "BinDiff",
       "vxsig/testdata/"
       "328b26dc3f0d8543e151495f4d6f3960323e3f51223522c2e4cd1e2fe9f9ed8f_vs_"
       "61971471cedcb4daed8d07ad79297568ffdaa17eb4ff301dc953cfafa91a4507."
       "BinDiff"});
  Signature signature;
  EXPECT_THAT(siggen.Generate(&signature).ToString(),
              HasSubstr("Input files do not form a chain of diffs"));
}

}  // namespace security::vxsig
