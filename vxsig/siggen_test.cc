// Copyright 2011-2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "vxsig/siggen.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "absl/status/status.h"
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
    const std::string file_name(JoinPath(getenv("TEST_SRCDIR"),
                                    "com_google_vxsig/vxsig/testdata/",
                                    diff_result));
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
      "test_malware:0:*:0d0083c404c707????????c747????????00c747????????00*"
      "558bec56578bf1e8*2bc78bce5fd1f85052e8*8b49f83bce7d37*5650ff15????*"
      "85c97406*41c645eb008d45eb894d103bc1732d*8b068a04038801eb4e*6a018d4d0ce8*"
      "8b06894604ff15????*8d4dcc348b8845db8d45db50e8*8a014184c075f9*68????????"
      "ff15????*fbff8bc885c9746e*f9ff8d85*f8ff85c00f8489010000*05008be55dc3*"
      "720000595985c07431*6a0259cd29*578bfe2bf9*f4fdff59";
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
  // Note: Weird empty comments in between are there to avoid trigraphs.
  constexpr char kExpectedSignature[] =
      "rule test_malware {meta:vxsig_build = \"redacted\"vxsig_taskid = "
      "\"testtask\"rs1 = \"item0\"rs2 = \"item1\"rs3 = \"item3\"\nstrings:$ = "
      "{0d0083c404c707????????c747????????00c747????????00// 0136655e: add "
      "esp, b1 0x4\n// 01366561: mov ds:[edi], 0x0\n// 01366567: mov "
      "ds:[edi+0x4], 0x0\n// 0136656e: mov ds:[edi+0x8], "
      "0x0\n[-]558bec56578bf1e8// 00216c90: push ebp\n// 00216c91: mov ebp, "
      "esp\n// 00216c93: push esi\n// 00216c94: push edi\n// 00216c95: mov "
      "esi, ecx\n// 00216c97: call 0x218590\n[-]2bc78bce5fd1f85052e8// "
      "0021784e: sub eax, edi\n// 00217850: mov ecx, esi\n// 00217852: pop "
      "edi\n// 00217853: sar eax, b1 0x1\n// 00217855: push eax\n// 00217856: "
      "push edx\n// 00217857: call 0x218a50\n[-]8b49f83bce7d37// 00218797: mov "
      "ecx, ds:[ecx+0xfffffffffffffff8]\n// 0021879a: cmp ecx, esi\n// "
      "0021879c: jge 0x2187d5\n[-]5650ff15????" /**/
      "// 01369a65: push esi\n// "
      "01369a66: push eax\n// 01369a67: call ds:[0x1470264]\n[-]85c97406// "
      "0022def0: test ecx, ecx\n// 0022def2: jz "
      "0x22defa\n[-]41c645eb008d45eb894d103bc1732d// 0022dfaa: inc ecx\n// "
      "0022dfab: mov b1 ss:[ebp+0xffffffffffffffeb], b1 0x0\n// 0022dfaf: lea "
      "eax, ss:[ebp+0xffffffffffffffeb]\n// 0022dfb2: mov ss:[ebp+0x10], "
      "ecx\n// 0022dfb5: cmp eax, ecx\n// 0022dfb7: jnb "
      "0x22dfe6\n[-]8b068a04038801eb4e// 0022e2dc: mov eax, ds:[esi]\n// "
      "0022e2de: mov b1 al, b1 ds:[ebx+eax]\n// 0022e2e1: mov b1 ds:[ecx], b1 "
      "al\n// 0022e2e3: jmp 0x22e333\n[-]6a018d4d0ce8// 00c10f28: push b1 "
      "0x1\n// 00c10f2a: lea ecx, ss:[ebp+0xc]\n// 00c10f2d: call "
      "0xbfbd10\n[-]8b06894604ff15????" /**/
      "// 013827fb: mov eax, ds:[esi]\n// "
      "013827fd: mov ds:[esi+0x4], eax\n// 01382800: call "
      "ds:[0x1470250]\n[-]8d4dcc348b8845db8d45db50e8// 013a5333: lea ecx, "
      "ss:[ebp+0xffffffffffffffcc]\n// 013a5336: xor b1 al, b1 0x8b\n// "
      "013a5338: mov b1 ss:[ebp+0xffffffffffffffdb], b1 al\n// 013a533b: lea "
      "eax, ss:[ebp+0xffffffffffffffdb]\n// 013a533e: push eax\n// 013a533f: "
      "call 0x136e3c0\n[-]8a014184c075f9// 00255350: mov b1 al, b1 "
      "ds:[ecx]\n// 00255352: inc ecx\n// 00255353: test b1 al, b1 al\n// "
      "00255355: jnz 0x255350\n[-]68????????ff15????" /**/
      "// 013a9c90: push "
      "0x1f4\n// 013a9c95: call ds:[0x5401a8]\n[-]fbff8bc885c9746e// 013ae5ec: "
      "mov ecx, eax\n// 013ae5ee: test ecx, ecx\n// 013ae5f0: jz "
      "0x13ae660\n[-]f9ff8d85// 013ccc1b: lea eax, "
      "ss:[ebp+0xfffffffffffffa78]\n[-]f8ff85c00f8489010000// 00c77583: test "
      "eax, eax\n// 00c77585: jz 0xc77714\n[-]05008be55dc3// 013e7a45: mov "
      "esp, ebp\n// 013e7a47: pop ebp\n// 013e7a48: "
      "retn\n[-]720000595985c07431// 002e74b3: pop ecx\n// 002e74b4: pop "
      "ecx\n// 002e74b5: test eax, eax\n// 002e74b7: jz "
      "0x2e74ea\n[-]6a0259cd29// 002e7559: push b1 0x2\n// 002e755b: pop "
      "ecx\n// 002e755c: int b1 0x29\n[-]578bfe2bf9// 002e93f1: push edi\n// "
      "002e93f2: mov edi, esi\n// 002e93f4: sub edi, ecx\n[-]f4fdff59// "
      "014596a8: pop ecx\n}condition:all of them}";

  Signature signature(signature_);
  auto* definition = signature.mutable_definition();
  definition->set_detection_name("test_malware");
  definition->set_trim_algorithm(SignatureDefinition::TRIM_RANDOM);
  definition->set_trim_length(200);
  EXPECT_THAT(formatter->Format(&signature), IsOk());
  EXPECT_THAT(MakeComparableYaraSignature(signature.yara_signature().data()),
              StrEq(kExpectedSignature));
}

TEST_F(SiggenTest, EmptyRawSignaturePieces) {
  AvSignatureGenerator siggen;
  const std::string file_name(JoinPath(
      getenv("TEST_SRCDIR"),
      "com_google_vxsig/vxsig/testdata/"
      "592fb377afa9f93670a23159aa585e0eca908b97571ab3218e026fea3598cc16_vs_"
      "65d25a86feb6d15527e398d7b5d043e7712b00e674bc6e8cf2a709a0c6f9b97b."
      "BinDiff"));
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
  constexpr char kTestData[] = "com_google_vxsig/vxsig/testdata/";
  // Intentionally add diffs in the wrong order.
  siggen.AddDiffResults({JoinPath(getenv("TEST_SRCDIR"), kTestData,
                                  "61971471cedcb4daed8d07ad79297568ffdaa17e"
                                  "b4ff301dc953cfafa91a4507_vs_"
                                  "8433c9a6345d210d2196096461804d7137bbf2a6"
                                  "b71b20cc21f4ecf7d15ef6c2.BinDiff"),
                         JoinPath(getenv("TEST_SRCDIR"), kTestData,
                                  "328b26dc3f0d8543e151495f4d6f3960323e3f51"
                                  "223522c2e4cd1e2fe9f9ed8f_vs_"
                                  "61971471cedcb4daed8d07ad79297568ffdaa17e"
                                  "b4ff301dc953cfafa91a4507.BinDiff")});
  Signature signature;
  EXPECT_THAT(siggen.Generate(&signature).ToString(),
              HasSubstr("Input files do not form a chain of diffs"));
}

}  // namespace security::vxsig
