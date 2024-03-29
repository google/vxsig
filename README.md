# VxSig

Copyright 2011-2024 Google LLC

Disclaimer: This is not an official Google product (experimental or otherwise),
it is just code that happens to be owned by Google.

## Introduction

VxSig is a tool and library to automatically generate AV byte signatures from
sets of similar binaries. It processes files generated by
[BinExport](https://github.com/google/binexport) and
[BinDiff](https://www.zynamics.com/software.html).

Signatures can be generated for [Yara](https://github.com/VirusTotal/yara) (the
default) and [ClamAV](https://www.clamav.net/).

## Status

VxSig is a mature tool that has been used at Google to create signature and scan
for many kinds of malware and targetted threats.

## Quick Start

VxSig uses [Bazel](https://bazel.build/) to build and manage its dependencies.
The preferred way to use a current version is via
[Bazelisk](https://github.com/bazelbuild/bazelisk), so install that first. For
example, on Debian-based Linux distributions do:

```bash
(cd /tmp && \
  wget -qO- \
  https://github.com/bazelbuild/bazelisk/releases/download/v1.19.0/bazelisk-linux-$(dpkg --print-architecture) \
  > bazelisk && \
  echo 'd28b588ac0916abd6bf02defb5433f6eddf7cba35ffa808eabb65a44aab226f7  bazelisk' | \
  sha256sum -c && \
  chmod +x bazelisk && \
  sudo mv bazelisk /usr/local/bin/ \
)
```

Refer to the Bazel
[Getting started guide](https://bazel.build/start) for how to get started on
other platforms.

Clone and run the build:

```bash
git clone https://github.com/google/vxsig && cd vxsig
bazelisk build -c opt //vxsig:vxsig
```

To build an example Yara signature:

```bash
bazel-bin/vxsig/vxsig --detection_name=VxSigTestSig --trim_length=400 \
  vxsig/testdata/592fvs2065.BinDiff
```

The output should look like this (truncated):

```
----8<--------8<---- Signature ----8<--------8<----                    
rule VxSigTestSig {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         00008bd85985db5975
         // 00401049: mov ebx, eax
         // 0040104b: pop ecx
         // 0040104c: test ebx, ebx
         // 0040104e: pop ecx
         // 0040104f: jnz 0x4010b7
      [-]110000435653e8
         // 004010c0: inc ebx
         // 004010c1: push esi
         // 004010c2: push ebx
         // 004010c3: call 0x40226c
      [-]1100006a10be
         // 004010fe: push b1 0x10
         // 00401100: mov esi, 0x4042a8
      [-]6a0056e8
         // 00401105: push b1 0x0
         // 00401107: push esi
         // 0040110b: call 0x402266
...
```

## Further reading / Similar tools

*   The original thesis that provided the basis for this tool (German language
    only):
    [Automatisierte Signaturgenerierung für Malware-Stämme](https://www.zynamics.com/downloads/blichmann-christian--diplomarbeit--final.pdf)
*   [zynamics VxClass](https://web.archive.org/web/20210224202639/https://www.zynamics.com/vxclass.html), a discontinued
    malware analysis pipeline using a previous version of VxSig.
*   Cisco's Talos Group's
    [BASS Automated Signature Synthesizer](https://github.com/Cisco-Talos/BASS),
    an open-source reimplementation of the thesis
*   [functionsimsearch](https://github.com/googleprojectzero/functionsimsearch),
    a tool that can be used to create a corpus of files for computing function
    occurrence counts.

## Getting Involved

If you want to contribute, please read [CONTRIBUTING.md](CONTRIBUTING.md) and
send pull requests. You can also report bugs or file feature requests.
