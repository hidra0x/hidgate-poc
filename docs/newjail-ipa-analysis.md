# `newjail.ipa` analysis

`newjail.ipa` is a 291 KB arm64 iOS app (`com.example.newjail`) with a
Objective-C UI and a C exploit-research framework. It is **not** a ready
jailbreak for iOS 18.7.2 / A12, and it is not a drop-in kernel-control port.

## What the binary contains

The app exposes these modes:

| Mode | Entry point | Purpose |
|---|---|---|
| KASLR | `_nj_stage0_kaslr_leaks` | try gRegistryRoot / AIO / m2scaler leaks |
| ANE | `_nj_stage1_ane_corrupt` | build a corrupted victim port via AppleH1xANE |
| 86950 | `_nj_entry_86950_*` | CVE-2026-86950 probes (IOKit / CoreGraphics groom) |
| 112611 | `_nj_entry_112611_*` | CVE-2026-112611 CoreGraphics shading OOB probes |
| KRW | `_nj_stage2_build_krw*` | fake task port + `mach_vm_read/write` |
| Sandbox | `_nj_stage3_sandbox_escape` | sandbox escape stage |
| Install | `_nj_stage4_install_jb` | bootstrap install stage |
| Full chain | `_nj_entry_full_chain` | run KASLR → KRW |

The CVE numbers in the strings are **internal/research labels**, not verified
Apple advisories. The app is a playground, not a published exploit.

## KASLR stage

`_nj_stage0_kaslr_leaks` tries:

1. `CVE-2026-65371` — `IODisplayWrangler` / `IOConsole` `gRegistryRoot` leak;
2. `CVE-2026-84530` — AIO `kn_sdata` leak via `kqueue` + `aio_read`;
3. `m2scaler` — `IOSurfaceAcceleratorCreate` / `IOSurfaceAcceleratorGetDiag`.

It has a **mock mode**:

```
NJ_MOCK_KASLR=1
[stage0] MOCK MODE: Using fake KASLR values
```

The mock values are `0xfffffe0000000000` and `0xfffffe0000001000`. A real run
must produce a kernel pointer; otherwise the KRW stage has nothing to use.

## KRW stage

There are two functions:

- `_nj_stage2_build_krw` at `0x10001982c` — a **stub**. It logs
  "Build-specific offsets required for full exploitation" and returns `-1`.
- `_nj_stage2_build_krw_from_leaks` at `0x1000198b8` — the actual framework.

The framework:

1. Requires three inputs: a leaked `reg`, a leaked `surf` (IOSurface KVA),
   and a corrupted victim `port`.
2. Computes:
   - `kernel_base = reg & 0xfffffffffe000000` (32 MB alignment);
   - `kslide = reg + 0x1fff8ffc000`;
   - `kernel_task = reg + 0x280`.
3. Creates an IOSurface (0x40 × 0x40, pixel format `0x42475241`), locks it,
   and writes a fake port at the surface base:
   - `*(u64 *)base = 1`;
   - `*(u64 *)(base + 0x10) = 0`;
   - `*(u64 *)(base + 0x18) = 0`.
4. Sends `mach_msg` to the corrupted victim port (option `0x102`,
   timeout `0x64`).
5. Extracts `tfp0` from the received message if present.
6. Tests `mach_vm_read_overwrite(tfp0, kernel_task, 8, ...)`.
7. On success, stores `tfp0` and `kslide`; `_nj_kread64` and `_nj_kwrite64`
   use `mach_vm_read_overwrite` / `mach_vm_write`.

This is a classic **fake task port** KRW, not a PAC function-pointer exploit.
That part is compatible with a data-only strategy.

## Why it is not a drop-in 18.7.2/A12 port

- `kernel_base`, `kslide`, and `kernel_task` are **hardcoded offsets** from a
  different build/leak source.
- The fake port layout (`+0x10`, `+0x18`) and the `mach_msg` message layout are
  build-specific.
- The KASLR stage has a mock mode; a mock leak cannot build a real KRW.
- The ANE stage must produce a corrupted victim port. Without it, the fake
  port has no receiver.
- No evidence in the binary that these offsets were validated on
  `iPhone11,8` / 18.7.2 / `xnu-11417.140.69.702.20~1`.

## What is useful for us

1. The **fake task port** design: IOSurface-backed fake port + `mach_msg` +
   `mach_vm_read_overwrite`/`mach_vm_write`.
2. The **kread64/kwrite64 wrappers** as a template.
3. The **leak-source ideas** (gRegistryRoot, AIO, m2scaler) as candidates to
   test on 18.7.2.
4. The **stage orchestration** (KASLR → ANE port → KRW → sandbox → install).

## Porting gate

Do not port the KRW until these are true on the target:

| Gate | Test | Required result |
|---|---|---|
| G1 | Run `KASLR` mode on the XR | a real kernel pointer, not mock |
| G2 | Run `ANE` mode | a non-zero corrupted victim port |
| G3 | Verify `kernel_task` offset | matches 18.7.2/A12 kernel |
| G4 | Verify fake port layout | `mach_msg` receives a port |
| G5 | `mach_vm_read_overwrite(tfp0, kernel_task, 8)` | reads kernel memory |

If G1/G2 fail, the IPA is a dead end for this target. Stay on the AppleJPEG
write path.

## How to test

1. Install `newjail.ipa` on the spare XR (bundle ID `com.example.newjail`).
2. Launch it.
3. Run **KASLR** mode; capture the log.
4. Run **ANE** mode; capture the log.
5. Do not run **Full Chain** until G1/G2 are confirmed.

The app's log is the only way to know whether the KASLR/ANE stages are real
on this device.

## Safety

The app can panic, corrupt kernel memory, or bootloop the device. Use only a
spare phone with a restore path. The code is an untrusted research binary;
do not run it on a primary device.
