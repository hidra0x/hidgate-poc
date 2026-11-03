# iOS 18.7.2 kernel candidate audit (A12 / iPhone11,8)

Target: iPhone XR (`iPhone11,8`), A12/T8020, iOS 18.7.2 (22H124),
kernel `xnu-11417.140.69.702.20~1`, AppleJPEGDriver 7.6.9.

This is the static + dynamic candidate map for the spare device. It lists
every kernel-relevant CVE fixed after 18.7.2, the component that changed,
whether a sandboxed app can reach it, and which CandProbe test covers it.

The companion app is [`experiments/candprobe/candprobe.m`](../experiments/candprobe/candprobe.m).
Build: `C:\Users\Public\jb\build_candprobe.sh`.

## 1. Method

1. Parsed Apple security notes for 18.7.3, 18.7.5, 18.7.7, 18.7.9,
   18.7.10 and 18.7.11 (18.7.4 and 18.7.6 have no published CVEs).
2. Extracted the 18.7.2, 18.7.9 and 18.7.10 kernelcaches and all 224 kexts.
3. Ran function-start normalisation (`fn_norm.py`) and sequence alignment
   (`align3.py`) on:
   - the kernel binary for 18.7.2 → 18.7.10 and 18.7.9 → 18.7.10;
   - AppleAVE2, AppleJPEGDriver, AppleH11ANEInterface, IOGPUFamily,
     IOSurface, IOHIDFamily, AppleAVD, AppleMultitouchDriver/SPI and
     AppleActuatorDriver for 18.7.2 → 18.7.10.
4. Resolved changed functions against the 18.7.2 kernel symbol map and
   against strings/asserts inside the kexts.
5. Built CandProbe to exercise the app-reachable surfaces on the device.

## 2. CVE matrix (fixed after 18.7.2)

Priority is exploitability from a sandboxed app, not CVSS.

| CVE | Fixed in | Component | Impact | App-reachable | CandProbe | Priority |
|---|---|---|---|---|---|---|
| CVE-2026-64747 | 18.7.10 | AVEVideoEncoder / AppleAVE2 | app may execute code with kernel privileges; buffer overflow, size validation | **yes**, via VideoToolbox / AppleAVE2Driver | `VT AVE`, `Raw AVE` | **P0** |
| CVE-2026-20687 | 18.7.7 | AppleJPEGDriver 7.6.9 | app may write kernel memory; UAF | **yes**, via AppleJPEGDriver | MOON / JPEG | **P0** |
| CVE-2026-43724 | 18.7.10 | Kernel | app may write kernel memory; input sanitisation | yes, Mach/BSD path | `Mach VM` | **P1** |
| CVE-2026-28972 | 18.7.9 | Kernel | app may write kernel memory; OOB write | yes, syscall path | `Mach VM` | **P1** |
| CVE-2026-43778 | 18.7.10 | Kernel | UAF; corrupt kernel memory | yes | `Mach VM` | **P1** |
| CVE-2026-64749 | 18.7.10 | Kernel | corrupt kernel memory | yes | `Mach VM` | **P1** |
| CVE-2026-39868 | 18.7.10 | Kernel | corrupt kernel memory; input validation | yes | `Mach VM` | **P1** |
| CVE-2026-64717 | 18.7.10 | Kernel | race; corrupt kernel memory | yes | `Mach VM` | **P2** |
| CVE-2026-43810 | 18.7.10 | Kernel | remote; corrupt kernel memory | network | none | P2 |
| CVE-2026-64760 | 18.7.10 | IOSurfaceAccelerator | app may leak sensitive kernel state | **yes**, IOSurface | generic scan | **P1** |
| CVE-2026-28943 | 18.7.9 | IOHIDFamily | app may determine kernel memory layout (KASLR) | **yes**, IOHID | generic scan | **P1** |
| CVE-2026-28868 | 18.7.7 | Kernel | app may disclose kernel memory (logging redaction) | yes | generic | P1 |
| CVE-2026-28867 | 18.7.7 | Kernel / mDNSResponder | leak sensitive kernel state | yes / network | generic | P2 |
| CVE-2026-43654 | 18.7.9 | Kernel | app may disclose kernel memory | yes | generic | P2 |
| CVE-2026-28897 | 18.7.9 | Kernel | local user may read kernel memory; buffer overflow | local | generic | P2 |
| CVE-2026-28987 | 18.7.9 | Kernel | leak sensitive kernel state (logging) | yes | generic | P2 |
| CVE-2026-64744 | 18.7.10 | Kernel | disclose kernel memory | yes | generic | P2 |
| CVE-2026-64709 | 18.7.10 | Kernel | disclose kernel memory | yes | generic | P2 |
| CVE-2026-43722 | 18.7.10 | Kernel | leak sensitive kernel state | yes | generic | P2 |
| CVE-2026-43754 | 18.7.10 | Kernel | leak sensitive kernel state (redaction) | yes | generic | P2 |
| CVE-2026-39877 | 18.7.10 | IOSkywalkFamily | disclose kernel memory | network kext | none | P3 |
| CVE-2026-64735 | 18.7.10 | Kernel | remote bypass of network filters | network | none | P3 |
| CVE-2026-64695 | 18.7.10 | APFS | remote corrupt kernel memory | disk image | none | P3 |
| CVE-2026-43822 / 43799 / 64700 | 18.7.10 | Kernel | UAF; unexpected termination | yes | generic | P3 |
| CVE-2026-43769 | 18.7.10 | Kernel | integer overflow; termination | yes | generic | P3 |
| CVE-2026-43809 / 43757 | 18.7.10 | Kernel | OOB read; termination | yes | generic | P3 |
| CVE-2026-64721 / 64723 | 18.7.10 | Kernel | sensitive user data / logic | yes | none | P3 |
| CVE-2025-43512 | 18.7.3 | Kernel | app may elevate privileges | yes | none | P2 |
| CVE-2025-46285 | 18.7.3 | Kernel | app may gain root; integer overflow in timestamps | yes | none | P2 |
| CVE-2026-20671 | 18.7.5 | Kernel | privileged network interception | network | none | P3 |
| CVE-2026-20621 | 18.7.5 | Wi-Fi | app may corrupt kernel memory | Wi-Fi | none | P3 |
| CVE-2026-43668 | 18.7.9 | mDNSResponder | remote UAF; corrupt kernel memory | network | none | P3 |
| CVE-2026-28819 | 18.7.9 | Wi-Fi | app may execute code with kernel privileges; OOB write | Wi-Fi | none | P2 |
| CVE-2026-28951 | 18.7.9 | Kernel | app may gain root; authorization | yes | none | P2 |
| CVE-2026-28952 | 18.7.9 | Kernel | integer overflow; termination | yes | none | P3 |
| CVE-2026-28986 | 18.7.9 | Kernel | race; termination | yes | none | P3 |
| CVE-2026-28954 | 18.7.9 | Kernel | Gatekeeper bypass via disk image | disk image | none | P3 |

18.7.11 has no kernel-related published entries.

## 3. Kext-level changes 18.7.2 → 18.7.10

Only these kexts changed between the target and the patched 18.7.10
kernelcache:

| Release | Kext | Version | Note |
|---|---|---|---|
| 18.7.5 | AppleActuatorDriver / AppleMultitouchDriver / AppleMultitouchSPI | 8140.5 → 8140.7 | input stack |
| 18.7.7 | **AppleJPEGDriver** | **7.6.9 → 7.6.10** | CVE-2026-20687; 2 functions changed |
| 18.7.8/9 | AppleActuator/Multitouch | 8140.7 → 8140.8 | input stack |
| 18.7.9 | IOTimeSyncFamily / IOgPTPPlugin | 1340.12 → 1340.13 | time sync |
| 18.7.10 | **AppleAVE2** | **803.73.1 → 803.73.3** | CVE-2026-64747; 19 functions changed |
| 18.7.10 | AppleAVD | 865 → 867 | video decode |
| 18.7.10 | AppleH11ANEInterface | 8.600.2 → 8.600.6 | ANE |
| 18.7.10 | IOGPUFamily | 104.6.3 → 104.6.4 | GPU |
| 18.7.10 | IOTimeSyncFamily / IOgPTPPlugin | 1340.13 → 1340.14 | time sync |

`IOSurface` itself did not change between 18.7.2 and 18.7.10. The
IOSurfaceAccelerator fix is in a component that is not a standalone kext in
this cache (or in the kernel proper); the service still needs dynamic
probing.

## 4. Kernel diff highlights

### 18.7.9 → 18.7.10 (66 changed blocks, 52 single-function blocks mapped)

Network / NECP / PF / IPv6 / key / BPF:

- `_bpfread`, `_bpfioctl`
- `_necp_create_domain_filter`, `_necp_client_parse_parameters`,
  `_necp_client_add`, `_necp_client_request_nexus`, `_necp_client_validate`,
  `_necp_client_check_tcp_heuristics`, `necp_open`
- `_netagent_ctl_getopt`, `_netagent_unregister_all_session_registrations`
- `_pf_test6`, `_pf_normalize_ip6`, `_pf_frag6cache`
- `_inp_join_group`, `_ip_input_process_list`, `_ip6_setmoptions`
- `_key_validate_address_ext_pair`, `_key_spddisable`, `_key_spdadd`
- `_flow_divert_handle_app_map_create`, `_flow_divert_handle_data`
- `_pktap_fill_proc_info`, `_inet_traffic_rule_match`

Mach / VM / task / process:

- `_exception_deliver`, `_set_exception_ports_validation`
- `_task_create_internal`, `_proc_set_task_ruse_cpu`
- `_vm_map_copyout_internal`, `_vm_map_protect`, `_vm_map_exec`
- `_mach_make_memory_entry_internal` (two blocks)
- `_vm_shared_region_map_file`, `_vm_shared_region_enter`
- `_vm_object_copy_slowly`, `_vm_object_upl_request`
- `posix_spawn`, `_threadsignal`, `memorystatus_get_level`
- `__shared_region_map_and_slide`

Filesystem / other:

- `_cluster_pagein_ext`, `_cluster_read_copy`
- `_mount_common`, `_fs_snapshot`, `chmod`, `utimes`
- `_devfs_rele_node`
- `_na_rings_mem_setup`, `_nx_mon_na_activate_common`
- `_tracker_dump`, `_tracker_entry_expire`
- `_firehose_buffer_tracepoint_reserve_slow.cold.1`

The presence of `mach_make_memory_entry_internal`, `vm_map_protect`,
`vm_map_copyout_internal`, `exception_deliver`, `task_create_internal` and
`posix_spawn` in the same patch window is why the Mach/VM cluster is the
first place to look for CVE-2026-43724 ("write kernel memory").

A concrete lead: 18.7.10 inserts a new `0x48`-byte outlined block at
`0xfffffff007f30fa0` (`mach_make_memory_entry_internal + 0x70`). It checks a
`vm_object` size/flag against a `vm_map_entry` offset
(`[x1,#0x10] & (-1 << [x0,#0x34])`) and branches into the entry
creation/deletion paths. This is exactly the kind of validation that would
be added for a memory-entry size/offset bug, and it is the first function
CandProbe's `Mach VM` edge-case test should stress.

### 18.7.8 → 18.7.9 (34 changed blocks, 29 single-function blocks mapped)

- `_mount_common`, `fs_snapshot`
- `_ip6_do_fragmentation`, `_sosetoptlock`
- `_kern_channel_tx_refill_common`, `_kr_txfinalize`, `_na_kr_teardown_common`
- `fsw_*`, `dp_flow_tx_process`, `_flow_init`, `_nx_netif_*`, `_pkt_*`
- `_fill_vlan_info`, `_pp_metadata_construct`
- `_firehose...`

This is the network/Wi-Fi cluster that contains CVE-2026-28819. It is not
directly app-reachable without the Wi-Fi userclient. CVE-2026-28943 is a
separate IOHIDFamily kext change and is covered by the HID selector scan.

## 5. Deep dive: CVE-2026-64747 (AppleAVE2)

### 5.1 What changed

AppleAVE2 803.73.1 (18.7.2 / 18.7.9) → 803.73.3 (18.7.10) changes 19
functions. The new binary adds these strings (not present in the 803.73.1
build shipped with 18.7.2 and 18.7.9):

```
AVE_CalcBufSizeOfColocated
AVE_CalcBufSizeOfCrcQPMod
AVE_CalcBufSizeOfEntropyCoding
AVE_CalcBufSizeOfLFSRef
AVE_CalcBufSizeOfLFSResult
AVE_CalcBufSizeOfLRSResult
AVE_CalcBufSizeOfMBInputCtrl
AVE_CalcBufSizeOfMBStats
AVE_CalcBufSizeOfMCTFOutput
AVE_CalcBufSizeOfSrcNeighborData
AVE_CalcBufSizeOfSrcNeighborFwData
AVE_CalcBufSizeOfSrcNeighborInfo
AVE_CalcBufSizeOfSrcNeighborPixel
... size overflow / pixel area overflow / negative dim / negative width
... width >= 0 && height >= 0 && iPixelProduct <= 2147483647
```

The 19 changed functions are the `AVE_CalcBufSizeOf*` cluster. The old
code computed block counts in 32-bit and multiplied by a per-format byte
size without an overflow check:

```
add  w8, w1, #0xf
asr  w8, w8, #4
add  w9, w2, #0xf
asr  w9, w9, #4
mul  w8, w9, w8
mov  w9, #0x1b0
mul  w8, w8, w9
add  w8, w8, #0xfff
and  w0, w8, #0xfffff000
```

The 18.7.10 code uses `smull` (64-bit), compares the block count against
`0x4bda13` / `0x348349`, and logs `size overflow` / `pixel area overflow`.
It also adds the explicit check `width >= 0 && height >= 0 &&
iPixelProduct <= 2147483647`.

**Working conclusion:** the 18.7.10 fix implies that 18.7.2 accepts
negative dimensions and/or a pixel product above `INT32_MAX`; the
resulting surface size wraps, the driver allocates a small buffer, and the
encoder can write past it. This is the strongest "app → kernel code
execution" candidate in the 18.7.2 image and needs dynamic confirmation.

### 5.2 AppleAVE2UserClient ABI (confirmed from 18.7.2)

Service class: `AppleAVE2Driver`; userclient: `AppleAVE2UserClient`.
The external-method table is at `__DATA_CONST` VA `0xfffffff007ad9288`,
stride `0x18`, selector 1..10. The table entries are chained fixups whose
targets are kernel-base-relative (`0xfffffff007004000 + low32`).

| Sel | Method | Input size | Output size | Handler (18.7.2) |
|---|---|---|---|---|
| 1 | IO_Open | `0x6e0` | `0x28` | `0xfffffff00897b7d0` |
| 2 | IO_Close | `0x28` | `0x20` | `0xfffffff00897c498` |
| 3 | IO_Config | `0x38` | `0x20` | `0xfffffff00897cd1c` |
| 4 | IO_Prepare | `0x2df70` | `0x20` | `0xfffffff00897d5dc` |
| 5 | IO_Start | `0x2df70` | `0x2d0` | `0xfffffff00897e0fc` |
| 6 | IO_Stop | `0x30` | `0x20` | `0xfffffff00897ec4c` |
| 7 | IO_Process | `0x30` | `0x20` | `0xfffffff00897f464` |
| 8 | IO_Complete | `0x30` | `0x20` | `0xfffffff00897fc7c` |
| 9 | IO_Flush | `0x30` | `0x20` | `0xfffffff008980494` |
| 10 | IO_Reset | `0x30` | `0x20` | `0xfffffff008980cac` |

`IO_Open` asserts:

```
pIn != nullptr && inSize >= sizeof(S_AVE_UCInParam_Open) &&
pOut != nullptr && outSize >= sizeof(S_AVE_UCOutParam_Open)
```

`S_AVE_UCInParam_Open` is `0x6e0` bytes. Confirmed fields:

- `+0x28`: 15-byte library version string, compared with `"803.73.1"`
  (`AVE_UCCmd_CheckParam_Open`). A mismatch fails with
  `library and driver mismatch`.
- `+0x698`: `VideoParams.ui32Width` (32-bit)
- `+0x69c`: `VideoParams.ui32Height` (32-bit)
- `+0x38`: 32-bit flag checked by `AVE_UCCmd_CheckParam_Open`
- `+0xa8`: sub-structure validated when `+0x38` is non-zero

`AVE_Client_CheckCommonInfo` reads `pInfo+0x698`/`+0x69c` and compares them
with the stored client dimensions; it does **not** apply a maximum or a
sign check in 18.7.2. The 18.7.10 fix adds exactly that check.

### 5.3 Test strategy

CandProbe has two independent paths:

1. **VT path** — `VTCompressionSessionCreate` with H.264/HEVC and
   dimensions: control 1920×1080, `-1×-1`, `-1×1080`, `1080×-1`,
   `INT32_MIN×2`, 46341×46341, 65535×65535, `0x40000000×2`.
   This is the public-API path an app would use.
2. **Raw path** — open `AppleAVE2Driver` directly and call selector 1 with
   a `0x6e0` struct, version string at `+0x28`, dimensions at
   `+0x698`/`+0x69c`. Presets vary the first `0x18` bytes and the `+0x38`
   flag.

If the device panics, `Documents/candprobe-state.txt` contains the last
`START ...` / `DONE ...` pair.

## 6. AppleJPEGDriver CVE-2026-20687

AppleJPEGDriver 7.6.9 (18.7.2) vs 7.6.10 (18.7.7 and later) changes
exactly two functions:

| Old | Size | New | Size | Note |
|---|---|---|---|---|
| `0xfffffff008df8300` | `0x5ec` | `0xfffffff008df9e50` | `0x5c8` | `AppleJPEGDriver::queue_io_gated(JpegRequest *)` |
| `0xfffffff008dfa704` | `0x11c` | `0xfffffff008dfc230` | `0x150` | wrapper referencing `sleepCommandGate` |

The first function is confirmed by its own assert strings:

```
IOReturn AppleJPEGDriver::queue_io_gated(JpegRequest *)
failed to pass the request validation return 0x%x
failed to pass the request setup return 0x%x
```

The 18.7.10 version of `queue_io_gated` adds early `cbz` null/state checks
before the request is queued and replaces the old `w2 = 10000` wait path
with a zero-timeout path. That is the 7.6.10 fix for the deferred
`JpegRequest` lifetime.

The known 18.7.2 panic is a read UAF in the OSArray iterator:
`pc=0x8df3418`, `ldrb w12,[x12,#0x308]`, `x12=0`, after a deferred
`JpegRequest` is freed by the 10 s sync timeout. MOON already demonstrates
the reachable UAF. The fix is in the exact queue function that contains the
stale-node walk, so CVE-2026-20687 is confirmed as the AppleJPEG bug.

Status: **read UAF confirmed; write/overlap not yet obtained.** Continue
with `jpegclose7`/`jpegmethods2` and the MOON test matrix. The AVE path is
now the higher-priority write candidate because the fix is a clear
integer-overflow/buffer-overflow class.

## 7. Priority order

1. **AppleAVE2 / CVE-2026-64747** — public VT API, negative-dimension and
   pixel-area overflow, 18.7.10 fix is a size-validation patch. Test
   `VT AVE` first, then `Raw AVE`.
2. **AppleJPEGDriver / CVE-2026-20687** — already have a reachable UAF;
   need a write/overlap from the stale queue node. Run `jpegclose7` and
   `jpegmethods2` alongside CandProbe.
3. **Mach/VM cluster / CVE-2026-43724, 28972, 43778, 64749, 39868** —
   the 18.7.10 patch touches `mach_make_memory_entry_internal`,
   `vm_map_protect`, `vm_map_copyout_internal` and `exception_deliver`.
   Use `Mach VM` edge cases; if a call returns an unexpected success or
   panics, that is the next target.
4. **IOSurfaceAccelerator / CVE-2026-64760** — leak; use generic selector
   scan and IOSurface-backed inputs.
5. **IOHIDFamily / CVE-2026-28943** — KASLR/layout leak; generic scan on
   HID services.
6. **Kernel leak CVEs** — use any successful candidate to get a KASLR
   base before attempting data-only control.

## 8. Running CandProbe

1. Install `candprobe-reuse-hidgate4.ipa` with the same sideload method as
   the other `com.example.hidgate4` builds.
2. Launch, tap **1. Enumerate IOKit (safe)**. Send the log; it lists every
   service whose class matches the media/GPU/HID families and which open
   types succeed.
3. Tap **2. VT AVE overflow / negative dims**. This is the main test.
   If the app disappears, reboot and send `Documents/candprobe-state.txt`
   plus `panic-full` if present.
4. Tap **3. Raw AppleAVE2 open presets** and **4. AppleAVE2 selector scan**.
5. Tap **5. Generic media/GPU/HID selector scan** only after the targeted
   tests; it is intentionally broad and may panic.
6. Tap **6. Mach VM edge cases** last.
7. Use **Share log** to export `candprobe-*.log`.

A panic is a result, not a failure: the breadcrumb tells us which
service/selector/input size reached the kernel.

## 9. Dynamic results on the spare XR (2026-11-03)

### IOKit reachability

`IOServiceOpen` results from the 18.7.2 device:

| Service | Types opened | Note |
|---|---|---|
| `AppleJPEGDriver` | 0, 1, 2 | reachable; CVE-2026-20687 |
| `AppleM2ScalerCSCDriver` | 0, 1, 2 | IOSurfaceAccelerator surface |
| `AGXAcceleratorG11P_B0` | 1 | GPU |
| `H11ANEIn` | 1 | ANE / newjail surface |
| `IOSurfaceRoot` | 0 | IOSurface KVA |
| `AppleAVE2Driver` | none | `IOServiceOpen` returns `0xe00002e2` (`kIOReturnNotPermitted`) for types 0–7 |
| `IODARTMapper` / `AppleSPUHIDDriver` | none | `0xe00002c2` / `0xe00002c1` |

The direct raw `AppleAVE2Driver` path is blocked for a sandboxed app. AVE
can only be reached through `mediaserverd` / VideoToolbox, which has the
required entitlement.

### VideoToolbox / AVE

- Control `1920x1080`: encoder ID
  `com.apple.videotoolbox.videoencoder.h264`; `prepare`/`encode` succeed
  and the callback returns a sample buffer.
- `46341x46341`, `65535x65535`, `0x40000000x2`: encoder ID
  `com.apple.videotoolbox.videoencoder.h264.rtvc` (software fallback);
  the 64x64 frame callback returns `-12902` (`kVTParameterErr`). The huge
  sizes do **not** reach AppleAVE2.
- Negative dimensions: `VTCompressionSessionCreate` returns `-12902`
  before any encoder is selected.
- v0.7 selects the hardware H264 encoder by
  `kVTVideoEncoderList_IsHardwareAccelerated`, forces it for the huge
  sizes, and calls `VTCopySupportedPropertyDictionaryForEncoder` first.
- The forced hardware query returns `st=-12902` (`kVTParameterErr`) for
  46341x46341, 65535x65535 and 0x40000000x2. The hardware H264 encoder
  therefore rejects the dimensions that would overflow the AVE size math.
  The default VT path returns `st=0` only because it falls back to the
  software `h264.rtvc` encoder.
- The malformed IOSurface frame test (v0.8) is closed: `IOSurfaceCreate`
  returns NULL for 46341x46341, 65535x65535, -1x-1, 8192x8192 and
  16384x16384 when `kIOSurfaceAllocSize` is 0x4000. Only the 1920x1080
  control is created. AVE cannot be reached through a tiny-allocation
  huge surface.

### Targeted scan v0.7

| Service | Result |
|---|---|
| `AppleM2ScalerCSCDriver` t=0/1/2 | all selectors 0xe00002c2 (bad argument) or 0xe00002c7 (unsupported) |
| `H11ANEIn` t=1 | all selectors 0xe00002c2 |
| `AGXAcceleratorG11P_B0` t=1 | sel 6 / in 0x10 → 0x1; sel 9 / in 0x58+ → 0xe00002be (`kIOReturnNoResources`) |
| `AppleJPEGDriver` t=0/1/2 | sel 4 / in 0x1000 → 0xe00002bc (`kIOReturnError`); sel 5 / in 0x1000 → 0xe00002cc (`kIOReturnCannotLock`) |
| `IOSurfaceRoot` t=0 | all selectors 0xe00002c2 |

The zero-struct scan found live selectors but no success/leak. These
services need their real ABI (IOSurfaceAccelerator API, ANE command
structures, the AppleJPEG 0x58 request, AGX context structures).

### Mach memory entry

With a real 0x4000 mapping at `0x10582c000`:

- `size=0x1000/0x4000/0x8000/0x100000000/0x7fff.../0x8000...` → `kr=0`,
  but the in/out `size` is clamped to `0x4000` (the mapping size).
- `size=0xffffffffffffffff` and `0` → `kr=0x4`
  (`KERN_INVALID_ARGUMENT`).
- `addr+0x0/+0x1/+0x1000` → `kr=0`; `addr+0x4000` → `kr=1`
  (`KERN_INVALID_ADDRESS`); `addr+0x8000` → `kr=2`
  (`KERN_PROTECTION_FAILURE`).
- `addr + 0xfffffffffffff000` wraps to `addr-0x1000` and returns `kr=0`
  because the previous page is mapped.

No memory-entry overflow was observed. The 18.7.10 validation block may
cover a different `vm_object`/`parent_entry` pattern, not the simple
huge-size case.

### SO_RESOLVER_SIGNATURE / NECP lead

The 18.7.8 → 18.7.9 diff includes `_sosetoptlock` (0x1100 → 0x1114 bytes).
The option table maps `0x1131` to `SO_RESOLVER_SIGNATURE`, a `SOL_SOCKET`
option that calls into `_necp_set_socket_attribute`. It is directly
reachable from an app with `setsockopt(fd, SOL_SOCKET, 0x1131, buf, len)`.

This makes it a candidate for the CVE-2026-28972 class ("out-of-bounds
write" in the kernel, fixed in 18.7.9).

Dynamic result (v1.0/v1.1): `SO_RESOLVER_SIGNATURE` returns success
(`r=0`, `errno=0`) for AF_INET and AF_INET6, SOCK_STREAM and SOCK_DGRAM,
for every length 0..4096. Lengths 8192 and above return `EINVAL`; AF_UNIX
returns `EINVAL`. The 4096-byte cap is present in 18.7.2, so the simple
length-overflow hypothesis for CVE-2026-28972 is **closed**. The option may
still be worth testing with a valid signature blob and a NECP-triggering
connection, but it is no longer the primary candidate.

### Next empirical step

1. Run CandProbe v1.0 button 9 (`SO_RESOLVER_SIGNATURE`) first. It tests
   the `_sosetoptlock`/NECP path with AF_INET, AF_INET6 and AF_UNIX and
   lengths 0..4096. A panic is the CVE-2026-28972 signal.
2. Run button 8 (malformed IOSurface frame). If AVE uses the frame/surface
   dimensions instead of the session dimensions, this is the last path to
   `AVE_CalcBufSizeOf*`.
3. If both fail, treat AVE as **not app-reachable on 18.7.2**: raw is
   `kIOReturnNotPermitted`, VT hardware rejects the overflow dimensions,
   and the software fallback is a different encoder.
4. Pivot to the reachable surfaces:
   - `AppleJPEGDriver` — confirmed UAF; convert the stale queue node into
     a write/overlap (MOON / `jpegclose7`).
   - `AppleM2ScalerCSCDriver` / IOSurfaceAccelerator — real ABI, leak
     CVE-2026-64760.
   - `AGXAcceleratorG11P_B0` — sel 6/9 are live; needs context structs.
   - `H11ANEIn` — newjail ANE path; needs command structures.
