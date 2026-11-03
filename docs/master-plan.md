# Master plan — from AppleJPEG UAF to data-only kernel control

Target: iPhone XR (`iPhone11,8`), A12 / T8020, iOS 18.7.2 (22H124).
Constraint: Windows/WSL only, spare device, no Mac required for research.
Goal: kernel read/write, then data-only control, then a semi-tethered
bootstrap. No kernel text patching, no fake PAC pointers.

## 1. Where we are

| Item | State |
|---|---|
| AppleJPEG userclient + 0x58 ABI | **done** |
| Deferred `JpegRequest` UAF | **done** |
| Controlled 10 s free (`kIOReturnTimeout`) | **done** |
| Same-type reclaim | **observed, not stable** |
| `sel6`/`sel4` (0xDA0/0x1000) | reachable, wrong input layout |
| Kernel write/read primitive | **not yet** |
| PAC / PPL / KTRR bypass | **not reached** |
| 18.7.2 candidate audit | **done** — [`kernel-candidates-18.7.2.md`](kernel-candidates-18.7.2.md) |
| CandProbe app | **built** — [`../experiments/candprobe/`](../experiments/candprobe/) |

The current panic is a **read UAF**: `far=0x308`, `x12=0`,
`x5/x6=0xfeedface...` in the AppleJPEG queue helper. It is not a PAC/PPL
failure. The blocker is S4: we need a write/read primitive.

## 2. Strategy

Two parallel tracks. Track A is the primary; Track B is the fallback if the
AppleJPEG typed-zone path stays read-only.

- **Track A:** turn the AppleJPEG stale node into a double-free, an
  IOSurface/IOUserClient refcount corruption, or a DART/buffer write.
- **Track B:** audit another 18.7.2 kext/userclient for a direct user pointer
  or write path.

Only after a write/read primitive exists do we start KASLR/PAC/PPL work.
The post-write strategy is **data-only**:
[`data-only-plan.md`](data-only-plan.md).

## 3. Track A — AppleJPEGDriver

### A1. Selector audit (P0)

Build/run `jpegmethods2` and `jpegmethods` successors:

- set a notification port;
- use proper encode surfaces (BGRA source, raw JPEG dest);
- try the 0x58 header at offsets `0`, `0x10`, `0x58`, `0x100` inside
  0xDA0/0x1000;
- log `kr`, `outSize`, and notification messages.

Exit criteria:

- any of `sel3/4/5/6/7` returns `KR_SUCCESS`;
- or a selector panics at a reproducible offset — that becomes the target.

Sources: [`../experiments/applejpeg/jpegmethods2.m`](../experiments/applejpeg/jpegmethods2.m),
[`applejpeg-methods.md`](applejpeg-methods.md).

### A2. Static reverse of the 0xDA0/0x1000 structs (P0)

Locate in the 18.7.2 kext:

- `startDecoderExt` / `startEncoderExt`;
- `startDecoder2024` / `startEncoder2024`;
- the userclient external-method dispatch table.

Map every struct field to:

- a request field write;
- an `IOSurface`/DART setup read;
- a `copyin`/`copyout`;
- a user pointer or a Mach port.

Exit criterion: a field that reaches a kernel write/dereference without
validation. That is the preferred primitive.

### A3. Free-path / double-free (P1)

The queue helper is read-only. To get a write, make the driver **free the
request twice** or free a referenced object:

- keep the reclaimed request in flight, close its connection, then complete;
- vary close-before/after-submit timing;
- free one reclaimer connection at a time and probe after each;
- watch for `kalloc`/`zone`/`freelist` panic signatures.

Builds: `jpegclose6`, `jpegclose7`, and successors.

### A4. IOSurface / IOUserClient refcount (P1)

The request holds source/dest IOSurface and userclient references.

- submit a decode;
- release/destroy the source or dest IOSurface before completion;
- force the completion/timeout;
- look for an IOSurface/UC UAF or refcount underflow.

If an IOSurface object is freed while still reachable, reclaim it with a new
IOSurface (same type) and look for a controllable field.

### A5. DART / decoder buffer write (P2)

If a request field that controls the destination surface/DART mapping can be
overwritten, the hardware decoder writes pixels to a controlled physical
range. This is the most direct "write kernel memory" path, but it needs a
controlled field write first.

## 4. Track B — alternate kexts

If Track A stays read-only after the A3/A4 experiments, the 18.7.2 →
18.7.10 audit already gives the strongest alternate: **AppleAVE2
CVE-2026-64747**. The 18.7.10 diff adds `AVE_CalcBufSizeOf*` overflow
checks and a `width >= 0 && height >= 0 && iPixelProduct <= 2147483647`
check. CandProbe exercises both the public VideoToolbox path and the raw
`AppleAVE2Driver` selector 1.

Other alternates:

- `IOSurfaceAccelerator` (`accelprobe2`);
- `AppleAVE2` / media decoder userclients;
- `AppleJPEGDriver` encode path (`sel3`, `sel7`);
- `IOHIDEventService` providers other than the SPU one;
- any userclient reachable from the app sandbox with a 0x1000+ struct.

The criterion is the same: a user pointer, a buffer descriptor, or a
refcount that reaches a kernel write.

## 5. After the write — data-only control

1. **KASLR:** use the new read primitive or a side channel.
2. **Data-only targets:**
   - `proc` / `task` / `p_ucred`;
   - `kauth_cred_t` (uid/gid, groups, entitlements);
   - `csflags` (`CS_DEBUGGED`, `CS_PLATFORM_BINARY`);
   - AMFI / MACF policy data;
   - launchd/bootstrap data.
3. **No kernel text patching** (KTRR/CPRR-class).
4. **No page-table changes unless required** (PPL). Prefer a data-only
   bootstrap via a trusted launchd child.
5. **Persistence:** semi-tethered launchd hook + bootstrap; recovery path.

## 6. Timeline and gates

| Gate | Target | Exit criterion | Confidence |
|---|---|---|---|
| G1 | 1–2 weeks | working `sel4/5/6/7` layout or a new panic offset | medium |
| G2 | 2–6 weeks | double-free/refcount/write primitive | medium-low |
| G3 | 1–3 months | KASLR leak | low |
| G4 | 2–4 months | data-only patch of proc/cred/csflags | low |
| G5 | Q2 2027 | closed beta bootstrap on the XR | low |
| G6 | Q3 2027 | public beta, if G2–G5 pass | low |

If G2 fails after the planned experiments, pivot to Track B. If G4 is blocked
by PPL, start a PPL-specific research track; do not patch text.

## 7. Test protocol

- One build answers one question.
- Every build logs to a file and, on panic, produces a `panic-full` with
  `pc`, `far`, `x5/x6`, `x12`, `esr`, and the kext backtrace.
- A result is accepted only if it reproduces on a clean boot.
- No result is called "control" unless it shows:
  - a controlled register/`far` value, or
  - an arbitrary read/write, or
  - a double-free that can be converted into an overlap.

## 8. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Typed zone blocks reclaim | no write | free-path/refcount path, Track B |
| PAC blocks function pointers | no PC control | data-only |
| PPL blocks page tables | no bootstrap | data-only launchd path |
| KTRR blocks text patches | no kernel patch | never patch text |
| Test device instability | lost time | spare device, recovery path |
| Apple patches 18.7.2 | target disappears | stay on 18.7.2, no updates |

## 9. What I need from the test device

- Run `jpegmethods2` and send `jpegmethods2.log` + `panic-full` if it reboots.
- Run `jpegclose7` and send `jpegclose7.log` + `panic-full`.
- Report whether the panic is:
  - same `0x308` read,
  - `kalloc/zone` double-free,
  - different `far`/PC,
  - power-state timeout.

That data decides G1/G2 and whether we continue Track A or pivot.
