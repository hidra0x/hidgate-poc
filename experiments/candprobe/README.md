# CandProbe

A12 / iOS 18.7.2 kernel candidate surface probe. Build output reuses the
`com.example.hidgate4` bundle ID so it can be installed with the existing
sideload workflow.

## What it tests

| Button | Surface | Candidate |
|---|---|---|
| 1. Enumerate IOKit | all `IOService` classes; open types 0–2 for media/GPU/HID families | reachability map |
| 2. VT AVE | `VTCompressionSessionCreate` with negative / overflowing dimensions | CVE-2026-64747 |
| 3. Raw AVE | `AppleAVE2Driver` selector 1 (`S_AVE_UCInParam_Open`, `0x6e0`) | CVE-2026-64747 |
| 4. AVE selector scan | selectors 1–10 with the real input sizes from the 18.7.2 dispatch table | CVE-2026-64747 |
| 5. Generic scan | selectors 0–15 with `0x10/0x30/0x58/0x100/0x1000` structs on media/GPU/HID services | IOSurfaceAccelerator, IOHIDFamily, AVE, AGX |
| 6. Mach VM | `mach_make_memory_entry_64` / `vm_protect` edge cases | CVE-2026-43724 / 28972 / 43778 |

## Build

From Windows/WSL:

```bash
wsl -e bash /mnt/c/Users/Public/jb/build_candprobe.sh
```

The IPA is written to:

- `/tmp/jb/candprobe/candprobe-reuse-hidgate4.ipa`
- `C:\Users\Артем\candprobe-reuse-hidgate4.ipa`

## Run

1. Install the IPA with the usual sideload tool.
2. Tap **1. Enumerate IOKit (safe)** and export the log.
3. Tap **2. VT AVE overflow / negative dims**.
4. If it survives, tap **3** and **4**.
5. Tap **5** only after the targeted tests.
6. Tap **6** last.

## Crash breadcrumb

Before every risky call the app writes and fsyncs:

```
Documents/candprobe-state.txt
[HH:mm:ss.SSS] START VT create neg-1x-1 codec=... -1x-1
[HH:mm:ss.SSS] DONE VT create ... st=-...
```

After a panic, reboot, launch the app again, and the last breadcrumb is
shown at the top and included in the new log. Send both the log and the
breadcrumb file.

## Notes

- 18.7.2 is the target; 18.7.10 is the patched comparison image.
- The AppleAVE2 18.7.10 diff adds `AVE_CalcBufSizeOf*` overflow checks and
  the `width >= 0 && height >= 0 && iPixelProduct <= 2147483647` check.
- The AppleJPEGDriver 7.6.9 → 7.6.10 diff changes two functions; the known
  UAF is still the MOON path.
- No kernel text patching and no fake PAC pointers are used.
