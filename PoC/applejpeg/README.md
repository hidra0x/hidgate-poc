# MOON Probe — open-source AppleJPEGDriver PoC

A small, readable iOS app that demonstrates the AppleJPEGDriver userclient
and the deferred use-after-free from **CVE-2026-20687** on iPhone XR
(A12) / iOS 18.7.2.

> **This is a crash PoC, not a jailbreak.**
> It will panic the kernel and reboot the device. Run it only on a spare
> phone you own. It does not provide kernel read/write, PAC/PPL bypass, or
> persistence.

## What it does

1. Finds `AppleJPEGDriver` and opens the userclient (type 0).
2. Checks `sel0`, `sel2`, `sel9`, `sel10`.
3. Creates a JPEG source IOSurface and a BGRA destination IOSurface.
4. Calls `sel1` with the `0x58`-byte `AppleJPEGDriverIOStruct`:
   - zeroed struct (expected `kIOReturnCannotLock`);
   - sync decode;
   - async decode.
5. Creates 2048×2048 surfaces, submits five async decodes, and closes the
   connection.
6. Tries to open Camera; otherwise shows an "Open Camera" alert.

Opening Camera after the prime triggers a synchronous 12 MP decode. On the
vulnerable build, the timeout frees a `JpegRequest` without removing its
queue node; a later completion walks the stale node and the kernel aborts.

## Requirements

- macOS with Xcode command line tools (for `build.sh`), or the GitHub Actions
  artifact.
- A spare iPhone XR (A12) on iOS 18.7.2 for the documented result.
- A signing/sideloading tool: Sideloadly, AltStore, Xcode, etc.

The app uses bundle ID `com.example.moonprobe`. Change it in
`Info.plist` to your own ID if your sideloading setup requires it.

## Build

```bash
./PoC/applejpeg/build.sh
```

Output:

```
build/MOONProbe.app
build/MOONProbe-unsigned.ipa
```

The IPA is unsigned. Sign it with your normal workflow before installing.

The GitHub Actions workflow `.github/workflows/build-applejpeg.yml` builds
the same IPA and uploads it as the `moonprobe-unsigned-ipa` artifact.

## Run

1. Sign and install `MOONProbe-unsigned.ipa` on the spare device.
2. Launch **MOON Probe**.
3. Wait for the log:

```
build=moonprobe pid=...
service=0x...
open type0 kr=0 conn=0x...
sel1 decode sync kr=0 outSize=88
sel1 decode async kr=0 outSize=88
big jpeg=... src=... dst=...
submit[0] kr=0 token=0x4141 out=0/0
...
submitted=5
closed after async submit
```

4. Open **Camera** manually and wait 15–20 seconds.
5. The phone panics and reboots.

## Expected panic

```
Kernel data abort
pc  = ... (AppleJPEGDriver)
x5  = 0xfeedfacefeedfacf
x6  = 0xfeedfacefeedfad3
x12 = 0
far = 0x308

0xfffffff008df3418:  ldrb w12, [x12, #0x308]
```

The panicking thread is `kernel_task`, not the app: the UAF is deferred.

## Logs

The app writes `moonprobe.log` to its Documents folder. To retrieve it:

1. Open **Files**.
2. **On My iPhone → MOON Probe**.
3. Copy `moonprobe.log`.

The panic log is in **Settings → Privacy & Security → Analytics &
Improvements → Analytics Data** as `panic-full-*.ips`.

## Safety

- The app intentionally panics the kernel.
- Do not run it on a primary phone.
- Save your data and keep a restore path available.
- iOS 18.7.7+ / 26.4+ are patched and will not reproduce the bug.
- The PoC is for security research on devices you own.

## More

- [AppleJPEG CVE notes](../../docs/applejpeg-cve-2026-20687.md)
- [Panic analysis](../../docs/applejpeg-panic-2026-10-30.md)
- [Kernel control ladder](../../docs/kernel-control.md)
- [Final test matrix](../../docs/final-tests.md)
- [Selector audit](../../docs/applejpeg-methods.md)
- Public PoC: https://github.com/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF

## License

MIT. See [`../../LICENSE`](../../LICENSE).
