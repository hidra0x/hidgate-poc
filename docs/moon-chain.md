# MOON — the AppleJPEGDriver exploit chain

**MOON** is the name of the exploit chain built on CVE-2026-20687:

| Letter | Stage | What it means | State |
|---|---|---|---|
| **M** | Media entry | Open `AppleJPEGDriver` from the app sandbox, validate the `0x58` decode ABI | **DONE** |
| **O** | Object free | Drive a true sync decode into `kIOReturnTimeout`; the driver frees a `JpegRequest` without dequeuing its node | **DONE** |
| **O** | Object reuse | Reclaim the freed slot with a same-type request, or make the stale queue node point at controlled data | **IN PROGRESS** |
| **N** | Native primitive | Turn the reuse into a double-free/write, then KASLR/PAC/PPL and kernel control | **NOT YET** |

## M — Media entry

`IOServiceOpen("AppleJPEGDriver", 0)` succeeds from a sideloaded app.
`sel1` accepts the `0x58`-byte `AppleJPEGDriverIOStruct`; sync and async
decodes work. This is the open-source `MOON Probe` build.

## O — Object free

An 8000-request mass prime stalls the codec. A true sync decode
(`asyncToken=0`, `flags=0`) hits the driver's 10 s wait and returns
`kIOReturnTimeout` (`0xe00002d6`). The request is freed while its embedded
queue node stays in the per-codec vector.

## O — Object reuse

The stale node is read by `finish_io_gated` → queue helper:

```asm
ldr x12, [x8]        ; vector slot -> node
ldr x12, [x12, #8]   ; node + 8 -> self pointer
ldrb w12, [x12,#0x308]
```

When the slot is freed, `node+8` is zero and the read faults at `far=0x308`.
Same-type reclaims have not yet covered the exact codec/pool; the current
work is a codec sweep (`sel6`/`sel4` audit, 2048/4032 storms, notification
port). A successful reuse shows `x12 != 0` or a different `far`, not
`0xfeedface...`.

## N — Native primitive

Targets, in order:

1. a double-free of `JpegRequest`, or
2. an `IOSurface`/`IOUserClient` refcount corruption, or
3. a write through the queue node / decoder buffer setup.

Then KASLR, PAC (arm64e `autda`/`blraa`), PPL/SPTM, and a semi-tethered
bootstrap. No kernel r/w yet.

## Why MOON

The chain starts in the **media** decoder, frees an **object**, tries to
reuse it, and aims for a **native** primitive. Four letters, four gates.

## Links

- [Kernel control ladder](kernel-control.md)
- [Final tests](final-tests.md)
- [AppleJPEG CVE notes](applejpeg-cve-2026-20687.md)
- [AppleJPEG selector audit](applejpeg-methods.md)
- [Open-source PoC](../PoC/applejpeg/)
- [Hidra jailbreak project](https://github.com/hidra0x/hidra)
