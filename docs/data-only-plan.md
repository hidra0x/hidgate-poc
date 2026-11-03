# Data-only kernel control plan — A12 / iOS 18.7.2

This is the post-write plan. It assumes the AppleJPEG UAF eventually gives a
kernel write/read primitive. It does **not** claim that primitive exists yet.

## Why data-only

On A12 / iOS 18.7.2 we must assume:

- **PAC** is active (arm64e `autda` / `blraa`);
- **PPL/KTRR-class** protections cover page tables and kernel text;
- kernel text cannot be patched after boot;
- a fake vtable or forged function pointer will fault before it runs.

The practical path is **data-only**: modify writable kernel data that controls
security policy, process credentials, code signing, and bootstrap behavior.
Do not patch kernel code. Do not forge PAC pointers unless a signing
gadget/oracle is found.

## Where we are

| Stage | State |
|---|---|
| Read UAF in AppleJPEGDriver | **confirmed** |
| Controlled free (10 s timeout) | **confirmed** |
| Same-type reclaim | **observed, not stable** |
| Write/read primitive | **not yet** |
| PAC/PPL/KTRR bypass | **not reached** |

The current panic (`far=0x308`, `x12=0`, `x5/x6=0xfeedface...`) is a **data
abort in the AppleJPEG queue helper**, not a PAC/PPL/KTRR failure. `x12=0` is
a freed queue-node self-pointer. Do not confuse it with a PAC fault.

## PAC — avoid, do not fight

The `finish_io_gated` call is:

```asm
ldr x0, [x19]        ; request->task
ldr x16, [x0]        ; task->vtable
autda x16, x17       ; data PAC
ldr x8, [x16, #0x28]!
blraa x8, x17        ; authenticated call
```

A same-type `JpegRequest` reclaim cannot change `request->task`; a fake task
needs a signed vtable pointer for its address. Without a signing oracle or a
kernel read, this path is closed.

Data-only avoids it entirely. Target data that the kernel reads but does not
authenticate with PAC:

- `proc` / `task` flags and `p_ucred`;
- `kauth_cred_t` (uid/gid, groups, entitlements);
- code-signing flags (`csflags`, `CS_DEBUGGED`, `CS_PLATFORM_BINARY`);
- AMFI / MACF policy data;
- `launchd` / bootstrap-related data;
- trust-cache / signature-policy data where writable.

The goal is to make the kernel treat our process (or a launchd child) as
trusted, not to execute a forged function pointer.

## PPL — avoid page tables

PPL protects page tables. Data-only does not need to mark pages RWX or modify
`pmap` for a first-stage jailbreak. A semi-tethered bootstrap can be installed
by:

1. gaining root/entitlement data in `ucred`;
2. disabling or relaxing code-signing policy data;
3. spawning a launchd child with a trusted label;
4. loading a bootstrap dylib/daemon through existing kernel code paths.

Only if a step requires page-table changes should we look for a PPL
data-only bug (physical-map mismatch, PPL context transition). That is a
separate research project.

## KTRR / CPRR — no kernel text patching

Kernel text is physically protected. Do not plan on:

- writing to `__TEXT`;
- patching syscall tables;
- installing a kernel extension;
- RWX pages.

Data-only targets live in writable kernel data (`__DATA`, zones, process
structures), not in text.

## Panic triage

| Panic signature | Meaning |
|---|---|
| `Kernel data abort` in AppleJPEGDriver, `far=0x308`, `x12=0` | stale queue node; read UAF, not PAC/PPL |
| `x5/x6=0xfeedface...` | freed-zone poison |
| translation/permission fault on a kernel text address | PPL/KTRR-class protection |
| `BRK`, invalid PC, `autia`/`autda`/`blraa` in the trace | PAC failure |
| `kalloc`/`zone`/`freelist` | double-free; this is the write path we want |

## Next steps

1. **S4:** turn the AppleJPEG stale node into a double-free or a write. Focus
   on the free path and object refcounts, not function pointers.
2. **S5:** leak KASLR with the new primitive.
3. **S6:** modify data-only targets (proc/cred/csflags/AMFI/MACF) and verify
   with a read-back.
4. **S7:** spawn a trusted launchd child and load the bootstrap; keep kernel
   text untouched.
5. Only if a step is blocked by PPL should we start a PPL-specific research
   track.

## See also

- [Kernel control ladder](kernel-control.md)
- [MOON chain](moon-chain.md)
- [AppleJPEG selector audit](applejpeg-methods.md)
- [Hidra architecture](https://github.com/hidra0x/hidra/blob/main/docs/architecture.md)
