# AppleJPEGDriver dispatch table — 18.7.2

The `AppleJPEGDriverUserClient` external-method table is in the kext's
`__DATA_CONST,__const` section. In the raw 18.7.2 kext it starts at file
offset `0x42080`; each entry is 40 bytes.

| Selector | Method | in size | out size | flags |
|---|---|---|---|---|
| 1 | decode (`AppleJPEGDriverIOStruct`, 0x58) | `0x58` | `0x58` | 0 |
| 2 | query | 0 | 0 | 0 |
| 3 | encode (`AppleJPEGDriverIOStruct`, 0x58) | `0x58` | `0x58` | 0 |
| 4 | Ext (0x1000 struct) | `0x1000` | `0x1000` | 0 |
| 5 | Ext (0x1000 struct) | `0x1000` | `0x1000` | 0 |
| 6 | 2024 async decode (0xDA0 struct) | `0xDA0` | `0xDA0` | **1** |
| 7 | 2024 async encode (0xDA0 struct) | `0xDA0` | `0xDA0` | **1** |
| 8 | privileged | 0 | 0 | 0 |
| 9 | privileged | 0 | 0 | 0 |

`sel0` (`getTarget`) is handled outside this table (the base userclient
method).

The `flags=1` on selectors 6/7 is the `allowAsync` bit: these are the
asynchronous 2024 paths. This explains why `jpegmethods` reached the handler
and returned the full `0xDA0` output size, but rejected a zeroed/partial
struct.

## Encoded pointers

Each entry starts with a chained/auth pointer, for example:

```
0x8050bcad01dfc12c
0x8050bcad01dfc160
0x8050bcad01dfc16c
0x8050bcad01dfc1a0
0x8050bcad01dfc1d4
0x8050bcad01dfc208
0x8050bcad01dfc23c
0x8050bcad01dfc270
0x8050bcad01dfc29c
```

The low 32 bits are target offsets in the kernelcache text; the high bits
carry the arm64e auth/diversity/key metadata. Resolving them to the kext's
C++ methods requires the kernelcache segment mapping, so the table is used
here for **selector/size/allowAsync** confirmation, not as a function symbol
table.

## Why it matters

- `sel6`/`sel7` are real async 2024 methods with a 0xDA0 struct and
  `allowAsync=1`.
- `sel4`/`sel5` are 0x1000 Ext methods.
- A working `kr=0` on any of them gives a new, larger input surface for a
  user-pointer/write search.
- The next probe (`jpegmethods2`) sets a notification port, uses proper
  encode surfaces, and tries the 0x58 header at offsets `0`, `0x10`, `0x58`,
  `0x100` inside 0xDA0/0x1000.

## See also

- [`applejpeg-methods.md`](applejpeg-methods.md)
- [`master-plan.md`](master-plan.md)
- [`../experiments/applejpeg/jpegmethods2.m`](../experiments/applejpeg/jpegmethods2.m)
