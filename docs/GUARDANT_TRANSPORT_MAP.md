# Guardant transport: static evidence map — 2026-10-19

This is a read-only inventory of the extracted distribution, not evidence of a
successful license check or an observed dongle transaction. File discovery used
`rg --files`; `pefile` inspected normal/delay imports, exports and PE address
mapping for 167 DLL/EXE paths. Selected device-name literals and small static code
windows were checked locally. No original executable was run, no native API or
device was called, and no original file was modified. A second review confirmed
the SHA-256 and import/export metadata for the seven files below.

All addresses are **preferred virtual addresses from the on-disk PE**, not RVAs,
file offsets, or observed runtime addresses. IAT slots, export entries and
literals establish static presence, not reachability or execution. Thunk addresses
alone do not establish a caller. No vendor image bytes or disassembly dumps are
included here.

## Candidate modules

Paths in this document are relative to the private `extracted/app/` directory;
those binaries are not part of this repository.

| File | Export entries | Transport import slots / other static evidence |
| --- | --- | --- |
| `Load/grdAPI32.dll` | `GrdStartup` `0x100ae15c`; `GrdFind` `0x100aea5c`; `GrdLogin` `0x100b1c5c`; `GrdLogout` `0x100b1efc`; `GrdGetInfo` `0x100b2e1c` | `DeviceIoControl` IAT `0x102dc09c`; `CreateFileA` `0x102dc0a0`; `CreateFileW` `0x102dc100`. Device-name literal `\\.\GRDKEY` at `0x1000494c`, `0x1000495c`. |
| `EraGis/bin/GrdAPI32.dll` | `GrdStartup` `0x100aeed0`; `GrdFind` `0x100af7d0`; `GrdLogin` `0x100b2a10`; `GrdLogout` `0x100b2cb0`; `GrdGetInfo` `0x100b3bd0` | Different binary from the preceding row. `DeviceIoControl` IAT `0x102f90f8`; `CreateFileA` `0x102f907c`; `CreateFileW` `0x102f90ac`. `\\.\GRDKEY` at `0x10004a28`, `0x10004a38`. |
| `Load/grdDrv.dll` | `GrdDrvIsInstalled` `0x1000cb03`; `GrdDrvInstallW` `0x1000dfc9`; `GrdDrvUnInstallW` `0x1000e086`; `GrdDrvGetDriverInfo` `0x1000e3a1` | Driver management/install exports and SetupAPI imports. `DeviceIoControl` IAT `0x10001414`; `CreateFileA` `0x100013dc`; `CreateFileW` `0x10001418`. `\\.\GRDUSB` at `0x10002538`, `0x10007910`; `\\.\GRDKEY` at `0x10001f10`, `0x10002550`, `0x10007928`. |
| `Load/cryGrd.dll` | `exCrypt` `0x00724fc0`; `FreeString` `0x007250d4` | `DeviceIoControl` IAT `0x00731c88`; `CreateFileA` `0x00731c98`; `\\.\GRDKEY` at `0x00457844`. No static `GrdAPI32.dll` import found. The inspected metadata does not establish which `exCrypt` branch reaches transport. |

The following indirect-jump thunks were also found in executable sections:

| File | DeviceIoControl thunk | CreateFileA thunk | CreateFileW thunk |
| --- | --- | --- | --- |
| `Load/grdAPI32.dll` | `0x102d6d98` | `0x102d6d9e` | `0x102d6e2e` |
| `EraGis/bin/GrdAPI32.dll` | `0x102f45ac` | `0x102f44f2` | `0x102f453a` |
| `Load/cryGrd.dll` | `0x00406c18` | — | — |

`grdDrv.dll` is not interchangeable with the runtime SDK: its exports explicitly
include installation, removal and driver/port inspection. A coherent local
wrapper beginning at `0x1000b4c8` contains `CreateFileW` at `0x1000b4e4`, followed
on the successful-open branch by `DeviceIoControl` at `0x1000b50e` and
`CloseHandle` at `0x1000b521`. The device name and IOCTL come from wrapper
arguments. This is a static code relationship, not an observed call or proof of
a licensing operation; no current-worker caller has been established.

## Static SDK consumers

| File | Imported symbol | Preferred IAT address |
| --- | --- | --- |
| `EraGis/bin/lpCorex86.dll` | `GrdAPI32.dll!_GrdCryptEx@40` | `0x10041014` |
| `EraGis/bin/lpCorex86_cnv.dll` | `GrdAPI32.dll!_GrdCryptEx@40` | `0x1003e014` |
| `Load/QT/MapsLoader.exe` | `GrdAPI32.dll!_GrdStartup@4` | `0x006cbb08` |

`MapsLoader.exe` additionally imports `GRDVKC32.DLL!GrdPrepare` at `0x006cfd60`.
These are import-table dependencies, not recorded SDK calls. In particular, they
do not establish that the currently investigated `p_perv.exe` worker loads or
calls either SDK copy.

## File identity

| Private file | SHA-256 |
| --- | --- |
| `Load/grdAPI32.dll` | `179f700867e2c5f513f553cc0aa76edfa70bf5f68d8e4c6a24f1f783524a91c7` |
| `EraGis/bin/GrdAPI32.dll` | `8bd943b1351616dff07422399a93a41ad148e98d39e84119851f0ceb0484f9e6` |
| `Load/grdDrv.dll` | `40cd1ee70b581b70b289140b8f4d7fc0df62d2c4195ac2bd5fd1368ca334c7f5` |
| `Load/cryGrd.dll` | `0991c888b9dd2fda1f830dec30a1028d0425c8e8be3fb75ce5e5150ade2a73ec` |
| `EraGis/bin/lpCorex86.dll` | `ddf12ffe8aa3632ce968a3a3943603a23272baec773799af0676b8e13f3e3009` |
| `EraGis/bin/lpCorex86_cnv.dll` | `ee9abadfa4eb84a654161ff5c07865270af5ab07227351f1a1f473d8c0d1d0af` |
| `Load/QT/MapsLoader.exe` | `e56ec1d038bc7e4f524dcb410dcc3cdf839f5adf2f795ceeb15cf8602db2f118` |

## Boundary with the current worker investigation

The copies of `grdvkc32.dll` under `0_START/`, `ERA_RB/` and `EraGis/bin/` share
SHA-256 `0eb1003dc43a6484f8bba7076a442fad8dad506bb80f6e9047d77c82f4c7ce30`.
`ERA_RB/p_perv.exe`, SHA-256
`e4ece1726a1615392ad3e90f2c0c03e49f9b70d50ef7ce1cafa99f9a8385739e`, statically
imports `GRDVKC32.DLL!GrdPrepare` at `0x0d244fb8`, but no `GrdLogin`, `GrdFind` or
`GrdAPI32.dll` dependency was found in its inspected import tables. Dynamic
resolution or unpacked code can add dependencies that this inventory cannot see.

The existing `grdvkc32.dll` CreateFile/DeviceIoControl imports do not prove that
the current worker reaches transport. Previously identified `GrdPrepare`
selectors for module/thread startup are not relabeled as key-operation codes.
The connection from the current worker to these candidate modules, the actual
device path, IOCTL, payload and licensing decision remain unestablished.
