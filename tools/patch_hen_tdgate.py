#!/usr/bin/env python3
"""Diagnostic build: drop the `td_name` gate from HEN's 594 hook.

Why
---
HEN's `sys_dynlib_load_prx` hook has two injection branches:

  * `/app0/sce_module/libc.prx` -> load plugin_bootloader.  This branch
    has no process-name test, and it demonstrably runs on 14.00 (the
    bootloader created `/data/hen/plugins.ini` with a valid `[all]`
    section on the console).
  * `/common/lib/libSceSysmodule.sprx` + `td_name` contains
    `SceShellUIMain` (or `ScePartyDaemonMain`) -> load plugin_mono /
    plugin_server and redirect libc's `_init_env`.

Only the second branch can put the HEN Settings menu into SceShellUI.
`td_name` is read at the hardcoded `struct thread` offset 0x284, which
is not part of HEN's per-firmware offsets table, so it is the one
firmware-dependent value in the condition that 14.00 has never been
checked against.

What this patch does
--------------------
At file offset 0xd658 the compiled condition ends with

    d655: 49 09 ef     or   %rbp,%r15      ; isPartyDaemon | isShellUI
    d658: 0f 84 f9 00 00 00  je 0xd757      ; skip branch when both 0

This replaces the six-byte `je` with six NOPs.  The `/common/lib/
libSceSysmodule.sprx` path test at 0xd646-0xd64f is left intact, so the
branch still only runs for the Sysmodule load.  When `isPartyDaemon`
does not match (the expected 14.00 case if 0x284 is wrong), the existing
`cmove` at 0xd674 selects `/data/hen/plugin_mono.prx`, which is exactly
the ShellUI target.

This is a diagnostic: if the menu appears, the 0x284 offset is the bug
and the proper fix is to locate the real 14.00 `td_name` offset.  If it
does not, the failure is in the PRX load, the `_init_env` dlsym/patch,
or plugin_mono itself.

Input must be the 3-patch Debug Settings image (sha256 pinned below).
"""
import hashlib
import pathlib
import sys

BASE_SHA256 = "1c1cec9f399f1c3261bc364e53b7e60f4bcf4b1dd0a76a7f6687b91d868222bd"
GATE_OFFSET = 0xD658
GATE_BYTES = bytes.fromhex("0f84f9000000")  # je 0xd757
NOP6 = b"\x90" * 6


def apply_gate(data: bytearray) -> None:
    """NOP the six-byte `je` in `data`, raising on unexpected bytes."""
    have = bytes(data[GATE_OFFSET:GATE_OFFSET + 6])
    if have != GATE_BYTES:
        raise ValueError("unexpected bytes at 0x%x: %s (want %s)"
                         % (GATE_OFFSET, have.hex(), GATE_BYTES.hex()))
    data[GATE_OFFSET:GATE_OFFSET + 6] = NOP6


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    src = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else (
        root / "artifacts" / "hen.bin.debugmenu3")
    dst = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else (
        root / "artifacts" / "hen.bin.tdgate")

    data = bytearray(src.read_bytes())
    got = hashlib.sha256(data).hexdigest()
    if got != BASE_SHA256:
        print("input is not the pinned 3-patch image:\n  got  %s\n  want %s"
              % (got, BASE_SHA256), file=sys.stderr)
        return 1
    try:
        apply_gate(data)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    dst.write_bytes(data)
    print("wrote %s" % dst)
    print("sha256 %s" % hashlib.sha256(data).hexdigest())
    print("patch 0x%x: %s -> %s (td_name gate removed)"
          % (GATE_OFFSET, GATE_BYTES.hex(), NOP6.hex()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
