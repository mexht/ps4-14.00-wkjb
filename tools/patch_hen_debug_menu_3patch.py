#!/usr/bin/env python3
"""Enable the Debug Settings menu in the bundled HEN payload.

The 14.00 HEN 2.2.0 image ships `shellui_patch()` but `apply_patches()`
guards the call with `if (0)`, so the Debug Settings menu is never enabled.
This tool patches the payload image in place:

  0xf21b  call remoteplay_patch   ->  call shellui_patch
  0xef43  call proc_write_mem     ->  xor eax,eax; nop;nop;nop
  0xf037  call proc_write_mem     ->  xor eax,eax; nop;nop;nop

The two `proc_write_mem` calls are `shellui_patch()`'s CreateUserForIDU and
Remote Play writes. They are skipped so that a missing `app.exe.sprx` cannot
make the function bail out before the Debug Settings writes, and so the only
kernel-side change is the two `libkernel_sys.sprx` patches:

  sceSblRcMgrIsAllowDebugMenuForSettings_patch = 0x0001D100
  sceSblRcMgrIsStoreMode_patch                 = 0x0001D460

The image is the payload itself (`_start` at 0x4aab), so file offsets are
payload offsets; no rebuild or runtime address is involved. The installer
embeds a different kpayload build, so rebuilding would move every config
offset the browser chain depends on.

Credits: HEN 2.2.0 by ChendoChap / the PS4 HEN contributors; Debug Settings
and Remote Play offsets from the 14.00 offset table in the same payload
(`source/offsets/1400.c`), with the Remote Play patch credited there to Aida.

Usage:
  python3 tools/patch_hen_debug_menu_3patch.py                 # patch artifacts/hen.bin
  python3 tools/patch_hen_debug_menu_3patch.py --check         # report only
  python3 tools/patch_hen_debug_menu_3patch.py -i copy.bin     # another image
"""

import argparse
import hashlib
import os
import struct
import sys

PRISTINE_SHA256 = "29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06"
PATCHED_SHA256 = "1c1cec9f399f1c3261bc364e53b7e60f4bcf4b1dd0a76a7f6687b91d868222bd"

APPLY_PATCHES_CALL = 0xF21B          # e8 e5 fe ff ff -> call 0xf105
SHELLUI_PATCH = 0xEE6B
CREATE_USER_CALL = 0xEF43            # e8 37 f9 ff ff -> call 0xe87f
REMOTE_PLAY_CALL = 0xF037            # e8 43 f8 ff ff -> call 0xe87f

CALL_REL32 = b"\xe8"
SKIP_WRITE = b"\x31\xc0\x90\x90\x90"  # xor eax,eax; nop;nop;nop


def patch(image):
    """Apply the three patches to a bytearray and return the list of changes."""
    changes = []
    for offset, want, new, label in (
        (APPLY_PATCHES_CALL, bytes.fromhex("e8e5feffff"),
         CALL_REL32 + struct.pack("<i", SHELLUI_PATCH - (APPLY_PATCHES_CALL + 5)),
         "apply_patches -> shellui_patch"),
        (CREATE_USER_CALL, bytes.fromhex("e837f9ffff"), SKIP_WRITE,
         "skip CreateUserForIDU write"),
        (REMOTE_PLAY_CALL, bytes.fromhex("e843f8ffff"), SKIP_WRITE,
         "skip Remote Play write"),
    ):
        have = bytes(image[offset:offset + len(want)])
        if have == new:
            changes.append((offset, label, "already"))
            continue
        if have != want:
            raise SystemExit(
                "unexpected bytes at 0x%x: %s (want %s)"
                % (offset, have.hex(), want.hex()))
        image[offset:offset + len(new)] = new
        changes.append((offset, label, "patched"))
    return changes


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-i", "--image", default="artifacts/hen.bin",
                        help="payload image (default: artifacts/hen.bin)")
    parser.add_argument("--check", action="store_true",
                        help="do not write; report the current state")
    args = parser.parse_args()

    data = bytearray(open(args.image, "rb").read())
    original = bytes(data)
    before = hashlib.sha256(data).hexdigest()
    print("image  %s (%d bytes)" % (args.image, len(data)))
    print("before %s" % before)

    if before not in (PRISTINE_SHA256, PATCHED_SHA256):
        print("warning: this is not the documented 14.00 image", file=sys.stderr)

    changes = patch(data)
    for offset, label, state in changes:
        print("  0x%06x  %-32s %s" % (offset, label, state))

    after = hashlib.sha256(data).hexdigest()
    print("after  %s" % after)

    if args.check:
        print("check only; nothing written")
        return

    if after == before:
        print("already patched; nothing to do")
        return

    backup = args.image + ".orig"
    if os.path.exists(backup):
        print("backup %s already exists" % backup)
    else:
        with open(backup, "wb") as handle:
            handle.write(original)
        print("backup %s" % backup)

    with open(args.image, "wb") as handle:
        handle.write(data)
    print("wrote  %s" % args.image)
    if after != PATCHED_SHA256:
        print("note: result differs from the documented patched hash",
              file=sys.stderr)


if __name__ == "__main__":
    main()
