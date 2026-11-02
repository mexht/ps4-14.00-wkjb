#!/usr/bin/env python3
"""Verify or rebuild the payload data shipped with this release.

The package ships:

  * artifacts/hen.bin        - the validated gate-NOP HEN 2.2.0 image;
  * artifacts/pkb.bin        - the reviewed 632-byte kernel patch blob;
  * probes/stage_patch_v1.js - the patch probe with that blob rendered in.

Run this script to verify all three, or to rebuild them from other copies:

  python3 tools/prepare_operator_data.py
  python3 tools/prepare_operator_data.py \
      --hen /path/to/hen.bin --blob /path/to/pkb.bin

Accepted HEN images (sha256 pinned):

  29ec095f...  pristine 14.00 HEN 2.2.0 payload
  1c1cec9f...  the same image with the proven 3-patch Debug Settings change
  820f9bbe...  the final image with the td_name gate NOPed (shipped)

Pristine and 3-patch inputs are patched automatically. The script verifies
every intermediate hash, writes artifacts/hen.bin, and renders
probes/stage_patch_v1.js from probes/stage_patch_v1.js.in.

Credits: HEN 2.2.0 is Scene-Collective/ps4-hen work; the 14.00 kernel patch
blob derives from Hx1400 research material. See CREDITS.md.
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import patch_hen_debug_menu_3patch as debugmenu  # noqa: E402
import patch_hen_tdgate as tdgate  # noqa: E402

PRISTINE_SHA256 = "29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06"
DEBUGMENU3_SHA256 = "1c1cec9f399f1c3261bc364e53b7e60f4bcf4b1dd0a76a7f6687b91d868222bd"
TDGATE_SHA256 = "820f9bbef2a7ffefdf3ba7f660cb501fcbc0c2849c70ab9ccfdf44da28cebae9"
PKB_SHA256 = "165d2ad966b3829d1fbcb53d5e7ecbc20563de4a6a49ee70d8126d0256a49c02"
PKB_LEN = 632

TEMPLATE = ROOT / "probes" / "stage_patch_v1.js.in"
RENDERED = ROOT / "probes" / "stage_patch_v1.js"
HEN_OUT = ROOT / "artifacts" / "hen.bin"
PLACEHOLDER = "@PKB_BLOB_HEX@"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fail(message, code=2):
    print("error: " + message, file=sys.stderr)
    raise SystemExit(code)


def prepare_image(raw):
    """Return the validated gate-NOP image, applying patches as needed."""
    data = bytearray(raw)
    digest = sha256(data)

    if digest == PRISTINE_SHA256:
        print("  applying the 3-patch Debug Settings change")
        try:
            debugmenu.patch(data)
        except SystemExit as exc:
            fail("debug-menu patch failed: %s" % exc)
        digest = sha256(data)
        if digest != DEBUGMENU3_SHA256:
            fail("debug-menu result is %s, expected %s"
                 % (digest, DEBUGMENU3_SHA256))
        print("  -> %s" % digest)

    if digest == DEBUGMENU3_SHA256:
        print("  applying the td_name gate NOP")
        try:
            tdgate.apply_gate(data)
        except ValueError as exc:
            fail("gate patch failed: %s" % exc)
        digest = sha256(data)
        if digest != TDGATE_SHA256:
            fail("gate result is %s, expected %s"
                 % (digest, TDGATE_SHA256))
        print("  -> %s" % digest)

    if digest != TDGATE_SHA256:
        fail("unsupported HEN image (sha256 %s).\n"
             "Accepted inputs:\n  %s\n  %s\n  %s\n"
             "This project only supports the 14.00 HEN 2.2.0 image pinned "
             "above; do not force another build."
             % (digest, PRISTINE_SHA256, DEBUGMENU3_SHA256, TDGATE_SHA256))

    return bytes(data), digest


def atomic_write(path, data):
    if isinstance(data, str):
        data = data.encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def main():
    parser = argparse.ArgumentParser(
        description="verify or rebuild the shipped HEN image and patch probe")
    parser.add_argument("--hen", default="artifacts/hen.bin",
                        help="HEN 2.2.0 14.00 image (default: %(default)s)")
    parser.add_argument("--blob", default="artifacts/pkb.bin",
                        help="632-byte kernel patch blob (default: %(default)s)")
    parser.add_argument("--check", action="store_true",
                        help="validate everything, write nothing")
    args = parser.parse_args()

    hen_path = Path(args.hen)
    blob_path = Path(args.blob)
    if not hen_path.is_absolute():
        hen_path = ROOT / hen_path
    if not blob_path.is_absolute():
        blob_path = ROOT / blob_path

    if not hen_path.is_file():
        fail("HEN image not found: %s\n"
             "Restore it from the package, or pass --hen PATH." % hen_path)
    if not blob_path.is_file():
        fail("kernel blob not found: %s\n"
             "Restore it from the package, or pass --blob PATH." % blob_path)
    if not TEMPLATE.is_file():
        fail("missing template: %s" % TEMPLATE)

    print("hen image   %s" % hen_path)
    image, image_digest = prepare_image(hen_path.read_bytes())
    print("  sha256    %s (%d bytes)" % (image_digest, len(image)))

    blob = blob_path.read_bytes()
    blob_digest = sha256(blob)
    print("kernel blob %s" % blob_path)
    print("  sha256    %s (%d bytes)" % (blob_digest, len(blob)))
    if len(blob) != PKB_LEN:
        fail("blob is %d bytes, expected %d" % (len(blob), PKB_LEN))
    if blob_digest != PKB_SHA256:
        fail("blob sha256 is %s, expected %s\n"
             "Use the reviewed 632-byte blob that matches this hash."
             % (blob_digest, PKB_SHA256))

    template = TEMPLATE.read_text()
    if template.count(PLACEHOLDER) != 1:
        fail("template %s does not contain exactly one %s"
             % (TEMPLATE, PLACEHOLDER))
    rendered = template.replace(PLACEHOLDER, blob.hex())

    if args.check:
        print("\ncheck only: inputs are valid; nothing written")
        return 0

    atomic_write(HEN_OUT, image)
    print("\nwrote       %s" % HEN_OUT)
    atomic_write(RENDERED, rendered)
    print("wrote       %s" % RENDERED)

    print("\nready. Start the lab server, open the page on the console, then "
          "run:\n"
          "  python3 lab/server.py serve --host 0.0.0.0 --port 8765\n"
          "  python3 chain-driver/chain.py --launch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
