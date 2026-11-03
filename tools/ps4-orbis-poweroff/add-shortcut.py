#!/usr/bin/env python3
"""Add a non-Steam shortcut to Steam's shortcuts.vdf (binary VDF).

Steam has no "add shortcut" CLI, so this writes the file directly. Run it as
the Steam user with Steam stopped; Steam only reads shortcuts.vdf at startup,
and rewrites it from memory when the shortcut list changes.

Usage:
    add-shortcut.py <steam-userdata-dir> <name> <exec-path> [start-dir] [icon]

Example:
    add-shortcut.py ~/.local/share/Steam/userdata/119826540 \\
        "Power off (Orbis)" /home/ps4/.local/bin/orbis-poweroff.sh
"""
import os
import shutil
import struct
import sys
import zlib


def cstr(text: str) -> bytes:
    return text.encode("utf-8") + b"\x00"


def i32(value: int) -> bytes:
    return struct.pack("<i", value)


def i64(value: int) -> bytes:
    return struct.pack("<Q", value)


def entry_fields(entry: dict) -> bytes:
    out = b""
    for key, (kind, value) in entry.items():
        out += bytes([kind]) + cstr(key)
        if kind == 0x01:
            out += cstr(value)
        elif kind == 0x02:
            out += i32(value)
        elif kind == 0x07:
            out += i64(value)
        else:
            raise ValueError("unsupported type %r for %s" % (kind, key))
    out += b"\x00" + cstr("tags") + b"\x08\x08"
    return out


def build(shortcuts: list) -> bytes:
    data = b"\x00" + cstr("shortcuts")
    for index, fields in enumerate(shortcuts):
        data += b"\x00" + cstr(str(index)) + entry_fields(fields)
    data += b"\x08\x08"
    return data


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    userdata = os.path.expanduser(sys.argv[1])
    name = sys.argv[2]
    exe = sys.argv[3]
    start_dir = sys.argv[4] if len(sys.argv) > 4 else os.path.dirname(exe)
    icon = sys.argv[5] if len(sys.argv) > 5 else ""

    path = os.path.join(userdata, "config", "shortcuts.vdf")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        backup = path + ".bak"
        shutil.copy2(path, backup)
        print("backup:", backup)

    appid = (zlib.crc32(('"%s"' % exe).encode()) | 0x80000000) & 0xFFFFFFFF
    if appid >= 0x80000000:
        appid -= 0x100000000

    fields = {
        "appid": (0x02, appid),
        "AppName": (0x01, name),
        "Exe": (0x01, '"%s"' % exe),
        "StartDir": (0x01, '"%s"' % start_dir),
        "icon": (0x01, icon),
        "ShortcutPath": (0x01, ""),
        "LaunchOptions": (0x01, ""),
        "IsHidden": (0x02, 0),
        "AllowDesktopConfig": (0x02, 1),
        "AllowOverlay": (0x02, 1),
        "OpenVR": (0x02, 0),
        "Devkit": (0x02, 0),
        "DevkitGameID": (0x01, ""),
        "DevkitOverrideAppID": (0x02, 0),
        "LastPlayTime": (0x07, 0),
    }

    blob = build([fields])
    with open(path, "wb") as fh:
        fh.write(blob)
    print("wrote %s (%d bytes, appid %d)" % (path, len(blob), appid))
    return 0


if __name__ == "__main__":
    sys.exit(main())
