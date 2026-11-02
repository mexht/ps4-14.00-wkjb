# Payload files

| file | sha256 | what it is |
| --- | --- | --- |
| `goldhen.bin` | `39452f5e1c305ac9efcb4745eef7958b4db8c6d85299529f08700970b009ea4d` | official GoldHEN v2.4b18.13 payload for 14.00, unmodified (297 496 bytes; default payload) |
| `hen.bin` | `820f9bbef2a7ffefdf3ba7f660cb501fcbc0c2849c70ab9ccfdf44da28cebae9` | ps4-hen 2.2.0 image for 14.00, with the Debug Settings patch and `td_name` gate NOP applied (562 240 bytes; `--payload hen`) |
| `pkb.bin` | `165d2ad966b3829d1fbcb53d5e7ecbc20563de4a6a49ee70d8126d0256a49c02` | reviewed 632-byte kernel patch blob |

`goldhen.bin` is served at `/goldhen.bin` for `stage_goldhen_v2`, and
`hen.bin` at `/hen.bin` for `stage_hen_map_v1`. `pkb.bin` is already embedded
in `probes/stage_patch_v1.js`; it is kept here so the probe can be regenerated.

Verify them with `sha256sum -c SHA256SUMS` (all shipped files, including both
payloads) or `python3 tools/prepare_operator_data.py --check` (ps4-hen image,
kernel blob and the rendered patch probe; `goldhen.bin` is not touched).

Credits: GoldHEN is the official [GoldHEN/GoldHEN](https://github.com/GoldHEN/GoldHEN)
project (SiSTRo and contributors). HEN is Scene-Collective/ps4-hen 2.2.0 work;
the kernel blob derives from Hx1400 research material. See `../CREDITS.md`.
