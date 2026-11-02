# Payload files

| file | sha256 | what it is |
| --- | --- | --- |
| `hen.bin` | `820f9bbef2a7ffefdf3ba7f660cb501fcbc0c2849c70ab9ccfdf44da28cebae9` | HEN 2.2.0 image for 14.00, with the Debug Settings patch and `td_name` gate NOP applied (562 240 bytes) |
| `pkb.bin` | `165d2ad966b3829d1fbcb53d5e7ecbc20563de4a6a49ee70d8126d0256a49c02` | reviewed 632-byte kernel patch blob |

`hen.bin` is served at `/hen.bin` for `stage_hen_map_v1`. `pkb.bin` is already
embedded in `probes/stage_patch_v1.js`; it is kept here so the probe can be
regenerated.

Verify them with `sha256sum -c SHA256SUMS` or
`python3 tools/prepare_operator_data.py --check`.

Credits: HEN is Scene-Collective/ps4-hen 2.2.0 work; the blob derives from
Hx1400 research material. See `../CREDITS.md`.
