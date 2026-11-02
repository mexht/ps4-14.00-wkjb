# Tools

## `prepare_operator_data.py` — verify or rebuild

Checks the bundled payload files and regenerates the patch probe. With the
shipped defaults it verifies `artifacts/hen.bin`, `artifacts/pkb.bin` and
renders `probes/stage_patch_v1.js` from `probes/stage_patch_v1.js.in`:

```bash
python3 tools/prepare_operator_data.py --check
```

To rebuild from your own copies:

```bash
python3 tools/prepare_operator_data.py \
    --hen /path/to/hen.bin --blob /path/to/pkb.bin
```

Accepted HEN inputs: pristine `29ec095f…`, 3-patch `1c1cec9f…`, or the final
`820f9bbe…`. Pristine and 3-patch images are patched automatically. Every
intermediate hash is verified; the script refuses images and blobs outside the
pinned set.

## `patch_hen_debug_menu_3patch.py` — manual alternative

Applies the proven three Debug Settings patches to a pristine 14.00 HEN 2.2.0
image:

- `0xf21b` `apply_patches` call → `shellui_patch`;
- `0xef43` skip the `CreateUserForIDU` write;
- `0xf037` skip the Remote Play write.

```bash
python3 tools/patch_hen_debug_menu_3patch.py -i artifacts/hen.bin
```

The result must hash to `1c1cec9f…222bd`. A `.orig` backup is created.

## `patch_hen_tdgate.py` — manual alternative

NOPs the six-byte `td_name` gate in the 594 hook so the Sysmodule branch fires
on the path match alone. Input must be the 3-patch image (`1c1cec9f…`); output
is the final image (`820f9bbe…`).

```bash
python3 tools/patch_hen_tdgate.py artifacts/hen.bin.debugmenu3 artifacts/hen.bin
```

These two tools are provided for inspection and manual recovery.
`prepare_operator_data.py` is the supported path and verifies the final hash.
