# Credits and provenance

This package is a public-release copy of a private research project: a
browser/WebKit-only jailbreak chain for a retail PS4 reporting firmware
**14.00**, plus the harness that drives it. It stands on public PS4 research
and the PS4 HEN ecosystem. If something used here is missing from this list,
please open an issue.

---

## 1. Work in this package

Written for this project and measured on the author's own console:

- the 14.00 browser chain: history address-directed read/write, the groom /
  spray / pair / plan / install prefix, the kqueue + zone-256 UAF race
  (stage C), the D-plant variants, the fake `filterops` rotation (F/G), the
  ROP call primitive, the ucred and sandbox escape, the HEN image mapping, the
  GoldHEN ring-0 installer launch, and `stage_safedown_v1` (restoring the
  global `sysfilt_ops` slot);
- `probes/` and their manifests, `lab/` (queue, page, tests),
  `chain-driver/`, the preparation and image-patch tools, and the
  documentation in this package.

---

## 2. Upstream code, binaries and interfaces

| project | what this package uses |
| --- | --- |
| [GoldHEN/GoldHEN](https://github.com/GoldHEN/GoldHEN) (v2.4b18.13, 14.00 build) | The default payload, included unmodified as `artifacts/goldhen.bin` with credit. Its installer convention (`jmp rel32` head, ring-0 entry at `0x1653`) is driven by `probes/stage_goldhen_v2.js`. |
| [Scene-Collective/ps4-hen](https://github.com/Scene-Collective/ps4-hen) (v2.2.0 BETA, 14.00 build) | The alternative payload (`--payload hen`), included as `artifacts/hen.bin` with credit. Its embedded `hen.ini` template and PRX slices are read from that binary at runtime. |
| [Scene-Collective/ps4-hen-plugins](https://github.com/Scene-Collective/ps4-hen-plugins) | Plugin interfaces and behaviour: `plugin_bootloader` / `plugin_loader` / `plugin_mono` / `plugin_server` / `plugin_shellcore`, `plugins.ini` `[all]`, the `/data/hen/shellui_data` menu marker, and the `_init_env` injection path. |
| [OpenOrbis/mira-project](https://github.com/OpenOrbis/mira-project) | The `sys_dynlib_load_prx` plugin-injection technique (`Substitute.cpp`) that the HEN hook follows. No Mira source is redistributed. |
| [Scene-Collective/ps4-payload-sdk](https://github.com/Scene-Collective/ps4-payload-sdk) | Payload build conventions (not redistributed). |
| [Al-Azif/ps4-exploit-kpatches](https://github.com/Al-Azif/ps4-exploit-kpatches) | Public 14.00 kpatch/offset reference, used as a source hypothesis only. |
| [adri22235/ps4-suid-scanner](https://github.com/adri22235/ps4-suid-scanner) | Public 14.00 stage reference; not imported. |
| Sony PS4 WebKit source archive | Object-layout hypotheses for the 13.00/14.00 browser; extracted members were kept local and are not redistributed. |
| [Node.js](https://nodejs.org/) | Optional page test only. |
| Python standard library | The entire harness; no third-party Python packages. |

---

## 3. Findings and prior research

- **qwertyoruiopz** — the 2016 WebKit exploitation primitives (addrof /
  fakeobj, typed-array corruption) that the browser stages build on.
- **Specter** — PS4 WebKit exploit research and writeups.
- **ChendoChap** — PS4 kernel exploitation, offset work, and HEN.
- **flat_z** — HEN design and the kernel patching model.
- **CTurt** — PS4 security research.
- **idc, Joonie, Vortex, SiSTRo, SocraticBliss, Biorn1950, zecoxao,
  Al-Azif, illusiony** — HEN and plugin contributors credited by the
  ps4-hen project.
- The **Hx1400** research material — used as an **untrusted oracle** during
  private research for the 14.00 kernel `P[]` table, the 24-site guard table,
  the 632-byte ring-0 blob, and the `safeDown()` semantics. The reviewed
  632-byte blob is included here as `artifacts/pkb.bin` with credit to that
  work.

---

## 4. Validation

The one-shot `--launch --payload hen` flow in this package was validated on
two consecutive cold boots of a retail 14.00 console (2026-11-02): the first
boot repaired four plugin PRXs after the hook went live; the second found them
already loadable and reported `unchanged`. Both ended with `CHAIN COMPLETE`, a
restarted `SceShellUI`, and a working HEN Settings menu. The default GoldHEN
path uses the same kernel stages and the official raw payload; exercise it on
your own console before relying on it.
