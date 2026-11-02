# Compliance and permitted use

This document explains what this package contains, the third-party material it
includes, and the rules for using or redistributing it. It is a technical
compliance statement, **not legal advice**.

---

## 1. Purpose

This is a security-research and homebrew tool for a **retail PlayStation 4
that you own**, running firmware **14.00**. It demonstrates a browser-only
exploit chain and installs HEN (Homebrew Enabler) so that homebrew software
and user-controlled plugins can run.

It is provided for:

- personal study of browser and kernel exploitation on hardware you own;
- homebrew development and testing;
- interoperability research.

It is **not** provided for piracy, cheating, account theft, or attacking
systems you do not own.

---

## 2. What this package contains

The package includes the files needed to run the chain:

| included item | source / credit |
| --- | --- |
| `artifacts/hen.bin` — HEN 2.2.0 image for 14.00, with the Debug Settings patch and `td_name` gate NOP applied | [Scene-Collective/ps4-hen](https://github.com/Scene-Collective/ps4-hen), built by its contributors. See [`CREDITS.md`](CREDITS.md). |
| `artifacts/pkb.bin` — the reviewed 632-byte 14.00 kernel patch blob | derived from Hx1400 research material; credited in [`CREDITS.md`](CREDITS.md). |
| `probes/stage_patch_v1.js` — the patch probe with that blob embedded | generated locally by `tools/prepare_operator_data.py`. |
| driver, lab, probes, tools, tests, documentation | written for this project. |

It does **not** contain:

| excluded item | why |
| --- | --- |
| Sony firmware, `.sprx`/`.self` modules, game content, keys | © Sony Interactive Entertainment or the respective rightsholders. |
| decompiled or leaked packages | used only as an offline oracle during private research; not included. |
| HEN plugin PRXs as separate files | embedded inside the included HEN image. |

If you fork or mirror this project, keep the credits and do not add Sony
firmware, game content, or extracted modules.

---

## 3. Your obligations

By using this package you agree to:

1. **Own the console.** Use it only on hardware you own or are explicitly
   authorised to modify.
2. **Use the bundled material as provided.** The HEN image and kernel blob are
   third-party work included here with credit. Verify their hashes before use,
   and do not present them as your own work.
3. **Do not pirate.** Do not use the tool to install, run, or distribute
   games, DLC, themes, or other content you do not own or have the right to
   use.
4. **Do not circumvent DRM for infringement.** Jailbreaking for personal
   interoperability may be permitted in some jurisdictions; using it to copy
   or distribute protected works is not.
5. **Do not cheat online.** Do not use the tool to gain an unfair advantage in
   multiplayer games or to tamper with other players' experiences.
6. **Respect the platform terms.** Modifying a console may violate the
   PlayStation Network terms of service. Account and console bans are a real
   possibility.
7. **Keep the credits.** If you redistribute the package or a modified
   version, keep [`CREDITS.md`](CREDITS.md), this file, and the pinned hashes.
8. **Keep the network private.** Run the lab server only on a trusted LAN.
   It has no authentication and can execute kernel-level commands in the
   console browser.
9. **Comply with local law.** Rules on jailbreaking, circumvention, and
   modification differ by country. If you are unsure, do not proceed.

---

## 4. Attribution

- **Work in this package** (driver, lab, probes, tools, tests and
  documentation written for this project) is original to this project.
- **HEN** (`artifacts/hen.bin`) is [Scene-Collective/ps4-hen](https://github.com/Scene-Collective/ps4-hen)
  2.2.0 work, created by its contributors. It is included with credit.
- **The 632-byte kernel patch blob** derives from Hx1400 research material.
  It is included with credit to that work.
- **Plugin interfaces and behaviour** follow
  [Scene-Collective/ps4-hen-plugins](https://github.com/Scene-Collective/ps4-hen-plugins);
  the injection technique follows
  [OpenOrbis/mira-project](https://github.com/OpenOrbis/mira-project).
- See [`CREDITS.md`](CREDITS.md) for the full acknowledgement list and
  provenance.
- If you redistribute a modified version: keep the credits and this
  compliance statement, mark your changes, and do not add Sony firmware, game
  content, or extracted modules.
- “PlayStation”, “PS4” and “Sony” are trademarks of Sony Interactive
  Entertainment. This project is not affiliated with or endorsed by Sony.

---

## 5. Security and responsible disclosure

- Do not expose the lab server to the internet.
- Do not use the exploit against consoles you do not own.
- If you discover a vulnerability in this project, report it privately to the
  maintainers before publishing details.
- If you discover a vulnerability in a vendor product, follow the vendor's
  responsible-disclosure process and applicable law. Do not weaponise it.

---

## 6. No warranty

The software is provided **“as is”**, without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose, and non-infringement. The authors are not
liable for any claim, damage, data loss, account ban, or other liability
arising from the use of the software.

---

## 7. Compliance checklist for redistributors

Before publishing a copy or fork:

- [ ] Keep `CREDITS.md`, `RISKS.md`, `SHA256SUMS` and this file.
- [ ] Keep `artifacts/hen.bin`, `artifacts/pkb.bin` and
      `probes/stage_patch_v1.js` unchanged, or regenerate them from the pinned
      inputs with `tools/prepare_operator_data.py`.
- [ ] Do not add Sony firmware, `.sprx`/`.self` files, game content, or
      extracted modules.
- [ ] Keep the pinned hashes and the preparation checks intact.
- [ ] Keep the credits for the HEN image and the kernel patch blob.
- [ ] Do not imply that the project is affiliated with or endorsed by Sony.
