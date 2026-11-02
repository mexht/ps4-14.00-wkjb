# Risk assessment

**Read this before running the chain.** The tool writes to kernel memory and
restarts a system process. That is inherently riskier than installing a normal
homebrew app. There is **no warranty** and no guaranteed recovery path.

If the console contains saves, accounts, or data you cannot lose, back them up
first — or do not run this.

---

## 1. Summary

| risk | likelihood | impact | mitigation |
| --- | --- | --- | --- |
| console powers off during a run | **common** (a failed draw or race) | low: next boot is stock | power-cycle and retry; no panic |
| console crashes after install / UI restarts | possible | medium: lost unsaved work | save work before starting; let it restart |
| **brick / unbootable console** | **rare, but non-zero** | **high** | stable power; do not interrupt a run; keep a USB recovery plan |
| corrupted or lost save data | low–medium | high if not backed up | back up saves first (USB / PS Plus) |
| PSN / account ban or blocked access | possible | high if the account matters | do not sign in on a modified console if this matters |
| warranty void | likely | financial | accept or do not proceed |
| legal exposure | jurisdiction-dependent | high | own console, personal use, no piracy; read `COMPLIANCE.md` |
| malicious plugin | high **if** you install untrusted PRXs | high (full privileges) | install only plugins you trust |
| LAN intrusion of the lab server | high on an untrusted network | high (kernel-level commands) | trusted LAN only; never expose port 8765 |
| wrong payload / modified blob | low if you verify hashes | high | let `prepare_operator_data.py` verify every hash |

---

## 2. What can actually go wrong

### 2.1 A power-off is not automatically a brick

The exploit deliberately exercises fragile kernel paths. A failed heap draw,
race, or relocation can make the console power off without a clean shutdown.
This is the **expected** failure mode and usually resolves on the next boot.

### 2.2 A brick is unlikely but possible

The chain writes to kernel memory and patches kernel text. A bug, a mismatched
payload, a power loss during a write, or a corrupted image can leave the
console unable to boot. This project mitigates that by:

- pinning the firmware (14.00) and every image/blob hash;
- validating the 24 guard sites against recorded stock bytes before patching;
- restoring the global `sysfilt_ops` slot (`safedown`) and making a best-effort
  restore if a later stage fails;
- refusing to patch when the guard table does not match.

None of that makes the risk zero. **Use a console you can afford to lose.**

### 2.3 PSN and your account

Modifying a console can violate the PlayStation Network terms of service and
may result in a console or account ban. This project does not provide methods
to evade detection, and you should not use it to cheat online or to access
content you do not own. If your PSN account matters, do not sign in on a
modified console.

### 2.4 Saves and data

The chain writes to `/data/hen` and restarts `SceShellUI`. It does not
intentionally touch save data, but a crash during a write can still corrupt
data. Back up anything important first.

### 2.5 Instability

HEN and its plugins run with high privileges. A buggy or malicious plugin can
crash the console or corrupt data. Install only plugins whose source or author
you trust.

### 2.6 Legal

Jailbreaking rules differ by country. Owning a device does not automatically
give you the right to circumvent every protection, and distributing tools or
modified firmware can be restricted. This is **not legal advice**. Read
[`COMPLIANCE.md`](COMPLIANCE.md) and, if in doubt, consult a qualified lawyer
in your jurisdiction.

---

## 3. Recovery ladder

Try these in order. Stop if the console shows hardware failure symptoms
(no video, repeated beeps, overheating, unusual noises).

1. **Wait.** Many failures end with the console powering off. Leave it off for
   ten seconds, then boot normally.
2. **Safe mode.** With the console off, hold the power button until the second
   beep (about seven seconds), then connect a USB cable and follow the
   on-screen options. Do not initialise the console unless you accept losing
   data.
3. **Official firmware reinstall.** Download the official firmware update for
   your model/region from Sony and reinstall it from USB in safe mode. This
   returns the console to stock but may erase data depending on the option
   you choose.
4. **Service.** If the console will not enter safe mode, it may need
   professional repair. Do not keep power-cycling a console that shows no
   signs of life.

If a run fails repeatedly at the same stage, stop and collect the driver log
instead of retrying indefinitely. Repeated hard power-offs are not good for
the hardware.

---

## 4. Network and supply-chain risks

- The lab server is plain HTTP with no authentication. Anyone on the same
  network can queue probes that execute in the console browser with kernel
  access. Use a trusted LAN, bind to the LAN interface, firewall the port, and
  stop the server when finished.
- Verify the bundled `artifacts/hen.bin`, `artifacts/pkb.bin` and
  `probes/stage_patch_v1.js` against `SHA256SUMS` and against the hashes
  printed by `prepare_operator_data.py`. Do not run a payload or blob from an
  untrusted source, and do not patch the scripts to bypass the checks.
- The page and probes are served by your own PC. Do not substitute a page from
  a third party.

---

## 5. Consent and responsibility

By running this software you accept that:

- you are responsible for the console, the data on it, and your account;
- the authors provide the software **as is**, without warranty of any kind;
- the authors are not liable for damage, data loss, bans, or legal
  consequences arising from your use;
- you will use it only on hardware you own and in compliance with applicable
  law.

If you are not comfortable with these risks, do not run it.
