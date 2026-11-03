# PS4 Linux on 14.00 — root cause and working procedure (2026-11-03)

Console: PS4 Slim **CUH-2016A** (Belize), retail FW **14.00**, GoldHEN **2.4b18.13**
Loader: **ps4-linux-loader v25.2** (first 14.00 release)
Result: **working** — Linux 7.1.7 (`Strawberry General`) boots, Arch Linux runs, Steam + Vulkan
work, and a native Linux game (Turing Complete) plays at 1920×1080 with clean frames.
Steam-specific details are in `STEAM-PS4-INVESTIGATION.md` §8.

## TL;DR

The loader's kexec arming on 14.00 is correct. What breaks is the loader's **own reboot
trigger**:

```c
int evf = evf_open("SceSysCoreReboot");
evf_cancel(evf, 0x4000, 0);   /* 0x4000 = RB_POWEROFF */
evf_close(evf);
kill(1, SIGUSR1);
```

On 14.00 this kills the console instantly (black screen, white LED, network services gone,
ICMP still answering). The shutdown never reaches the ICC path, so the installed
`icc_query_nowait` hook never runs and the kexec never happens.

Starting the **same shutdown from the PS4's own power menu** works: the hook fires and Linux
boots.

**Root cause (confirmed):** `sys_reboot()` on 14.00 never calls `icc_query_nowait`. Only the
shell-orchestrated shutdown does — which is exactly why the power menu works and no
`evf`/`kill(1)` variant does. Reverse-engineered from `/mini-syscore.elf` (pid 1): its
`SIGUSR1` handler polls the `SceSysCoreReboot` flag and then calls
`reboot(0x80000 | bits)`; that reaches `kern_reboot`, not `icc_query_nowait`.

**Fix (`linux-autoboot.bin`):** hook **`kern_reboot`** as well, and call it from kernel
context (`-DHOOK_KERN_REBOOT -DAUTO_TRIGGER=0x0`). `kern_reboot` is on *every* reboot path,
so the hand-off no longer depends on the shell, on the power menu, or on userland at all:

```
sys_reboot() ─────────────► kern_reboot ─────► [kern_reboot hook] ──► Linux
SceShellCore shutdown ────► icc_query_nowait ► [ICC hook] ────────► Linux
```

Sending that single raw `.bin` boots Linux immediately — no shutdown, no evf, no
`kill(1)`, no power-menu step.

A second, independent problem: the payload ignores `SIGTERM`/`SIGSTOP` at startup. During a
shutdown the system asks every process to exit; the payload refuses, so the shutdown stalls
(display already torn down) until a timeout. This makes a successful hand-off look like a
hang for minutes. Hooking `kern_reboot` sidesteps this entirely.

## Bisection evidence

| payload | what it did | result |
|---|---|---|
| `linux-probe1.elf` | full arm + hook, **no** reboot trigger | console stays alive |
| `linux-probe4.elf` | hook = `return 0` only | black screen |
| `linux-probe5.elf` | no hook installed | black screen |
| `linux-probe6.elf` | skip pstate patch | black screen |
| `linux-probe7.elf` | skip kmem_alloc patches | black screen (arms fine) |
| `linux-probe8.elf` | skip all byte patches | black screen |
| `linux-probe9.elf` | **only** the reboot trigger, no kexec | **instant black screen** |

`linux-probe9` is the decisive test: with no kexec, no patches and no allocations, the trigger
alone kills the console. Therefore the arming path was never at fault.

Control: GoldHEN loaded, no payload, PS4 power menu → Restart → clean restart. So the
jailbreak itself does not break shutdown.

## Working procedure

GoldHEN stays the default payload; Linux is a **separate, explicit hand-off** so nothing depends
on exploit timing.

1. Boot Orbis, run the jailbreak (GoldHEN).
2. Once GoldHEN is up (`:9090`/`:2121` open, "GoldHEN loaded" seen), do **one** of:
   - **on console:** PayLoader → `linux-autoboot.elf` (it scans `/data/payloads/` and
     `/usb*/payloads/`, exactly like the probe ELFs); or
   - **from the lab:** press the **Linux** button (it only POSTs the `.bin` to `:9090`;
     it does not start the chain).
3. Linux boots, ~2 s later.

Both builds ship: `/data/payloads/linux-autoboot.elf` (PayLoader, local) and
`artifacts/linux-autoboot.bin` (lab POST, network). Note the binloader on `:9090` only
executes raw `.bin`; `.elf` images hang it, which is why the two paths use different files.

**Do not chain these.** Sending the payload in the same second the installer returns fires
`kern_reboot` while SceShellCore is still restarting and hard-hangs the console (no ICMP). The
lab used to do exactly that; it now waits for an explicit press instead.

### Manual fallback (power menu)

1. Boot Orbis, run the jailbreak **with the USB drives unplugged**.
2. Plug in the boot medium (FAT32 with `bzImage`, `initramfs.cpio.gz`, `bootargs.txt`).
3. Run the **arm-only** payload (`payloads/linux-arm.bin`, `-DNO_REBOOT_WATCHDOG`).
   Wait for `kexec successfully armed. Please shut down the system.`
4. PS4 power menu → **Restart PS4**.
5. Linux boots. Console keeps the LED white/blue; HDMI comes back in the new kernel.

### Why the evf trigger cannot work on 14.00

`/mini-syscore.elf` (pid 1) handles `SIGUSR1` like this:

```c
poll("SceSysCoreReboot", bits=1, WAITMODE_AND, &result);  /* failure is non-fatal */
reboot(0x80000 | result);
```

`evf_cancel(evf, 0x4000, 0)` *clears* bits, so the poll fails and pid 1 reboots with whatever
was on the stack. `evf_set(evf, 0x1b, 0)` + `kill(1, SIGUSR1)` does give an orderly shutdown
(userland exits cleanly) but still never reaches `icc_query_nowait`, so the console stalls at
its last step (white LED, kernel alive, all userland ports closed).
`reboot(0x4000)` = power off (`SIGUSR2` path). Do not use either on 14.00.

## Required boot files

`bootargs.txt` must include a root, otherwise the initramfs drops to a rescue shell:

```
panic=0 clocksource=tsc consoleblank=0 net.ifnames=0 radeon.dpm=0 amdgpu.dpm=0 drm.debug=0 \
debug ignore_loglevel console=tty0 video=HDMI-A-1:1920x1080@60 \
ip=192.168.1.188::192.168.1.1:255.255.255.0:ps4linux:eth0:off \
netconsole=6666@192.168.1.188/eth0,6666@192.168.1.10/d8:3a:dd:e2:b9:b2 \
root=LABEL=psxitarch rootfstype=ext4 rw
```

The initramfs is a better-initramfs build with PS4 helpers (`find-install.sh`,
`install-linux-ext.sh`, `start-psxitarch.sh`). It mounts `LABEL=psxitarch`, prepares
`/newroot` and does `switch_root /newroot /sbin/init`.

## 14.00 offsets used (loader `magic.h`)

```
kern_off_icc_query_nowait 0x448630
kern_off_kern_reboot      0x3A2850
kern_off_pstate_before_shutdown 0x3A2E40
```

`kernel_hook_install` patches `icc_query_nowait` at kernel base + `0x448630`; the kernel base
is derived from `rdmsr 0xc0000082` minus `xfast_syscall`, so KASLR is handled.

The one-click payload additionally patches `kern_reboot` at kernel base + `0x3A2850`
(`-DHOOK_KERN_REBOOT`). `AUTO_TRIGGER` only fires if that hook installed successfully
(`kern_reboot_hooked`), so a failed install degrades to the manual power-menu procedure
rather than shutting the console down.

## Gotchas found on the way

- The initramfs `telnetd` is busybox without `-p`; `telnetd -l /bin/sh -p 23` in `/init`
  fails silently. `-a` (auto login) works; for scripting, `nc -l -p 2222 -e /bin/sh` is
  easier.
- `nc -l` serves one connection and exits; wrap in `while true; do nc ...; done &`.
- `%p` in this kernel sometimes prints `0xffffffffffffffff` for valid pointers; `%lx` prints
  are trustworthy.
- The payload's diag file on USB is truncated but not flushed before a hang; klog is the
  reliable channel.
- Only run one Linux payload per boot (double arming hangs the GPU/ShellCore).
