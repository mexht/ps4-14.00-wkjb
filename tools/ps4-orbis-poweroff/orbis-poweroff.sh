#!/bin/sh
# Power off this PS4 and leave it ready to boot Orbis.
#
# A warm "reboot"/"shutdown" does not come back cleanly here, and the ordered
# shutdown stalls in userland, so flush the disks and ask the kernel to power
# the board off directly. Press the power button afterwards to boot Orbis.
sync
sync

# logind allows a local active session to power off; sudo is the fallback
# (ps4 has NOPASSWD in /etc/sudoers.d/10-ps4).
if systemctl poweroff -f 2>/dev/null; then
        exit 0
fi
exec sudo -n poweroff -f
