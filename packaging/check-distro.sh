#!/bin/sh
# Install, share, remove and purge the .deb on whatever distribution this runs
# on, and prove smb.conf comes back byte-identical.
#
#   packaging/check-distro.sh path/to/smbpal_X.Y.Z_all.deb
#
# Run as root in a throwaway container or VM: it installs packages and starts
# Samba. CI runs it in debian:12, debian:13, ubuntu:24.04 and ubuntu:26.04
# (plan §12.1, Phase 1.5: "the packaging half should be pushed into
# containers rather than repeated by hand").
#
# **Byte-identical, not "has no smbpal in it".** The package job on the runner
# greps for our block; this compares the whole file with what it was before
# SMBPal touched it, which is the guarantee §6 makes and the one most likely to
# break on a distribution that patches Samba's packaging.
#
# A container has no systemd, so this starts smbd and smbpald itself, which is
# also why it cannot say anything about the unit, Type=notify or polkit. The
# package job covers those on a real systemd host.
set -eux

deb=$(realpath "$1")
export DEBIAN_FRONTEND=noninteractive

. /etc/os-release
echo "== ${PRETTY_NAME}"

apt-get update
# `./` or an absolute path, never a bare name: apt reads a bare argument as a
# package name. This is the command the site tells people to run.
apt-get install -y "$deb"

# What this distribution actually gave us, for the record in the log.
python3 --version
dpkg-query -W -f='${Package} ${Version}\n' \
    samba samba-common-bin cifs-utils python3-gi gir1.2-gtk-4.0 2>/dev/null || true

smbpal --version
smbpald --version
test -f /usr/share/polkit-1/actions/org.smbpal.policy
test -f /etc/xdg/autostart/smbpal-tray.desktop

# Every entry point's module imports against this distribution's Python and
# PyGObject. The GUI is imported, not run: there is no display here, and the
# point is to catch an API this GTK or GLib does not have at import time.
python3 -c 'import smbpal.cli.main, smbpal.daemon.main, smbpal.gui.tray, smbpal.gui.app'

# The baseline is taken now, after samba's own postinst has written the file
# and after ours has run, which must not have touched it.
cp /etc/samba/smb.conf /tmp/smb.conf.before

# No systemd: start what the units would have. `--authorisation root` because
# polkit is not running either; the CLI as uid 0 is what prerm uses too.
smbd -D
install -d -m 0750 -g smbpal /run/smbpal
smbpald --authorisation root &
daemon=$!
i=0
until [ -S /run/smbpal/smbpald.sock ]; do
    i=$((i + 1))
    [ "$i" -le 50 ] || { echo "smbpald never made its socket"; exit 1; }
    sleep 0.2
done
smbpal ping

# **Configure something before removing**, or the removal proves nothing:
# that is how the Pi's first purge test passed while removing nothing at all.
mkdir -p /srv/smbpal-ci
smbpal share add CI /srv/smbpal-ci
smbpal status
grep -q smbpal /etc/samba/smb.conf
testparm -s 2>/dev/null | grep -qx '\[CI\]'

# prerm runs `smbpal teardown --yes` against the daemon, which is still up.
apt-get remove -y smbpal
test -d /etc/smbpal || { echo "remove deleted the config; only purge may"; exit 1; }
cmp /etc/samba/smb.conf /tmp/smb.conf.before \
    || { echo "remove did not restore smb.conf"; diff /tmp/smb.conf.before /etc/samba/smb.conf; exit 1; }

kill "$daemon"
wait "$daemon" || true

apt-get purge -y smbpal
test ! -e /etc/smbpal || { echo "purge left /etc/smbpal behind"; exit 1; }
test ! -e /etc/samba/smbpal.conf || { echo "purge left smbpal.conf behind"; exit 1; }
test ! -e /etc/avahi/services/smbpal.service || { echo "purge left the Avahi service"; exit 1; }
cmp /etc/samba/smb.conf /tmp/smb.conf.before \
    || { echo "purge did not restore smb.conf"; diff /tmp/smb.conf.before /etc/samba/smb.conf; exit 1; }

echo "== ${PRETTY_NAME}: installed, shared, removed and purged; smb.conf byte-identical"
