#!/bin/sh
# Install, share and erase the .rpm on whatever RPM distribution this runs on,
# and prove smb.conf comes back byte-identical.
#
#   packaging/check-rpm.sh path/to/smbpal-X.Y.Z-1.fcNN.noarch.rpm
#
# The sibling of packaging/check-distro.sh, which does the same for the .deb,
# and it is deliberately the same shape: same order, same claims, same failure
# messages, so a difference in the output is a difference between the packages
# and not between two scripts that drifted.
#
# Run as root in a throwaway container or VM: it installs packages and starts
# Samba. CI runs it in fedora containers.
#
# **Two things this cannot see, and a Fedora VM must**, because a container
# inherits the host's kernel and its SELinux state:
#
#   1. **SELinux.** smbd is confined (smbd_t) and will not read a directory
#      labelled user_home_t or var_t, which is what a folder someone wants to
#      share is labelled. Nothing here is enforcing, so a share works in this
#      container that would be refused on a real Fedora desktop.
#   2. **firewalld.** Fedora blocks 445 inbound by default, so a share that
#      serves perfectly to localhost is unreachable from another machine until
#      the samba service is allowed through.
#
# Both belong to the Fedora runbook, not to CI, and both are recorded there.
set -eux

rpm_file=$(realpath "$1")

. /etc/os-release
echo "== ${PRETTY_NAME}"

# A bare name would be read as a package to fetch from the repositories, the
# same trap the .deb has with apt, so the path stays absolute.
dnf install -y "$rpm_file"

# What this distribution actually gave us, for the record in the log.
python3 --version
rpm -q samba samba-common-tools cifs-utils python3-gobject gtk4 2>&1 || true
rpm -q --queryformat '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' smbpal

smbpal --version
smbpald --version
test -f /usr/share/polkit-1/actions/org.smbpal.policy
test -f /etc/xdg/autostart/smbpal-tray.desktop
test -f /usr/lib/systemd/system/smbpald.service
test -f /usr/lib/sysusers.d/smbpal.conf

# The group the socket is guarded by, created by %pre rather than left to
# systemd's file trigger — which is the one thing in this spec that a container
# with no systemd running could not otherwise prove.
getent group smbpal

# Every entry point's module imports against this distribution's Python and
# PyGObject. The GUI is imported, not run: there is no display here, and the
# point is to catch an API this GTK or GLib does not have at import time.
python3 -c 'import smbpal.cli.main, smbpal.daemon.main, smbpal.gui.tray, smbpal.gui.app'

# The baseline is taken now, after samba's own install has written the file and
# after ours has run, which must not have touched it.
cp /etc/samba/smb.conf /tmp/smb.conf.before

# No systemd: start what the units would have. `--authorisation root` because
# polkit is not running either; the CLI as uid 0 is what %preun uses too.
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

# **Configure something before erasing**, or the erase proves nothing: that is
# how the Pi's first purge test passed while removing nothing at all.
mkdir -p /srv/smbpal-ci
smbpal share add CI /srv/smbpal-ci
smbpal status
grep -q smbpal /etc/samba/smb.conf
testparm -s 2>/dev/null | grep -qx '\[CI\]'

kill "$daemon"
wait "$daemon" || true

# **One step, and it is purge.** RPM has no remove/purge pair, so %postun does
# what the Debian postrm does on purge: the config goes too. The spec says why.
dnf remove -y smbpal
test ! -e /etc/smbpal || { echo "erase left /etc/smbpal behind"; exit 1; }
test ! -e /etc/samba/smbpal.conf || { echo "erase left smbpal.conf behind"; exit 1; }
test ! -e /etc/avahi/services/smbpal.service || { echo "erase left the Avahi service"; exit 1; }
cmp /etc/samba/smb.conf /tmp/smb.conf.before \
    || { echo "erase did not restore smb.conf"; diff /tmp/smb.conf.before /etc/samba/smb.conf; exit 1; }

echo "== ${PRETTY_NAME}: installed, shared and erased; smb.conf byte-identical"
