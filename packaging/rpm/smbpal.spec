# SMBPal for the RPM distributions: Fedora first, and whatever of RHEL,
# CentOS Stream, AlmaLinux and Rocky has Python 3.11 or newer.
#
# **The Debian package is the reference and this file follows it**, rather than
# the two diverging into different products. Every file installed here is the
# same file `packaging/debian/smbpal.install` names, read out of the same
# source tree, and the scriptlets do what `smbpal.prerm` and `smbpal.postrm`
# do. Where this spec deliberately differs from the .deb, the comment says so
# and says why — there are three such places and they are all about RPM having
# no second removal step.

Name:           smbpal
Version:        0.2.2
Release:        1%{?dist}
Summary:        Share folders over SMB, and connect to shares on other machines

# SPDX, which modern Fedora requires. `pyproject.toml` still states the licence
# as a classifier for the reason written there; both name GPL-3.0-or-later and
# LICENSE is the text itself.
License:        GPL-3.0-or-later
URL:            https://github.com/smbpal/smbpal-desktop
Source0:        %{name}-%{version}.tar.gz

# Pure Python, one wheel, no compiled extension. The same claim
# `Architecture: all` makes in the .deb.
BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  systemd-rpm-macros

# Named the way Fedora names them, which is not the way Debian does:
#
#   Debian                  Fedora
#   samba                   samba                  smbd itself
#   samba-common-bin        samba-common-tools     testparm, smbcontrol, pdbedit, smbpasswd
#   cifs-utils              cifs-utils             mount.cifs
#   polkitd | policykit-1   polkit                 one name, no era to span
#
# `samba-common-tools` is not optional however little of Samba someone wants:
# `samba/control.py` shells out to `testparm` and `smbcontrol` on every apply,
# and `credentials` calls `smbpasswd` and `pdbedit`.
Requires:       samba
Requires:       samba-common-tools
Requires:       cifs-utils
Requires:       polkit

# The GUI half, kept out of Requires for the reason `pyproject.toml` gives:
# the daemon and the CLI are the product on a headless machine, and a server
# should not pull GTK in to run them. `dnf install smbpal` on a desktop gets
# them anyway, because Fedora installs weak dependencies by default.
Recommends:     python3-gobject
Recommends:     gtk4
Recommends:     avahi
Recommends:     avahi-tools
Suggests:       samba-client

# groupadd, in %%pre.
Requires(pre):  shadow-utils
# The %%systemd_* scriptlet macros below need systemd present when they run.
%{?systemd_requires}

%description
SMBPal manages Samba shares and cifs mounts on one computer, through a daemon,
a command line and a GTK4 window that all speak to the same socket.

It owns an include file rather than smb.conf, so an existing hand-written
configuration is left exactly as it was found, and removing SMBPal leaves it
byte-identical.

%prep
%autosetup -n %{name}-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files smbpal

# Everything below is what `smbpal.install` installs on the Debian side, from
# the same paths in the same tree. The unit, the sysusers file and both desktop
# files live under packaging/debian/ because that is where they were written
# first; they are not Debian-specific and copying them here would be a second
# copy to keep in step.
install -D -m 0644 packaging/debian/smbpal.smbpald.service \
    %{buildroot}%{_unitdir}/smbpald.service
install -D -m 0644 packaging/debian/smbpal.sysusers \
    %{buildroot}%{_sysusersdir}/smbpal.conf
install -D -m 0644 packaging/polkit/org.smbpal.policy \
    %{buildroot}%{_datadir}/polkit-1/actions/org.smbpal.policy
install -D -m 0644 packaging/debian/smbpal.desktop \
    %{buildroot}%{_datadir}/applications/smbpal.desktop
install -D -m 0644 packaging/debian/smbpal-tray.desktop \
    %{buildroot}%{_sysconfdir}/xdg/autostart/smbpal-tray.desktop
for icon in smbpal smbpal-idle smbpal-attention; do
    install -D -m 0644 "packaging/icons/hicolor/scalable/status/${icon}.svg" \
        "%{buildroot}%{_datadir}/icons/hicolor/scalable/status/${icon}.svg"
done

# The Debian build skips its test suite deliberately (`rules`: pulling GTK into
# the build chroot would make the package build-depend on the toolkit it only
# recommends). Here it runs, with one condition, and the condition is the
# interesting part.
#
# **The suite asserts what a non-root caller is refused.** `handlers.py` gives
# uid 0 the short-circuit past polkit, and a dozen tests exist to prove that
# everyone else is stopped; run as root they assert a refusal that correctly
# never comes, and 13 of them fail. That is the tests being right about the
# product, not the product being wrong.
#
# `mock` builds as an unprivileged user, so on the path Fedora actually uses to
# build a package this runs the whole suite and means something. `rpmbuild` in
# a container runs as root, so there it says why it did not. It prints the
# reason either way rather than passing quietly, because a %%check that silently
# does nothing is worse than no %%check at all.
%check
if [ "$(id -u)" -eq 0 ]; then
    echo "%%check: skipped. The suite asserts what a non-root peer is refused"
    echo "  and uid 0 takes the short-circuit past polkit, so it must be run"
    echo "  unprivileged. mock does; this build is root. CI runs the whole"
    echo "  suite on every commit, and check-rpm.sh imports every entry point"
    echo "  against the installed package."
else
    %{python3} -m unittest discover -s tests -t . -q
fi

%pre
# The socket's group guard (D4). The sysusers file below is the modern route
# and systemd's own file trigger runs it, but that trigger fires at the end of
# the transaction, and this group has to exist before anything starts the
# daemon. `groupadd -r` is idempotent behind the getent, and an install that
# left the group to chance is how the first .deb shipped a daemon that could
# not bind its socket.
getent group smbpal >/dev/null || groupadd -r smbpal

%post
%systemd_post smbpald.service
# Same words as the Debian postinst, and for the same reason: membership of
# this group is access to a root daemon, so granting it is the administrator's
# decision and not a package's. Saying nothing would leave an install that
# cannot be used and does not explain itself.
if [ $1 -eq 1 ]; then
    echo "SMBPal: to use it, add each user to the 'smbpal' group:"
    echo "    sudo usermod -aG smbpal <user>"
    echo "  They will need to log out and back in for it to take effect."
    echo "  Then start the daemon: sudo systemctl enable --now smbpald"
fi

%preun
# **Uninstall, not upgrade.** $1 is the number of instances that will remain.
#
# This is `smbpal.prerm`, and the ordering argument there applies unchanged:
# teardown needs a daemon that answers and a /usr/bin/smbpal that still exists,
# so it runs before %%systemd_preun stops the unit and before RPM removes the
# files. It hands the machine back — unmounts what SMBPal mounted, removes the
# units it wrote, and takes its block out of smb.conf — because none of that is
# owned by the package and nothing else would ever remove it.
if [ $1 -eq 0 ]; then
    if [ -x %{_bindir}/smbpal ]; then
        if ! %{_bindir}/smbpal teardown --yes; then
            echo "SMBPal: teardown failed. Its mount units, its smb.conf" >&2
            echo "  block, or both may still be in place. Removal will" >&2
            echo "  continue: blocking it would leave you with neither a" >&2
            echo "  working package nor a clean machine." >&2
        fi
    fi
fi
%systemd_preun smbpald.service

%postun
%systemd_postun_with_restart smbpald.service
# **The first deliberate difference from the .deb: erase is purge.**
#
# dpkg has two steps, `remove` and `purge`, and SMBPal uses the gap between
# them — remove keeps /etc/smbpal so a reinstall picks the configuration back
# up, and only purge forgets it. RPM has one step, so a thing kept here is kept
# for ever, and one of the things kept would be /etc/smbpal/credentials: cifs
# passwords in plain text, 0600, belonging to a package that is no longer
# installed. Between leaving those on disk indefinitely and losing a config
# that can be rebuilt in a minute from the window, this takes the config.
#
# Keep it first if you want it: `cp -a /etc/smbpal /etc/smbpal.keep` before
# erasing, and copy it back before the daemon's first start.
if [ $1 -eq 0 ]; then
    rm -rf %{_sysconfdir}/smbpal
    remove_smb_conf_block() {
        conf=%{_sysconfdir}/samba/smb.conf
        [ -f "$conf" ] || return 0
        begins=$(grep -c '^[[:space:]]*# >>> smbpal >>>[[:space:]]*$' "$conf" || true)
        ends=$(grep -c '^[[:space:]]*# <<< smbpal <<<[[:space:]]*$' "$conf" || true)
        if [ "$begins" = 0 ] && [ "$ends" = 0 ]; then
            return 0
        fi
        # Refusing beats guessing, exactly as in the Debian postrm and in
        # include.remove_include: a range delete with no end deletes to the end
        # of a file we did not write.
        if [ "$begins" != 1 ] || [ "$ends" != 1 ]; then
            echo "SMBPal: $conf has $begins opening and $ends closing markers," >&2
            echo "  which is not the one block SMBPal writes. Leaving it alone;" >&2
            echo "  remove the block by hand." >&2
            return 0
        fi
        tmp=$(mktemp "$conf.smbpal-erase.XXXXXX") || return 0
        if sed -e '/^[[:space:]]*# >>> smbpal >>>[[:space:]]*$/,/^[[:space:]]*# <<< smbpal <<<[[:space:]]*$/d' \
               -e '\%^[[:space:]]*include[[:space:]]*=[[:space:]]*/etc/samba/smbpal\.conf[[:space:]]*$%d' \
               "$conf" > "$tmp"; then
            # cat rather than mv, so the file keeps its inode, mode and owner
            # instead of inheriting mktemp's 0600 root.
            cat "$tmp" > "$conf"
        fi
        rm -f "$tmp"
    }
    remove_smb_conf_block
    rm -f %{_sysconfdir}/samba/smbpal.conf
    rm -f %{_sysconfdir}/avahi/services/smbpal.service
    # Best effort, and deliberately not fatal: a Samba that will not reload is
    # worth nothing next to an erase that fails half-done.
    if command -v smbcontrol >/dev/null 2>&1; then
        smbcontrol smbd reload-config >/dev/null 2>&1 || true
    fi
fi

%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/smbpal
%{_bindir}/smbpald
%{_bindir}/smbpal-gui
%{_bindir}/smbpal-tray
%{_unitdir}/smbpald.service
%{_sysusersdir}/smbpal.conf
%{_datadir}/polkit-1/actions/org.smbpal.policy
%{_datadir}/applications/smbpal.desktop
%{_sysconfdir}/xdg/autostart/smbpal-tray.desktop
%{_datadir}/icons/hicolor/scalable/status/smbpal.svg
%{_datadir}/icons/hicolor/scalable/status/smbpal-idle.svg
%{_datadir}/icons/hicolor/scalable/status/smbpal-attention.svg

%changelog
* Sun Sep 20 2026 Luke Hynek <luke.hynek@aiminternet.co.uk> - 0.2.2-1
- First RPM packaging, following the .deb file for file.
