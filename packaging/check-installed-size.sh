#!/bin/sh
# D10's Linux size budget, enforced against a built .deb.
#
# Run it the same way everywhere: CI calls this script, and so can you.
#
#     packaging/check-installed-size.sh ../smbpal_0.1.0_all.deb
#
# **What this is really guarding.** Not disk space — 425 kB against a Pi's SD
# card is nothing. It guards D11, *system Python, depend don't bundle*. The way
# a package like this grows is not by gaining code; it is by somebody vendoring
# a library to make an import work, and a vendored PyGObject or a copy of GTK
# arrives as tens of megabytes. A budget with real headroom still catches that
# on the first commit, while never firing on honest growth.
#
# It also catches the quieter version: shipping `tests/`, or `__pycache__`, or
# the icons twice. Those are tens of kB each and would otherwise go unnoticed
# for as long as nobody looked.
set -eu

# The number, and the one line in this file worth arguing about.
#
# 425 KiB was the first build, 29 August 2026, measured with
# `dpkg-query -W -f='${Installed-Size}'`. 700 leaves about 65% of headroom:
# loose enough that adding a screen, an icon set or another maintainer script
# never trips it, tight enough that no bundled dependency fits underneath.
BUDGET_KIB=700

deb=${1:-}
if [ -z "$deb" ]; then
    echo "usage: $0 PATH-TO-DEB" >&2
    exit 2
fi
if [ ! -f "$deb" ]; then
    echo "no such file: $deb" >&2
    exit 2
fi

size=$(dpkg-deb --field "$deb" Installed-Size)
case "$size" in
    ''|*[!0-9]*)
        echo "could not read Installed-Size from $deb (got '$size')" >&2
        exit 2
        ;;
esac

printf 'installed size: %s KiB\nD10 budget:     %s KiB\n' "$size" "$BUDGET_KIB"

if [ "$size" -gt "$BUDGET_KIB" ]; then
    echo
    echo "OVER BUDGET by $((size - BUDGET_KIB)) KiB." >&2
    echo "Either something is being bundled that should be depended on (D11)," >&2
    echo "or the package is shipping files it does not mean to. Check with:" >&2
    echo "  dpkg-deb -c $deb | sort -k3 -n -r | head -20" >&2
    exit 1
fi

printf 'headroom:       %s KiB\n' "$((BUDGET_KIB - size))"
