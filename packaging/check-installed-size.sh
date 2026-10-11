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
# `dpkg-query -W -f='${Installed-Size}'`. 700 left about 65% of headroom:
# loose enough that adding a screen, an icon set or another maintainer script
# never trips it, tight enough that no bundled dependency fits underneath.
#
# **Raised to 1024 on 11 October 2026, a deliberate decision recorded in the
# plan's §3.2.** The 700 was fully consumed by honest growth: main measured
# *exactly* 700 KiB, so the next commit to add a line of anything failed CI,
# and the one that did was 51 lines of docstring. 85% of the package is our own
# Python source -- 593 KiB of it -- and nothing unintended ships: the install
# list is six files plus `smbpal/`. So the ceiling moved rather than the code.
#
# **What the new number still catches**, which is the only test that matters
# here: a vendored PyGObject or GTK, tens of megabytes, instantly; `tests/`,
# which is 472 KiB of source against 321 KiB of headroom; a shipped
# `__pycache__`, which for 593 KiB of source is a few hundred KiB.
#
# **What it no longer catches, and what that means.** The icons shipped twice is
# about 50 KiB, and no fixed ceiling can resolve that any more: the package grew
# 425 -> 700 KiB in six weeks, about 46 KiB a week, so any headroom small enough
# to catch a 50 KiB mistake is gone within days of being set. **A budget on
# weight stopped being able to separate vendoring from honest growth once our
# own source became the dominant term.** The answer is to assert *what* ships
# rather than how much -- the six installed paths plus `smbpal/**.py` and
# nothing else -- which is immune to growth and catches the small mistakes by
# name. Recorded as a candidate in the plan's §12.2; this file is the stopgap.
BUDGET_KIB=1024

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
