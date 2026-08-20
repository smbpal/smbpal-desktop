"""Everything that touches Samba: the include block, our config file, and
`smbpasswd`.

The shape of this package is dictated by M0 §1, which found three things that
invert what the plan assumed. They are enforced here rather than remembered:

1. `testparm` cannot validate our file — it reports OK when the included file
   is malformed *and* when it is missing. We verify by presence instead.
2. The include goes in `[global]`. Appended to end-of-file it lands inside
   `[print$]`, the last section of Debian's stock file.
3. The insertion must be idempotent, because the daemon rewrites config on
   every share change.
"""

from smbpal.samba.include import (
    BEGIN_MARKER,
    END_MARKER,
    INCLUDE_LINE,
    has_include,
    insert_include,
    remove_include,
)

__all__ = [
    "BEGIN_MARKER",
    "END_MARKER",
    "INCLUDE_LINE",
    "has_include",
    "insert_include",
    "remove_include",
]
