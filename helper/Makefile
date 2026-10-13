# macOS only. The Linux package does not contain the helper and must not try to
# build it: `packaging/debian/smbpal.install` names its files explicitly, and
# CI's Linux jobs never enter this directory.
#
# -Wall -Wextra -Werror because this is the one component that runs as root, and
# `-fstack-protector-strong` for the same reason. No optimisation flags: the
# whole program is a socket and one exec, so there is nothing to optimise and a
# reader comparing the binary to the source should not have to account for it.
CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -fstack-protector-strong -D_DARWIN_C_SOURCE
# Security for Authorization Services (§10's rights and the verify), and
# CoreFoundation for the dictionary a right's rule is expressed as. Linked
# rather than dlopened: this is the component that must not be able to run with
# its authorisation code missing.
LDFLAGS ?= -framework Security -framework CoreFoundation
PREFIX ?= /usr/local
LIBEXEC = $(PREFIX)/libexec/smbpal

all: smbpal-helper

smbpal-helper: smbpal-helper.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Root-owned storage, which is the whole point: see the spike's §0. `-S` renames
# a temporary file into place, so the root binary is never half-written.
#
# **A replaced helper must be bootstrapped again, or it is killed at launch.**
# launchd attaches a launch constraint to the job's plist that the build it was
# registered with satisfies; a new build fails it -- OS_REASON_CODESIGNING |
# Launch Constraint Violation -- and the helper stays down behind its old
# socket. Measured 12 October 2026, twice; `bootout` then `bootstrap` cleared it
# (helper spike §16). So when a job is installed, this target re-registers it.
#
# **`bootout` returns before launchd has finished with the job**, and a
# `bootstrap` straight after it fails with `5: Input/output error` -- which is
# what 0.2.12's version of this target did on its first real upgrade, 13
# October 2026, leaving no helper loaded at all. So it waits for `print` to
# stop finding the job, then retries `bootstrap` a few times before giving up.
# The wait is the documented-behaviour half; the retry is for a launchd that
# still answers EIO a moment after the job reads as gone, which nobody has
# measured either way.
#
# **It installs a binary you built, and does not build one.** `install` used to
# depend on the build, so `sudo make install` compiled as root and left a
# root-owned file in the checkout that the next unprivileged `make` -- the test
# suite's among them -- could not replace. Build as yourself, install as root.
install:
	@if [ ! -f smbpal-helper ] || [ smbpal-helper.c -nt smbpal-helper ]; then \
	    echo "build the helper as yourself first: make -C helper" >&2; exit 1; \
	fi
	install -d -o root -g wheel -m 755 $(LIBEXEC)
	install -S -o root -g wheel -m 755 smbpal-helper $(LIBEXEC)/smbpal-helper
	@if [ -f /Library/LaunchDaemons/app.smbpal.helper.plist ]; then \
	    launchctl bootout system/app.smbpal.helper 2>/dev/null || true; \
	    i=0; while launchctl print system/app.smbpal.helper >/dev/null 2>&1; do \
	        i=$$((i + 1)); \
	        if [ $$i -gt 50 ]; then echo "the old helper job is still loaded after 10s" >&2; exit 1; fi; \
	        sleep 0.2; \
	    done; \
	    for attempt in 1 2 3 4 5; do \
	        if launchctl bootstrap system /Library/LaunchDaemons/app.smbpal.helper.plist 2>/dev/null; then \
	            echo "re-registered app.smbpal.helper with launchd"; exit 0; \
	        fi; \
	        sleep 1; \
	    done; \
	    echo "could not bootstrap app.smbpal.helper; run: sudo launchctl bootstrap system /Library/LaunchDaemons/app.smbpal.helper.plist" >&2; \
	    exit 1; \
	fi

# `-Dmain=` renames the helper's entry point so the test can have its own,
# which is how the parser is tested without the shipped file knowing about it.
# -Wno-unused-function because the test exercises the parser, not every verb.
parse-test: parse-test.c smbpal-helper.c
	$(CC) $(CFLAGS) -Wno-unused-function -Dmain=smbpal_helper_main -I. \
	    -o $@ parse-test.c $(LDFLAGS)

check: parse-test
	./parse-test

clean:
	rm -f smbpal-helper parse-test

.PHONY: all install clean check
