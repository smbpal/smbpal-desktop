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

# Root-owned storage, which is the whole point: see the spike's §0.
install: smbpal-helper
	install -d -o root -g wheel -m 755 $(LIBEXEC)
	install -o root -g wheel -m 755 smbpal-helper $(LIBEXEC)/smbpal-helper

clean:
	rm -f smbpal-helper

.PHONY: all install clean
