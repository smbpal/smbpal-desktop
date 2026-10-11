# `smbpal-helper` — the only part of SMBPal that runs as root on macOS

**Why there is C in a Python project.** The Homebrew prefix is admin-writable —
interpreter symlink and `site-packages` included — so a root LaunchDaemon
running `smbpald` would let any member of `admin` execute code as root with no
password. That escalation is measured in the docs' `phase-2/macos-helper-spike.md`
§0. A compiled binary in root-owned storage has no interpreter and no import
path, so the escalation is **dissolved rather than worked around**.

**Why it is small, and must stay small.** The account spike's §4 enumerated the
privileged surface: six `dscl` calls, four OpenDirectory calls, `chmod +a`,
`sharing`, one file write, and the runtime directory. Nothing in it needs
SMBPal's config engine, IPC server or discovery, so those stay in Python with
their tests. **The Python daemon still runs** — as a service account rather than
as root, which is what makes it safe to leave in an admin-writable prefix.

## The thing that asks is not trusted

`smbpald` is admin-writable code talking to a root helper, so **a helper that
performs whatever it is asked is a root-escalation service with a socket on it.**
Spike §9 sets three rules and they are requirements, not preferences:

1. **A fixed vocabulary of verbs.** No pass-through exec, no caller-supplied
   command. Job A has exactly one verb and it takes no arguments.
2. **Arguments validated against what the helper owns**, never relayed.
3. **Never a shell.** `execv` with a vector the helper built itself.

`tests/test_helper.py` asserts rules 1 and 3 against the source, because they are
properties of the code and the running process needs root to reach.

## What job A does

| | |
|---|---|
| `/var/run/smbpal` | created `root:smbpal 0750` — the daemon cannot, since it is not root |
| `/var/run/smbpal/helper.sock` | owned by the service account, `0600`. **Not group-guarded**: `smbpal` answers *may this person ask the daemon*, never *may this person ask root* |
| peer check | `getpeereid`, refusing any uid but the service account's — defence in depth behind the `0600`, not instead of it |
| `share.list` | runs `sharing -l -f json`. Read-only on purpose: the first verb should have nothing to undo |

## Building

```sh
make                      # -Wall -Wextra -Werror; macOS only
make install PREFIX=/usr/local   # as root; lands in root-owned storage
./smbpal-helper --service-user <name> --check
```

`--check` resolves the identities and touches nothing, so it **does not need
root** — it is the one diagnostic available before elevating.

## Not here yet

- **The install step**, which `brew` cannot perform: the binary must reach
  root-owned storage and the plists must be bootstrapped, and §0 forbids the root
  plist pointing into the Homebrew prefix. There is a `sudo` step after
  `brew install` and its wording is an open decision (spike §9).
- **Identity creation.** The install scans 450–499, creates the pair, reads back
  what it landed on and records it. The recipe is the account spike's §4 minus
  the `SMB-NT` step; no number is compiled in anywhere.
- **Job B**, the privileged operations for sharing and accounts, which need real
  request framing. One verb with no arguments does not, and inventing a protocol
  before there is a second verb would be guessing at its shape.
- **The socket's own behaviour under test.** Binding, the `0600` ownership and
  the peer check need root and a `smbpal` group, so they are a runbook step
  rather than an assertion. Overridable paths would have made them testable and
  were rejected: a root binary that can be told where to put its socket is a
  worse trade than an untested bind.
