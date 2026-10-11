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

## Identities

`_smbpald` and the `smbpal` group, **both preferring 450 and both scanning
450–499 if it is taken.** Apple requires a role account's uid to be in that
range — measured 11 October 2026, `sysadminctl -addUser -roleAccount` refuses
without it — and fifty slots with no registry means a collision is a real
possibility rather than a theoretical one. A collision is not benign: two
accounts sharing a uid are indistinguishable for file ownership.

**`Password "*"` is the point of the service account, not a detail.** It is a
process identity: it runs `smbpald` and must never authenticate to anything. Job
B's SMB account is a *different* account for exactly that reason — it carries
`SMB-NT` and a real password, and merging them would turn the identity the
daemon runs as into a login credential. That is also why the daemon takes 450
and job B's account will scan past it.

What the install created is written to `/var/db/smbpal/created`, because §10.6
removes what SMBPal made and nothing else, and an account that was already there
when we arrived is somebody else's.

## Building and running

```sh
make                                   # -Wall -Wextra -Werror; macOS only
./smbpal-helper install --dry-run      # what it would choose; needs no root
./smbpal-helper serve --service-user _smbpald --check
```

**`smbpal setup` is the front door**, and it prints the rest rather than running
it. On macOS it reports what is installed and then names three commands:

```sh
sudo install -d -o root -g wheel -m 755 /usr/local/libexec/smbpal
sudo install -o root -g wheel -m 755 <built helper> /usr/local/libexec/smbpal/smbpal-helper
sudo /usr/local/libexec/smbpal/smbpal-helper install --daemon <path to smbpald>
```

**The order is the property worth having: nothing of SMBPal's runs as root until
the third command, and by then it is a root-owned file.** The first two are
`install(1)`, a system binary. A `setup` that elevated by itself, or a one-liner
that ran the Homebrew copy under `sudo`, would both put admin-writable code
behind root — once, briefly, but that is the thing §0 is about.

`--daemon` has no default because the Homebrew prefix is not one place —
`/opt/homebrew` on Apple silicon, `/usr/local` on Intel — and `smbpal setup`
knows its own, which is why it is the documented route.

**`--dry-run` and `--check` need no root.** Between them they answer *what will
this do* and *is it set up*, which are the two questions somebody has before
they are willing to type a password.

## Logs, and why they are in two places

| | |
|---|---|
| `/var/log/app.smbpal.helper.log` | root-owned, written by the root component |
| `/var/log/smbpal/daemon.log` | in a directory the install gives to the service account |

**The split is deliberate.** The helper's log records refused uids, so the
unprivileged component must not be able to edit the root component's account of
what it refused.

**And the daemon's own directory is not cosmetic.** launchd opens
`StandardErrorPath` **as the job's user, before it execs the program**. A
non-root job pointed at root-owned `/var/log` fails its own configuration with
`EX_CONFIG`, the program never runs, and there is **no log to say why — because
the log is what could not be created.** Measured on the first real start,
11 October 2026, and it cost a diagnosis that read `last exit code = 78` against
a binary that ran perfectly under `sudo -u`.

## Installing twice, and uninstalling

**`install` refuses to run twice** and points at `uninstall`. Repairing would
mean deciding whether to re-bootstrap, re-chown and rewrite plists it may not
have written, against identities it may not have created — and
`/var/db/smbpal/created` is the only record of which. Remove and install is two
commands that each do one knowable thing.

`uninstall` removes **what the install recorded and nothing else**, in the order
the account spike's §4 established: owned files before the account, the account
before the group, because an ACE outlives the account it names and orphans to a
raw UUID. `/etc/smbpal` and its contents are left alone and it says so.

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
