# smbpal-desktop

The desktop application: GUI, daemon and CLI in **one package**, per D4 — shipping them
together is what removes version skew between client and daemon.

**Toolkit: GTK4 + PyGObject**, decided 18 August 2026 by §12.1.3 rule 1. A single toolkit
cleared the hard gates on all three desktops across ~20 runs on Pi 4, Windows 11 and macOS,
with no hard-gate failure found anywhere. Evidence: `smbpal-spikes/gtk4/results/RESULTS.md`.

Three configuration decisions carried from the spike, all load-bearing:

- **`GSK_RENDERER=cairo` on Windows** — GTK4 there cannot use the GPU at all, and asking for a
  GPU renderer still pays ~60 MiB and ~0.4 s for an unused context.
- **Never Vulkan on the Pi** — 4.0 s cold start against 1.1 s on GL.
- **`PYTHONUTF8=1` in the launcher** — reconfiguring `sys.stdout` from inside the app stops the
  cp1252 crash but still mangles accented text, and `PYTHONUTF8` cannot be set from within the
  process it governs.

## Layout

```
smbpal/
  config/       D7 schema, validation, atomic write   — the daemon is the only writer (D12)
  ipc/          transport-agnostic boundary, server and client (D4)
  samba/        the include block, the generated conf, testparm/smbcontrol, smbpasswd
  shares/       §3c directory ownership
  discovery/    §3e browsing, §3f advertising
  system/       running commands, atomic file writes
  cli/          smbpal
  daemon/       smbpald: method dispatch and the entry point
packaging/debian/
tests/
```

`mounts/`, `state/` and `gui/` arrive with M4–M6.

## Running it

No dependencies beyond the standard library, and the test suite uses `unittest`
so it runs anywhere Python does:

```sh
python3 -m unittest discover -s tests -t . -q

# a daemon you can talk to, no root and no smbpal group needed
python3 -m smbpal.daemon.main --socket /tmp/d.sock --config /tmp/c.json --socket-group ''

# validate a config and exit
python3 -m smbpal.daemon.main --check --config /etc/smbpal/config.json

# hold config only, never touching Samba or Avahi — for a machine without Samba
python3 -m smbpal.daemon.main --no-apply --socket /tmp/d.sock --config /tmp/c.json \
        --socket-group ''
```

In production it is a root system service on `/run/smbpal/smbpald.sock`, mode
0660, group `smbpal`. Root is not a preference: `passdb.tdb` is `0600 root:root`
(M0 §2), so nothing short of root can touch Samba's credential store.

## Status: M3 done

**M1** — schema, validation, atomic writes, the socket, and a daemon that starts,
loads, holds the socket and does nothing else.

**M2** — the CLI, and the daemon methods behind it:

```sh
smbpal status
smbpal share list | add <name> <path> --user <account> [--read-only] [--disabled]
                  | remove <ref> | make-writable <ref>
smbpal connection list | add <host> <share> <mountpoint> [--auto ...] | remove <ref>
smbpal credential list | set <account> | remove <account>
smbpal apply
smbpal browse
smbpal ping
```

Every command takes `--json`. Exit codes separate the cases a script cares
about: `0` worked, `1` the daemon refused, `2` the command line was wrong, `3`
no daemon.

**M3** — shares are actually served. `share add` now writes
`/etc/samba/smbpal.conf`, adds a marked include block to `[global]` in
`smb.conf`, reloads Samba with `smbcontrol all reload-config`, **verifies the
share is in the effective configuration**, and reconciles the `_smbpal._tcp`
record. Plus `smbpal apply`, `smbpal share make-writable`, and
`smbpal credential set/list/remove`.

Connections are still **recorded but not mounted** — that is M4, which is why
`status` reports their state as `unknown` rather than guessing.

Three properties worth knowing:

- **Verification is by presence, not by `testparm`'s verdict.** M0 §1a found
  `testparm` reporting OK both when the included file was malformed and when it
  was missing, so its exit status says nothing about our file. A share either
  appears in the effective config or the operation failed.
- **Config and reality cannot disagree.** If applying fails, the config change
  is rolled back and the previous state re-applied. D12: a config edit the
  daemon has not applied is a lie.
- **`smb.conf` comes back byte-identical.** The include is a marked block,
  removed as a block.

### Two deviations from the plan, flagged rather than made quietly

- **D7's share record carried `auto_connect`**, which reads as a copy-paste from
  the connection record next to it — a share is served, it does not connect to
  anything. Shares take `enabled`. The plan is corrected.
- **`smbpal connect` became `smbpal connection add`.** The plan lists `connect`
  in a sentence of examples; making it a noun group symmetrical with `share`
  means one shape to learn instead of two.

### Known interim: authorisation

Mutating methods currently accept any peer that got through the socket's `0660
root:smbpal` guard — so *may talk* and *may act* are the same answer, which is
not what D4 says. polkit is the plan's answer and ships with the policy file at
M7. The seam is `Authoriser.check`, every mutation is audited to
`smbpal.audit`, and the daemon logs the policy in force at startup.

