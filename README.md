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
  daemon/       smbpald: method dispatch and the entry point
packaging/debian/
tests/
```

`samba/`, `mounts/`, `state/`, `cli/` and `gui/` arrive with M3–M6.

## Running it

No dependencies beyond the standard library, and the test suite uses `unittest`
so it runs anywhere Python does:

```sh
python3 -m unittest discover -s tests -t . -q

# a daemon you can talk to, no root and no smbpal group needed
python3 -m smbpal.daemon.main --socket /tmp/d.sock --config /tmp/c.json --socket-group ''

# validate a config and exit
python3 -m smbpal.daemon.main --check --config /etc/smbpal/config.json
```

In production it is a root system service on `/run/smbpal/smbpald.sock`, mode
0660, group `smbpal`. Root is not a preference: `passdb.tdb` is `0600 root:root`
(M0 §2), so nothing short of root can touch Samba's credential store.

## Status: M1 done

Schema, validation, atomic writes, the socket, and a daemon that starts, loads,
holds the socket and does nothing else. Three methods — `ping`, `version`,
`config.get`.

**One deviation from the plan's D7 example**, flagged rather than made quietly:
its share record carries `auto_connect`, which reads as a copy-paste from the
connection record next to it — a share is served, it does not connect to
anything. Shares here take `enabled` instead. See `phase-1-plan.md` §2 D7.

