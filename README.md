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

Not yet scaffolded. Phase 1 starts here.
