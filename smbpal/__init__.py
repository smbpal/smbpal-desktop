"""SMBPal — daemon, CLI and GUI as one installable (D4: no version skew)."""

__version__ = "0.1.0"

# The IPC wire version, sent as `v` on every message from the first commit (D4).
# Independent of __version__: the application can move without the protocol moving.
PROTOCOL_VERSION = 1
