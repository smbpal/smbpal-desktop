"""Test package.

Several tests deliberately provoke errors the daemon logs — a handler raising,
a client flooding the socket. The behaviour is asserted; the log lines would
only make real failures harder to find.
"""

import logging

logging.getLogger("smbpal").setLevel(logging.CRITICAL)
logging.getLogger("smbpal.ipc.server").setLevel(logging.CRITICAL)
logging.getLogger("smbpal.daemon.handlers").setLevel(logging.CRITICAL)
