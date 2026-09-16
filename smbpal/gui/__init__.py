"""The GTK4 client. A third consumer of the D4 socket, not a second daemon."""

# Provisional until M7 settles the packaging identity: this string ends up in
# the .desktop file name, the icon name and the tray's bus name, and changing
# it after those exist is three coordinated renames.
#
# Here rather than in `app`, because the tray needs it too and must not import
# `app`: that module loads Gtk, and the tray never does. A running GUI owns
# this name on the session bus, which is how the tray knows one is open.
APP_ID = "org.smbpal.Smbpal"
