"""Adding a share and adding a connection.

**Neither form validates what the daemon validates.** The rules live in
`smbpal.config.schema`, the name collision check lives in the dispatcher, and
copying either into a widget would create a second place that can disagree with
the first — and the copy is the one that goes stale. So a form enables Save when
its required fields are filled in, and everything else is the daemon's answer,
shown *in the form* rather than dismissing it. That is what `Session.submit`'s
`catch` is for.

**The mountpoint field is empty on purpose** (3h). Omitting it entirely is not
laziness: only the daemon can see `/media/<user>`, what is already mounted
there, and which name is free — and a path SMBPal chooses is a path the file
manager will show, which is the whole finding. The field is behind "Where to
put it" for the case where somebody genuinely wants to say.
"""

from __future__ import annotations

from typing import Any, Callable

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gio, Gtk  # noqa: E402

from smbpal.errors import SmbpalError  # noqa: E402
from smbpal.gui.session import Session  # noqa: E402

AUTO_CONNECT = (
    ("on_this_network", "When this network is available"),
    ("always", "Always"),
    ("never", "Only when I ask"),
)


class _Form(Gtk.Window):
    """The shared shape: a heading, fields, an inline error, Cancel and Add."""

    def __init__(
        self, parent: Gtk.Window, session: Session, title: str, verb: str
    ) -> None:
        super().__init__(transient_for=parent, modal=True, title=title)
        self.set_default_size(460, -1)
        self.session = session
        self._done: Callable[[], None] = lambda: None

        self.fields = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)

        self._error = Gtk.Label(label="", xalign=0, wrap=True, visible=False)
        self._error.add_css_class("banner")
        self._error.add_css_class("banner-problem")

        self._go = Gtk.Button(label=verb)
        self._go.add_css_class("suggested-action")
        self._go.set_sensitive(False)
        self._go.connect("clicked", lambda _b: self._submit())
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda _b: self.close())

        buttons = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.END
        )
        buttons.append(cancel)
        buttons.append(self._go)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        body.set_margin_top(20)
        body.set_margin_bottom(20)
        body.set_margin_start(20)
        body.set_margin_end(20)
        body.append(self.fields)
        body.append(self._error)
        body.append(buttons)
        self.set_child(body)

    def on_added(self, callback: Callable[[], None]) -> None:
        self._done = callback

    # --- subclasses fill these in -----------------------------------------

    def _ready(self) -> bool:
        raise NotImplementedError

    def _submit(self) -> None:
        raise NotImplementedError

    # --- shared plumbing ---------------------------------------------------

    def recheck(self, *_args: object) -> None:
        self._go.set_sensitive(self._ready())

    def working(self, busy: bool) -> None:
        self._go.set_sensitive(not busy and self._ready())

    def failed(self, exc: SmbpalError) -> None:
        # In the form, not in the window behind it, and the form stays open:
        # what somebody typed is still there to correct.
        text = exc.message if not exc.detail else f"{exc.message}\n\n{exc.detail}"
        self._error.set_text(text)
        self._error.set_visible(True)
        self.working(False)

    def succeeded(self, _result: Any) -> None:
        self.close()
        self._done()

    def labelled(self, text: str, widget: Gtk.Widget, hint: str = "") -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        caption = Gtk.Label(label=text, xalign=0)
        box.append(caption)
        box.append(widget)
        if hint:
            note = Gtk.Label(label=hint, xalign=0, wrap=True)
            note.add_css_class("row-detail")
            box.append(note)
        self.fields.append(box)


class AddShareDialog(_Form):
    """Share a folder on this computer."""

    def __init__(self, parent: Gtk.Window, session: Session) -> None:
        super().__init__(parent, session, "Share a folder", "Share")

        self._path = Gtk.Entry(placeholder_text="/srv/media", hexpand=True)
        chooser = Gtk.Button(label="Choose…")
        chooser.connect("clicked", lambda _b: self._pick_folder())
        picker = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        picker.append(self._path)
        picker.append(chooser)
        self.labelled("Folder", picker)

        self._name = Gtk.Entry(placeholder_text="Media")
        self.labelled(
            "Name people will see", self._name, "Filled in from the folder name."
        )

        self._user = Gtk.Entry(placeholder_text="pi")
        self.labelled(
            "Serve it as",
            self._user,
            "An account that already exists on this computer (§3b). Without "
            "one, the share is open to anyone on the network and SMBPal cannot "
            "tell whether the folder is writable.",
        )

        self._read_only = Gtk.CheckButton(label="Share it read-only")
        self.fields.append(self._read_only)

        self._path.connect("changed", self._path_changed)
        self._name.connect("changed", self.recheck)

    def _path_changed(self, _entry: Gtk.Widget) -> None:
        text = self._path.get_text().rstrip("/")
        if text and not self._name.get_text():
            self._name.set_text(text.rsplit("/", 1)[-1])
        self.recheck()

    def _ready(self) -> bool:
        return bool(self._path.get_text().strip() and self._name.get_text().strip())

    def _pick_folder(self) -> None:
        """The native folder picker.

        `Gtk.FileChooserNative` rather than `Gtk.FileDialog`, which arrived in
        GTK 4.10 and does not exist on Pi OS's 4.8. Native is what routes the
        request through xdg-desktop-portal where one is running, and falls back
        to GTK's own dialog where one is not.
        """
        chooser = Gtk.FileChooserNative.new(
            "Choose a folder to share",
            self,
            Gtk.FileChooserAction.SELECT_FOLDER,
            "Choose",
            "Cancel",
        )

        def chosen(dialog: Gtk.FileChooserNative, response: int) -> None:
            if response == Gtk.ResponseType.ACCEPT:
                folder = dialog.get_file()
                if folder is not None and folder.get_path():
                    self._path.set_text(folder.get_path())
            dialog.destroy()

        chooser.connect("response", chosen)
        self._chooser = chooser  # keep it alive until it answers
        chooser.show()

    def _submit(self) -> None:
        self.working(True)
        params: dict[str, Any] = {
            "name": self._name.get_text().strip(),
            "path": self._path.get_text().strip(),
            "read_only": self._read_only.get_active(),
        }
        user = self._user.get_text().strip()
        if user:
            params["credential_ref"] = user
        self.session.submit(
            "share.add", params, then=self.succeeded, catch=self.failed
        )


class AddConnectionDialog(_Form):
    """Connect to a share on another computer, with §3e's browse alongside."""

    def __init__(self, parent: Gtk.Window, session: Session) -> None:
        super().__init__(parent, session, "Connect to a share", "Connect")
        self.set_default_size(520, -1)

        self._host = Gtk.Entry(placeholder_text="rivendell.local")
        find = Gtk.Button(label="Find servers")
        find.connect("clicked", lambda _b: self._browse())
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._host.set_hexpand(True)
        row.append(self._host)
        row.append(find)
        self.labelled("Server", row)

        self._found = Gtk.ListBox()
        self._found.set_selection_mode(Gtk.SelectionMode.NONE)
        self._found_frame = Gtk.Frame(visible=False)
        self._found_frame.set_child(self._found)
        self.fields.append(self._found_frame)

        self._share = Gtk.Entry(placeholder_text="Media")
        self.labelled(
            "Share name on that server",
            self._share,
            "The name as it appears on the server, not a path.",
        )

        self._user = Gtk.Entry(placeholder_text="Leave empty to connect as a guest")
        self._password = Gtk.PasswordEntry(show_peek_icon=True)
        credentials = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        credentials.append(self._user)
        credentials.append(self._password)
        self.labelled("Sign in as", credentials)

        self._auto = Gtk.DropDown.new_from_strings(
            [label for _value, label in AUTO_CONNECT]
        )
        self.labelled("Connect", self._auto)

        self._mountpoint = Gtk.Entry(
            placeholder_text="SMBPal chooses somewhere the file manager shows it"
        )
        advanced = Gtk.Expander(label="Where to put it")
        advanced.set_child(self._mountpoint)
        self.fields.append(advanced)

        self._host.connect("changed", self.recheck)
        self._share.connect("changed", self.recheck)

    def _ready(self) -> bool:
        return bool(self._host.get_text().strip() and self._share.get_text().strip())

    # --- §3e ---------------------------------------------------------------

    def _browse(self) -> None:
        self._show_found([Gtk.Label(label="Looking…", xalign=0)])
        self.session.submit(
            "browse",
            {"timeout": 5.0},
            then=self._found_machines,
            catch=self._browse_failed,
        )

    def _browse_failed(self, exc: SmbpalError) -> None:
        # Clear the pane first. Leaving "Looking…" under an error message says
        # the search is still running when it has stopped, which is the same
        # class of untruth as a summary that describes less than it did.
        self._found_frame.set_visible(False)
        self.failed(exc)

    def _found_machines(self, machines: list[dict[str, Any]]) -> None:
        if not machines:
            # Not "no servers exist". mDNS only finds what advertises itself,
            # and a Windows box or a NAS with mDNS off is invisible to it while
            # being perfectly reachable by name.
            self._show_found(
                [
                    Gtk.Label(
                        label="Nothing advertised itself. A server that does "
                        "not use mDNS still works — type its name above.",
                        xalign=0,
                        wrap=True,
                    )
                ]
            )
            return
        self._show_found([self._machine_row(m) for m in machines])

    def _machine_row(self, machine: dict[str, Any]) -> Gtk.Widget:
        name = machine.get("hostname") or machine.get("name") or "?"
        addresses = ", ".join(machine.get("addresses") or []) or "no address"
        button = Gtk.Button()
        button.add_css_class("flat")
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        title = Gtk.Label(label=machine.get("name") or name, xalign=0)
        title.add_css_class("row-title")
        text.append(title)
        detail = Gtk.Label(label=f"{name} — {addresses}", xalign=0)
        detail.add_css_class("row-detail")
        text.append(detail)
        if machine.get("running_smbpal"):
            badge = Gtk.Label(label="running SMBPal", xalign=0)
            badge.add_css_class("row-hint")
            text.append(badge)
        button.set_child(text)
        button.connect("clicked", lambda _b: self._host.set_text(name))
        return button

    def _show_found(self, widgets: list[Gtk.Widget]) -> None:
        while (child := self._found.get_first_child()) is not None:
            self._found.remove(child)
        for widget in widgets:
            widget.set_margin_top(6)
            widget.set_margin_bottom(6)
            widget.set_margin_start(10)
            widget.set_margin_end(10)
            self._found.append(widget)
        self._found_frame.set_visible(True)

    # --- adding ------------------------------------------------------------

    def _submit(self) -> None:
        self.working(True)
        params: dict[str, Any] = {
            "host": self._host.get_text().strip(),
            "share": self._share.get_text().strip(),
            "auto_connect": AUTO_CONNECT[self._auto.get_selected()][0],
        }
        mountpoint = self._mountpoint.get_text().strip()
        if mountpoint:
            # Only when somebody typed one. Sending "" would be SMBPal being
            # told where to put it by an empty box.
            params["mountpoint"] = mountpoint
        self.session.submit(
            "connection.add", params, then=self._added, catch=self.failed
        )

    def _added(self, connection: dict[str, Any]) -> None:
        username = self._user.get_text().strip()
        password = self._password.get_text()
        if not username or not password:
            self.succeeded(connection)
            return
        # Two calls, the same as the CLI's: the connection exists first, then
        # it is given credentials. A failure here leaves a connection that
        # mounts as a guest, which is recoverable from the row.
        self.session.submit(
            "connection.set_credentials",
            {"ref": connection["id"], "username": username, "password": password},
            then=self.succeeded,
            catch=self.failed,
        )


def add_menu(
    window: Gtk.Window, session: Session, refresh: Callable[[], None]
) -> Gtk.Widget:
    """The header bar's Add button: one menu, two forms."""
    menu = Gio.Menu()
    menu.append("Share a folder…", "win.add-share")
    menu.append("Connect to a share…", "win.add-connection")

    def opener(dialog_class: type[_Form]) -> Callable[..., None]:
        def open_it(*_args: object) -> None:
            dialog = dialog_class(window, session)
            dialog.on_added(refresh)
            dialog.present()

        return open_it

    for name, dialog_class in (
        ("add-share", AddShareDialog),
        ("add-connection", AddConnectionDialog),
    ):
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", opener(dialog_class))
        window.add_action(action)

    button = Gtk.MenuButton(label="Add")
    button.set_menu_model(menu)
    return button
