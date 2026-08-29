"""The window. Layout and plumbing, and no decisions.

Everything this module draws was decided in `smbpal.gui.model`: the wording, the
tone, which buttons a row offers, what a destructive action asks first, and
which daemon method each button calls. What is left here is genuinely GTK's
business — boxes, labels, CSS, and turning a click into a `Session.submit`.

**Plain GTK4, no libadwaita.** Nothing in these three sections needs a widget
GTK does not have, and libadwaita would be another Debian dependency (D11)
against D10's size budget, on a desktop — Pi OS's — that is not GNOME. The
cost of that choice is the row layout below, which is about forty lines.

**Rebuilt, not patched.** A pushed event replaces the row list and the section
is built again from scratch. At the scale this app works at — a household's
shares, a handful of connections — diffing widgets would be more code, more
state, and more ways to show something that is no longer true.
"""

from __future__ import annotations

from typing import Any, Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")

from gi.repository import Gdk, Gtk  # noqa: E402

from smbpal.errors import SmbpalError  # noqa: E402
from smbpal.gui import model  # noqa: E402
from smbpal.gui.dialogs import add_menu  # noqa: E402
from smbpal.gui.session import Session  # noqa: E402

CSS = b"""
.dot {
  min-width: 10px;
  min-height: 10px;
  border-radius: 5px;
  background: #9a9a9a;
}
.tone-ok       { background: #2ec27e; }
.tone-busy     { background: #3584e4; }
.tone-idle     { background: #7d8ba0; }
.tone-attention{ background: #e5a50a; }
.tone-problem  { background: #e01b24; }
.tone-muted    { background: #9a9a9a; }

.row-title    { font-weight: bold; }
.row-detail   { opacity: 0.65; font-size: 90%; }
.row-hint     { opacity: 0.8; font-size: 90%; font-style: italic; }
.section-head { font-weight: bold; opacity: 0.7; margin: 12px 4px 4px 4px; }
.banner       { padding: 8px 12px; border-radius: 6px; }
.banner-problem { background: #e01b24; color: #ffffff; }
.banner-note    { background: #3584e4; color: #ffffff; }
.empty        { opacity: 0.6; margin: 16px; }
"""


def install_css() -> None:
    """Once per display. Called by the application, not by each window."""
    display = Gdk.Display.get_default()
    if display is None:  # pragma: no cover - no display, nothing to style
        return
    provider = Gtk.CssProvider()
    try:
        provider.load_from_data(CSS)
    except TypeError:
        # GTK 4.12 replaced the bytes-taking form, so both have to work rather
        # than one being chosen at packaging time. See `confirm` for which
        # GTK this floor is actually set by — it is not the Pi.
        provider.load_from_string(CSS.decode("utf-8"))
    Gtk.StyleContext.add_provider_for_display(
        display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )


class Window(Gtk.ApplicationWindow):
    """One window, one `Session`, three lists."""

    def __init__(self, application: Gtk.Application, session: Session) -> None:
        super().__init__(application=application, title="SMBPal")
        self.set_default_size(720, 560)
        self.session = session
        self._screen = model.Screen()

        self._subtitle = Gtk.Label(label="", xalign=0.5)
        self._subtitle.add_css_class("row-detail")
        self.set_titlebar(self._header())

        self._banner = Gtk.Label(label="", xalign=0, wrap=True, visible=False)
        self._banner.add_css_class("banner")

        self._body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._body.set_margin_start(12)
        self._body.set_margin_end(12)
        self._body.set_margin_bottom(12)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(self._body)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.set_margin_top(8)
        outer.set_margin_start(12)
        outer.set_margin_end(12)
        outer.append(self._banner)
        outer.append(scroller)
        self.set_child(outer)

        # Row ids with a call in flight. Kept here rather than on the buttons
        # because `_rebuild` destroys every widget it has ever made: an
        # unrelated `state.changed` arriving mid-call would otherwise hand
        # back a live Remove for something already being removed.
        self._in_flight: set[str] = set()
        self._row_buttons: dict[str, list[Gtk.Button]] = {}

        session.on_screen = self._show
        session.on_event = self._on_event
        session.on_error = self._on_error
        session.on_daemon_lost = self._on_daemon_lost
        session.on_daemon_back = self._on_daemon_back

    # --- chrome ------------------------------------------------------------

    def _header(self) -> Gtk.HeaderBar:
        header = Gtk.HeaderBar()
        title = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        name = Gtk.Label(label="SMBPal")
        name.add_css_class("row-title")
        title.append(name)
        title.append(self._subtitle)
        header.set_title_widget(title)

        refresh = Gtk.Button(label="Refresh")
        refresh.set_tooltip_text(
            "Connection states arrive on their own. This re-reads the shares."
        )
        refresh.connect("clicked", lambda _b: self.session.refresh())
        header.pack_end(refresh)
        header.pack_start(add_menu(self, self.session, self.session.refresh))
        return header

    # --- session callbacks, all on the main thread -------------------------

    def _show(self, screen: model.Screen) -> None:
        self._screen = screen
        self._subtitle.set_text(screen.daemon)
        self._rebuild()

    def _on_event(self, data: dict[str, Any]) -> None:
        self._screen = model.Screen(
            shares=self._screen.shares,
            connections=model.apply_event(self._screen.connections, data),
            unaccounted=self._screen.unaccounted,
            daemon=self._screen.daemon,
        )
        self._rebuild()

    def _on_error(self, exc: SmbpalError) -> None:
        self._say(exc.message if not exc.detail else f"{exc.message} — {exc.detail}")

    def _on_daemon_lost(self, exc: SmbpalError) -> None:
        self._say(f"{exc.message}. Reconnecting…")

    def _on_daemon_back(self) -> None:
        self._clear_banner()
        self.session.refresh()

    def _say(self, message: str, *, problem: bool = True) -> None:
        self._banner.set_text(message)
        self._banner.remove_css_class("banner-note")
        self._banner.remove_css_class("banner-problem")
        self._banner.add_css_class("banner-problem" if problem else "banner-note")
        self._banner.set_visible(True)

    def _clear_banner(self) -> None:
        self._banner.set_visible(False)

    # --- building ----------------------------------------------------------

    def _rebuild(self) -> None:
        while (child := self._body.get_first_child()) is not None:
            self._body.remove(child)
        self._row_buttons = {}
        self._section(
            "Shared from this computer",
            self._screen.shares,
            "Nothing is shared yet.",
        )
        self._section(
            "Connected to",
            self._screen.connections,
            "No connections yet.",
        )
        if self._screen.unaccounted:
            # Only when there is something to say. A permanently empty section
            # headed "not managed by SMBPal" would teach people to skip it, and
            # the one time it matters is the one time it is not empty.
            self._section("Not managed by SMBPal", self._screen.unaccounted, "")

    def _section(self, heading: str, rows: list[model.Row], empty: str) -> None:
        label = Gtk.Label(label=heading, xalign=0)
        label.add_css_class("section-head")
        self._body.append(label)

        if not rows:
            placeholder = Gtk.Label(label=empty, xalign=0, wrap=True)
            placeholder.add_css_class("empty")
            self._body.append(placeholder)
            return

        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        for row in rows:
            listbox.append(self._row(row))
        frame = Gtk.Frame()
        frame.set_child(listbox)
        self._body.append(frame)

    def _row(self, row: model.Row) -> Gtk.ListBoxRow:
        line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        line.set_margin_top(10)
        line.set_margin_bottom(10)
        line.set_margin_start(12)
        line.set_margin_end(12)

        dot = Gtk.Box(valign=Gtk.Align.START)
        dot.set_margin_top(6)
        dot.add_css_class("dot")
        dot.add_css_class(f"tone-{row.tone}")
        dot.set_tooltip_text(row.state)
        line.append(dot)

        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        title = Gtk.Label(label=row.title, xalign=0)
        title.add_css_class("row-title")
        text.append(title)
        if row.subtitle:
            path = Gtk.Label(label=row.subtitle, xalign=0, wrap=True)
            path.add_css_class("row-detail")
            text.append(path)
        message = Gtk.Label(label=row.message, xalign=0, wrap=True)
        message.add_css_class("row-detail")
        text.append(message)
        if row.hint:
            hint = Gtk.Label(label=row.hint, xalign=0, wrap=True)
            hint.add_css_class("row-hint")
            text.append(hint)
        line.append(text)

        if row.actions:
            buttons = Gtk.Box(
                orientation=Gtk.Orientation.HORIZONTAL,
                spacing=6,
                valign=Gtk.Align.START,
            )
            for action in row.actions:
                buttons.append(self._button(row, action))
            line.append(buttons)

        holder = Gtk.ListBoxRow()
        holder.set_activatable(False)
        holder.set_child(line)
        return holder

    def _button(self, row: model.Row, action: str) -> Gtk.Button:
        button = Gtk.Button(label=model.ACTION_LABELS[action])
        if action == model.REMOVE:
            button.add_css_class("destructive-action")
        button.connect("clicked", lambda _b: self._invoke(row, action))
        button.set_sensitive(row.id not in self._in_flight)
        self._row_buttons.setdefault(row.id, []).append(button)
        return button

    # --- doing it ----------------------------------------------------------

    def _invoke(self, row: model.Row, action: str) -> None:
        if action == model.SET_CREDENTIALS:
            self._ask_for_credentials(row)
            return
        question = model.confirmation(row, action)
        if question is None:
            self._send(row, action)
            return
        confirm(self, question, model.ACTION_LABELS[action],
                lambda: self._send(row, action))

    def _send(
        self,
        row: model.Row,
        action: str,
        params: dict[str, Any] | None = None,
    ) -> None:
        if row.id in self._in_flight:
            # Belt as well as braces. The dead button is what a person meets,
            # but sensitivity is a property of a widget `_rebuild` is free to
            # replace, and a synthetic click ignores it outright. The rule is
            # one call per row at a time, so state it where it cannot be
            # redrawn away.
            return
        self._clear_banner()
        self._hold(row.id)
        self.session.submit(
            model.method_for(row, action),
            {"ref": row.id, **(params or {})},
            then=self._release(row.id, self._done),
            catch=self._release(row.id, self._failed),
        )

    def _hold(self, ref: str) -> None:
        """Nothing else happens to this row until the daemon has answered.

        A removal is a round trip, and the row stays on screen for all of it
        because the window only changes when `refresh` comes back. A second
        click sends a second call with a `ref` the daemon has already acted
        on, so the error arrives *after* the removal worked and reads as it
        having failed.
        """
        self._in_flight.add(ref)
        for button in self._row_buttons.get(ref, ()):
            button.set_sensitive(False)

    def _release(
        self, ref: str, then: Callable[[Any], None]
    ) -> Callable[[Any], None]:
        def done(result: Any) -> None:
            self._in_flight.discard(ref)
            then(result)

        return done

    def _failed(self, exc: SmbpalError) -> None:
        # The row is still there and its buttons are still dead, because only
        # a rebuild re-reads `_in_flight` and an error does not refresh.
        self._on_error(exc)
        self._rebuild()

    def _done(self, result: Any) -> None:
        # `share.make_writable` returns a note about clients that were already
        # connected. Anything else the daemon wants said arrives the same way.
        if isinstance(result, dict) and result.get("note"):
            self._say(result["note"], problem=False)
        self.session.refresh()

    def _ask_for_credentials(self, row: model.Row) -> None:
        def save(username: str, password: str) -> None:
            self._send(
                row,
                model.SET_CREDENTIALS,
                {"username": username, "password": password},
            )

        CredentialsDialog(self, row.title, save).present()


def confirm(
    parent: Gtk.Window, question: str, verb: str, then: Callable[[], None]
) -> None:
    """Ask before something that cannot be undone by pressing the button again.

    A plain window rather than `Gtk.MessageDialog` or its 4.10 replacement
    `Gtk.AlertDialog`, because **the oldest GTK we intend to run on is not the
    Pi's**. Pi OS is on trixie and GTK 4.18.6 (confirmed 27 August 2026), which
    is comfortably above the floor; Debian bookworm is 4.8 and Ubuntu 22.04 is
    4.6, and §1 says Phase 1 is Linux and the Pi rather than the Pi alone. A
    plain window needs neither and works on all of them.

    Worth stating because the tempting deletion is easy to justify wrongly:
    somebody checks the Pi, finds 4.18, and removes compatibility the Pi was
    never the reason for.
    """
    dialog = Gtk.Window(transient_for=parent, modal=True, title=verb.rstrip("…"))
    dialog.set_default_size(420, -1)

    body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
    body.set_margin_top(20)
    body.set_margin_bottom(20)
    body.set_margin_start(20)
    body.set_margin_end(20)
    body.append(Gtk.Label(label=question, xalign=0, wrap=True))

    buttons = Gtk.Box(
        orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.END
    )
    cancel = Gtk.Button(label="Cancel")
    cancel.connect("clicked", lambda _b: dialog.close())
    go = Gtk.Button(label=verb.rstrip("…"))
    go.add_css_class("destructive-action")

    def accept(_button: Gtk.Button) -> None:
        dialog.close()
        then()

    go.connect("clicked", accept)
    buttons.append(cancel)
    buttons.append(go)
    body.append(buttons)
    dialog.set_child(body)
    dialog.present()


class CredentialsDialog(Gtk.Window):
    """Username and password for one connection.

    The password goes to the daemon in a request parameter and no further: the
    daemon writes it to a 0600 file and hands cifs the *path*. It is never put
    in an argv, which is the rule M0 §9 arrived at the hard way.
    """

    def __init__(
        self, parent: Gtk.Window, title: str, save: Callable[[str, str], None]
    ) -> None:
        super().__init__(transient_for=parent, modal=True, title="Sign in")
        self.set_default_size(400, -1)
        self._save = save

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        body.set_margin_top(20)
        body.set_margin_bottom(20)
        body.set_margin_start(20)
        body.set_margin_end(20)
        body.append(Gtk.Label(label=f"Credentials for {title}", xalign=0))

        self._username = Gtk.Entry(placeholder_text="Username on the server")
        self._password = Gtk.PasswordEntry(show_peek_icon=True)
        body.append(self._username)
        body.append(self._password)

        buttons = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=8, halign=Gtk.Align.END
        )
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda _b: self.close())
        self._go = Gtk.Button(label="Save")
        self._go.add_css_class("suggested-action")
        self._go.set_sensitive(False)
        self._go.connect("clicked", self._accept)
        buttons.append(cancel)
        buttons.append(self._go)
        body.append(buttons)
        self.set_child(body)

        self._username.connect("changed", self._recheck)
        self._password.connect("changed", self._recheck)
        self._password.connect("activate", self._accept)

    def _recheck(self, _entry: Gtk.Widget) -> None:
        self._go.set_sensitive(
            bool(self._username.get_text()) and bool(self._password.get_text())
        )

    def _accept(self, _widget: Gtk.Widget) -> None:
        username = self._username.get_text()
        password = self._password.get_text()
        if not username or not password:
            return
        self.close()
        self._save(username, password)
