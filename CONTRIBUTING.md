# Contributing

Thanks for looking. Issues and pull requests are welcome.

## The CLA, and the one reason it exists

**A pull request cannot be merged until its author has signed the contributor
licence agreement.** This is not boilerplate and it is not about ownership for
its own sake — it buys exactly one thing, and losing it is permanent.

SMBPal is GPL-3.0-or-later. Apple's App Store terms and the GPL are in
long-standing conflict: the App Store adds usage restrictions the GPL forbids
adding, and GPL apps have been removed over it. The way through is
dual-licensing — GPL for this repository, a proprietary grant for an App Store
build, same code, two grants — and dual-licensing is only available to a single
copyright holder. One merged contribution whose copyright sits elsewhere ends
the ability to ship SMBPal on iOS at all, for everyone, forever.

So the CLA asks a contributor to assign or licence their copyright broadly
enough that the dual-licence stays possible. Everything contributed remains
GPL-3.0-or-later here, in this repository, permanently — that part is not
something the CLA can take away.

If you would rather not sign one, an issue describing the bug or the design is
genuinely as useful, and often more so.

## What will not be merged

- **Code you did not write**, or code carrying licence terms of its own. This
  includes anything copied from a GPL project: SMBPal can *use* GPL software as
  a separate process, which is what it does with Samba, but incorporating GPL
  source removes the relicensing ability the CLA exists to protect.
- **A vendored dependency.** D11 is settled for Phase 1: system Python, depend
  don't bundle. The `.deb` has a size budget enforced in CI
  (`packaging/check-installed-size.sh`) and the way a package like this blows
  through it is somebody vendoring a library to make an import work.

## Before you open a pull request

- `python3 -m unittest discover -s tests` passes. CI runs the same suite under
  `xvfb`, plus a full build, install, remove and purge of the package.
- Anything that could carry real data off a real machine stays out of the
  commit rather than being removed in a later one — the history here is
  published in full, so a deleted file is still a published file. Captured
  `smb.conf`, credentials, and hostnames from a live network are the cases that
  have come up. Templates and fixtures with placeholders are fine and are
  meant to be committed.
