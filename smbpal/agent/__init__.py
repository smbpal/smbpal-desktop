"""The per-user agent, which exists because macOS mounts belong in a session.

**D13, and it is not a stylistic choice.** Two independent constraints put
macOS mounting outside the privileged daemon, and both were measured rather
than reasoned:

- **Mounting needs no elevation there.** An unprivileged `mount_smbfs` reached
  the network — it failed with a timeout, which is a network answer, where a
  permission problem would have failed sooner. So §10.1's *"needed for OS
  shares and for all mounting"* is a Linux sentence.
- **The login Keychain is unreadable from root**, and D13 puts the credential
  there, because NetFS will not fetch one for us (`phase-2-porting-surface.md`
  §6.6).

So macOS has **two components where Linux has one**: a privileged helper for
sharepoints and accounts, and this, which owns mounting and nothing else.

**What it is not.** Not a second daemon — it holds no configuration, makes no
policy and serves one user. It is the part of the daemon that had to move, and
the split is the platform's rather than ours.

**And it needs no `SMAppService`.** `phase-2-porting-surface.md` §3.3 found
`SMJobBless` deprecated in favour of `SMAppService`, whose registration can end
in *requires approval* — a step the app cannot perform for the user. **That
applies to an agent inside an application bundle, and D11 decided macOS ships
as a Homebrew formula rather than an `.app`.** A plist in
`~/Library/LaunchAgents` bootstrapped with `launchctl` starts immediately and
asks nobody, which is how every other agent on a stock Mac is installed and
what a TCC probe demonstrated on 30 September 2026. §3.3's finding still stands
for the privileged helper, which is a `LaunchDaemon` and deferred with the
`.app`.
"""
