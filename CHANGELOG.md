# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- SSH config support: ssh hosts are looked up in `~/.ssh/config` (then
  `/etc/ssh/ssh_config`) like ssh does, so `hopsock myalias` or
  `-F ssh://myalias` works wherever `ssh myalias` does. Honors HostName,
  User, Port, IdentityFile, IdentitiesOnly, IdentityAgent, ProxyJump (jump
  hosts appear as hops), ProxyCommand, known hosts files,
  StrictHostKeyChecking, HostKeyAlias and ConnectTimeout, with Host/Match
  blocks, Include and % tokens. `-ssh-config FILE|none` and the
  `ssh_config=` hop option pick another file or turn it off.
- Hosts can be given as plain arguments after the flags.
- Known hosts also checked in `~/.ssh/known_hosts2` and
  `/etc/ssh/ssh_known_hosts`, like ssh.
- Library: `ParseHops`, `ChainOptions.SSHConfig`, `CommandDialer`.
- Discord desktop launch: `-discord`, or pick it with `b` in the dashboard.
  Finds stable, PTB and Canary on Linux (including Flatpak and Snap), macOS
  and Windows, and refuses to launch while Discord is already running.
- Interactive logins: when a SOCKS5, HTTP or SSH hop needs a username or
  password that wasn't given, or rejects the one it got, hopsock asks for it
  (a form in the dashboard, a hidden prompt with `-plain`). `-prompt=false`
  turns this off.
- Library: `ChainOptions.Credentials`, `CredRequest`, `ErrAuthRequired`,
  `ErrAuthFailed`, `ErrPromptCanceled`, `Chain.ResetPrompts`, and `Ask` on
  each dialer.

### Fixed

- The dashboard no longer stalls while an SSH session is connecting.
- The exit line shows "checking" during the first test instead of "pending".

## [1.0.0] - 2026-10-14

### Added

- Local SOCKS5 server (CONNECT) with optional username/password auth.
- Upstream hops: SOCKS5 with RFC 1929 auth, HTTP CONNECT with Basic auth,
  and SSH direct-tcpip (like `ssh -D`), chainable in any order.
- SSH: key files, ssh-agent, password and keyboard-interactive auth;
  known_hosts, pinned fingerprints, or `insecure=1`; one shared session with
  keepalives and automatic reconnect.
- `passenv=VAR` and `keypassenv=VAR` to read secrets from the environment.
- Startup preflight through the chain that reports exit IP, location and ISP.
- Browser launch (`-browser`, or `b` in the TUI) with DNS and WebRTC leak
  protection.
- `-exec` to run any command through the proxy.
- Bubbletea dashboard with route, exit, SSH state, live connections, traffic
  and log. `-plain` mode for scripts.

[Unreleased]: https://github.com/abdullahwaqar/hopsock/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/abdullahwaqar/hopsock/releases/tag/v1.0.0
