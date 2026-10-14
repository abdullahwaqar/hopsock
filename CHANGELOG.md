# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
