# hopsock

Chromium browsers (Chrome, Vivaldi, Brave, Edge) don't support username and
password auth for SOCKS5 proxies, and they leak DNS and WebRTC traffic around
a proxy unless you pass the right flags. hopsock runs a local, auth-free SOCKS5
proxy that forwards everything through your real upstream: an authenticated
SOCKS5 or HTTP proxy, an SSH server, or a chain of them. It can then open your
browser, or the Discord desktop app, through it with leaks blocked.

![hopsock dashboard](docs/demo.gif)

```sh
hopsock -F socks5://proxy.example.com:10001
# type the username and password when asked, press b, pick a browser or Discord
```

- One static binary for Linux, macOS and Windows
- SOCKS5 (with auth), HTTP CONNECT and SSH hops, chained in any order
- Live dashboard: route, exit IP and location, SSH state, connections, traffic
- Browser and Discord launch with DNS and WebRTC leak protection, and a refusal
  to open an unproxied window
- Asks for a proxy's username and password when they aren't given, and again
  when they're wrong
- A small Go library if you want the same thing inside your own program

## Install

Download a binary from [Releases](https://github.com/abdullahwaqar/hopsock/releases), or:

```sh
go install github.com/abdullahwaqar/hopsock/cmd/hopsock@latest
```

## Use

```sh
# SSH dynamic forward, like ssh -D 1080 me@server
hopsock -F ssh://me@server.example.com

# Authenticated upstream SOCKS5, open Vivaldi when the test passes
hopsock -F 'socks5://user@proxy.example.com:10001?passenv=PROXY_PASS' -browser vivaldi-stable

# No credentials given: hopsock asks for them, then opens Discord
hopsock -F socks5://proxy.example.com:10001 -discord

# Chain: reach an SSH box through the proxy, exit from the SSH box
hopsock -F 'socks5://user@proxy:1080?passenv=PROXY_PASS' -F 'ssh://me@box?key=~/.ssh/id_ed25519'

# Anything else
hopsock -F ssh://me@box -exec 'curl -sx socks5h://{addr} https://ipinfo.io'
```

Point other apps at `socks5h://127.0.0.1:1080`. The `h` makes DNS resolve at
the far end of the chain.

### Flags

| Flag         | Default                  |                                                                                        |
| ------------ | ------------------------ | -------------------------------------------------------------------------------------- |
| `-L`         | `127.0.0.1:1080`         | Local listener: a port, `host:port`, or `socks5://user:pass@host:port` to require auth |
| `-F`         | none                     | Upstream hop URL. Repeat for a chain, outermost first. No `-F` means direct            |
| `-test`      | `https://ipinfo.io/json` | Fetched through the chain at startup to show the exit IP. `off` to skip                |
| `-browser`   |                          | Open a Chromium-based browser through the proxy once the test passes                   |
| `-discord`   | false                    | Open the Discord desktop app through the proxy once the test passes                    |
| `-profile`   |                          | Passed to the browser as `--user-data-dir` for a separate instance                     |
| `-exec`      |                          | Run a command once ready. `{addr}` becomes the proxy address, `$HOPSOCK_PROXY` is set  |
| `-stay`      | false                    | Keep running after the `-browser`/`-discord`/`-exec` process exits                     |
| `-prompt`    | true                     | Ask for missing or rejected proxy logins. Needs a terminal. `-prompt=false` to fail    |
| `-plain`     | false                    | No TUI, log to stderr. Automatic when output isn't a terminal                          |
| `-v`         | false                    | Per-connection log lines                                                               |
| `-keepalive` | `30s`                    | SSH keepalive interval, `0` disables                                                   |
| `-version`   |                          | Print version and exit                                                                 |

### Hop URLs

```
socks5://[user[:pass]@]host[:1080]     socks5h:// and socks:// also work
http://[user[:pass]@]host[:8080]       HTTP CONNECT
ssh://[user[:pass]@]host[:22]          SSH direct-tcpip channels
```

| Option               | Hops |                                                                          |
| -------------------- | ---- | ------------------------------------------------------------------------ |
| `passenv=VAR`        | all  | Read the password from `$VAR`: no URL-encoding, nothing in shell history |
| `key=PATH`           | ssh  | Private key file, repeatable                                             |
| `keypassenv=VAR`     | ssh  | Passphrase for encrypted keys                                            |
| `agent=0`            | ssh  | Don't use `$SSH_AUTH_SOCK`                                               |
| `known_hosts=PATH`   | ssh  | Default `~/.ssh/known_hosts`                                             |
| `hostkey=SHA256:...` | ssh  | Pin the server key instead of using known_hosts                          |
| `insecure=1`         | ssh  | Skip host key checking. Testing only                                     |
| `timeout=20s`        | ssh  | Handshake timeout                                                        |

SSH tries key files, ssh-agent and your default keys (`id_ed25519`,
`id_ecdsa`, `id_rsa`) first, then password and keyboard-interactive.

### Logins

You don't have to put credentials in the URL. When a hop needs a login hopsock
doesn't have, it asks:

- SOCKS5 and HTTP hops: when the proxy says it needs auth (SOCKS5 method
  negotiation, HTTP 407), you're asked for a username and password. If the URL
  has a username but no password, only the password is asked for.
- SSH hops: after keys and the agent fail, you're asked for the password (or
  whatever the server's keyboard-interactive prompt asks for).
- A rejected login is asked for again. A login that works is kept in memory
  for the rest of the session, so reconnects don't ask twice. Nothing is
  written to disk.

In the dashboard this is a form (`tab` to switch fields, `enter` to log in,
`esc` to skip). With `-plain` it's a prompt in the terminal with the password
hidden. If you skip, that hop stops asking until you press `t` to retest.
Open proxies never trigger a prompt. Without a terminal (or with
`-prompt=false`) hopsock fails with the auth error as before.

### Browsers

Every launch gets:

- `--proxy-server=socks5://127.0.0.1:1080`
- `--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1`, so DNS can't leak
- `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, so WebRTC can't reveal your real IP

Without `-profile` the browser opens with your normal profile, so it has to be
fully closed first. A running instance would open a new window and silently
ignore the proxy flags. hopsock checks for that and refuses to launch.

A browser started with `-browser` ends the session when you close it, unless
you pass `-stay`. Browsers opened with `b` don't end it.

### Discord

`-discord` (or `b` in the dashboard) finds the Discord desktop app and starts
it with the same flags. Discord is an Electron app, so its chat, API and media
requests go through the proxy like a browser's would. Found automatically:

- Linux: `discord`, `discord-ptb`, `discord-canary` on `$PATH` (deb, Snap, AUR),
  `/opt/discord`, `/usr/share/discord`, and the Flatpak
  (`com.discordapp.Discord`)
- macOS: `Discord.app`, `Discord PTB.app`, `Discord Canary.app` in
  `/Applications` or `~/Applications`
- Windows: the newest `%LocalAppData%\Discord\app-*\Discord.exe` (plus PTB and
  Canary)

Anything else: `-browser /path/to/Discord` works too, since the name gives it
away.

Things to know:

- Discord has to be fully quit first, including the tray icon. A running
  Discord just focuses its window and ignores the proxy flags, so hopsock
  refuses to launch it. `-profile` doesn't apply.
- Voice and video calls use UDP through Discord's own voice engine, which
  can't go through a SOCKS5 proxy. They connect directly and Discord's voice
  servers see your real IP.
- If Discord updates itself and restarts, the new instance starts without the
  proxy flags. Quit it and open it again from hopsock.

### Keys

`b` open a browser or Discord · `t` rerun the test (and re-ask skipped logins) · `tab` switch table/log · `v`
per-connection log · `f` follow log · `c` clear log · `q` quit

## Library

```go
chain, err := hopsock.NewChain([]string{
	"socks5://user@proxy.example.com:10001?passenv=PROXY_PASS",
	"ssh://me@box.example.com?key=~/.ssh/id_ed25519",
}, nil)
if err != nil {
	return err
}
defer chain.Close()

// Use the chain as a dialer...
client := &http.Client{Transport: &http.Transport{DialContext: chain.DialContext}}

// ...or serve it as a local SOCKS5 proxy.
srv := &hopsock.Server{Addr: "127.0.0.1:1080", Dialer: chain}
err = srv.ListenAndServe(ctx)
```

To ask for missing or rejected credentials, pass a `Credentials` callback:

```go
chain, err := hopsock.NewChain(hops, &hopsock.ChainOptions{
	Credentials: func(ctx context.Context, req hopsock.CredRequest) (user, pass string, err error) {
		// req.Hop, req.NeedUser, req.Retry, req.Prompt describe what's wanted.
		return askSomehow(req)
	},
})
```

Concurrent dials that hit the same auth error share one call. Return
`hopsock.ErrPromptCanceled` to give up; `chain.ResetPrompts()` allows asking
again. Without a callback, auth failures wrap `hopsock.ErrAuthRequired` or
`hopsock.ErrAuthFailed`.

`SOCKS5Dialer`, `HTTPDialer` and `SSHDialer` each take a `Forward` dialer, so
you can also stack them by hand. `SSHDialer` shares one session across
connections, sends keepalives and reconnects on demand. `Preflight` fetches a
URL through any dialer and parses the exit IP.

The Go API may change before 1.0.

## Not supported

UDP ASSOCIATE and BIND, remote (`-R`) forwarding, an HTTP proxy listener, and
TLS, WebSocket or QUIC transports.

## Development

```sh
make test       # go test -race ./...
make lint       # golangci-lint
make snapshot   # local GoReleaser build of every platform into ./dist
```
