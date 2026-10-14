# hopsock

Chromium browsers (Chrome, Vivaldi, Brave, Edge) don't support username and
password auth for SOCKS5 proxies, and they leak DNS and WebRTC traffic around
a proxy unless you pass the right flags. hopsock runs a local, auth-free SOCKS5
proxy that forwards everything through your real upstream: an authenticated
SOCKS5 or HTTP proxy, an SSH server, or a chain of them. It can then open your
browser through it with leaks blocked.

![hopsock dashboard](docs/demo.gif)

```sh
export PROXY_PASS='...'
hopsock -F 'socks5://user@proxy.example.com:10001?passenv=PROXY_PASS'
# press b, pick a browser, done
```

- One static binary for Linux, macOS and Windows
- SOCKS5 (with auth), HTTP CONNECT and SSH hops, chained in any order
- Live dashboard: route, exit IP and location, SSH state, connections, traffic
- Browser launch with DNS and WebRTC leak protection, and a refusal to open an
  unproxied window
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
| `-profile`   |                          | Passed to the browser as `--user-data-dir` for a separate instance                     |
| `-exec`      |                          | Run a command once ready. `{addr}` becomes the proxy address, `$HOPSOCK_PROXY` is set  |
| `-stay`      | false                    | Keep running after the `-browser`/`-exec` process exits                                |
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

### Keys

`b` open browser · `t` rerun the test · `tab` switch table/log · `v`
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
