# phetail

A small, portable C99 client for the Tailscale protocol (Headscale or, later,
tailscale.com control), meant to run on constrained and unusual platforms.
Status: **spike** (S0-S2).

`phetaild <control-host> <port> <authkey> [statefile] [socks-port]` joins the
tailnet and exposes it as a SOCKS5 proxy on 127.0.0.1:1055 (CONNECT, IPv4 or
peer names such as `phe-peer` / `phe-peer.<domain>`).

## Quick start
You need a Headscale server (or another compatible control server) and a pre-auth key from it. On Linux, to try it:
```
make                                                       # C99 + POSIX sockets; produces ./phetaild
./phetaild headscale.example.org 443 <preauth-key> node.state 1055 --tls-pin <sha256-of-the-server-certificate>
curl --socks5-hostname 127.0.0.1:1055 http://some-peer:8080/   # reach a tailnet peer through the local SOCKS5 proxy
```
`--tls-pin` needs a build with mbedTLS (`-DPHETAIL_TLS`, see "Stage 2"); without it the control connection is plain HTTP, which is only for a local test server.
`spike/run.sh` (Docker, `HOST=<this machine's address>`) starts Headscale and a peer so you can try the whole path; `spike/s2_test.sh` checks reconnection.
For a phone, see "Symbian (Open C)" below.

## What works

- Control: `GET /key`, the `ts2021` upgrade, Noise IK, the early payload, a minimal
  HTTP/2 client (literal HPACK, flow control), register with a pre-auth key, the
  long-lived map stream (jsmn: full maps, `PeersChanged`, keepalives), and a
  "lite" endpoint update that sets our home DERP region.
- DERP: upgrade, ServerKey, boxed ClientInfo, NotePreferred, send/recv, ping/pong.
- WireGuard over DERP: initiator and responder, rekey-after-time, handshake
  retries, passive keepalive, previous-keypair receive.
- Disco: Ping -> Pong over DERP (`tailscale ping` shows "via DERP").
- lwIP 2.2.0 as the userspace IPv4/TCP stack on the tunnel (answers ICMP too).

## Layout

| File | Role |
|---|---|
| `src/plat.h`, `src/plat_posix.c` | Platform layer: the only OS contact. Port this. |
| `src/phetaild.c` | Startup + the single-threaded poll loop and timer tick. |
| `src/ctrl.*` | /key, ts2021 Noise, HTTP/2, map stream framing. |
| `src/netmap.c` | Map JSON -> peer table (jsmn). |
| `src/derp.*` | DERP client. |
| `src/wg.c` | WireGuard handshakes, transport, timers. |
| `src/disco.c` | Disco ping/pong. |
| `src/tunnel.c`, `src/lwipport/` | lwIP netif over WireGuard, lwIP options. |
| `src/socks.*` | SOCKS5 front-end bridging local sockets to lwIP TCP. |
| `src/tcrypto.*` | AEAD, BLAKE2s, HKDF, X25519, NaCl box. |
| `spike/` | Headscale config + Docker recipes (`run.sh`, `s2_test.sh`). |
| `vendor/` | Third-party code, see `vendor/README.md` (no GPL). |

Build: `make` (C99 + POSIX sockets).

## Event-loop model (for the port)

One thread. The only blocking call is `plat_poll` (<= 100 ms); after it the loop
dispatches control / DERP / SOCKS readiness, then a timer tick runs
`sys_check_timeouts` (lwIP) and `wg_timers`. All callbacks run to completion.
This maps onto one active scheduler: each socket = an active object with a
pending read, the tick = a periodic timer active object.

What a port must provide (`plat.h`):

| Function | POSIX | Symbian equivalent |
|---|---|---|
| `plat_tcp_connect` | getaddrinfo + connect (blocking, startup only) | RHostResolver + RSocket::Connect |
| `plat_send_all` / `plat_send_some` | send / MSG_DONTWAIT | RSocket::Write / Send (async) |
| `plat_recv` (timeout 0 = poll) | poll + recv | RSocket::RecvOneOrMore |
| `plat_tcp_listen_local`, `plat_accept` | bind 127.0.0.1 + listen/accept | RSocket::Bind/Listen/Accept on loopback |
| `plat_poll` | poll(2) | the active scheduler itself (no direct analogue) |
| `plat_close` | close | RSocket::Close |
| `plat_random` | /dev/urandom | Math::Random / a CSPRNG seeded from it (needs review) |
| `plat_time` | CLOCK_REALTIME (TAI64N for WireGuard) | TTime::UniversalTime |
| `plat_ms` | CLOCK_MONOTONIC (lwIP `sys_now`, timers) | User::NTickCount / fast counter |

The state file uses stdio (`fopen`), available in Open C.

## Symbian (Open C)

`group/phetaild.mmp` builds `phetaild.exe`, an Open C console exe (`libcrt0` +
`libc`, CAPABILITY NetworkServices LocalServices) with `src/plat_symbian.cpp`:
BSD sockets + `select` for the loop, `TTime`/`NTickCount` for time, and a
BLAKE2s pool over `Math::Random`, the fast counter, the clock and a persisted
seed for randomness. It logs to `C:\data\phetail\phetaild.log` and selects
the access point named in `C:\data\phetail\iap.txt` (default "ASUS") with
`setdefaultif`. Next step: native `RSocket` active objects + a `CPeriodic`
tick instead of `select`.

## Security
- **Spike status:** the protocol code (Noise IK, WireGuard, DISCO, DERP, HTTP/2) is written from the public protocol descriptions and tested against Headscale and the official client; it has not had an
  independent audit. Do not rely on it for anything that needs strong guarantees yet.
- **Keys:** the node keys live in the state file (`node.state`); protect it like a private key (mode 0600, not on a shared card). The pre-auth key is used once and should be short-lived.
- **TLS:** the control and DERP connections use TLS 1.2/1.3 with the server certificate **pinned by SHA-256** (no chain validation and no insecure mode); without `--tls-pin` they are plain HTTP (test servers only).
- **SOCKS:** the proxy listens on 127.0.0.1 only. Anything running on the same device can use it: on a shared device that is a trust decision.
- **Memory safety:** C code with fixed buffers; the third-party code is vendored unmodified (see `NOTICE`). Build with `CFLAGS="-fsanitize=address,undefined"` while testing.
- Report vulnerabilities privately: see `SECURITY.md`.

## Not yet

Disco CallMeMaybe and direct UDP paths, WireGuard replay window and
cookie replies, PeersChangedPatch / PeersRemoved handling, control reconnect,
TLS (https control and DERP), zstd maps, DNS beyond peer names, IPv6.

## Stage 2 (reconnect, TLS, SOCKS on the device)
- **Reconnect.** `phetaild` runs control + DERP as a session; when either connection drops (or the control stream is silent for
  3 minutes) it closes both, waits 1 s, 2 s, 4 s ... 30 s (back to 1 s after a session that ran for 30 s) and registers again.
  WireGuard state of peers that stay in the new map is kept; SOCKS clients stay connected to the local listener.
- **TLS.** `--tls-pin <64 hex>` makes the control (`/key`, ts2021) and DERP connections go over TLS 1.2/1.3 (mbedTLS 3.6, built
  with `-DPHETAIL_TLS`, see `src/net.c`); the server certificate must match the SHA-256 of its DER encoding (no chain
  validation, no insecure mode). Put a TLS terminator (Caddy `reverse_proxy`) in front of Headscale.
- **SOCKS.** The existing SOCKS5 front-end on 127.0.0.1 (default port 1055) is what other applications on the device use;
  `socksget` (`group/socksget.mmp`) is a small test client.
- **Arguments from a file.** `--args <file>` (whitespace separated) for launchers with a short command-line limit.
- mbedTLS sources are expected at `../phedav/.deps/mbedtls` (see the phedav repo's fetch).

## License
Apache-2.0 (see `LICENSE`); vendored third-party code keeps its own licences, listed in `NOTICE` and `vendor/README.md`.
