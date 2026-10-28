# tailscale-symbian

This is a small Tailscale client written in plain C99, so it can run on legacy systems that the official
client will never support. It joins your tailnet through a [Headscale](https://headscale.net) server (tailscale.com
support may come later), and lets the apps on the device reach your other machines through a SOCKS5 proxy on
`127.0.0.1:1055`.

It's an early prototype. It works, but the protocol code hasn't been independently reviewed, so please read the
security notes before relying on it.

## Trying it on Linux

You'll need a Headscale server and a pre-auth key from it.

```sh
make
./phetaild headscale.example.org 443 <preauth-key> node.state 1055 --tls-pin <sha256-of-the-server-certificate>
curl --socks5-hostname 127.0.0.1:1055 http://some-peer:8080/
```

That joins the tailnet and fetches a page from one of your machines through it. Peers can be reached by IPv4 address or
by name, like `some-peer` or `some-peer.<your domain>`.

`--tls-pin` needs a build with mbedTLS (`-DPHETAIL_TLS`, with the mbedTLS source in `../dav-sync/.deps/mbedtls`).
Without it the control connection is plain HTTP, which is only good for a test server on your own machine.

If you don't have Headscale handy, `spike/run.sh` starts one in Docker together with a peer, so you can try the whole
path. `spike/s2_test.sh` checks that it reconnects when the server goes away.

## On a phone

`group/phetaild.mmp` builds `phetaild.exe` for Symbian, using Open C's BSD sockets. It logs to
`C:\data\phetail\phetaild.log`, and it uses the access point named in `C:\data\phetail\iap.txt`. Many launchers have a
short limit on command lines, so you can also put the arguments in a file and pass `--args <file>`. `socksget` is a
small test program that fetches a page through the proxy.

## What works

- Logging in to the control server, registering with a pre-auth key, and following network map updates.
- WireGuard tunnels to your peers, relayed through DERP, including rekeying and keepalives. `tailscale ping` from
  another machine shows the connection via DERP.
- A full TCP/IP stack on the tunnel ([lwIP](https://savannah.nongnu.org/projects/lwip/)), which answers pings too.
- TLS 1.2 and 1.3 to the control and DERP servers, with the server certificate pinned.
- Reconnecting by itself when the connection drops, with backoff from 1 to 30 seconds. Open SOCKS connections survive
  the reconnect.

Direct UDP connections between peers aren't done yet, so all traffic goes through DERP. IPv6, full DNS and the
official tailscale.com control server are also still to come.

## Porting it

The client runs in one thread around one loop. Each pass waits up to 100 ms for any connection to have data, handles
whatever arrived, and then runs the timers. All the operating system calls go through `src/plat.h`, so that's the one
file you write for a new platform. `src/plat_posix.c` is the Linux version and `src/plat_symbian.cpp` the Symbian one.

The rest is laid out by protocol: `ctrl` talks to the control server, `derp` to the relays, and `wg` does WireGuard.
`disco` handles peer pings, `tunnel` connects lwIP to the tunnel, and `socks` is the proxy. Third-party code is in
`vendor/`, and none of it is GPL.

## Security

- The protocol code was written from the public descriptions and tested against Headscale and the official client,
  but nobody has audited it yet. Don't use it for anything that needs strong guarantees.
- The node's keys live in the state file, so protect it like a private key. Keep the pre-auth key short-lived.
- The server certificate is pinned by its SHA-256. There's no certificate chain check and no way to turn checking off.
- The proxy only listens on 127.0.0.1, but any program on the same device can use it.
- Please report vulnerabilities privately, as described in `SECURITY.md`.

## License

Apache-2.0. The third-party code keeps its own licenses, listed in `NOTICE` and `vendor/README.md`.
