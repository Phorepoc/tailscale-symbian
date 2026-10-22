# phetail

A small, portable C99 client for the Tailscale protocol (Headscale or tailscale.com
control), meant to run on constrained and unusual platforms. Status: **spike**.

## What works (S0 + S1)

- `GET /key`, the `ts2021` upgrade (`POST /ts2021`, `X-Tailscale-Handshake`), Noise
  `IK_25519_ChaChaPoly_BLAKE2s` with the server's machine key, the optional early payload.
- A minimal HTTP/2 (h2c) client inside the Noise transport (literal HPACK, no Huffman,
  flow control by WINDOW_UPDATE).
- `/machine/register` with a pre-auth key, `/machine/map` (streaming; first message printed).
- DERP: HTTP upgrade, ServerKey, NaCl-boxed ClientInfo, ServerInfo, NotePreferred,
  SendPacket/RecvPacket, ping/pong.
- WireGuard initiator (Noise IKpsk2, MAC1, TAI64N), transport data, IPv4 ICMP echo to the
  first peer through DERP.

## Layout

- `src/plat.h`, `src/plat_posix.c` - the platform layer (sockets, time, random). Port this.
- `src/tcrypto.*` - primitives: AEAD, BLAKE2s, HMAC-BLAKE2s HKDF, X25519, box.
- `src/ctrl.*` - control plane: /key, ts2021 Noise, HTTP/2.
- `src/derpwg.*` - DERP client, WireGuard, ICMP (S1).
- `src/main.c` - spike driver: `phetail <host> <port> <authkey> [statefile]`, `PHETAIL_PING=1` runs S1.
- `spike/` - the Headscale config and the Docker recipe used for testing.
- `vendor/` - third-party code, see `vendor/README.md`.

Build: `make` (any C99 compiler with POSIX sockets).

## Not yet

Map stream follow-up (deltas, keepalives), JSON parser, responder-side WireGuard,
disco (so `tailscale ping` without `--icmp` works), rekey/timers, UDP direct paths,
TLS for https control/DERP, zstd map compression.
