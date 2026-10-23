// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// Stream layer between the protocol code (ctrl, DERP) and the platform sockets: plain TCP, or TLS (mbedTLS) with the server
// certificate pinned by the SHA-256 of its DER encoding. The handle is the platform socket handle; local SOCKS sockets
// stay on plat_* directly.
#ifndef PHETAIL_NET_H
#define PHETAIL_NET_H

#include <stddef.h>
#include <stdint.h>

/* tls = 1: every net_connect from now on does TLS and checks the server certificate against pin (32 bytes). Without
 * PHETAIL_TLS compiled in this returns -1. */
int net_set_tls(const uint8_t pin[32]);
int net_connect(const char *host, int port);
int net_send_all(int s, const void *buf, size_t len);
/* like plat_recv: bytes, 0 = timeout, -1 = error / EOF */
int net_recv(int s, void *buf, size_t len, int timeout_ms);
void net_close(int s);
/* 1 if decrypted bytes are waiting although the socket itself is not readable */
int net_pending(int s);

#endif
