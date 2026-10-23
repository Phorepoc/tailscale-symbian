// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
#ifndef PHETAIL_DERP_H
#define PHETAIL_DERP_H

#include <stddef.h>
#include <stdint.h>

/* Blocking connect + DERP handshake with g_tail's node key. 0 = ok. */
int derp_connect(const char *host, int port);
int derp_sock(void);
void derp_close(void);
/* Event loop hook; dispatches RecvPacket frames to disco / WireGuard. */
int derp_on_readable(void);

#endif
