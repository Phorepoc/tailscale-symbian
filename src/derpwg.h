// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// S1: DERP relay client + a WireGuard initiator + ICMP echo, enough to ping
// one Tailscale peer through DERP.
#ifndef PHETAIL_DERPWG_H
#define PHETAIL_DERPWG_H

#include <stdint.h>

/* Connects to the DERP server at host:port, handshakes WireGuard with the
 * first peer in the map JSON and pings it. 0 = got echo replies. */
int s1_run(const char *derp_host, int derp_port, const uint8_t node_priv[32], const char *map_json);

#endif
