// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// Minimal disco: answer Ping with Pong over DERP, so peers see us as reachable
// "via DERP". Wire format: "TS\xf0\x9f\x92\xac" + sender disco key (32) +
// NaCl box (nonce 24 || tag 16 || ct) of: type(1) version(1) body.
#include <stdio.h>
#include <string.h>

#include "tail.h"
#include "tcrypto.h"
#include "util.h"

#define MAGIC "TS\xf0\x9f\x92\xac"
#define DERP_MAGIC_IP 127, 3, 3, 40

int disco_is(const uint8_t *pkt, size_t len) { return len >= 6 + 32 + 40 && memcmp(pkt, MAGIC, 6) == 0; }

static peer *peer_by_disco(const uint8_t k[32])
{
	int i;
	for (i = 0; i < MAX_PEERS; i++)
		if (g_tail.peers[i].used && memcmp(g_tail.peers[i].discokey, k, 32) == 0)
			return &g_tail.peers[i];
	return NULL;
}

void disco_on_packet(const uint8_t src[32], const uint8_t *pkt, size_t len)
{
	uint8_t pt[512], out[6 + 32 + 40 + 32];
	const uint8_t *sender = pkt + 6;
	peer *p = peer_by_disco(sender);
	size_t n = len - 38 - 40;
	if (!p || len - 38 > sizeof pt + 40 || tc_box_open(pt, pkt + 38, len - 38, sender, g_tail.disco_priv)) {
		printf("disco: undecryptable message (%u bytes)\n", (unsigned)len);
		return;
	}
	if (n >= 2 + 12 && pt[0] == 1) {
		uint8_t pong[2 + 12 + 16 + 2];
		static const uint8_t v4mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, DERP_MAGIC_IP};
		size_t bn;
		pong[0] = 2; /* Pong */
		pong[1] = 0;
		memcpy(pong + 2, pt + 2, 12);
		memcpy(pong + 14, v4mapped, 16);
		put_be16(pong + 30, (uint16_t)(p->home_derp ? p->home_derp : 999));
		memcpy(out, MAGIC, 6);
		memcpy(out + 6, g_tail.disco_pub, 32);
		bn = tc_box_seal(out + 38, pong, sizeof pong, sender, g_tail.disco_priv);
		derp_send_packet(src, out, 38 + bn);
		printf("disco: <- ping from %s, -> pong via DERP\n", p->name);
	} else if (n >= 1) {
		printf("disco: message type %u from %s (ignored)\n", pt[0], p->name);
	}
}
