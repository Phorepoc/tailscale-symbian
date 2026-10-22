// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// Shared daemon state: the node's keys, the peer table, and the hooks the
// modules use to talk to each other. Everything runs on one thread.
#ifndef PHETAIL_TAIL_H
#define PHETAIL_TAIL_H

#include <stddef.h>
#include <stdint.h>

#define MAX_PEERS 32
#define WG_QUEUE 8

typedef struct {
	int valid;
	uint8_t tsend[32], trecv[32];
	uint32_t my_idx, peer_idx;
	uint64_t send_ctr, recv_max;
	uint64_t created_ms;
	int initiator;
} wg_keypair;

typedef struct {
	int in_progress;
	uint8_t C[32], H[32], epriv[32];
	uint32_t my_idx;
	uint64_t sent_ms, started_ms;
} wg_handshake;

typedef struct peer {
	int used;
	uint8_t nodekey[32], discokey[32];
	uint8_t ip4[4];
	char name[64];
	int home_derp;
	wg_keypair cur, prev;
	wg_handshake hs;
	uint64_t last_sent_ms, last_recv_ms;
	uint8_t *queue[WG_QUEUE];
	size_t queue_len[WG_QUEUE];
	int nqueue;
} peer;

typedef struct {
	uint8_t node_priv[32], node_pub[32];
	uint8_t disco_priv[32], disco_pub[32];
	uint8_t ip4[4];
	int have_ip;
	char name[64];
	peer peers[MAX_PEERS];
} tailstate;

extern tailstate g_tail;

peer *peer_by_nodekey(const uint8_t k[32]);
peer *peer_by_ip4(const uint8_t ip[4]);
peer *peer_by_name(const char *name);

/* netmap.c: applies one map response JSON (full or delta). Returns 0 if parsed. */
int netmap_apply(const char *json, size_t len);

/* derp.c / phetaild.c: send a packet to a node key through our DERP connection. */
int derp_send_packet(const uint8_t dst[32], const uint8_t *pkt, size_t len);

/* wg.c */
void wg_on_packet(const uint8_t src[32], const uint8_t *pkt, size_t len); /* from DERP */
int wg_send_ip(peer *p, const uint8_t *ip, size_t len);                   /* from the stack */
void wg_timers(uint64_t now);

/* disco.c */
int disco_is(const uint8_t *pkt, size_t len);
void disco_on_packet(const uint8_t src[32], const uint8_t *pkt, size_t len);

/* tunnel.c: the userspace IP stack (lwIP) */
void tun_init(void);
void tun_set_addr(const uint8_t ip[4]);
void tun_input(const uint8_t *ip, size_t len);
void tun_timers(void);

#endif
