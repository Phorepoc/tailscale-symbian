// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// WireGuard over DERP: initiator + responder handshakes (Noise IKpsk2, psk = 0),
// transport data, keepalives, rekey timers. Packets travel as DERP payloads.
#include <stdio.h>
#include "log.h"
#include <stdlib.h>
#include <string.h>

#include "plat.h"
#include "tail.h"
#include "tcrypto.h"
#include "util.h"

#define REKEY_AFTER_MS 120000
#define REJECT_AFTER_MS 180000
#define REKEY_TIMEOUT_MS 5000
#define KEEPALIVE_MS 10000
#define REKEY_ATTEMPT_MS 90000

static const char CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char IDENTIFIER[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const uint8_t zn[12];

static void nonce_le(uint8_t n[12], uint64_t c)
{
	int i;
	memset(n, 0, 4);
	for (i = 0; i < 8; i++)
		n[4 + i] = (uint8_t)(c >> (8 * i));
}

static void init_hash(uint8_t C[32], uint8_t H[32], const uint8_t resp_pub[32])
{
	tc_blake2s(C, CONSTRUCTION, strlen(CONSTRUCTION), NULL, 0);
	tc_blake2s(H, C, 32, IDENTIFIER, strlen(IDENTIFIER));
	tc_blake2s(H, H, 32, resp_pub, 32);
}

static void mac1(uint8_t *out, const uint8_t to_pub[32], const uint8_t *msg, size_t n)
{
	uint8_t k[32];
	tc_blake2s(k, "mac1----", 8, to_pub, 32);
	tc_blake2s_mac16(out, k, msg, n);
}

static uint32_t new_idx(void)
{
	uint32_t i;
	plat_random(&i, 4);
	return i;
}

static void send_initiation(peer *p, uint64_t now)
{
	uint8_t m[148], epub[32], k[32], dh[32], ts[12];
	uint64_t sec;
	uint32_t nsec;
	wg_handshake *h = &p->hs;
	int i;

	init_hash(h->C, h->H, p->nodekey);
	memset(m, 0, sizeof m);
	m[0] = 1;
	h->my_idx = new_idx();
	put_le32(m + 4, h->my_idx);
	tc_keypair(h->epriv, epub);
	memcpy(m + 8, epub, 32);
	tc_hkdf(h->C, NULL, NULL, h->C, epub, 32);
	tc_blake2s(h->H, h->H, 32, epub, 32);
	tc_x25519(dh, h->epriv, p->nodekey);
	tc_hkdf(h->C, k, NULL, h->C, dh, 32);
	tc_aead_seal(m + 40, k, zn, g_tail.node_pub, 32, h->H, 32);
	tc_blake2s(h->H, h->H, 32, m + 40, 48);
	tc_x25519(dh, g_tail.node_priv, p->nodekey);
	tc_hkdf(h->C, k, NULL, h->C, dh, 32);
	plat_time(&sec, &nsec);
	sec += 0x400000000000000aULL;
	for (i = 0; i < 8; i++)
		ts[i] = (uint8_t)(sec >> (56 - 8 * i));
	put_be32(ts + 8, nsec);
	tc_aead_seal(m + 88, k, zn, ts, 12, h->H, 32);
	tc_blake2s(h->H, h->H, 32, m + 88, 28);
	mac1(m + 116, p->nodekey, m, 116);
	if (!h->in_progress)
		h->started_ms = now;
	h->in_progress = 1;
	h->sent_ms = now;
	derp_send_packet(p->nodekey, m, sizeof m);
	printf("wg: -> handshake initiation to %s\n", p->name);
}

static void install(peer *p, const uint8_t k1[32], const uint8_t k2[32], uint32_t my, uint32_t theirs, int initiator,
		    uint64_t now)
{
	p->prev = p->cur;
	memset(&p->cur, 0, sizeof p->cur);
	p->cur.valid = 1;
	p->cur.initiator = initiator;
	p->cur.my_idx = my;
	p->cur.peer_idx = theirs;
	p->cur.created_ms = now;
	if (initiator) {
		memcpy(p->cur.tsend, k1, 32);
		memcpy(p->cur.trecv, k2, 32);
	} else {
		memcpy(p->cur.trecv, k1, 32);
		memcpy(p->cur.tsend, k2, 32);
	}
}

static void send_data(peer *p, const uint8_t *ip, size_t n, uint64_t now)
{
	uint8_t out[1600 + 32], nonce[12];
	uint8_t *pt = out + 16;
	size_t padded = (n + 15) & ~(size_t)15;
	int i;
	if (padded > 1600)
		return;
	memset(pt, 0, padded);
	if (n)
		memcpy(pt, ip, n);
	out[0] = 4;
	out[1] = out[2] = out[3] = 0;
	put_le32(out + 4, p->cur.peer_idx);
	for (i = 0; i < 8; i++)
		out[8 + i] = (uint8_t)(p->cur.send_ctr >> (8 * i));
	nonce_le(nonce, p->cur.send_ctr++);
	tc_aead_seal(out + 16, p->cur.tsend, nonce, pt, padded, NULL, 0);
	derp_send_packet(p->nodekey, out, 16 + padded + 16);
	p->last_sent_ms = now;
}

static void flush_queue(peer *p, uint64_t now)
{
	int i;
	for (i = 0; i < p->nqueue; i++) {
		send_data(p, p->queue[i], p->queue_len[i], now);
		free(p->queue[i]);
	}
	p->nqueue = 0;
}

int wg_send_ip(peer *p, const uint8_t *ip, size_t len)
{
	uint64_t now = plat_ms();
	int usable = p->cur.valid && now - p->cur.created_ms < REJECT_AFTER_MS;
	if (usable) {
		send_data(p, ip, len, now);
		if (p->cur.initiator && now - p->cur.created_ms > REKEY_AFTER_MS && !p->hs.in_progress)
			send_initiation(p, now);
		return 0;
	}
	if (p->nqueue == WG_QUEUE) {
		free(p->queue[0]);
		memmove(p->queue, p->queue + 1, sizeof p->queue[0] * (WG_QUEUE - 1));
		memmove(p->queue_len, p->queue_len + 1, sizeof p->queue_len[0] * (WG_QUEUE - 1));
		p->nqueue--;
	}
	p->queue[p->nqueue] = malloc(len);
	memcpy(p->queue[p->nqueue], ip, len);
	p->queue_len[p->nqueue++] = len;
	if (!p->hs.in_progress || now - p->hs.sent_ms > REKEY_TIMEOUT_MS)
		send_initiation(p, now);
	return 0;
}

static void on_initiation(peer *p, const uint8_t *m, size_t n, uint64_t now)
{
	uint8_t C[32], H[32], k[32], dh[32], spub[32], ts[12], r[92], epriv[32], epub[32], tau[32], t1[32], t2[32];
	static const uint8_t zero[32];
	uint32_t my;
	if (n != 148)
		return;
	init_hash(C, H, g_tail.node_pub);
	tc_hkdf(C, NULL, NULL, C, m + 8, 32);
	tc_blake2s(H, H, 32, m + 8, 32);
	tc_x25519(dh, g_tail.node_priv, m + 8);
	tc_hkdf(C, k, NULL, C, dh, 32);
	if (tc_aead_open(spub, k, zn, m + 40, 48, H, 32) || memcmp(spub, p->nodekey, 32)) {
		printf("wg: bad initiation from %s\n", p->name);
		return;
	}
	tc_blake2s(H, H, 32, m + 40, 48);
	tc_x25519(dh, g_tail.node_priv, spub);
	tc_hkdf(C, k, NULL, C, dh, 32);
	if (tc_aead_open(ts, k, zn, m + 88, 28, H, 32))
		return;
	tc_blake2s(H, H, 32, m + 88, 28);

	memset(r, 0, sizeof r);
	r[0] = 2;
	my = new_idx();
	put_le32(r + 4, my);
	memcpy(r + 8, m + 4, 4);
	tc_keypair(epriv, epub);
	memcpy(r + 12, epub, 32);
	tc_hkdf(C, NULL, NULL, C, epub, 32);
	tc_blake2s(H, H, 32, epub, 32);
	tc_x25519(dh, epriv, m + 8);
	tc_hkdf(C, NULL, NULL, C, dh, 32);
	tc_x25519(dh, epriv, spub);
	tc_hkdf(C, NULL, NULL, C, dh, 32);
	tc_hkdf(C, tau, k, C, zero, 32);
	tc_blake2s(H, H, 32, tau, 32);
	tc_aead_seal(r + 44, k, zn, NULL, 0, H, 32);
	mac1(r + 60, spub, r, 60);
	tc_hkdf(t1, t2, NULL, C, NULL, 0);
	install(p, t1, t2, my, get_le32(m + 4), 0, now);
	derp_send_packet(p->nodekey, r, sizeof r);
	printf("wg: <- initiation from %s, -> response (responder)\n", p->name);
	flush_queue(p, now);
}

static void on_response(peer *p, const uint8_t *m, size_t n, uint64_t now)
{
	static const uint8_t zero[32];
	wg_handshake *h = &p->hs;
	uint8_t dh[32], tau[32], k[32], tmp[1], t1[32], t2[32];
	if (n != 92 || !h->in_progress || get_le32(m + 8) != h->my_idx)
		return;
	tc_hkdf(h->C, NULL, NULL, h->C, m + 12, 32);
	tc_blake2s(h->H, h->H, 32, m + 12, 32);
	tc_x25519(dh, h->epriv, m + 12);
	tc_hkdf(h->C, NULL, NULL, h->C, dh, 32);
	tc_x25519(dh, g_tail.node_priv, m + 12);
	tc_hkdf(h->C, NULL, NULL, h->C, dh, 32);
	tc_hkdf(h->C, tau, k, h->C, zero, 32);
	tc_blake2s(h->H, h->H, 32, tau, 32);
	if (tc_aead_open(tmp, k, zn, m + 44, 16, h->H, 32)) {
		printf("wg: bad response from %s\n", p->name);
		return;
	}
	tc_hkdf(t1, t2, NULL, h->C, NULL, 0);
	h->in_progress = 0;
	install(p, t1, t2, h->my_idx, get_le32(m + 4), 1, now);
	printf("wg: <- handshake response from %s (initiator)\n", p->name);
	if (!p->nqueue)
		send_data(p, NULL, 0, now); /* keepalive confirms the session */
	flush_queue(p, now);
}

static void on_data(peer *p, const uint8_t *m, size_t n, uint64_t now)
{
	uint32_t idx = get_le32(m + 4);
	wg_keypair *kp = p->cur.valid && p->cur.my_idx == idx ? &p->cur
			 : p->prev.valid && p->prev.my_idx == idx ? &p->prev
								  : NULL;
	uint8_t nonce[12], pt[1600];
	uint64_t ctr = 0;
	int i;
	if (!kp || n < 32 || n - 32 > sizeof pt)
		return;
	for (i = 0; i < 8; i++)
		ctr |= (uint64_t)m[8 + i] << (8 * i);
	nonce_le(nonce, ctr);
	if (tc_aead_open(pt, kp->trecv, nonce, m + 16, n - 16, NULL, 0))
		return;
	/* Replay protection is a TODO (window of 2048 per RFC); accept in-order + reordered. */
	if (ctr > kp->recv_max)
		kp->recv_max = ctr;
	p->last_recv_ms = now;
	if (n - 32 >= 20 && (pt[0] >> 4) == 4) {
		size_t tl = get_be16(pt + 2);
		if (tl <= n - 32)
			tun_input(pt, tl);
	}
}

void wg_on_packet(const uint8_t src[32], const uint8_t *m, size_t n)
{
	peer *p = peer_by_nodekey(src);
	uint64_t now = plat_ms();
	if (!p || n < 4)
		return;
	switch (m[0]) {
	case 1:
		on_initiation(p, m, n, now);
		break;
	case 2:
		on_response(p, m, n, now);
		break;
	case 4:
		on_data(p, m, n, now);
		break;
	default:
		break;
	}
}

void wg_timers(uint64_t now)
{
	int i;
	for (i = 0; i < MAX_PEERS; i++) {
		peer *p = &g_tail.peers[i];
		if (!p->used)
			continue;
		if (p->hs.in_progress && now - p->hs.sent_ms > REKEY_TIMEOUT_MS) {
			if (now - p->hs.started_ms > REKEY_ATTEMPT_MS) {
				p->hs.in_progress = 0;
				p->nqueue = 0;
			} else {
				send_initiation(p, now);
			}
		}
		if (p->cur.valid && now - p->cur.created_ms > REJECT_AFTER_MS * 3)
			p->cur.valid = 0;
		/* Passive keepalive: we received data recently but have not sent anything. */
		if (p->cur.valid && now - p->cur.created_ms < REJECT_AFTER_MS && p->last_recv_ms > p->last_sent_ms &&
		    now - p->last_recv_ms < KEEPALIVE_MS && now - p->last_sent_ms > KEEPALIVE_MS)
			send_data(p, NULL, 0, now);
	}
}
