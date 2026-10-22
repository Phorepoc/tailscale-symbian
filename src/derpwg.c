// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
#include "derpwg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plat.h"
#include "tcrypto.h"
#include "util.h"

/* ---------- DERP ---------- */

typedef struct {
	int sock;
	uint8_t buf[70000];
	size_t len;
} derp;

static int derp_send(derp *d, uint8_t type, const void *a, size_t alen, const void *b, size_t blen)
{
	uint8_t h[5];
	h[0] = type;
	put_be32(h + 1, (uint32_t)(alen + blen));
	if (plat_send_all(d->sock, h, 5) || (alen && plat_send_all(d->sock, a, alen)) ||
	    (blen && plat_send_all(d->sock, b, blen)))
		return -1;
	return 0;
}

/* Returns frame type, payload in p and n (valid until next call); 0 = timeout, -1 = error. */
static int derp_recv(derp *d, const uint8_t **p, size_t *n, int timeout_ms, size_t *consumed)
{
	if (*consumed) {
		memmove(d->buf, d->buf + *consumed, d->len - *consumed);
		d->len -= *consumed;
		*consumed = 0;
	}
	for (;;) {
		if (d->len >= 5) {
			size_t fl = get_be32(d->buf + 1);
			if (fl > sizeof d->buf - 5)
				return -1;
			if (d->len >= 5 + fl) {
				*p = d->buf + 5;
				*n = fl;
				*consumed = 5 + fl;
				return d->buf[0];
			}
		}
		{
			int r = plat_recv(d->sock, d->buf + d->len, sizeof d->buf - d->len, timeout_ms);
			if (r == 0)
				return 0;
			if (r < 0)
				return -1;
			d->len += (size_t)r;
		}
	}
}

static int derp_connect(derp *d, const char *host, int port, const uint8_t priv[32])
{
	char req[256];
	char *e;
	const uint8_t *p;
	size_t n, used = 0;
	uint8_t pub[32], msg[256];
	static const char info[] = "{\"version\":2}";
	int t;

	d->len = 0;
	d->sock = plat_tcp_connect(host, port);
	if (d->sock < 0)
		return -1;
	snprintf(req, sizeof req, "GET /derp HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
		 host, port);
	plat_send_all(d->sock, req, strlen(req));
	for (;;) {
		int r = plat_recv(d->sock, d->buf + d->len, sizeof d->buf - 1 - d->len, 10000);
		if (r <= 0)
			return -1;
		d->len += (size_t)r;
		d->buf[d->len] = 0;
		e = strstr((char *)d->buf, "\r\n\r\n");
		if (e)
			break;
	}
	printf("derp: %.*s\n", (int)(strchr((char *)d->buf, '\r') - (char *)d->buf), d->buf);
	n = (size_t)(e + 4 - (char *)d->buf);
	memmove(d->buf, d->buf + n, d->len - n);
	d->len -= n;

	t = derp_recv(d, &p, &n, 10000, &used);
	if (t != 1 || n < 40 || memcmp(p, "DERP\xf0\x9f\x94\x91", 8) != 0) {
		fprintf(stderr, "derp: no server key frame (type %d)\n", t);
		return -1;
	}
	{
		uint8_t spub[32];
		char hx[65];
		memcpy(spub, p + 8, 32);
		tc_hex(hx, spub, 32);
		printf("derp: server key %s\n", hx);
		tc_x25519_pub(pub, priv);
		n = tc_box_seal(msg, info, strlen(info), spub, priv);
		if (derp_send(d, 2, pub, 32, msg, n))
			return -1;
	}
	t = derp_recv(d, &p, &n, 10000, &used);
	if (t != 3) {
		fprintf(stderr, "derp: expected ServerInfo, got frame %d\n", t);
		return -1;
	}
	printf("derp: ServerInfo received, connected\n");
	memmove(d->buf, d->buf + used, d->len - used);
	d->len -= used;
	{
		uint8_t one = 1;
		derp_send(d, 7, &one, 1, NULL, 0);
	}
	return 0;
}

/* ---------- WireGuard ---------- */

static const char WG_CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char WG_IDENTIFIER[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";

typedef struct {
	uint8_t C[32], H[32], epriv[32];
	uint32_t my_idx, peer_idx;
	uint8_t tsend[32], trecv[32];
	uint64_t send_ctr;
} wg;

static void wg_nonce(uint8_t n[12], uint64_t c)
{
	int i;
	memset(n, 0, 4);
	for (i = 0; i < 8; i++)
		n[4 + i] = (uint8_t)(c >> (8 * i));
}

static void wg_init_msg(wg *w, uint8_t m[148], const uint8_t spriv[32], const uint8_t rpub[32])
{
	static const uint8_t zn[12];
	uint8_t epub[32], spub[32], k[32], dh[32], ts[12], mackey[32];
	uint64_t sec;
	uint32_t nsec;
	int i;

	tc_blake2s(w->C, WG_CONSTRUCTION, strlen(WG_CONSTRUCTION), NULL, 0);
	tc_blake2s(w->H, w->C, 32, WG_IDENTIFIER, strlen(WG_IDENTIFIER));
	tc_blake2s(w->H, w->H, 32, rpub, 32);
	memset(m, 0, 148);
	m[0] = 1;
	plat_random(&w->my_idx, 4);
	put_le32(m + 4, w->my_idx);
	tc_keypair(w->epriv, epub);
	memcpy(m + 8, epub, 32);
	tc_hkdf(w->C, NULL, NULL, w->C, epub, 32);
	tc_blake2s(w->H, w->H, 32, epub, 32);
	tc_x25519(dh, w->epriv, rpub);
	tc_hkdf(w->C, k, NULL, w->C, dh, 32);
	tc_x25519_pub(spub, spriv);
	tc_aead_seal(m + 40, k, zn, spub, 32, w->H, 32);
	tc_blake2s(w->H, w->H, 32, m + 40, 48);
	tc_x25519(dh, spriv, rpub);
	tc_hkdf(w->C, k, NULL, w->C, dh, 32);
	plat_time(&sec, &nsec);
	sec += 0x400000000000000aULL;
	for (i = 0; i < 8; i++)
		ts[i] = (uint8_t)(sec >> (56 - 8 * i));
	put_be32(ts + 8, nsec);
	tc_aead_seal(m + 88, k, zn, ts, 12, w->H, 32);
	tc_blake2s(w->H, w->H, 32, m + 88, 28);
	tc_blake2s(mackey, "mac1----", 8, rpub, 32);
	tc_blake2s_mac16(m + 116, mackey, m, 116);
}

static int wg_consume_resp(wg *w, const uint8_t *m, size_t n, const uint8_t spriv[32])
{
	static const uint8_t zn[12], zero[32];
	uint8_t dh[32], tau[32], k[32], tmp[1];
	if (n != 92 || m[0] != 2 || get_le32(m + 8) != w->my_idx)
		return -1;
	w->peer_idx = get_le32(m + 4);
	tc_hkdf(w->C, NULL, NULL, w->C, m + 12, 32);
	tc_blake2s(w->H, w->H, 32, m + 12, 32);
	tc_x25519(dh, w->epriv, m + 12);
	tc_hkdf(w->C, NULL, NULL, w->C, dh, 32);
	tc_x25519(dh, spriv, m + 12);
	tc_hkdf(w->C, NULL, NULL, w->C, dh, 32);
	tc_hkdf(w->C, tau, k, w->C, zero, 32);
	tc_blake2s(w->H, w->H, 32, tau, 32);
	if (tc_aead_open(tmp, k, zn, m + 44, 16, w->H, 32))
		return -1;
	tc_blake2s(w->H, w->H, 32, m + 44, 16);
	tc_hkdf(w->tsend, w->trecv, NULL, w->C, NULL, 0);
	w->send_ctr = 0;
	return 0;
}

static size_t wg_data(wg *w, uint8_t *out, const uint8_t *pkt, size_t n)
{
	uint8_t nonce[12], pt[1500];
	size_t padded = (n + 15) & ~(size_t)15;
	int i;
	memset(pt, 0, padded);
	memcpy(pt, pkt, n);
	out[0] = 4;
	out[1] = out[2] = out[3] = 0;
	put_le32(out + 4, w->peer_idx);
	for (i = 0; i < 8; i++)
		out[8 + i] = (uint8_t)(w->send_ctr >> (8 * i));
	wg_nonce(nonce, w->send_ctr++);
	tc_aead_seal(out + 16, w->tsend, nonce, pt, padded, NULL, 0);
	return 16 + padded + 16;
}

/* ---------- IPv4 / ICMP ---------- */

static uint16_t csum(const uint8_t *p, size_t n)
{
	uint32_t s = 0;
	size_t i;
	for (i = 0; i + 1 < n; i += 2)
		s += (uint32_t)(p[i] << 8 | p[i + 1]);
	if (n & 1)
		s += (uint32_t)p[n - 1] << 8;
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (uint16_t)~s;
}

static size_t icmp_echo(uint8_t *p, const uint8_t src[4], const uint8_t dst[4], uint16_t seq)
{
	size_t n = 20 + 8 + 16;
	memset(p, 0, n);
	p[0] = 0x45;
	put_be16(p + 2, (uint16_t)n);
	put_be16(p + 4, seq);
	p[8] = 64;
	p[9] = 1;
	memcpy(p + 12, src, 4);
	memcpy(p + 16, dst, 4);
	put_be16(p + 10, csum(p, 20));
	p[20] = 8;
	put_be16(p + 24, 0x7068); /* "ph" */
	put_be16(p + 26, seq);
	memcpy(p + 28, "phetail ping....", 16);
	put_be16(p + 22, csum(p + 20, 24));
	return n;
}

static int parse_ip(const char *s, uint8_t ip[4])
{
	unsigned a, b, c, d;
	if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
		return -1;
	ip[0] = (uint8_t)a;
	ip[1] = (uint8_t)b;
	ip[2] = (uint8_t)c;
	ip[3] = (uint8_t)d;
	return 0;
}

/* ---------- S1 driver ---------- */

int s1_run(const char *host, int port, const uint8_t spriv[32], const char *json)
{
	char tmp[128];
	const char *node = strstr(json, "\"Node\":"), *peers = strstr(json, "\"Peers\":");
	uint8_t myip[4], peerip[4], peerkey[32], m[1600];
	derp d;
	wg w;
	const uint8_t *p;
	size_t n, used = 0;
	int t, replies = 0, seq;
	uint64_t deadline;

	if (!node || !peers || !json_str(node, "Addresses", tmp, sizeof tmp) || parse_ip(tmp, myip)) {
		fprintf(stderr, "s1: no self address in map\n");
		return -1;
	}
	if (!json_str(peers, "Key", tmp, sizeof tmp) || strncmp(tmp, "nodekey:", 8) ||
	    tc_unhex(peerkey, tmp + 8, 32)) {
		fprintf(stderr, "s1: no peer key in map\n");
		return -1;
	}
	if (!json_str(peers, "Addresses", tmp, sizeof tmp) || parse_ip(tmp, peerip)) {
		fprintf(stderr, "s1: no peer address\n");
		return -1;
	}
	printf("s1: self %u.%u.%u.%u peer %u.%u.%u.%u\n", myip[0], myip[1], myip[2], myip[3], peerip[0], peerip[1],
	       peerip[2], peerip[3]);
	if (derp_connect(&d, host, port, spriv))
		return -1;

	wg_init_msg(&w, m, spriv, peerkey);
	derp_send(&d, 4, peerkey, 32, m, 148);
	printf("wg: sent handshake initiation via DERP\n");
	deadline = plat_ms() + 15000;
	for (;;) {
		if (plat_ms() > deadline) {
			fprintf(stderr, "wg: no handshake response\n");
			return -1;
		}
		t = derp_recv(&d, &p, &n, 1000, &used);
		if (t < 0)
			return -1;
		if (t == 5 && n > 32) {
			const uint8_t *pk = p + 32;
			size_t pl = n - 32;
			if (pl >= 6 && memcmp(pk, "TS\xf0\x9f\x92\xac", 6) == 0) {
				printf("derp: disco message from peer (%u bytes), ignored\n", (unsigned)pl);
				continue;
			}
			if (pk[0] == 2 && wg_consume_resp(&w, pk, pl, spriv) == 0) {
				printf("wg: handshake response OK (peer idx %08x)\n", w.peer_idx);
				break;
			}
			printf("wg: unexpected packet type %u len %u\n", pk[0], (unsigned)pl);
		} else if (t == 0x12) {
			derp_send(&d, 0x13, p, n, NULL, 0);
		}
	}

	for (seq = 1; seq <= 3; seq++) {
		uint8_t pkt[64], out[200];
		size_t pn = icmp_echo(pkt, myip, peerip, (uint16_t)seq), on = wg_data(&w, out, pkt, pn);
		uint64_t t0 = plat_ms();
		derp_send(&d, 4, peerkey, 32, out, on);
		deadline = t0 + 5000;
		while (plat_ms() < deadline) {
			t = derp_recv(&d, &p, &n, 500, &used);
			if (t < 0)
				return -1;
			if (t == 5 && n > 32 + 32 && p[32] == 4) {
				uint8_t nonce[12], plain[1600];
				const uint8_t *pk = p + 32;
				size_t pl = n - 32;
				uint64_t ctr = 0;
				int i;
				for (i = 0; i < 8; i++)
					ctr |= (uint64_t)pk[8 + i] << (8 * i);
				wg_nonce(nonce, ctr);
				if (pl - 16 > sizeof plain || tc_aead_open(plain, w.trecv, nonce, pk + 16, pl - 16, NULL, 0)) {
					printf("wg: data decrypt failed\n");
					continue;
				}
				if (pl - 32 == 0)
					continue; /* keepalive */
				if (plain[9] == 1 && plain[20] == 0 && get_be16(plain + 26) == seq) {
					printf("ping: reply from %u.%u.%u.%u seq=%d ttl=%u time=%ums via DERP\n", plain[12],
					       plain[13], plain[14], plain[15], seq, plain[8], (unsigned)(plat_ms() - t0));
					replies++;
					break;
				}
				printf("wg: data packet proto %u (%u bytes)\n", plain[9], (unsigned)(pl - 32));
			} else if (t == 5 && n > 32 && memcmp(p + 32, "TS\xf0\x9f\x92\xac", 6) == 0) {
				/* disco: ignore */
			} else if (t == 0x12) {
				derp_send(&d, 0x13, p, n, NULL, 0);
			}
		}
	}
	printf("ping: %d/3 replies\n", replies);
	plat_close(d.sock);
	return replies ? 0 : -1;
}
