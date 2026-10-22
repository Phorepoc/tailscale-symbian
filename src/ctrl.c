// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
#include "ctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plat.h"
#include "tcrypto.h"
#include "util.h"

#define NOISE_PROTO "Noise_IK_25519_ChaChaPoly_BLAKE2s"
#define MAX_PT (4096 - 3 - 16)

/* ---------- plain HTTP/1.1 helpers ---------- */

/* Reads until "\r\n\r\n"; returns header length (incl. terminator), extra bytes in buf after it. */
static int read_http_head(int s, char *buf, size_t cap, size_t *got)
{
	size_t n = 0;
	for (;;) {
		char *e;
		int r;
		if (n + 1 >= cap)
			return -1;
		r = plat_recv(s, buf + n, cap - 1 - n, 10000);
		if (r <= 0)
			return -1;
		n += (size_t)r;
		buf[n] = 0;
		e = strstr(buf, "\r\n\r\n");
		if (e) {
			*got = n;
			return (int)(e - buf) + 4;
		}
	}
}

int ctrl_fetch_key(const char *host, int port, int capver, uint8_t server_pub[32])
{
	char req[256], resp[4096], *k;
	size_t n = 0;
	int s = plat_tcp_connect(host, port), r;
	if (s < 0)
		return -1;
	snprintf(req, sizeof req, "GET /key?v=%d HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", capver, host,
		 port);
	plat_send_all(s, req, strlen(req));
	while (n < sizeof resp - 1 && (r = plat_recv(s, resp + n, sizeof resp - 1 - n, 10000)) > 0)
		n += (size_t)r;
	resp[n] = 0;
	plat_close(s);
	k = strstr(resp, "\"publicKey\":\"mkey:");
	if (!k)
		return -1;
	return tc_unhex(server_pub, k + 18, 32);
}

/* ---------- Noise transport ---------- */

static void mknonce(uint8_t n[12], uint64_t c)
{
	int i;
	memset(n, 0, 4);
	for (i = 0; i < 8; i++)
		n[4 + i] = (uint8_t)(c >> (56 - 8 * i));
}

static int noise_write(ctrl *c, const uint8_t *p, size_t len)
{
	uint8_t frame[4096], nonce[12];
	while (len) {
		size_t chunk = len > MAX_PT ? MAX_PT : len;
		frame[0] = 4;
		put_be16(frame + 1, (uint16_t)(chunk + 16));
		mknonce(nonce, c->txn++);
		tc_aead_seal(frame + 3, c->txk, nonce, p, chunk, NULL, 0);
		if (plat_send_all(c->sock, frame, chunk + 19))
			return -1;
		p += chunk;
		len -= chunk;
	}
	return 0;
}

/* Fill c->pt with the next decrypted record. */
static int noise_fill(ctrl *c, int timeout_ms)
{
	uint8_t nonce[12];
	for (;;) {
		if (c->rawlen >= 3) {
			size_t flen = 3 + get_be16(c->raw + 1);
			if (c->raw[0] != 4) {
				fprintf(stderr, "noise: unexpected record type %d\n", c->raw[0]);
				return -1;
			}
			if (c->rawlen >= flen) {
				mknonce(nonce, c->rxn++);
				if (tc_aead_open(c->pt, c->rxk, nonce, c->raw + 3, flen - 3, NULL, 0)) {
					fprintf(stderr, "noise: decrypt failed\n");
					return -1;
				}
				c->ptoff = 0;
				c->ptlen = flen - 3 - 16;
				memmove(c->raw, c->raw + flen, c->rawlen - flen);
				c->rawlen -= flen;
				return 0;
			}
		}
		{
			int r = plat_recv(c->sock, c->raw + c->rawlen, sizeof c->raw - c->rawlen, timeout_ms);
			if (r <= 0)
				return -1;
			c->rawlen += (size_t)r;
		}
	}
}

static int noise_read(ctrl *c, uint8_t *out, size_t len)
{
	while (len) {
		size_t n;
		if (c->ptoff == c->ptlen && noise_fill(c, 15000))
			return -1;
		n = c->ptlen - c->ptoff;
		if (n > len)
			n = len;
		memcpy(out, c->pt + c->ptoff, n);
		c->ptoff += n;
		out += n;
		len -= n;
	}
	return 0;
}

/* ---------- ts2021 handshake ---------- */

typedef struct {
	uint8_t h[32], ck[32];
} symstate;

static void mixhash(symstate *s, const void *d, size_t n) { tc_blake2s(s->h, s->h, 32, d, n); }

static void mixdh(symstate *s, uint8_t k[32], const uint8_t priv[32], const uint8_t pub[32])
{
	uint8_t dh[32];
	tc_x25519(dh, priv, pub);
	tc_hkdf(s->ck, k, NULL, s->ck, dh, 32);
}

int ctrl_connect(ctrl *c, const char *host, int port, int capver, const uint8_t mpriv[32], const uint8_t spub[32])
{
	static const uint8_t zn[12];
	symstate s;
	uint8_t init[101], epriv[32], epub[32], mpub[32], k[32], resp[51], dh[32];
	char prologue[64], b64[160], req[512], head[2048];
	size_t got = 0;
	int hl;

	memset(c, 0, sizeof *c);
	snprintf(c->host, sizeof c->host, "%s", host);
	c->port = port;
	c->next_stream = 1;

	tc_blake2s(s.h, NOISE_PROTO, strlen(NOISE_PROTO), NULL, 0);
	memcpy(s.ck, s.h, 32);
	snprintf(prologue, sizeof prologue, "Tailscale Control Protocol v%d", capver);
	mixhash(&s, prologue, strlen(prologue));
	mixhash(&s, spub, 32);

	put_be16(init, (uint16_t)capver);
	init[2] = 1;
	put_be16(init + 3, 96);
	tc_keypair(epriv, epub);
	memcpy(init + 5, epub, 32);
	mixhash(&s, epub, 32);
	mixdh(&s, k, epriv, spub);
	tc_x25519_pub(mpub, mpriv);
	tc_aead_seal(init + 37, k, zn, mpub, 32, s.h, 32);
	mixhash(&s, init + 37, 48);
	mixdh(&s, k, mpriv, spub);
	tc_aead_seal(init + 85, k, zn, NULL, 0, s.h, 32);
	mixhash(&s, init + 85, 16);

	b64_encode(b64, init, sizeof init);
	snprintf(req, sizeof req,
		 "POST /ts2021 HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: tailscale-control-protocol\r\n"
		 "Connection: upgrade\r\nX-Tailscale-Handshake: %s\r\nContent-Length: 0\r\n\r\n",
		 host, port, b64);
	c->sock = plat_tcp_connect(host, port);
	if (c->sock < 0)
		return -1;
	plat_send_all(c->sock, req, strlen(req));
	hl = read_http_head(c->sock, head, sizeof head, &got);
	if (hl < 0 || strncmp(head, "HTTP/1.1 101", 12) != 0) {
		fprintf(stderr, "ts2021: upgrade refused:\n%s\n", hl < 0 ? "(no response)" : head);
		return -1;
	}
	printf("ts2021: %.*s\n", (int)(strchr(head, '\r') - head), head);
	memcpy(c->raw, head + hl, got - (size_t)hl);
	c->rawlen = got - (size_t)hl;
	while (c->rawlen < 51) {
		int r = plat_recv(c->sock, c->raw + c->rawlen, sizeof c->raw - c->rawlen, 10000);
		if (r <= 0)
			return -1;
		c->rawlen += (size_t)r;
	}
	memcpy(resp, c->raw, 51);
	memmove(c->raw, c->raw + 51, c->rawlen - 51);
	c->rawlen -= 51;
	if (resp[0] != 2 || get_be16(resp + 1) != 48) {
		fprintf(stderr, "ts2021: bad response type %d\n", resp[0]);
		return -1;
	}
	mixhash(&s, resp + 3, 32);
	mixdh(&s, k, epriv, resp + 3);
	mixdh(&s, k, mpriv, resp + 3);
	if (tc_aead_open(dh, k, zn, resp + 35, 16, s.h, 32)) {
		fprintf(stderr, "ts2021: response tag mismatch\n");
		return -1;
	}
	mixhash(&s, resp + 35, 16);
	tc_hkdf(c->txk, c->rxk, NULL, s.ck, NULL, 0);
	printf("ts2021: Noise IK handshake complete\n");

	/* Optional early payload: "\xff\xff\xffTS" + BE32 length + JSON. */
	{
		uint8_t hdr[9];
		if (noise_read(c, hdr, 9))
			return -1;
		if (memcmp(hdr, "\xff\xff\xffTS", 5) == 0) {
			uint32_t n = get_be32(hdr + 5);
			char *j = malloc(n + 1);
			if (!j || noise_read(c, (uint8_t *)j, n))
				return -1;
			j[n] = 0;
			printf("ts2021: early payload %s\n", j);
			free(j);
		} else {
			/* It was the first HTTP/2 frame header: push it back. */
			c->ptoff -= 9;
		}
	}

	/* HTTP/2 preface + SETTINGS(INITIAL_WINDOW_SIZE=16M) + conn WINDOW_UPDATE. */
	{
		static const char pre[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
		uint8_t f[24 + 15 + 13];
		memcpy(f, pre, 24);
		put_be24(f + 24, 6);
		f[27] = 4;
		f[28] = 0;
		put_be32(f + 29, 0);
		put_be16(f + 33, 4);
		put_be32(f + 35, 1u << 24);
		put_be24(f + 39, 4);
		f[42] = 8;
		f[43] = 0;
		put_be32(f + 44, 0);
		put_be32(f + 48, (1u << 24) - 65535);
		return noise_write(c, f, sizeof f);
	}
}

/* ---------- minimal HTTP/2 ---------- */

static size_t hpack_lit(uint8_t *p, const char *name, const char *val)
{
	size_t nl = strlen(name), vl = strlen(val), o = 0;
	p[o++] = 0x00; /* literal without indexing, new name */
	p[o++] = (uint8_t)nl;
	memcpy(p + o, name, nl);
	o += nl;
	p[o++] = (uint8_t)vl;
	memcpy(p + o, val, vl);
	return o + vl;
}

static int h2_frame(ctrl *c, uint8_t type, uint8_t flags, uint32_t sid, const void *p, size_t n)
{
	uint8_t *f = malloc(9 + n);
	int r;
	put_be24(f, (uint32_t)n);
	f[3] = type;
	f[4] = flags;
	put_be32(f + 5, sid);
	if (n)
		memcpy(f + 9, p, n);
	r = noise_write(c, f, 9 + n);
	free(f);
	return r;
}

int ctrl_post(ctrl *c, const char *path, const char *body, size_t len, char **out, size_t *outlen)
{
	uint8_t hb[512];
	char auth[160], clen[24];
	size_t o = 0, cap = 65536, n = 0;
	uint32_t sid = c->next_stream;
	char *buf = malloc(cap);
	int status = -1;

	c->next_stream += 2;
	snprintf(auth, sizeof auth, "%s:%d", c->host, c->port);
	snprintf(clen, sizeof clen, "%u", (unsigned)len);
	o += hpack_lit(hb + o, ":method", "POST");
	o += hpack_lit(hb + o, ":scheme", "http");
	o += hpack_lit(hb + o, ":path", path);
	o += hpack_lit(hb + o, ":authority", auth);
	o += hpack_lit(hb + o, "content-type", "application/json");
	o += hpack_lit(hb + o, "content-length", clen);
	if (h2_frame(c, 1, 0x4, sid, hb, o))
		return -1;
	{
		size_t off = 0;
		while (off < len) {
			size_t ch = len - off > 16384 ? 16384 : len - off;
			if (h2_frame(c, 0, off + ch == len ? 1 : 0, sid, body + off, ch))
				return -1;
			off += ch;
		}
	}

	for (;;) {
		uint8_t fh[9], *p;
		uint32_t fl, fsid;
		if (noise_read(c, fh, 9))
			break;
		fl = get_be24(fh);
		fsid = get_be32(fh + 5) & 0x7fffffff;
		p = malloc(fl + 1);
		if (fl && noise_read(c, p, fl)) {
			free(p);
			break;
		}
		switch (fh[3]) {
		case 4: /* SETTINGS */
			if (!(fh[4] & 1))
				h2_frame(c, 4, 1, 0, NULL, 0);
			break;
		case 6: /* PING */
			if (!(fh[4] & 1))
				h2_frame(c, 6, 1, 0, p, fl);
			break;
		case 7: /* GOAWAY */
			fprintf(stderr, "h2: GOAWAY code %u\n", fl >= 8 ? get_be32(p + 4) : 0);
			free(p);
			goto done;
		case 3: /* RST_STREAM */
			if (fsid == sid) {
				fprintf(stderr, "h2: RST_STREAM code %u\n", fl >= 4 ? get_be32(p) : 0);
				free(p);
				goto done;
			}
			break;
		case 1: /* HEADERS: we do not decode HPACK; 0x88 = indexed ":status: 200" */
			if (fsid == sid) {
				status = (fl && p[(fh[4] & 0x20) ? 5 : 0] == 0x88) ? 0 : 1;
				if (status)
					fprintf(stderr, "h2: non-200 response (first hpack byte 0x%02x)\n", p[0]);
				if (fh[4] & 1) {
					free(p);
					goto done;
				}
			}
			break;
		case 0: /* DATA */
			if (fsid == sid) {
				uint8_t wu[4];
				size_t pad = (fh[4] & 8) ? p[0] + 1u : 0, dl = fl - pad;
				const uint8_t *d = p + ((fh[4] & 8) ? 1 : 0);
				while (n + dl + 1 > cap)
					buf = realloc(buf, cap *= 2);
				memcpy(buf + n, d, dl);
				n += dl;
				if (fl) {
					put_be32(wu, fl);
					h2_frame(c, 8, 0, 0, wu, 4);
					if (!(fh[4] & 1))
						h2_frame(c, 8, 0, sid, wu, 4);
				}
				if ((fh[4] & 1) || (c->stop_after_msg && n >= 4 && n >= 4 + get_le32((uint8_t *)buf))) {
					free(p);
					goto done;
				}
			}
			break;
		default:
			break;
		}
		free(p);
	}
done:
	buf[n] = 0;
	*out = buf;
	*outlen = n;
	return status == 0 ? 0 : -1;
}

void ctrl_close(ctrl *c)
{
	if (c->sock >= 0)
		plat_close(c->sock);
	c->sock = -1;
}
