// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// DERP relay client: HTTP upgrade, ServerKey, boxed ClientInfo, then frames.
#include "derp.h"

#include <stdio.h>
#include "log.h"
#include <string.h>

#include "net.h"
#include "plat.h"
#include "tail.h"
#include "tcrypto.h"
#include "util.h"

static struct {
	int sock;
	uint8_t buf[70000];
	size_t len;
} d = {-1, {0}, 0};

static int send_frame(uint8_t type, const void *a, size_t alen, const void *b, size_t blen)
{
	uint8_t h[5];
	if (d.sock < 0)
		return -1;
	h[0] = type;
	put_be32(h + 1, (uint32_t)(alen + blen));
	if (net_send_all(d.sock, h, 5) || (alen && net_send_all(d.sock, a, alen)) ||
	    (blen && net_send_all(d.sock, b, blen)))
		return -1;
	return 0;
}

int derp_send_packet(const uint8_t dst[32], const uint8_t *pkt, size_t len)
{
	return send_frame(4, dst, 32, pkt, len);
}

/* Next complete frame in the buffer: type, or 0 if incomplete. */
static int next_frame(const uint8_t **p, size_t *n, size_t *used)
{
	size_t fl;
	if (d.len < 5)
		return 0;
	fl = get_be32(d.buf + 1);
	if (d.len < 5 + fl)
		return 0;
	*p = d.buf + 5;
	*n = fl;
	*used = 5 + fl;
	return d.buf[0];
}

static void consume(size_t used)
{
	memmove(d.buf, d.buf + used, d.len - used);
	d.len -= used;
}

static int fill(int timeout_ms)
{
	int r = net_recv(d.sock, d.buf + d.len, sizeof d.buf - d.len, timeout_ms);
	if (r == NET_TIMEOUT)
		return 0;
	if (r <= 0)
		return -1;                      /* EOF or error */
	d.len += (size_t)r;
	return r;
}

static int wait_frame(const uint8_t **p, size_t *n, size_t *used)
{
	int t;
	while ((t = next_frame(p, n, used)) == 0)
		if (fill(10000) <= 0)
			return -1;
	return t;
}

int derp_connect(const char *host, int port)
{
	char req[256], *e;
	const uint8_t *p;
	size_t n, used;
	uint8_t msg[256];
	static const char info[] = "{\"version\":2}";
	int t;

	d.len = 0;
	d.sock = net_connect(host, port);
	if (d.sock < 0) {
		fprintf(stderr, "derp: connect to %s:%d failed\n", host, port);
		return -1;
	}
	snprintf(req, sizeof req, "GET /derp HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
		 host, port);
	net_send_all(d.sock, req, strlen(req));
	for (;;) {
		if (fill(10000) <= 0 || d.len >= sizeof d.buf - 1) {
			d.buf[d.len < sizeof d.buf ? d.len : 0] = 0;
			fprintf(stderr, "derp: no HTTP reply head (%u bytes: %.60s)\n", (unsigned)d.len, (char *)d.buf);
			return -1;
		}
		d.buf[d.len] = 0;
		if ((e = strstr((char *)d.buf, "\r\n\r\n")) != NULL)
			break;
	}
	printf("derp: %.*s\n", (int)(strchr((char *)d.buf, '\r') - (char *)d.buf), d.buf);
	consume((size_t)(e + 4 - (char *)d.buf));

	t = wait_frame(&p, &n, &used);
	if (t < 0) fprintf(stderr, "derp: no ServerKey frame within 10 s\n");
	if (t != 1 || n < 40 || memcmp(p, "DERP\xf0\x9f\x94\x91", 8) != 0) {
		fprintf(stderr, "derp: no server key frame (type %d)\n", t);
		return -1;
	}
	n = tc_box_seal(msg, info, strlen(info), p + 8, g_tail.node_priv);
	consume(used);
	if (send_frame(2, g_tail.node_pub, 32, msg, n))
		return -1;
	t = wait_frame(&p, &n, &used);
	if (t != 3) {
		fprintf(stderr, "derp: expected ServerInfo, got frame %d\n", t);
		return -1;
	}
	consume(used);
	{
		uint8_t one = 1;
		send_frame(7, &one, 1, NULL, 0);
	}
	printf("derp: connected (ServerInfo received, preferred home)\n");
	return 0;
}

int derp_sock(void) { return d.sock; }

void derp_close(void)
{
	if (d.sock >= 0)
		net_close(d.sock);
	d.sock = -1;
	d.len = 0;
}

int derp_on_readable(void)
{
	const uint8_t *p;
	size_t n, used;
	int t;
	if (fill(0) < 0) {
		fprintf(stderr, "derp: connection lost\n");
		net_close(d.sock);
		d.sock = -1;
		return -1;
	}
	while ((t = next_frame(&p, &n, &used)) != 0) {
		if (t == 5 && n > 32) {
			if (disco_is(p + 32, n - 32))
				disco_on_packet(p, p + 32, n - 32);
			else
				wg_on_packet(p, p + 32, n - 32);
		} else if (t == 0x12 && n == 8) {
			uint8_t pong[8];
			memcpy(pong, p, 8);
			consume(used);
			send_frame(0x13, pong, 8, NULL, 0);
			continue;
		}
		consume(used);
	}
	return 0;
}
