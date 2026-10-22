// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// SOCKS5 front-end (RFC 1928, CONNECT only, no auth) bridging local client
// sockets to lwIP TCP connections inside the tailnet.
#include "socks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwip/tcp.h"
#include "plat.h"
#include "tail.h"
#include "util.h"

#define MAX_CLIENTS 16
enum { S_FREE, S_GREET, S_REQ, S_CONNECTING, S_OPEN };

typedef struct {
	int state, sock;
	uint8_t in[600];
	size_t inlen;
	struct tcp_pcb *pcb;
	uint8_t out[65536];
	size_t outlen;
	int remote_closed;
} client;

static client cl[MAX_CLIENTS];
static int listen_sock = -1;

static void drop(client *c)
{
	if (c->pcb) {
		tcp_arg(c->pcb, NULL);
		tcp_recv(c->pcb, NULL);
		tcp_err(c->pcb, NULL);
		if (tcp_close(c->pcb) != ERR_OK)
			tcp_abort(c->pcb);
	}
	if (c->sock >= 0)
		plat_close(c->sock);
	memset(c, 0, sizeof *c);
	c->sock = -1;
}

static void reply(client *c, uint8_t code)
{
	uint8_t r[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
	r[1] = code;
	plat_send_all(c->sock, r, sizeof r);
}

static err_t on_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
	client *c = arg;
	(void)pcb;
	if (!c)
		return ERR_ABRT;
	printf("socks: tunnel TCP connected\n");
	reply(c, err == ERR_OK ? 0 : 5);
	c->state = S_OPEN;
	return ERR_OK;
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	client *c = arg;
	(void)pcb;
	(void)err;
	if (!c) {
		if (p)
			pbuf_free(p);
		return ERR_OK;
	}
	if (!p) {
		c->remote_closed = 1;
		return ERR_OK;
	}
	if (c->outlen + p->tot_len > sizeof c->out)
		return ERR_MEM; /* lwIP keeps it and retries */
	pbuf_copy_partial(p, c->out + c->outlen, p->tot_len, 0);
	c->outlen += p->tot_len;
	pbuf_free(p);
	return ERR_OK;
}

static void on_err(void *arg, err_t err)
{
	client *c = arg;
	if (!c)
		return;
	printf("socks: tunnel TCP error %d\n", err);
	c->pcb = NULL; /* already freed by lwIP */
	if (c->state == S_CONNECTING)
		reply(c, 5);
	drop(c);
}

static int resolve(const uint8_t *req, size_t len, uint8_t ip[4], uint16_t *port, size_t *used)
{
	char name[256];
	unsigned a, b, cc, d;
	peer *p;
	if (len < 5)
		return -1;
	if (req[0] != 5 || req[1] != 1)
		return -2;
	if (req[3] == 1) {
		if (len < 10)
			return -1;
		memcpy(ip, req + 4, 4);
		*port = get_be16(req + 8);
		*used = 10;
		return 0;
	}
	if (req[3] != 3)
		return -2;
	if (len < 5u + req[4] + 2)
		return -1;
	memcpy(name, req + 5, req[4]);
	name[req[4]] = 0;
	*port = get_be16(req + 5 + req[4]);
	*used = 5u + req[4] + 2;
	if (sscanf(name, "%u.%u.%u.%u", &a, &b, &cc, &d) == 4) {
		ip[0] = (uint8_t)a, ip[1] = (uint8_t)b, ip[2] = (uint8_t)cc, ip[3] = (uint8_t)d;
		return 0;
	}
	name[strcspn(name, ".")] = 0; /* MagicDNS-style: first label */
	p = peer_by_name(name);
	if (!p)
		return -3;
	memcpy(ip, p->ip4, 4);
	printf("socks: %s -> %u.%u.%u.%u:%u\n", name, ip[0], ip[1], ip[2], ip[3], *port);
	return 0;
}

static void on_client_data(client *c)
{
	int r;
	if (c->state == S_OPEN) {
		uint8_t buf[4096];
		u16_t room = c->pcb ? tcp_sndbuf(c->pcb) : 0;
		if (!room)
			return;
		r = plat_recv(c->sock, buf, room < sizeof buf ? room : sizeof buf, 0);
		if (r < 0) {
			drop(c);
			return;
		}
		if (r > 0) {
			tcp_write(c->pcb, buf, (u16_t)r, TCP_WRITE_FLAG_COPY);
			tcp_output(c->pcb);
		}
		return;
	}
	r = plat_recv(c->sock, c->in + c->inlen, sizeof c->in - c->inlen, 0);
	if (r < 0) {
		drop(c);
		return;
	}
	c->inlen += (size_t)r;
	if (c->state == S_GREET && c->inlen >= 2 && c->inlen >= 2u + c->in[1]) {
		static const uint8_t ok[2] = {5, 0};
		size_t g = 2u + c->in[1];
		plat_send_all(c->sock, ok, 2);
		memmove(c->in, c->in + g, c->inlen - g);
		c->inlen -= g;
		c->state = S_REQ;
	}
	if (c->state == S_REQ) {
		uint8_t ip[4];
		uint16_t port;
		size_t used;
		ip_addr_t dst;
		int rr = resolve(c->in, c->inlen, ip, &port, &used);
		if (rr == -1)
			return;
		if (rr < 0) {
			reply(c, rr == -3 ? 4 : 7);
			drop(c);
			return;
		}
		c->pcb = tcp_new();
		tcp_arg(c->pcb, c);
		tcp_recv(c->pcb, on_recv);
		tcp_err(c->pcb, on_err);
		IP4_ADDR(&dst, ip[0], ip[1], ip[2], ip[3]);
		c->state = S_CONNECTING;
		if (tcp_connect(c->pcb, &dst, port, on_connected) != ERR_OK) {
			reply(c, 1);
			drop(c);
		}
	}
}

int socks_listen(int port)
{
	int i;
	for (i = 0; i < MAX_CLIENTS; i++)
		cl[i].sock = -1;
	listen_sock = plat_tcp_listen_local(port);
	if (listen_sock >= 0)
		printf("socks: listening on 127.0.0.1:%d\n", port);
	return listen_sock < 0 ? -1 : 0;
}

int socks_poll_set(plat_pollent *e, int max)
{
	int i, n = 0;
	if (listen_sock < 0 || max < 1)
		return 0;
	e[n].sock = listen_sock;
	e[n++].want = PLAT_RD;
	for (i = 0; i < MAX_CLIENTS && n < max; i++) {
		client *c = &cl[i];
		if (c->state == S_FREE)
			continue;
		e[n].sock = c->sock;
		e[n].want = (short)((c->state != S_CONNECTING && (c->state != S_OPEN || (c->pcb && tcp_sndbuf(c->pcb))))
					    ? PLAT_RD
					    : 0);
		if (c->outlen)
			e[n].want |= PLAT_WR;
		n++;
	}
	return n;
}

void socks_handle(const plat_pollent *e, int n)
{
	int i, j;
	for (i = 0; i < n; i++) {
		if (!e[i].got)
			continue;
		if (e[i].sock == listen_sock) {
			int s = plat_accept(listen_sock);
			for (j = 0; j < MAX_CLIENTS && s >= 0; j++)
				if (cl[j].state == S_FREE) {
					memset(&cl[j], 0, sizeof cl[j]);
					cl[j].sock = s;
					cl[j].state = S_GREET;
					s = -1;
				}
			if (s >= 0)
				plat_close(s);
			continue;
		}
		for (j = 0; j < MAX_CLIENTS; j++)
			if (cl[j].state != S_FREE && cl[j].sock == e[i].sock && (e[i].got & PLAT_RD))
				on_client_data(&cl[j]);
	}
}

void socks_flush(void)
{
	int i;
	for (i = 0; i < MAX_CLIENTS; i++) {
		client *c = &cl[i];
		if (c->state == S_FREE)
			continue;
		if (c->outlen) {
			int w = plat_send_some(c->sock, c->out, c->outlen);
			if (w < 0) {
				drop(c);
				continue;
			}
			memmove(c->out, c->out + w, c->outlen - (size_t)w);
			c->outlen -= (size_t)w;
			if (c->pcb && w)
				tcp_recved(c->pcb, (u16_t)w);
		}
		if (c->remote_closed && !c->outlen)
			drop(c);
	}
}
