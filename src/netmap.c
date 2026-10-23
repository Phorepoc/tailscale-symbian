// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// Map response handling with jsmn: self address, full peer lists,
// PeersChanged / PeersRemoved deltas, keepalives.
#include <stdio.h>
#include "log.h"
#include <stdlib.h>
#include <string.h>

#define JSMN_STATIC
#include "../vendor/jsmn/jsmn.h"
#include "tail.h"
#include "tcrypto.h"

typedef struct {
	const char *js;
	jsmntok_t *t;
	int n;
} doc;

/* Index of the token after token i and all its children. */
static int skip(const doc *d, int i)
{
	int end = d->t[i].end;
	i++;
	while (i < d->n && d->t[i].start < end)
		i++;
	return i;
}

static int eq(const doc *d, int i, const char *s)
{
	size_t l = strlen(s);
	return d->t[i].type == JSMN_STRING && (size_t)(d->t[i].end - d->t[i].start) == l &&
	       memcmp(d->js + d->t[i].start, s, l) == 0;
}

/* Value token of key in object o, or -1. */
static int get(const doc *d, int o, const char *key)
{
	int i, k;
	if (o < 0 || d->t[o].type != JSMN_OBJECT)
		return -1;
	for (i = o + 1, k = 0; k < d->t[o].size; k++) {
		if (eq(d, i, key))
			return i + 1;
		i = skip(d, i + 1);
	}
	return -1;
}

static void str(const doc *d, int i, char *out, size_t cap)
{
	size_t l;
	out[0] = 0;
	if (i < 0 || (d->t[i].type != JSMN_STRING && d->t[i].type != JSMN_PRIMITIVE))
		return;
	l = (size_t)(d->t[i].end - d->t[i].start);
	if (l >= cap)
		l = cap - 1;
	memcpy(out, d->js + d->t[i].start, l);
	out[l] = 0;
}

static int keyhex(const doc *d, int i, const char *prefix, uint8_t k[32])
{
	char s[128];
	size_t pl = strlen(prefix);
	str(d, i, s, sizeof s);
	return strncmp(s, prefix, pl) == 0 && tc_unhex(k, s + pl, 32) == 0 ? 0 : -1;
}

static int first_ip4(const doc *d, int arr, uint8_t ip[4])
{
	int i, k;
	unsigned a, b, c, e;
	char s[64];
	if (arr < 0 || d->t[arr].type != JSMN_ARRAY)
		return -1;
	for (i = arr + 1, k = 0; k < d->t[arr].size; k++, i = skip(d, i)) {
		str(d, i, s, sizeof s);
		if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &e) == 4) {
			ip[0] = (uint8_t)a, ip[1] = (uint8_t)b, ip[2] = (uint8_t)c, ip[3] = (uint8_t)e;
			return 0;
		}
	}
	return -1;
}

static void short_name(char *out, size_t cap, const char *fqdn)
{
	size_t l = strcspn(fqdn, ".");
	if (l >= cap)
		l = cap - 1;
	memcpy(out, fqdn, l);
	out[l] = 0;
}

static void apply_peer(const doc *d, int o)
{
	uint8_t k[32];
	peer *p;
	char s[128];
	int i, v;
	if (keyhex(d, get(d, o, "Key"), "nodekey:", k))
		return;
	p = peer_by_nodekey(k);
	if (!p) {
		for (i = 0; i < MAX_PEERS && g_tail.peers[i].used; i++)
			;
		if (i == MAX_PEERS)
			return;
		p = &g_tail.peers[i];
		memset(p, 0, sizeof *p);
		p->used = 1;
		memcpy(p->nodekey, k, 32);
	}
	keyhex(d, get(d, o, "DiscoKey"), "discokey:", p->discokey);
	first_ip4(d, get(d, o, "Addresses"), p->ip4);
	if ((v = get(d, o, "Name")) >= 0) {
		str(d, v, s, sizeof s);
		short_name(p->name, sizeof p->name, s);
	}
	if ((v = get(d, o, "HomeDERP")) >= 0) {
		str(d, v, s, sizeof s);
		p->home_derp = atoi(s);
	}
	printf("netmap: peer %s %u.%u.%u.%u derp %d\n", p->name, p->ip4[0], p->ip4[1], p->ip4[2], p->ip4[3],
	       p->home_derp);
}

static void apply_peer_list(const doc *d, int arr, int full)
{
	int i, k;
	if (arr < 0 || d->t[arr].type != JSMN_ARRAY)
		return;
	if (full) {
		/* A full list replaces the table; keep WireGuard state of peers that stay. */
		peer old[MAX_PEERS];
		memcpy(old, g_tail.peers, sizeof old);
		memset(g_tail.peers, 0, sizeof g_tail.peers);
		for (i = arr + 1, k = 0; k < d->t[arr].size; k++, i = skip(d, i))
			apply_peer(d, i);
		for (k = 0; k < MAX_PEERS; k++) {
			peer *p = old[k].used ? peer_by_nodekey(old[k].nodekey) : NULL;
			if (p) {
				p->cur = old[k].cur;
				p->prev = old[k].prev;
				p->hs = old[k].hs;
			}
		}
		return;
	}
	for (i = arr + 1, k = 0; k < d->t[arr].size; k++, i = skip(d, i))
		apply_peer(d, i);
}

int netmap_apply(const char *json, size_t len)
{
	doc d;
	int n, v;
	jsmn_parser jp;

	jsmn_init(&jp);
	n = jsmn_parse(&jp, json, len, NULL, 0);
	if (n <= 0)
		return -1;
	d.js = json;
	d.n = n;
	d.t = malloc(sizeof(jsmntok_t) * (size_t)n);
	jsmn_init(&jp);
	jsmn_parse(&jp, json, len, d.t, (unsigned)n);

	if ((v = get(&d, 0, "KeepAlive")) >= 0 && d.js[d.t[v].start] == 't' && d.t[0].size == 1) {
		free(d.t);
		return 0;
	}
	if ((v = get(&d, 0, "Node")) >= 0) {
		char s[128];
		first_ip4(&d, get(&d, v, "Addresses"), g_tail.ip4);
		str(&d, get(&d, v, "Name"), s, sizeof s);
		short_name(g_tail.name, sizeof g_tail.name, s);
		if (!g_tail.have_ip) {
			g_tail.have_ip = 1;
			tun_set_addr(g_tail.ip4);
		}
		printf("netmap: self %s %u.%u.%u.%u\n", g_tail.name, g_tail.ip4[0], g_tail.ip4[1], g_tail.ip4[2],
		       g_tail.ip4[3]);
	}
	if ((v = get(&d, 0, "Peers")) >= 0)
		apply_peer_list(&d, v, 1);
	if ((v = get(&d, 0, "PeersChanged")) >= 0)
		apply_peer_list(&d, v, 0);
	if ((v = get(&d, 0, "PeersRemoved")) >= 0 && d.t[v].type == JSMN_ARRAY) {
		/* Removed peers are given by node ID; the spike keeps them (harmless). */
		printf("netmap: %d peers removed (ignored)\n", d.t[v].size);
	}
	free(d.t);
	return 0;
}
