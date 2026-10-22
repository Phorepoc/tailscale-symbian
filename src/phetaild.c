// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// phetaild: joins a tailnet and exposes it as a SOCKS5 proxy.
//   phetaild <control-host> <port> <authkey> [statefile] [socks-port]
//
// One thread, one blocking point (plat_poll) and a periodic timer tick:
// the shape of a single active-object loop.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctrl.h"
#include "derp.h"
#include "plat.h"
#include "socks.h"
#include "tail.h"
#include "tcrypto.h"
#include "util.h"

#define CAPVER 130
#define TICK_MS 100

tailstate g_tail;

peer *peer_by_nodekey(const uint8_t k[32])
{
	int i;
	for (i = 0; i < MAX_PEERS; i++)
		if (g_tail.peers[i].used && memcmp(g_tail.peers[i].nodekey, k, 32) == 0)
			return &g_tail.peers[i];
	return NULL;
}

peer *peer_by_ip4(const uint8_t ip[4])
{
	int i;
	for (i = 0; i < MAX_PEERS; i++)
		if (g_tail.peers[i].used && memcmp(g_tail.peers[i].ip4, ip, 4) == 0)
			return &g_tail.peers[i];
	return NULL;
}

peer *peer_by_name(const char *name)
{
	int i;
	for (i = 0; i < MAX_PEERS; i++)
		if (g_tail.peers[i].used && strcmp(g_tail.peers[i].name, name) == 0)
			return &g_tail.peers[i];
	return NULL;
}

static int load_keys(const char *path, uint8_t machine[32])
{
	uint8_t k[96], pub[32];
	FILE *f = fopen(path, "rb");
	size_t n = 0;
	if (f) {
		n = fread(k, 1, sizeof k, f);
		fclose(f);
	}
	if (n != sizeof k) {
		tc_keypair(k, pub);
		tc_keypair(k + 32, pub);
		tc_keypair(k + 64, pub);
		f = fopen(path, "wb");
		if (!f)
			return -1;
		fwrite(k, 1, sizeof k, f);
		fclose(f);
	}
	memcpy(machine, k, 32);
	memcpy(g_tail.node_priv, k + 32, 32);
	memcpy(g_tail.disco_priv, k + 64, 32);
	tc_x25519_pub(g_tail.node_pub, g_tail.node_priv);
	tc_x25519_pub(g_tail.disco_pub, g_tail.disco_priv);
	return 0;
}

static const char HOSTINFO[] = "{\"IPNVersion\":\"1.80.0-phetail\",\"OS\":\"linux\",\"Hostname\":\"phetail\","
			       "\"NetInfo\":{\"PreferredDERP\":999}}";

int main(int argc, char **argv)
{
	const char *host, *authkey, *state;
	int port, socks_port;
	uint8_t machine[32], spub[32];
	char nhex[65], dhex[65], body[2048], *resp, *msg;
	size_t rlen;
	uint32_t map_sid;
	uint64_t last_tick = 0;
	ctrl c;

	if (argc < 4) {
		fprintf(stderr, "usage: %s <host> <port> <authkey> [statefile] [socks-port]\n", argv[0]);
		return 2;
	}
	if (plat_init(argc, argv))
		return 1;
	setvbuf(stdout, NULL, _IOLBF, 0);
	host = argv[1];
	port = atoi(argv[2]);
	authkey = argv[3];
	state = argc > 4 ? argv[4] : "phetail.state";
	socks_port = argc > 5 ? atoi(argv[5]) : 1055;
	if (load_keys(state, machine))
		return 1;
	tc_hex(nhex, g_tail.node_pub, 32);
	tc_hex(dhex, g_tail.disco_pub, 32);
	tun_init();

	if (ctrl_fetch_key(host, port, CAPVER, spub) || ctrl_connect(&c, host, port, CAPVER, machine, spub))
		return 1;
	snprintf(body, sizeof body,
		 "{\"Version\":%d,\"NodeKey\":\"nodekey:%s\",\"OldNodeKey\":\"nodekey:"
		 "0000000000000000000000000000000000000000000000000000000000000000\","
		 "\"Auth\":{\"AuthKey\":\"%s\"},\"Hostinfo\":%s}",
		 CAPVER, nhex, authkey, HOSTINFO);
	if (ctrl_post(&c, "/machine/register", body, strlen(body), &resp, &rlen)) {
		fprintf(stderr, "register failed: %s\n", resp);
		return 1;
	}
	printf("register: %s\n", strstr(resp, "\"MachineAuthorized\":true") ? "authorized" : resp);
	free(resp);

	snprintf(body, sizeof body,
		 "{\"Version\":%d,\"NodeKey\":\"nodekey:%s\",\"DiscoKey\":\"discokey:%s\",\"Stream\":true,"
		 "\"Compress\":\"\",\"KeepAlive\":true,\"OmitPeers\":false,\"Hostinfo\":%s}",
		 CAPVER, nhex, dhex, HOSTINFO);
	map_sid = ctrl_open(&c, "/machine/map", body, strlen(body));
	while (!(msg = ctrl_next_msg(&c, map_sid))) {
		plat_pollent one;
		one.sock = c.sock;
		one.want = PLAT_RD;
		plat_poll(&one, 1, 1000);
		if (ctrl_on_readable(&c))
			return 1;
	}
	printf("map: first message %u bytes\n", (unsigned)strlen(msg));
	netmap_apply(msg, strlen(msg));
	free(msg);

	/* "Lite" endpoint update once the stream is up (as tailscaled does): Headscale
	 * takes Hostinfo/NetInfo (our home DERP) from non-streaming requests and only
	 * pushes the change to peers while we are online. */
	snprintf(body, sizeof body,
		 "{\"Version\":%d,\"NodeKey\":\"nodekey:%s\",\"DiscoKey\":\"discokey:%s\",\"Stream\":false,"
		 "\"OmitPeers\":true,\"Hostinfo\":%s}",
		 CAPVER, nhex, dhex, HOSTINFO);
	if (ctrl_post(&c, "/machine/map", body, strlen(body), &resp, &rlen) == 0)
		printf("map: lite update (home DERP 999) accepted\n");
	free(resp);

	if (derp_connect(host, port))
		return 1;
	if (socks_listen(socks_port))
		return 1;

	for (;;) {
		plat_pollent e[40];
		int n = 0, ns;
		uint64_t now;
		e[n].sock = c.sock;
		e[n++].want = PLAT_RD;
		e[n].sock = derp_sock();
		e[n++].want = PLAT_RD;
		ns = socks_poll_set(e + n, 38);
		plat_poll(e, n + ns, TICK_MS);
		if (e[0].got && ctrl_on_readable(&c)) {
			fprintf(stderr, "control connection lost\n");
			return 1;
		}
		while ((msg = ctrl_next_msg(&c, map_sid)) != NULL) {
			if (!strstr(msg, "\"KeepAlive\":true") || strlen(msg) > 40)
				printf("map: update %u bytes\n", (unsigned)strlen(msg));
			netmap_apply(msg, strlen(msg));
			free(msg);
		}
		if (e[1].got && derp_on_readable())
			return 1;
		socks_handle(e + n, ns);
		socks_flush();
		now = plat_ms();
		if (now - last_tick >= TICK_MS) {
			last_tick = now;
			tun_timers();
			wg_timers(now);
		}
	}
}
