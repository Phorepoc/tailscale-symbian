// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// phetail spike driver.
//   phetail <host> <port> <authkey> [statefile]          S0: register + first map
//   ... with PHETAIL_PING=1 also runs S1: DERP + WireGuard + ICMP to the first peer.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctrl.h"
#include "derpwg.h"
#include "plat.h"
#include "tcrypto.h"
#include "util.h"

#define CAPVER 130

typedef struct {
	uint8_t machine[32], node[32], disco[32];
} keys;

static int load_keys(const char *path, keys *k)
{
	FILE *f = fopen(path, "rb");
	if (f) {
		size_t n = fread(k, 1, sizeof *k, f);
		fclose(f);
		if (n == sizeof *k)
			return 0;
	}
	{
		uint8_t pub[32];
		tc_keypair(k->machine, pub);
		tc_keypair(k->node, pub);
		tc_keypair(k->disco, pub);
	}
	f = fopen(path, "wb");
	if (!f)
		return -1;
	fwrite(k, 1, sizeof *k, f);
	fclose(f);
	return 0;
}

static void hostinfo(char *out, size_t cap)
{
	snprintf(out, cap, "{\"IPNVersion\":\"1.80.0-phetail\",\"OS\":\"linux\",\"Hostname\":\"phetail\","
			   "\"GoArch\":\"amd64\",\"FrontendLogID\":\"\",\"BackendLogID\":\"\"}");
}

int main(int argc, char **argv)
{
	const char *host, *authkey, *state;
	int port;
	keys k;
	uint8_t spub[32], npub[32], dpub[32];
	char nhex[65], dhex[65], hi[256], *body, *resp;
	size_t rlen;
	ctrl c;

	if (argc < 4) {
		fprintf(stderr, "usage: %s <host> <port> <authkey> [statefile]\n", argv[0]);
		return 2;
	}
	host = argv[1];
	port = atoi(argv[2]);
	authkey = argv[3];
	state = argc > 4 ? argv[4] : "phetail.state";
	if (load_keys(state, &k))
		return 1;
	tc_x25519_pub(npub, k.node);
	tc_x25519_pub(dpub, k.disco);
	tc_hex(nhex, npub, 32);
	tc_hex(dhex, dpub, 32);

	if (ctrl_fetch_key(host, port, CAPVER, spub)) {
		fprintf(stderr, "GET /key failed\n");
		return 1;
	}
	{
		char sh[65];
		tc_hex(sh, spub, 32);
		printf("key: server noise key mkey:%s\n", sh);
	}
	if (ctrl_connect(&c, host, port, CAPVER, k.machine, spub))
		return 1;

	hostinfo(hi, sizeof hi);
	body = malloc(2048);
	snprintf(body, 2048,
		 "{\"Version\":%d,\"NodeKey\":\"nodekey:%s\",\"OldNodeKey\":\"nodekey:"
		 "0000000000000000000000000000000000000000000000000000000000000000\","
		 "\"Auth\":{\"AuthKey\":\"%s\"},\"Hostinfo\":%s}",
		 CAPVER, nhex, authkey, hi);
	if (ctrl_post(&c, "/machine/register", body, strlen(body), &resp, &rlen)) {
		fprintf(stderr, "register failed: %s\n", resp);
		return 1;
	}
	printf("register: %s\n", resp);
	free(resp);

	snprintf(body, 2048,
		 "{\"Version\":%d,\"NodeKey\":\"nodekey:%s\",\"DiscoKey\":\"discokey:%s\",\"Stream\":true,"
		 "\"Compress\":\"\",\"KeepAlive\":false,\"OmitPeers\":false,\"Hostinfo\":%s}",
		 CAPVER, nhex, dhex, hi);
	c.stop_after_msg = 1;
	if (ctrl_post(&c, "/machine/map", body, strlen(body), &resp, &rlen)) {
		fprintf(stderr, "map failed: %s\n", resp);
		return 1;
	}
	if (rlen < 4) {
		fprintf(stderr, "map: short response\n");
		return 1;
	}
	{
		uint32_t jl = get_le32((uint8_t *)resp);
		char *json = resp + 4;
		if (jl < rlen - 4)
			json[jl] = 0;
		printf("map: %u bytes of JSON\n%s\n", jl, json);
		if (getenv("PHETAIL_PING"))
			return s1_run(host, port, k.node, json) ? 1 : 0;
	}
	ctrl_close(&c);
	return 0;
}
