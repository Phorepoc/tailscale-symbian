// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// phetaild: joins a tailnet and exposes it as a SOCKS5 proxy.
//   phetaild <control-host> <port> <authkey> [statefile] [socks-port]
//
// One thread, one blocking point (plat_poll) and a periodic timer tick:
// the shape of a single active-object loop.
#include <stdio.h>
#include "log.h"
#include <stdlib.h>
#include <string.h>

#include "ctrl.h"
#include "derp.h"
#include "net.h"
#include "plat.h"
#include "socks.h"
#include "tail.h"
#include "tcrypto.h"
#include "util.h"

#define CAPVER 130
#define TICK_MS 100
#define CTRL_SILENT_MS 180000   /* Headscale keepalives come about every minute */
#define MAX_BACKOFF_MS 30000

static int socks_up;
static uint64_t g_stop_at;   /* --max-seconds: leave cleanly (stdio closed, the log is complete) */
static int g_stop;

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

/* One control + DERP session: register, map stream, DERP, then the event loop. Returns when either connection is lost (or
 * fails to come up); *up_ms is set to how long the session ran fully connected (0 = never got there). */
static int session(const char *host, int port, const char *authkey, const uint8_t machine[32], int socks_port, uint64_t *up_ms)
{
	uint8_t spub[32];
	char nhex[65], dhex[65], body[2048], *resp, *msg;
	size_t rlen;
	uint32_t map_sid;
	uint64_t last_tick = 0, started, last_ctrl;
	int rc = 1;
	ctrl c;

	*up_ms = 0;
	memset(&c, 0, sizeof c);
	c.sock = -1;
	tc_hex(nhex, g_tail.node_pub, 32);
	tc_hex(dhex, g_tail.disco_pub, 32);
	if (ctrl_fetch_key(host, port, CAPVER, spub) || ctrl_connect(&c, host, port, CAPVER, machine, spub))
		goto out;
	snprintf(body, sizeof body,
		 "{\"Version\":%d,\"NodeKey\":\"nodekey:%s\",\"OldNodeKey\":\"nodekey:"
		 "0000000000000000000000000000000000000000000000000000000000000000\","
		 "\"Auth\":{\"AuthKey\":\"%s\"},\"Hostinfo\":%s}",
		 CAPVER, nhex, authkey, HOSTINFO);
	if (ctrl_post(&c, "/machine/register", body, strlen(body), &resp, &rlen)) {
		fprintf(stderr, "register failed: %s\n", resp ? resp : "(no reply)");
		free(resp);
		goto out;
	}
	printf("register: %s\n", strstr(resp, "\"MachineAuthorized\":true") ? "authorized" : resp);
	free(resp);

	snprintf(body, sizeof body,
		 "{\"Version\":%d,\"NodeKey\":\"nodekey:%s\",\"DiscoKey\":\"discokey:%s\",\"Stream\":true,"
		 "\"Compress\":\"\",\"KeepAlive\":true,\"OmitPeers\":false,\"Hostinfo\":%s}",
		 CAPVER, nhex, dhex, HOSTINFO);
	map_sid = ctrl_open(&c, "/machine/map", body, strlen(body));
	started = plat_ms();
	while (!(msg = ctrl_next_msg(&c, map_sid))) {
		plat_pollent one;
		if (plat_ms() - started > 30000) {
			fprintf(stderr, "map: no first message in 30 s\n");
			goto out;
		}
		one.sock = c.sock;
		one.want = PLAT_RD;
		plat_poll(&one, 1, 1000);
		if (net_pending(c.sock) || one.got) {
			if (ctrl_on_readable(&c))
				goto out;
		}
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
		goto out;
	if (socks_port >= 0 && !socks_up && socks_listen(socks_port) == 0)
		socks_up = 1;
	started = plat_ms();
	last_ctrl = started;
	*up_ms = 1;

	for (;;) {
		plat_pollent e[40];
		int n = 0, ns, pend;
		uint64_t now;
		e[n].sock = c.sock;
		e[n++].want = PLAT_RD;
		e[n].sock = derp_sock();
		e[n++].want = PLAT_RD;
		ns = socks_poll_set(e + n, 38);
		pend = net_pending(c.sock) || net_pending(derp_sock());
		plat_poll(e, n + ns, pend ? 0 : TICK_MS);
		if ((e[0].got || net_pending(c.sock)) && ctrl_on_readable(&c)) {
			fprintf(stderr, "control connection lost\n");
			break;
		}
		if (e[0].got)
			last_ctrl = plat_ms();
		while ((msg = ctrl_next_msg(&c, map_sid)) != NULL) {
			if (!strstr(msg, "\"KeepAlive\":true") || strlen(msg) > 40)
				printf("map: update %u bytes\n", (unsigned)strlen(msg));
			netmap_apply(msg, strlen(msg));
			free(msg);
		}
		if ((e[1].got || net_pending(derp_sock())) && derp_on_readable())
			break;
		socks_handle(e + n, ns);
		socks_flush();
		now = plat_ms();
		if (now - last_ctrl > CTRL_SILENT_MS) {
			fprintf(stderr, "control stream silent for %d s: reconnecting\n", CTRL_SILENT_MS / 1000);
			break;
		}
		if (g_stop_at && now >= g_stop_at) {
			printf("max-seconds reached: leaving\n");
			g_stop = 1;
			break;
		}
		if (now - last_tick >= TICK_MS) {
			last_tick = now;
			tun_timers();
			wg_timers(now);
		}
	}
	*up_ms = plat_ms() - started + 1;
out:
	derp_close();
	ctrl_close(&c);
	return rc;
}

/* Command line: positional <host> <port> <authkey> [statefile] [socks-port]; options anywhere:
 *   --tls-pin <64 hex>   TLS (mbedTLS) to the control/DERP server, certificate pinned by SHA-256 of its DER encoding
 *   --args <file>        read the arguments from a text file instead (whitespace separated)
 *   --max-sessions <n>   (tests) stop after n sessions */
static char *g_av[48];
static char g_text[2500];

static int args_from_file(const char *path, int *argc, char ***argv)
{
	FILE *f = fopen(path, "rb");
	int n, ac = 0;
	char *p;
	if (!f)
		return -1;
	n = (int)fread(g_text, 1, sizeof g_text - 1, f);
	fclose(f);
	g_text[n] = 0;
	g_av[ac++] = (*argv)[0];
	for (p = g_text; *p && ac < 47;) {
		while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
			p++;
		if (!*p)
			break;
		g_av[ac++] = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
			p++;
		if (*p)
			*p++ = 0;
	}
	*argc = ac;
	*argv = g_av;
	return 0;
}

int main(int argc, char **argv)
{
	const char *host, *authkey, *state, *pos[8];
	int port, socks_port, i, npos = 0, max_sessions = 0, sessions = 0;
	uint8_t machine[32];
	uint32_t backoff = 1000;

	if (argc >= 3 && strcmp(argv[1], "--args") == 0 && args_from_file(argv[2], &argc, &argv)) {
		fprintf(stderr, "cannot read the argument file\n");
		return 2;
	}
	if (plat_init(argc, argv))
		return 1;
	setvbuf(stdout, NULL, _IOLBF, 0);
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--tls-pin") == 0 && i + 1 < argc) {
			uint8_t pin[32];
			int k;
			const char *h = argv[++i];
			if (strlen(h) != 64) {
				fprintf(stderr, "--tls-pin wants 64 hex digits\n");
				return 2;
			}
			for (k = 0; k < 32; k++) {
				unsigned v;
				if (sscanf(h + 2 * k, "%2x", &v) != 1)
					return 2;
				pin[k] = (uint8_t)v;
			}
			if (net_set_tls(pin)) {
				fprintf(stderr, "this build has no TLS\n");
				return 2;
			}
		} else if (strcmp(argv[i], "--max-seconds") == 0 && i + 1 < argc) {
			g_stop_at = plat_ms() + (uint64_t)atoi(argv[++i]) * 1000;
		} else if (strcmp(argv[i], "--max-sessions") == 0 && i + 1 < argc) {
			max_sessions = atoi(argv[++i]);
		} else if (npos < 8) {
			pos[npos++] = argv[i];
		}
	}
	if (npos < 3) {
		fprintf(stderr, "usage: %s <host> <port> <authkey> [statefile] [socks-port] [--tls-pin <hex>] [--args <file>]\n", argv[0]);
		return 2;
	}
	host = pos[0];
	port = atoi(pos[1]);
	authkey = pos[2];
	state = npos > 3 ? pos[3] : "phetail.state";
	socks_port = npos > 4 ? atoi(pos[4]) : 1055;
	if (load_keys(state, machine))
		return 1;
	tun_init();

	for (;;) {
		uint64_t up;
		int r = session(host, port, authkey, machine, socks_port, &up);
		sessions++;
		(void)r;
		if (g_stop) {
			fflush(stdout);
			return 0;
		}
		if (max_sessions && sessions >= max_sessions)
			return 1;
		if (up > 30000)
			backoff = 1000;      /* it ran: start again quickly */
		printf("reconnect in %u ms\n", (unsigned)backoff);
		plat_poll(NULL, 0, (int)backoff);
		if (backoff < MAX_BACKOFF_MS)
			backoff = backoff * 2 > MAX_BACKOFF_MS ? MAX_BACKOFF_MS : backoff * 2;
	}
}
