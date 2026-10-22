// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// Control-plane client: /key, the ts2021 Noise IK upgrade, and a minimal
// HTTP/2 (h2c) client running inside the Noise transport.
//
// Setup (ctrl_fetch_key, ctrl_connect, ctrl_post) blocks; the long-lived map
// stream is driven from the event loop with ctrl_on_readable + ctrl_next_msg.
#ifndef PHETAIL_CTRL_H
#define PHETAIL_CTRL_H

#include <stddef.h>
#include <stdint.h>

#define CTRL_MAX_STREAMS 4

typedef struct {
	uint32_t sid;      /* 0 = free slot */
	char *buf;
	size_t len, cap;
	int done;          /* END_STREAM / RST seen */
	int status;        /* 0 = 200, 1 = other, -1 = no headers yet */
} ctrl_stream;

typedef struct ctrl {
	int sock;
	uint8_t txk[32], rxk[32];
	uint64_t txn, rxn;
	uint8_t raw[8192];      /* undecrypted bytes from the socket */
	size_t rawlen;
	uint8_t *h2in;          /* decrypted HTTP/2 bytes not yet parsed */
	size_t h2len, h2cap;
	uint32_t next_stream;
	ctrl_stream st[CTRL_MAX_STREAMS];
	int dead;
	char host[128];
	int port;
} ctrl;

/* GET /key; fills the server's Noise public key. 0 = ok. */
int ctrl_fetch_key(const char *host, int port, int capver, uint8_t server_pub[32]);
/* TCP connect, ts2021 upgrade, Noise IK handshake, HTTP/2 preface. 0 = ok. */
int ctrl_connect(ctrl *c, const char *host, int port, int capver, const uint8_t machine_priv[32],
		 const uint8_t server_pub[32]);
/* Starts a POST; returns the stream id or 0. */
uint32_t ctrl_open(ctrl *c, const char *path, const char *body, size_t len);
/* Blocking POST; *out is malloc'd (NUL-terminated), caller frees. 0 = 200 OK. */
int ctrl_post(ctrl *c, const char *path, const char *body, size_t len, char **out, size_t *outlen);
/* Event loop hook: socket readable. Returns -1 when the connection is gone. */
int ctrl_on_readable(ctrl *c);
/* Pops the next LE32-length-framed message of a streaming response (map).
 * Returns a malloc'd NUL-terminated JSON string or NULL. */
char *ctrl_next_msg(ctrl *c, uint32_t sid);
void ctrl_close(ctrl *c);

#endif
