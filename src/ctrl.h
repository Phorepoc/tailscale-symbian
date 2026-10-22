// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// Control-plane client: /key, the ts2021 Noise IK upgrade, and a minimal
// HTTP/2 (h2c) client running inside the Noise transport.
#ifndef PHETAIL_CTRL_H
#define PHETAIL_CTRL_H

#include <stddef.h>
#include <stdint.h>

typedef struct ctrl {
	int sock;
	uint8_t txk[32], rxk[32];
	uint64_t txn, rxn;
	uint8_t raw[8192];      /* undecrypted bytes from the socket */
	size_t rawlen;
	uint8_t pt[4096];       /* decrypted, not yet consumed */
	size_t ptoff, ptlen;
	uint32_t next_stream;
	char host[128];
	int port;
	int stop_after_msg; /* return once one LE32-length-framed message has arrived (map streams) */
} ctrl;

/* GET /key; fills the server's Noise public key. 0 = ok. */
int ctrl_fetch_key(const char *host, int port, int capver, uint8_t server_pub[32]);
/* TCP connect, ts2021 upgrade, Noise IK handshake, HTTP/2 preface. 0 = ok. */
int ctrl_connect(ctrl *c, const char *host, int port, int capver, const uint8_t machine_priv[32],
		 const uint8_t server_pub[32]);
/* One HTTP/2 POST; *out is malloc'd (NUL-terminated), caller frees. Returns HTTP-ish
 * status: 0 = ok, -1 = error. */
int ctrl_post(ctrl *c, const char *path, const char *body, size_t len, char **out, size_t *outlen);
void ctrl_close(ctrl *c);

#endif
