// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// Platform layer: the only place the core touches the OS. A POSIX version
// lives in plat_posix.c; a Symbian Open C one can follow the same contract.
#ifndef PHETAIL_PLAT_H
#define PHETAIL_PLAT_H

#include <stddef.h>
#include <stdint.h>

/* Opaque TCP stream handle; negative = error. */
int plat_tcp_connect(const char *host, int port);
/* Write all bytes; 0 on success, -1 on error. */
int plat_send_all(int s, const void *buf, size_t len);
/* Read up to len bytes, waiting at most timeout_ms (-1 = forever).
 * Returns bytes read, 0 on timeout, -1 on error/EOF. */
int plat_recv(int s, void *buf, size_t len, int timeout_ms);
void plat_close(int s);
/* Non-blocking send: bytes accepted (0 = would block), -1 on error. */
int plat_send_some(int s, const void *buf, size_t len);

/* Listening TCP socket on 127.0.0.1:port (local proxy front-ends). */
int plat_tcp_listen_local(int port);
/* Accepts one pending connection, or -1. */
int plat_accept(int ls);

/* Readiness wait over a set of handles: the one blocking point of the event
 * loop. want/got: PLAT_RD | PLAT_WR. Returns number ready, 0 on timeout. */
#define PLAT_RD 1
#define PLAT_WR 2
typedef struct {
	int sock;
	short want, got;
} plat_pollent;
int plat_poll(plat_pollent *ents, int n, int timeout_ms);

/* Cryptographically secure random bytes; 0 on success. */
int plat_random(void *buf, size_t len);
/* Wall-clock time: seconds and nanoseconds since the Unix epoch. */
void plat_time(uint64_t *sec, uint32_t *nsec);
/* Monotonic milliseconds. */
uint64_t plat_ms(void);

#endif
