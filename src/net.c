// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
#include "net.h"

#include <stdio.h>
#include "log.h"
#include <string.h>

#include "plat.h"

#ifndef PHETAIL_TLS

int net_set_tls(const uint8_t pin[32]) { (void)pin; return -1; }
int net_connect(const char *host, int port) { return plat_tcp_connect(host, port); }
int net_send_all(int s, const void *buf, size_t len) { return plat_send_all(s, buf, len); }
int net_recv(int s, void *buf, size_t len, int timeout_ms)
{
	int r = plat_recv(s, buf, len, timeout_ms);
	return r > 0 ? r : (r == 0 ? NET_TIMEOUT : 0);      /* plat_recv: 0 = timeout, -1 = EOF or error */
}
void net_close(int s) { plat_close(s); }
int net_pending(int s) { (void)s; return 0; }

#else

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#define MAXFD 128

typedef struct {
	int used, fd;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
} tlsconn;

static tlsconn g_conn[MAXFD];
static int g_tls;
static uint8_t g_pin[32];

int mbedtls_hardware_poll(void *data, unsigned char *out, size_t len, size_t *olen)
{
	(void)data;
	if (plat_random(out, len))
		return -1;
	*olen = len;
	return 0;
}

mbedtls_ms_time_t mbedtls_ms_time(void) { return (mbedtls_ms_time_t)plat_ms(); }

int net_set_tls(const uint8_t pin[32])
{
	memcpy(g_pin, pin, 32);
	g_tls = 1;
	return 0;
}

static tlsconn *find(int s)
{
	int i;
	for (i = 0; i < MAXFD; i++)
		if (g_conn[i].used && g_conn[i].fd == s)
			return &g_conn[i];
	return NULL;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	tlsconn *t = (tlsconn *)ctx;
	return plat_send_all(t->fd, buf, len) ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : (int)len;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	tlsconn *t = (tlsconn *)ctx;
	int r = plat_recv(t->fd, buf, len, 0);
	if (r > 0)
		return r;
	return r == 0 ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_SSL_CONN_EOF;
}

static void teardown(tlsconn *t)
{
	if (!t->used)
		return;
	mbedtls_ssl_free(&t->ssl);
	mbedtls_ssl_config_free(&t->conf);
	mbedtls_ctr_drbg_free(&t->drbg);
	mbedtls_entropy_free(&t->entropy);
	t->used = 0;
}

int net_connect(const char *host, int port)
{
	tlsconn *t = NULL;
	int s, i, rc, tries;
	unsigned char hash[32];
	size_t hl = 0;
	const mbedtls_x509_crt *crt;
	static const char pers[] = "phetail";

	s = plat_tcp_connect(host, port);
	if (s < 0 || !g_tls)
		return s;
	for (i = 0; i < MAXFD; i++)
		if (!g_conn[i].used) { t = &g_conn[i]; break; }
	if (!t) { plat_close(s); return -1; }
	memset(t, 0, sizeof *t);
	t->used = 1;
	t->fd = s;
	mbedtls_ssl_init(&t->ssl);
	mbedtls_ssl_config_init(&t->conf);
	mbedtls_entropy_init(&t->entropy);
	mbedtls_ctr_drbg_init(&t->drbg);
	if (psa_crypto_init() != PSA_SUCCESS)
		goto fail;
	if (mbedtls_ctr_drbg_seed(&t->drbg, mbedtls_entropy_func, &t->entropy, (const unsigned char *)pers, sizeof pers - 1))
		goto fail;
	if (mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT))
		goto fail;
	mbedtls_ssl_conf_min_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_rng(&t->conf, mbedtls_ctr_drbg_random, &t->drbg);
	mbedtls_ssl_conf_session_tickets(&t->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);   /* the client keeps no tickets: discard them */
	mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_NONE);   /* the pin replaces chain validation */
	if (mbedtls_ssl_setup(&t->ssl, &t->conf) || mbedtls_ssl_set_hostname(&t->ssl, host))
		goto fail;
	mbedtls_ssl_set_bio(&t->ssl, t, bio_send, bio_recv, NULL);
	for (tries = 0; (rc = mbedtls_ssl_handshake(&t->ssl)) != 0;) {
		if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
			fprintf(stderr, "net: TLS handshake failed: -0x%04x\n", (unsigned)-rc);
			goto fail;
		}
		if (++tries > 600) {   /* ~30 s */
			fprintf(stderr, "net: TLS handshake timed out\n");
			goto fail;
		}
		{
			plat_pollent pe;
			pe.sock = s; pe.want = PLAT_RD; pe.got = 0;
			plat_poll(&pe, 1, 50);
		}
	}
	crt = mbedtls_ssl_get_peer_cert(&t->ssl);
	if (!crt || psa_hash_compute(PSA_ALG_SHA_256, crt->raw.p, crt->raw.len, hash, sizeof hash, &hl) != PSA_SUCCESS || hl != 32)
		goto fail;
	if (memcmp(hash, g_pin, 32) != 0) {
		fprintf(stderr, "net: TLS server certificate does not match the pin\n");
		goto fail;
	}
	return s;
fail:
	teardown(t);
	plat_close(s);
	return -1;
}

int net_send_all(int s, const void *buf, size_t len)
{
	tlsconn *t = find(s);
	size_t off = 0;
	if (!t)
		return plat_send_all(s, buf, len);
	while (off < len) {
		int rc = mbedtls_ssl_write(&t->ssl, (const unsigned char *)buf + off, len - off);
		if (rc > 0) { off += (size_t)rc; continue; }
		if (rc == MBEDTLS_ERR_SSL_WANT_WRITE || rc == MBEDTLS_ERR_SSL_WANT_READ) continue;
		return -1;
	}
	return 0;
}

int net_recv(int s, void *buf, size_t len, int timeout_ms)
{
	tlsconn *t = find(s);
	plat_pollent pe;
	uint64_t end = plat_ms() + (uint64_t)(timeout_ms < 0 ? 0 : timeout_ms);
	if (!t) {
		int r = plat_recv(s, buf, len, timeout_ms);
		return r > 0 ? r : (r == 0 ? NET_TIMEOUT : 0);
	}
	for (;;) {
		int rc, left;
		if (mbedtls_ssl_get_bytes_avail(&t->ssl) == 0) {
			uint64_t now = plat_ms();
			left = timeout_ms < 0 ? 1000 : (now >= end ? 0 : (int)(end - now));
			pe.sock = s; pe.want = PLAT_RD; pe.got = 0;
			if (plat_poll(&pe, 1, left) <= 0) {
				if (timeout_ms < 0)
					continue;
				return NET_TIMEOUT;
			}
		}
		rc = mbedtls_ssl_read(&t->ssl, (unsigned char *)buf, len);
		if (rc > 0)
			return rc;
		if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
			return 0;                                    /* EOF */
		/* not data: a TLS 1.3 NewSessionTicket / more bytes needed -- read on until data, EOF or the timeout */
		if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET || rc == MBEDTLS_ERR_SSL_WANT_READ ||
		    rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if (timeout_ms >= 0 && plat_ms() >= end)
				return NET_TIMEOUT;
			continue;
		}
		fprintf(stderr, "net: TLS read failed: -0x%04x\n", (unsigned)-rc);
		return -1;
	}
}

void net_close(int s)
{
	tlsconn *t = find(s);
	if (t) {
		mbedtls_ssl_close_notify(&t->ssl);
		teardown(t);
	}
	plat_close(s);
}

int net_pending(int s)
{
	tlsconn *t = find(s);
	return t && mbedtls_ssl_get_bytes_avail(&t->ssl) > 0;
}

#endif
