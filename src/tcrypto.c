// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
#include "tcrypto.h"

#include <stdlib.h>
#include <string.h>

#include "../vendor/blake2s/blake2.h"
#include "../vendor/monocypher/monocypher.h"
#include "../vendor/tweetnacl/tweetnacl.h"
#include "plat.h"

/* tweetnacl wants this symbol; only crypto_box_keypair would call it. */
void randombytes(unsigned char *p, unsigned long long n) { plat_random(p, (size_t)n); }

void tc_x25519_pub(uint8_t pub[32], const uint8_t priv[32]) { crypto_x25519_public_key(pub, priv); }
void tc_x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]) { crypto_x25519(out, priv, pub); }

int tc_keypair(uint8_t priv[32], uint8_t pub[32])
{
	if (plat_random(priv, 32))
		return -1;
	priv[0] &= 248;
	priv[31] &= 127;
	priv[31] |= 64;
	tc_x25519_pub(pub, priv);
	return 0;
}

void tc_blake2s(uint8_t out[32], const void *a, size_t alen, const void *b, size_t blen)
{
	blake2s_state s;
	blake2s_init(&s, 32);
	if (alen)
		blake2s_update(&s, a, alen);
	if (blen)
		blake2s_update(&s, b, blen);
	blake2s_final(&s, out, 32);
}

void tc_blake2s_mac16(uint8_t out[16], const uint8_t key[32], const void *in, size_t len)
{
	blake2s_state s;
	blake2s_init_key(&s, 16, key, 32);
	blake2s_update(&s, in, len);
	blake2s_final(&s, out, 16);
}

static void hmac(uint8_t out[32], const uint8_t *key, size_t klen, const void *a, size_t alen,
		 const void *b, size_t blen)
{
	uint8_t k[64], ipad[64], opad[64], inner[32];
	blake2s_state s;
	int i;
	memset(k, 0, sizeof k);
	if (klen > 64)
		tc_blake2s(k, key, klen, NULL, 0);
	else
		memcpy(k, key, klen);
	for (i = 0; i < 64; i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}
	blake2s_init(&s, 32);
	blake2s_update(&s, ipad, 64);
	if (alen)
		blake2s_update(&s, a, alen);
	if (blen)
		blake2s_update(&s, b, blen);
	blake2s_final(&s, inner, 32);
	tc_blake2s(out, opad, 64, inner, 32);
}

void tc_hkdf(uint8_t *o1, uint8_t *o2, uint8_t *o3, const uint8_t ck[32], const void *ikm, size_t ikmlen)
{
	uint8_t prk[32], t[33], one = 1;
	hmac(prk, ck, 32, ikm, ikmlen, NULL, 0);
	hmac(t, prk, 32, &one, 1, NULL, 0);
	if (o1)
		memcpy(o1, t, 32);
	t[32] = 2;
	hmac(t, prk, 32, t, 33, NULL, 0);
	if (o2)
		memcpy(o2, t, 32);
	t[32] = 3;
	hmac(t, prk, 32, t, 33, NULL, 0);
	if (o3)
		memcpy(o3, t, 32);
}

static void poly_tag(uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[12], const uint8_t *ct,
		     size_t len, const void *ad, size_t adlen)
{
	static const uint8_t zero[16];
	uint8_t polykey[64], lens[16];
	crypto_poly1305_ctx ctx;
	int i;
	memset(polykey, 0, sizeof polykey);
	crypto_chacha20_ietf(polykey, polykey, 64, key, nonce, 0);
	crypto_poly1305_init(&ctx, polykey);
	crypto_poly1305_update(&ctx, ad, adlen);
	crypto_poly1305_update(&ctx, zero, (16 - adlen % 16) % 16);
	crypto_poly1305_update(&ctx, ct, len);
	crypto_poly1305_update(&ctx, zero, (16 - len % 16) % 16);
	for (i = 0; i < 8; i++) {
		lens[i] = (uint8_t)((uint64_t)adlen >> (8 * i));
		lens[8 + i] = (uint8_t)((uint64_t)len >> (8 * i));
	}
	crypto_poly1305_update(&ctx, lens, 16);
	crypto_poly1305_final(&ctx, tag);
}

void tc_aead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const void *pt, size_t len,
		  const void *ad, size_t adlen)
{
	if (len)
		crypto_chacha20_ietf(out, pt, len, key, nonce, 1);
	poly_tag(out + len, key, nonce, out, len, ad, adlen);
}

int tc_aead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12], const void *in, size_t len,
		 const void *ad, size_t adlen)
{
	uint8_t tag[16];
	const uint8_t *c = in;
	if (len < 16)
		return -1;
	len -= 16;
	poly_tag(tag, key, nonce, c, len, ad, adlen);
	if (crypto_verify16(tag, c + len))
		return -1;
	if (len)
		crypto_chacha20_ietf(out, c, len, key, nonce, 1);
	return 0;
}

size_t tc_box_seal(uint8_t *out, const void *msg, size_t len, const uint8_t peer_pub[32], const uint8_t my_priv[32])
{
	size_t n = len + crypto_box_ZEROBYTES;
	unsigned char *m = calloc(1, n), *c = calloc(1, n);
	plat_random(out, 24);
	memcpy(m + crypto_box_ZEROBYTES, msg, len);
	crypto_box(c, m, n, out, peer_pub, my_priv);
	memcpy(out + 24, c + crypto_box_BOXZEROBYTES, n - crypto_box_BOXZEROBYTES);
	free(m);
	free(c);
	return 24 + n - crypto_box_BOXZEROBYTES;
}

void tc_hex(char *out, const uint8_t *in, size_t n)
{
	static const char h[] = "0123456789abcdef";
	size_t i;
	for (i = 0; i < n; i++) {
		out[2 * i] = h[in[i] >> 4];
		out[2 * i + 1] = h[in[i] & 15];
	}
	out[2 * n] = 0;
}

static int hv(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int tc_unhex(uint8_t *out, const char *in, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		int a = hv(in[2 * i]), b = hv(in[2 * i + 1]);
		if (a < 0 || b < 0)
			return -1;
		out[i] = (uint8_t)(a << 4 | b);
	}
	return 0;
}
