// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// The primitives Tailscale needs: X25519, ChaCha20-Poly1305 (RFC 8439),
// BLAKE2s, HMAC-BLAKE2s HKDF, and NaCl box (for DERP ClientInfo).
#ifndef PHETAIL_TCRYPTO_H
#define PHETAIL_TCRYPTO_H

#include <stddef.h>
#include <stdint.h>

void tc_x25519_pub(uint8_t pub[32], const uint8_t priv[32]);
void tc_x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]);
/* Generates a clamped private key and its public key. */
int tc_keypair(uint8_t priv[32], uint8_t pub[32]);

void tc_blake2s(uint8_t out[32], const void *a, size_t alen, const void *b, size_t blen);
/* Keyed BLAKE2s with a 16-byte output (WireGuard MAC). */
void tc_blake2s_mac16(uint8_t out[16], const uint8_t key[32], const void *in, size_t len);
/* HKDF over HMAC-BLAKE2s: n outputs (1..3) of 32 bytes. */
void tc_hkdf(uint8_t *out1, uint8_t *out2, uint8_t *out3, const uint8_t ck[32],
	     const void *ikm, size_t ikmlen);

/* nonce12 is the full 96-bit RFC 8439 nonce. out has len+16 bytes. */
void tc_aead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce12[12],
		  const void *pt, size_t len, const void *ad, size_t adlen);
/* in has len bytes incl. 16-byte tag; out gets len-16. 0 = ok. */
int tc_aead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce12[12],
		 const void *in, size_t len, const void *ad, size_t adlen);

/* NaCl crypto_box: out = nonce(24) || tag(16) || ct. Returns out length. */
size_t tc_box_seal(uint8_t *out, const void *msg, size_t len,
		   const uint8_t peer_pub[32], const uint8_t my_priv[32]);

void tc_hex(char *out, const uint8_t *in, size_t n);
int tc_unhex(uint8_t *out, const char *in, size_t n);

#endif
