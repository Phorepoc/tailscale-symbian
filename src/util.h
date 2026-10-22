// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
#ifndef PHETAIL_UTIL_H
#define PHETAIL_UTIL_H

#include <stddef.h>
#include <stdint.h>

static inline void put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void put_be24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v; }
static inline void put_be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); put_be24(p + 1, v); }
static inline void put_le32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static inline uint16_t get_be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t get_be24(const uint8_t *p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }
static inline uint32_t get_be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | get_be24(p + 1); }
static inline uint32_t get_le32(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

void b64_encode(char *out, const uint8_t *in, size_t n);

/* Tiny JSON scanning for the spike: finds "key": after `from` and copies the
 * string value (without quotes) into out. Returns pointer past the value or NULL. */
const char *json_str(const char *from, const char *key, char *out, size_t cap);

#endif
