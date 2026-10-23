// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
#include "util.h"

#include <stdio.h>
#include <string.h>

void b64_encode(char *out, const uint8_t *in, size_t n)
{
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i, o = 0;
	for (i = 0; i + 2 < n; i += 3) {
		uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
		out[o++] = t[v >> 18];
		out[o++] = t[(v >> 12) & 63];
		out[o++] = t[(v >> 6) & 63];
		out[o++] = t[v & 63];
	}
	if (n - i == 1) {
		uint32_t v = (uint32_t)in[i] << 16;
		out[o++] = t[v >> 18];
		out[o++] = t[(v >> 12) & 63];
		out[o++] = '=';
		out[o++] = '=';
	} else if (n - i == 2) {
		uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
		out[o++] = t[v >> 18];
		out[o++] = t[(v >> 12) & 63];
		out[o++] = t[(v >> 6) & 63];
		out[o++] = '=';
	}
	out[o] = 0;
}

const char *json_str(const char *from, const char *key, char *out, size_t cap)
{
	char pat[64];
	const char *p, *e;
	size_t n;
	snprintf(pat, sizeof pat, "\"%s\":", key);
	p = strstr(from, pat);
	if (!p)
		return NULL;
	p += strlen(pat);
	while (*p == ' ')
		p++;
	if (*p == '[')
		p++;
	if (*p != '"')
		return NULL;
	p++;
	e = strchr(p, '"');
	if (!e)
		return NULL;
	n = (size_t)(e - p);
	if (n >= cap)
		n = cap - 1;
	memcpy(out, p, n);
	out[n] = 0;
	return e + 1;
}

/* ---- logging with a trace mirror (log.h) ---- */
#include <stdarg.h>
#include "plat.h"
void phe_printf(const char *fmt, ...)
{
	char b[400];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	va_end(ap);
	fputs(b, stdout);
	plat_dbg(b);
}

void phe_fprintf(FILE *f, const char *fmt, ...)
{
	char b[400];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	va_end(ap);
	fputs(b, f);
	plat_dbg(b);
}
