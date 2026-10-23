// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// Include after <stdio.h>: printf and fprintf also go to plat_dbg (the platform's trace channel: the serial port on Symbian), so a
// stalled or crashed daemon can be followed from outside even when its log file never reaches the disk.
#ifndef PHETAIL_LOG_H
#define PHETAIL_LOG_H
#include <stdio.h>
void phe_printf(const char *fmt, ...);
void phe_fprintf(FILE *f, const char *fmt, ...);
#undef printf
#undef fprintf
#define printf(...) phe_printf(__VA_ARGS__)
#define fprintf(f, ...) phe_fprintf(f, __VA_ARGS__)
#endif
