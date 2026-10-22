// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
#ifndef PHETAIL_LWIP_CC_H
#define PHETAIL_LWIP_CC_H

#include <stdio.h>
#include <stdlib.h>

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#define LWIP_PLATFORM_DIAG(x) do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { fprintf(stderr, "lwip assert: %s\n", x); abort(); } while (0)

#endif
