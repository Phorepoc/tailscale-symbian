// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
#ifndef PHETAIL_SOCKS_H
#define PHETAIL_SOCKS_H

#include "plat.h"

int socks_listen(int port);
/* Adds the listener + client sockets to the poll set; returns entries added. */
int socks_poll_set(plat_pollent *e, int max);
void socks_handle(const plat_pollent *e, int n);
/* Pushes tunnel->client data; call once per loop iteration. */
void socks_flush(void);

#endif
