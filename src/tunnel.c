// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// The userspace IP stack: one lwIP netif whose output is WireGuard.
#include <string.h>

#include "lwip/init.h"
#include "lwip/ip4.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/timeouts.h"
#include "plat.h"
#include "tail.h"

static struct netif tun;

unsigned int phe_lwip_rand(void)
{
	unsigned int r;
	plat_random(&r, sizeof r);
	return r;
}

u32_t sys_now(void) { return (u32_t)plat_ms(); }

static err_t tun_output(struct netif *nif, struct pbuf *p, const ip4_addr_t *next)
{
	uint8_t buf[1600];
	peer *pe;
	(void)nif;
	(void)next;
	if (p->tot_len > sizeof buf)
		return ERR_BUF;
	pbuf_copy_partial(p, buf, p->tot_len, 0);
	pe = peer_by_ip4(buf + 16);
	if (!pe)
		return ERR_RTE;
	wg_send_ip(pe, buf, p->tot_len);
	return ERR_OK;
}

static err_t tun_netif_init(struct netif *nif)
{
	nif->name[0] = 'w';
	nif->name[1] = 'g';
	nif->mtu = 1280;
	nif->output = tun_output;
	nif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
	return ERR_OK;
}

void tun_init(void)
{
	ip4_addr_t ip, mask, gw;
	lwip_init();
	IP4_ADDR(&ip, 0, 0, 0, 0);
	IP4_ADDR(&mask, 255, 192, 0, 0);
	IP4_ADDR(&gw, 0, 0, 0, 0);
	netif_add(&tun, &ip, &mask, &gw, NULL, tun_netif_init, ip4_input);
	netif_set_default(&tun);
	netif_set_up(&tun);
	netif_set_link_up(&tun);
}

void tun_set_addr(const uint8_t a[4])
{
	ip4_addr_t ip;
	IP4_ADDR(&ip, a[0], a[1], a[2], a[3]);
	netif_set_ipaddr(&tun, &ip);
}

void tun_input(const uint8_t *ip, size_t len)
{
	struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
	if (!p)
		return;
	pbuf_take(p, ip, (u16_t)len);
	if (tun.input(p, &tun) != ERR_OK)
		pbuf_free(p);
}

void tun_timers(void) { sys_check_timeouts(); }
