// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// lwIP configuration for phetail: raw API, single thread (NO_SYS), IPv4 + TCP
// over one point-to-point netif (the WireGuard tunnel). No ARP, no DHCP.
#ifndef PHETAIL_LWIPOPTS_H
#define PHETAIL_LWIPOPTS_H

#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_ACD 0
#define LWIP_IGMP 0
#define LWIP_DNS 0
#define LWIP_RAW 0
#define LWIP_UDP 1
#define LWIP_TCP 1
#define LWIP_ICMP 1
#define LWIP_STATS 0
#define LWIP_NETIF_LOOPBACK 0
#define IP_REASSEMBLY 0
#define IP_FRAG 0

#define MEM_ALIGNMENT 4
#define MEM_SIZE (256 * 1024)
#define MEMP_NUM_PBUF 64
#define PBUF_POOL_SIZE 64
#define MEMP_NUM_TCP_PCB 16
#define MEMP_NUM_TCP_SEG 128
#define TCP_MSS 1200 /* WireGuard MTU 1280 - 40 */
#define TCP_WND (16 * TCP_MSS)
#define TCP_SND_BUF (16 * TCP_MSS)
#define TCP_SND_QUEUELEN (4 * TCP_SND_BUF / TCP_MSS)

#define LWIP_RAND() phe_lwip_rand()
unsigned int phe_lwip_rand(void);

#endif
