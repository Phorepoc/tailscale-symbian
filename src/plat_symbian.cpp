// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// Symbian implementation of plat.h: Open C (P.I.P.S.) BSD sockets + select,
// Symbian user-library calls for time and entropy.
//
// First cut: the event loop's plat_poll maps onto select(). The planned next
// step is native: one RSocket active object per handle (RecvOneOrMore pending)
// plus a CPeriodic for the tick, all on the thread's active scheduler, with the
// core callbacks unchanged.
#include <e32std.h>
#include <e32math.h>
#include <e32debug.h>
#include <hal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern "C" {
#include "plat.h"
#include "tcrypto.h"
}

#define PHE_DIR "C:\\data\\phetail"
#define PHE_LOG PHE_DIR "\\phetaild.log"
#define PHE_SEED PHE_DIR "\\seed.bin"
#define PHE_IAP_FILE PHE_DIR "\\iap.txt"
#define PHE_IAP_DEFAULT "ASUS"

/* ---------- CSPRNG: BLAKE2s over a pool seeded from several sources ---------- */

static uint8_t g_pool[32];
static uint64_t g_ctr;

static void pool_mix(const void *p, size_t n)
{
	tc_blake2s(g_pool, g_pool, 32, p, n);
}

static void pool_stir(void)
{
	struct {
		TUint32 fast, tick, rnd[4];
		TInt64 now;
		TUint32 heap;
	} e;
	TTime t;
	int i;
	e.fast = User::FastCounter();
	e.tick = User::NTickCount();
	for (i = 0; i < 4; i++)
		e.rnd[i] = Math::Random();
	t.UniversalTime();
	e.now = t.Int64();
	e.heap = (TUint32)(TUint)&e;
	pool_mix(&e, sizeof e);
}

static void seed_init(void)
{
	uint8_t seed[32];
	FILE *f = fopen(PHE_SEED, "rb");
	if (f) {
		if (fread(seed, 1, sizeof seed, f) == sizeof seed)
			pool_mix(seed, sizeof seed);
		fclose(f);
	}
	pool_stir();
	/* Persist a successor seed so the next run starts from fresh state. */
	tc_blake2s(seed, g_pool, 32, "phetail-seed", 12);
	f = fopen(PHE_SEED, "wb");
	if (f) {
		fwrite(seed, 1, sizeof seed, f);
		fclose(f);
	}
}

extern "C" int plat_random(void *buf, size_t len)
{
	uint8_t *p = (uint8_t *)buf, blk[32];
	pool_stir();
	while (len) {
		size_t n = len < 32 ? len : 32;
		g_ctr++;
		tc_blake2s(blk, g_pool, 32, &g_ctr, sizeof g_ctr);
		memcpy(p, blk, n);
		p += n;
		len -= n;
	}
	tc_blake2s(g_pool, g_pool, 32, "rekey", 5); /* forward secrecy of past output */
	return 0;
}

/* ---------- process setup ---------- */

extern "C" int plat_init(int argc, char **argv)
{
	struct ifreq ifr;
	FILE *f;
	(void)argc;
	(void)argv;
	mkdir("C:\\data", 0755);
	mkdir(PHE_DIR, 0755);
	freopen(PHE_LOG, "a", stdout);
	freopen(PHE_LOG, "a", stderr);
	setvbuf(stderr, NULL, _IONBF, 0);
	printf("---- phetaild start\n");
	seed_init();

	/* Open C has no default connection: without one every socket asks the user.
	 * The access point name comes from C:\data\phetail\iap.txt, else the default. */
	memset(&ifr, 0, sizeof ifr);
	f = fopen(PHE_IAP_FILE, "r");
	if (f == NULL || fgets(ifr.ifr_name, sizeof ifr.ifr_name, f) == NULL)
		strncpy(ifr.ifr_name, PHE_IAP_DEFAULT, sizeof ifr.ifr_name - 1);
	if (f)
		fclose(f);
	ifr.ifr_name[strcspn(ifr.ifr_name, "\r\n")] = 0;
	printf("plat: access point \"%s\" -> setdefaultif %d\n", ifr.ifr_name, setdefaultif(&ifr));
	return 0;
}

/* ---------- sockets ---------- */

extern "C" int plat_tcp_connect(const char *host, int port)
{
	struct sockaddr_in a;
	int s;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	if (inet_aton(host, &a.sin_addr) == 0) {
		struct hostent *h = gethostbyname(host);
		if (!h || h->h_addrtype != AF_INET)
			return -1;
		memcpy(&a.sin_addr, h->h_addr_list[0], 4);
	}
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return -1;
	if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
		printf("plat: connect %s:%d failed errno %d\n", host, port, errno);
		close(s);
		return -1;
	}
	return s;
}

extern "C" int plat_send_all(int s, const void *buf, size_t len)
{
	const char *p = (const char *)buf;
	while (len) {
		int n = send(s, p, len, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int wait_one(int s, int write, int timeout_ms)
{
	fd_set fs;
	struct timeval tv, *tvp = NULL;
	FD_ZERO(&fs);
	FD_SET(s, &fs);
	if (timeout_ms >= 0) {
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000;
		tvp = &tv;
	}
	return select(s + 1, write ? NULL : &fs, write ? &fs : NULL, NULL, tvp);
}

extern "C" int plat_send_some(int s, const void *buf, size_t len)
{
	int n;
	if (wait_one(s, 1, 0) <= 0)
		return 0;
	/* Writable: a bounded blocking send is fine for a local client socket. */
	n = send(s, (const char *)buf, len > 4096 ? 4096 : len, 0);
	return n < 0 ? (errno == EINTR ? 0 : -1) : n;
}

extern "C" int plat_recv(int s, void *buf, size_t len, int timeout_ms)
{
	int n;
	if (wait_one(s, 0, timeout_ms) <= 0)
		return 0;
	n = recv(s, (char *)buf, len, 0);
	return n > 0 ? n : -1;
}

extern "C" void plat_close(int s) { close(s); }

extern "C" int plat_tcp_listen_local(int port)
{
	struct sockaddr_in a;
	int one = 1, s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return -1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 8)) {
		close(s);
		return -1;
	}
	return s;
}

extern "C" int plat_accept(int ls) { return accept(ls, NULL, NULL); }

extern "C" int plat_poll(plat_pollent *e, int n, int timeout_ms)
{
	fd_set rd, wr;
	struct timeval tv;
	int i, mx = -1, r;
	FD_ZERO(&rd);
	FD_ZERO(&wr);
	for (i = 0; i < n; i++) {
		e[i].got = 0;
		if (e[i].sock < 0)
			continue;
		if (e[i].want & PLAT_RD)
			FD_SET(e[i].sock, &rd);
		if (e[i].want & PLAT_WR)
			FD_SET(e[i].sock, &wr);
		if (e[i].sock > mx)
			mx = e[i].sock;
	}
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	r = select(mx + 1, &rd, &wr, NULL, &tv);
	if (r <= 0)
		return 0;
	for (i = 0; i < n; i++) {
		if (e[i].sock < 0)
			continue;
		e[i].got = (short)((FD_ISSET(e[i].sock, &rd) ? PLAT_RD : 0) | (FD_ISSET(e[i].sock, &wr) ? PLAT_WR : 0));
	}
	return r;
}

/* ---------- time ---------- */

extern "C" void plat_time(uint64_t *sec, uint32_t *nsec)
{
	/* TTime counts microseconds from 0 AD; the Unix epoch is 62168256000 s later. */
	TTime t;
	t.UniversalTime();
	TInt64 us = t.Int64() - TInt64(62168256000LL) * 1000000;
	*sec = (uint64_t)(us / 1000000);
	*nsec = (uint32_t)((us % 1000000) * 1000);
}

extern "C" uint64_t plat_ms(void)
{
	/* NTickCount is in nanokernel ticks (1 ms on current hardware). Extend the
	 * 32-bit counter across wraps. */
	static TUint32 last;
	static uint64_t high;
	static TInt period_us;
	TUint32 now = User::NTickCount();
	if (!period_us) {
		TInt p = 0;
		if (HAL::Get(HAL::ENanoTickPeriod, p) != KErrNone || p <= 0)
			p = 1000;
		period_us = p;
	}
	if (now < last)
		high += (uint64_t)1 << 32;
	last = now;
	return ((high | now) * (uint64_t)period_us) / 1000;
}

extern "C" void plat_dbg(const char *line)
{
	/* RDebug::Printf takes a format; keep the text out of it, and one trace line per call */
	TBuf8<200> b;
	b.Copy(TPtrC8((const TUint8 *)line).Left(190));
	for (TInt i = 0; i < b.Length(); ++i)
		if (b[i] == '\n' || b[i] == '\r')
			b[i] = ' ';
	RDebug::Printf("[phetail] %S", &b);
}
