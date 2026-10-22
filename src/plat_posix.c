// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// POSIX implementation of plat.h (Linux, BSD, macOS).
#define _POSIX_C_SOURCE 200809L
#include "plat.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int plat_tcp_connect(const char *host, int port)
{
	struct addrinfo hints, *res, *ai;
	char portstr[16];
	int s = -1;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(portstr, sizeof portstr, "%d", port);
	if (getaddrinfo(host, portstr, &hints, &res) != 0)
		return -1;
	for (ai = res; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s < 0)
			continue;
		if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(s);
		s = -1;
	}
	freeaddrinfo(res);
	return s;
}

int plat_send_all(int s, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	while (len) {
		ssize_t n = send(s, p, len, 0);
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

int plat_recv(int s, void *buf, size_t len, int timeout_ms)
{
	struct pollfd pfd;
	ssize_t n;
	pfd.fd = s;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, timeout_ms) == 0)
		return 0;
	n = recv(s, buf, len, 0);
	return n > 0 ? (int)n : -1;
}

void plat_close(int s) { close(s); }

int plat_send_some(int s, const void *buf, size_t len)
{
	ssize_t n = send(s, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0)
		return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? 0 : -1;
	return (int)n;
}

int plat_tcp_listen_local(int port)
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
	if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 16)) {
		close(s);
		return -1;
	}
	return s;
}

int plat_accept(int ls) { return accept(ls, NULL, NULL); }

int plat_poll(plat_pollent *e, int n, int timeout_ms)
{
	struct pollfd p[64];
	int i, r;
	if (n > 64)
		n = 64;
	for (i = 0; i < n; i++) {
		p[i].fd = e[i].sock;
		p[i].events = (short)(((e[i].want & PLAT_RD) ? POLLIN : 0) | ((e[i].want & PLAT_WR) ? POLLOUT : 0));
		p[i].revents = 0;
	}
	r = poll(p, (nfds_t)n, timeout_ms);
	for (i = 0; i < n; i++)
		e[i].got = (short)(((p[i].revents & (POLLIN | POLLHUP | POLLERR)) ? PLAT_RD : 0) |
				   ((p[i].revents & POLLOUT) ? PLAT_WR : 0));
	return r < 0 ? 0 : r;
}

int plat_random(void *buf, size_t len)
{
	int fd = open("/dev/urandom", O_RDONLY);
	unsigned char *p = buf;
	if (fd < 0)
		return -1;
	while (len) {
		ssize_t n = read(fd, p, len);
		if (n <= 0) {
			close(fd);
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	close(fd);
	return 0;
}

void plat_time(uint64_t *sec, uint32_t *nsec)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	*sec = (uint64_t)ts.tv_sec;
	*nsec = (uint32_t)ts.tv_nsec;
}

uint64_t plat_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
