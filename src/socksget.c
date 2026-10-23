// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0
//
// socksget: fetches http://<host>:<port><path> through a SOCKS5 proxy (default 127.0.0.1:1055, the phetaild front-end) and
// prints the reply. A test client: it shows that an ordinary application can reach a tailnet peer through the device.
//   socksget <host> <port> [path] [proxy-port] [tries] [delay-s]     (--args <file> as in phetaild)
// Exit status 0 = an HTTP reply came back. On Symbian the output goes to C:\data\phetail\socksget.log (appended).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

static int readn(int s, unsigned char *b, int n, int secs)
{
	int got = 0;
	while (got < n) {
		fd_set fs;
		struct timeval tv;
		int r;
		FD_ZERO(&fs);
		FD_SET(s, &fs);
		tv.tv_sec = secs;
		tv.tv_usec = 0;
		if (select(s + 1, &fs, NULL, NULL, &tv) <= 0)
			return -1;
		r = recv(s, b + got, n - got, 0);
		if (r <= 0)
			return -1;
		got += r;
	}
	return got;
}

static int one_try(const char *host, int port, const char *path, int pport)
{
	struct sockaddr_in a;
	unsigned char buf[600], r[10];
	char req[300], line[2048];
	int s, n, total = 0, hl = (int)strlen(host);

	s = socket(AF_INET, SOCK_STREAM, 0);
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((unsigned short)pport);
	a.sin_addr.s_addr = htonl(0x7f000001);
	if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
		printf("socksget: cannot connect to the proxy 127.0.0.1:%d\n", pport);
		if (s >= 0)
			close(s);
		return -1;
	}
	send(s, "\x05\x01\x00", 3, 0);
	if (readn(s, r, 2, 10) < 0 || r[0] != 5 || r[1] != 0) {
		printf("socksget: SOCKS greeting refused\n");
		close(s);
		return -1;
	}
	buf[0] = 5; buf[1] = 1; buf[2] = 0; buf[3] = 3; buf[4] = (unsigned char)hl;
	memcpy(buf + 5, host, hl);
	buf[5 + hl] = (unsigned char)(port >> 8);
	buf[6 + hl] = (unsigned char)port;
	send(s, buf, 7 + hl, 0);
	if (readn(s, r, 10, 40) < 0 || r[1] != 0) {
		printf("socksget: SOCKS connect to %s:%d failed (%d)\n", host, port, r[1]);
		close(s);
		return -1;
	}
	snprintf(req, sizeof req, "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
	send(s, req, strlen(req), 0);
	while (total < (int)sizeof line - 1) {
		fd_set fs;
		struct timeval tv;
		FD_ZERO(&fs);
		FD_SET(s, &fs);
		tv.tv_sec = 30;
		tv.tv_usec = 0;
		if (select(s + 1, &fs, NULL, NULL, &tv) <= 0)
			break;
		n = recv(s, line + total, sizeof line - 1 - total, 0);
		if (n <= 0)
			break;
		total += n;
	}
	close(s);
	line[total] = 0;
	if (total == 0) {
		printf("socksget: no reply\n");
		return -1;
	}
	printf("socksget: reply %d bytes: %.*s", total, total > 400 ? 400 : total, line);
	printf("\n");
	return strncmp(line, "HTTP/", 5) == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
	static char text[1500];
	static char *av[16];
	int tries = 1, i, pport = 1055;
	const char *path = "/";

#ifdef __SYMBIAN32__
	freopen("C:\data\phetail\socksget.log", "a", stdout);
	setvbuf(stdout, NULL, _IOLBF, 0);
#endif
	if (argc >= 3 && strcmp(argv[1], "--args") == 0) {
		FILE *f = fopen(argv[2], "rb");
		int n = 0, ac = 0;
		char *p;
		if (f) {
			n = (int)fread(text, 1, sizeof text - 1, f);
			fclose(f);
		}
		text[n] = 0;
		av[ac++] = argv[0];
		for (p = text; *p && ac < 15;) {
			while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
				p++;
			if (!*p)
				break;
			av[ac++] = p;
			while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
				p++;
			if (*p)
				*p++ = 0;
		}
		argc = ac;
		argv = av;
	}
	if (argc < 3) {
		printf("usage: socksget <host> <port> [path] [proxy-port] [tries]\n");
		return 2;
	}
	if (argc > 3) path = argv[3];
	if (argc > 4) pport = atoi(argv[4]);
	if (argc > 5) tries = atoi(argv[5]);
	if (argc > 6) sleep(atoi(argv[6]));        /* wait first (a test kills the server side meanwhile) */
	for (i = 0; i < tries; i++) {
		int r = one_try(argv[1], atoi(argv[2]), path, pport);
		if (r == 0)
			return 0;
		sleep(5);
	}
	return 1;
}
