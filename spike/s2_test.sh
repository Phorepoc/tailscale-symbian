#!/bin/sh
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
#
# S2 check on the spike box (after run.sh set up Headscale + phe-tsnode):
# rebuilds phetaild, runs it in a capped container, serves a page inside the
# peer's network namespace, then: disco ping from the peer, curl via SOCKS5.
set -u
HOST=${HOST:?}
KEY=$(cat ../hs/authkey)
docker run --rm --cpus 1 --memory 1g -v "$PWD:/w" -w /w gcc:14 nice make -s 2>&1 | grep -E "error" | head
docker rm -f phe-phetaild >/dev/null 2>&1
docker run -d --name phe-phetaild --cpus 1 --memory 1g -v "$PWD:/w" -w /w gcc:14 \
	./phetaild "$HOST" 18080 "$KEY" /w/phetail.state 1055 >/dev/null
docker inspect phe-httpd >/dev/null 2>&1 || docker run -d --name phe-httpd --cpus 0.5 --memory 128m \
	--network container:phe-tsnode busybox:1.37 sh -c \
	"mkdir -p /www && echo hello from phe-peer over the tailnet > /www/index.html && httpd -f -p 8080 -h /www" >/dev/null
sleep 5
echo "== tailscale ping --icmp from the peer (peer-initiated WireGuard + lwIP ICMP)"
timeout 40 docker exec phe-tsnode tailscale ping --icmp -c 3 phetail
echo "== tailscale ping (disco) from the peer"
timeout 30 docker exec phe-tsnode tailscale ping -c 3 phetail
echo "== curl through phetaild SOCKS5"
timeout 30 docker run --rm --cpus 0.5 --memory 128m --network container:phe-phetaild curlimages/curl:8.11.1 \
	-sS --max-time 20 --socks5-hostname 127.0.0.1:1055 http://phe-peer:8080/
echo "== phetaild log"
docker logs phe-phetaild 2>&1 | tail -25
