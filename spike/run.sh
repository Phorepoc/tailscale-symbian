#!/bin/sh
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
#
# S0/S1 spike recipe, run on a Linux box with Docker. HOST = that box's LAN IP.
# Every container is capped (--cpus 1 --memory 1g).
set -e
HOST=${HOST:?set HOST to this box's IP}
HS=${HS:-headscale/headscale:v0.29.5}
mkdir -p hs/config hs/data
sed "s/192.168.2.247/$HOST/g" "$(dirname "$0")/headscale-config.yaml" > hs/config/config.yaml
docker run -d --name phe-headscale --cpus 1 --memory 1g -p 18080:18080 -p 3478:3478/udp \
	-v "$PWD/hs/config:/etc/headscale" -v "$PWD/hs/data:/var/lib/headscale" "$HS" serve
sleep 5
docker exec phe-headscale headscale users create phe
KEY=$(docker exec phe-headscale headscale preauthkeys create -u 1 --reusable --expiration 720h | tail -1)
# Peer: official image, userspace networking; DERP over plain HTTP (the embedded DERP has no TLS here).
docker run -d --name phe-tsnode --cpus 1 --memory 1g -e TS_DEBUG_USE_DERP_HTTP=1 -e TS_AUTHKEY="$KEY" \
	-e TS_USERSPACE=true -e TS_STATE_DIR=/var/lib/tailscale \
	-e TS_EXTRA_ARGS="--login-server=http://$HOST:18080 --hostname=phe-peer" tailscale/tailscale:stable
# Client (from the repo root):
docker run --rm --cpus 1 --memory 1g -e PHETAIL_PING=1 -v "$PWD:/w" -w /w gcc:14 \
	sh -c "make -s && ./phetail $HOST 18080 $KEY /w/phetail.state"
