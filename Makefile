# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
CC ?= cc
CFLAGS ?= -std=c99 -O2 -Wall -Wno-unused-parameter
LWIP = vendor/lwip
INC = -Isrc/lwipport -I$(LWIP)/include
SRC = src/phetaild.c src/ctrl.c src/netmap.c src/derp.c src/wg.c src/disco.c src/tunnel.c src/socks.c \
      src/tcrypto.c src/util.c src/plat_posix.c \
      vendor/monocypher/monocypher.c vendor/blake2s/blake2s-ref.c vendor/tweetnacl/tweetnacl.c \
      $(wildcard $(LWIP)/core/*.c) $(wildcard $(LWIP)/core/ipv4/*.c)

phetaild: $(SRC) $(wildcard src/*.h)
	$(CC) $(CFLAGS) $(INC) -o $@ $(SRC)

clean:
	rm -f phetaild
