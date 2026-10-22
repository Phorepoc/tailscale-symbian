# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
CC ?= cc
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Wno-unused-parameter
SRC = src/main.c src/ctrl.c src/derpwg.c src/tcrypto.c src/util.c src/plat_posix.c \
      vendor/monocypher/monocypher.c vendor/blake2s/blake2s-ref.c vendor/tweetnacl/tweetnacl.c

phetail: $(SRC) $(wildcard src/*.h)
	$(CC) $(CFLAGS) -o $@ $(SRC)

clean:
	rm -f phetail
