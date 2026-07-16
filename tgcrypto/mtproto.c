/*
 * Pyroblack - Telegram MTProto API Client Library for Python
 * Copyright (C) 2017-2024 Dan <https://github.com/delivrance>
 * Copyright (C) 2024-present eyMarv <https://github.com/eyMarv>
 * Maintainer: irisXDR <https://github.com/irisXDR>
 *
 * This file is part of Pyroblack.
 *
 * Pyroblack is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pyroblack is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * Pyroblack is a continuation fork of Pyrogram <https://github.com/pyrogram/pyrogram>
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Pyroblack.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>

#include "mtproto.h"
#include "sha256.h"

/*
 * Platform CSPRNG. We deliberately avoid rand()/random() (not cryptographically
 * secure) and OpenSSL (not a dependency). Windows uses BCryptGenRandom; POSIX
 * prefers getrandom(2) / getentropy(3) and falls back to /dev/urandom.
 */
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS) 0x00000000L)
#endif

int mtproto_random(uint8_t *buf, size_t len) {
    NTSTATUS status = BCryptGenRandom(
        NULL, buf, (ULONG) len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status == STATUS_SUCCESS ? MTPROTO_OK : MTPROTO_ERR_RANDOM;
}
#else
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

int mtproto_random(uint8_t *buf, size_t len) {
#if defined(__linux__)
    size_t off = 0;
    while (off < len) {
        ssize_t n = getrandom(buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;  /* fall through to /dev/urandom */
        }
        off += (size_t) n;
    }
    if (off == len)
        return MTPROTO_OK;
#endif
    /* Portable fallback: read from /dev/urandom. */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL)
        return MTPROTO_ERR_RANDOM;

    size_t got = fread(buf, 1, len, f);
    fclose(f);

    return got == len ? MTPROTO_OK : MTPROTO_ERR_RANDOM;
}
#endif

void mtproto_kdf(const uint8_t auth_key[256], const uint8_t msg_key[16],
                 int outgoing, uint8_t aes_key[32], uint8_t aes_iv[32]) {
    // https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector
    int x = outgoing ? 0 : 8;

    uint8_t sha256_a[SHA256_DIGEST_SIZE];
    uint8_t sha256_b[SHA256_DIGEST_SIZE];
    SHA256_CTX ctx;

    // sha256_a = SHA256(msg_key + auth_key[x : x + 36])
    sha256_init(&ctx);
    sha256_update(&ctx, msg_key, 16);
    sha256_update(&ctx, auth_key + x, 36);
    sha256_final(&ctx, sha256_a);

    // sha256_b = SHA256(auth_key[x + 40 : x + 76] + msg_key)
    sha256_init(&ctx);
    sha256_update(&ctx, auth_key + x + 40, 36);
    sha256_update(&ctx, msg_key, 16);
    sha256_final(&ctx, sha256_b);

    // aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    memcpy(aes_key, sha256_a, 8);
    memcpy(aes_key + 8, sha256_b + 8, 16);
    memcpy(aes_key + 24, sha256_a + 24, 8);

    // aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]
    memcpy(aes_iv, sha256_b, 8);
    memcpy(aes_iv + 8, sha256_a + 8, 16);
    memcpy(aes_iv + 24, sha256_b + 24, 8);
}
