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

#include <stdint.h>
#include <stddef.h>

#ifndef SHA256_H
#define SHA256_H

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[SHA256_BLOCK_SIZE];
    size_t buflen;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);

void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);

void sha256_final(SHA256_CTX *ctx, uint8_t out[SHA256_DIGEST_SIZE]);

#endif  // SHA256_H
