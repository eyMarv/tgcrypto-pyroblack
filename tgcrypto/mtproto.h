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

#ifndef MTPROTO_H
#define MTPROTO_H

/*
 * Combined MTProto 2.0 message framing + crypto, computed entirely in C so the
 * whole per-packet path (KDF + msg_key + AES-IGE) runs under a single GIL
 * release. Mirrors pyrogram/crypto/mtproto.py:pack / unpack byte-for-byte.
 *
 * Return codes for the internal helpers (the Python-facing wrappers translate
 * negatives into exceptions).
 */
#define MTPROTO_OK 0
#define MTPROTO_ERR_RANDOM -1        /* CSPRNG failure */
#define MTPROTO_ERR_ALLOC -2         /* allocation failure */
#define MTPROTO_ERR_AUTH_KEY_ID -3   /* auth_key_id mismatch */
#define MTPROTO_ERR_SESSION_ID -4    /* session_id mismatch */
#define MTPROTO_ERR_MSG_KEY -5       /* msg_key mismatch */
#define MTPROTO_ERR_TRUNCATED -6     /* packet shorter than the fixed header */

/*
 * Derive the AES key/IV per https://core.telegram.org/mtproto/description.
 * outgoing selects x = 0 (send) or x = 8 (recv). auth_key is 256 bytes.
 */
void mtproto_kdf(const uint8_t auth_key[256], const uint8_t msg_key[16],
                 int outgoing, uint8_t aes_key[32], uint8_t aes_iv[32]);

/*
 * Fill buf with len cryptographically secure random bytes using the platform
 * CSPRNG (BCryptGenRandom on Windows, getrandom/getentropy/urandom on POSIX).
 * Returns MTPROTO_OK or MTPROTO_ERR_RANDOM. Callable with the GIL released.
 */
int mtproto_random(uint8_t *buf, size_t len);

#endif  // MTPROTO_H
