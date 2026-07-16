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

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include "aes256.h"
#include "ige256.h"
#include "ctr256.h"
#include "cbc256.h"
#include "sha256.h"
#include "mtproto.h"

#define DESCRIPTION "Fast and Portable Cryptography Extension Library for Pyrogram\n" \
    "TgCrypto is part of Pyrogram, a Telegram MTProto library for Python\n" \
    "You can learn more about Pyrogram here: https://pyrogram.org\n"

static PyObject *ige(PyObject *args, uint8_t encrypt) {
    Py_buffer data, key, iv;
    uint8_t *buf;
    PyObject *out;

    if (!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv))
        return NULL;

    if (data.len == 0) {
        PyErr_SetString(PyExc_ValueError, "Data must not be empty");
        return NULL;
    }

    if (data.len % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "Data size must match a multiple of 16 bytes");
        return NULL;
    }

    if (key.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Key size must be exactly 32 bytes");
        return NULL;
    }

    if (iv.len != 32) {
        PyErr_SetString(PyExc_ValueError, "IV size must be exactly 32 bytes");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
        buf = ige256(data.buf, data.len, key.buf, iv.buf, encrypt);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);

    out = Py_BuildValue("y#", buf, data.len);
    free(buf);

    return out;
}

static PyObject *ige256_encrypt(PyObject *self, PyObject *args) {
    return ige(args, 1);
}

static PyObject *ige256_decrypt(PyObject *self, PyObject *args) {
    return ige(args, 0);
}

static PyObject *ctr256_encrypt(PyObject *self, PyObject *args) {
    Py_buffer data, key, iv, state;
    uint8_t *buf;
    PyObject *out;

    if (!PyArg_ParseTuple(args, "y*y*y*y*", &data, &key, &iv, &state))
        return NULL;

    if (data.len == 0) {
        PyErr_SetString(PyExc_ValueError, "Data must not be empty");
        return NULL;
    }

    if (key.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Key size must be exactly 32 bytes");
        return NULL;
    }

    if (iv.len != 16) {
        PyErr_SetString(PyExc_ValueError, "IV size must be exactly 16 bytes");
        return NULL;
    }

    if (state.len != 1) {
        PyErr_SetString(PyExc_ValueError, "State size must be exactly 1 byte");
        return NULL;
    }

    if (*(uint8_t *) state.buf > 15) {
        PyErr_SetString(PyExc_ValueError, "State value must be in the range [0, 15]");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
        buf = ctr256(data.buf, data.len, key.buf, iv.buf, state.buf);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);

    out = Py_BuildValue("y#", buf, data.len);
    free(buf);

    return out;
}

static PyObject *cbc(PyObject *args, uint8_t encrypt) {
    Py_buffer data, key, iv;
    uint8_t *buf;
    PyObject *out;

    if (!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv))
        return NULL;

    if (data.len == 0) {
        PyErr_SetString(PyExc_ValueError, "Data must not be empty");
        return NULL;
    }

    if (data.len % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "Data size must match a multiple of 16 bytes");
        return NULL;
    }

    if (key.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Key size must be exactly 32 bytes");
        return NULL;
    }

    if (iv.len != 16) {
        PyErr_SetString(PyExc_ValueError, "IV size must be exactly 16 bytes");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
        buf = cbc256(data.buf, data.len, key.buf, iv.buf, encrypt);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);

    out = Py_BuildValue("y#", buf, data.len);
    free(buf);

    return out;
}

static PyObject *cbc256_encrypt(PyObject *self, PyObject *args) {
    return cbc(args, 1);
}

static PyObject *cbc256_decrypt(PyObject *self, PyObject *args) {
    return cbc(args, 0);
}

/*
 * Combined MTProto 2.0 pack/unpack. These mirror pyrogram/crypto/mtproto.py
 * byte-for-byte, but fold KDF (SHA-256) + msg_key + AES-IGE + framing into a
 * single call whose crypto runs with the GIL released, so the per-packet hot
 * path no longer serializes on Python/hashlib under concurrent transfers.
 *
 * Little-endian plaintext layout (matches raw.core Message.write prefixed with
 * salt + session_id):
 *   salt(8) | session_id(8) | msg_id(8) | seq_no(4) | length(4) | body | pad
 */

// Signature: pack_message(msg_id, seq_no, body, salt, session_id, auth_key, auth_key_id)
static PyObject *pack_message(PyObject *self, PyObject *args) {
    long long msg_id;
    unsigned int seq_no;
    unsigned long long salt;
    Py_buffer body, session_id, auth_key, auth_key_id;

    if (!PyArg_ParseTuple(args, "LIy*Ky*y*y*",
                          &msg_id, &seq_no, &body, &salt,
                          &session_id, &auth_key, &auth_key_id))
        return NULL;

    if (session_id.len != 8) {
        PyErr_SetString(PyExc_ValueError, "session_id must be exactly 8 bytes");
        goto err_release;
    }
    if (auth_key.len != 256) {
        PyErr_SetString(PyExc_ValueError, "auth_key must be exactly 256 bytes");
        goto err_release;
    }
    if (auth_key_id.len != 8) {
        PyErr_SetString(PyExc_ValueError, "auth_key_id must be exactly 8 bytes");
        goto err_release;
    }

    // data = salt(8) | session_id(8) | msg_id(8) | seq_no(4) | length(4) | body
    Py_ssize_t data_len = 32 + body.len;

    // padding = urandom(-(len(data) + 12) % 16 + 12), i.e. 12..27 bytes, so the
    // total plaintext length is a multiple of 16. Reproduce Python's always
    // non-negative modulo.
    Py_ssize_t r = (data_len + 12) % 16;
    Py_ssize_t pad_len = ((16 - r) % 16) + 12;
    Py_ssize_t plain_len = data_len + pad_len;

    uint8_t *plaintext = (uint8_t *) malloc((size_t) plain_len);
    uint8_t *encrypted = NULL;
    uint8_t msg_key[16];
    int rc = MTPROTO_OK;

    if (plaintext == NULL) {
        PyErr_NoMemory();
        goto err_release;
    }

    const uint8_t *body_buf = (const uint8_t *) body.buf;
    const uint8_t *sid_buf = (const uint8_t *) session_id.buf;
    const uint8_t *ak_buf = (const uint8_t *) auth_key.buf;
    uint32_t body_len32 = (uint32_t) body.len;

    Py_BEGIN_ALLOW_THREADS
        // Assemble plaintext (all little-endian scalars).
        for (int i = 0; i < 8; i++) plaintext[i] = (uint8_t) (salt >> (i * 8));
        memcpy(plaintext + 8, sid_buf, 8);
        for (int i = 0; i < 8; i++) plaintext[16 + i] = (uint8_t) ((unsigned long long) msg_id >> (i * 8));
        for (int i = 0; i < 4; i++) plaintext[24 + i] = (uint8_t) (seq_no >> (i * 8));
        for (int i = 0; i < 4; i++) plaintext[28 + i] = (uint8_t) (body_len32 >> (i * 8));
        memcpy(plaintext + 32, body_buf, (size_t) body.len);

        rc = mtproto_random(plaintext + data_len, (size_t) pad_len);

        if (rc == MTPROTO_OK) {
            // msg_key = SHA256(auth_key[88:120] + plaintext)[8:24]
            uint8_t msg_key_large[SHA256_DIGEST_SIZE];
            SHA256_CTX ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, ak_buf + 88, 32);
            sha256_update(&ctx, plaintext, (size_t) plain_len);
            sha256_final(&ctx, msg_key_large);
            memcpy(msg_key, msg_key_large + 8, 16);

            uint8_t aes_key[32], aes_iv[32];
            mtproto_kdf(ak_buf, msg_key, 1, aes_key, aes_iv);

            encrypted = ige256(plaintext, (uint32_t) plain_len, aes_key, aes_iv, 1);
            if (encrypted == NULL)
                rc = MTPROTO_ERR_ALLOC;
        }
    Py_END_ALLOW_THREADS

    free(plaintext);

    if (rc == MTPROTO_ERR_RANDOM) {
        PyErr_SetString(PyExc_OSError, "CSPRNG failed to generate padding");
        goto err_release;
    }
    if (rc == MTPROTO_ERR_ALLOC || encrypted == NULL) {
        PyErr_NoMemory();
        goto err_release;
    }

    // out = auth_key_id(8) + msg_key(16) + encrypted
    Py_ssize_t out_len = 24 + plain_len;
    PyObject *out = PyBytes_FromStringAndSize(NULL, out_len);
    if (out == NULL) {
        free(encrypted);
        goto err_release;
    }
    uint8_t *out_buf = (uint8_t *) PyBytes_AS_STRING(out);
    memcpy(out_buf, auth_key_id.buf, 8);
    memcpy(out_buf + 8, msg_key, 16);
    memcpy(out_buf + 24, encrypted, (size_t) plain_len);
    free(encrypted);

    PyBuffer_Release(&body);
    PyBuffer_Release(&session_id);
    PyBuffer_Release(&auth_key);
    PyBuffer_Release(&auth_key_id);

    return out;

err_release:
    PyBuffer_Release(&body);
    PyBuffer_Release(&session_id);
    PyBuffer_Release(&auth_key);
    PyBuffer_Release(&auth_key_id);
    return NULL;
}

// Signature: unpack_message(packed, session_id, auth_key, auth_key_id)
// Returns: (msg_id, seq_no, length, body_bytes, total_len)
static PyObject *unpack_message(PyObject *self, PyObject *args) {
    Py_buffer packed, session_id, auth_key, auth_key_id;

    if (!PyArg_ParseTuple(args, "y*y*y*y*",
                          &packed, &session_id, &auth_key, &auth_key_id))
        return NULL;

    if (session_id.len != 8) {
        PyErr_SetString(PyExc_ValueError, "session_id must be exactly 8 bytes");
        goto err_release;
    }
    if (auth_key.len != 256) {
        PyErr_SetString(PyExc_ValueError, "auth_key must be exactly 256 bytes");
        goto err_release;
    }
    if (auth_key_id.len != 8) {
        PyErr_SetString(PyExc_ValueError, "auth_key_id must be exactly 8 bytes");
        goto err_release;
    }

    const uint8_t *pk = (const uint8_t *) packed.buf;

    // Layout: auth_key_id(8) | msg_key(16) | encrypted
    if (packed.len < 24 + 32) {
        PyErr_SetString(PyExc_ValueError, "packet is truncated");
        goto err_release;
    }

    Py_ssize_t enc_len = packed.len - 24;
    if (enc_len % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "encrypted payload is not block-aligned");
        goto err_release;
    }

    // https://core.telegram.org/mtproto/security_guidelines#checking-sha256-hash-value-of-auth-key-id
    if (memcmp(pk, auth_key_id.buf, 8) != 0) {
        PyErr_SetString(PyExc_ValueError, "b.read(8) == auth_key_id");
        goto err_release;
    }

    const uint8_t *msg_key = pk + 8;
    const uint8_t *ak_buf = (const uint8_t *) auth_key.buf;

    uint8_t *plaintext = NULL;
    int rc = MTPROTO_OK;

    Py_BEGIN_ALLOW_THREADS
        uint8_t aes_key[32], aes_iv[32];
        mtproto_kdf(ak_buf, msg_key, 0, aes_key, aes_iv);

        plaintext = ige256(pk + 24, (uint32_t) enc_len, aes_key, aes_iv, 0);
        if (plaintext == NULL) {
            rc = MTPROTO_ERR_ALLOC;
        } else {
            // msg_key == SHA256(auth_key[96:128] + plaintext)[8:24]
            uint8_t computed[SHA256_DIGEST_SIZE];
            SHA256_CTX ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, ak_buf + 96, 32);
            sha256_update(&ctx, plaintext, (size_t) enc_len);
            sha256_final(&ctx, computed);

            if (memcmp(computed + 8, msg_key, 16) != 0)
                rc = MTPROTO_ERR_MSG_KEY;
            else if (memcmp(plaintext + 8, session_id.buf, 8) != 0)
                rc = MTPROTO_ERR_SESSION_ID;
        }
    Py_END_ALLOW_THREADS

    if (rc == MTPROTO_ERR_ALLOC || plaintext == NULL) {
        PyErr_NoMemory();
        goto err_release;
    }
    if (rc == MTPROTO_ERR_MSG_KEY) {
        free(plaintext);
        PyErr_SetString(PyExc_ValueError,
                        "msg_key == sha256(auth_key[96:96 + 32] + data.getvalue()).digest()[8:24]");
        goto err_release;
    }
    if (rc == MTPROTO_ERR_SESSION_ID) {
        free(plaintext);
        PyErr_SetString(PyExc_ValueError, "data.read(8) == session_id");
        goto err_release;
    }

    // plaintext: salt(8) | session_id(8) | msg_id(8) | seq_no(4) | length(4) | body | pad
    long long msg_id = 0;
    unsigned int seq_no = 0, length = 0;
    for (int i = 0; i < 8; i++) msg_id |= (long long) plaintext[16 + i] << (i * 8);
    for (int i = 0; i < 4; i++) seq_no |= (unsigned int) plaintext[24 + i] << (i * 8);
    for (int i = 0; i < 4; i++) length |= (unsigned int) plaintext[28 + i] << (i * 8);

    // The body must fit inside the decrypted buffer.
    if ((Py_ssize_t) 32 + (Py_ssize_t) length > enc_len) {
        free(plaintext);
        PyErr_SetString(PyExc_ValueError, "declared message length exceeds payload");
        goto err_release;
    }

    // total_len mirrors wzgram: length of (msg_id..pad) = enc_len - 16.
    Py_ssize_t total_len = enc_len - 16;

    PyObject *body_bytes = PyBytes_FromStringAndSize(
        (const char *) (plaintext + 32), (Py_ssize_t) length);
    free(plaintext);

    if (body_bytes == NULL)
        goto err_release;

    // Tuple order matches the wzgram/warpcrypto contract:
    // (msg_id, seq_no, length, body_bytes, total_len)
    // Format: L=msg_id (long long), I=seq_no, I=length, O=body_bytes (borrows,
    // so refcount is incremented), n=total_len (Py_ssize_t).
    PyObject *result = Py_BuildValue(
        "LIIOn", msg_id, seq_no, length, body_bytes, total_len);
    // Py_BuildValue "O" increments body_bytes' refcount; drop our reference.
    Py_DECREF(body_bytes);

    PyBuffer_Release(&packed);
    PyBuffer_Release(&session_id);
    PyBuffer_Release(&auth_key);
    PyBuffer_Release(&auth_key_id);

    return result;

err_release:
    PyBuffer_Release(&packed);
    PyBuffer_Release(&session_id);
    PyBuffer_Release(&auth_key);
    PyBuffer_Release(&auth_key_id);
    return NULL;
}

PyDoc_STRVAR(
    ige256_encrypt_docs,
    "ige256_encrypt(data, key, iv)\n"
    "--\n\n"
    "AES-256-IGE Encryption"
);

PyDoc_STRVAR(
    ige256_decrypt_docs,
    "ige256_decrypt(data, key, iv)\n"
    "--\n\n"
    "AES-256-IGE Decryption"
);

PyDoc_STRVAR(
    ctr256_encrypt_docs,
    "ctr256_encrypt(data, key, iv, state)\n"
    "--\n\n"
    "AES-256-CTR Encryption"
);

PyDoc_STRVAR(
    ctr256_decrypt_docs,
    "ctr256_decrypt(data, key, iv, state)\n"
    "--\n\n"
    "AES-256-CTR Decryption"
);

PyDoc_STRVAR(
    cbc256_encrypt_docs,
    "cbc256_encrypt(data, key, iv)\n"
    "--\n\n"
    "AES-256-CBC Encryption"
);

PyDoc_STRVAR(
    cbc256_decrypt_docs,
    "cbc256_decrypt(data, key, iv)\n"
    "--\n\n"
    "AES-256-CBC Encryption"
);

PyDoc_STRVAR(
    pack_message_docs,
    "pack_message(msg_id, seq_no, body, salt, session_id, auth_key, auth_key_id)\n"
    "--\n\n"
    "Encrypt an MTProto 2.0 message (KDF + msg_key + AES-256-IGE + framing) in a\n"
    "single GIL-released call. Returns the wire bytes: auth_key_id + msg_key + "
    "encrypted."
);

PyDoc_STRVAR(
    unpack_message_docs,
    "unpack_message(packed, session_id, auth_key, auth_key_id)\n"
    "--\n\n"
    "Decrypt and validate an MTProto 2.0 message in a single GIL-released call.\n"
    "Returns a tuple (msg_id, seq_no, length, body_bytes, total_len). Raises\n"
    "ValueError on any auth_key_id / session_id / msg_key mismatch."
);

static PyMethodDef methods[] = {
    {"ige256_encrypt", (PyCFunction) ige256_encrypt, METH_VARARGS, ige256_encrypt_docs},
    {"ige256_decrypt", (PyCFunction) ige256_decrypt, METH_VARARGS, ige256_decrypt_docs},
    {"ctr256_encrypt", (PyCFunction) ctr256_encrypt, METH_VARARGS, ctr256_encrypt_docs},
    {"ctr256_decrypt", (PyCFunction) ctr256_encrypt, METH_VARARGS, ctr256_decrypt_docs},
    {"cbc256_encrypt", (PyCFunction) cbc256_encrypt, METH_VARARGS, cbc256_encrypt_docs},
    {"cbc256_decrypt", (PyCFunction) cbc256_decrypt, METH_VARARGS, cbc256_decrypt_docs},
    {"pack_message", (PyCFunction) pack_message, METH_VARARGS, pack_message_docs},
    {"unpack_message", (PyCFunction) unpack_message, METH_VARARGS, unpack_message_docs},
    {NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "TgCrypto",
    DESCRIPTION,
    -1,
    methods
};

PyMODINIT_FUNC PyInit_tgcrypto(void) {
    return PyModule_Create(&module);
}
