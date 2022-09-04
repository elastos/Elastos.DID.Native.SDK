/*
 * Copyright (c) 2019 - 2021 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "didencryption.h"
#include "diderror.h"

Cipher *Cipher_Create(uint8_t *key) {
    Cipher *cipher;

    assert(key);

    cipher = (Cipher *)malloc(sizeof(Cipher));
    if (!cipher) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Create cipher memory error.");
        return NULL;
    }

    cipher->isCurve25519 = false;
    memcpy(cipher->privateKey, key, PRIVATEKEY_BYTES);
    return cipher;
}

Curve25519KeyPair *Cipher_CreateCurve25519KeyPair(uint8_t *key) {
    int ret;
    unsigned char privateKey[crypto_sign_SECRETKEYBYTES], publicKey[crypto_sign_PUBLICKEYBYTES];
    unsigned char *curvePrivateKey, *curvePublicKey;

    assert(key);

    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized; it is not safe to use */
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Init cipher failed.");
        return NULL;
    }

    ret = crypto_sign_seed_keypair(publicKey, privateKey, (unsigned char *)key);
    if (ret != 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create sign key pair.");
        return NULL;
    }

    Curve25519KeyPair *pair = (Curve25519KeyPair *)malloc(sizeof(Curve25519KeyPair));
    if (!pair) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Create curve25519 key pair memory error.");
        return NULL;
    }

    ret = crypto_sign_ed25519_pk_to_curve25519(pair->publicKey, publicKey);
    if (ret != 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Convert curve25519 public key error.");
        goto ERROR_EXIT;
    }
    ret = crypto_sign_ed25519_sk_to_curve25519(pair->privateKey, privateKey);
    if (ret != 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Convert curve25519 private key error.");
        goto ERROR_EXIT;
    }

    return pair;

ERROR_EXIT:
    if (pair) {
        free(pair);
    }
    return NULL;
}

Cipher *Cipher_CreateCurve25519(Curve25519KeyPair *keyPair, bool isServer, uint8_t *otherSidePublicKey) {
    Cipher *cipher;
    int ret;

    assert(keyPair);
    assert(otherSidePublicKey);

    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized; it is not safe to use */
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Init cipher failed.");
        return NULL;
    }

    cipher = (Cipher *)malloc(sizeof(Cipher));
    if (!cipher) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Create cipher memory error.");
        return NULL;
    }

    cipher->isCurve25519 = true;
    memcpy(&cipher->keyPair, keyPair, sizeof(Curve25519KeyPair));
    cipher->isServer = isServer;
    memcpy(cipher->otherSidePublicKey, otherSidePublicKey, crypto_scalarmult_curve25519_BYTES);

    ret = crypto_box_beforenm(cipher->encryptKey, otherSidePublicKey, keyPair->privateKey);
    if (ret != 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Create encrypt key error.");
        free(cipher);
        return NULL;
    }

    if (isServer) {
        ret = crypto_kx_server_session_keys(cipher->sharedKeyRx, cipher->sharedKeyTx, keyPair->privateKey, keyPair->publicKey, otherSidePublicKey);
    } else {
        ret = crypto_kx_client_session_keys(cipher->sharedKeyRx, cipher->sharedKeyTx, keyPair->privateKey, keyPair->publicKey, otherSidePublicKey);
    }
    if (ret != 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Create shared keys error.");
        free(cipher);
        return NULL;
    }

    return cipher;
}

unsigned char *Cipher_Encrypt(Cipher *cipher, const unsigned char *data,
                              unsigned int dataLen, const unsigned char *nonce, unsigned int *cipherTextLen) {
    unsigned char *cipherText;
    unsigned long long clen;
    int ret;
    unsigned int ctlen;

    CHECK_ARG(!cipher, "Invalid cipher.", NULL);
    CHECK_ARG(!data, "Invalid data.", NULL);
    CHECK_ARG(!nonce, "Invalid nonce.", NULL);
    CHECK_ARG(!cipherTextLen, "Invalid cipherTextLen.", NULL);

    if (cipher->isCurve25519) {
        ctlen = dataLen + crypto_box_MACBYTES;
        cipherText = (unsigned char *)malloc(ctlen);
        if (!cipherText) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create cipher text memory.");
            return NULL;
        }

        ret = crypto_box_easy_afternm(cipherText, (uint8_t *)data, dataLen, nonce, cipher->encryptKey);
        if (ret != 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to encrypt with curve25519.");
            free(cipherText);
            return NULL;
        }
    } else {
        ctlen = dataLen + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        cipherText = (unsigned char *)malloc(ctlen);
        if (!cipherText) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create cipher text memory..");
            return NULL;
        }

        ret = crypto_aead_xchacha20poly1305_ietf_encrypt(cipherText, &clen,
                                                         (uint8_t *)data, dataLen, NULL, 0, NULL, nonce, cipher->privateKey);
        if (ret != 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to encrypt with xchacha20.");
            free(cipherText);
            return NULL;
        }
    }

    if (cipherTextLen) {
        *cipherTextLen = ctlen;
    }
    return cipherText;
}

unsigned char *Cipher_Decrypt(Cipher *cipher, const unsigned char *data,
                              unsigned int dataLen, const unsigned char *nonce, unsigned int *clearTextLen) {
    unsigned char *clearText;
    unsigned long long clen;
    int ret;
    unsigned int ctlen;

    CHECK_ARG(!cipher, "Invalid cipher.", NULL);
    CHECK_ARG(!data, "Invalid data.", NULL);
    CHECK_ARG(!nonce, "Invalid nonce.", NULL);
    CHECK_ARG(!clearTextLen, "Invalid cipherTextLen.", NULL);

    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized; it is not safe to use */
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Init cipher failed.");
        return NULL;
    }

    if (cipher->isCurve25519) {
        CHECK_ARG(dataLen <= crypto_box_MACBYTES, "Invalid dataLen.", NULL);

        ctlen = dataLen - crypto_box_MACBYTES;
        clearText = (unsigned char *)malloc(ctlen);
        if (!clearText) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create clear text memory.");
            return NULL;
        }

        ret = crypto_box_open_easy_afternm(clearText, data, dataLen, nonce, cipher->encryptKey);
        if (ret != 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to decrypt with curve25519.");
            free(clearText);
            return NULL;
        }
    } else {
        CHECK_ARG(dataLen <= crypto_aead_xchacha20poly1305_ietf_ABYTES, "Invalid dataLen.", NULL);

        ctlen = dataLen - crypto_aead_xchacha20poly1305_ietf_ABYTES;
        clearText = (unsigned char *)malloc(ctlen);
        if (!clearText) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create clear text memory..");
            return NULL;
        }

        ret = crypto_aead_xchacha20poly1305_ietf_decrypt(clearText, &clen,
                                                         NULL, data, dataLen, NULL, 0, nonce, cipher->privateKey);
        if (ret != 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to decrypt with xchacha20.");
            free(clearText);
            return NULL;
        }
    }

    if (clearTextLen) {
        *clearTextLen = ctlen;
    }
    return clearText;
}

Cipher_EncryptionStream *Cipher_EncryptionStream_Create(Cipher *cipher) {
    Cipher_EncryptionStream *stream;
    int ret;

    stream = (Cipher_EncryptionStream *)malloc(sizeof(Cipher_EncryptionStream));
    if (!stream) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create stream memory.");
        return NULL;
    }

    uint8_t *key = cipher->isCurve25519 ? cipher->encryptKey : cipher->privateKey;
    ret = crypto_secretstream_xchacha20poly1305_init_push(&stream->state, stream->header, key);
    if (ret != 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to initialize stream.");
        free(stream);
        return NULL;
    }

    return stream;
}

unsigned char *Cipher_EncryptionStream_Header(Cipher_EncryptionStream *stream, unsigned int *headerLen) {
    CHECK_ARG(!stream, "Invalid stream.", false);

    if (headerLen) {
        *headerLen = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    }
    return stream->header;
}

unsigned char *Cipher_EncryptionStream_Push(Cipher_EncryptionStream *stream, const unsigned char *data,
                                            unsigned int dataLen, bool isFinal, unsigned int *cipherTextLen) {
    unsigned char tag, *cipherText;
    int ret;
    unsigned int ctlen;

    CHECK_ARG(!stream, "Invalid stream.", NULL);
    CHECK_ARG(!data, "Invalid data.", NULL);
    CHECK_ARG(!cipherTextLen, "Invalid cipherTextLen.", NULL);

    tag = isFinal ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                  : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

    ctlen = dataLen + crypto_secretstream_xchacha20poly1305_ABYTES;
    cipherText = (unsigned char *)malloc(ctlen);
    if (!cipherText) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create cipher data memory.");
        return NULL;
    }

    ret = crypto_secretstream_xchacha20poly1305_push(&stream->state, cipherText, NULL, data, dataLen, NULL, 0, tag);
    if (ret != 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to encrypt data.");
        free(cipherText);
        return NULL;
    }

    if (cipherTextLen) {
        *cipherTextLen = ctlen;
    }
    return cipherText;
}

Cipher_DecryptionStream *Cipher_DecryptionStream_Create(Cipher *cipher, const unsigned char *header) {
    Cipher_DecryptionStream *stream;
    int ret;

    CHECK_ARG(!cipher, "Invalid cipher.", NULL);
    CHECK_ARG(!header, "Invalid header.", NULL);

    stream = (Cipher_DecryptionStream *)malloc(sizeof(Cipher_DecryptionStream));
    if (!stream) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create stream memory.");
        return NULL;
    }
    stream->isComplete = false;

    uint8_t *key = cipher->isCurve25519 ? cipher->encryptKey : cipher->privateKey;
    ret = crypto_secretstream_xchacha20poly1305_init_pull(&stream->state, header, key);
    if (ret != 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to initialize stream.");
        free(stream);
        return NULL;
    }

    return stream;
}

unsigned int Cipher_DecryptionStream_GetHeaderLen() {
    return crypto_secretstream_xchacha20poly1305_HEADERBYTES;
}

unsigned int Cipher_DecryptionStream_GetExtraEncryptSize() {
    return crypto_secretstream_xchacha20poly1305_ABYTES;
}

unsigned char *Cipher_DecryptionStream_Pull(Cipher_DecryptionStream *stream, const unsigned char *data,
                                            unsigned int dataLen, unsigned int *clearTextLen) {
    unsigned char tag, *clearText;
    int ret;
    unsigned int ctlen;

    CHECK_ARG(!stream, "Invalid stream.", NULL);
    CHECK_ARG(!data, "Invalid data.", NULL);
    CHECK_ARG(dataLen <= crypto_secretstream_xchacha20poly1305_ABYTES, "Invalid dataLen.", NULL);
    CHECK_ARG(!clearTextLen, "Invalid clearTextLen.", NULL);

    ctlen = dataLen - crypto_secretstream_xchacha20poly1305_ABYTES;
    clearText = (unsigned char *)malloc(ctlen);
    if (!clearText) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create clear data memory.");
        return NULL;
    }

    ret = crypto_secretstream_xchacha20poly1305_pull(&stream->state, clearText, NULL, &tag, data, dataLen, NULL, 0);
    if (ret != 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to decrypt data.");
        free(clearText);
        return NULL;
    }

    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        stream->isComplete = true;
    }

    if (clearTextLen) {
        *clearTextLen = ctlen;
    }
    return clearText;
}

bool Cipher_DecryptionStream_IsComplete(Cipher_DecryptionStream *stream) {
    CHECK_ARG(!stream, "Invalid stream.", false);

    return stream->isComplete;
}
