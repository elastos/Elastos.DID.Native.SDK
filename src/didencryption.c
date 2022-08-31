#include "didencryption.h"

Cipher *Cipher_Create(uint8_t *key) {
    Cipher *cipher;

    assert(key, "Invalid key");

    cipher = (Cipher *)malloc(sizeof Cipher);
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

    assert(key, "Invalid key");

    ret = crypto_sign_seed_keypair(publicKey, privateKey, (unsigned char *)key);
    if (!ret) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create sign key pair.");
        return NULL;
    }

    Curve25519KeyPair *pair = (Curve25519KeyPair *)malloc(sizeof Curve25519KeyPair);
    if (!pair) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Create curve25519 key pair memory error.");
        return NULL;
    }

    ret = crypto_sign_ed25519_pk_to_curve25519(publicKey, pair->publicKey);
    if (!ret) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Convert curve25519 public key error.");
        goto ERROR_EXIT;
    }
    ret = crypto_sign_ed25519_sk_to_curve25519(privateKey, pair->privateKey);
    if (!ret) {
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

    assert(keyPair, "Invalid keyPair");
    assert(otherSidePublicKey, "Invalid otherSidePublicKey");

    cipher = (Cipher *)malloc(sizeof Cipher);
    if (!cipher) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Create cipher memory error.");
        return NULL;
    }

    cipher->isCurve25519 = true;
    memcpy(&cipher->keyPair, keyPair, sizeof Curve25519KeyPair);
    cipher->isServer = isServer;
    memcpy(cipher->otherSidePublicKey, otherSidePublicKey, crypto_scalarmult_curve25519_BYTES);

    ret = crypto_box_beforenm(cipher->encryptKey, otherSidePublicKey, keyPair->privateKey);
    if (!ret) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Create encrypt key error.");
        free(cipher);
        return NULL;
    }

    if (isServer) {
        ret = crypto_kx_server_session_keys(cipher->sharedKeyRx, cipher->sharedKeyTx, keyPair->privateKey, keyPair->publicKey, otherSidePublicKey);
    } else {
        ret = crypto_kx_client_session_keys(cipher->sharedKeyRx, cipher->sharedKeyTx, keyPair->privateKey, keyPair->publicKey, otherSidePublicKey);
    }
    if (!ret) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Create shared keys error.");
        free(cipher);
        return NULL;
    }

    return cipher;
}

uint8_t *Cipher_Encrypt(Cipher *cipher, uint8_t *data, unsigned int dataLen, uint8_t *nonce, int *cipherTextLen) {
    unsigned char *cipherText;
    int ret;

    CHECK_ARG(!cipher, "Invalid cipher.", NULL);
    CHECK_ARG(!data, "Invalid data.", NULL);
    CHECK_ARG(!nonce, "Invalid nonce.", NULL);
    CHECK_ARG(!cipherTextLen, "Invalid cipherTextLen.", NULL);

    if (cipher->isCurve25519) {
        *cipherTextLen = dataLen + crypto_box_MACBYTES;
        cipherText = (unsigned char *)malloc(*cipherTextLen);
        if (!cipherText) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create cipher text memory.");
            return NULL;
        }

        ret = crypto_box_easy_afternm(cipherText, data, dataLen, nonce, cipherText->encryptKey);
        if (!ret) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to encrypt with curve25519.");
            free(cipherText);
            return NULL;
        }
    } else {
        *cipherTextLen = dataLen + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        cipherText = (unsigned char *)malloc(*cipherTextLen);
        if (!cipherText) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create cipher text memory..");
            return NULL;
        }

        ret = crypto_aead_xchacha20poly1305_ietf_encrypt(cipherText, *cipherTextLen,
                                                         data, dataLen, NULL, 0, NULL, nonce, cipher->privateKey);
        if (!ret) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to encrypt with xchacha20.");
            free(cipherText);
            return NULL;
        }
    }

    return cipherText;
}

uint8_t *Cipher_Decrypt(Cipher *cipher, uint8_t *data, unsigned int dataLen, uint8_t *nonce, int *clearTextLen) {
    unsigned char *cipherText;
    int ret;

    CHECK_ARG(!cipher, "Invalid cipher.", NULL);
    CHECK_ARG(!data, "Invalid data.", NULL);
    CHECK_ARG(!nonce, "Invalid nonce.", NULL);
    CHECK_ARG(!cipherTextLen, "Invalid cipherTextLen.", NULL);

    if (cipher->isCurve25519) {
        CHECK_ARG(dataLen <= crypto_box_MACBYTES, "Invalid dataLen.", NULL);

        *clearTextLen = dataLen - crypto_box_MACBYTES;
        cipherText = (unsigned char *)malloc(*clearTextLen);
        if (!cipherText) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create clear text memory.");
            return NULL;
        }

        ret = crypto_box_open_easy_afternm(cipherText, data, dataLen, nonce, cipherText->encryptKey);
        if (!ret) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to decrypt with curve25519.");
            free(cipherText);
            return NULL;
        }
    } else {
        CHECK_ARG(dataLen <= crypto_aead_xchacha20poly1305_ietf_ABYTES, "Invalid dataLen.", NULL);

        *clearTextLen = dataLen - crypto_aead_xchacha20poly1305_ietf_ABYTES;
        cipherText = (unsigned char *)malloc(*clearTextLen);
        if (!cipherText) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create clear text memory..");
            return NULL;
        }

        ret = crypto_aead_xchacha20poly1305_ietf_decrypt(cipherText, *clearTextLen,
                                                         NULL, data, dataLen, NULL, 0, nonce, cipher->privateKey);
        if (!ret) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to decrypt with xchacha20.");
            free(cipherText);
            return NULL;
        }
    }

    return cipherText;
}

Cipher_EncryptionStream *Cipher_EncryptionStream_Create(Cipher *cipher) {
    Cipher_EncryptStream *stream;
    int ret;

    CHECK_ARG(!header, "Invalid header.", NULL);

    stream = (Cipher_EncryptStream *)malloc(sizeof Cipher_EncryptStream);
    if (!stream) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create stream memory.");
        return NULL;
    }

    uint8_t *key = cipher->isCurve25519 ? cipher->encryptKey : cipher->privateKey;
    ret = crypto_secretstream_xchacha20poly1305_init_push(&stream->state, stream->header, key);
    if (!ret) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to initialize stream.");
        free(stream);
        return NULL;
    }

    return stream;
}

uint8_t *Cipher_EncryptionStream_Header(Cipher_EncryptStream *stream, unsigned int *headerLen) {
    CHECK_ARG(!stream, "Invalid stream.", false);

    if (headerLen) {
        *headerLen = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    }
    return stream->header;
}

uint8_t *Cipher_EncryptionStream_Push(Cipher_DecryptStream *stream, uint8_t *data, unsigned int dataLen, bool isFinal) {
    unsigned char tag, *cipherText;
    int ret;

    CHECK_ARG(!stream, "Invalid stream.", NULL);
    CHECK_ARG(!data, "Invalid data.", NULL);

    tag = isFinal ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                  : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

    cipherText = (unsigned char *)malloc(dataLen + crypto_secretstream_xchacha20poly1305_ABYTES);
    if (!cipherText) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create cipher data memory.");
        return NULL;
    }

    ret = crypto_secretstream_xchacha20poly1305_push(&stream->state, cipherText, NULL, data, dataLen, NULL, 0, tag);
    if (!ret) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to encrypt data.");
        free(cipherText);
        return NULL;
    }

    return cipherText;
}

Cipher_DecryptStream *Cipher_DecryptionStream_Create(Cipher *cipher, uint8_t *header) {
    Cipher_DecryptStream *stream;
    int ret;

    CHECK_ARG(!cipher, "Invalid cipher.", NULL);
    CHECK_ARG(!header, "Invalid header.", NULL);

    stream = (Cipher_DecryptStream *)malloc(sizeof Cipher_DecryptStream);
    if (!stream) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create stream memory.");
        return NULL;
    }
    stream->isComplete = false;

    uint8_t *key = cipher->isCurve25519 ? cipher->encryptKey : cipher->privateKey;
    ret = crypto_secretstream_xchacha20poly1305_init_pull(&stream->state, header, key);
    if (!ret) {
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

uint8_t *Cipher_DecryptionStream_Pull(Cipher_DecryptStream *stream, uint8_t *data, unsigned int dataLen) {
    unsigned char tag, *clearText;
    int ret;

    CHECK_ARG(!stream, "Invalid stream.", NULL);
    CHECK_ARG(!data, "Invalid data.", NULL);
    CHECK_ARG(dataLen > crypto_secretstream_xchacha20poly1305_ABYTES, "Invalid dataLen.", NULL);

    clearText = (unsigned char *)malloc(dataLen - crypto_secretstream_xchacha20poly1305_ABYTES);
    if (!clearText) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to create clear data memory.");
        return NULL;
    }

    ret = crypto_secretstream_xchacha20poly1305_pull(&stream->state, clearText, NULL, &tag, data, dataLen, NULL, 0);
    if (!ret) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Failed to decrypt data.");
        free(clearText);
        return NULL;
    }

    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        stream->isComplete = true;
    }

    return cipherText;
}

bool Cipher_DecryptionStream_IsComplete(Cipher_DecryptStream *stream) {
    CHECK_ARG(!stream, "Invalid stream.", false);

    return stream->isComplete;
}
