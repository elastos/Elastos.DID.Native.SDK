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

#ifndef __DIDENCRYPTION_H__
#define __DIDENCRYPTION_H__

#include <stdbool.h>
#include <time.h>
#include <sodium.h>

#include "ela_did.h"
#include "did.h"
#include "didurl.h"
#include "didmeta.h"
#include "common.h"
#include "HDkey.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Curve25519KeyPair {
    unsigned char privateKey[crypto_scalarmult_curve25519_BYTES];
    unsigned char publicKey[crypto_scalarmult_curve25519_BYTES];
} Curve25519KeyPair;

struct Cipher {
    bool isCurve25519;

    // xchacha20poly1305
    uint8_t privateKey[PRIVATEKEY_BYTES]; // key for symmetric encryption

    // curve25519
    Curve25519KeyPair keyPair;
    bool isServer; // here is server side or client side.
    uint8_t encryptKey[crypto_box_BEFORENMBYTES]; // key for symmetric encryption
    uint8_t otherSidePublicKey[crypto_scalarmult_curve25519_BYTES];
    uint8_t sharedKeyTx[crypto_kx_SESSIONKEYBYTES]; // keys for asymmetric encryption
    uint8_t sharedKeyRx[crypto_kx_SESSIONKEYBYTES];
};

struct Cipher_EncryptionStream {
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;
};

struct Cipher_DecryptionStream {
    crypto_secretstream_xchacha20poly1305_state state;
    bool isComplete;
};

Cipher *Cipher_Create(uint8_t *key);

Curve25519KeyPair *Cipher_CreateCurve25519KeyPair(uint8_t *key);

Cipher *Cipher_CreateCurve25519(Curve25519KeyPair *keyPair, bool isServer, uint8_t *otherSidePublicKey);

#ifdef __cplusplus
}
#endif

#endif //__DIDENCRYPTION_H__
