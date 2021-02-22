/*
 * Copyright (c) 2019 Elastos Foundation
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

#ifndef __ROOTIDENTITY_H__
#define __ROOTIDENTITY_H__

#include "ela_did.h"
#include "HDkey.h"
#include "common.h"
#include "identitymeta.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ROOT_PRIVATEKEY_BASE64_LEN     512

struct RootIdentity {
    char mnemonic[ELA_MAX_MNEMONIC_LEN];
    uint8_t rootPrivateKey[EXTENDEDKEY_BYTES];   //base64url encode extended private key
    uint8_t preDerivedPublicKey[EXTENDEDKEY_BYTES];    //extended public key
    int index;

    const char id[MAX_ID_LEN];
    IdentityMetadata metadata;
};

void RootIdentity_Wipe(RootIdentity *rootidentity);

ssize_t RootIdentity_LazyCreatePrivateKey(DIDURL *key, DIDStore *store, const char *storepass,
        uint8_t *extendedkey, size_t size);

#ifdef __cplusplus
}
#endif

#endif //__ROOTIDENTITY_H__
