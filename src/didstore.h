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

#ifndef __DIDSTORE_H__
#define __DIDSTORE_H__

#include "ela_did.h"
#include "didbackend.h"
#include "didmeta.h"
#include "credmeta.h"
#include "storemeta.h"

#if defined(_WIN32) || defined(_WIN64)
    #include <crystal.h>
#else
    #include <limits.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PRIVATEKEY_BASE64           160

struct DIDStore {
    char root[PATH_MAX];
    StoreMetadata metadata;
};

int DIDStore_StoreDIDMetadata(DIDStore *store, DIDMetadata *meta, DID *did);

int DIDStore_StoreCredMetadata(DIDStore *store, CredentialMetadata *meta, DIDURL *id);

int DIDStore_Sign(DIDStore *store, const char *storepass, DID *did,
        DIDURL *key, char *sig, uint8_t *digest, size_t size);

ssize_t DIDStore_LoadRootIdentityPrvkey(DIDStore *store, const char *storepass,
        const char *id, uint8_t *extendedkey, size_t size);

ssize_t DIDStore_LoadPrivateKey(DIDStore *store, const char *storepass, DID *did,
        DIDURL *key, uint8_t *privatekey, size_t size);

ssize_t DIDStore_LoadPrivateKey_Internal(DIDStore *store, const char *storepass, DID *did,
        DIDURL *key, uint8_t *extendedkey, size_t size);

int DIDStore_StorePrivateKey_Internal(DIDStore *store, DID *did, DIDURL *id, const char *prvkey);

int DIDStore_StoreDefaultPrivateKey(DIDStore *store, const char *storepass,
        const char *idstring, uint8_t *privatekey, size_t size);

///////////////
int DIDStore_StoreRootIdentity(DIDStore *store, const char *storepass, RootIdentity *rootidentity);

DIDDocument *DIDStore_NewDIDByIndex(DIDStore *store, const char *storepass,
        const char *id, int index, const char *alias);

int DIDStore_StoreIndex(DIDStore *store, const char *id, int index);

int DIDStore_LoadIndex(DIDStore *store, const char *id);

DID *DIDStore_GetDIDByIndex(DIDStore *store, int index);

int DIDStore_StoreRootIdentityWithElem(DIDStore *store, const char *storepass, const char *id,
        const char *mnemonic, uint8_t *rootPrivatekey, size_t rootsize,
        uint8_t *preDerivedPublicKey, size_t keysize, int index);

int DIDStore_SetDefaultRootIdentity(DIDStore *store, const char *id);

#ifdef __cplusplus
}
#endif

#endif //__DIDSTORE_H__