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

#ifndef __DIDBACKEND_H__
#define __DIDBACKEND_H__

#include "ela_did.h"
#include "credentialhistory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DIDBackend {
    DIDAdapter adapter;
} DIDBackend;

bool DIDBackend_CreateDID(DIDBackend *backend, DIDDocument *document,
        DIDURL *signkey, const char *storepass);

bool DIDBackend_UpdateDID(DIDBackend *backend, DIDDocument *document,
        DIDURL *signkey, const char *storepass);

bool DIDBackend_DeactivateDID(DIDBackend *backend, DID *did,
        DIDURL *signkey, const char *storepass);

DIDDocument *DIDBackend_ResolveDID(DID *did, bool force);

DIDHistory *DIDBackend_ResolveDIDHistory(DID *did);

bool DIDBackend_DeclearCredential(DIDBackend *backend, Credential *vc, DIDURL *signkey,
        DIDDocument *document, const char *storepass);

bool DIDBackend_RevokeCredential(DIDBackend *backend, DIDURL *credid, DIDURL *signkey,
        DIDDocument *document,  const char *storepass);

Credential *DIDBackend_ResolveCredential(DIDURL *id, int *status, bool force);

CredentialHistory *DIDBackend_ResolveCredentialHistory(CredentialHistory *history, DIDURL *id);

#ifdef __cplusplus
}
#endif

#endif //__DIDBACKEND_H__