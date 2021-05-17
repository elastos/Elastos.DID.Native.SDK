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

#ifndef __DIDBACKEND_H__
#define __DIDBACKEND_H__

#include "ela_did.h"
#include "credentialbiography.h"

#ifdef __cplusplus
extern "C" {
#endif

int DIDBackend_CreateDID(DIDDocument *document, DIDURL *signkey, const char *storepass);

int DIDBackend_UpdateDID(DIDDocument *document, DIDURL *signkey, const char *storepass);

int DIDBackend_DeactivateDID(DIDDocument *signerdoc, DIDURL *signkey,
        DIDURL *creater, const char *storepass);

int DIDBackend_TransferDID(DIDDocument *document, TransferTicket *ticket,
        DIDURL *signkey, const char *storepass);

DIDBiography *DIDBackend_ResolveDIDBiography(DID *did);

int DIDBackend_DeclareCredential(Credential *vc, DIDURL *signkey,
        DIDDocument *document, const char *storepass);

DIDDocument *DIDBackend_ResolveDID(DID *did, int *status, bool force);

int DIDBackend_RevokeCredential(DIDURL *credid, DIDURL *signkey,
        DIDDocument *document,  const char *storepass);

Credential *DIDBackend_ResolveCredential(DIDURL *id, int *status, bool force);

int DIDBackend_ResolveRevocation(DIDURL *id, DID *issuer);

CredentialBiography *DIDBackend_ResolveCredentialBiography(DIDURL *id, DID *issuer);

ssize_t DIDBackend_ListCredentials(DID *did, DIDURL **buffer, size_t size,
        int skip, int limit);

#ifdef __cplusplus
}
#endif

#endif //__DIDBACKEND_H__
