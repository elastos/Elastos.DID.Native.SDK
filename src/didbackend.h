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
#include "backend/didrequest.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DIDBackend {
    DIDAdapter *adapter;
} DIDBackend;

bool DIDBackend_PublishDID(DIDBackend *backend, const char *payload);

DIDDocument *DIDBackend_Resolve(DID *did, bool force);

DIDHistory *DIDBackend_ResolveHistory(DID *did);

ssize_t DIDBackend_ResolvePayload(DID *did, DIDDocument **docs, int count, bool force);

ssize_t DIDBackend_ResolveRequest(DID *did, DIDRequest *reqs, int count, bool force);

bool DIDBackend_Create(DIDBackend *backend, DIDDocument *document,
        DIDURL *signkey, const char *storepass);

bool DIDBackend_Update(DIDBackend *backend, DIDDocument *document, DIDURL *signkey,
        const char *storepass);

bool DIDBackend_Deactivate(DIDBackend *backend, DID *did, DIDURL *signkey,
        const char *storepass);

#ifdef __cplusplus
}
#endif

#endif //__DIDBACKEND_H__