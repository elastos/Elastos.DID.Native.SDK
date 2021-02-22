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

#ifndef __DIDDOCUMENT_H__
#define __DIDDOCUMENT_H__

#include <time.h>

#include "ela_did.h"
#include "did.h"
#include "didmeta.h"
#include "common.h"
#include "HDkey.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ENDPOINT                    256

typedef struct DocumentProof {
    char type[MAX_TYPE_LEN];
    time_t created;
    DIDURL creater;
    char signatureValue[MAX_SIGNATURE_LEN];
} DocumentProof;

struct DIDDocument {
    DID did;

    struct {                  //optional
        size_t size;
        DIDDocument **docs;
    } controllers;

    int multisig;

    struct {
        size_t size;
        PublicKey **pks;
    } publickeys;

    struct {
        size_t size;
        Credential **credentials;
    } credentials;

    struct {
        size_t size;
        Service **services;
    } services;

    struct {
        size_t size;
        DocumentProof *proofs;
    } proofs;

    time_t expires;
    DIDMetadata metadata;
};

struct PublicKey {
    DIDURL id;
    char type[MAX_TYPE_LEN];
    DID controller;
    char publicKeyBase58[PUBLICKEY_BASE58_BYTES];
    bool authenticationKey;
    bool authorizationKey;
};

struct Service {
    DIDURL id;
    char type[MAX_TYPE_LEN];
    char endpoint[MAX_ENDPOINT];
};

struct DIDDocumentBuilder {
    DIDDocument *document;
    DIDDocument *controllerdoc;
};

int DIDDocument_SetStore(DIDDocument *document, DIDStore *store);

int DIDDocument_ToJson_Internal(JsonGenerator *gen, DIDDocument *doc,
        bool compact, bool forsign);

DIDDocument *DIDDocument_FromJson_Internal(json_t *root);

DIDDocument *DIDDocument_GetControllerDocument(DIDDocument *doc, DID *controller);

size_t DIDDocument_GetSelfAuthenticationKeyCount(DIDDocument *document);

DIDDocumentBuilder* DIDDocument_CreateBuilder(DID *did, DIDDocument *controllerdoc, DIDStore *store);

bool DIDDocument_IsValid_Internal(DIDDocument *document, bool isqualified);

int DIDDocument_Copy(DIDDocument *destdoc, DIDDocument *srcdoc);

const char *DIDDocument_Merge(DIDDocument **documents, size_t size);

ssize_t DIDDocument_GetDigest(DIDDocument *document, uint8_t *digest, size_t size);

#ifdef __cplusplus
}
#endif

#endif //__DIDDOCUMENT_H__
