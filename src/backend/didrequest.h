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

#ifndef __DIDREQUEST_H__
#define __DIDREQUEST_H__

#include <jansson.h>

#include "ela_did.h"
#include "JsonGenerator.h"
#include "did.h"

#ifdef __cplusplus
extern "C" {
#endif

#define  MAX_SPEC_LEN             32
#define  MAX_OP_LEN               32
#define  MAX_REQ_SIG_LEN          128

typedef struct RequestProof {
    DIDURL verificationMethod;
    char signature[MAX_REQ_SIG_LEN];
} RequestProof;

typedef struct DIDRequest {
    struct {
        char spec[MAX_SPEC_LEN];
        char op[MAX_OP_LEN];
        char prevtxid[ELA_MAX_TXID_LEN];
        int multisig_m;
        int multisig_n;
    } header;

    const char *payload;
    DIDDocument *doc;
    DID did;

    struct {
        size_t size;
        RequestProof *proofs;
    } proofs;

} DIDRequest;

typedef enum DIDRequest_Type
{
   RequestType_Create,
   RequestType_Update,
   RequestType_Deactivate
} DIDRequest_Type;

DIDDocument *DIDRequest_FromJson_Internal(DIDRequest *request, json_t *json);

DIDDocument *DIDRequest_FromJson(DIDRequest *request, const char *json);

void DIDRequest_Destroy(DIDRequest *request);

void DIDRequest_Free(DIDRequest *request);

const char* DIDRequest_Sign(DIDRequest_Type type, DIDDocument *document,
        DIDURL *signkey, const char *storepass);

int DIDRequest_Verify(DIDRequest *request);

int DIDRequest_ToJson_Internal(JsonGenerator *gen, DIDRequest *req);

//free the returned value
const char *DIDRequest_ToJson(DIDRequest *req);

bool DIDRequest_CheckWithPrevious(DIDRequest *request, DIDDocument *document);

bool DIDRequest_IsValid(DIDRequest *request);

#ifdef __cplusplus
}
#endif

#endif //__DIDREQUEST_H__