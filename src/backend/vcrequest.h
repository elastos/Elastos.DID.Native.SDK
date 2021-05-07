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

#ifndef __VCREQUEST_H__
#define __VCREQUEST_H__

#include <jansson.h>

#include "ela_did.h"
#include "JsonGenerator.h"
#include "did.h"

#ifdef __cplusplus
extern "C" {
#endif

#define  MAX_SPEC_LEN             32
#define  MAX_OP_LEN               32

typedef struct CredentialRequest {
    struct {
        char spec[MAX_SPEC_LEN];
        char op[MAX_OP_LEN];
    } header;

    const char *payload;
    //todo: remove it
    Credential *vc;
    DIDURL id;

    struct {
        DIDURL verificationMethod;
        char signature[MAX_SIGNATURE_LEN];
    } proof;
} CredentialRequest;

typedef enum CredentialRequest_Type
{
   RequestType_Declare,
   RequestType_Revoke
} CredentialRequest_Type;

const char *CredentialRequest_Sign(CredentialRequest_Type type, DIDURL *credid,
        Credential *credential, DIDURL *signkey, DIDDocument *document, const char *storepass);

const char *CredentialRequest_ToJson(CredentialRequest *request);

int CredentialRequest_FromJson(CredentialRequest *request, json_t *json);

void CredentialRequest_Destroy(CredentialRequest *request);

void CredentialRequest_Free(CredentialRequest *request);

int CredentialRequest_ToJson_Internal(JsonGenerator *gen, CredentialRequest *request);

bool CredentialRequest_IsValid(CredentialRequest *request, Credential *credential);

#ifdef __cplusplus
}
#endif

#endif //__VCREQUEST_H__