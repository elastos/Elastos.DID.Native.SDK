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

#ifndef __VCTRANSACTIONINFO_H__
#define __VCTRANSACTIONINFO_H__

#include <jansson.h>

#include "ela_did.h"
#include "vcrequest.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CredentialTransaction {
    char txid[ELA_MAX_TXID_LEN];
    time_t timestamp;

    CredentialRequest request;
} CredentialTransaction;

int CredentialTransaction_FromJson(CredentialTransaction *txinfo, json_t *json);

void CredentialTransaction_Destroy(CredentialTransaction *txinfo);

void CredentialTransaction_Free(CredentialTransaction *txinfo);

int CredentialTransaction_ToJson_Internal(JsonGenerator *gen, CredentialTransaction *info);

const char *CredentialTransaction_ToJson(CredentialTransaction *txinfo);

CredentialRequest *CredentialTransaction_GetRequest(CredentialTransaction *txinfo);

const char *CredentialTransaction_GetTransactionId(CredentialTransaction *txinfo);

time_t CredentialTransaction_GetTimeStamp(CredentialTransaction *txinfo);

DID *CredentialTransaction_GetOwner(CredentialTransaction *txinfo);

DIDURL *CredentialTransaction_GetId(CredentialTransaction *txinfo);

#ifdef __cplusplus
}
#endif

#endif //__VCTRANSACTIONINFO_H__