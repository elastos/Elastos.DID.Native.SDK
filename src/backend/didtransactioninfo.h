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

#ifndef __DIDTRANSACTIONINFO_H__
#define __DIDTRANSACTIONINFO_H__

#include <jansson.h>

#include "ela_did.h"
#include "didrequest.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DIDTransaction {
    char txid[ELA_MAX_TXID_LEN];
    time_t timestamp;

    DIDRequest request;
} DIDTransaction;

int DIDTransaction_FromJson(DIDTransaction *txinfo, json_t *json);

void DIDTransaction_Destroy(DIDTransaction *txinfo);

void DIDTransaction_Free(DIDTransaction *txinfo);

int DIDTransaction_ToJson_Internal(JsonGenerator *gen, DIDTransaction *info);

const char *DIDTransaction_ToJson(DIDTransaction *txinfo);

DIDRequest *DIDTransaction_GetRequest(DIDTransaction *txinfo);

const char *DIDTransaction_GetTransactionId(DIDTransaction *txinfo);

time_t DIDTransaction_GetTimeStamp(DIDTransaction *txinfo);

DID *DIDTransaction_GetOwner(DIDTransaction *txinfo);

#ifdef __cplusplus
}
#endif

#endif //__DIDTRANSACTIONINFO_H__
