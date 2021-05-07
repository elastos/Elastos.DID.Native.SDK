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

#ifndef __DIDMETA_H__
#define __DIDMETA_H__

#include <jansson.h>

#include "ela_did.h"
#include "JsonGenerator.h"
#include "meta.h"

#ifdef __cplusplus
extern "C" {
#endif

struct DIDMetadata {
    Metadata base;
    char did[ELA_MAX_DID_LEN];
};

const char *DIDMetadata_ToJson(DIDMetadata *metadata);

int DIDMetadata_ToJson_Internal(DIDMetadata *metadata, JsonGenerator *gen);

int DIDMetadata_FromJson(DIDMetadata *metadata, const char *data);

int DIDMetadata_FromJson_Internal(DIDMetadata *metadata, json_t *json);

const char *DIDMetadata_ToString(DIDMetadata *metadata);

void DIDMetadata_Free(DIDMetadata *metadata);

int DIDMetadata_SetDeactivated(DIDMetadata *metadata, bool deactived);

int DIDMetadata_SetPublished(DIDMetadata *metadata, time_t time);

int DIDMetadata_SetRootIdentity(DIDMetadata *metadata, const char *rootidentity);

int DIDMetadata_SetIndex(DIDMetadata *metadata, int index);

const char *DIDMetadata_GetSignature(DIDMetadata *metadata);

const char *DIDMetadata_GetRootIdentity(DIDMetadata *metadata);

int DIDMetadata_GetIndex(DIDMetadata *metadata);

int DIDMetadata_Merge(DIDMetadata *metadata, DIDMetadata *frommeta);

int DIDMetadata_Copy(DIDMetadata *metadata, DIDMetadata *frommeta);

void DIDMetadata_SetStore(DIDMetadata *metadata, DIDStore *store);

DIDStore *DIDMetadata_GetStore(DIDMetadata *metadata);

bool DIDMetadata_AttachedStore(DIDMetadata *metadata);

int DIDMetadata_Store(DIDMetadata *metadata);

//for DID_API
DID_API const char *DIDMetadata_GetPrevSignature(DIDMetadata *metadata);

DID_API int DIDMetadata_SetTxid(DIDMetadata *metadata, const char *txid);

DID_API int DIDMetadata_SetSignature(DIDMetadata *metadata, const char *signature);

DID_API int DIDMetadata_SetPrevSignature(DIDMetadata *metadata, const char *signature);

DID_API const char *DIDMetadata_GetTxid(DIDMetadata *metadata);

#ifdef __cplusplus
}
#endif

#endif //__DIDMETA_H__
