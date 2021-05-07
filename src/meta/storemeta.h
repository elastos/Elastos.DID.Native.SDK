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

#ifndef __STOREMETA_H__
#define __STOREMETA_H__

#include <jansson.h>

#include "ela_did.h"
#include "JsonGenerator.h"
#include "meta.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StoreMetadata {
    Metadata base;
} StoreMetadata;

int StoreMetadata_Init(StoreMetadata *metadata, const char *type, const char *version,
        const char *fingerprint, const char *defaultrootidentity);

const char *StoreMetadata_ToJson(StoreMetadata *metadata);

int StoreMetadata_ToJson_Internal(StoreMetadata *metadata, JsonGenerator *gen);

int StoreMetadata_FromJson(StoreMetadata *metadata, const char *data);

int StoreMetadata_FromJson_Internal(StoreMetadata *metadata, json_t *json);

const char *StoreMetadata_ToString(StoreMetadata *metadata);

void StoreMetadata_Free(StoreMetadata *metadata);

int StoreMetadata_SetType(StoreMetadata *metadata, const char *type);

int StoreMetadata_SetVersion(StoreMetadata *metadata, const char *version);

int StoreMetadata_SetFingerPrint(StoreMetadata *metadata, const char *fingerprint);

int StoreMetadata_SetDefaultRootIdentity(StoreMetadata *metadata, const char *rootidentity);

const char *StoreMetadata_GetType(StoreMetadata *metadata);

const char *StoreMetadata_GetVersion(StoreMetadata *metadata);

const char *StoreMetadata_GetFingerPrint(StoreMetadata *metadata);

const char *StoreMetadata_GetDefaultRootIdentity(StoreMetadata *metadata);

int StoreMetadata_Merge(StoreMetadata *metadata, StoreMetadata *frommeta);

int StoreMetadata_Copy(StoreMetadata *metadata, StoreMetadata *frommeta);

void StoreMetadata_SetStore(StoreMetadata *metadata, DIDStore *store);

DIDStore *StoreMetadata_GetStore(StoreMetadata *metadata);

bool StoreMetadata_AttachedStore(StoreMetadata *metadata);

#ifdef __cplusplus
}
#endif

#endif //__STOREMETA_H__
