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

#ifndef __IDENTITYMETA_H__
#define __IDENTITYMETA_H__

#include <jansson.h>

#include "ela_did.h"
#include "JsonGenerator.h"
#include "meta.h"

#ifdef __cplusplus
extern "C" {
#endif

struct IdentityMetadata {
    Metadata base;
};

const char *IdentityMetadata_ToJson(IdentityMetadata *metadata);

int IdentityMetadata_ToJson_Internal(IdentityMetadata *metadata, JsonGenerator *gen);

int IdentityMetadata_FromJson(IdentityMetadata *metadata, const char *data);

int IdentityMetadata_FromJson_Internal(IdentityMetadata *metadata, json_t *json);

const char *IdentityMetadata_ToString(IdentityMetadata *metadata);

void IdentityMetadata_Free(IdentityMetadata *metadata);

int IdentityMetadata_SetAlias(IdentityMetadata *metadata, const char *alias);

int IdentityMetadata_SetDefaultDID(IdentityMetadata *metadata, const char *did);

const char *IdentityMetadata_GetAlias(IdentityMetadata *metadata);

const char *IdentityMetadata_GetDefaultDID(IdentityMetadata *metadata);

int IdentityMetadata_Merge(IdentityMetadata *metadata, IdentityMetadata *frommeta);

int IdentityMetadata_Copy(IdentityMetadata *metadata, IdentityMetadata *frommeta);

void IdentityMetadata_SetStore(IdentityMetadata *metadata, DIDStore *store);

DIDStore *IdentityMetadata_GetStore(IdentityMetadata *metadata);

bool IdentityMetadata_AttachedStore(IdentityMetadata *metadata);

#ifdef __cplusplus
}
#endif

#endif //__IDENTITYMETA_H__
