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

#ifndef __CREDMETA_H__
#define __CREDMETA_H__

#include <jansson.h>

#include "JsonGenerator.h"
#include "meta.h"

#ifdef __cplusplus
extern "C" {
#endif

struct CredentialMetadata {
    Metadata base;
    char id[ELA_MAX_DIDURL_LEN];
};

int CredentialMetadata_ToJson_Internal(CredentialMetadata *metadata, JsonGenerator *gen);

const char *CredentialMetadata_ToJson(CredentialMetadata *metadata);

int CredentialMetadata_FromJson_Internal(CredentialMetadata *metadata, json_t *json);

int CredentialMetadata_FromJson(CredentialMetadata *metadata, const char *data);

void CredentialMetadata_Free(CredentialMetadata *metadata);

int CredentialMetadata_Merge(CredentialMetadata *tometa, CredentialMetadata *frommeta);

int CredentialMetadata_Copy(CredentialMetadata *tometa, CredentialMetadata *frommeta);

void CredentialMetadata_SetStore(CredentialMetadata *metadata, DIDStore *store);

DIDStore *CredentialMetadata_GetStore(CredentialMetadata *metadata);

int CredentialMetadata_SetRevoke(CredentialMetadata *metadata, bool revoke);

int CredentialMetadata_SetPublished(CredentialMetadata *metadata, time_t time);

int CredentialMetadata_SetTxid(CredentialMetadata *metadata, const char *txid);

bool CredentialMetadata_AttachedStore(CredentialMetadata *metadata);

int CredentialMetadata_Store(CredentialMetadata *metadata);

#ifdef __cplusplus
}
#endif

#endif //__CREDMETA_H__
