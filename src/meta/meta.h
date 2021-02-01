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

#ifndef __META_H__
#define __META_H__

#include <jansson.h>

#include "ela_did.h"
#include "JsonGenerator.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Metadata {
    json_t *data;
    DIDStore *store;
} Metadata;

const char *Metadata_ToJson(Metadata *metadata);

int Metadata_ToJson_Internal(Metadata *metadata, JsonGenerator *gen);

int Metadata_FromJson(Metadata *metadata, const char *data);
int Metadata_FromJson_Internal(Metadata *metadata, json_t *json);

const char *Metadata_ToString(Metadata *metadata);

void Metadata_Free(Metadata *metadata);
int Metadata_Merge(Metadata *tometa, Metadata *frommeta);
int Metadata_Copy(Metadata *metadata, Metadata *frommeta);

int Metadata_SetExtra(Metadata *metadata, const char* key, const char *value);
int Metadata_SetExtraWithBoolean(Metadata *metadata, const char *key, bool value);
int Metadata_SetExtraWithDouble(Metadata *metadata, const char *key, double value);
int Metadata_SetExtraWithInteger(Metadata *metadata, const char *key, int value);

const char *Metadata_GetExtra(Metadata *metadata, const char *key);
bool Metadata_GetExtraAsBoolean(Metadata *metadata, const char *key);
double Metadata_GetExtraAsDouble(Metadata *metadata, const char *key);
int Metadata_GetExtraAsInteger(Metadata *metadata, const char *key);

int Metadata_SetDefaultExtra(Metadata *metadata, const char* key, const char *value);
int Metadata_SetDefaultExtraWithBoolean(Metadata *metadata, const char *key, bool value);
int Metadata_SetDefaultExtraWithDouble(Metadata *metadata, const char *key, double value);
int Metadata_SetDefaultExtraWithInteger(Metadata *metadata, const char *key, int value);

const char *Metadata_GetDefaultExtra(Metadata *metadata, const char *key);
bool Metadata_GetDefaultExtraAsBoolean(Metadata *metadata, const char *key);
double Metadata_GetDefaultExtraAsDouble(Metadata *metadata, const char *key);
int Metadata_GetDefaultExtraAsInteger(Metadata *metadata, const char *key);

void Metadata_SetStore(Metadata *metadata, DIDStore *store);
DIDStore *Metadata_GetStore(Metadata *metadata);
bool Metadata_AttachedStore(Metadata *metadata);

#ifdef __cplusplus
}
#endif

#endif //__META_H__
