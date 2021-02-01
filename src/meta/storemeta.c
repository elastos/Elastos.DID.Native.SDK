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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ela_did.h"
#include "identitymeta.h"
#include "JsonGenerator.h"
#include "common.h"
#include "diderror.h"
#include "storemeta.h"

static const char *TYPE = "type";
static const char *VERSION = "version";
static const char *FINGERPRINT = "fingerprint";
static const char *ROOTIDENTITY = "defaultRootIdentity";

int StoreMetadata_Init(StoreMetadata *metadata, const char *type, const char *version,
        const char *fingerprint, const char *defaultrootidentity)
{
    char string[32];

    assert(metadata);
    assert(type);
    assert(version);
    assert(fingerprint);

    memset(metadata, 0, sizeof(StoreMetadata));
    if (type && StoreMetadata_SetType(metadata, type) < 0)
        goto errorExit;
    if (StoreMetadata_SetFingerPrint(metadata, fingerprint) < 0 ||
           StoreMetadata_SetVersion(metadata, string) < 0)
        goto errorExit;

    if (defaultrootidentity && StoreMetadata_SetDefaultRootIdentity(metadata, defaultrootidentity) < 0)
        goto errorExit;

    return 0;

errorExit:
    memset(metadata, 0, sizeof(StoreMetadata));
    return -1;
}

int StoreMetadata_ToJson_Internal(StoreMetadata *metadata, JsonGenerator *gen)
{
    assert(metadata);

    return Metadata_ToJson_Internal(&metadata->base, gen);
}

const char *StoreMetadata_ToJson(StoreMetadata *metadata)
{
    assert(metadata);

    return Metadata_ToJson(&metadata->base);
}

int StoreMetadata_FromJson_Internal(StoreMetadata *metadata, json_t *json)
{
    assert(metadata);

    return Metadata_FromJson_Internal(&metadata->base, json);
}

int StoreMetadata_FromJson(StoreMetadata *metadata, const char *data)
{
    assert(metadata);

    return Metadata_FromJson(&metadata->base, data);
}

const char *StoreMetadata_ToString(StoreMetadata *metadata)
{
    assert(metadata);

    return Metadata_ToString(&metadata->base);
}

void StoreMetadata_Free(StoreMetadata *metadata)
{
    if (metadata)
        Metadata_Free(&metadata->base);
}

int StoreMetadata_SetType(StoreMetadata *metadata, const char *type)
{
    assert(metadata);

    return Metadata_SetDefaultExtra(&metadata->base, TYPE, type);
}

int StoreMetadata_SetVersion(StoreMetadata *metadata, const char *version)
{
    assert(metadata);

    return Metadata_SetDefaultExtra(&metadata->base, VERSION, version);
}

int StoreMetadata_SetFingerPrint(StoreMetadata *metadata, const char *fingerprint)
{
    assert(metadata);

    return Metadata_SetDefaultExtra(&metadata->base, FINGERPRINT, fingerprint);
}

int StoreMetadata_SetDefaultRootIdentity(StoreMetadata *metadata, const char *rootidentity)
{
    assert(metadata);

    return Metadata_SetDefaultExtra(&metadata->base, ROOTIDENTITY, rootidentity);
}

const char *StoreMetadata_GetType(StoreMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, TYPE);
}

const char *StoreMetadata_GetVersion(StoreMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, VERSION);
}

const char *StoreMetadata_GetFingerPrint(StoreMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, FINGERPRINT);
}

const char *StoreMetadata_GetDefaultRootIdentity(StoreMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, ROOTIDENTITY);
}

int StoreMetadata_Merge(StoreMetadata *tometa, StoreMetadata *frommeta)
{
    assert(tometa && frommeta);

    return Metadata_Merge(&tometa->base, &frommeta->base);
}

int StoreMetadata_Copy(StoreMetadata *tometa, StoreMetadata *frommeta)
{
    assert(tometa && frommeta);

    return Metadata_Copy(&tometa->base, &frommeta->base);
}

void StoreMetadata_SetStore(StoreMetadata *metadata, DIDStore *store)
{
    assert(metadata);

    Metadata_SetStore(&metadata->base, store);
}

DIDStore *StoreMetadata_GetStore(StoreMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetStore(&metadata->base);
}

bool StoreMetadata_AttachedStore(StoreMetadata *metadata)
{
    bool bAttached;

    assert(metadata);

    bAttached = Metadata_AttachedStore(&metadata->base);
    if (!bAttached)
        DIDError_Set(DIDERR_MALFORMED_META, "No attached did store.");

    return bAttached;
}
