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
#include <time.h>
#include <assert.h>

#include "ela_did.h"
#include "did.h"
#include "didmeta.h"
#include "JsonGenerator.h"
#include "common.h"
#include "diddocument.h"
#include "diderror.h"

static const char *ROOTIDENTITY = "rootidentity";
static const char *INDEX = "index";
static const char *ALIAS = "alias";
static const char *TXID = "txid";
static const char *PREV_SIGNATURE = "prevSignature";
static const char *SIGNATURE = "signature";
static const char *PUBLISHED = "published";
static const char *DEACTIVATED = "deactivated";

int DIDMetadata_ToJson_Internal(DIDMetadata *metadata, JsonGenerator *gen)
{
    assert(metadata);

    return Metadata_ToJson_Internal(&metadata->base, gen);
}

const char *DIDMetadata_ToJson(DIDMetadata *metadata)
{
    assert(metadata);

    return Metadata_ToJson(&metadata->base);
}

int DIDMetadata_FromJson_Internal(DIDMetadata *metadata, json_t *json)
{
    assert(metadata);

    return Metadata_FromJson_Internal(&metadata->base, json);
}

int DIDMetadata_FromJson(DIDMetadata *metadata, const char *data)
{
    assert(metadata);

    return Metadata_FromJson(&metadata->base, data);
}

const char *DIDMetadata_ToString(DIDMetadata *metadata)
{
    assert(metadata);

    return Metadata_ToString(&metadata->base);
}

void DIDMetadata_Free(DIDMetadata *metadata)
{
    if (metadata)
        Metadata_Free(&metadata->base);
}

int DIDMetadata_SetDeactivated(DIDMetadata *metadata, bool deactived)
{
    assert(metadata);

    return Metadata_SetDefaultExtraWithBoolean(&metadata->base, DEACTIVATED, deactived);
}

int DIDMetadata_SetPublished(DIDMetadata *metadata, time_t time)
{
    assert(metadata);

    return Metadata_SetDefaultExtraWithInteger(&metadata->base, PUBLISHED, time);
}

int DIDMetadata_SetTxid(DIDMetadata *metadata, const char *txid)
{
    assert(metadata);

    return Metadata_SetDefaultExtra(&metadata->base, TXID, txid);
}

int DIDMetadata_SetSignature(DIDMetadata *metadata, const char *signature)
{
    assert(metadata);

    return Metadata_SetDefaultExtra(&metadata->base, SIGNATURE, signature);
}

int DIDMetadata_SetPrevSignature(DIDMetadata *metadata, const char *signature)
{
    assert(metadata);

    return Metadata_SetDefaultExtra(&metadata->base, PREV_SIGNATURE, signature);
}

int DIDMetadata_SetRootIdentity(DIDMetadata *metadata, const char *rootidentity)
{
    assert(metadata);

    return Metadata_SetDefaultExtra(&metadata->base, ROOTIDENTITY, rootidentity);
}

int DIDMetadata_SetIndex(DIDMetadata *metadata, int index)
{
    assert(metadata);

    return Metadata_SetDefaultExtraWithInteger(&metadata->base, INDEX, index);
}

const char *DIDMetadata_GetRootIdentity(DIDMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, SIGNATURE);
}

int DIDMetadata_GetIndex(DIDMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtraAsInteger(&metadata->base, INDEX);
}

const char *DIDMetadata_GetTxid(DIDMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, TXID);
}

const char *DIDMetadata_GetSignature(DIDMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, SIGNATURE);
}

const char *DIDMetadata_GetPrevSignature(DIDMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, PREV_SIGNATURE);
}

int DIDMetadata_Merge(DIDMetadata *tometa, DIDMetadata *frommeta)
{
    assert(tometa && frommeta);

    return Metadata_Merge(&tometa->base, &frommeta->base);
}

int DIDMetadata_Copy(DIDMetadata *tometa, DIDMetadata *frommeta)
{
    assert(tometa && frommeta);

    return Metadata_Copy(&tometa->base, &frommeta->base);
}

void DIDMetadata_SetStore(DIDMetadata *metadata, DIDStore *store)
{
    assert(metadata);

    Metadata_SetStore(&metadata->base, store);
}

DIDStore *DIDMetadata_GetStore(DIDMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetStore(&metadata->base);
}

bool DIDMetadata_AttachedStore(DIDMetadata *metadata)
{
    bool attached;

    assert(metadata);

    attached = Metadata_AttachedStore(&metadata->base);
    if (!attached)
        DIDError_Set(DIDERR_MALFORMED_META, "No attached did store.");

    return attached;
}

//******** DID_API
time_t DIDMetadata_GetPublished(DIDMetadata *metadata)
{
    if (!metadata) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    return (time_t)Metadata_GetDefaultExtraAsInteger(&metadata->base, PUBLISHED);
}

bool DIDMetadata_GetDeactivated(DIDMetadata *metadata)
{
    if (!metadata) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return Metadata_GetDefaultExtraAsBoolean(&metadata->base, DEACTIVATED);
}

int DIDMetadata_SetAlias(DIDMetadata *metadata, const char *alias)
{
    if (!metadata) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return Metadata_SetDefaultExtra(&metadata->base, ALIAS, alias);
}

const char *DIDMetadata_GetAlias(DIDMetadata *metadata)
{
    if (!metadata) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return Metadata_GetDefaultExtra(&metadata->base, ALIAS);
}

int DIDMetadata_SetExtra(DIDMetadata *metadata, const char* key, const char *value)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return Metadata_SetExtra(&metadata->base, key, value);
}

int DIDMetadata_SetExtraWithBoolean(DIDMetadata *metadata, const char *key, bool value)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return Metadata_SetExtraWithBoolean(&metadata->base, key, value);
}

int DIDMetadata_SetExtraWithDouble(DIDMetadata *metadata, const char *key, double value)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return Metadata_SetExtraWithDouble(&metadata->base, key, value);
}

const char *DIDMetadata_GetExtra(DIDMetadata *metadata, const char *key)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }


    return Metadata_GetExtra(&metadata->base, key);
}

bool DIDMetadata_GetExtraAsBoolean(DIDMetadata *metadata, const char *key)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return Metadata_GetExtraAsBoolean(&metadata->base, key);
}

double DIDMetadata_GetExtraAsDouble(DIDMetadata *metadata, const char *key)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    return Metadata_GetExtraAsDouble(&metadata->base, key);
}
