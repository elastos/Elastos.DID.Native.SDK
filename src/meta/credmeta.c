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
#include "did.h"
#include "didstore.h"
#include "common.h"
#include "credmeta.h"
#include "JsonGenerator.h"
#include "diddocument.h"
#include "diderror.h"

static const char *ALIAS = "alias";
static const char *PUBLISHED = "published";
static const char *REVOKED = "revoke";
static const char *TXID = "txid";

int CredentialMetadata_Store(CredentialMetadata *metadata)
{
    DIDURL id;

    assert(metadata);

    if (metadata->base.store && *metadata->id) {
        Parse_DIDURL(&id, metadata->id, NULL);
        return DIDStore_StoreCredMetadata(metadata->base.store, metadata, &id);
    }

    return 0;
}

int CredentialMetadata_ToJson_Internal(CredentialMetadata *metadata, JsonGenerator *gen)
{
    assert(metadata);
    assert(gen);

    return Metadata_ToJson_Internal(&metadata->base, gen);
}

const char *CredentialMetadata_ToJson(CredentialMetadata *metadata)
{
    assert(metadata);

    return Metadata_ToJson(&metadata->base);
}

int CredentialMetadata_FromJson_Internal(CredentialMetadata *metadata, json_t *json)
{
    assert(metadata);
    assert(json);

    return Metadata_FromJson_Internal(&metadata->base, json);
}

int CredentialMetadata_FromJson(CredentialMetadata *metadata, const char *data)
{
    assert(metadata);
    assert(data);

    return Metadata_FromJson(&metadata->base, data);
}

void CredentialMetadata_Free(CredentialMetadata *metadata)
{
    assert(metadata);

    Metadata_Free(&metadata->base);
}

int CredentialMetadata_Merge(CredentialMetadata *tometa, CredentialMetadata *frommeta)
{
    assert(tometa && frommeta);

    return Metadata_Merge(&tometa->base, &frommeta->base);
}

int CredentialMetadata_Copy(CredentialMetadata *tometa, CredentialMetadata *frommeta)
{
    assert(tometa && frommeta);

    return Metadata_Copy(&tometa->base, &frommeta->base);
}

void CredentialMetadata_SetStore(CredentialMetadata *metadata, DIDStore *store)
{
    assert(metadata);
    assert(store);

    Metadata_SetStore(&metadata->base, store);
}

int CredentialMetadata_SetRevoke(CredentialMetadata *metadata, bool revoke)
{
    assert(metadata);

    if (Metadata_SetDefaultExtraWithBoolean(&metadata->base, REVOKED, revoke) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;
}

bool CredentialMetadata_GetRevoke(CredentialMetadata *metadata)
{
    if (!metadata) {
        DIDError_Set(DIDERR_INVALID_ARGS, "There is not meta data for credential.");
        return false;
    }

    return Metadata_GetDefaultExtraAsBoolean(&metadata->base, REVOKED);
}

int CredentialMetadata_SetPublished(CredentialMetadata *metadata, time_t time)
{
    assert(metadata);

    if (Metadata_SetDefaultExtraWithInteger(&metadata->base, PUBLISHED, time) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;
}

time_t CredentialMetadata_GetPublished(CredentialMetadata *metadata)
{
    if (!metadata) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    return (time_t)Metadata_GetDefaultExtraAsInteger(&metadata->base, PUBLISHED);
}

DIDStore *CredentialMetadata_GetStore(CredentialMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetStore(&metadata->base);
}

bool CredentialMetadata_AttachedStore(CredentialMetadata *metadata)
{
    assert(metadata);

    return Metadata_AttachedStore(&metadata->base);
}

int CredentialMetadata_SetTxid(CredentialMetadata *metadata, const char *txid)
{
    assert(metadata);

    if (Metadata_SetDefaultExtra(&metadata->base, TXID, txid) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;
}

const char *CredentialMetadata_GetTxid(CredentialMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, TXID);
}

//****** DID_API
int CredentialMetadata_SetAlias(CredentialMetadata *metadata, const char *alias)
{
    if (!metadata) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (Metadata_SetDefaultExtra(&metadata->base, ALIAS, alias) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;
}

const char *CredentialMetadata_GetAlias(CredentialMetadata *metadata)
{
    if (!metadata) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return Metadata_GetDefaultExtra(&metadata->base, ALIAS);
}

int CredentialMetadata_SetExtra(CredentialMetadata *metadata, const char* key, const char *value)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (Metadata_SetExtra(&metadata->base, key, value) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;
}

int CredentialMetadata_SetExtraWithBoolean(CredentialMetadata *metadata, const char *key, bool value)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (Metadata_SetExtraWithBoolean(&metadata->base, key, value) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;
}

int CredentialMetadata_SetExtraWithDouble(CredentialMetadata *metadata, const char *key, double value)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (Metadata_SetExtraWithDouble(&metadata->base, key, value) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;
}

const char *CredentialMetadata_GetExtra(CredentialMetadata *metadata, const char *key)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return Metadata_GetExtra(&metadata->base, key);
}

bool CredentialMetadata_GetExtraAsBoolean(CredentialMetadata *metadata, const char *key)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return Metadata_GetExtraAsBoolean(&metadata->base, key);
}

double CredentialMetadata_GetExtraAsDouble(CredentialMetadata *metadata, const char *key)
{
    if (!metadata || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    return Metadata_GetExtraAsDouble(&metadata->base, key);
}
