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
        DIDURL_Parse(&id, metadata->id, NULL);
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

int CredentialMetadata_GetRevoke(CredentialMetadata *metadata)
{
    CHECK_ARG(!metadata, "No credential metadata argument.", -1);

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
    CHECK_ARG(!metadata, "No credential metadata argument.", 0);

    return (time_t)Metadata_GetDefaultExtraAsLongLong(&metadata->base, PUBLISHED, 0);
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
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", NULL);

    return Metadata_GetDefaultExtra(&metadata->base, TXID);

    DIDERROR_FINALIZE();
}

int CredentialMetadata_SetAlias(CredentialMetadata *metadata, const char *alias)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", -1);

    if (Metadata_SetDefaultExtra(&metadata->base, ALIAS, alias) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;

    DIDERROR_FINALIZE();
}

const char *CredentialMetadata_GetAlias(CredentialMetadata *metadata)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", NULL);

    return Metadata_GetDefaultExtra(&metadata->base, ALIAS);

    DIDERROR_FINALIZE();
}

int CredentialMetadata_SetExtra(CredentialMetadata *metadata, const char* key, const char *value)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", -1);
    CHECK_ARG(!key || !*key, "Invalid key argument.", -1);

    if (Metadata_SetExtra(&metadata->base, key, value) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;

    DIDERROR_FINALIZE();
}

int CredentialMetadata_SetExtraWithBoolean(CredentialMetadata *metadata, const char *key, bool value)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", -1);
    CHECK_ARG(!key || !*key, "Invalid key argument.", -1);

    if (Metadata_SetExtraWithBoolean(&metadata->base, key, value) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;

    DIDERROR_FINALIZE();
}

int CredentialMetadata_SetExtraWithDouble(CredentialMetadata *metadata, const char *key, double value)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", -1);
    CHECK_ARG(!key || !*key, "Invalid key argument.", -1);

    if (Metadata_SetExtraWithDouble(&metadata->base, key, value) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;

    DIDERROR_FINALIZE();
}

int CredentialMetadata_SetExtraWithLongLong(CredentialMetadata *metadata,
        const char *key, long long value)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", -1);
    CHECK_ARG(!key || !*key, "Invalid key argument.", -1);

    if (Metadata_SetExtraWithLongLong(&metadata->base, key, value) < 0 ||
            CredentialMetadata_Store(metadata) < 0)
        return -1;

    return 0;

    DIDERROR_FINALIZE();
}

const char *CredentialMetadata_GetExtra(CredentialMetadata *metadata, const char *key)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", NULL);
    CHECK_ARG(!key || !*key, "Invalid key argument.", NULL);

    return Metadata_GetExtra(&metadata->base, key);

    DIDERROR_FINALIZE();
}

bool CredentialMetadata_GetExtraAsBoolean(CredentialMetadata *metadata, const char *key,
        bool dvalue)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", dvalue);
    CHECK_ARG(!key || !*key, "Invalid key argument.", dvalue);

    return Metadata_GetExtraAsBoolean(&metadata->base, key, dvalue);

    DIDERROR_FINALIZE();
}

double CredentialMetadata_GetExtraAsDouble(CredentialMetadata *metadata, const char *key,
        double dvalue)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", dvalue);
    CHECK_ARG(!key || !*key, "Invalid key argument.", dvalue);

    return Metadata_GetExtraAsDouble(&metadata->base, key, dvalue);

    DIDERROR_FINALIZE();
}

long long CredentialMetadata_GetExtraAsLongLong(CredentialMetadata *metadata,
        const char *key, long long dvalue)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!metadata, "No credential metadata argument.", dvalue);
    CHECK_ARG(!key || !*key, "Invalid key argument.", dvalue);

    return Metadata_GetExtraAsLongLong(&metadata->base, key, dvalue);

    DIDERROR_FINALIZE();
}
