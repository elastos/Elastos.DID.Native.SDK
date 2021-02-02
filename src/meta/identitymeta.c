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
#include "meta.h"

static const char *ALIAS = "alias";
static const char *DEFAULTDID = "default";

int IdentityMetadata_ToJson_Internal(IdentityMetadata *metadata, JsonGenerator *gen)
{
    assert(metadata);

    return Metadata_ToJson_Internal(&metadata->base, gen);
}

const char *IdentityMetadata_ToJson(IdentityMetadata *metadata)
{
    assert(metadata);

    return Metadata_ToJson(&metadata->base);
}

int IdentityMetadata_FromJson_Internal(IdentityMetadata *metadata, json_t *json)
{
    assert(metadata);

    return Metadata_FromJson_Internal(&metadata->base, json);
}

int IdentityMetadata_FromJson(IdentityMetadata *metadata, const char *data)
{
    assert(metadata);

    return Metadata_FromJson(&metadata->base, data);
}

const char *IdentityMetadata_ToString(IdentityMetadata *metadata)
{
    assert(metadata);

    return Metadata_ToString(&metadata->base);
}

void IdentityMetadata_Free(IdentityMetadata *metadata)
{
    if (metadata)
        Metadata_Free(&metadata->base);
}

int IdentityMetadata_SetAlias(IdentityMetadata *metadata, const char *alias)
{
    assert(metadata);

    return Metadata_SetDefaultExtra(&metadata->base, ALIAS, alias);
}

int IdentityMetadata_SetDefaultDID(IdentityMetadata *metadata, const char *did)
{
    assert(metadata);

    return Metadata_SetDefaultExtra(&metadata->base, DEFAULTDID, did);
}

const char *IdentityMetadata_GetAlias(IdentityMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, ALIAS);
}

const char *IdentityMetadata_GetDefaultDID(IdentityMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetDefaultExtra(&metadata->base, DEFAULTDID);
}

int IdentityMetadata_Merge(IdentityMetadata *tometa, IdentityMetadata *frommeta)
{
    assert(tometa && frommeta);

    return Metadata_Merge(&tometa->base, &frommeta->base);
}

int IdentityMetadata_Copy(IdentityMetadata *tometa, IdentityMetadata *frommeta)
{
    assert(tometa && frommeta);

    return Metadata_Copy(&tometa->base, &frommeta->base);
}

void IdentityMetadata_SetStore(IdentityMetadata *metadata, DIDStore *store)
{
    assert(metadata);

    Metadata_SetStore(&metadata->base, store);
}

DIDStore *IdentityMetadata_GetStore(IdentityMetadata *metadata)
{
    assert(metadata);

    return Metadata_GetStore(&metadata->base);
}

bool IdentityMetadata_AttachedStore(IdentityMetadata *metadata)
{
    bool attached;

    assert(metadata);

    attached = Metadata_AttachedStore(&metadata->base);
    if (!attached)
        DIDError_Set(DIDERR_MALFORMED_META, "No attached did store.");

    return attached;
}
