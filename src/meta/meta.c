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
#include <time.h>
#include <assert.h>

#include "ela_did.h"
#include "did.h"
#include "didmeta.h"
#include "JsonGenerator.h"
#include "JsonHelper.h"
#include "common.h"
#include "diddocument.h"
#include "diderror.h"

static const char *PREFIX = "UX-";

int Metadata_ToJson_Internal(Metadata *metadata, JsonGenerator *gen)
{
    int rc = 0;

    assert(metadata);
    assert(gen);

    if (metadata->data) {
        rc = JsonHelper_ToJson(gen, metadata->data, false);
        if (rc < 0)
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize metadata to json failed.");
    }

    return rc;
}

const char *Metadata_ToJson(Metadata *metadata)
{
    JsonGenerator g, *gen;

    assert(metadata);

    if (metadata->data) {
        gen = DIDJG_Initialize(&g);
        if (!gen) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator for metadata initialize failed.");
            return NULL;
        }

        if (Metadata_ToJson_Internal(metadata, gen) == -1) {
            DIDJG_Destroy(gen);
            return NULL;
        }

        return DIDJG_Finish(gen);
    }

    return NULL;
}

int Metadata_FromJson_Internal(Metadata *metadata, json_t *json)
{
    json_t *copy;

    assert(metadata);
    assert(json);

    copy = json_deep_copy(json);
    if (!copy) {
       DIDError_Set(DIDERR_METADATA_ERROR, "Duplicate metadata content failed.");
        return -1;
    }

    json_decref(metadata->data);
    metadata->data = copy;

    return 0;
}

const char *Metadata_ToString(Metadata *metadata)
{
    assert(metadata);
    return metadata->data ? json_dumps(metadata->data, JSON_COMPACT) : NULL;
}

int Metadata_FromJson(Metadata *metadata, const char *data)
{
    json_t *root;
    json_error_t error;
    int rc;

    assert(metadata);
    assert(data && *data);

    root = json_loads(data, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_METADATA_ERROR, "Deserialize metadata failed, error: %s.", error.text);
        return -1;
    }

    rc = Metadata_FromJson_Internal(metadata, root);
    json_decref(root);
    return rc;
}

void Metadata_Free(Metadata *metadata)
{
    assert(metadata);

    if (metadata->data) {
        json_decref(metadata->data);
        metadata->data = NULL;
    }
}

static int Metadata_Set(Metadata *metadata, const char* key, json_t *value)
{
    assert(metadata);
    assert(key);

    if (!metadata->data) {
        metadata->data = json_object();
        if (!metadata->data)
            return -1;
    }

    json_object_del(metadata->data, key);
    json_object_set(metadata->data, key, value);
    return 0;
}

int Metadata_SetExtra(Metadata *metadata, const char* key, const char *value)
{
    char *uskey;
    json_t *json;
    int rc = -1;

    assert(metadata);
    assert(key);

    json = value ? json_string(value) : json_null();
    if (!json)
        goto errorExit;

    uskey = alloca(strlen(PREFIX) + strlen(key) + 1);
    if (!uskey)
        goto errorExit;

    if (sprintf(uskey, "%s%s", PREFIX, key) == -1)
        goto errorExit;

    rc = Metadata_Set(metadata, uskey, json);
    json_decref(json);

errorExit:
    if (rc < 0)
        DIDError_Set(DIDERR_METADATA_ERROR, "Set '%s' to metadata failed.", key);

    return rc;
}

int Metadata_SetDefaultExtra(Metadata *metadata, const char* key, const char *value)
{
    json_t *json;
    int rc = -1;

    assert(metadata);
    assert(key);

    json = value ? json_string(value) : json_null();
    if (!json)
        goto errorExit;

    rc = Metadata_Set(metadata, key, json);
    json_decref(json);

errorExit:
    if (rc < 0)
        DIDError_Set(DIDERR_METADATA_ERROR, "Set '%s' to metadata failed.", key);

    return rc;
}

int Metadata_SetExtraWithBoolean(Metadata *metadata, const char *key, bool value)
{
    char *uskey;
    json_t *json;
    int rc = -1;

    assert(metadata);
    assert(key);

    json = json_boolean(value);
    if (!json)
        goto errorExit;

    uskey = alloca(strlen(PREFIX) + strlen(key) + 1);
    if (!uskey)
        goto errorExit;

    if (sprintf(uskey, "%s%s", PREFIX, key) == -1)
        goto errorExit;

    rc = Metadata_Set(metadata, uskey, json);
    json_decref(json);

errorExit:
    if (rc < 0)
        DIDError_Set(DIDERR_METADATA_ERROR, "Set '%s' to metadata failed.", key);

    return rc;
}

int Metadata_SetDefaultExtraWithBoolean(Metadata *metadata, const char *key, bool value)
{
    json_t *json;
    int rc = -1;

    assert(metadata);
    assert(key);

    json = json_boolean(value);
    if (!json)
        goto errorExit;

    rc = Metadata_Set(metadata, key, json);
    json_decref(json);

errorExit:
    if (rc < 0)
        DIDError_Set(DIDERR_METADATA_ERROR, "Set '%s' to metadata failed.", key);

    return rc;
}

int Metadata_SetExtraWithDouble(Metadata *metadata, const char *key, double value)
{
    char *uskey;
    json_t *json;
    int rc = -1;

    assert(metadata);
    assert(key);

    json = json_real(value);
    if (!json)
        goto errorExit;

    uskey = alloca(strlen(PREFIX) + strlen(key) + 1);
    if (!uskey)
        goto errorExit;

    if (sprintf(uskey, "%s%s", PREFIX, key) == -1)
        goto errorExit;

    rc = Metadata_Set(metadata, uskey, json);
    json_decref(json);

errorExit:
    if (rc < 0)
        DIDError_Set(DIDERR_METADATA_ERROR, "Set '%s' to metadata failed.", key);

    return rc;
}

int Metadata_SetDefaultExtraWithDouble(Metadata *metadata, const char *key, double value)
{
    json_t *json;
    int rc = -1;

    assert(metadata);
    assert(key);

    json = json_real(value);
    if (!json)
        goto errorExit;

    rc = Metadata_Set(metadata, key, json);
    json_decref(json);

errorExit:
    if (rc < 0)
        DIDError_Set(DIDERR_METADATA_ERROR, "Set '%s' to metadata failed.", key);

    return rc;
}

int Metadata_SetExtraWithInteger(Metadata *metadata, const char *key, long long value)
{
    char *uskey;
    json_t *json;
    int rc = -1;

    assert(metadata);
    assert(key);

    json = json_integer(value);
    if (!json)
        goto errorExit;

    uskey = alloca(strlen(PREFIX) + strlen(key) + 1);
    if (!uskey)
        goto errorExit;

    if (sprintf(uskey, "%s%s", PREFIX, key) == -1)
        goto errorExit;

    rc = Metadata_Set(metadata, uskey, json);
    json_decref(json);

errorExit:
    if (rc < 0)
        DIDError_Set(DIDERR_METADATA_ERROR, "Set '%s' to metadata failed.", key);

    return rc;
}

int Metadata_SetDefaultExtraWithInteger(Metadata *metadata, const char *key, int value)
{
    json_t *json;
    int rc = -1;

    assert(metadata);
    assert(key);

    json = json_integer(value);
    if (!json)
        goto errorExit;

    rc = Metadata_Set(metadata, key, json);
    json_decref(json);

errorExit:
    if (rc < 0)
        DIDError_Set(DIDERR_METADATA_ERROR, "Set '%s' to metadata failed.", key);

    return rc;
}

static json_t *Metadata_Get(Metadata *metadata, const char *key)
{
    json_t *json;

    assert(metadata);
    assert(key);

    if (!metadata->data)
        return NULL;

    json = json_object_get(metadata->data, key);
    if (!json)
        return NULL;

    return json;
}

const char *Metadata_GetExtra(Metadata *metadata, const char *key)
{
    char *uskey;
    json_t *json;
    const char *value = NULL;

    assert(metadata);
    assert(key);

    uskey = alloca(strlen(PREFIX) + strlen(key) + 1);
    if (!uskey)
        goto errorExit;

    if (sprintf(uskey, "%s%s", PREFIX, key) == -1)
        goto errorExit;

    json = Metadata_Get(metadata, uskey);
    if (!json)
        goto errorExit;

    if (!json_is_string(json))
        goto errorExit;

    value = json_string_value(json);

errorExit:
    if (!value)
        DIDError_Set(DIDERR_METADATA_ERROR, "Get '%s' value from metadata failed", key);

    return value;
}

const char *Metadata_GetDefaultExtra(Metadata *metadata, const char *key)
{
    json_t *json;
    const char *value = NULL;

    assert(metadata);
    assert(key);

    json = Metadata_Get(metadata, key);
    if (!json)
        goto errorExit;

    if (!json_is_string(json)) {
        DIDError_Set(DIDERR_METADATA_ERROR, "'%s' elem is not string type.", key);
        goto errorExit;
    }

    value = json_string_value(json);

errorExit:
    if (!value)
        DIDError_Set(DIDERR_METADATA_ERROR, "Get '%s' value from metadata failed", key);

    return value;
}

bool Metadata_GetExtraAsBoolean(Metadata *metadata, const char *key, bool dvalue)
{
    char *uskey;
    json_t *json;

    assert(metadata);
    assert(key);

    uskey = alloca(strlen(PREFIX) + strlen(key) + 1);
    if (!uskey)
        goto errorExit;

    if (sprintf(uskey, "%s%s", PREFIX, key) == -1)
        goto errorExit;

    json = Metadata_Get(metadata, uskey);
    if (!json)
        goto errorExit;

    if (!json_is_boolean(json)) {
        DIDError_Set(DIDERR_METADATA_ERROR, "'%s' elem is not boolean type.", key);
        goto errorExit;
    }

    return (int)json_is_true(json);

errorExit:
    DIDError_Set(DIDERR_METADATA_ERROR, "Get '%s' value from metadata failed", key);
    return dvalue;
}

int Metadata_GetDefaultExtraAsBoolean(Metadata *metadata, const char *key)
{
    json_t *json;

    assert(metadata);
    assert(key);

    json = Metadata_Get(metadata, key);
    if (!json)
        return 0;

    if (!json_is_boolean(json)) {
        DIDError_Set(DIDERR_METADATA_ERROR, "'%s' elem is not boolean type.", key);
        return -1;
    }

    return (int)json_is_true(json);
}

double Metadata_GetExtraAsDouble(Metadata *metadata, const char *key, double dvalue)
{
    char *uskey;
    json_t *json;

    assert(metadata);
    assert(key);

    uskey = alloca(strlen(PREFIX) + strlen(key) + 1);
    if (!uskey)
        goto errorExit;

    if (sprintf(uskey, "%s%s", PREFIX, key) == -1)
        goto errorExit;

    json = Metadata_Get(metadata, uskey);
    if (!json)
        goto errorExit;

    if (!json_is_real(json))
        goto errorExit;

    return json_real_value(json);

errorExit:
    DIDError_Set(DIDERR_METADATA_ERROR, "Get '%s' value from metadata failed", key);
    return dvalue;
}

double Metadata_GetDefaultExtraAsDouble(Metadata *metadata, const char *key, double dvalue)
{
    json_t *json;

    assert(metadata);
    assert(key);

    json = Metadata_Get(metadata, key);
    if (!json)
        goto errorExit;

    if (!json_is_real(json))
        goto errorExit;

    return json_real_value(json);

errorExit:
    DIDError_Set(DIDERR_METADATA_ERROR, "Get '%s' value from metadata failed", key);
    return dvalue;
}

long long Metadata_GetExtraAsInteger(Metadata *metadata, const char *key, long long dvalue)
{
    char *uskey;
    json_t *json;

    assert(metadata);
    assert(key);

    uskey = alloca(strlen(PREFIX) + strlen(key) + 1);
    if (!uskey)
        goto errorExit;

    if (sprintf(uskey, "%s%s", PREFIX, key) == -1)
        goto errorExit;

    json = Metadata_Get(metadata, uskey);
    if (!json)
        goto errorExit;

    if (!json_is_integer(json))
        goto errorExit;

    return json_integer_value(json);

errorExit:
    DIDError_Set(DIDERR_METADATA_ERROR, "Get '%s' value from metadata failed", key);
    return dvalue;
}

long long Metadata_GetDefaultExtraAsInteger(Metadata *metadata, const char *key, long long dvalue)
{
    json_t *json;

    assert(metadata);
    assert(key);

    json = Metadata_Get(metadata, key);
    if (!json)
        goto errorExit;

    if (!json_is_integer(json))
        goto errorExit;

    return json_integer_value(json);

errorExit:
    DIDError_Set(DIDERR_METADATA_ERROR, "Get '%s' value from metadata failed", key);
    return dvalue;
}

int Metadata_Merge(Metadata *tometadata, Metadata *frommetadata)
{
    json_t *value, *item, *json;
    const char *key;
    int rc;

    assert(tometadata && frommetadata);

    json_object_foreach(frommetadata->data, key, value) {
        json = json_object_get(frommetadata->data, key);
        item = json_object_get(tometadata->data, key);
        if (item) {
            if (json_is_null(item) || json_is_null(json))
                json_object_del(tometadata->data, key);
        } else {
            item = json_deep_copy(json);
            if (!item)
                goto errorExit;

            rc = Metadata_Set(tometadata, key, item);
            json_decref(item);
            if (rc < 0) {
                DIDError_Set(DIDERR_METADATA_ERROR, "Add '%s' to metadata failed.", key);
                goto errorExit;
            }
        }
    }

    return 0;

errorExit:
    DIDError_Set(DIDERR_METADATA_ERROR, "Merge metadata failed");
    return -1;
}

int Metadata_Upgrade(Metadata *newmetadata, Metadata *oldmetadata)
{
    json_t *value, *json;
    const char *key;
    char *uskey;

    assert(newmetadata);
    assert(oldmetadata);

    memset(newmetadata, 0, sizeof(Metadata));

    json_object_foreach(oldmetadata->data, key, value) {
        json = json_object_get(oldmetadata->data, key);
        if (!strcmp(key, "DX-lastModified"))
            continue;

        if (!strncmp(key, "DX-", 3)) {
            uskey = (char*)(key + 3);
        } else {
            uskey = alloca(strlen(PREFIX) + strlen(key) + 1);
            if (!uskey)
                goto errorExit;

            if (sprintf(uskey, "%s%s", PREFIX, key) == -1)
                goto errorExit;
        }

        if (Metadata_Set(newmetadata, uskey, json) < 0)
            goto errorExit;
    }

    return 0;

errorExit:
    DIDError_Set(DIDERR_METADATA_ERROR, "Upgrade metadata failed");
    return -1;
}

int Metadata_Copy(Metadata *dest, Metadata *src)
{
    json_t *data = NULL;

    assert(dest);
    assert(src);

    if (src->data) {
        data = json_deep_copy(src->data);
        if (!data) {
            DIDError_Set(DIDERR_METADATA_ERROR, "metadata duplication failed.");
            return -1;
        }
    }

    json_decref(dest->data);

    dest->store = src->store;
    dest->data  = data;

    return 0;
}

void Metadata_SetStore(Metadata *metadata, DIDStore *store)
{
    assert(metadata);

    metadata->store = store;
}

DIDStore *Metadata_GetStore(Metadata *metadata)
{
    assert(metadata);

    return metadata->store;
}

bool Metadata_AttachedStore(Metadata *metadata)
{
    assert(metadata);

    return metadata->store != NULL;
}
