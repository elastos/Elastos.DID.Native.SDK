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
#include "JsonHelper.h"
#include "common.h"
#include "diddocument.h"
#include "diderror.h"

int MetaData_ToJson_Internal(MetaData *metadata, JsonGenerator *gen)
{
    int rc = 0;

    assert(metadata);
    assert(gen);

    if (metadata->data) {
        rc = JsonHelper_ToJson(gen, metadata->data, false);
        if (rc < 0)
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize DID metadata to json failed.");
    }

    return rc;
}

const char *MetaData_ToJson(MetaData *metadata)
{
    JsonGenerator g, *gen;

    assert(metadata);

    if (metadata->data) {
        gen = JsonGenerator_Initialize(&g);
        if (!gen) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator initialize failed.");
            return NULL;
        }

        if (MetaData_ToJson_Internal(metadata, gen) == -1) {
            JsonGenerator_Destroy(gen);
            return NULL;
        }

        return JsonGenerator_Finish(gen);
    }

    return NULL;
}

int MetaData_FromJson_Internal(MetaData *metadata, json_t *json)
{
    json_t *copy;

    assert(metadata);
    assert(json);

    copy = json_deep_copy(json);
    if (!copy) {
       DIDError_Set(DIDERR_MALFORMED_META, "Duplicate metadata content failed.");
        return -1;
    }

    json_decref(metadata->data);
    metadata->data = copy;

    return 0;
}

const char *MetaData_ToString(MetaData *metadata)
{
    assert(metadata);
    return metadata->data ? json_dumps(metadata->data, JSON_COMPACT) : NULL;
}

int MetaData_FromJson(MetaData *metadata, const char *data)
{
    json_t *root;
    json_error_t error;
    int rc;

    assert(metadata);
    assert(data && *data);

    root = json_loads(data, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_MALFORMED_META, "Deserialize did metadata failed, error: %s.", error.text);
        return -1;
    }

    rc = MetaData_FromJson_Internal(metadata, root);
    json_decref(root);
    return rc;
}

void MetaData_Free(MetaData *metadata)
{
    assert(metadata);

    if (metadata->data) {
        json_decref(metadata->data);
        metadata->data = NULL;
    }
}

static int MetaData_Set(MetaData *metadata, const char* key, json_t *value)
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

int MetaData_SetExtra(MetaData *metadata, const char* key, const char *value)
{
    json_t *json;
    int rc;

    assert(metadata);
    assert(key);

    json = value ? json_string(value) : json_null();
    if (!json)
        return -1;

    rc = MetaData_Set(metadata, key, json);
    if (rc < 0)
        json_decref(json);

    return rc;
}

int MetaData_SetExtraWithBoolean(MetaData *metadata, const char *key, bool value)
{
    json_t *json;
    int rc;

    assert(metadata);
    assert(key);

    json = json_boolean(value);
    if (!json)
        return -1;

    rc = MetaData_Set(metadata, key, json);
    if (rc < 0)
        json_decref(json);

    return rc;
}

int MetaData_SetExtraWithDouble(MetaData *metadata, const char *key, double value)
{
    json_t *json;
    int rc;

    assert(metadata);
    assert(key);

    json = json_real(value);
    if (!json)
        return -1;

    rc = MetaData_Set(metadata, key, json);
    if (rc < 0)
        json_decref(json);

    return rc;
}

int MetaData_SetExtraWithInteger(MetaData *metadata, const char *key, int value)
{
    json_t *json;
    int rc;

    assert(metadata);
    assert(key);

    json = json_integer(value);
    if (!json)
        return -1;

    rc = MetaData_Set(metadata, key, json);
    if (rc < 0)
        json_decref(json);

    return rc;
}

static json_t *MetaData_Get(MetaData *metadata, const char *key)
{
    json_t *json;

    assert(metadata);
    assert(key);

    if (!metadata->data) {
        DIDError_Set(DIDERR_MALFORMED_META, "No content in metadata.");
        return NULL;
    }

    json = json_object_get(metadata->data, key);
    if (!json) {
        DIDError_Set(DIDERR_MALFORMED_META, "No '%s' elem in metadata.", key);
        return NULL;
    }

    return json;
}

const char *MetaData_GetExtra(MetaData *metadata, const char *key)
{
    json_t *json;

    assert(metadata);
    assert(key);

    json = MetaData_Get(metadata, key);
    if (!json)
        return NULL;

    if (!json_is_string(json)) {
        DIDError_Set(DIDERR_MALFORMED_META, "'%s' elem is not string type.", key);
        return NULL;
    }

    return json_string_value(json);
}

bool MetaData_GetExtraAsBoolean(MetaData *metadata, const char *key)
{
    json_t *json;

    assert(metadata);
    assert(key);

    json = MetaData_Get(metadata, key);
    if (!json)
        return false;

    if (!json_is_boolean(json)) {
        DIDError_Set(DIDERR_MALFORMED_META, "'%s' elem is not boolean type.", key);
        return false;
    }

    return json_is_true(json);
}

double MetaData_GetExtraAsDouble(MetaData *metadata, const char *key)
{
    json_t *json;

    assert(metadata);
    assert(key);

    json = MetaData_Get(metadata, key);
    if (!json)
        return 0;

    if (!json_is_real(json)) {
        DIDError_Set(DIDERR_MALFORMED_META, "'%s' elem is not double type.", key);
        return 0;
    }

    return json_real_value(json);
}

int MetaData_GetExtraAsInteger(MetaData *metadata, const char *key)
{
    json_t *json;

    assert(metadata);
    assert(key);

    json = MetaData_Get(metadata, key);
    if (!json)
        return 0;

    if (!json_is_integer(json)) {
        DIDError_Set(DIDERR_MALFORMED_META, "'%s' elem is not double type.", key);
        return 0;
    }

    return json_integer_value(json);
}

int MetaData_Merge(MetaData *tometa, MetaData *frommeta)
{
    json_t *value, *item, *json;
    const char *key;

    assert(tometa && frommeta);

    json_object_foreach(frommeta->data, key, value) {
        json = json_object_get(frommeta->data, key);
        item = json_object_get(tometa->data, key);
        if (item) {
            if (json_is_null(item) || json_is_null(json))
                json_object_del(tometa->data, key);
        } else {
            item = json_deep_copy(json);
            if (!item) {
                DIDError_Set(DIDERR_MALFORMED_META, "Add '%s' to metadata failed.", key);
                return -1;
            }
            json_object_set_new(tometa->data, key, item);
        }
    }

    return 0;
}

int MetaData_Copy(MetaData *dest, MetaData *src)
{
    json_t *data = NULL;

    assert(dest);
    assert(src);

    if (src->data) {
        data = json_deep_copy(src->data);
        if (!data) {
            DIDError_Set(DIDERR_MALFORMED_META, "MetaData duplication failed.");
            return -1;
        }
    }

    json_decref(dest->data);

    dest->store = src->store;
    dest->data  = data;

    return 0;
}

void MetaData_SetStore(MetaData *metadata, DIDStore *store)
{
    assert(metadata);
    assert(store);

    metadata->store = store;
}

DIDStore *MetaData_GetStore(MetaData *metadata)
{
    assert(metadata);

    return metadata->store;
}

bool MetaData_AttachedStore(MetaData *metadata)
{
    assert(metadata);

    return metadata->store != NULL;
}