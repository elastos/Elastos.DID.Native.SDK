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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <jansson.h>

#include "ela_did.h"
#include "diderror.h"
#include "common.h"
#include "JsonHelper.h"

static int item_compr(const void *a, const void *b)
{
    const char **propa = (const char**)a;
    const char **propb = (const char**)b;

    return strcmp(*propa, *propb);
}

//free the return value
static const char **item_sort(json_t *json, size_t size)
{
    size_t i = 0;
    json_t *value;
    const char *key;

    assert(json);
    assert(size == json_object_size(json));

    const char **keylist = (const char**)calloc(size, sizeof(char*));
    if (!keylist)
        return NULL;

    json_object_foreach(json, key, value) {
        keylist[i++] = key;
    }

    qsort(keylist, size, sizeof(char*), item_compr);
    return keylist;
}

int JsonHelper_ToJson(JsonGenerator *generator, json_t *object, bool objectcontext)
{
    int rc;
    size_t size, i;
    json_t *item;

    assert(generator);
    assert(object);

    if (json_is_array(object)) {
        CHECK(DIDJG_WriteStartArray(generator));
        size = json_array_size(object);
        for (i = 0; i < size; i++) {
            item  = json_array_get(object, i);
            CHECK(JsonHelper_ToJson(generator, item, false));
        }
        CHECK(DIDJG_WriteEndArray(generator));
        return 0;
    }

    if (json_is_object(object)) {
        if (!objectcontext)
            CHECK(DIDJG_WriteStartObject(generator));

        size = json_object_size(object);
        const char **items = item_sort(object, size);
        if (!items)
            return -1;

        for (i = 0; i < size; i++) {
            const char *key = items[i];
            CHECK(DIDJG_WriteFieldName(generator, key));
            rc = JsonHelper_ToJson(generator, json_object_get(object, key), false);
            if (rc < 0) {
                free(items);
                return -1;
            }
        }
        free(items);

        if (!objectcontext)
            CHECK(DIDJG_WriteEndObject(generator));

        return 0;
    }

    if (json_is_false(object)) {
        CHECK(DIDJG_WriteBoolean(generator, false));
        return 0;
    }

    if (json_is_true(object)) {
        CHECK(DIDJG_WriteBoolean(generator, true));
        return 0;
    }

    if (json_is_null(object)) {
        CHECK(DIDJG_WriteString(generator, NULL));
        return 0;
    }

    if (json_is_integer(object)) {
        CHECK(DIDJG_WriteNumber(generator, json_integer_value(object)));
        return 0;
    }

    if (json_is_real(object)) {
        CHECK(DIDJG_WriteDouble(generator, json_real_value(object)));
        return 0;
    }

    if (json_is_string(object)) {
        CHECK(DIDJG_WriteString(generator, json_string_value(object)));
        return 0;
    }

    return -1;
}

const char *JsonHelper_ToString(json_t *object)
{
    JsonGenerator g, *gen;

    assert(object);

    gen = DIDJG_Initialize(&g);
    if (!gen)
        return NULL;

    if (JsonHelper_ToJson(gen, object, false) < 0) {
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}
