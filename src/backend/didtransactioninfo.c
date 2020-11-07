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

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "ela_did.h"
#include "diderror.h"
#include "common.h"
#include "diddocument.h"
#include "didtransactioninfo.h"
#include "didrequest.h"

DIDTransactionInfo *DIDTransactionInfo_FromJson_Internal(json_t *json)
{
    DIDTransactionInfo *txinfo = NULL;
    json_t *item;

    assert(json);

    txinfo = (DIDTransactionInfo*)calloc(1, sizeof(DIDTransactionInfo));
    if (!txinfo) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for did transaction failed.");
        return NULL;
    }

    item = json_object_get(json, "txid");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing transaction id.");
        goto errorExit;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid transaction id.");
        goto errorExit;
    }
    if (strlen(json_string_value(item)) >= ELA_MAX_TXID_LEN) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Transaction id is too long.");
        goto errorExit;
    }
    strcpy(txinfo->txid, json_string_value(item));

    item = json_object_get(json, "timestamp");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing time stamp.");
        goto errorExit;
    }
    if (!json_is_string(item) || parse_time(&txinfo->timestamp, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid time stamp.");
        goto errorExit;
    }

    item = json_object_get(json, "operation");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing ID operation.");
        goto errorExit;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid ID operation.");
        goto errorExit;
    }

    txinfo->request = DIDRequest_FromJson_Internal(item);
    if (!txinfo->request)
        goto errorExit;

    return txinfo;

errorExit:
    DIDTransactionInfo_Destroy(txinfo);
    return NULL;
}

DIDTransactionInfo *DIDTransactionInfo_FromJson(const char *json)
{
    DIDTransactionInfo *txinfo;
    json_t *root;
    json_error_t error;

    if (!json || !*json) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    root = json_loads(json, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Deserialize document failed, error: %s.", error.text);
        return NULL;
    }

    txinfo = DIDTransactionInfo_FromJson_Internal(root);
    json_decref(root);
    return txinfo;
}

void DIDTransactionInfo_Destroy(DIDTransactionInfo *txinfo)
{
    if (!txinfo) {
        DIDRequest_Destroy(txinfo->request);
        free((void*)txinfo);
    }
}

void DIDTransactionInfo_Free(DIDTransactionInfo *txinfo)
{
    if (txinfo) {
        DIDRequest_Free(txinfo->request);
        free((void*)txinfo);
    }
}

int DIDTransactionInfo_ToJson_Internal(JsonGenerator *gen, DIDTransactionInfo *txinfo)
{
    char _timestring[DOC_BUFFER_LEN];

    assert(gen);
    assert(txinfo);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "txid", txinfo->txid));
    CHECK(JsonGenerator_WriteStringField(gen, "timestamp",
            get_time_string(_timestring, sizeof(_timestring), &txinfo->timestamp)));
    CHECK(JsonGenerator_WriteFieldName(gen, "operation"));
    CHECK(DIDRequest_ToJson_Internal(gen, txinfo->request));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

const char *DIDTransactionInfo_ToJson(DIDTransactionInfo *txinfo)
{
    JsonGenerator g, *gen;

    assert(txinfo);

    gen = JsonGenerator_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator initialize failed.");
        return NULL;
    }

    if (DIDTransactionInfo_ToJson_Internal(gen, txinfo) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize ID transaction to json failed.");
        JsonGenerator_Destroy(gen);
        return NULL;
    }

    return JsonGenerator_Finish(gen);
}

DIDRequest *DIDTransactionInfo_GetRequest(DIDTransactionInfo *txinfo)
{
    if (!txinfo) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return txinfo->request;
}

const char *DIDTransactionInfo_GetTransactionId(DIDTransactionInfo *txinfo)
{
    if (!txinfo) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return txinfo->txid;
}

time_t DIDTransactionInfo_GetTimeStamp(DIDTransactionInfo *txinfo)
{
    if (!txinfo) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    return txinfo->timestamp;
}

DID *DIDTransactionInfo_GetOwner(DIDTransactionInfo *txinfo)
{
    if (!txinfo)
        return NULL;

    return &txinfo->request->did;
}

