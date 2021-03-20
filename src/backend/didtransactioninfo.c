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

int DIDTransaction_FromJson(DIDTransaction *txinfo, json_t *json)
{
    json_t *item;

    assert(txinfo);
    assert(json);

    item = json_object_get(json, "txid");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing transaction id.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid transaction id.");
        return -1;
    }
    if (strlen(json_string_value(item)) >= ELA_MAX_TXID_LEN) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Transaction id is too long.");
        return -1;
    }
    strcpy(txinfo->txid, json_string_value(item));

    item = json_object_get(json, "timestamp");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing time stamp.");
        return -1;
    }
    if (!json_is_string(item) || parse_time(&txinfo->timestamp, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid time stamp.");
        return -1;
    }

    item = json_object_get(json, "operation");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing ID operation.");
        return -1;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid ID operation.");
        return -1;
    }
    if (DIDRequest_FromJson(&txinfo->request, item) < 0)
        return -1;

    return 0;
}

void DIDTransaction_Destroy(DIDTransaction *txinfo)
{
    if (txinfo)
        DIDRequest_Destroy(&txinfo->request);
}

void DIDTransaction_Free(DIDTransaction *txinfo)
{
    if (txinfo)
        DIDRequest_Free(&txinfo->request);
}

int DIDTransaction_ToJson_Internal(JsonGenerator *gen, DIDTransaction *txinfo)
{
    char _timestring[DOC_BUFFER_LEN];

    assert(gen);
    assert(txinfo);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "txid", txinfo->txid));
    CHECK(DIDJG_WriteStringField(gen, "timestamp",
            get_time_string(_timestring, sizeof(_timestring), &txinfo->timestamp)));
    CHECK(DIDJG_WriteFieldName(gen, "operation"));
    CHECK(DIDRequest_ToJson_Internal(gen, &txinfo->request));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

const char *DIDTransaction_ToJson(DIDTransaction *txinfo)
{
    JsonGenerator g, *gen;

    assert(txinfo);

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator initialize failed.");
        return NULL;
    }

    if (DIDTransaction_ToJson_Internal(gen, txinfo) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize ID transaction to json failed.");
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

DIDRequest *DIDTransaction_GetRequest(DIDTransaction *txinfo)
{
    assert(txinfo);

    return &txinfo->request;
}

const char *DIDTransaction_GetTransactionId(DIDTransaction *txinfo)
{
    assert(txinfo);

    return txinfo->txid;
}

time_t DIDTransaction_GetTimeStamp(DIDTransaction *txinfo)
{
    assert(txinfo);

    return txinfo->timestamp;
}

DID *DIDTransaction_GetOwner(DIDTransaction *txinfo)
{
    if (!txinfo)
        return NULL;

    return &txinfo->request.did;
}
