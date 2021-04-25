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
#include "credential.h"
#include "vctransactioninfo.h"
#include "vcrequest.h"

int CredentialTransaction_FromJson(CredentialTransaction *txinfo, json_t *json)
{
    json_t *item;

    assert(txinfo);
    assert(json);

    item = json_object_get(json, "txid");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINTRANSACTION, "Missing transaction id.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINTRANSACTION, "Invalid transaction id.");
        return -1;
    }
    if (strlen(json_string_value(item)) >= ELA_MAX_TXID_LEN) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINTRANSACTION, "Transaction id is too long.");
        return -1;
    }
    strcpy(txinfo->txid, json_string_value(item));

    item = json_object_get(json, "timestamp");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINTRANSACTION, "Missing time stamp.");
        return -1;
    }
    if (!json_is_string(item) || parse_time(&txinfo->timestamp, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINTRANSACTION, "Invalid time stamp.");
        return -1;
    }

    item = json_object_get(json, "operation");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINTRANSACTION, "Missing ID operation.");
        return -1;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINTRANSACTION, "Invalid ID operation.");
        return -1;
    }

    if (CredentialRequest_FromJson(&txinfo->request, item) < 0)
        return -1;

    return 0;
}

void CredentialTransaction_Destroy(CredentialTransaction *txinfo)
{
    if (txinfo)
        CredentialRequest_Destroy(&txinfo->request);
}

void CredentialTransaction_Free(CredentialTransaction *txinfo)
{
    if (txinfo)
        CredentialRequest_Free(&txinfo->request);
}

int CredentialTransaction_ToJson_Internal(JsonGenerator *gen, CredentialTransaction *txinfo)
{
    char _timestring[DOC_BUFFER_LEN];

    assert(gen);
    assert(txinfo);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "txid", txinfo->txid));
    CHECK(DIDJG_WriteStringField(gen, "timestamp",
            get_time_string(_timestring, sizeof(_timestring), &txinfo->timestamp)));
    CHECK(DIDJG_WriteFieldName(gen, "operation"));
    CHECK(CredentialRequest_ToJson_Internal(gen, &txinfo->request));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

const char *CredentialTransaction_ToJson(CredentialTransaction *txinfo)
{
    JsonGenerator g, *gen;

    assert(txinfo);

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator for credential transaction initialize failed.");
        return NULL;
    }

    if (CredentialTransaction_ToJson_Internal(gen, txinfo) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize credential transaction to json failed.");
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

CredentialRequest *CredentialTransaction_GetRequest(CredentialTransaction *txinfo)
{
    assert(txinfo);

    return &txinfo->request;
}

const char *CredentialTransaction_GetTransactionId(CredentialTransaction *txinfo)
{
    assert(txinfo);

    return txinfo->txid;
}

time_t CredentialTransaction_GetTimeStamp(CredentialTransaction *txinfo)
{
    assert(txinfo);

    return txinfo->timestamp;
}

DID *CredentialTransaction_GetOwner(CredentialTransaction *txinfo)
{
    if (!txinfo)
        return NULL;

    return &txinfo->request.vc->subject.id;
}

DIDURL *CredentialTransaction_GetId(CredentialTransaction *txinfo)
{
    if (!txinfo)
        return NULL;

    return &txinfo->request.id;
}
