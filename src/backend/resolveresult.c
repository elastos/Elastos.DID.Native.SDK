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
#include <jansson.h>

#include "ela_did.h"
#include "diderror.h"
#include "common.h"
#include "diddocument.h"
#include "JsonGenerator.h"
#include "resolveresult.h"
#include "didhistory.h"
#include "credential.h"

int ResolveResult_FromJson(ResolveResult *result, json_t *json, bool all)
{
    json_t *item, *field;
    int i, size = 0;
    bool deactivated;

    assert(result);
    assert(json);

    item = json_object_get(json, "did");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Missing resolved DID.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Invalid resolved DID.");
        return -1;
    }
    if (Parse_DID(&result->did, json_string_value(item)) == -1)
        return -1;

    item = json_object_get(json, "status");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing resolve result status.");
        return -1;
    }
    if (!json_is_integer(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid resolve result status.");
        return -1;
    }
    if (json_integer_value(item) > DIDStatus_NotFound) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Unknown DID status code.");
        return -1;
    }
    result->status = json_integer_value(item);

    if (result->status != DIDStatus_NotFound) {
        item = json_object_get(json, "transaction");
        if (!item) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing transaction.");
            return -1;
        }
        if (!json_is_array(item)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid transaction.");
            return -1;
        }

        if (!all) {
            size = 1;
        } else {
            size = json_array_size(item);
            if (size <= 0) {
                DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing transaction.");
                return -1;
            }
        }

        result->txinfos.infos = (DIDTransactionInfo *)calloc(size, sizeof(DIDTransactionInfo));
        if (!result->txinfos.infos) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Create transaction info failed.");
            return -1;
        }

        for (i = 0; i < size; i++) {
            field = json_array_get(item, i);
            if (!field) {
                DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing resovled transaction.");
                return -1;
            }
            if (!json_is_object(field)) {
                DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid resovled transaction.");
                return -1;
            }

            DIDTransactionInfo *txinfo = &result->txinfos.infos[i];
            if (DIDTransactionInfo_FromJson(txinfo, field) == -1) {
                return -1;
            }

            DIDDocument *doc = txinfo->request.doc;
            if (doc) {
                DIDMetaData_SetPublished(&doc->metadata, txinfo->timestamp);
                DIDMetaData_SetLastModified(&doc->metadata, txinfo->timestamp);
                DIDMetaData_SetTxid(&doc->metadata, txinfo->txid);
                DIDMetaData_SetSignature(&doc->metadata, doc->proof.signatureValue);
                deactivated = (result->status == DIDStatus_Deactivated) ? true : false;
                DIDMetaData_SetDeactivated(&doc->metadata, result->status);
                memcpy(&doc->did.metadata, &doc->metadata, sizeof(DIDMetaData));
            }
            result->txinfos.size++;
        }
    }
    return 0;
}

void ResolveResult_Destroy(ResolveResult *result)
{
    size_t i;

    if (!result || !result->txinfos.infos)
        return;

    for (i = 0; i < result->txinfos.size; i++)
        DIDTransactionInfo_Destroy(&result->txinfos.infos[i]);

    free(result->txinfos.infos);
    memset(result, 0, sizeof(ResolveResult));
}

void ResolveResult_Free(ResolveResult *result)
{
    size_t i;

    if (!result || !result->txinfos.infos)
        return;

    for (i = 0; i < result->txinfos.size; i++)
        DIDTransactionInfo_Free(&result->txinfos.infos[i]);

    free(result->txinfos.infos);
}

static int resolveresult_tojson_internal(JsonGenerator *gen, ResolveResult *result)
{
    char id[ELA_MAX_DIDURL_LEN];
    size_t i;

    assert(gen);
    assert(result);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "did",
            DID_ToString(&result->did, id, sizeof(id))));
    CHECK(JsonGenerator_WriteFieldName(gen, "status"));
    CHECK(JsonGenerator_WriteNumber(gen, result->status));
    if (result->status != DIDStatus_NotFound) {
        CHECK(JsonGenerator_WriteFieldName(gen, "transaction"));
        CHECK(JsonGenerator_WriteStartArray(gen));
        for (i = 0; i < result->txinfos.size; i++)
            //todo: check
            CHECK(DIDTransactionInfo_ToJson_Internal(gen, &result->txinfos.infos[i]));
        CHECK(JsonGenerator_WriteEndArray(gen));
    }
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

const char *ResolveResult_ToJson(ResolveResult *result)
{
    JsonGenerator g, *gen;

    assert(result);

    gen = JsonGenerator_Initialize(&g);
    if (!gen)
        return NULL;

    if (resolveresult_tojson_internal(gen, result) < 0) {
        JsonGenerator_Destroy(gen);
        return NULL;
    }

    return JsonGenerator_Finish(gen);
}

DID *ResolveResult_GetDID(ResolveResult *result)
{
    assert(result);

    return &result->did;
}

DIDStatus ResolveResult_GetStatus(ResolveResult *result)
{
    assert(result);

    return result->status;
}

ssize_t ResolveResult_GetTransactionCount(ResolveResult *result)
{
    assert(result);

    return result->txinfos.size;
}

DIDTransactionInfo *ResolveResult_GetTransactionInfo(ResolveResult *result, int index)
{
    assert(result);
    assert(index >= 0);

    return &result->txinfos.infos[index];
}

DIDHistory *ResolveResult_ToDIDHistory(ResolveResult *result)
{
    DIDHistory *history;
    size_t size;

    assert(result);

    size = result->txinfos.size;
    if (size == 0) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "No transaction from resolve result.");
        return NULL;
    }

    history = (DIDHistory*)calloc(1, sizeof(DIDHistory));
    if (!history) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for didhistory failed.");
        return NULL;
    }

    memcpy(history, result, sizeof(DIDHistory));
    return history;
}

int VcResolveResult_FromJson(VcResolveResult *result, json_t *json, bool all)
{
    json_t *item, *field;
    int i, size = 0;
    bool revoked;

    assert(result);
    assert(json);

    item = json_object_get(json, "id");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Missing resolved DID.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Invalid resolved DID.");
        return -1;
    }
    if (Parse_DIDURL(&result->id, json_string_value(item), NULL) == -1)
        return -1;

    item = json_object_get(json, "status");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing resolve result status.");
        return -1;
    }
    if (!json_is_integer(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid resolve result status.");
        return -1;
    }
    if (json_integer_value(item) > CredentialStatus_NotFound) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Unknown DID status code.");
        return -1;
    }
    result->status = json_integer_value(item);

    if (result->status != CredentialStatus_NotFound) {
        item = json_object_get(json, "transaction");
        if (!item) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing transaction.");
            return -1;
        }
        if (!json_is_array(item)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid transaction.");
            return -1;
        }

        if (!all) {
            size = 1;
        } else {
            size = json_array_size(item);
            if (size > 2 || size == 0) {
                DIDError_Set(DIDERR_RESOLVE_ERROR, "Wrong transaction.");
                return -1;
            }
        }

        for (i = 0; i < size; i++) {
            field = json_array_get(item, i);
            if (!field) {
                DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing resovled transaction.");
                return -1;
            }
            if (!json_is_object(field)) {
                DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid resovled transaction.");
                return -1;
            }

            CredentialTransaction *txinfo = &result->txinfos.infos[i];
            if (CredentialTransaction_FromJson(txinfo, field) == -1)
                return -1;

            Credential *vc = txinfo->request.vc;
            if (vc) {
                revoked = (result->status == CredentialStatus_Revoked) ? true : false;
                CredentialMetaData_SetRevoke(&vc->metadata, revoked);
            }

            result->txinfos.size++;
        }
    }
    return 0;
}

void VcResolveResult_Destroy(VcResolveResult *result)
{
    size_t i;

    if (!result)
        return;

    for (i = 0; i < result->txinfos.size; i++)
        CredentialTransaction_Destroy(&result->txinfos.infos[i]);

    memset(result, 0, sizeof(ResolveResult));
}

void VcResolveResult_Free(VcResolveResult *result)
{
    size_t i;

    if (!result)
        return;

    for (i = 0; i < result->txinfos.size; i++)
        CredentialTransaction_Free(&result->txinfos.infos[i]);

    memset(result, 0, sizeof(ResolveResult));
}

static int vcresolveresult_tojson_internal(JsonGenerator *gen, VcResolveResult *result)
{
    char id[ELA_MAX_DIDURL_LEN];
    size_t i;

    assert(gen);
    assert(result);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "did",
            DIDURL_ToString(&result->id, id, sizeof(id), false)));
    CHECK(JsonGenerator_WriteFieldName(gen, "status"));
    CHECK(JsonGenerator_WriteNumber(gen, result->status));
    if (result->status != CredentialStatus_NotFound) {
        CHECK(JsonGenerator_WriteFieldName(gen, "transaction"));
        CHECK(JsonGenerator_WriteStartArray(gen));
        for (i = 0; i < result->txinfos.size; i++)
            //todo: check
            CHECK(CredentialTransaction_ToJson_Internal(gen, &result->txinfos.infos[i]));
        CHECK(JsonGenerator_WriteEndArray(gen));
    }
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

const char *VcResolveResult_ToJson(VcResolveResult *result)
{
    JsonGenerator g, *gen;

    assert(result);

    gen = JsonGenerator_Initialize(&g);
    if (!gen)
        return NULL;

    if (vcresolveresult_tojson_internal(gen, result) < 0) {
        JsonGenerator_Destroy(gen);
        return NULL;
    }

    return JsonGenerator_Finish(gen);
}

CredentialStatus VcResolveResult_GetStatus(VcResolveResult *result)
{
    assert(result);

    return result->status;
}

ssize_t VcResolveResult_GetTransactionCount(VcResolveResult *result)
{
    assert(result);

    return result->txinfos.size;
}

CredentialTransaction *VcResolveResult_GetTransactionInfo(VcResolveResult *result, int index)
{
    if (index > 2) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The count of credential's transaction is not more than two.");
        return NULL;
    }

    return &result->txinfos.infos[index];
}
