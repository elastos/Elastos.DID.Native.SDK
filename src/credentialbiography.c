/*
 * Copyright (c) 2020 Elastos Foundation
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
#include "JsonGenerator.h"
#include "didmeta.h"
#include "credentialbiography.h"
#include "vctransactioninfo.h"
#include "vcrequest.h"
#include "credential.h"

void CredentialBiography_Destroy(CredentialBiography *biography)
{
    size_t i;

    if (!biography)
        return;

    for (i = 0; i < biography->txs.size; i++)
        CredentialTransaction_Destroy(&biography->txs.txs[i]);

    free((void*)biography);
}

void CredentialBiography_Free(CredentialBiography *biography)
{
    size_t i;

    if (!biography)
        return;

    for (i = 0; i < biography->txs.size; i++)
        CredentialTransaction_Free(&biography->txs.txs[i]);

    free((void*)biography);
}

CredentialBiography *CredentialBiography_FromJson(json_t *json)
{
    CredentialBiography *biography;
    CredentialTransaction *tx;
    Credential *vc;
    json_t *item, *field;
    int i, size = 0;
    bool revoked;

    assert(json);

    biography = (CredentialBiography*)calloc(1, sizeof(CredentialBiography));
    if (!biography) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for CredentialBiography failed.");
        return NULL;
    }

    item = json_object_get(json, "id");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Missing resolved DID.");
        goto errorExit;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Invalid resolved DID.");
        goto errorExit;
    }
    if (DIDURL_Parse(&biography->id, json_string_value(item), NULL) == -1)
        goto errorExit;

    item = json_object_get(json, "status");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing credential status.");
        goto errorExit;
    }
    if (!json_is_integer(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid credential status.");
        goto errorExit;
    }
    if (json_integer_value(item) > CredentialStatus_NotFound) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Unknown credential status code.");
        goto errorExit;
    }
    biography->status = json_integer_value(item);

    item = json_object_get(json, "transaction");
    if (item) {
        if (biography->status == CredentialStatus_NotFound) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing transaction.");
            goto errorExit;
        }
        if (!json_is_array(item)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid transaction.");
            goto errorExit;
        }

        size = json_array_size(item);
        if (size > 2 || size == 0) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Wrong transaction.");
            goto errorExit;
        }

        for (i = 0; i < size; i++) {
            field = json_array_get(item, i);
            if (!field) {
                DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing resovled transaction.");
                goto errorExit;
            }
            if (!json_is_object(field)) {
                DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid resovled transaction.");
                goto errorExit;
            }

            tx = &biography->txs.txs[i];
            if (CredentialTransaction_FromJson(tx, field) == -1)
                goto errorExit;

            vc = tx->request.vc;
            if (vc) {
                revoked = (biography->status == CredentialStatus_Revoked) ? true : false;
                CredentialMetadata_SetRevoke(&vc->metadata, revoked);
                CredentialMetadata_SetPublished(&vc->metadata, tx->timestamp);
                CredentialMetadata_SetTxid(&vc->metadata, tx->txid);
            }

            biography->txs.size++;
        }
    }

    return biography;

errorExit:
    CredentialBiography_Destroy(biography);
    return NULL;
}

static int credentialbiography_toJson_internal(JsonGenerator *gen, CredentialBiography *biography)
{
    char id[ELA_MAX_DIDURL_LEN];
    size_t i;

    assert(gen);
    assert(biography);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "did",
            DIDURL_ToString(&biography->id, id, sizeof(id), false)));
    CHECK(DIDJG_WriteFieldName(gen, "status"));
    CHECK(DIDJG_WriteNumber(gen, biography->status));
    if (biography->status != CredentialStatus_NotFound) {
        CHECK(DIDJG_WriteFieldName(gen, "transaction"));
        CHECK(DIDJG_WriteStartArray(gen));
        for (i = 0; i < biography->txs.size; i++)
            CHECK(CredentialTransaction_ToJson_Internal(gen, &biography->txs.txs[i]));
        CHECK(DIDJG_WriteEndArray(gen));
    }
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

const char *Credentialbiography_ToJson(CredentialBiography *biography)
{
    JsonGenerator g, *gen;

    assert(biography);

    gen = DIDJG_Initialize(&g);
    if (!gen)
        return NULL;

    if (credentialbiography_toJson_internal(gen, biography) < 0) {
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

DIDURL *CredentialBiography_GetId(CredentialBiography *biography)
{
    if (!biography) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &biography->id;
}

DID *CredentialBiography_GetOwner(CredentialBiography *biography)
{
    if (!biography) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &biography->id.did;
}

int CredentialBiography_GetStatus(CredentialBiography *biography)
{
    if (!biography) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return biography->status;
}

ssize_t CredentialBiography_GetTransactionCount(CredentialBiography *biography)
{
    if (!biography) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return biography->txs.size;
}

Credential *CredentialBiography_GetCredentialByIndex(CredentialBiography *biography, int index)
{
    Credential *cred;

    if (!biography || index < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (index >= biography->txs.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The count of Credential transaction isn't larger than transactions' size, please check index.");
        return NULL;
    }

    if (biography->txs.txs[index].request.vc) {
        cred = (Credential*)calloc(1, sizeof(Credential));
        if (!cred) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for Credential failed.");
            return NULL;
        }

        if (Credential_Copy(cred, biography->txs.txs[index].request.vc) == -1) {
            Credential_Destroy(cred);
            return NULL;
        }

        return cred;
    }

    return NULL;
}

const char *CredentialBiography_GetTransactionIdByIndex(CredentialBiography *biography, int index)
{
    if (!biography || index < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (index >= biography->txs.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The count of Credential transaction isn't larger than transactions' size, please check index.");
        return NULL;
    }

    return biography->txs.txs[index].txid;
}

time_t CredentialBiography_GetPublishedByIndex(CredentialBiography *biography, int index)
{
    if (!biography || index < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    if (index >= biography->txs.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The count of Credential transaction isn't larger than transactions' size, please check index.");
        return 0;
    }

    return biography->txs.txs[index].timestamp;
}

const char *CredentialBiography_GetOperationByIndex(CredentialBiography *biography, int index)
{
    if (!biography || index < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (index >= biography->txs.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The count of Credential transaction isn't larger than transactions' size, please check index.");
        return NULL;
    }

    return biography->txs.txs[index].request.header.op;
}

DIDURL *CredentialBiography_GetTransactionSignkeyByIndex(CredentialBiography *biography, int index)
{
    if (!biography || index < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (index >= biography->txs.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The count of Credential transaction isn't larger than transactions' size, please check index.");
        return NULL;
    }

    return &biography->txs.txs[index].request.proof.verificationMethod;
}
