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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/opensslv.h>
#include <jansson.h>
#include <time.h>
#include <assert.h>

#include "ela_did.h"
#include "diderror.h"
#include "did.h"
#include "common.h"
#include "diddocument.h"
#include "crypto.h"
#include "didstore.h"
#include "JsonGenerator.h"
#include "didrequest.h"

static const char *spec = "elastos/did/1.0";
static const char* operation[] = {"create", "update", "deactivate"};

static int header_toJson(JsonGenerator *gen, DIDRequest *req)
{
    char multisig[128] = {0};

    assert(gen);
    assert(req);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "specification", req->header.spec));
    CHECK(JsonGenerator_WriteStringField(gen, "operation", req->header.op));
    if (!strcmp(req->header.op, operation[RequestType_Update]))
        CHECK(JsonGenerator_WriteStringField(gen, "previousTxid", req->header.prevtxid));

    if (req->header.multisig_m > 1)
        CHECK(JsonGenerator_WriteStringField(gen, "multisig",
                set_multisig(multisig, sizeof(multisig), req->header.multisig_m, req->header.multisig_n)));

    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

static int proof_toJson(JsonGenerator *gen, DIDRequest *req)
{
    char _method[ELA_MAX_DIDURL_LEN], *method;
    int i;

    assert(gen);
    assert(req);

    if (req->proofs.size > 1)
        CHECK(JsonGenerator_WriteStartArray(gen));

    for (i = 0; i < req->proofs.size; i++) {
        method = DIDURL_ToString(&req->proofs.proofs[i].verificationMethod, _method, ELA_MAX_DIDURL_LEN, 0);
        if (!method)
            return -1;

        CHECK(JsonGenerator_WriteStartObject(gen));
        CHECK(JsonGenerator_WriteStringField(gen, "verificationMethod", method));
        CHECK(JsonGenerator_WriteStringField(gen, "signature", req->proofs.proofs[i].signature));
        CHECK(JsonGenerator_WriteEndObject(gen));
    }

    if (req->proofs.size > 1)
        CHECK(JsonGenerator_WriteEndArray(gen));

    return 0;
}

int DIDRequest_ToJson_Internal(JsonGenerator *gen, DIDRequest *req)
{
    assert(gen);
    assert(req);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteFieldName(gen, "header"));
    CHECK(header_toJson(gen, req));
    CHECK(JsonGenerator_WriteStringField(gen, "payload", req->payload));
    CHECK(JsonGenerator_WriteFieldName(gen, "proof"));
    CHECK(proof_toJson(gen, req));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

const char *DIDRequest_ToJson(DIDRequest *req)
{
    JsonGenerator g, *gen;

    assert(req);

    gen = JsonGenerator_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator initialize failed.");
        return NULL;
    }

    if (DIDRequest_ToJson_Internal(gen, req) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize DIDRequest to json failed.");
        JsonGenerator_Destroy(gen);
        return NULL;
    }

    return JsonGenerator_Finish(gen);
}

static int didrequest_addproof(DIDRequest *request, char *signature, DIDURL *signkey)
{
    size_t size;
    RequestProof *rp;

    assert(request);
    assert(signature);
    assert(signkey);

    size = request->proofs.size;
    rp = request->proofs.proofs;
    if (!request->proofs.proofs)
        request->proofs.proofs = (RequestProof*)calloc(1, sizeof(RequestProof));
    else
        request->proofs.proofs = realloc(rp, (request->proofs.size + 1) * sizeof(RequestProof));

    if (!request->proofs.proofs)
        return -1;

    strcpy(request->proofs.proofs[size].signature, signature);
    DIDURL_Copy(&request->proofs.proofs[size].verificationMethod, signkey);
    request->proofs.size++;
    return 0;
}

const char *DIDRequest_Sign(DIDRequest_Type type, DIDDocument *document, DIDURL *signkey,
        const char *storepass)
{
    DIDRequest req;
    DIDDocument *doc;
    const char *payload, *op, *requestJson, *prevtxid, *data, *multisig;
    size_t len;
    int rc;
    char signature[SIGNATURE_BYTES * 2 + 16], idstring[ELA_MAX_DID_LEN], buffer[128] = {0};

    assert(type >= RequestType_Create && type <= RequestType_Deactivate);
    assert(document);
    assert(signkey);
    assert(storepass && *storepass);

    memset(&req, 0, sizeof(DIDRequest));

    if (type == RequestType_Create || type == RequestType_Deactivate) {
        prevtxid = "";
    } else {
        prevtxid = DIDMetaData_GetTxid(&document->metadata);
        if (!prevtxid) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "Can not determine the previous transaction ID.");
            return NULL;
        }
    }

    if (type == RequestType_Deactivate) {
        data = DID_ToString(DIDDocument_GetSubject(document), idstring, sizeof(idstring));
        if (!data)
            return NULL;
        payload = strdup(data);
    }
    else {
        data = DIDDocument_ToJson(document, true);
        if (!data)
            return NULL;

        len = strlen(data);
        payload = (char*)malloc(len * 4 / 3 + 16);
        base64_url_encode((char*)payload, (const uint8_t *)data, len);
        free((void*)data);
    }

    op = operation[type];

    multisig = DIDMetaData_GetMultisig(&document->metadata);
    if (!multisig)
        multisig = "";

    get_multisig(multisig, &req.header.multisig_m, &req.header.multisig_n);

    if (!DIDDocument_GetPublicKey(document, signkey)) {
        doc = DIDStore_LoadDID(document->metadata.base.store, &signkey->did);
    } else {
        doc = document;
    }

    rc = DIDDocument_Sign(doc, signkey, storepass, signature, 5,
            (unsigned char*)spec, strlen(spec), (unsigned char*)op, strlen(op),
            (unsigned char *)prevtxid, strlen(prevtxid),
            (unsigned char *)multisig, strlen(multisig),
            (unsigned char*)payload, strlen(payload));
    if (rc < 0) {
        free((void*)payload);
        return NULL;
    }

    strcpy(req.header.spec, (char*)spec);
    strcpy(req.header.op, (char*)op);
    strcpy(req.header.prevtxid, (char*)prevtxid);
    req.payload = payload;
    if(didrequest_addproof(&req, signature, signkey) < 0)
        return NULL;

    requestJson = DIDRequest_ToJson(&req);
    free((void*)payload);
    return requestJson;
}

int DIDRequest_Verify(DIDRequest *request)
{
    int i;
    char buffer[128], *b;
    DIDDocument *doc;
    DIDURL *keyid;

    assert(request);

    if (!request->doc)
        return 0;

    b = set_multisig(buffer, sizeof(buffer), request->header.multisig_m, request->header.multisig_n);

    //todo: if(request->doc) is for deacativated without doc.
    for (i = 0; i < request->proofs.size; i++) {
        keyid = &request->proofs.proofs[i].verificationMethod;
        if (DIDDocument_GetPublicKey(request->doc, keyid))
            doc = request->doc;
        else
            doc = DID_Resolve(&keyid->did, true);

        if (DIDDocument_Verify(doc, &request->proofs.proofs[i].verificationMethod,
                (char*)request->proofs.proofs[i].signature, 5,
                request->header.spec, strlen(request->header.spec),
                request->header.op, strlen(request->header.op),
                request->header.prevtxid, strlen(request->header.prevtxid),
                b, strlen(b),
                request->payload, strlen(request->payload)) < 0)
            return -1;
    }
    return 0;
}

static int proof_fromjson(DIDRequest *request, json_t *json)
{
    size_t size = 1, i;
    json_t *item, *field;

    assert(request);
    assert(json);

    if (json_is_array(json))
        size = json_array_size(json);

    request->proofs.proofs = (RequestProof*)calloc(size, sizeof(RequestProof));
    if (!request->proofs.proofs) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for proof failed.");
        return -1;
    }

    request->proofs.size = 0;
    for (i = 0; i < size; i++) {
        if (json_is_object(json))
            item = json;
        else
            item = json_array_get(json, i);

        if (!json_is_object(item)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid proof format.");
            return -1;
        }

        field = json_object_get(item, "verificationMethod");
        if (!field) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing signing key.");
            return -1;
        }
        if (!json_is_string(field)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid signing key.");
            return -1;
        }

        if (Parse_DIDURL(&request->proofs.proofs[request->proofs.size].verificationMethod,
                json_string_value(field), &request->did) < 0) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid signing key.");
            return -1;
        }

        field = json_object_get(item, "signature");
        if (!field) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing signature.");
            return -1;
        }
        if (!json_is_string(field) || strlen(json_string_value(field)) >= MAX_REQ_SIG_LEN) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid signature.");
            return -1;
        }
        strcpy(request->proofs.proofs[request->proofs.size].signature, json_string_value(field));
        request->proofs.size++;
    }

    return 0;
}

static int header_fromjson(DIDRequest *request, json_t *json)
{
    json_t *item;
    const char *op;

    assert(request);
    assert(json);

    item = json_object_get(json, "specification");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing specification.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid specification.");
        return -1;
    }
    if (strcmp(json_string_value(item), spec)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Unknown DID specification. \
                excepted: %s, actual: %s", spec, json_string_value(item));
        return -1;
    }
    strcpy(request->header.spec, (char *)spec);

    item = json_object_get(json, "operation");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing operation.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid operation.");
        return -1;
    }
    op = json_string_value(item);
    if (!strcmp(op, operation[RequestType_Create]) || !strcmp(op, operation[RequestType_Update]) ||
            !strcmp(op, operation[RequestType_Deactivate])) {
        strcpy(request->header.op, op);
    } else {
        DIDError_Set(DIDERR_UNKNOWN, "Unknown DID operaton.");
        return -1;
    }

    if (!strcmp(op, operation[RequestType_Update])) {
        item = json_object_get(json, "previousTxid");
        if (!item) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing payload.");
            return -1;
        }
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid payload.");
            return -1;
        }
        strcpy(request->header.prevtxid, json_string_value(item));
    } else {
        *request->header.prevtxid = 0;
    }

    item = json_object_get(json, "multisig");
    if (item) {
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid multisig.");
            return -1;
        }

        get_multisig(json_string_value(item), &request->header.multisig_m, &request->header.multisig_n);
        if (request->header.multisig_n > request->header.multisig_m) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Wrong multisig.");
            return -1;
        }
    }

    return 0;
}

DIDDocument *DIDRequest_FromJson_Internal(DIDRequest *request, json_t *json)
{
    json_t *item, *field = NULL;
    char *docJson;
    const char *payload;
    DID *subject;
    size_t len;
    int m = 0, n = 0;

    assert(request);
    assert(json);

    memset(request, 0, sizeof(DIDRequest));
    item = json_object_get(json, "header");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing header.");
        return NULL;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid header.");
        return NULL;
    }

    if (header_fromjson(request, item) < 0)
        return NULL;

    item = json_object_get(json, "payload");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing payload.");
        return NULL;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid payload.");
        return NULL;
    }
    payload = json_string_value(item);
    if (!payload) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "No payload.");
        return NULL;
    }
    request->payload = strdup(payload);
    if (!request->payload) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Record payload failed.");
        return NULL;
    }

    if (strcmp(request->header.op, operation[RequestType_Deactivate])) {
        len = strlen(request->payload) + 1;
        docJson = (char*)malloc(len);
        len = base64_url_decode((uint8_t *)docJson, request->payload);
        if (len <= 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode the payload failed");
            free(docJson);
            goto errorExit;
        }
        docJson[len] = 0;

        request->doc = DIDDocument_FromJson(docJson);

        free(docJson);
        if (!request->doc) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Deserialize transaction payload from json failed.");
            goto errorExit;
        }

        if (request->doc->controllers.size > 1 &&
                request->header.multisig_m != request->doc->controllers.size) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "The multisig does not equal to the count of controllers.");
            goto errorExit;
        }

        if (request->doc->controllers.size == 1) {
            request->header.multisig_m = 1;
            request->header.multisig_n = 1;
        }

        strcpy(request->did.idstring, request->doc->did.idstring);
        DIDMetaData_SetTxid(&request->doc->metadata, request->header.prevtxid);
    } else {
        subject = DID_FromString(request->payload);
        if (!subject)
            goto errorExit;

        strcpy(request->did.idstring, subject->idstring);
        request->doc = NULL;
        DID_Destroy(subject);
    }

    item = json_object_get(json, "proof");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing proof.");
        goto errorExit;
    }
    if (!json_is_object(item) && !json_is_array(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid proof.");
        goto errorExit;
    }

    if (proof_fromjson(request, item) < 0)
        goto errorExit;

    if (request->doc->controllers.size > 1 && request->header.multisig_n != request->proofs.size) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "The multisig does not equal to the count of signers.");
        goto errorExit;
    }

    if (DIDRequest_Verify(request) < 0) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Verify payload failed.");
        goto errorExit;
    }

    return request->doc;

errorExit:
    DIDRequest_Destroy(request);
    return NULL;
}

DIDDocument *DIDRequest_FromJson(DIDRequest *request, const char *json)
{
    DIDDocument *doc;
    json_t *root;
    json_error_t error;

    assert(request);
    assert(json);

    root = json_loads(json, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Deserialize document failed, error: %s.", error.text);
        return NULL;
    }

    doc = DIDRequest_FromJson_Internal(request, root);
    json_decref(root);
    return doc;
}

bool DIDRequest_CheckWithPrevious(DIDRequest *request, DIDDocument *resolve_doc)
{
    DIDDocument *doc, *_doc;
    const char *txid;
    int i;

    assert(request);

    doc = request->doc;
    if (!doc && strcmp(request->header.op, operation[2])) {
        DIDError_Set(DIDERR_INVALID_REQUEST, "DID Request misses document.");
        return false;
    }

    if (!DID_Equals(&request->did, &doc->did)) {
        DIDError_Set(DIDERR_INVALID_REQUEST, "DID Request owner and document is mismatch.");
        return false;
    }

    if (!resolve_doc && strcmp(request->header.op, operation[0])) {
        DIDError_Set(DIDERR_INVALID_REQUEST, "DID Request's type is wrong.");
        return false;
    }

    if (resolve_doc) {
        txid = DIDMetaData_GetTxid(&resolve_doc->metadata);
        //create operation
        if (!strcmp(request->header.op, operation[0]) && (txid || *txid)) {
            DIDError_Set(DIDERR_INVALID_REQUEST, "DID Request's is disabled, not 'create' operation.");
            return false;
        }

        //update operation
        if (!strcmp(request->header.op, operation[1])) {
            if (!txid || !*txid) {
                DIDError_Set(DIDERR_INVALID_REQUEST, "DID Request's is disabled, not 'update' operation.");
                return false;
            }
            if (strcmp(txid, request->header.prevtxid)) {
                DIDError_Set(DIDERR_INVALID_REQUEST, "DID Request's is disabled, the newest transaction is on the chain.");
                return false;
            }
        }

        if (strcmp(request->header.op, operation[2]) && !request->doc) {
            DIDError_Set(DIDERR_INVALID_REQUEST, "DID Request's dosen't contains document.");
            return false;
        }
    }

    if (request->header.multisig_m != doc->controllers.size) {
        DIDError_Set(DIDERR_INVALID_REQUEST, "The multisig does not match the count of controllers.");
        return false;
    }

    for (i = 0; i < request->proofs.size; i++) {
        DIDURL *keyid = &request->proofs.proofs[i].verificationMethod;
        if (!strcmp(request->header.op, operation[0]) && !Is_DefaultKey(doc, keyid))
            return false;

        if (strcmp(request->header.op, operation[0]) && !Is_Controller_DefaultKey(resolve_doc, keyid))
            return false;
    }

    if (DIDRequest_Verify(request) < 0) {
        DIDError_Set(DIDERR_INVALID_REQUEST, "DID request is not genuine.");
        return false;
    }

    return true;
}

bool DIDRequest_IsValid(DIDRequest *request)
{
    DIDDocument *doc;

    assert(request);

    doc = DID_Resolve(&request->did, true);
    return DIDRequest_CheckWithPrevious(request, doc);
}

void DIDRequest_Destroy(DIDRequest *request)
{
    if (!request)
        return;

    if (request->payload) {
        free((void*)request->payload);
        request->payload = NULL;
    }
    if (request->doc) {
        DIDDocument_Destroy(request->doc);
        request->doc = NULL;
    }

    if (request->proofs.proofs) {
        free((void*)request->proofs.proofs);
        request->proofs.proofs = NULL;
    }
}

void DIDRequest_Free(DIDRequest *request)
{
    if (request && request->payload) {
        free((void*)request->payload);
        request->payload = NULL;
    }

    if (request->proofs.proofs) {
        free((void*)request->proofs.proofs);
        request->proofs.proofs = NULL;
    }
}
