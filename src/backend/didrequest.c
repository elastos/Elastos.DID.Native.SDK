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
    char multisig[32] = {0};

    assert(gen);
    assert(req);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "specification", req->header.spec));
    CHECK(JsonGenerator_WriteStringField(gen, "operation", req->header.op));
    if (!strcmp(req->header.op, operation[RequestType_Update]))
        CHECK(JsonGenerator_WriteStringField(gen, "previousTxid", req->header.prevtxid));

    if (req->header.multisig_n > 1)
        CHECK(JsonGenerator_WriteStringField(gen, "multisig",
                format_multisig(multisig, sizeof(multisig), req->header.multisig_m, req->header.multisig_n)));

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

ssize_t DIDRequest_GetDigest(DIDRequest *request, uint8_t *digest, size_t size)
{
    char buffer[32] = {0}, *multisig;

    assert(request);
    assert(digest);
    assert(size >= SHA256_BYTES);

    multisig = format_multisig(buffer, sizeof(buffer), request->header.multisig_m, request->header.multisig_n);
    return sha256_digest(digest,  5,
            (unsigned char*)request->header.spec, strlen(request->header.spec),
            (unsigned char*)request->header.op, strlen(request->header.op),
            (unsigned char*)request->header.prevtxid, strlen(request->header.prevtxid),
            (unsigned char*)multisig, strlen(multisig),
            (unsigned char*)request->payload, strlen(request->payload));
}

const char *DIDRequest_SignRequest(DIDRequest *request, DIDDocument *document,
        DIDURL *signkey, const char *storepass)
{
    uint8_t digest[SHA256_BYTES];
    char signature[SIGNATURE_BYTES * 2 + 16];
    ssize_t size;
    const char *requestJson;

    assert(request);
    assert(storepass && *storepass);

    size = DIDRequest_GetDigest(request, digest, sizeof(digest));
    if (size < 0) {
        DIDError_Set(DIDERR_MALFORMED_REQUEST, "Get digest from did request failed.");
        return NULL;
    }

    if (DIDDocument_SignDigest(document, signkey, storepass, signature, digest, sizeof(digest)) < 0)
        return NULL;

    if(DIDRequest_AddProof(request, signature, signkey, time(NULL)) < 0)
        return NULL;

    return DIDRequest_ToJson(request);
}

const char *DIDRequest_Sign(DIDRequest_Type type, DIDDocument *document, DIDURL *signkey,
        const char *storepass)
{
    DIDRequest req;
    DIDDocument *doc;
    const char *payload, *op, *requestJson, *prevtxid, *data, *multisig;
    size_t len;
    int rc;
    char signature[SIGNATURE_BYTES * 2 + 16], idstring[ELA_MAX_DID_LEN], buffer[32] = {0};

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

    strcpy(req.header.spec, (char*)spec);
    strcpy(req.header.op, operation[type]);
    strcpy(req.header.prevtxid, (char*)prevtxid);
    req.payload = payload;

    multisig = DIDMetaData_GetMultisig(&document->metadata);
    if (!multisig)
        multisig = "";

    parse_multisig(multisig, &req.header.multisig_m, &req.header.multisig_n);

    if (!DIDDocument_GetPublicKey(document, signkey)) {
        doc = DIDStore_LoadDID(document->metadata.base.store, &signkey->did);
    } else {
        doc = document;
    }

    requestJson = DIDRequest_SignRequest(&req, doc, signkey, storepass);
    if (doc != document)
        DIDDocument_Destroy(doc);
    DIDRequest_Free(&req, false);
    return requestJson;
}

bool DIDRequest_ExistSignKey(DIDRequest *request, DIDURL *signkey)
{
    int i;
    size_t size;
    RequestProof *rp;

    assert(request);
    assert(signkey);

    size = request->proofs.size;
    rp = request->proofs.proofs;
    for (i = 0; i < size && rp; i++) {
        if (DIDURL_Equals(&rp[i].verificationMethod, signkey))
            return true;
    }

    return false;
}

int DIDRequest_AddProof(DIDRequest *request, char *signature, DIDURL *signkey, time_t created)
{
    int i;
    size_t size;
    RequestProof *rp;

    assert(request);
    assert(signature);
    assert(signkey);

    size = request->proofs.size;
    rp = request->proofs.proofs;
    for (i = 0; i < size && rp; i++) {
        RequestProof *p = &rp[i];
        if (DIDURL_Equals(&p->verificationMethod, signkey) || !strcmp(p->signature, signature)) {
            DIDError_Set(DIDERR_INVALID_KEY, "The signkey already exist.");
            return -1;
        }
    }

    if (!rp)
        request->proofs.proofs = (RequestProof*)calloc(1, sizeof(RequestProof));
    else
        request->proofs.proofs = realloc(rp, (request->proofs.size + 1) * sizeof(RequestProof));

    if (!request->proofs.proofs)
        return -1;

    strcpy(request->proofs.proofs[size].signature, signature);
    DIDURL_Copy(&request->proofs.proofs[size].verificationMethod, signkey);
    request->proofs.proofs[size].created = created;
    request->proofs.size++;
    return 0;
}

static int Parser_Proof(DIDRequest *request, json_t *json)
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

static int Parser_Header(DIDRequest *request, json_t *json)
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

        parse_multisig(json_string_value(item), &request->header.multisig_m, &request->header.multisig_n);
        if (request->header.multisig_m > request->header.multisig_n) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Wrong multisig.");
            return -1;
        }
    }

    return 0;
}

static int Parser_Payload(DIDRequest *request, json_t *json)
{
    const char *payload;
    char *docJson, buffer[32] = {0};
    DID *subject;
    size_t len;

    assert(request);
    assert(json);

    payload = json_string_value(json);
    if (!payload) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "No payload.");
        return -1;
    }

    request->payload = strdup(payload);
    if (!request->payload) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Record payload failed.");
        return -1;
    }

    //not deactivated
    if (strcmp(request->header.op, operation[RequestType_Deactivate])) {
        len = strlen(request->payload) + 1;
        docJson = (char*)malloc(len);
        len = base64_url_decode((uint8_t *)docJson, request->payload);
        if (len <= 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode the payload failed");
            free((void*)docJson);
            return -1;
        }
        docJson[len] = 0;

        request->doc = DIDDocument_FromJson(docJson);
        free(docJson);
        if (!request->doc) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Deserialize transaction payload from json failed.");
            return -1;
        }

        if (request->doc->controllers.size > 1) {
            if (request->doc->controllers.size != request->header.multisig_n) {
                DIDError_Set(DIDERR_RESOLVE_ERROR, "Deserialize transaction payload from json failed.");
                return -1;
            }
        }

        strcpy(request->did.idstring, request->doc->did.idstring);
        DIDMetaData_SetTxid(&request->doc->metadata, request->header.prevtxid);
        DIDMetaData_SetMultisig(&request->doc->metadata,
                format_multisig(buffer, sizeof(buffer), request->header.multisig_m, request->header.multisig_m));
    } else {
        subject = DID_FromString(request->payload);
        if (!subject)
            return -1;

        strcpy(request->did.idstring, subject->idstring);
        request->doc = NULL;
        DID_Destroy(subject);
    }

    return 0;
}

DIDRequest *DIDRequest_FromJson_Internal(json_t *json)
{
    json_t *item, *field = NULL;
    char *docJson;
    DID *subject;
    size_t len;
    DIDRequest *request;

    assert(json);

    request = (DIDRequest*)calloc(1, sizeof(DIDRequest));
    if (!request) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DIDRequest failed.");
        return NULL;
    }

    //parse header
    item = json_object_get(json, "header");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing header.");
        goto errorExit;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid header.");
        goto errorExit;
    }
    if (Parser_Header(request, item) < 0)
        goto errorExit;

    //parse payload
    item = json_object_get(json, "payload");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing payload.");
        goto errorExit;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid payload.");
        goto errorExit;
    }
    if (Parser_Payload(request, item) < 0)
        goto errorExit;

    //parse proof
    item = json_object_get(json, "proof");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing proof.");
        goto errorExit;
    }
    if (!json_is_object(item) && !json_is_array(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid proof.");
        goto errorExit;
    }
    if (Parser_Proof(request, item) < 0)
        goto errorExit;

    return request;

errorExit:
    DIDRequest_Destroy(request);
    return NULL;
}

DIDRequest *DIDRequest_FromJson(const char *json)
{
    DIDRequest *request;
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

    request = DIDRequest_FromJson_Internal(root);
    json_decref(root);
    return request;
}

int DIDRequest_GetMultisig(DIDRequest *request, int *multisig_m, int *multisig_n)
{
    if (!request || !multisig_m || !multisig_n) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    *multisig_m = request->header.multisig_m;
    *multisig_n = request->header.multisig_n;
    return 0;
}

const char *DIDRequest_GetPayload(DIDRequest *request)
{
    if (!request) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return request->payload;
}

const char *DIDRequest_GetVersion(DIDRequest *request)
{
    if (!request) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return request->header.spec;
}

const char *DIDRequest_GetOperation(DIDRequest *request)
{
    if (!request) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return request->header.op;
}

ssize_t DIDRequest_GetProofCount(DIDRequest *request)
{
    if (!request) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return request->proofs.size;
}

int DIDRequest_GetProof(DIDRequest *request, int index, DIDURL *keyid,
        time_t *created, const char *signature, size_t size)
{
    RequestProof *proof;

    if (!request || index < 0 || !keyid || !created || !signature) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (request->proofs.size == 0 || !request->proofs.proofs) {
        DIDError_Set(DIDERR_MALFORMED_REQUEST, "There is no proof in DIDRequest.");
        return -1;
    }

    if (request->proofs.size <= index) {
        DIDError_Set(DIDERR_MALFORMED_REQUEST, "The index is larger than the total count of proof.");
        return -1;
    }

    proof = &request->proofs.proofs[index];
    if (size <= strlen(proof->signature)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The buffer to store signature is too small.");
        return -1;
    }

    DIDURL_Copy(keyid, &proof->verificationMethod);
    *created = proof->created;
    strcpy((char*)signature, proof->signature);
    return 0;
}

DIDDocument *DIDRequest_GetDIDDocument(DIDRequest *request)
{
    if (!request) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return request->doc;
}

static bool DIDRequest_CheckSignature(DIDRequest *request, DIDDocument *document)
{
    char buffer[32] = {0}, *multisig;
    int i;

    assert(request);
    assert(document);

    if (request->doc && !DIDDocument_IsValid(request->doc))
        return false;

    multisig = format_multisig(buffer, sizeof(buffer), request->header.multisig_m, request->header.multisig_n);

    for (i = 0; i < request->proofs.size; i++) {
        DIDURL *keyid = &request->proofs.proofs[i].verificationMethod;
        if (!Is_DefaultKey(document, keyid))
            return false;

        if (DIDDocument_Verify(document, keyid,
                (char*)request->proofs.proofs[i].signature, 5,
                request->header.spec, strlen(request->header.spec),
                request->header.op, strlen(request->header.op),
                request->header.prevtxid, strlen(request->header.prevtxid),
                multisig, strlen(multisig),
                request->payload, strlen(request->payload)) < 0)
            return false;
    }

    return true;
}

bool DIDRequest_IsValid(DIDRequest *request, bool isqualified)
{
    DIDDocument *resolve_doc = NULL, *doc;
    const char *multisig;
    int m, n;
    bool bchecked = false;

    if (!request) {
        DIDError_Set(DIDERR_MALFORMED_REQUEST, "No idrequest.");
        return false;
    }

    if (!strcmp(request->header.op, "create") && *request->header.prevtxid) {
        DIDError_Set(DIDERR_MALFORMED_REQUEST, "'create' request does not have previous transaction id.");
        return false;
    }

    if (!strcmp(request->header.op, "update") && !*request->header.prevtxid) {
        DIDError_Set(DIDERR_MALFORMED_REQUEST, "'update' request must have previous transaction id.");
        return false;
    }

    resolve_doc = DID_Resolve(&request->did, true);
    if (!resolve_doc || !*request->header.prevtxid) {  //create transaction-----!*request->header.prevtxid
        doc = request->doc;
        if (isqualified && (request->header.multisig_m > request->proofs.size)) {
            DIDError_Set(DIDERR_MALFORMED_REQUEST, "The count of signer is less than mulitsig.");
            goto errorExit;
        }
    } else {
        if (!strcmp(request->header.prevtxid, DIDMetaData_GetTxid(&request->doc->metadata))) {
            doc = resolve_doc;
        } else {
            doc = DID_ResolveByTransactionId(&request->did, request->header.prevtxid);
            if (!doc)
                goto errorExit;
        }

        multisig = DIDMetaData_GetMultisig(&resolve_doc->metadata);
        parse_multisig(multisig, &m, &n);
        if (isqualified && m > request->proofs.size) {
            DIDError_Set(DIDERR_MALFORMED_REQUEST, "The count of signer is less than mulitsig.");
            goto errorExit;
        }
    }

    bchecked = DIDRequest_CheckSignature(request, doc);

errorExit:
    DIDDocument_Destroy(resolve_doc);
    return bchecked;
}

bool DIDRequest_IsQualified(DIDRequest *request)
{
    DIDDocument *resolve_doc;
    const char *multisig;
    int m, n;

    if (!request)
        return false;

    resolve_doc = DID_Resolve(&request->did, true);
    if (!resolve_doc || !*request->header.prevtxid) {  //create transaction-----!*request->header.prevtxid
        DIDDocument_Destroy(resolve_doc);
        return request->header.multisig_m == request->proofs.size ? true : false;
    }

    DIDDocument_Destroy(resolve_doc);
    resolve_doc = DID_ResolveByTransactionId(&request->did, request->header.prevtxid);
    if (!resolve_doc) {
        DIDError_Set(DIDERR_MALFORMED_REQUEST, "The DID Request does not match with the chain copy.");
        return false;
    }

    multisig = DIDMetaData_GetMultisig(&resolve_doc->metadata);
    parse_multisig(multisig, &m, &n);
    DIDDocument_Destroy(resolve_doc);
    return request->proofs.size >= m ? true : false;
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
        request->proofs.size = 0;
        request->proofs.proofs = NULL;
    }

    free((void*)request);
}

void DIDRequest_Free(DIDRequest *request, bool all)
{
    if (!request)
        return;

    if (request->payload) {
        free((void*)request->payload);
        request->payload = NULL;
    }

    if (request->proofs.proofs) {
        free((void*)request->proofs.proofs);
        request->proofs.size = 0;
        request->proofs.proofs = NULL;
    }

    if (all)
       free(request);
}
