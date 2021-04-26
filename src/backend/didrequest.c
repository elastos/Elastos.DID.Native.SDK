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
static const char* operation[] = {"create", "update", "transfer", "deactivate"};

static int header_toJson(JsonGenerator *gen, DIDRequest *req)
{
    assert(gen);
    assert(req);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "specification", req->header.spec));
    CHECK(DIDJG_WriteStringField(gen, "operation", req->header.op));
    if (!strcmp(req->header.op, operation[RequestType_Update]))
        CHECK(DIDJG_WriteStringField(gen, "previousTxid", req->header.prevtxid));
    if (req->header.ticket && *req->header.ticket)
        CHECK(DIDJG_WriteStringField(gen, "ticket", req->header.ticket));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static int proof_toJson(JsonGenerator *gen, DIDRequest *req)
{
    char _method[ELA_MAX_DIDURL_LEN], *method;

    assert(gen);
    assert(req);

    method = DIDURL_ToString(&req->proof.verificationMethod, _method, ELA_MAX_DIDURL_LEN, 0);
    if (!method)
        return -1;

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "verificationMethod", method));
    CHECK(DIDJG_WriteStringField(gen, "signature", req->proof.signatureValue));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

int DIDRequest_ToJson_Internal(JsonGenerator *gen, DIDRequest *req)
{
    assert(gen);
    assert(req);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteFieldName(gen, "header"));
    CHECK(header_toJson(gen, req));
    CHECK(DIDJG_WriteStringField(gen, "payload", req->payload));
    CHECK(DIDJG_WriteFieldName(gen, "proof"));
    CHECK(proof_toJson(gen, req));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static const char *DIDRequest_ToJson(DIDRequest *req)
{
    JsonGenerator g, *gen;

    assert(req);

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator for didrequest initialize failed.");
        return NULL;
    }

    if (DIDRequest_ToJson_Internal(gen, req) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize didrequest to json failed.");
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

//document is for signkey. If DID is deactivated by authorizor, document is authorizor's document.
const char *DIDRequest_Sign(DIDRequest_Type type, DIDDocument *document,
        DIDURL *signkey, DIDURL *creater, TransferTicket *ticket, const char *storepass)
{
    DIDRequest req;
    const char *payload = NULL, *op, *requestJson = NULL, *prevtxid, *data, *ticket_data = "";
    char signature[SIGNATURE_BYTES * 2 + 16], idstring[ELA_MAX_DID_LEN];
    DID *did;
    size_t len;
    int rc;

    assert(type >= RequestType_Create && type <= RequestType_Deactivate);
    assert(document);
    assert(signkey);
    assert(storepass && *storepass);

    if (type != RequestType_Transfer && ticket) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Only support transfer operation with transfer ticket.");
        return NULL;
    }

    if (type == RequestType_Transfer && !ticket) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Transfer operation must attatch transfer ticket.");
        return NULL;
    }

    if (type == RequestType_Update) {
        prevtxid = DIDMetadata_GetTxid(&document->metadata);
        if (!prevtxid) {
            DIDError_Set(DIDERR_NOT_EXISTS, "Can't determine the previous transaction ID.");
            return NULL;
        }
    } else {
        prevtxid = "";
    }

    if (type == RequestType_Deactivate) {
        if (creater)
            did = &creater->did;
        else
            did = &document->did;

        data = DID_ToString(did, idstring, sizeof(idstring));
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
        b64_url_encode((char*)payload, (const uint8_t *)data, len);
        free((void*)data);
    }

    if (ticket) {
        data = TransferTicket_ToJson(ticket);
        if (!data)
            goto pointExit;

        len = strlen(data);
        ticket_data = (char*)malloc(len * 4 / 3 + 16);
        b64_url_encode((char*)ticket_data, (const uint8_t *)data, len);
        free((void*)data);
    }

    op = operation[type];
    rc = DIDDocument_Sign(document, signkey, storepass, signature, 5,
            (unsigned char*)spec, strlen(spec), (unsigned char*)op, strlen(op),
            (unsigned char*)prevtxid, strlen(prevtxid),
            (unsigned char*)ticket_data, strlen(ticket_data),
            (unsigned char*)payload, strlen(payload));
    if (rc < 0) {
        DIDError_Set(DIDERR_SIGN_ERROR, "Sign the did request faile.");
        goto pointExit;
    }

    strcpy(req.header.spec, (char*)spec);
    strcpy(req.header.op, (char*)op);
    strcpy(req.header.prevtxid, (char*)prevtxid);
    req.header.ticket = ticket_data;
    req.payload = payload;
    strcpy(req.proof.signatureValue, signature);
    if (creater)
        DIDURL_Copy(&req.proof.verificationMethod, creater);
    else
        DIDURL_Copy(&req.proof.verificationMethod, signkey);

    requestJson = DIDRequest_ToJson(&req);

pointExit:
    if (payload)
        free((void*)payload);
    if (ticket_data && *ticket_data)
        free((void*)ticket_data);
    return requestJson;
}

static int parser_header(DIDRequest *request, json_t *json)
{
    json_t *item;
    int type = -1, i;

    assert(request);
    assert(json);

    item = json_object_get(json, "specification");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Missing specification.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid specification.");
        return -1;
    }
    if (strcmp(json_string_value(item), spec)) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Unknown DID specification. \
                excepted: %s, actual: %s", spec, json_string_value(item));
        return -1;
    }
    strcpy(request->header.spec, (char *)spec);

    item = json_object_get(json, "operation");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Missing operation.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid operation.");
        return -1;
    }
    for (i = 0; i < 4; i++) {
        if (!strcmp(json_string_value(item), operation[i])) {
            type = i;
            strcpy(request->header.op, json_string_value(item));
            break;
        }
    }
    if (type == -1) {
        DIDError_Set(DIDERR_UNKNOWN, "Unknown DID operaton.");
        return -1;
    }

    if (type == RequestType_Update) {
        item = json_object_get(json, "previousTxid");
        if (!item) {
            DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Missing previous transaction id.");
            return -1;
        }
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid previous transaction id.");
            return -1;
        }
        strcpy(request->header.prevtxid, json_string_value(item));
    } else {
        *request->header.prevtxid = 0;
    }

    item = json_object_get(json, "ticket");
    if (!item) {
        if (type == RequestType_Transfer) {
            DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Missing ticket.");
            return -1;
        }
        request->header.ticket = "";
    }
    if (item) {
        if (type != RequestType_Transfer) {
            DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid ticket.");
            return -1;
        }
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid ticket.");
            return -1;
        }
        request->header.ticket = strdup(json_string_value(item));
    }

    return 0;
}

static int parser_payload(DIDRequest *request, json_t *json)
{
    const char *payload;
    char *docJson;
    DID *subject;
    size_t len;

    assert(request);
    assert(json);

    payload = json_string_value(json);
    if (!payload) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "No payload.");
        return -1;
    }
    request->payload = strdup(payload);
    if (!request->payload) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Record payload failed.");
        return -1;
    }

    if (strcmp(request->header.op, operation[RequestType_Deactivate])) {
        len = strlen(request->payload) + 1;
        docJson = (char*)malloc(len);
        len = b64_url_decode((uint8_t *)docJson, request->payload);
        if (len <= 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode payload failed");
            free(docJson);
            return -1;
        }
        docJson[len] = 0;

        request->doc = DIDDocument_FromJson(docJson);
        free(docJson);
        if (!request->doc) {
            DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Deserialize payload from json failed.");
            return -1;
        }

        strcpy(request->did.idstring, request->doc->did.idstring);
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

static int parser_proof(DIDRequest *request, json_t *json)
{
    json_t *item;

    assert(request);
    assert(json);

    item = json_object_get(json, "verificationMethod");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Missing signing key.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid sign key.");
        return -1;
    }

    if (DIDURL_Parse(&request->proof.verificationMethod,
            json_string_value(item), &request->did) < 0) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid sign key.");
        return -1;
    }

    item = json_object_get(json, "signature");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Missing signature.");
        return -1;
    }

    if (!json_is_string(item) || strlen(json_string_value(item)) >= MAX_SIGNATURE_LEN) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid signature.");
        return -1;
    }
    strcpy(request->proof.signatureValue, json_string_value(item));

    return 0;
}

int DIDRequest_FromJson(DIDRequest *request, json_t *json)
{
    json_t *item, *field = NULL;

    assert(request);
    assert(json);

    memset(request, 0, sizeof(DIDRequest));
    //parser header
    item = json_object_get(json, "header");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Missing header.");
        return -1;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid header.");
        return -1;
    }
    if (parser_header(request, item) < 0)
        goto errorExit;

    //parser payload
    item = json_object_get(json, "payload");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Missing payload.");
        goto errorExit;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid payload.");
        goto errorExit;
    }
    if (parser_payload(request, item) < 0)
        goto errorExit;

    //parser proof
    item = json_object_get(json, "proof");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Missing proof.");
        goto errorExit;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_IDCHAINREQUEST, "Invalid proof.");
        goto errorExit;
    }
    if (parser_proof(request, item) < 0)
        goto errorExit;

    return 0;

errorExit:
    DIDRequest_Destroy(request);
    memset(request, 0, sizeof(DIDRequest));
    return -1;
}

bool DIDRequest_IsValid(DIDRequest *request, DIDDocument *document)
{
    DIDDocument *signerdoc;
    DIDURL *signkey;
    int rc;

    assert(request);

    if (!request->doc && !document) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No document to check didrequest.");
        return false;
    }

    signkey = &request->proof.verificationMethod;

    if (!strcmp(operation[RequestType_Deactivate], request->header.op)) {
        signerdoc = document;
        if (!DIDDocument_IsAuthenticationKey(signerdoc, signkey) &&
                !DIDDocument_IsAuthorizationKey(signerdoc, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Sign key to deactivate did isn't \
                    an authentication key or an athorization key.");
            return false;
        }
    } else {
        if (!request->doc)
            return false;
        signerdoc = request->doc;
        if (!DIDDocument_IsAuthenticationKey(signerdoc, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Sign key isn't an authentication key.");
            return false;
        }
    }

    rc = DIDDocument_Verify(signerdoc, &request->proof.verificationMethod,
                (char*)request->proof.signatureValue, 5,
                request->header.spec, strlen(request->header.spec),
                request->header.op, strlen(request->header.op),
                request->header.prevtxid, strlen(request->header.prevtxid),
                request->header.ticket, strlen(request->header.ticket),
                request->payload, strlen(request->payload));
    if (rc < 0)
        DIDError_Set(DIDERR_VERIFY_ERROR, "Verify didrequest failed.");

    return rc == -1 ? false : true;
}

void DIDRequest_Destroy(DIDRequest *request)
{
    if (!request)
        return;

    if (request->header.ticket && *request->header.ticket) {
        free((void*)request->header.ticket);
        request->header.ticket = NULL;
    }

    if (request->payload) {
        free((void*)request->payload);
        request->payload = NULL;
    }

    if (request->doc) {
        DIDDocument_Destroy(request->doc);
        request->doc = NULL;
    }
}

void DIDRequest_Free(DIDRequest *request)
{
    if (!request)
        return;

    if (request->header.ticket && *request->header.ticket) {
        free((void*)request->header.ticket);
        request->header.ticket = NULL;
    }

    if (request->payload) {
        free((void*)request->payload);
        request->payload = NULL;
    }
}
