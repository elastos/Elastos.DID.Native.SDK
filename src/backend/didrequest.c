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

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "specification", req->header.spec));
    CHECK(JsonGenerator_WriteStringField(gen, "operation", req->header.op));
    if (!strcmp(req->header.op, operation[RequestType_Update]) ||
           !strcmp(req->header.op, operation[RequestType_Transfer]))
        CHECK(JsonGenerator_WriteStringField(gen, "previousTxid", req->header.prevtxid));
    if (req->header.ticket && *req->header.ticket)
        CHECK(JsonGenerator_WriteStringField(gen, "ticket", req->header.ticket));
    CHECK(JsonGenerator_WriteEndObject(gen));
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

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "verificationMethod", method));
    CHECK(JsonGenerator_WriteStringField(gen, "signature", req->proof.signatureValue));
    CHECK(JsonGenerator_WriteEndObject(gen));
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

static const char *DIDRequest_ToJson(DIDRequest *req)
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

const char *DIDRequest_Sign(DIDRequest_Type type, DIDDocument *document,
        TransferTicket *ticket, DIDURL *signkey, const char *storepass)
{
    DIDRequest req;
    const char *payload = NULL, *op, *requestJson = NULL, *prevtxid, *data, *ticket_data = "";
    size_t len;
    int rc;
    char signature[SIGNATURE_BYTES * 2 + 16], idstring[ELA_MAX_DID_LEN];

    assert(type >= RequestType_Create && type <= RequestType_Deactivate);
    assert(document);
    assert(signkey);
    assert(storepass && *storepass);

    if (type != RequestType_Transfer && ticket) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Only support transfer operation with transfer ticket.");
        return NULL;
    }

    if (type == RequestType_Transfer && !ticket) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Transfer operation must attatch transfer ticket.");
        return NULL;
    }

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

    if (ticket) {
        data = TransferTicket_ToJson(ticket);
        if (!data)
            goto pointExit;

        len = strlen(data);
        ticket_data = (char*)malloc(len * 4 / 3 + 16);
        base64_url_encode((char*)ticket_data, (const uint8_t *)data, len);
        free((void*)data);
    }

    op = operation[type];
    rc = DIDDocument_Sign(document, signkey, storepass, signature, 5,
            (unsigned char*)spec, strlen(spec), (unsigned char*)op, strlen(op),
            (unsigned char*)prevtxid, strlen(prevtxid),
            (unsigned char*)ticket_data, strlen(ticket_data),
            (unsigned char*)payload, strlen(payload));
    if (rc < 0)
        goto pointExit;

    strcpy(req.header.spec, (char*)spec);
    strcpy(req.header.op, (char*)op);
    strcpy(req.header.prevtxid, (char*)prevtxid);
    req.header.ticket = ticket_data;
    req.payload = payload;
    strcpy(req.proof.signatureValue, signature);
    DIDURL_Copy(&req.proof.verificationMethod, signkey);

    requestJson = DIDRequest_ToJson(&req);

pointExit:
    if (payload)
        free((void*)payload);
    if (ticket_data && *ticket_data)
        free((void*)ticket_data);
    return requestJson;
}

int DIDRequest_Verify(DIDRequest *request)
{
    assert(request);

    if (!request->doc)
        return 0;

    //todo: if(request->doc) is for deacativated without doc.
    return DIDDocument_Verify(request->doc, &request->proof.verificationMethod,
                (char*)request->proof.signatureValue, 5,
                request->header.spec, strlen(request->header.spec),
                request->header.op, strlen(request->header.op),
                request->header.prevtxid, strlen(request->header.prevtxid),
                request->header.ticket, strlen(request->header.ticket),
                request->payload, strlen(request->payload));
}

static int parser_header(DIDRequest *request, json_t *json)
{
    json_t *item;
    int type = -1, i;

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

    if (type == RequestType_Update || type == RequestType_Transfer) {
        item = json_object_get(json, "previousTxid");
        if (!item) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing previous transaction id.");
            return -1;
        }
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid previous transaction id.");
            return -1;
        }
        strcpy(request->header.prevtxid, json_string_value(item));
    } else {
        *request->header.prevtxid = 0;
    }

    item = json_object_get(json, "ticket");
    if (!item) {
        if (type == RequestType_Transfer) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing ticket.");
            return -1;
        }
        request->header.ticket = "";
    }
    if (item) {
        if (type != RequestType_Transfer) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid ticket.");
            return -1;
        }
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid ticket.");
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
        DIDError_Set(DIDERR_RESOLVE_ERROR, "No payload.");
        return -1;
    }
    request->payload = strdup(payload);
    if (!request->payload) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Record payload failed.");
        return -1;
    }

    if (strcmp(request->header.op, operation[RequestType_Deactivate])) {
        len = strlen(request->payload) + 1;
        docJson = (char*)malloc(len);
        len = base64_url_decode((uint8_t *)docJson, request->payload);
        if (len <= 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode the payload failed");
            free(docJson);
            return -1;
        }
        docJson[len] = 0;

        request->doc = DIDDocument_FromJson(docJson);
        free(docJson);
        if (!request->doc) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Deserialize transaction payload from json failed.");
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
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing signing key.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid sign key.");
        return -1;
    }

    if (Parse_DIDURL(&request->proof.verificationMethod,
            json_string_value(item), &request->did) < 0) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid sign key.");
        return -1;
    }

    item = json_object_get(json, "signature");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing signature.");
        return -1;
    }

    if (!json_is_string(item) || strlen(json_string_value(item)) >= MAX_SIGN_LEN) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid signature.");
        return -1;
    }
    strcpy(request->proof.signatureValue, json_string_value(item));

    return 0;
}

DIDDocument *DIDRequest_FromJson(DIDRequest *request, json_t *json)
{
    json_t *item, *field = NULL;

    assert(request);
    assert(json);

    memset(request, 0, sizeof(DIDRequest));
    //parser header
    item = json_object_get(json, "header");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing header.");
        return NULL;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid header.");
        return NULL;
    }
    if (parser_header(request, item) < 0)
        goto errorExit;

    //parser payload
    item = json_object_get(json, "payload");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing payload.");
        goto errorExit;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid payload.");
        goto errorExit;
    }
    if (parser_payload(request, item) < 0)
        goto errorExit;

    //parser proof
    item = json_object_get(json, "proof");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing proof.");
        goto errorExit;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid proof.");
        goto errorExit;
    }
    if (parser_proof(request, item) < 0)
        goto errorExit;

    if (DIDRequest_Verify(request) < 0) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Verify payload failed.");
        goto errorExit;
    }

    return request->doc;

errorExit:
    DIDRequest_Destroy(request);
    return NULL;
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
