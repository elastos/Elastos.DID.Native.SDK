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
    if (!strcmp(req->header.op, operation[RequestType_Update]))
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
        free((void*)payload);
        return NULL;
    }

    if (type == RequestType_Transfer && !ticket) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Transfer operation must attatch transfer ticket.");
        free((void*)payload);
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
            (unsigned char *)prevtxid, strlen(prevtxid),
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

DIDDocument *DIDRequest_FromJson(DIDRequest *request, json_t *json)
{
    json_t *item, *field = NULL;
    char *docJson, *ticketJson;
    const char *op, *payload;
    DID *subject;
    size_t len;

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

    field = json_object_get(item, "specification");
    if (!field) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing specification.");
        return NULL;
    }
    if (!json_is_string(field)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid specification.");
        return NULL;
    }
    if (strcmp(json_string_value(field), spec)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Unknown DID specification. \
                excepted: %s, actual: %s", spec, json_string_value(field));
        return NULL;
    }
    strcpy(request->header.spec, (char *)spec);

    field = json_object_get(item, "operation");
    if (!field) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing operation.");
        return NULL;
    }
    if (!json_is_string(field)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid operation.");
        return NULL;
    }
    op = json_string_value(field);
    if (!strcmp(op, operation[RequestType_Create]) || !strcmp(op, operation[RequestType_Update]) ||
            !strcmp(op, operation[RequestType_Deactivate])) {
        strcpy(request->header.op, op);
    } else {
        DIDError_Set(DIDERR_UNKNOWN, "Unknown DID operaton.");
        return NULL;
    }

    if (!strcmp(op, operation[RequestType_Update])) {
        field = json_object_get(item, "previousTxid");
        if (!field) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing payload.");
            return NULL;
        }
        if (!json_is_string(field)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid payload.");
            return NULL;
        }
        strcpy(request->header.prevtxid, json_string_value(field));
    } else {
        *request->header.prevtxid = 0;
    }

    field = json_object_get(item, "ticket");
    if (!field) {
        if (!strcmp(request->header.op, "transfer")) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing ticket.");
            return NULL;
        }
        request->header.ticket = "";
    }
    if (field) {
        if (strcmp(request->header.op, "transfer")) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid payload.");
            return NULL;
        }
        len = strlen(json_string_value(field)) + 1;
        ticketJson = (char*)malloc(len);
        len = base64_url_decode((uint8_t *)ticketJson, json_string_value(field));
        if (len <= 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode the ticket failed");
            free(ticketJson);
            goto errorExit;
        }
        ticketJson[len] = 0;
        request->header.ticket = ticketJson;
    }

    item = json_object_get(json, "payload");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing payload.");
        goto errorExit;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid payload.");
        goto errorExit;
    }
    payload = json_string_value(item);
    if (!payload) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "No payload.");
        goto errorExit;
    }
    request->payload = strdup(payload);
    if (!request->payload) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Record payload failed.");
        goto errorExit;
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

        strcpy(request->did.idstring, request->doc->did.idstring);
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
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid proof.");
        goto errorExit;
    }

    field = json_object_get(item, "verificationMethod");
    if (!field) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing signing key.");
        goto errorExit;
    }
    if (!json_is_string(field)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid signing key.");
        goto errorExit;
    }

    if (Parse_DIDURL(&request->proof.verificationMethod,
            json_string_value(field), &request->did) < 0) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid signing key.");
        goto errorExit;
    }

    field = json_object_get(item, "signature");
    if (!field) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing signature.");
        goto errorExit;
    }

    if (!json_is_string(field) || strlen(json_string_value(field)) >= MAX_SIGN_LEN) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid signature.");
        goto errorExit;
    }
    strcpy(request->proof.signatureValue, json_string_value(field));

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
