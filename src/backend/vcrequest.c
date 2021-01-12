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
#include "vcrequest.h"
#include "credential.h"

static const char *spec = "elastos/credential/1.0";
static const char* operation[] = {"declare", "revoke"};

static int header_toJson(JsonGenerator *gen, CredentialRequest *request)
{
    assert(gen);
    assert(request);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "specification", request->header.spec));
    CHECK(JsonGenerator_WriteStringField(gen, "operation", request->header.op));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

static int proof_toJson(JsonGenerator *gen, CredentialRequest *request)
{
    char _method[ELA_MAX_DIDURL_LEN], *method;

    assert(gen);
    assert(request);

    method = DIDURL_ToString(&request->proof.verificationMethod, _method, ELA_MAX_DIDURL_LEN, 0);
    if (!method)
        return -1;

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "verificationMethod", method));
    CHECK(JsonGenerator_WriteStringField(gen, "signature", request->proof.signature));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

int CredentialRequest_ToJson_Internal(JsonGenerator *gen, CredentialRequest *request)
{
    assert(gen);
    assert(request);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteFieldName(gen, "header"));
    CHECK(header_toJson(gen, request));
    CHECK(JsonGenerator_WriteStringField(gen, "payload", request->payload));
    CHECK(JsonGenerator_WriteFieldName(gen, "proof"));
    CHECK(proof_toJson(gen, request));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

const char *CredentialRequest_ToJson(CredentialRequest *request)
{
    JsonGenerator g, *gen;

    assert(request);

    gen = JsonGenerator_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator initialize failed.");
        return NULL;
    }

    if (CredentialRequest_ToJson_Internal(gen, request) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize CredentialRequest to json failed.");
        JsonGenerator_Destroy(gen);
        return NULL;
    }

    return JsonGenerator_Finish(gen);
}

const char *CredentialRequest_Sign(CredentialRequest_Type type, DIDURL *credid,
        Credential *credential, DIDURL *signkey, DIDDocument *document, const char *storepass)
{
    CredentialRequest req;
    const char *payload, *op, *requestJson, *data;
    size_t len;
    int rc;
    char signature[SIGNATURE_BYTES * 2 + 16], idstring[ELA_MAX_DID_LEN];

    assert((type == RequestType_Declare && credential) || (type == RequestType_Revoke && credid));
    assert(signkey);
    assert(storepass && *storepass);

    if (type == RequestType_Revoke) {
        data = DIDURL_ToString(credid, idstring, sizeof(idstring), false);
        if (!data)
            return NULL;
        payload = strdup(data);
    } else {
        data = Credential_ToJson(credential, true);
        if (!data)
            return NULL;

        len = strlen(data);
        payload = (char*)malloc(len * 4 / 3 + 16);
        base64_url_encode((char*)payload, (const uint8_t *)data, len);
        free((void*)data);
    }

    op = operation[type];
    rc = DIDDocument_Sign(document, signkey, storepass, signature, 3,
            (unsigned char*)spec, strlen(spec), (unsigned char*)op, strlen(op),
            (unsigned char*)payload, strlen(payload));
    if (rc < 0) {
        free((void*)payload);
        return NULL;
    }

    strcpy(req.header.spec, (char*)spec);
    strcpy(req.header.op, (char*)op);
    req.payload = payload;
    strcpy(req.proof.signature, signature);
    DIDURL_Copy(&req.proof.verificationMethod, signkey);

    requestJson = CredentialRequest_ToJson(&req);
    free((void*)payload);
    return requestJson;
}

int CredentialRequest_Verify(CredentialRequest *request)
{
    DIDDocument *doc;
    int rc, status;

    assert(request);

    if (!request->vc)
        return 0;

    doc = DID_Resolve(&request->vc->subject.id, &status, false);
    if (!doc)
        return -1;

    rc = DIDDocument_Verify(doc, &request->proof.verificationMethod,
                (char*)request->proof.signature, 3,
                request->header.spec, strlen(request->header.spec),
                request->header.op, strlen(request->header.op),
                request->payload, strlen(request->payload));
    DIDDocument_Destroy(doc);
    return rc;
}

Credential *CredentialRequest_FromJson(CredentialRequest *request, json_t *json)
{
    json_t *item, *field = NULL;
    char *vcJson;
    const char *op, *payload;
    DIDURL *id;
    size_t len;

    assert(request);
    assert(json);

    memset(request, 0, sizeof(CredentialRequest));
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
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Unknown Credential specification. \
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
    if (!strcmp(op, operation[RequestType_Declare]) || !strcmp(op, operation[RequestType_Revoke])) {
        strcpy(request->header.op, op);
    } else {
        DIDError_Set(DIDERR_UNKNOWN, "Unknown Credential operaton.");
        return NULL;
    }

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

    if (!strcmp(request->header.op, operation[RequestType_Declare])) {
        len = strlen(request->payload) + 1;
        vcJson = (char*)malloc(len);
        len = base64_url_decode((uint8_t *)vcJson, request->payload);
        if (len <= 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode the payload failed");
            free(vcJson);
            goto errorExit;
        }
        vcJson[len] = 0;

        request->vc = Credential_FromJson(vcJson, NULL);
        free(vcJson);
        if (!request->vc) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Deserialize transaction payload from json failed.");
            goto errorExit;
        }

        DIDURL_Copy(&request->id, &request->vc->id);
    } else {
        id = DIDURL_FromString(request->payload, false);
        if (!id)
            goto errorExit;

        DIDURL_Copy(&request->id, id);
        request->vc = NULL;
        DIDURL_Destroy(id);
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
            json_string_value(field), NULL) < 0) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid signing key.");
        goto errorExit;
    }

    field = json_object_get(item, "signature");
    if (!field) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing signature.");
        goto errorExit;
    }
    if (!json_is_string(field) || strlen(json_string_value(field)) >= MAX_SIGNATURE_LEN) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid signature.");
        goto errorExit;
    }
    strcpy(request->proof.signature, json_string_value(field));

    if (CredentialRequest_Verify(request) < 0) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Verify payload failed.");
        goto errorExit;
    }

    return request->vc;

errorExit:
    if (request->payload) {
        free((void*)request->payload);
        request->payload = NULL;
    }

    if (request->vc) {
        Credential_Destroy(request->vc);
        request->vc = NULL;
    }

    return NULL;
}

void CredentialRequest_Destroy(CredentialRequest *request)
{
    if (!request)
        return;

    if (request->payload) {
        free((void*)request->payload);
        request->payload = NULL;
    }
    if (request->vc) {
        Credential_Destroy(request->vc);
        request->vc = NULL;
    }
}

void CredentialRequest_Free(CredentialRequest *request)
{
    if (request && request->payload) {
        free((void*)request->payload);
        request->payload = NULL;
    }
}
