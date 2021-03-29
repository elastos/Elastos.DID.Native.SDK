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

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "specification", request->header.spec));
    CHECK(DIDJG_WriteStringField(gen, "operation", request->header.op));
    CHECK(DIDJG_WriteEndObject(gen));
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

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "verificationMethod", method));
    CHECK(DIDJG_WriteStringField(gen, "signature", request->proof.signature));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

int CredentialRequest_ToJson_Internal(JsonGenerator *gen, CredentialRequest *request)
{
    assert(gen);
    assert(request);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteFieldName(gen, "header"));
    CHECK(header_toJson(gen, request));
    CHECK(DIDJG_WriteStringField(gen, "payload", request->payload));
    CHECK(DIDJG_WriteFieldName(gen, "proof"));
    CHECK(proof_toJson(gen, request));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

const char *CredentialRequest_ToJson(CredentialRequest *request)
{
    JsonGenerator g, *gen;

    assert(request);

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator initialize failed.");
        return NULL;
    }

    if (CredentialRequest_ToJson_Internal(gen, request) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize CredentialRequest to json failed.");
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
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
        b64_url_encode((char*)payload, (const uint8_t *)data, len);
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

int CredentialRequest_FromJson(CredentialRequest *request, json_t *json)
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
        return -1;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid header.");
        return -1;
    }

    field = json_object_get(item, "specification");
    if (!field) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing specification.");
        return -1;
    }
    if (!json_is_string(field)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid specification.");
        return -1;
    }
    if (strcmp(json_string_value(field), spec)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Unknown Credential specification. \
                excepted: %s, actual: %s", spec, json_string_value(field));
        return -1;
    }
    strcpy(request->header.spec, (char *)spec);

    field = json_object_get(item, "operation");
    if (!field) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing operation.");
        return -1;
    }
    if (!json_is_string(field)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid operation.");
        return -1;
    }
    op = json_string_value(field);
    if (!strcmp(op, operation[RequestType_Declare]) || !strcmp(op, operation[RequestType_Revoke])) {
        strcpy(request->header.op, op);
    } else {
        DIDError_Set(DIDERR_UNKNOWN, "Unknown Credential operaton.");
        return -1;
    }

    item = json_object_get(json, "payload");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing payload.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid payload.");
        return -1;
    }
    payload = json_string_value(item);
    if (!payload) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "No payload.");
        return -1;
    }
    request->payload = strdup(payload);
    if (!request->payload) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Record payload failed.");
        return -1;
    }

    if (!strcmp(request->header.op, operation[RequestType_Declare])) {
        len = strlen(request->payload) + 1;
        vcJson = (char*)malloc(len);
        len = b64_url_decode((uint8_t *)vcJson, request->payload);
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

    if (DIDURL_Parse(&request->proof.verificationMethod,
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
    return 0;

errorExit:
    CredentialRequest_Destroy(request);
    memset(request, 0, sizeof(CredentialRequest));
    return -1;
}

bool CredentialRequest_IsValid(CredentialRequest *request, Credential *credential)
{
    DIDDocument *signerdoc = NULL, *ownerdoc = NULL, *issuerdoc = NULL;
    DIDURL *signkey;
    Credential *vc = NULL;
    int status, rc = -1;

    assert(request);

    signkey = &request->proof.verificationMethod;
    ownerdoc = DID_Resolve(&request->id.did, &status, false);
    if (!ownerdoc) {
        if (status == DIDStatus_NotFound)
            DIDError_Set(DIDERR_NOT_EXISTS, "Credential request's signer does not exist.");
        return false;
    }

    if (!DIDDocument_IsValid(ownerdoc))
        goto errorExit;

    if (!strcmp("declare", request->header.op)) {
        vc = request->vc;
        if (!vc) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "Miss credential in the transaction.");
            goto errorExit;
        }

        if (!DIDDocument_IsAuthenticationKey(ownerdoc, signkey)) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "The signer is not the controller of customized did.");
            goto errorExit;
        }
    } else {
        vc = request->vc;
        if (!vc)
            vc = credential;

        if (vc) {
            issuerdoc = DID_Resolve(&vc->issuer, &status, false);
            if (!issuerdoc) {
               DIDError_Set(DIDERR_TRANSACTION_ERROR, "Issuer of credential does not exist.");
               goto errorExit;
            }
        }

        if (!DIDDocument_IsAuthenticationKey(ownerdoc, signkey) &&
                (issuerdoc && !DIDDocument_IsAuthenticationKey(issuerdoc, signkey)))
            goto errorExit;
    }

    if (vc && !Credential_IsValid(vc)) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Credential in request is invalid.");
        goto errorExit;
    }

    signerdoc = DID_Resolve(&signkey->did, &status, false);
    if (!signerdoc) {
        if (status == DIDStatus_NotFound)
            DIDError_Set(DIDERR_NOT_EXISTS, "Credential request's signer does not exist.");
        goto errorExit;
    }

    if (!DIDDocument_IsValid(signerdoc))
        goto errorExit;

    rc = DIDDocument_Verify(signerdoc, &request->proof.verificationMethod,
            (char*)request->proof.signature, 3,
            request->header.spec, strlen(request->header.spec),
            request->header.op, strlen(request->header.op),
            request->payload, strlen(request->payload));

errorExit:
    DIDDocument_Destroy(signerdoc);
    DIDDocument_Destroy(ownerdoc);
    DIDDocument_Destroy(issuerdoc);
    return rc == -1 ? false : true;
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
