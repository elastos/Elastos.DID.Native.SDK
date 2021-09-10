/*
 * Copyright (c) 2019 - 2021 Elastos Foundation
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
#include <time.h>
#include <stdlib.h>
#include <assert.h>

#include "ela_did.h"
#include "did.h"
#include "diddocument.h"
#include "didstore.h"
#include "credential.h"
#include "common.h"
#include "JsonGenerator.h"
#include "JsonHelper.h"
#include "crypto.h"
#include "HDkey.h"
#include "didmeta.h"
#include "diderror.h"
#include "ticket.h"
#include "resolvercache.h"

#ifndef DISABLE_JWT
    #include "ela_jwt.h"
    #include "jwtbuilder.h"
    #include "jwsparser.h"
#endif

#define MAX_EXPIRES              5

const char *ProofType = "ECDSAsecp256r1";

static const char *ID = "id";
static const char *PUBLICKEY = "publicKey";
static const char *TYPE = "type";
static const char *CONTROLLER = "controller";
static const char *MULTI_SIGNATURE = "multisig";
static const char *PUBLICKEY_BASE58 = "publicKeyBase58";
static const char *AUTHENTICATION = "authentication";
static const char *AUTHORIZATION = "authorization";
static const char *SERVICE = "service";
static const char *VERIFIABLE_CREDENTIAL = "verifiableCredential";
static const char *SERVICE_ENDPOINT = "serviceEndpoint";
static const char *EXPIRES = "expires";
static const char *PROOF = "proof";
static const char *CREATOR = "creator";
static const char *CREATED = "created";
static const char *SIGNATURE_VALUE = "signatureValue";

typedef enum KeyType {
    KeyType_PublicKey,
    KeyType_Authentication,
    KeyType_Authorization
} KeyType;

static void PublicKey_Destroy(PublicKey *publickey)
{
    if(publickey)
        free(publickey);
}

static void Service_Destroy(Service *service)
{
    if (!service)
        return;

    if (service->properties)
        json_decref(service->properties);

    free(service);
}

static int PublicKey_ToJson(JsonGenerator *gen, PublicKey *pk, int compact)
{
    char id[ELA_MAX_DIDURL_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(pk);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, ID,
        DIDURL_ToString_Internal(&pk->id, id, sizeof(id), compact)));
    if (!compact) {
        CHECK(DIDJG_WriteStringField(gen, TYPE, pk->type));
        CHECK(DIDJG_WriteStringField(gen, CONTROLLER,
                DID_ToString(&pk->controller, id, sizeof(id))));
    } else {
        if (!DID_Equals(&pk->id.did, &pk->controller))
            CHECK(DIDJG_WriteStringField(gen, CONTROLLER,
                   DID_ToString(&pk->controller, id, sizeof(id))));
    }
    CHECK(DIDJG_WriteStringField(gen, PUBLICKEY_BASE58, pk->publicKeyBase58));
    CHECK(DIDJG_WriteEndObject(gen));

    return 0;
}

static int didurl_func(const void *a, const void *b)
{
    char _stringa[ELA_MAX_DIDURL_LEN], _stringb[ELA_MAX_DIDURL_LEN];
    char *stringa, *stringb;

    PublicKey *keya = *(PublicKey**)a;
    PublicKey *keyb = *(PublicKey**)b;

    stringa = DIDURL_ToString_Internal(&keya->id, _stringa, ELA_MAX_DIDURL_LEN, true);
    stringb = DIDURL_ToString_Internal(&keyb->id, _stringb, ELA_MAX_DIDURL_LEN, true);

    return strcmp(stringa, stringb);
}

static int controllers_func(const void *a, const void *b)
{
    char _stringa[ELA_MAX_DID_LEN], _stringb[ELA_MAX_DID_LEN];
    char *stringa, *stringb;

    DID *dida = *(DID**)a;
    DID *didb = *(DID**)b;

    stringa = DID_ToString(dida, _stringa, ELA_MAX_DID_LEN);
    stringb = DID_ToString(didb, _stringb, ELA_MAX_DID_LEN);

    return strcmp(stringa, stringb);
}

static int ControllerArray_ToJson(JsonGenerator *gen, DIDDocument **docs, size_t size)
{
    DID **controllers;
    char _string[ELA_MAX_DID_LEN];
    int i;

    assert(gen);
    assert(gen->buffer);
    assert(docs);
    assert(size > 0);

    controllers = (DID**)alloca(size * sizeof(DID*));
    if (!controllers) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for controllers failed.");
        return -1;
    }

    for (i = 0; i < size; i++)
        controllers[i] = DIDDocument_GetSubject(docs[i]);

    qsort(controllers, size, sizeof(DID*), controllers_func);

    if (size != 1)
        CHECK(DIDJG_WriteStartArray(gen));

    for (i = 0; i < size; i++ ) {
        CHECK(DIDJG_WriteString(gen,
                DID_ToString(controllers[i], _string, sizeof(_string))));
    }

    if (size != 1)
        CHECK(DIDJG_WriteEndArray(gen));

    return 0;
}

static int PublicKeyArray_ToJson(JsonGenerator *gen, PublicKey **pks, size_t size,
        int compact, KeyType type)
{
    size_t i;

    assert(gen);
    assert(gen->buffer);
    assert(pks);
    assert(type == KeyType_PublicKey || type == KeyType_Authentication ||
            type == KeyType_Authorization);

    qsort(pks, size, sizeof(PublicKey*), didurl_func);

    CHECK(DIDJG_WriteStartArray(gen));
    for (i = 0; i < size; i++ ) {
        char id[ELA_MAX_DIDURL_LEN];

        if ((type == KeyType_Authentication && !PublicKey_IsAuthenticationKey(pks[i])) ||
            (type == KeyType_Authorization && !PublicKey_IsAuthorizationKey(pks[i])))
            continue;

        if (type == KeyType_PublicKey)
            CHECK(PublicKey_ToJson(gen, pks[i], compact));
        else
            CHECK(DIDJG_WriteString(gen,
                DIDURL_ToString_Internal(&pks[i]->id, id, sizeof(id), compact)));
    }
    CHECK(DIDJG_WriteEndArray(gen));

    return 0;
}

static int Service_ToJson(JsonGenerator *gen, Service *service, int compact)
{
    char id[ELA_MAX_DIDURL_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(service);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, ID,
        DIDURL_ToString_Internal(&service->id, id, sizeof(id), compact)));
    CHECK(DIDJG_WriteStringField(gen, TYPE, service->type));
    CHECK(DIDJG_WriteStringField(gen, SERVICE_ENDPOINT, service->endpoint));

    if (service->properties)
        CHECK(JsonHelper_ToJson(gen, service->properties, true));

    CHECK(DIDJG_WriteEndObject(gen));

    return 0;
}

static int ServiceArray_ToJson(JsonGenerator *gen, Service **services, size_t size,
        int compact)
{
    size_t i;

    assert(gen);
    assert(gen->buffer);
    assert(services);

    qsort(services, size, sizeof(Service*), didurl_func);

    CHECK(DIDJG_WriteStartArray(gen));
    for ( i = 0; i < size; i++ )
        CHECK(Service_ToJson(gen, services[i], compact));

    CHECK(DIDJG_WriteEndArray(gen));

    return 0;
}

static int Proof_ToJson(JsonGenerator *gen, DocumentProof *proof, DIDDocument *document, int compact)
{
    char id[ELA_MAX_DIDURL_LEN];
    char _timestring[DOC_BUFFER_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(proof);
    assert(document);

    CHECK(DIDJG_WriteStartObject(gen));
    if (!compact)
        CHECK(DIDJG_WriteStringField(gen, TYPE, proof->type));
    CHECK(DIDJG_WriteStringField(gen, CREATED,
            get_time_string(_timestring, sizeof(_timestring), &proof->created)));
    if (!compact || !DID_Equals(&document->did, &proof->creater.did)) {
        CHECK(DIDJG_WriteStringField(gen, CREATOR,
                DIDURL_ToString_Internal(&proof->creater, id, sizeof(id), false)));
    }

    CHECK(DIDJG_WriteStringField(gen, SIGNATURE_VALUE, proof->signatureValue));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static int proof_cmp(const void *a, const void *b)
{
    char _stringa[ELA_MAX_DIDURL_LEN], _stringb[ELA_MAX_DIDURL_LEN];
    char *stringa, *stringb;
    int equals;

    DocumentProof *proofa = (DocumentProof*)a;
    DocumentProof *proofb = (DocumentProof*)b;

    equals = (int)(proofa->created - proofb->created);
    if (equals != 0)
        return equals;

    stringa = DIDURL_ToString_Internal(&proofa->creater, _stringa, ELA_MAX_DIDURL_LEN, false);
    stringb = DIDURL_ToString_Internal(&proofb->creater, _stringb, ELA_MAX_DIDURL_LEN, false);

    return strcmp(stringa, stringb);
}

static int ProofArray_ToJson(JsonGenerator *gen, DIDDocument *document, int compact)
{
    size_t size;
    DocumentProof *proofs;
    int i;

    assert(gen);
    assert(gen->buffer);
    assert(document);

    size = document->proofs.size;
    proofs = document->proofs.proofs;
    if (size > 1)
        CHECK(DIDJG_WriteStartArray(gen));

    qsort(proofs, size, sizeof(DocumentProof), proof_cmp);

    for (i = 0; i < size; i++)
        CHECK(Proof_ToJson(gen, &proofs[i], document, compact));

    if (size > 1)
        CHECK(DIDJG_WriteEndArray(gen));

    return 0;
}

//api don't check if pk is existed in array.
static int add_to_publickeys(DIDDocument *document, PublicKey *pk)
{
    PublicKey **pks;

    assert(document);
    assert(pk);

    pks = realloc(document->publickeys.pks, (document->publickeys.size + 1) * sizeof(PublicKey*));
    if (!pks) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for publicKeys failed.");
        return -1;
    }

    pks[document->publickeys.size++] = pk;
    document->publickeys.pks = pks;
    return 0;
}

static int Parse_PublicKey(DID *did, json_t *json, PublicKey **publickey)
{
    PublicKey *pk;
    json_t *field;

    assert(did);
    assert(json);
    assert(publickey);

    pk = (PublicKey*)calloc(1, sizeof(PublicKey));
    if (!pk) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for public key failed.");
        return -1;
    }

    field = json_object_get(json, ID);
    if (!field) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing public key id.");
        PublicKey_Destroy(pk);
        return -1;
    }

    if (!json_is_string(field) || DIDURL_Parse(&pk->id, json_string_value(field), did) < 0) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid public key id.");
        PublicKey_Destroy(pk);
        return -1;
    }

    assert(strcmp(did->idstring, pk->id.did.idstring) == 0);

    // set default value for 'type'
    strcpy(pk->type, ProofType);

    field = json_object_get(json, PUBLICKEY_BASE58);
    if (!field) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing publicKey base58.");
        PublicKey_Destroy(pk);
        return -1;
    }
    if (!json_is_string(field)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid publicKey base58.");
        PublicKey_Destroy(pk);
        return -1;
    }

    //public key must be have 'publicKeyBase58'
    strcpy(pk->publicKeyBase58, json_string_value(field));

    //'controller' may be default
    field = json_object_get(json, CONTROLLER);
    if (field) {
        if (!json_is_string(field) || DID_Parse(&pk->controller, json_string_value(field)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid publicKey's controller.");
            PublicKey_Destroy(pk);
            return -1;
        }
    }

    if (!field) { // the controller is self did.
        DID_Copy(&pk->controller, did);
        //strcpy(pk->controller.idstring, did->idstring);
        *publickey = pk;
        return 0;
    }

    *publickey = pk;
    return 0;
}

static int Parse_Controllers(DIDDocument *document, json_t *json, bool resolve)
{
    DIDDocument *controllerdoc;
    json_t *field;
    DID controller;
    int i, size = 1, status;

    assert(document);
    assert(json);

    if (json_is_array(json))
        size = json_array_size(json);

    document->controllers.docs = (DIDDocument**)calloc(size, sizeof(DIDDocument*));
    if (!document->controllers.docs) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for controllers failed.");
        return -1;
    }

    for (i = 0; i < size; i++) {
        if (json_is_string(json))
            field = json;
        else
            field = json_array_get(json, i);

        if (!field || !json_is_string(field)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Wrong controller.");
            return -1;
        }
        if (DID_Parse(&controller, json_string_value(field)) < 0) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Create controller failed.");
            return -1;
        }

        if (resolve) {
            controllerdoc = DID_Resolve(&controller, &status, false);
            if (!controllerdoc) {
                DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Controller %s %s", DIDSTR(&controller), DIDSTATUS_MSG(status));
                return -1;
            }
        } else {
            controllerdoc = (DIDDocument*)calloc(1, sizeof(DIDDocument));
            if (!controllerdoc) {
                DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for Controller document %s failed.", DIDSTR(&controller));
                return -1;
            }

            DID_Copy(&controllerdoc->did, &controller);
        }

        document->controllers.docs[document->controllers.size++] = controllerdoc;
    }

    return 0;
}

static int Parse_PublicKeys(DIDDocument *document, DID *did, json_t *json)
{
    int pk_size, i, size = 0;

    assert(document);
    assert(did);
    assert(json);

    pk_size = json_array_size(json);
    if (!pk_size) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "PublicKey array is empty.");
        return -1;
    }

    //parse public key(required)
    PublicKey **pks = (PublicKey**)calloc(pk_size, sizeof(PublicKey*));
    if (!pks) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for publicKeys failed.");
        return -1;
    }

    for (i = 0; i < pk_size; i++) {
        json_t *pk_item, *id_field, *base_field;
        PublicKey *pk;

        pk_item = json_array_get(json, i);
        if (!pk_item)
            continue;

        //check public key's format
        id_field = json_object_get(pk_item, ID);
        base_field = json_object_get(pk_item, PUBLICKEY_BASE58);
        if (!id_field || !base_field)              //(required and can't default)
            continue;

        if (Parse_PublicKey(did, pk_item, &pk) == -1)
            continue;

        pks[size++] = pk;
    }

    if (!size) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No invalid publicKey.");
        free(pks);
        return -1;
    }

    document->publickeys.pks = pks;
    document->publickeys.size = size;

    return 0;
}

static int Parse_Auth_PublicKeys(DIDDocument *document, json_t *json, KeyType type)
{
    int pk_size, i, size = 0, total_size = 0;
    PublicKey *pk;

    assert(document);
    assert(json);

    pk_size = json_array_size(json);
    if (!pk_size) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Auth key array is empty.");
        return -1;
    }

    for (i = 0; i < pk_size; i++) {
        DIDURL id;
        json_t *pk_item, *id_field;

        pk_item = json_array_get(json, i);
        if (!pk_item)
            continue;

        if (!json_is_object(pk_item) && !json_is_string(pk_item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Auth key array is invalid.");
            return -1;
        }

        if (json_is_string(pk_item)) {
            if (DIDURL_Parse(&id, json_string_value(pk_item), &document->did) < 0)
                continue;

            pk = DIDDocument_GetPublicKey(document, &id);
            if (!pk) {
                DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Auth key is not in pulicKeys.");
                return -1;
            }

            if (type == KeyType_Authentication)
                pk->authenticationKey = true;
            if (type == KeyType_Authorization)
                pk->authorizationKey = true;
        } else {
            if (Parse_PublicKey(&(document->did), pk_item, &pk) < 0)
                return -1;

            if (type == KeyType_Authentication)
                pk->authenticationKey = true;
            if (type == KeyType_Authorization)
                pk->authorizationKey = true;

            if (add_to_publickeys(document, pk) < 0) {
                free(pk);
                return -1;
            }
        }
    }

    return 0;
}

static int Parse_Services(DIDDocument *document, json_t *json)
{
    size_t service_size;
    size_t autal_size = 0;
    size_t i;

    assert(document);
    assert(json);

    service_size = json_array_size(json);
    if (!service_size) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Service array is empty.");
        return -1;
    }

    Service **services = (Service**)calloc(service_size, sizeof(Service*));
    if (!services) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for services failed.");
        return -1;
    }

    for (i = 0; i < service_size; i++) {
        Service *service;
        json_t *item, *field;

        item = json_array_get(json, i);
        if (!item)
            continue;

        service = (Service *)calloc(1, sizeof(Service));
        if (!service)
            continue;

        field = json_object_get(item, ID);
        if (!field || !json_is_string(field)) {
            Service_Destroy(service);
            continue;
        }

        if (DIDURL_Parse(&service->id, json_string_value(field), &document->did) < 0) {
            Service_Destroy(service);
            continue;
        }

        //if (!*service->id.did.idstring)
        if (DID_IsEmpty(&service->id.did))
            DID_Copy(&service->id.did, &document->did);
            //strcpy(service->id.did.idstring, document->did.idstring);

        field = json_object_get(item, TYPE);
        if (!field || !json_is_string(field)) {
            Service_Destroy(service);
            continue;
        }
        strcpy(service->type, json_string_value(field));

        field = json_object_get(item, SERVICE_ENDPOINT);
        if (!field || !json_is_string(field)) {
            Service_Destroy(service);
            continue;
        }
        strcpy(service->endpoint, json_string_value(field));

        //for property
        json_object_del(item, ID);
        json_object_del(item, TYPE);
        json_object_del(item, SERVICE_ENDPOINT);
        if (json_object_size(item) > 0)
            service->properties = json_deep_copy(item);

        services[autal_size++] = service;
    }

    if (!autal_size) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No invalid service.");
        free(services);
        return -1;
    }

    document->services.services = services;
    document->services.size = autal_size;

    return 0;
}

static int Parse_Proofs(DIDDocument *document, json_t *json)
{
    json_t *item, *field;
    size_t size = 1, i;
    DocumentProof *proof;

    assert(document);
    assert(json);

    if (json_is_array(json))
        size = json_array_size(json);

    document->proofs.proofs = (DocumentProof*)calloc(size, sizeof(DocumentProof));
    if (!document->proofs.proofs) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for proofs failed.");
        return -1;
    }

    document->proofs.size = 0;
    for (i = 0; i < size; i++) {
        if (json_is_object(json))
            item = json;
        else
            item = json_array_get(json, i);

        if (!json_is_object(item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid proof format.");
            return -1;
        }

        proof = &document->proofs.proofs[document->proofs.size];

        field = json_object_get(item, TYPE);
        if (field) {
            if ((json_is_string(field) && strlen(json_string_value(field)) + 1 > MAX_TYPE_LEN) ||
                    !json_is_string(field)) {
                DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid proof type.");
                return -1;
            }
            strcpy(proof->type, json_string_value(field));
        }
        else
            strcpy(proof->type, ProofType);

        field = json_object_get(item, CREATED);
        if (!field) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing create document time.");
            return -1;
        }
        if (!json_is_string(field) ||
                parse_time(&proof->created, json_string_value(field)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid create document time.");
            return -1;
        }

        field = json_object_get(item, CREATOR);
        if (field) {
            if (!json_is_string(field) ||
                    DIDURL_Parse(&proof->creater, json_string_value(field), &document->did) == -1) {
                DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid document creater.");
                return -1;
            }
        }

        if (!field && (!DIDDocument_GetDefaultPublicKey(document) ||
                !DIDURL_Copy(&proof->creater, DIDDocument_GetDefaultPublicKey(document)))) {
            DIDError_Set(DIDERR_MALFORMED_DIDURL, "Set document creater failed.");
            return -1;
        }

        field = json_object_get(item, SIGNATURE_VALUE);
        if (!field) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing signature.");
            return -1;
        }
        if (!json_is_string(field)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid signature.");
            return -1;
        }
        if (strlen(json_string_value(field)) + 1 > MAX_SIGNATURE_LEN) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Document signature is too long.");
            return -1;
        }
        strcpy(proof->signatureValue, json_string_value(field));
        document->proofs.size++;
    }

    return 0;
}

static int remove_publickey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey **pks;
    PublicKey *pk;
    DIDURL *key;
    size_t size, i;

    assert(document);
    assert(keyid);

    size = document->publickeys.size;
    pks = document->publickeys.pks;

    if (!DIDDocument_IsCustomizedDID(document)) {
        key = DIDDocument_GetDefaultPublicKey(document);
        if (key && DIDURL_Equals(key, keyid)) {
            DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't remove default key!!!!");
            return -1;
        }
    }

    for (i = 0; i < size; i++ ) {
        pk = pks[i];
        if (!DIDURL_Equals(&pk->id, keyid))
            continue;

        if (i != size - 1)
            memmove(pks + i, pks + i + 1, sizeof(PublicKey*) * (size - i - 1));

        pks[--document->publickeys.size] = NULL;
        PublicKey_Destroy(pk);
        if (document->publickeys.size == 0) {
            free((void*)pks);
            document->publickeys.pks = NULL;
        }

        if (DIDMetadata_AttachedStore(&document->metadata))
            DIDStore_DeletePrivateKey(document->metadata.base.store, keyid);

        return 0;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "No this publicKey.");
    return -1;
}

static int Parse_Credentials_InDoc(DIDDocument *document, json_t *json)
{
    size_t size = 0;
    Credential **credentials;

    assert(document);
    assert(json);

    size = json_array_size(json);
    if (size <= 0) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Credential array is empty.");
        return -1;
    }

    credentials = (Credential**)calloc(size, sizeof(Credential*));
    if (!credentials) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credentials failed.");
        return -1;
    }

    size = Parse_Credentials(&document->did, credentials, size, json);
    if (size <= 0) {
        free(credentials);
        return -1;
    }

    document->credentials.credentials = credentials;
    document->credentials.size = size;

    return 0;
}

int DIDDocument_SetStore(DIDDocument *document, DIDStore *store)
{
    assert(document);
    assert(store);

    document->metadata.base.store = store;
    document->did.metadata.base.store = store;
    return 0;
}

size_t DIDDocument_GetSelfAuthenticationKeyCount(DIDDocument *document)
{
    size_t size = 0, i;

    assert(document);

    for (i = 0; i < document->publickeys.size; i++) {
        if(document->publickeys.pks[i]->authenticationKey)
            size++;
    }

    return size;
}

static size_t get_self_authorization_count(DIDDocument *document)
{
    size_t size = 0, i;

    assert(document);

    for (i = 0; i < document->publickeys.size; i++) {
        if(document->publickeys.pks[i]->authorizationKey)
            size++;
    }

    return size;
}

int DIDDocument_IsCustomizedDID(DIDDocument *document)
{
    DIDURL *signkey;
    int rc = 1;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to check be customized did or not.", -1);

    signkey = DIDDocument_GetDefaultPublicKey(document);
    if (signkey && DID_Equals(&signkey->did, &document->did))
        rc = 0;

    return rc;

    DIDERROR_FINALIZE();
}

bool controllers_check(DIDDocument *document)
{
    DIDDocument *doc;
    int i;

    assert(document);
    assert((document->controllers.size > 0 && document->controllers.docs) ||
            (document->controllers.size == 0 && !document->controllers.docs));

    if (!DIDDocument_IsCustomizedDID(document) && document->controllers.size > 0) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, " * %s : is not customized did, so it doesn't have controller.", DIDSTR(&document->did));
        return false;
    }

    if (DIDDocument_IsCustomizedDID(document)) {
        if (document->controllers.size == 0) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, " * %s : no controller.", DIDSTR(&document->did));
            return false;
        }

        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            if (DIDDocument_IsCustomizedDID(doc)) {
                DIDError_Set(DIDERR_MALFORMED_DOCUMENT, " * %s: is a controller that must not be customized DID.", DIDSTR(&doc->did));
                return false;
            }
        }
    }

    return true;
}

static char *format_multisig(char *buffer, size_t size, int m, int n)
{
    size_t len;

    assert(buffer);

    if (n <= 1) {
        *buffer = 0;
    } else {
        len = snprintf(buffer, size, "%d:%d", m, n);
        if (len < 0 || len > size)
            return NULL;
    }

    return buffer;
}

static void parse_multisig(const char *buffer, int *m, int *n)
{
    assert(m && n);

    if (sscanf(buffer, "%d:%d", m, n) < 2) {
        *m = 0;
        *n = 0;
    }
}

////////////////////////////////Document/////////////////////////////////////
DIDDocument *DIDDocument_FromJson_Internal(json_t *root, bool resolve)
{
    DIDDocument *doc;
    json_t *item;
    int m, n;
    uint8_t binkey[PUBLICKEY_BYTES];
    char idstring[ELA_MAX_DID_LEN];
    bool has = false;

    assert(root);

    doc = (DIDDocument*)calloc(1, sizeof(DIDDocument));
    if (!doc) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for document failed.");
        return NULL;
    }

    item = json_object_get(root, ID);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing document subject.");
        goto errorExit;
    }
    if (!json_is_string(item) ||
            DID_Parse(&doc->did, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid document subject.");
        goto errorExit;
    }

    //parse constroller
    item = json_object_get(root, CONTROLLER);
    if (item) {
        if (!json_is_string(item) && !json_is_array(item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid controller.");
            goto errorExit;
        }
        if (Parse_Controllers(doc, item, resolve) == -1)
            goto errorExit;
    }

    //parser multisig
    item = json_object_get(root, MULTI_SIGNATURE);
    if (!item && doc->controllers.size > 1) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing multisig.");
        goto errorExit;
    }
    if (item) {
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid multisig, multisig must be string.");
            goto errorExit;
        }
        if (doc->controllers.size <= 1) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid multisig.");
            goto errorExit;
        }

        parse_multisig(json_string_value(item), &m, &n);
        if (n != doc->controllers.size || m > n) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Multisig doesn't match the count of controllers.");
            goto errorExit;
        }
        doc->multisig = m;
    }

    //parse publickey
    item = json_object_get(root, PUBLICKEY);
    if (item && !json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid publicKey.");
        goto errorExit;
    }
    if (item && Parse_PublicKeys(doc, &doc->did, item) < 0)
        goto errorExit;

    //parse authentication
    item = json_object_get(root, AUTHENTICATION);
    if (item && !json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid authentication key.");
        goto errorExit;
    }
    if (item && Parse_Auth_PublicKeys(doc, item, KeyType_Authentication) < 0)
        goto errorExit;

    //check pk size
    if (!doc->controllers.size) {
        if (!doc->publickeys.size || !doc->publickeys.pks) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No publicKey.");
            goto errorExit;
        }

        //check: pk array has default key.
        for (int i = 0; i < doc->publickeys.size; i++) {
            PublicKey *pk = doc->publickeys.pks[i];
            assert(pk);

            b58_decode(binkey, sizeof(binkey), pk->publicKeyBase58);
            HDKey_PublicKey2Address(binkey, idstring, sizeof(idstring));

            if (!strcmp(idstring, pk->id.did.idstring)) {
                pk->authenticationKey = true;
                doc->defaultkey = &pk->id;
                break;
            }
        }
        if (!doc->defaultkey) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No default key.");
            goto errorExit;
        }
    }

    //parse authorization
    item = json_object_get(root, AUTHORIZATION);
    if (item) {
        if (!json_is_array(item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid authorization key.");
            goto errorExit;
        }
        if (Parse_Auth_PublicKeys(doc, item, KeyType_Authorization) < 0)
            goto errorExit;
    }

    //parse expires
    item = json_object_get(root, EXPIRES);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing expires time.");
        goto errorExit;
    }
    if (!json_is_string(item) ||
           parse_time(&doc->expires, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid expires time.");
        goto errorExit;
    }

    //parse credential
    item = json_object_get(root, VERIFIABLE_CREDENTIAL);
    if (item) {
        if (!json_is_array(item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid credentials.");
            goto errorExit;
        }
        if (Parse_Credentials_InDoc(doc, item) < 0)
            goto errorExit;
    }

    //parse services
    item = json_object_get(root, SERVICE);
    if (item) {
        if (!json_is_array(item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid services.");
            goto errorExit;
        }
        if (Parse_Services(doc, item) < 0)
            goto errorExit;
    }

    item = json_object_get(root, PROOF);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing document proof.");
        goto errorExit;
    }
    if (!json_is_object(item) && !json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid document proof.");
        goto errorExit;
    }
    if (Parse_Proofs(doc, item) == -1)
        goto errorExit;

    //check the document format
    if (resolve && !controllers_check(doc))
        goto errorExit;

    return doc;

errorExit:
    DIDDocument_Destroy(doc);
    return NULL;
}

DIDDocument *DIDDocument_FromJson(const char *json)
{
    DIDDocument *doc;
    json_t *root;
    json_error_t error;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!json || !*json, "Invalid document json.", NULL);

    root = json_loads(json, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Deserialize document failed, error: %s.", error.text);
        return NULL;
    }

    doc = DIDDocument_FromJson_Internal(root, true);
    json_decref(root);
    return doc;

    DIDERROR_FINALIZE();
}

int DIDDocument_ToJson_Internal(JsonGenerator *gen, DIDDocument *doc,
        bool compact, bool forsign)
{
    char id[ELA_MAX_DIDURL_LEN], _timestring[DOC_BUFFER_LEN];
    char multisig[32] = {0};

    assert(gen);
    assert(gen->buffer);
    assert(doc);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, ID,
            DID_ToString(&doc->did, id, sizeof(id))));
    if (doc->controllers.size > 0) {
        CHECK(DIDJG_WriteFieldName(gen, CONTROLLER));
        CHECK(ControllerArray_ToJson(gen, doc->controllers.docs, doc->controllers.size));
    }
    if (doc->controllers.size > 1)
        CHECK(DIDJG_WriteStringField(gen, MULTI_SIGNATURE,
                format_multisig(multisig, sizeof(multisig), doc->multisig, doc->controllers.size)));

    if (doc->publickeys.size > 0) {
        CHECK(DIDJG_WriteFieldName(gen, PUBLICKEY));
        CHECK(PublicKeyArray_ToJson(gen, doc->publickeys.pks, doc->publickeys.size,
                compact, KeyType_PublicKey));

        if (DIDDocument_GetSelfAuthenticationKeyCount(doc) > 0) {
            CHECK(DIDJG_WriteFieldName(gen, AUTHENTICATION));
            CHECK(PublicKeyArray_ToJson(gen, doc->publickeys.pks, doc->publickeys.size,
                    compact, KeyType_Authentication));
        }

        if (get_self_authorization_count(doc) > 0) {
            CHECK(DIDJG_WriteFieldName(gen, AUTHORIZATION));
            CHECK(PublicKeyArray_ToJson(gen, doc->publickeys.pks,
                    doc->publickeys.size, compact, KeyType_Authorization));
        }
    }

    if (doc->credentials.size > 0) {
        CHECK(DIDJG_WriteFieldName(gen, VERIFIABLE_CREDENTIAL));
        CHECK(CredentialArray_ToJson(gen, doc->credentials.credentials,
                doc->credentials.size, &doc->did, compact));
    }

    if (doc->services.size > 0) {
        CHECK(DIDJG_WriteFieldName(gen, SERVICE));
        CHECK(ServiceArray_ToJson(gen, doc->services.services,
                doc->services.size, compact));
    }

    CHECK(DIDJG_WriteStringField(gen, EXPIRES,
            get_time_string(_timestring, sizeof(_timestring), &doc->expires)));
    if (!forsign) {
        CHECK(DIDJG_WriteFieldName(gen, PROOF));
        CHECK(ProofArray_ToJson(gen, doc, compact));
    }
    CHECK(DIDJG_WriteEndObject(gen));

    return 0;
}

static const char *diddocument_tojson_forsign(DIDDocument *document, bool compact, bool forsign)
{
    JsonGenerator g, *gen;

    assert(document);

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator for document initialize failed.");
        return NULL;
    }

    if (DIDDocument_ToJson_Internal(gen, document, compact, forsign) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize document to json failed.");
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

const char *DIDDocument_ToJson(DIDDocument *document, bool normalized)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to serialize json", NULL);
    return diddocument_tojson_forsign(document, !normalized, false);

    DIDERROR_FINALIZE();
}

const char *DIDDocument_ToString(DIDDocument *document, bool normalized)
{
    const char *data;
    json_t *json;
    json_error_t error;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to serialize string", NULL);

    data = diddocument_tojson_forsign(document, !normalized, false);
    if (!data)
        return NULL;

    json = json_loads(data, JSON_INDENT(4), &error);
    free((void*)data);
    if (!json) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Deserialize document failed, error: %s.", error.text);
        return NULL;
    }

    return json_dumps(json, JSON_INDENT(4));

    DIDERROR_FINALIZE();
}

void DIDDocument_Destroy(DIDDocument *document)
{
    size_t i;

    DIDERROR_INITIALIZE();

    if (!document)
        return;

    for (i = 0; i < document->controllers.size; i++)
        DIDDocument_Destroy(document->controllers.docs[i]);

    for (i = 0; i < document->publickeys.size; i++)
        PublicKey_Destroy(document->publickeys.pks[i]);

    for (i = 0; i < document->services.size; i++)
        Service_Destroy(document->services.services[i]);

    for (i = 0; i < document->credentials.size; i++)
        Credential_Destroy(document->credentials.credentials[i]);

    if (document->controllers.docs)
        free((void*)document->controllers.docs);

    if (document->publickeys.pks)
        free((void*)document->publickeys.pks);

    if (document->services.services)
        free((void*)document->services.services);

    if (document->credentials.credentials)
        free((void*)document->credentials.credentials);

    if (document->proofs.proofs)
        free((void*)document->proofs.proofs);

    DIDMetadata_Free(&document->metadata);
    free(document);

    DIDERROR_FINALIZE();
}

DIDMetadata *DIDDocument_GetMetadata(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to get metadata.", NULL);
    return &document->metadata;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_GetProofCount(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to get count of proof.", -1);
    return document->proofs.size;

    DIDERROR_FINALIZE();
}

const char *DIDDocument_GetProofType(DIDDocument *document, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to get proof type.", NULL);
    CHECK_ARG(index >= document->proofs.size, "Index is larger than count of proofs.", NULL);
    return document->proofs.proofs[index].type;

    DIDERROR_FINALIZE();
}

DIDURL *DIDDocument_GetProofCreater(DIDDocument *document, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to get creater of proof.", NULL);
    CHECK_ARG(index >= document->proofs.size, "Index is larger than count of proofs.", NULL);
    return &document->proofs.proofs[index].creater;

    DIDERROR_FINALIZE();
}

time_t DIDDocument_GetProofCreatedTime(DIDDocument *document, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to get create time of proof.", 0);
    CHECK_ARG(index >= document->proofs.size, "Index is larger than count of proofs.", 0);
    return document->proofs.proofs[index].created;

    DIDERROR_FINALIZE();
}

const char *DIDDocument_GetProofSignature(DIDDocument *document, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to get signature.", NULL);
    CHECK_ARG(index >= document->proofs.size, "Index is larger than count of proofs.", NULL);
    return document->proofs.proofs[index].signatureValue;

    DIDERROR_FINALIZE();
}

int DIDDocument_IsDeactivated(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to check be deactivated or not.", -1);
    return DIDMetadata_GetDeactivated(&document->metadata);

    DIDERROR_FINALIZE();
}

static int DIDDocument_IsGenuine_Internal(DIDDocument *document, bool qualified)
{
    DIDDocument *proof_doc;
    DocumentProof *proof;
    DID **checksigners;
    const char *data;
    int genuine = 0, i, rc;
    size_t size;

    assert(document);

    if (qualified && !DIDDocument_IsQualified(document)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, " * %s : signers are less than multisig number.", DIDSTR(&document->did));
        return 0;
    }

    if (document->controllers.size > 0) {
        for(i = 0; i < document->controllers.size; i++) {
            rc = DIDDocument_IsGenuine(document->controllers.docs[i]);
            if (rc != 1) {
                DIDError_Set(DIDERR_NOT_GENUINE, " * %s : controller %s is not geninue.",
                        DIDSTR(&document->did), DIDSTR(&document->controllers.docs[i]->did));
                return rc;
            }
        }
    }

    data = diddocument_tojson_forsign(document, false, true);
    if (!data)
        return -1;

    size = document->proofs.size;
    checksigners = (DID**)alloca(size * sizeof(DID*));
    if (!checksigners) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, " * %s : malloc buffer for signers failed.", DIDSTR(&document->did));
        genuine = -1;
        goto errorExit;
    }

    for (i = 0; i < size; i++) {
        proof = &document->proofs.proofs[i];
        assert(proof);
        if (document->controllers.size == 0) {
            proof_doc = document;
        } else {
            proof_doc = DIDDocument_GetControllerDocument(document, &proof->creater.did);
            if (!proof_doc) {
                DIDError_Set(DIDERR_MALFORMED_DOCUMENT, " * %s : the signer %s isn't the controller.",
                        DIDSTR(&document->did), DIDSTR(&proof->creater.did));
                goto errorExit;
            }
        }

        if (Contains_DID(checksigners, i, &proof->creater.did)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, " * %s : there is the same controller signed document two times.",
                    DIDSTR(&document->did));
            goto errorExit;
        }

        if (strcmp(proof->type, ProofType)) {
            DIDError_Set(DIDERR_UNSUPPORTED, " * %s : unsupported other publicKey type.",
                    DIDSTR(&document->did));
            goto errorExit;
        }

        if (!DIDURL_Equals(DIDDocument_GetDefaultPublicKey(proof_doc), &proof->creater)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, " * %s : signkey %s is not controller's default key.",
                    DIDSTR(&document->did), DIDURLSTR(&proof->creater));
            goto errorExit;
        }

        if (DIDDocument_Verify(proof_doc, &proof->creater, proof->signatureValue, 1,
                data, strlen(data)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, " * %s : verify document signature failed.",
                    DIDSTR(&document->did));
            goto errorExit;
        }

        checksigners[i] = &proof->creater.did;
    }

    genuine = 1;

errorExit:
    free((void*)data);
    return genuine;
}

int DIDDocument_IsGenuine(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to check geninue.", -1);
    int rc = DIDDocument_IsGenuine_Internal(document, true);
    if (rc != 1)
        DIDError_Set(DIDERR_NOT_GENUINE, " * %s : is not geninue.", DIDSTR(&document->did));

    return rc;

    DIDERROR_FINALIZE();
}

int DIDDocument_IsExpired(DIDDocument *document)
{
    time_t curtime;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to check expired status.", -1);

    curtime = time(NULL);
    if (curtime > document->expires)
        return 1;

    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocument_IsQualified(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to check be qualified or not.", -1);
    return document->proofs.size == (document->controllers.size > 1 ? document->multisig : 1) ? 1 : 0;

    DIDERROR_FINALIZE();
}

int DIDDocument_IsValid_Internal(DIDDocument *document, bool isqualified)
{
    int rc;
    assert(document);

    if (!controllers_check(document))
        return 0;

    rc = DIDDocument_IsExpired(document);
    if (rc != 0) {
        if (rc == 1)
            DIDError_Set(DIDERR_EXPIRED, " * %s : is expired.", DIDSTR(&document->did));
        return rc;
    }

    rc = DIDDocument_IsDeactivated(document);
    if (rc != 0) {
        if (rc == 1)
            DIDError_Set(DIDERR_DID_DEACTIVATED, "* %s : is deactivated.", DIDSTR(&document->did));
        return rc;
    }

    rc = DIDDocument_IsGenuine_Internal(document, isqualified);
    if (rc != 1)
        DIDError_Set(DIDERR_NOT_GENUINE, "* %s : is not geninue.", DIDSTR(&document->did));

    return rc;
}

int DIDDocument_IsValid(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to check valid.",-1);
    int rc = DIDDocument_IsValid_Internal(document, true);
    if (rc != 1)
        DIDError_Set(DIDERR_NOT_VALID, " * %s : is not valid.", DIDSTR(&document->did));

    return rc;

    DIDERROR_FINALIZE();
}

static int publickeys_copy(DIDDocument *doc, PublicKey **pks, size_t size)
{
    PublicKey **pk_array = NULL;
    size_t i, j;

    assert(doc);
    assert(pks);
    assert(size >= 0);

    if (size == 0)
        return 0;

    pk_array = (PublicKey**)calloc(size, sizeof(PublicKey*));
    if (!pk_array)
        return -1;

    for (i = 0; i < size; i++) {
        pk_array[i] = (PublicKey*)calloc(1, sizeof(PublicKey));
        if (!pk_array[i])
            goto errorExit;

        memcpy(pk_array[i], pks[i], sizeof(PublicKey));
    }

    doc->publickeys.pks = pk_array;
    doc->publickeys.size = i;

    return 0;

errorExit:
    for (j = 0; j < i; j++)
        if (pk_array[j])
            free(pk_array[j]);

    if (pk_array)
        free(pk_array);

    return -1;
}

static int credentials_copy(DIDDocument *doc, Credential **creds, size_t size)
{
    size_t i;

    assert(doc);
    assert(creds);
    assert(size >= 0);

    if (size == 0)
        return 0;

    doc->credentials.credentials = (Credential**)calloc(size, sizeof(Credential*));
    if (!doc->credentials.credentials)
        return -1;

    for (i = 0; i < size; i++) {
        doc->credentials.credentials[i] = (Credential*)calloc(1, sizeof(Credential));
        if (!doc->credentials.credentials[i])
            return -1;

        if (Credential_Copy(doc->credentials.credentials[i], creds[i]) == -1) {
            Credential_Destroy(doc->credentials.credentials[i]);
            doc->credentials.credentials[i] = NULL;
            return -1;
        }

        doc->credentials.size = i + 1;
    }

    return 0;
}

static int services_copy(DIDDocument *doc, Service **services, size_t size)
{
    size_t i;

    assert(doc);
    assert(services);
    assert(size >= 0);

    if (size == 0)
        return 0;

    doc->services.services = (Service**)calloc(size, sizeof(Service*));
    if (!doc->services.services)
        return -1;

    for (i = 0; i < size; i++) {
        Service *service = (Service*)calloc(1, sizeof(Service));
        if (!service)
            return -1;

        DIDURL_Copy(&service->id, &services[i]->id);
        strcpy(service->type, services[i]->type);
        strcpy(service->endpoint, services[i]->endpoint);
        service->properties = json_deep_copy(services[i]->properties);

        doc->services.services[i] = service;
        doc->services.size = i + 1;
    }
    return 0;
}

static int proofs_copy(DIDDocument *doc, DocumentProof *proofs, size_t size)
{
    assert(doc);
    assert(proofs);
    assert(size >= 0);

    if (size == 0)
        return 0;

    doc->proofs.proofs = (DocumentProof*)calloc(size, sizeof(DocumentProof));
    if (!doc->proofs.proofs)
        return -1;

    memcpy(doc->proofs.proofs, proofs, size * sizeof(DocumentProof));
    doc->proofs.size = size;
    return 0;
}

static int documents_copy(DIDDocument *document, DIDDocument **docs, size_t size)
{
    DIDDocument **documents = NULL;
    int i = 0, j = 0;

    assert(document);
    assert(docs);
    assert(size >= 0);

    if (size == 0)
        return 0;

    documents = (DIDDocument**)calloc(size, sizeof(DIDDocument*));
    if (!documents)
        goto errorExit;

    for (i = 0; i < size; i++) {
        documents[i] = (DIDDocument*)calloc(1, sizeof(DIDDocument));
        if (!documents[i])
            goto errorExit;

        if (DIDDocument_Copy(documents[i], docs[i]) < 0)
            goto errorExit;
    }

    document->controllers.docs = documents;
    document->controllers.size = i;
    return 0;

errorExit:
    for (j = 0; j < i; j++)
        if (documents[j])
            free(documents[j]);

    if (documents)
        free(documents);

    DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for documents to copy failed.");
    return -1;
}

int DIDDocument_Copy(DIDDocument *destdoc, DIDDocument *srcdoc)
{
    assert(destdoc);
    assert(srcdoc);

    DID_Copy(&destdoc->did, &srcdoc->did);

    if (srcdoc->controllers.size > 0 && srcdoc->controllers.docs &&
            documents_copy(destdoc, srcdoc->controllers.docs, srcdoc->controllers.size) == -1)
        return -1;

    if (srcdoc->publickeys.size != 0 &&
            publickeys_copy(destdoc, srcdoc->publickeys.pks, srcdoc->publickeys.size) == -1)
        return -1;

    if (srcdoc->credentials.size != 0  && credentials_copy(destdoc,
            srcdoc->credentials.credentials, srcdoc->credentials.size) == -1)
        return -1;

    if (srcdoc->services.size != 0 && services_copy(destdoc,
            srcdoc->services.services, srcdoc->services.size) == -1)
        return -1;

    if (srcdoc->proofs.size != 0 && proofs_copy(destdoc,
            srcdoc->proofs.proofs, srcdoc->proofs.size) == -1)
        return -1;

    destdoc->multisig = srcdoc->multisig;
    destdoc->expires = srcdoc->expires;
    DIDMetadata_Copy(&destdoc->metadata, &srcdoc->metadata);
    memcpy(&destdoc->did.metadata, &destdoc->metadata, sizeof(DIDMetadata));
    return 0;
}

DIDDocumentBuilder* DIDDocument_Edit(DIDDocument *document, DIDDocument *controllerdoc)
{
    DIDDocumentBuilder *builder;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to edit.", NULL);

    if (DIDDocument_IsCustomizedDID(document) && document->controllers.size > 1 && !controllerdoc) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Specify the controller to edit multi-controller customized DID.");
        return NULL;
    }

    if (!DIDDocument_IsCustomizedDID(document) && controllerdoc) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Don't specify the controller to edit normal DID.");
        return NULL;
    }

    builder = (DIDDocumentBuilder*)calloc(1, sizeof(DIDDocumentBuilder));
    if (!builder) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for document builder failed.");
        return NULL;
    }

    builder->document = (DIDDocument*)calloc(1, sizeof(DIDDocument));
    if (!builder->document) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for document failed.");
        free(builder);
        return NULL;
    }

    if (DIDDocument_Copy(builder->document, document) == -1) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Document copy failed.");
        DIDDocumentBuilder_Destroy(builder);
        return NULL;
    }

    if (controllerdoc) {
        builder->controllerdoc = DIDDocument_GetControllerDocument(builder->document, &controllerdoc->did);
        if (!builder->controllerdoc) {
            DIDError_Set(DIDERR_INVALID_ARGS, "Document has no this controller.");
            DIDDocumentBuilder_Destroy(builder);
            return NULL;
        }
        DIDMetadata_SetStore(&builder->controllerdoc->metadata, controllerdoc->metadata.base.store);
    }

    return builder;

    DIDERROR_FINALIZE();
}

void DIDDocumentBuilder_Destroy(DIDDocumentBuilder *builder)
{
    DIDERROR_INITIALIZE();

    if (!builder)
        return;

    if (builder->document)
        DIDDocument_Destroy(builder->document);

    free(builder);

    DIDERROR_FINALIZE();
}

DIDDocument *DIDDocument_GetControllerDocument(DIDDocument *document, DID *controller)
{
    DIDDocument *doc;
    size_t size;
    int i;

    assert(document);
    assert(controller);

    size = document->controllers.size;
    if (size == 0)
        return NULL;

    for(i = 0; i < size; i++) {
        doc = document->controllers.docs[i];
        assert(doc);
        if (DID_Equals(&doc->did, controller))
            return doc;
    }

    return NULL;
}

static int diddocument_addproof(DIDDocument *document, char *signature, DIDURL *signkey, time_t created)
{
    int i;
    size_t size;
    DocumentProof *dps, *p;

    assert(document);
    assert(signature);
    assert(signkey);

    size = document->proofs.size;
    for (i = 0; i < size; i++) {
        p = &document->proofs.proofs[i];
        if (DID_Equals(&p->creater.did, &signkey->did)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Signkey already exist.");
            return -1;
        }
    }

    dps = (DocumentProof*)realloc(document->proofs.proofs, (size + 1) * sizeof(DocumentProof));
    if (!dps) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for proofs failed.");
        return -1;
    }

    strcpy(dps[size].signatureValue, signature);
    strcpy(dps[size].type, ProofType);
    DIDURL_Copy(&dps[size].creater, signkey);
    dps[size].created = created;
    document->proofs.proofs = dps;
    document->proofs.size++;
    return 0;
}

DIDDocument *DIDDocumentBuilder_Seal(DIDDocumentBuilder *builder, const char *storepass)
{
    DIDDocument *doc, *controllerdoc, *signdoc = NULL;
    DIDURL *key;
    const char *data;
    char signature[SIGNATURE_BYTES * 2 + 16];
    Credential *cred;
    int rc, i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder, "No document builder argument.", NULL);
    CHECK_PASSWORD(storepass, NULL);

    doc = builder->document;
    controllerdoc = builder->controllerdoc;
    assert((doc->controllers.size > 0 && doc->controllers.docs) ||
            (doc->controllers.size == 0 && !doc->controllers.docs));

    //check controller document and multisig
    rc = DIDDocument_IsCustomizedDID(doc);
    if (rc == -1)
        return NULL;

    if (!rc) {
        if (controllerdoc) {
            DIDError_Set(DIDERR_ILLEGALUSAGE, "Don't specify the controller to seal normal DID.");
            return NULL;
        }
        signdoc = doc;
    } else {
        if (doc->controllers.size > 1 && doc->multisig == 0) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Please set multisig first for multi-controller DID.");
            return NULL;
        }
        if (!controllerdoc) {
            if (doc->controllers.size > 1) {
                DIDError_Set(DIDERR_NOT_EXISTS, "Please specify the controller to seal multi-controller document.");
                return NULL;
            } else {
                controllerdoc = doc->controllers.docs[0];
                DIDMetadata_SetStore(&controllerdoc->metadata, doc->metadata.base.store);
            }
        } else {
            if (!DIDDocument_GetControllerDocument(doc, &controllerdoc->did)) {
                DIDError_Set(DIDERR_INVALID_CONTROLLER, "The signer is not the controller for document.");
                return NULL;
            }
        }

        signdoc = controllerdoc;
    }

    //check proof
    if (DIDDocument_IsQualified(doc)) {
        DIDError_Set(DIDERR_ALREADY_SEALED, "The signers are enough.");
        return NULL;
    }

    for (i = 0; i < doc->proofs.size; i++) {
        if (DID_Equals(&controllerdoc->did, &doc->proofs.proofs[i].creater.did)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "The controller already signed the DID.");
            return NULL;
        }
    }

    //get signkey
    key = DIDDocument_GetDefaultPublicKey(signdoc);
    if (!key) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Signer has no default key.");
        return NULL;
    }

    //check credential
    for (i = 0; i < doc->credentials.size; i++) {
        cred = doc->credentials.credentials[i];
        if (Credential_IsValid_Internal(cred, doc) != 1) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Credential %s is invalid.", DIDURLSTR(&cred->id));
            return NULL;
        }
    }

    //check and get document data
    if (DIDDocument_IsValid_Internal(doc, false) != 1) {
        DIDError_Set(DIDERRCODE, "Document to seal is invalid, error: %s.", DIDERRMSG);
        return NULL;
    }

    data = diddocument_tojson_forsign(doc, false, true);
    if (!data) {
        DIDError_Set(DIDERRCODE, "Get doc data to signed failed.");
        return NULL;
    }

    rc = DIDDocument_Sign(signdoc, key, storepass, signature, 1, (unsigned char*)data, strlen(data));
    free((void*)data);
    if (rc) {
        DIDError_Set(DIDERRCODE, "Sign document failed, error: %s.", DIDERRMSG);
        return NULL;
    }

    if (diddocument_addproof(doc, signature, key, time(NULL)) < 0)
        return NULL;

    builder->document = NULL;
    return doc;

    DIDERROR_FINALIZE();
}

static PublicKey *create_publickey(DIDURL *id, DID *controller, const char *publickey,
        KeyType type)
{
    PublicKey *pk = NULL;

    assert(id);
    assert(controller);
    assert(publickey);

    pk = (PublicKey*)calloc(1, sizeof(PublicKey));
    if (!pk) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for publicKey failed.");
        return NULL;
    }

    DIDURL_Copy(&pk->id, id);
    DID_Copy(&pk->controller, controller);

    strcpy(pk->type, ProofType);
    assert(strlen(publickey) < sizeof(pk->publicKeyBase58));
    strcpy(pk->publicKeyBase58, publickey);

    if (type == KeyType_Authentication)
        pk->authenticationKey = true;
    if (type == KeyType_Authorization)
        pk->authorizationKey = true;

    return pk;
}

static void clean_proofs(DIDDocument *document)
{
    assert(document);

    if (document->proofs.proofs) {
        free((void*)document->proofs.proofs);
        document->proofs.proofs = NULL;
    }
    document->proofs.size = 0;
}

int DIDDocumentBuilder_AddPublicKey(DIDDocumentBuilder *builder, DIDURL *keyid,
        DID *controller, const char *key)
{
    DIDDocument *document;
    PublicKey *pk;
    uint8_t binkey[PUBLICKEY_BYTES];
    size_t i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!keyid, "No key id to add, please specify one..", -1);
    CHECK_ARG(!key || !*key, "Invalid key.", -1);
    CHECK_ARG(strlen(key) >= PUBLICKEY_BASE58_BYTES, "key is too long.", -1);

    //check base58 is valid
    if (b58_decode(binkey, sizeof(binkey), key) != PUBLICKEY_BYTES) {
        DIDError_Set(DIDERR_INVALID_KEY, "Decode public key failed.");
        return -1;
    }

    //check keyid is existed in pk array
    document = builder->document;
    assert(document);
    if (!DID_Equals(&document->did, &keyid->did)) {
        DIDError_Set(DIDERR_INVALID_KEY, "The key id does not owned by this DID.");
        return -1;
    }

    for (i = 0; i < document->publickeys.size; i++) {
        pk = document->publickeys.pks[i];
        assert(pk);
        if (DIDURL_Equals(&pk->id, keyid) ||
               !strcmp(pk->publicKeyBase58, key)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Publickey id %s already exist", DIDURLSTR(keyid));
            return -1;
        }
    }

    if (!controller)
        controller = &document->did;

    pk = create_publickey(keyid, controller, key, KeyType_PublicKey);
    if (!pk)
        return -1;

    if (add_to_publickeys(document, pk) == -1) {
        PublicKey_Destroy(pk);
        return -1;
    }

    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_RemovePublicKey(DIDDocumentBuilder *builder, DIDURL *keyid, bool force)
{
    DIDDocument* document;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!keyid, "No key id to remove, please specify one.", -1);

    document = builder->document;
    assert(document);
    if (!force && (DIDDocument_IsAuthenticationKey(document, keyid) ||
            DIDDocument_IsAuthorizationKey(document, keyid))) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't remove authenticated or authoritied key!!!!");
        return -1;
    }

    if (!DID_Equals(&document->did, DIDURL_GetDid(keyid))) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't remove other DID's key or controller's key!!!!");
        return -1;
    }

    if (remove_publickey(document, keyid) < 0)
        return -1;

    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

//authentication keys are all did's own key.
int DIDDocumentBuilder_AddAuthenticationKey(DIDDocumentBuilder *builder,
        DIDURL *keyid, const char *key)
{
    DIDDocument *document;
    PublicKey *pk;
    uint8_t binkey[PUBLICKEY_BYTES];
    DID *controller;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!keyid, "No key id to add, please specify one.", -1);
    CHECK_ARG(key && strlen(key) >= PUBLICKEY_BASE58_BYTES, "key is too long.", -1);

    if (key && b58_decode(binkey, sizeof(binkey), key) != PUBLICKEY_BYTES) {
        DIDError_Set(DIDERR_INVALID_KEY, "Decode authentication key failed.");
        return -1;
    }

    document = builder->document;
    assert(document);
    if (!DID_Equals(&document->did, &keyid->did)) {
        DIDError_Set(DIDERR_INVALID_KEY, "The key id does not owned by this DID.");
        return -1;
    }

    //check new authentication key is exist in publickeys
    pk = DIDDocument_GetPublicKey(document, keyid);
    if (pk) {
        if (key && strcmp(pk->publicKeyBase58, key)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Public key already exist.");
            return -1;
        }

        if (pk->authenticationKey || pk->authorizationKey) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Public key already authentication key or authorization key.");
            return -1;
        }

        pk->authenticationKey = true;
        return 0;
    }

    if (!key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Missing authentication key argument.");
        return -1;
    }

    controller = &document->did;
    pk = create_publickey(keyid, controller, key, KeyType_Authentication);
    if (!pk)
        return -1;

    if (add_to_publickeys(document, pk) < 0) {
        PublicKey_Destroy(pk);
        return -1;
    }

    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_RemoveAuthenticationKey(DIDDocumentBuilder *builder, DIDURL *keyid)
{
    DIDDocument *document;
    DIDURL *key;
    PublicKey *pk;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!keyid, "No key id to remove, please specify one.", -1);

    document = builder->document;
    assert(document);
    key = DIDDocument_GetDefaultPublicKey(document);
    if (key && DIDURL_Equals(key, keyid)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't remove default key!!!!");
        return -1;
    }

    if (!DID_Equals(&document->did, &keyid->did)) {
        DIDError_Set(DIDERR_INVALID_KEY, "Can't remove other DID's authentication key!!!!");
        return -1;
    }

    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No this authentication key.");
        return -1;
    }

    pk->authenticationKey = false;
    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocument_IsAuthenticationKey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey *pk;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument.", -1);
    CHECK_ARG(!keyid, "No key id, please specify one.", -1);

    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk)
        return 0;

    return pk->authenticationKey;

    DIDERROR_FINALIZE();
}

int DIDDocument_IsAuthorizationKey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey *pk;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument.", -1);
    CHECK_ARG(!keyid, "No key id, please specify one.", -1);

    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk)
        return 0;

    return pk->authorizationKey;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_AddAuthorizationKey(DIDDocumentBuilder *builder, DIDURL *keyid,
        DID *controller, const char *key)
{
    DIDDocument *document;
    PublicKey *pk = NULL;
    uint8_t binkey[PUBLICKEY_BYTES];

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!keyid, "No key id to add, please specify one.", -1);

    document = builder->document;
    assert(document);
    if (DIDDocument_IsCustomizedDID(document)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "The customized did doesn't support authorization key.");
        return -1;
    }

    if (!DID_Equals(&document->did, &keyid->did)) {
        DIDError_Set(DIDERR_INVALID_KEY, "The key id does not owned by this DID.");
        return -1;
    }

    if (controller && DID_Equals(controller, &document->did)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Own key can't used to be an authorization key.");
        return -1;
    }

    if (key && b58_decode(binkey, sizeof(binkey), key) != PUBLICKEY_BYTES) {
        DIDError_Set(DIDERR_INVALID_KEY, "Decode publicKey failed.");
        return -1;
    }

    //check new authentication key is exist in publickeys
    pk = DIDDocument_GetPublicKey(document, keyid);
    if (pk) {
        if (key && strcmp(pk->publicKeyBase58, key)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "PublicKey already exist.");
            return -1;
        }
        if (controller && !DID_Equals(controller, &pk->controller)) {
            DIDError_Set(DIDERR_UNSUPPORTED, "PublicKey can't be used for authorizating.");
            return -1;
        }

        if (pk->authenticationKey || pk->authorizationKey) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "PublicKey is already authentication key or authorization key.");
            return -1;
        }

        pk->authorizationKey = true;
        clean_proofs(document);
        return 0;
    }

    CHECK_ARG(!controller, "Missing controller argument.", -1);
    CHECK_ARG(!key, "Missing publicKey argument.", -1);

    pk = create_publickey(keyid, controller, key, KeyType_Authorization);
    if (!pk)
        return -1;

    if (add_to_publickeys(document, pk) == -1) {
        PublicKey_Destroy(pk);
        return -1;
    }

    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_AuthorizeDid(DIDDocumentBuilder *builder, DIDURL *keyid,
        DID *controller, DIDURL *authorkeyid)
{
    DIDDocument *doc, *document;
    PublicKey *pk;
    int rc, status;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!keyid, "No key id to add, please specify one.", -1);
    CHECK_ARG(!controller, "No controller argument.", -1);

    document = builder->document;
    assert(document);
    if (!DID_Equals(&document->did, &keyid->did)) {
        DIDError_Set(DIDERR_INVALID_KEY, "The key id does not owned by this DID.");
        return -1;
    }

    if (DID_Equals(controller, &document->did)) {
        DIDError_Set(DIDERR_UNSUPPORTED, "Key can't be used for authorizating.");
        return -1;
    }

    doc = DID_Resolve(controller, &status, false);
    if (!doc) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Controller %s %s", DIDSTR(controller), DIDSTATUS_MSG(status));
        return -1;
    }

    if (!authorkeyid) {
        authorkeyid = DIDDocument_GetDefaultPublicKey(doc);
        pk = DIDDocument_GetPublicKey(doc, authorkeyid);
    } else {
        pk = DIDDocument_GetAuthenticationKey(doc, authorkeyid);
    }

    if (!pk) {
        DIDDocument_Destroy(doc);
        return -1;
    }

    rc = DIDDocumentBuilder_AddAuthorizationKey(builder, keyid, controller,
            pk->publicKeyBase58);
    DIDDocument_Destroy(doc);
    return rc;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_RemoveAuthorizationKey(DIDDocumentBuilder *builder, DIDURL *keyid)
{
    DIDDocument *document;
    PublicKey *pk;
    DIDURL *key;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!keyid, "No key id to remove, please specify one.", -1);

    document = builder->document;
    assert(document);
    key = DIDDocument_GetDefaultPublicKey(document);
    if (key && DIDURL_Equals(key, keyid)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't remove default key!!!!");
        return -1;
    }

    if (!DID_Equals(&document->did, &keyid->did)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't remove other DID's authentication key!!!!");
        return -1;
    }

    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk)
        return -1;

    pk->authorizationKey = false;
    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

static int diddocument_addcredential(DIDDocument *document, Credential *credential)
{
    Credential **creds;

    assert(document);
    assert(credential);

    creds = (Credential**)realloc(document->credentials.credentials,
            (document->credentials.size + 1) * sizeof(Credential*));
    if (!creds) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credentials failed.");
        return -1;
    }

    creds[document->credentials.size++] = credential;
    document->credentials.credentials = creds;
    return 0;
}

static int diddocumentbuilder_addcontroller_internal(DIDDocument *customizedoc, DIDDocument *document)
{
    DIDDocument **docs;

    assert(customizedoc);
    assert(document);

    if (DIDDocument_IsCustomizedDID(document)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't add the customized did as a controller.");
        return -1;
    }

    docs = (DIDDocument**)realloc(customizedoc->controllers.docs,
            (customizedoc->controllers.size + 1) * sizeof(DIDDocument*));
    if (!docs) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for controllers failed.");
        return -1;
    }

    docs[customizedoc->controllers.size++] = document;
    customizedoc->controllers.docs = docs;

    return 0;
}

int DIDDocumentBuilder_AddController(DIDDocumentBuilder *builder, DID *controller)
{
    DIDDocument *controllerdoc, *document;
    int i, status;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!controller, "No controller argument.", -1);

    document = builder->document;
    //check the normal DID or customized DID
    if(DIDDocument_IsCustomizedDID(document) != 1) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't add controller into normal DID.");
        return -1;
    }

    if (DID_Equals(&document->did, controller)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Document does not controlled by itself.");
        return -1;
    }

    for (i = 0; i < document->controllers.size && document->controllers.docs; i++) {
        if (document->controllers.docs[i] && DID_Equals(&document->controllers.docs[i]->did, controller)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "The controller already exists in the document.");
            return -1;
        }
    }

    controllerdoc = DID_Resolve(controller, &status, false);
    if (!controllerdoc) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Controller %s %s", DIDSTR(controller), DIDSTATUS_MSG(status));
        return -1;
    }

    if (diddocumentbuilder_addcontroller_internal(document, controllerdoc) < 0)
        return -1;

    document->multisig = 0;
    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_RemoveController(DIDDocumentBuilder *builder, DID *controller)
{
    DIDDocument *document, *controller_doc;
    Credential *cred;
    size_t size;
    int i, j;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!controller, "No controller argument.", -1);

    document = builder->document;
    if (!DIDDocument_IsCustomizedDID(document)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Customized did isn't specified to be controller, please check it.");
        return -1;
    }

    assert(builder->controllerdoc);
    if (DID_Equals(controller, &builder->controllerdoc->did)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't remove the controller specified to seal document builder.");
        return -1;
    }

    size = DIDDocument_GetControllerCount(document);
    for (i = 0; i < size; i++) {
        controller_doc = document->controllers.docs[i];
        assert(controller_doc);
        if (!DID_Equals(controller, &controller_doc->did))
            continue;

        if (size == 1) {
            DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't remove the last controller.");
            return -1;
        }

        //check if credential is signed by controller.
        for (j = 0; j < document->credentials.size; j++) {
            cred = document->credentials.credentials[j];
            assert(cred);
            if(Credential_IsSelfProclaimed(cred) && DID_Equals(controller, &cred->proof.verificationMethod.did)) {
                DIDError_Set(DIDERR_ILLEGALUSAGE,
                        "There are self-proclaimed credentials signed by controller, please remove or renew these credentials at first.");
                return -1;
            }
        }

        DIDDocument_Destroy(controller_doc);

        if (i != size - 1)
            memmove(document->controllers.docs + i, document->controllers.docs + i + 1,
                    sizeof(DIDDocument*) * (size - i - 1));

        document->controllers.docs[size - 1] = NULL;
        document->controllers.size--;
        document->multisig = 0;
        clean_proofs(document);
        return 0;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "No this controller in document.");
    return -1;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_AddCredential(DIDDocumentBuilder *builder, Credential *credential)
{
    DIDDocument *document;
    Credential *temp_cred;
    Credential *cred;
    size_t i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!credential, "No credential argument.", -1);

    document = builder->document;
    assert(document);
    if (!DID_Equals(&document->did, &credential->id.did)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't add Credential not owned by did self.");
        return -1;
    }

    for (i = 0; i < document->credentials.size; i++) {
        temp_cred = document->credentials.credentials[i];
        assert(temp_cred);
        if (DIDURL_Equals(&temp_cred->id, &credential->id)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Credential already exist.");
            return -1;
        }
    }

    cred = (Credential *)calloc(1, sizeof(Credential));
    if (!cred) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credential failed.");
        return -1;
    }

    if (Credential_Copy(cred, credential) == -1 ||
            diddocument_addcredential(document, cred) == -1) {
        Credential_Destroy(cred);
        return -1;
    }

    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_AddSelfProclaimedCredential(DIDDocumentBuilder *builder,
        DIDURL *credid, const char **types, size_t typesize,
        Property *properties, int propsize, time_t expires,
        DIDURL *signkey, const char *storepass)
{
    DIDDocument *document;
    Credential *cred;
    Issuer *issuer;
    const char *defaulttypes[] = {"SelfProclaimedCredential"};
    int i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!credid, "No credential id argument.", -1);
    CHECK_ARG(!properties || propsize <= 0, "Invalid property argument.", -1);
    CHECK_PASSWORD(storepass, -1);

    document = builder->document;
    assert(document);
    if (!DID_Equals(&document->did, &credid->did)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "The credential id mismatch with the document.");
        return -1;
    }

    for (i = 0; i < document->credentials.size; i++) {
        cred = document->credentials.credentials[i];
        assert(cred);
        if (DIDURL_Equals(&cred->id, credid)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Credential already exist.");
            return -1;
        }
    }

    if (!signkey && document->controllers.size > 1) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Must specify the key to sign the credential owned by multi-controller did.");
        return -1;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(document);
        if (!signkey)
            return -1;
    } else {
        if (!DIDDocument_IsAuthenticationKey(document, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Signkey is not an authentication key.");
            return -1;
        }
    }

    issuer = Issuer_Create(&document->did, signkey, document->metadata.base.store);
    if (!issuer)
        return -1;

    if (!types) {
        types = defaulttypes;
        typesize = 1;
    }

    if (expires <= 0)
        expires = document->expires;

    cred = Issuer_CreateCredential(issuer, &document->did, credid,
        types, typesize, properties, propsize, expires, storepass);
    Issuer_Destroy(issuer);
    if (!cred)
        return -1;

    if (diddocument_addcredential(document, cred) < 0) {
        Credential_Destroy(cred);
        return -1;
    }

    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_RenewSelfProclaimedCredential(DIDDocumentBuilder *builder,
        DID *controller, DIDURL *signkey, const char *storepass)
{
    DIDDocument *document;
    Credential *cred;
    Issuer *issuer = NULL;
    int i, rc = -1;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!controller, "No controller argument.", -1);
    CHECK_ARG(!signkey, "No signkey argument to sign.", -1);
    CHECK_PASSWORD(storepass, -1);

    document = builder->document;
    assert(document);
    if (!DIDDocument_IsCustomizedDID(document)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't renew self-proclaimed Credential owned by normal DID.");
        return -1;
    }

    if (!issuer) {
        issuer = Issuer_Create(&document->did, signkey, document->metadata.base.store);
        if (!issuer)
            return -1;
    }

    for (i = 0; i < document->credentials.size; i++) {
        cred = document->credentials.credentials[i];
        assert(cred);
        if (!Credential_IsSelfProclaimed(cred) ||
                !DID_Equals(controller, &cred->proof.verificationMethod.did))
            continue;

        cred = Issuer_Generate_Credential(issuer, &document->did, &cred->id,
                (const char**)cred->type.types, cred->type.size, cred->subject.properties,
                cred->expirationDate, storepass);
        if (!cred)
            goto pointexit;

        Credential_Destroy(document->credentials.credentials[i]);
        document->credentials.credentials[i] = cred;
    }

    rc = 0;

pointexit:
    Issuer_Destroy(issuer);
    return rc;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_RemoveSelfProclaimedCredential(DIDDocumentBuilder *builder,
       DID *controller)
{
    DIDDocument *document;
    Credential *cred;
    int i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!controller, "No controller argument.", -1);

    document = builder->document;
    assert(document);
    if (!DIDDocument_IsCustomizedDID(document)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't remove self-proclaimed Credential owned by normal DID.");
        return -1;
    }

    for (i = 0; i < document->credentials.size; i++) {
        cred = document->credentials.credentials[i];
        assert(cred);
        if (Credential_IsSelfProclaimed(cred) &&
                DID_Equals(controller, &cred->proof.verificationMethod.did)) {
            Credential_Destroy(cred);
            if (i != document->credentials.size - 1)
                memmove(document->credentials.credentials + i,
                        document->credentials.credentials + i + 1,
                        sizeof(Credential*) * (document->credentials.size - i - 1));

            document->credentials.credentials[--document->credentials.size] = NULL;
            i--;
            if (document->credentials.size == 0) {
                free((void*)document->credentials.credentials);
                document->credentials.credentials = NULL;
            }
        }
    }

    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_RemoveCredential(DIDDocumentBuilder *builder, DIDURL *credid)
{
    DIDDocument *document;
    Credential *cred = NULL;
    size_t size;
    size_t i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!credid, "No credential id argument.", -1);

    document = builder->document;
    assert(document);
    size = DIDDocument_GetCredentialCount(document);
    for (i = 0; i < size; i++ ) {
        cred = document->credentials.credentials[i];
        if (!DIDURL_Equals(&cred->id, credid))
            continue;

        Credential_Destroy(cred);

        if (i != size - 1)
            memmove(document->credentials.credentials + i,
                    document->credentials.credentials + i + 1,
                    sizeof(Credential*) * (size - i - 1));

        document->credentials.credentials[--document->credentials.size] = NULL;
        if (document->credentials.size == 0) {
            free((void*)document->credentials.credentials);
            document->credentials.credentials = NULL;
        }

        clean_proofs(document);
        return 0;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "No this credential in document.");
    return -1;

    DIDERROR_FINALIZE();
}

static int document_addservice(DIDDocumentBuilder *builder, DIDURL *serviceid,
        const char *type, const char *endpoint, json_t *properties)
{
    DIDDocument *document;
    Service **services = NULL;
    Service *service = NULL;
    int i;

    assert(builder);
    assert(serviceid);
    assert(type);
    assert(endpoint);

    CHECK_ARG(strlen(type) >= MAX_TYPE_LEN, "Type argument is too long.", -1);
    CHECK_ARG(strlen(endpoint) >= MAX_ENDPOINT, "End point argument is too long.", -1);

    document = builder->document;
    if (!DID_Equals(DIDDocument_GetSubject(document), DIDURL_GetDid(serviceid))) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Service not owned by self, please check service id.");
        return -1;
    }

    for (i = 0; i < document->services.size; i++) {
        service = document->services.services[i];
        if (DIDURL_Equals(&service->id, serviceid)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "This service already exist.");
            return -1;
        }
    }

    services = (Service**)realloc(document->services.services,
            (document->services.size + 1) * sizeof(Service*));
    if (!services) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for services failed.");
        return -1;
    }

    service = (Service*)calloc(1, sizeof(Service));
    if (!service) {
        free(services);
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for service failed.");
        return -1;
    }

    DIDURL_Copy(&service->id, serviceid);
    strcpy(service->type, type);
    strcpy(service->endpoint, endpoint);
    if (properties)
        service->properties = properties;

    services[document->services.size++] = service;
    document->services.services = services;
    clean_proofs(document);
    return 0;
}

int DIDDocumentBuilder_AddService(DIDDocumentBuilder *builder, DIDURL *serviceid,
        const char *type, const char *endpoint, Property *properties, int size)
{
    json_t *root = NULL;
    int i, rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!serviceid, "No service id argument.", -1);
    CHECK_ARG(!type || !*type, "Invalid type of service argument.", -1);
    CHECK_ARG(!endpoint || !*endpoint, "Invalid endpoint of service argument.", -1);
    CHECK_ARG(properties && size <= 0, "Invalid properties of service argument.", -1);

    if (properties) {
        root = json_object();
        if (!root) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Create property json of service failed.");
            return -1;
        }

        for (i = 0; i < size; i++) {
            if (json_object_set_new(root, properties[i].key, json_string(properties[i].value)) < 0) {
               DIDError_Set(DIDERR_OUT_OF_MEMORY, "Add property of service failed.");
               json_decref(root);
               return -1;
            }
        }
    }

    rc = document_addservice(builder, serviceid, type, endpoint, root);
    if (rc < 0) {
        json_decref(root);
        return -1;
    }

    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_AddServiceByString(DIDDocumentBuilder *builder,
        DIDURL *serviceid, const char *type, const char *endpoint,
        const char *properties)
{
    json_t *root = NULL;
    json_error_t error;
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!serviceid, "No service id argument.", -1);
    CHECK_ARG(!type || !*type, "Invalid type of service argument.", -1);
    CHECK_ARG(!endpoint || !*endpoint, "Invalid endpoint of service argument.", -1);

    if (properties) {
        root = json_loads(properties, JSON_COMPACT, &error);
        if (!root) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Deserialize property string of service failed, error: %s.", error.text);
            return -1;
        }
    }

    rc = document_addservice(builder, serviceid, type, endpoint, root);
    if (rc < 0) {
        json_decref(root);
        return -1;
    }

    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_RemoveService(DIDDocumentBuilder *builder, DIDURL *serviceid)
{
    DIDDocument *document;
    Service *service = NULL;
    size_t size;
    size_t i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(!serviceid, "No service id argument.", -1);

    document = builder->document;
    assert(document);
    size = DIDDocument_GetServiceCount(document);
    for (i = 0; i < size; i++) {
        service = document->services.services[i];
        assert(service);
        if (!DIDURL_Equals(&service->id, serviceid))
            continue;

        Service_Destroy(service);

        if (i != size - 1)
            memmove(document->services.services + i,
                    document->services.services + i + 1,
                    sizeof(Service*) * (size - i - 1));

        document->services.services[--document->services.size] = NULL;
        if (document->services.size == 0) {
            free((void*)document->services.services);
            document->services.services = NULL;
        }

        clean_proofs(document);
        return 0;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "This service is not exist.");
    return -1;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_RemoveProof(DIDDocumentBuilder *builder, DID *controller)
{
    DIDDocument *document;
    size_t size;
    int i, index = -1;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);

    document = builder->document;
    assert(document);
    size = document->proofs.size;

    if (DIDDocument_IsCustomizedDID(document)) {
        if (!controller) {
            DIDError_Set(DIDERR_INVALID_ARGS, "Must be specified the controller to remove proof of customized did.");
            return -1;
        }

        for (i = 0; i < size; i++) {
            if (DID_Equals(controller, &document->proofs.proofs[i].creater.did))
                index = i;
        }
        if (index == -1) {
            DIDError_Set(DIDERR_NOT_EXISTS, "No proof signed by this DID.");
            return -1;
        }
    } else {
        if (controller) {
            DIDError_Set(DIDERR_INVALID_CONTROLLER, "Can't remove the specified controller for normal did.");
            return -1;
        }
        index = 0;
    }

    if (index != size - 1)
        memmove(&document->proofs.proofs[index], &document->proofs.proofs[index + 1],
                sizeof(DocumentProof) * (size - index - 1));

    if (--document->proofs.size == 0) {
        free((void*)document->proofs.proofs);
        document->proofs.proofs = NULL;
    }

    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_SetExpires(DIDDocumentBuilder *builder, time_t expires)
{
    time_t max_expires;
    struct tm *tm = NULL;
    DIDDocument *document;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(expires < 0, "Invalid expires time.", -1);

    max_expires = time(NULL);
    tm = gmtime(&max_expires);
    tm->tm_year += MAX_EXPIRES;
    max_expires = mktime(tm);

    document = builder->document;
    if (expires == 0) {
        document->expires = max_expires;
        clean_proofs(document);
        return 0;
    }

    //Don't remove, get local time
    //tm = gmtime(&expires);
    //expires = mktime(tm);

    if (expires > max_expires) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Expire time is too long, not longer than five years.");
        return -1;
    }

    document->expires = expires;
    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

int DIDDocumentBuilder_SetMultisig(DIDDocumentBuilder *builder, int multisig)
{
    DIDDocument *document;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!builder || !builder->document, "Invalid document builder argument.", -1);
    CHECK_ARG(multisig <= 0, "Invalid multisig.", -1);

    document = builder->document;
    assert(document);
    if (!DIDDocument_IsCustomizedDID(document)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't set multisig for normal DID.");
        return -1;
    }

    if (multisig > document->controllers.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Please reset multisig isn't larger than %d.", document->controllers.size);
        return -1;
    }

    document->multisig = multisig;
    clean_proofs(document);
    return 0;

    DIDERROR_FINALIZE();
}

//////////////////////////DIDDocument//////////////////////////////////////////
DID* DIDDocument_GetSubject(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get subject.", NULL);
    return &document->did;

    DIDERROR_FINALIZE();
}

int DIDDocument_GetMultisig(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get multisig.", -1);

    if (!DIDDocument_IsCustomizedDID(document))
        return 0;

    if (document->controllers.size == 1)
        return 0;

    return document->multisig;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_GetControllerCount(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get controller count.", -1);
    return document->controllers.size;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_GetControllers(DIDDocument *document, DID **controllers, size_t size)
{
    DIDDocument *doc;
    int i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get controllers.", -1);
    CHECK_ARG(!controllers || size == 0, "No buffer for controllers argument.", -1);
    CHECK_ARG(size == 0 || size < document->controllers.size, "Wrong size of buffer for controllers argument.", -1);

    for (i = 0; i < document->controllers.size; i++) {
        doc = document->controllers.docs[i];
        assert(doc);
        controllers[i] = &doc->did;
    }

    return document->controllers.size;

    DIDERROR_FINALIZE();
}

int DIDDocument_ContainsController(DIDDocument *document, DID *controller)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to check controller.", -1);
    CHECK_ARG(!controller, "No controller argument to check.", -1);
    return !DIDDocument_GetControllerDocument(document, controller) ? 0 : 1;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_GetPublicKeyCount(DIDDocument *document)
{
    size_t count;
    DIDDocument *doc;
    int i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get publickeys count.", -1);

    count = document->publickeys.size;
    if (document->controllers.size && document->controllers.docs) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            if (doc)
                count += doc->publickeys.size;
        }
    }

    return (ssize_t)count;

    DIDERROR_FINALIZE();
}

PublicKey *DIDDocument_GetPublicKey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey *pk;
    DIDDocument *doc;
    size_t i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get publicKey.", NULL);
    CHECK_ARG(!keyid, "No key id argument.", NULL);

    if (!*keyid->fragment || !*keyid->did.idstring) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Malformed key id.");
        return NULL;
    }

    if (DID_Equals(&document->did, &keyid->did)) {
        doc = document;
    } else {
        doc = DIDDocument_GetControllerDocument(document, &keyid->did);
        if (!doc) {
            DIDError_Set(DIDERR_NOT_EXISTS, "The owner of this key is not the controller of document.");
            return NULL;
        }
    }

    for (i = 0; i < doc->publickeys.size && doc->publickeys.pks; i++) {
        pk = doc->publickeys.pks[i];
        assert(pk);
        if (DIDURL_Equals(keyid, &pk->id))
            return pk;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "No this public key in document.");
    return NULL;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_GetPublicKeys(DIDDocument *document, PublicKey **pks,
        size_t size)
{
    size_t actual_size, pk_size = 0;
    DIDDocument *doc;
    int i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get publicKeys.", -1);
    CHECK_ARG(!pks || size == 0, "Invalid buffer for publickeys.", -1);

    actual_size = DIDDocument_GetPublicKeyCount(document);
    if (actual_size > size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer for publicKeys is small.");
        return -1;
    }

    actual_size = document->publickeys.size;
    if (actual_size > 0 && document->publickeys.pks)
        memcpy(pks, document->publickeys.pks, sizeof(PublicKey*) * actual_size);

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            if (doc) {
                pk_size = DIDDocument_GetPublicKeys(doc, pks + actual_size, (size - actual_size));
                if (pk_size > 0)
                    actual_size += pk_size;
            }
        }
    }

    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_SelectPublicKeys(DIDDocument *document, const char *type,
        DIDURL *keyid, PublicKey **pks, size_t size)
{
    DIDDocument *doc;
    size_t actual_size = 0, total_size, i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to select publicKeys.", -1);
    CHECK_ARG(!pks || size == 0, "Invalid buffer for publickeys.", -1);
    CHECK_ARG(!keyid && !type, "No feature to select key.", -1);

    if (keyid && !*keyid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Key id misses fragment.");
        return -1;
    }

    if (keyid && DID_IsEmpty(&keyid->did))
        DID_Copy(&keyid->did, &document->did);

    total_size = document->publickeys.size;
    for (i = 0; i < total_size; i++) {
        PublicKey *pk = document->publickeys.pks[i];

        if (keyid && !DIDURL_Equals(keyid, &pk->id))
            continue;
        if (type && strcmp(type, pk->type))
            continue;

        if (actual_size >= size) {
            DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer for publicKeys is small.");
            return -1;
        }

        pks[actual_size++] = pk;
    }

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            assert(doc);
            total_size = DIDDocument_SelectPublicKeys(doc, type, keyid, pks + actual_size, size - actual_size);
            if (total_size > 0)
                actual_size += total_size;
        }
    }

    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

DIDURL *DIDDocument_GetDefaultPublicKey(DIDDocument *document)
{
    DIDDocument *doc;
    char idstring[MAX_ID_SPECIFIC_STRING];
    uint8_t binkey[PUBLICKEY_BYTES];
    PublicKey *pk;
    size_t i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get default key.", NULL);

    if (document->defaultkey)
        return document->defaultkey;

    if (document->controllers.size > 1) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Multipe controllers, so no default public key.");
        return NULL;
    }

    if (!document->controllers.size)
        doc = document;
    else
        doc = document->controllers.docs[0];

    for (i = 0; i < doc->publickeys.size; i++) {
        pk = doc->publickeys.pks[i];
        assert(pk);
        if (DID_Equals(&pk->controller, &doc->did) == 0)
            continue;

        b58_decode(binkey, sizeof(binkey), pk->publicKeyBase58);
        HDKey_PublicKey2Address(binkey, idstring, sizeof(idstring));

        if (!strcmp(idstring, pk->id.did.idstring)) {
            document->defaultkey = &pk->id;
            return &pk->id;
        }
    }

    DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No default public key.");
    return NULL;

    DIDERROR_FINALIZE();
}

///////////////////////Authentications/////////////////////////////
ssize_t DIDDocument_GetAuthenticationCount(DIDDocument *document)
{
    size_t size, i, pk_size;
    DIDDocument *doc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get authentication key.", -1);

    size = DIDDocument_GetSelfAuthenticationKeyCount(document);
    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            assert(doc);
            pk_size = DIDDocument_GetSelfAuthenticationKeyCount(doc);
            if (pk_size > 0)
                size += pk_size;
        }
    }

    return (ssize_t)size;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_GetAuthenticationKeys(DIDDocument *document, PublicKey **pks,
        size_t size)
{
    size_t actual_size = 0, i, pk_size;
    DIDDocument *doc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get authentication keys.", -1);
    CHECK_ARG(!pks || size == 0, "Invalid buffer for authentication keys.", -1);

    if (size < DIDDocument_GetAuthenticationCount(document)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
        return -1;
    }

    for (i = 0; i < document->publickeys.size && document->publickeys.pks; i++) {
        if (document->publickeys.pks[i]->authenticationKey) {
            if (actual_size >= size) {
                DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer for authentication keys is small.");
                return -1;
            }
            pks[actual_size++] = document->publickeys.pks[i];
        }
    }

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            assert(doc);
            pk_size = DIDDocument_GetAuthenticationKeys(doc, pks + actual_size,
                    (size - actual_size));
            if (pk_size > 0)
                actual_size += pk_size;
        }
    }

    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

PublicKey *DIDDocument_GetAuthenticationKey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey *pk;

    DIDERROR_INITIALIZE();

    if (!document || !keyid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (!*keyid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Key id misses fragment.");
        return NULL;
    }

    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk)
        return NULL;

    if (!pk->authenticationKey) {
        DIDError_Set(DIDERR_NOT_EXISTS, "This is not authentication key.");
        return NULL;
    }

    return pk;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_SelectAuthenticationKeys(DIDDocument *document,
        const char *type, DIDURL *keyid, PublicKey **pks, size_t size)
{
    size_t actual_size = 0, i, pk_size;
    PublicKey *pk;
    DIDDocument *doc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to select authentication keys.", -1);
    CHECK_ARG(!pks || size == 0, "Invalid buffer for authentication keys.", -1);
    CHECK_ARG(!keyid && !type, "No feature to select key.", -1);

    if (keyid && !*keyid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Key id misses fragment.");
        return -1;
    }

    for (i = 0; i < document->publickeys.size; i++) {
        pk = document->publickeys.pks[i];
        if (!pk->authenticationKey)
            continue;
        if (keyid && !DIDURL_Equals(keyid, &pk->id))
            continue;
        if (type && strcmp(type, pk->type))
            continue;

        if (actual_size >= size) {
            DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer for authentication keys is small.");
            return -1;
        }

        pks[actual_size++] = pk;
    }

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            assert(doc);
            pk_size = DIDDocument_SelectAuthenticationKeys(doc, type, keyid,
                    pks + actual_size, size - actual_size);
            if (pk_size > 0)
                actual_size += pk_size;
        }
    }

    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

////////////////////////////Authorization//////////////////////////
ssize_t DIDDocument_GetAuthorizationCount(DIDDocument *document)
{
    DIDDocument *doc;
    size_t size, pk_size;
    int i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get count of authentication keys.", -1);

    size = get_self_authorization_count(document);
    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            assert(doc);
            pk_size = get_self_authorization_count(doc);
            if (pk_size > 0)
                size += pk_size;
        }
    }

    return (ssize_t)size;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_GetAuthorizationKeys(DIDDocument *document, PublicKey **pks,
        size_t size)
{
    size_t actual_size = 0, i, pk_size;
    DIDDocument *doc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get authorization keys.", -1);
    CHECK_ARG(!pks || size == 0, "Invalid buffer for authorization keys.", -1);

    if (size < DIDDocument_GetAuthorizationCount(document)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The buffer is too small.");
        return -1;
    }

    for (i = 0; i < document->publickeys.size && document->publickeys.pks; i++) {
        if (document->publickeys.pks[i]->authorizationKey) {
            if (actual_size >= size) {
                DIDError_Set(DIDERR_INVALID_ARGS, "The buffer for authorization keys is too small.");
                return -1;
            }
            pks[actual_size++] = document->publickeys.pks[i];
        }
    }

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            assert(doc);
            pk_size = DIDDocument_GetAuthorizationKeys(doc, pks + actual_size,
                    size - actual_size);
            if (pk_size > 0)
                actual_size += pk_size;
        }
    }

    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

PublicKey *DIDDocument_GetAuthorizationKey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey *pk;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get authorization key.", NULL);
    CHECK_ARG(!keyid, "No key id argument.", NULL);

    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk)
        return NULL;

    if (!pk->authorizationKey) {
        DIDError_Set(DIDERR_NOT_EXISTS, "This isn't authorization key.");
        return NULL;
    }

    return pk;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_SelectAuthorizationKeys(DIDDocument *document,
        const char *type, DIDURL *keyid, PublicKey **pks, size_t size)
{
    size_t actual_size = 0, i, pk_size;
    PublicKey *pk;
    DIDDocument *doc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to select authorization keys.", -1);
    CHECK_ARG(!pks || size == 0, "Invalid buffer for authorization keys.", -1);
    CHECK_ARG(!keyid && !type, "No feature to select key.", -1);

    if (keyid && !*keyid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Key id misses fragment.");
        return -1;
    }

    for (i = 0; i < document->publickeys.size; i++) {
        pk = document->publickeys.pks[i];
        if (!pk->authorizationKey)
            continue;
        if (keyid && !DIDURL_Equals(keyid, &pk->id))
            continue;
        if (type && strcmp(type, pk->type))
            continue;

        if (actual_size >= size) {
            DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer for authorization keys is small.");
            return -1;
        }

        pks[actual_size++] = pk;
    }

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            assert(doc);
            pk_size = DIDDocument_SelectAuthorizationKeys(doc, type, keyid,
                    pks + actual_size, size - actual_size);
            if (pk_size > 0)
                actual_size += pk_size;
        }
    }

    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

//////////////////////////Credential///////////////////////////
ssize_t DIDDocument_GetCredentialCount(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get count of credentials.", -1);
    return (ssize_t)document->credentials.size;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_GetCredentials(DIDDocument *document, Credential **creds,
        size_t size)
{
    size_t actual_size;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get credentials.", -1);
    CHECK_ARG(!creds || size == 0, "Invalid buffer for credentials.", -1);

    actual_size = document->credentials.size;
    if (actual_size > size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer for credentials is small.");
        return -1;
    }

    memcpy(creds, document->credentials.credentials, sizeof(Credential*) * actual_size);
    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

Credential *DIDDocument_GetCredential(DIDDocument *document, DIDURL *credid)
{
    Credential *credential = NULL;
    size_t size, i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get credential.", NULL);
    CHECK_ARG(!credid, "No credential id.", NULL);

    if (!*credid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Invalid credential id.");
        return NULL;
    }

    size = document->credentials.size;
    if (!size) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No credential in document.");
        return NULL;
    }

    for (i = 0; i < size; i++) {
        credential = document->credentials.credentials[i];
        assert(credential);
        if (DIDURL_Equals(credid, &credential->id))
            return credential;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "No this credential.");
    return NULL;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_SelectCredentials(DIDDocument *document, const char *type,
        DIDURL *credid, Credential **creds, size_t size)
{
    size_t actual_size = 0, total_size, i, j;
    bool flag;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to select credentials.", -1);
    CHECK_ARG(!creds || size == 0, "Invalid buffer for credentials.", -1);
    CHECK_ARG(!credid && !type, "No feature to select credential.", -1);

    if (credid && !*credid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Credential id misses fragment.");
        return -1;
    }

    total_size = document->credentials.size;
    if (!total_size) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No credential in document.");
        return -1;
    }

    if (credid && DID_IsEmpty(&credid->did))
        DID_Copy(&credid->did, &document->did);

    for (i = 0; i < total_size; i++) {
        Credential *cred = document->credentials.credentials[i];
        assert(cred);
        flag = false;

        if (credid && !DIDURL_Equals(credid, &cred->id))
            continue;

        if (type) {
            for (j = 0; j < cred->type.size; j++) {
                const char *new_type = cred->type.types[j];
                if (new_type && !strcmp(new_type, type)) {
                    flag = true;
                    break;
                }
            }
        } else {
            flag = true;
        }

        if (actual_size >= size) {
            DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer for credentials is small.");
            return -1;
        }

        if (flag)
            creds[actual_size++] = cred;
    }

    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

////////////////////////////////service//////////////////////
ssize_t DIDDocument_GetServiceCount(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get count of service.", -1);
    return (ssize_t)document->services.size;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_GetServices(DIDDocument *document, Service **services,
        size_t size)
{
    size_t actual_size;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get services.", -1);
    CHECK_ARG(!services || size == 0, "Invalid buffer for services.", -1);

    actual_size = document->services.size;
    if (actual_size > size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer for services is small.");
        return -1;
    }

    memcpy(services, document->services.services, sizeof(Service*) * actual_size);
    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

Service *DIDDocument_GetService(DIDDocument *document, DIDURL *serviceid)
{
    Service *service = NULL;
    size_t size, i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get service.", NULL);
    CHECK_ARG(!serviceid, "No service id argument.", NULL);

    if (!*serviceid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Service id misses fragment.");
        return NULL;
    }

    size = document->services.size;
    if (!size) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No service in document.");
        return NULL;
    }

    for (i = 0; i < size; i++) {
        service = document->services.services[i];
        assert(service);
        if (DIDURL_Equals(serviceid, &service->id))
            return service;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "This service is in document.");
    return NULL;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_SelectServices(DIDDocument *document,
        const char *type, DIDURL *serviceid, Service **services, size_t size)
{
    size_t actual_size = 0, total_size, i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to select services.", -1);
    CHECK_ARG(!services || size == 0, "Invalid buffer for services.", -1);
    CHECK_ARG(!serviceid && !type, "No feature to select service.", -1);

    if (serviceid && !*serviceid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Service id misses fragment.");
        return -1;
    }

    total_size = document->services.size;
    if (!total_size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer for services is small.");
        return -1;
    }

    if (serviceid && DID_IsEmpty(&serviceid->did))
        DID_Copy(&serviceid->did, &document->did);

    for (i = 0; i < total_size; i++) {
        Service *service = document->services.services[i];
        assert(service);

        if (serviceid && !DIDURL_Equals(serviceid, &service->id))
            continue;
        if (type && strcmp(type, service->type))
            continue;

        if (actual_size >= size) {
            DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer for services is small.");
            return -1;
        }

        services[actual_size++] = service;
    }

    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

///////////////////////////////expires////////////////////////
time_t DIDDocument_GetExpires(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get expires time.", 0);
    return document->expires;

    DIDERROR_FINALIZE();
}

ssize_t DIDDocument_GetDigest(DIDDocument *document, uint8_t *digest, size_t size)
{
    const char *data;
    ssize_t rc;

    assert(document);
    assert(digest);
    assert(size >= SHA256_BYTES);

    data = diddocument_tojson_forsign(document, false, true);
    if (!data)
        return -1;

    rc = sha256_digest(digest, 1, (unsigned char*)data, strlen(data));
    if (rc < 0)
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get digest failed.");

    return rc;
}

int DIDDocument_HasPrivateKey(DIDDocument *document, DIDURL *keyid)
 {
    const char *rootidentity;
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to check.", -1);
    CHECK_ARG(!keyid, "No key to check.", -1);

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with document.");
        return -1;
    }

    if (!DIDDocument_GetPublicKey(document, keyid)) {
        DIDError_Set(DIDERR_INVALID_KEY, "Key doesn't own to document.");
        return -1;
    }

    return DIDStore_ContainsPrivateKey(document->metadata.base.store, &keyid->did, keyid);

    DIDERROR_FINALIZE();
}

int DIDDocument_Sign(DIDDocument *document, DIDURL *keyid, const char *storepass,
        char *sig, int count, ...)
{
    uint8_t digest[SHA256_BYTES];
    va_list inputs;
    ssize_t size;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to sign.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!sig, "No buffer to store signature.", -1);
    CHECK_ARG(count <= 0, "No datas to sign.", -1);

    va_start(inputs, count);
    size = sha256v_digest(digest, count, inputs);
    va_end(inputs);
    if (size == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get digest failed.");
        return -1;
    }

    return DIDDocument_SignDigest(document, keyid, storepass, sig, digest, sizeof(digest));

    DIDERROR_FINALIZE();
}

int DIDDocument_SignDigest(DIDDocument *document, DIDURL *keyid,
        const char *storepass, char *sig, uint8_t *digest, size_t size)
{
    DID *signer;
    PublicKey *pk;
    DIDDocument *doc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to sign.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!sig, "No buffer to store signature.", -1);
    CHECK_ARG(!digest || size == 0, "Invalid digest to sign.", -1);

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with document.");
        return -1;
    }

    if (!keyid)
        keyid = DIDDocument_GetDefaultPublicKey(document);

    //confirm the signer
    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk || !PublicKey_IsAuthenticationKey(pk)) {
        DIDError_Set(DIDERR_INVALID_KEY, "Signkey isn't authentication key.");
        return -1;
    }

    if (DID_Equals(&document->did, &pk->controller)) {
       signer = &document->did;
    } else {
        doc = DIDDocument_GetControllerDocument(document, &keyid->did);
        if (!doc) {
            DIDError_Set(DIDERR_INVALID_KEY, "Signkey doesn't own to document.");
            return -1;
        }

        if (!DID_Equals(&doc->did, &pk->controller)) {
            DIDError_Set(DIDERR_INVALID_CONTROLLER, "Invalid signkey.");
            return -1;
        }
        signer = &doc->did;
    }

    return DIDStore_Sign(document->metadata.base.store, storepass,
            signer, keyid, sig, digest, size);

    DIDERROR_FINALIZE();
}

int DIDDocument_Verify(DIDDocument *document, DIDURL *keyid, char *sig,
        int count, ...)
{
    va_list inputs;
    uint8_t digest[SHA256_BYTES];
    ssize_t size;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to verify signature.", -1);
    CHECK_ARG(!sig, "No signature to verify", -1);
    CHECK_ARG(count <= 0, "No data to verify", -1);

    va_start(inputs, count);
    size = sha256v_digest(digest, count, inputs);
    va_end(inputs);
    if (size == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get digest failed.");
        return -1;
    }

    return DIDDocument_VerifyDigest(document, keyid, sig, digest, sizeof(digest));

    DIDERROR_FINALIZE();
}

int DIDDocument_VerifyDigest(DIDDocument *document, DIDURL *keyid,
        char *sig, uint8_t *digest, size_t size)
{
    PublicKey *publickey;
    uint8_t binkey[PUBLICKEY_BYTES];

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to verify signature.", -1);
    CHECK_ARG(!sig, "No signature to verify", -1);
    CHECK_ARG(!digest || size == 0, "Invalid digest to verify", -1);

    if (!keyid) {
        keyid = DIDDocument_GetDefaultPublicKey(document);
        if (!keyid) {
            DIDError_Set(DIDERR_INVALID_ARGS, "Document doesn't have default key, so please provide key to verify.");
            return -1;
        }
    }

    publickey = DIDDocument_GetPublicKey(document, keyid);
    if (!publickey) {
        DIDError_Set(DIDERR_INVALID_KEY, "No signkey.");
        return -1;
    }

    b58_decode(binkey, sizeof(binkey), PublicKey_GetPublicKeyBase58(publickey));

    if (ecdsa_verify_base64(sig, binkey, digest, size) == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Ecdsa verify failed.");
        return -1;
    }

    return 0;

    DIDERROR_FINALIZE();
}

static bool proof_isexist(DocumentProof **proofs, size_t size, DocumentProof *proof)
{
    int i;

    assert(proofs);
    assert(proof);

    for (i = 0; i < size; i++) {
        if (DIDURL_Equals(&proofs[i]->creater, &proof->creater)) {
            if (proofs[i]->created > proof->created)
                proofs[i] = proof;
            return true;
        }
    }

    return false;
}

const char *DIDDocument_Merge(DIDDocument **documents, size_t size)
{
    DocumentProof **proofs, *proof;
    size_t proof_size = 0, actual_size = 0;
    DIDDocument *merged_document, *document;
    int i, j;

    assert(documents);
    assert(size > 0);

    for (i = 0; i < size; i++)
        proof_size += documents[i]->proofs.size;
    assert(proof_size > 0);

    proofs = (DocumentProof**)alloca(proof_size * sizeof(DocumentProof*));
    if (!proofs) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DocumentProof array failed.");
        return NULL;
    }

    for (i = 0; i < size; i++) {
        document = documents[i];
        for(j = 0; j < document->proofs.size; j++) {
            proof = &document->proofs.proofs[j];
            if (!proof_isexist(proofs, actual_size, proof))
                proofs[actual_size++] = proof;
        }
    }

    qsort(proofs, actual_size, sizeof(DocumentProof*), proof_cmp);

    merged_document = documents[0];
    for (i = 0; i < merged_document->multisig; i++)
        diddocument_addproof(merged_document, proofs[i]->signatureValue,
                &proofs[i]->creater, proofs[i]->created);

    if (!DIDDocument_IsValid(merged_document))
        return NULL;

    return DIDDocument_ToJson(merged_document, true);
}

#ifndef DISABLE_JWT
JWTBuilder *DIDDocument_GetJwtBuilder(DIDDocument *document)
{
    JWTBuilder *builder;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to get JwtBuilder.", NULL);

    builder = JWTBuilder_Create(&document->did);
    if (!builder)
        return NULL;

    return builder;

    DIDERROR_FINALIZE();
}

JWSParser *DIDDocument_GetJwsParser(DIDDocument *document)
{
    DIDERROR_INITIALIZE();

    return JWSParser_Create(document);

    DIDERROR_FINALIZE();
}
#endif

inline static uint32_t UInt32GetBE(const void *b4)
{
    return (((uint32_t)((const uint8_t *)b4)[0] << 24) | ((uint32_t)((const uint8_t *)b4)[1] << 16) |
            ((uint32_t)((const uint8_t *)b4)[2] << 8)  | ((uint32_t)((const uint8_t *)b4)[3]));
}

static int map_to_derivepath(int *paths, size_t size, const char *identifier)
{
    uint8_t digest[SHA256_BYTES];

    assert(paths);
    assert(size == 8);
    assert(identifier);

    if (sha256_digest(digest, 1, identifier, strlen(identifier)) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get digest failed.");
        return -1;
    }

    for (int i = 0; i < size; i++)
        paths[i] = UInt32GetBE(digest + i*4);

    return 0;
}

static const char *document_derive(DIDDocument *document, const char *identifier,
        int index, const char *storepass)
{
    uint8_t extendedkey[EXTENDEDKEY_BYTES];
    int paths[8];
    HDKey *hdkey, *derivedkey, _hdkey, _dkey;
    char extendedkeyBase58[512];

    assert(document);
    assert(storepass && *storepass);

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with document.");
        return NULL;
    }

    if (DIDDocument_IsCustomizedDID(document)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't use customized did to derive.");
        return NULL;
    }

    if (DIDStore_LoadPrivateKey_Internal(document->metadata.base.store, storepass,
            &document->did, DIDDocument_GetDefaultPublicKey(document),
            extendedkey, sizeof(extendedkey)) < 0)
        return NULL;

    hdkey = HDKey_Deserialize(&_hdkey, extendedkey, sizeof(extendedkey));
    memset(extendedkey, 0, sizeof(extendedkey));
    if (!hdkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Deserialize extended key failed.");
        return NULL;
    }

    if (identifier) {
        if (map_to_derivepath(paths, 8, identifier) < 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Get derived path failed.");
            return NULL;
        }

        derivedkey = HDKey_GetDerivedKey(hdkey, &_dkey, 9, paths[0], paths[1], paths[2], paths[3],
                paths[4], paths[5], paths[6], paths[7], index);
    } else {
        derivedkey = HDKey_GetDerivedKey(hdkey, &_dkey, 1, index);
    }

    if (!derivedkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get derived key failed.");
        return NULL;
    }

    if (!HDKey_SerializePrvBase58(derivedkey, extendedkeyBase58, sizeof(extendedkeyBase58))) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Serialize derived key failed.");
        return NULL;
    }

   return strdup(extendedkeyBase58);
}

const char *DIDDocument_DeriveByIdentifier(DIDDocument *document, const char *identifier,
        int securityCode, const char *storepass)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to derive.", NULL);
    CHECK_ARG(!identifier || !*identifier, "Invalid identifier string to derive.", NULL);
    CHECK_PASSWORD(storepass, NULL);
    return document_derive(document, identifier, securityCode, storepass);

    DIDERROR_FINALIZE();
}

const char *DIDDocument_DeriveByIndex(DIDDocument *document, int index,
        const char *storepass)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to derive.", NULL);
    CHECK_ARG(index < 0, "Invalid index", NULL);
    CHECK_PASSWORD(storepass, NULL);
    return document_derive(document, NULL, index, storepass);

    DIDERROR_FINALIZE();
}

DIDDocument *DIDDocument_SignDIDDocument(DIDDocument* controllerdoc,
        const char *document, const char *storepass)
{
    DIDDocument *doc;
    DIDDocumentBuilder *builder;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!controllerdoc, "No controller doc to sign.", NULL);
    CHECK_ARG(!document || !*document, "Invalid document string to be sign.", NULL);
    CHECK_PASSWORD(storepass, NULL);

    doc = DIDDocument_FromJson(document);
    if (!doc)
        return NULL;

    if (DIDDocument_IsQualified(doc)) {
        DIDDocument_Destroy(doc);
        DIDError_Set(DIDERR_ALREADY_SEALED, "The signers are enough.");
        return NULL;
    }

    builder = DIDDocument_Edit(doc, controllerdoc);
    DIDDocument_Destroy(doc);
    if (!builder)
        return NULL;

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    return doc;

    DIDERROR_FINALIZE();
}

const char *DIDDocument_MergeDIDDocuments(int count, ...)
{
    va_list list;
    const char *doc = NULL, *merged_doc = NULL;
    DIDDocument *document = NULL, **documents;
    uint8_t digest[SHA256_BYTES], digest1[SHA256_BYTES];
    int i, actual_count = 0;

    DIDERROR_INITIALIZE();

    CHECK_ARG(count <= 0, "No documents to be merged.", NULL);

    documents = (DIDDocument**)alloca(count * sizeof(DIDDocument*));
    if (!documents) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for documents failed.");
        return NULL;
    }

    va_start(list, count);
    for (i = 0; i < count; i++) {
        doc = va_arg(list, const char *);
        if (!doc)
            continue;

        document = DIDDocument_FromJson(doc);
        if (!document)
            continue;

        if (DIDDocument_IsValid_Internal(document, false) != 1) {
            DIDDocument_Destroy(document);
            continue;
        }

        if (DIDDocument_GetDigest(document, digest1, sizeof(digest1)) < 0) {
            DIDDocument_Destroy(document);
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Get digest from document failed.");
            continue;
        }

        if (actual_count == 0) {
            memcpy(digest, digest1, sizeof(digest));
        } else {
            if (memcmp(digest, digest1, sizeof(digest))) {
                DIDDocument_Destroy(document);
                continue;
            }
        }

        if (DIDDocument_IsQualified(document)) {
            DIDDocument_Destroy(document);
            merged_doc = strdup(doc);
            goto pointexit;
        }

        documents[actual_count++] = document;
    }
    va_end(list);

    merged_doc = DIDDocument_Merge(documents, actual_count);

pointexit:
    for (i = 0; i < actual_count; i++)
        DIDDocument_Destroy(documents[i]);

    return merged_doc;

    DIDERROR_FINALIZE();
}

TransferTicket *DIDDocument_CreateTransferTicket(DIDDocument *controllerdoc, DID *owner,
        DID *to, const char *storepass)
{
    TransferTicket *ticket;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!controllerdoc, "No controller doc argument.", NULL);
    CHECK_ARG(!owner, "No owner of ticket.", NULL);
    CHECK_ARG(!to, "No receiver for ticket.", NULL);
    CHECK_PASSWORD(storepass, NULL);

    ticket = TransferTicket_Construct(owner, to);
    if (!ticket)
        return NULL;

    if (TransferTicket_Seal(ticket, controllerdoc, storepass) < 0) {
        TransferTicket_Destroy(ticket);
        return NULL;
    }

    return ticket;

    DIDERROR_FINALIZE();
}

int DIDDocument_SignTransferTicket(DIDDocument *controllerdoc,
        TransferTicket *ticket, const char *storepass)
{
    CHECK_ARG(!controllerdoc, "No controller's document argument.", -1);
    CHECK_ARG(!ticket, "No ticket argument.", -1);
    CHECK_PASSWORD(storepass, -1);

    return TransferTicket_Seal(ticket, controllerdoc, storepass);
}

static bool controllers_equals(DIDDocument *_doc1, DIDDocument *_doc2)
{
    DIDDocument **docs1, **docs2, *doc1, *doc2;
    size_t size1, size2;
    int i, j;
    bool equal = false;

    assert(_doc1);
    assert(_doc2);

    docs1 = _doc1->controllers.docs;
    docs2 = _doc2->controllers.docs;
    size1 = _doc1->controllers.size;
    size2 = _doc2->controllers.size;

    if (size1 != size2)
        return false;

    for(i = 0; i < size2; i++) {
        doc2 = docs2[i];
        for (j = 0; j < size1; j++) {
            doc1 = docs1[j];
            if (DID_Equals(&doc1->did, &doc2->did)) {
                equal = true;
                break;
            }
        }

        if (!equal)
            return false;
    }

    return true;
}

int DIDDocument_PublishDID(DIDDocument *document, DIDURL *signkey, bool force,
        const char *storepass)
{
    const char *last_txid, *local_signature, *local_prevsignature, *resolve_signature = NULL;
    DIDDocument *resolve_doc = NULL;
    DIDStore *store;
    int rc = -1, status, check;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document argument to be published.", -1);
    CHECK_PASSWORD(storepass, -1);

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with document.");
        return -1;
    }

    store = document->metadata.base.store;
    if (DIDDocument_IsCustomizedDID(document) && document->controllers.size > 1 && !signkey) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Multi-controller customized DID must have signkey to publish.");
        return -1;
    }

    if (!DIDDocument_IsQualified(document)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Document isn't qualified.");
        return -1;
    }

    check = DIDDocument_IsGenuine(document);
    if (check != 1) {
        if (check == 0)
            DIDError_Set(DIDERR_NOT_GENUINE, "Document isn't genuine.");
        return -1;
    }

    check = DIDDocument_IsDeactivated(document);
    if (check != 0) {
        if (check == 1)
            DIDError_Set(DIDERR_DID_DEACTIVATED, "Did is already deactivated.");
        return -1;
    }

    if (!force && DIDDocument_IsExpired(document)) {
        DIDError_Set(DIDERR_EXPIRED, "Did is already expired, use force mode to publish anyway.");
        return -1;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(document);
        if (!signkey) {
            DIDError_Set(DIDERR_NOT_EXISTS, "No signkey to publish did.");
            return -1;
        }
    } else {
        if (!DIDDocument_IsAuthenticationKey(document, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Signkey isn't an authentication key.");
            return -1;
        }
    }

    resolve_doc = DID_Resolve(&document->did, &status, true);
    if (!resolve_doc) {
        if (status == DIDStatus_NotFound)
            rc = DIDBackend_CreateDID(document, signkey, storepass);
        else {
            DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Document %s %s", &document->did, DIDSTATUS_MSG(status));
            return -1;
        }
    } else {
        check = DIDDocument_IsDeactivated(resolve_doc);
        if (check != 0) {
            if (check == 1)
                DIDError_Set(DIDERR_EXPIRED, "Did is already deactivated.");
            goto errorExit;
        }

        if (DIDDocument_IsCustomizedDID(document)) {
            if (!controllers_equals(document, resolve_doc)) {
                DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't publish DID which is changed controller, please transfer it.");
                goto errorExit;
            }
            if (document->multisig != resolve_doc->multisig)  {
                DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't publish DID which is changed multisig, please transfer it.");
                goto errorExit;
            }
        }

        resolve_signature = resolve_doc->proofs.proofs[0].signatureValue;
        if (!resolve_signature || !*resolve_signature) {
            DIDError_Set(DIDERR_NOT_UPTODATE, "Missing resolve signature.");
            goto errorExit;
        }
        last_txid = DIDMetadata_GetTxid(&resolve_doc->metadata);

        if (!force) {
            local_signature = DIDMetadata_GetSignature(&document->metadata);
            local_prevsignature = DIDMetadata_GetPrevSignature(&document->metadata);
            if ((!local_signature || !*local_signature) && (!local_prevsignature || !*local_prevsignature)) {
                DIDError_Set(DIDERR_NOT_UPTODATE,
                        "Missing signatures information, DID SDK dosen't know how to handle it, use force mode to ignore checks.");
                goto errorExit;
            } else if (!local_signature || !local_prevsignature) {
                const char *sig = local_signature != NULL ? local_signature : local_prevsignature;
                if (strcmp(sig, resolve_signature)) {
                    DIDError_Set(DIDERR_NOT_UPTODATE,
                            "Current copy not based on the lastest on-chain copy.");
                    goto errorExit;
                }
            } else {
                if (strcmp(local_signature, resolve_signature) &&
                        strcmp(local_prevsignature, resolve_signature)) {
                    DIDError_Set(DIDERR_NOT_UPTODATE,
                            "Current copy not based on the lastest on-chain copy.");
                    goto errorExit;
                }
            }
        }

        DIDMetadata_SetTxid(&document->metadata, last_txid);
        rc = DIDBackend_UpdateDID(document, signkey, storepass);
    }

    if (rc != 1)
        goto errorExit;

    ResolveCache_InvalidateDID(&document->did);
    //Meta stores the resolved txid and local signature.
    DIDMetadata_SetSignature(&document->metadata, DIDDocument_GetProofSignature(document, 0));
    if (resolve_signature)
        DIDMetadata_SetPrevSignature(&document->metadata, resolve_signature);

errorExit:
    DIDDocument_Destroy(resolve_doc);
    return rc;

    DIDERROR_FINALIZE();
}

int DIDDocument_TransferDID(DIDDocument *document, TransferTicket *ticket,
        DIDURL *signkey, const char *storepass)
{
    DIDDocument *resolve_doc = NULL;
    DocumentProof *proof;
    DIDStore *store;
    bool equal = false;
    int rc = -1, i, status, check;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to be tranfered.", -1);
    CHECK_ARG(!ticket, "No ticket argument.", -1);
    CHECK_ARG(!signkey, "No signkey argument.", -1);
    CHECK_PASSWORD(storepass, -1);

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with document.");
        return -1;
    }

    store = document->metadata.base.store;
    resolve_doc = DID_Resolve(&document->did, &status, true);
    if (!resolve_doc) {
        if (status == DIDStatus_NotFound)
            DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't transfer DID which isn't published.");
        else
            DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Can't transfer DID which isn't published.");
        return -1;
    }

    if (!DIDDocument_IsCustomizedDID(resolve_doc)) {
        DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't transfer normal DID.");
        goto errorExit;
    }

    check = TransferTicket_IsValid(ticket);
    if (check != 1) {
        if (check == 0)
            DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Ticket isn't valid.");
        goto errorExit;
    }

    if (strcmp(ticket->txid, DIDMetadata_GetTxid(&resolve_doc->metadata))) {
        DIDError_Set(DIDERR_NOT_UPTODATE, "Transaction id of ticket mismatches with the chain one.");
        goto errorExit;
    }

    //check ticket "to"
    for (i = 0; i < document->proofs.size; i++) {
        proof = &document->proofs.proofs[i];
        if (DID_Equals(&ticket->to, &proof->creater.did)) {
            equal = true;
            break;
        }
    }

    if (!equal) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "DID to receive ticket isn't document's signer.");
        goto errorExit;
    }

    check = DIDDocument_IsAuthenticationKey(document, signkey);
    if (check != 1) {
        if (check == 0)
            DIDError_Set(DIDERR_INVALID_KEY, "Signkey isn't authentication key.");
        goto errorExit;
    }

    DIDMetadata_SetTxid(&document->metadata, DIDMetadata_GetTxid(&resolve_doc->metadata));
    rc = DIDBackend_TransferDID(document, ticket, signkey, storepass);
    if (rc != 1)
        goto errorExit;

    ResolveCache_InvalidateDID(&document->did);
    //Meta stores the resolved txid and local signature.
    DIDMetadata_SetSignature(&document->metadata, DIDDocument_GetProofSignature(document, 0));
    if (*resolve_doc->proofs.proofs[0].signatureValue)
        DIDMetadata_SetPrevSignature(&document->metadata, resolve_doc->proofs.proofs[0].signatureValue);

errorExit:
    DIDDocument_Destroy(resolve_doc);
    return rc;

    DIDERROR_FINALIZE();
}

int DIDDocument_DeactivateDID(DIDDocument *document, DIDURL *signkey, const char *storepass)
{
    DIDDocument *resolve_doc, *controllerdoc;
    bool localcopy = false;
    int rc = 0, status;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No document to deactivated.", -1);
    CHECK_PASSWORD(storepass, -1);

    resolve_doc = DID_Resolve(&document->did, &status, true);
    if (!resolve_doc) {
        if (status == DIDStatus_NotFound)
            DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't deactivate did that isn't be pulished.");
        else
            DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Resolve target did failed.");

        return -1;
    }
    DIDDocument_Destroy(resolve_doc);

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with document.");
        return -1;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(document);
        if (!signkey) {
            DIDError_Set(DIDERR_NOT_EXISTS, "No default key to sign.");
            return -1;
        }
    } else {
        if (DIDDocument_IsCustomizedDID(document)) {
            controllerdoc = DIDDocument_GetControllerDocument(document, &signkey->did);
            if (!controllerdoc) {
                DIDError_Set(DIDERR_INVALID_KEY, "Signkey isn't owned to controller of DID.");
                return -1;
            }
        } else {
            controllerdoc = document;
        }

        if (!DIDURL_Equals(signkey, DIDDocument_GetDefaultPublicKey(controllerdoc))) {
            DIDError_Set(DIDERR_INVALID_KEY, "Signkey isn‘t default key.");
            return -1;
        }
    }

    rc = DIDBackend_DeactivateDID(document, signkey, NULL, storepass);
    if (rc == 1)
        ResolveCache_InvalidateDID(&document->did);

    return rc;

    DIDERROR_FINALIZE();
}

int DIDDocument_DeactivateDIDByAuthorizor(DIDDocument *document, DID *target,
        DIDURL *signkey, const char *storepass)
{
    DIDDocument *targetdoc = NULL;
    DIDStore *store;
    PublicKey **candidatepks;
    PublicKey *candidatepk, *pk;
    bool exist = false;
    size_t size;
    int i, j, status, rc = -1;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!document, "No authorizor's document to deactivate did.", -1);
    CHECK_ARG(!target, "No target did.", -1);
    CHECK_PASSWORD(storepass, -1);

    targetdoc = DID_Resolve(target, &status, true);
    if (!targetdoc) {
        if (status == DIDStatus_NotFound)
            DIDError_Set(DIDERR_ILLEGALUSAGE, "Can't deactivate did not be pulished.");
        else
            DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Resolve target did failed.");

        return -1;
    }

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with document.");
        goto errorExit;
    }

    //check signkey
    store = document->metadata.base.store;
    if (!signkey) {
        candidatepks = document->publickeys.pks;
        size = document->publickeys.size;
    } else {
        candidatepks = (PublicKey **)alloca(sizeof(PublicKey*));
        if (!candidatepks) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for candidate publicKeys failed.");
            goto errorExit;
        }
        candidatepks[0] = DIDDocument_GetAuthenticationKey(document, signkey);
        if (!candidatepks[0]) {
            DIDError_Set(DIDERR_INVALID_KEY, "Signkey is not authentication key.");
            goto errorExit;
        }
        size = 1;
    }

    for (i = 0; i < size; i++) {
        candidatepk = candidatepks[i];
        for (j = 0; j < targetdoc->publickeys.size; j++) {
            pk = targetdoc->publickeys.pks[j];
            if (!pk->authorizationKey || !DID_Equals(&document->did, &pk->controller) ||
                    strcmp(candidatepk->publicKeyBase58, pk->publicKeyBase58))
                continue;

            exist = true;
            break;
        }
        if (exist)
            break;
    }

    if (!exist) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No valid authorization key to deactivate did.");
        goto errorExit;
    }

    rc = DIDBackend_DeactivateDID(document, &candidatepk->id, &pk->id, storepass);
    if (rc == 1)
        ResolveCache_InvalidateDID(&document->did);

errorExit:
    DIDDocument_Destroy(targetdoc);
    return rc;

    DIDERROR_FINALIZE();
}

DIDDocumentBuilder* DIDDocument_CreateBuilder(DID *did, DIDDocument *controllerdoc, DIDStore *store)
{
    DIDDocumentBuilder *builder;
    DIDDocument *controller_doc = NULL;

    assert(did);
    assert(store);

    builder = (DIDDocumentBuilder*)calloc(1, sizeof(DIDDocumentBuilder));
    if (!builder) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for document builder failed.");
        return NULL;
    }

    builder->document = (DIDDocument*)calloc(1, sizeof(DIDDocument));
    if (!builder->document) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for document failed.");
        goto errorExit;
    }

    if (!DID_Copy(&builder->document->did, did))
        goto errorExit;

    if (controllerdoc) {
        builder->controllerdoc = (DIDDocument*)calloc(1, sizeof(DIDDocument));
        if (!builder->controllerdoc) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for controller document failed.");
            goto errorExit;
        }

        if (DIDDocument_Copy(builder->controllerdoc, controllerdoc) < 0) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Copy controller document failed.");
            free((void*)builder->controllerdoc);
            goto errorExit;
        }

        if (diddocumentbuilder_addcontroller_internal(builder->document, builder->controllerdoc) < 0)
            goto errorExit;
    }

    DIDDocument_SetStore(builder->document, store);
    return builder;

errorExit:
    DIDDocumentBuilder_Destroy(builder);
    return NULL;
}

static DIDDocument *create_customized_document(DID *did, DID **controllers, size_t size,
        DIDDocument *controllerdoc, int multisig, DIDStore *store, const char *storepass)
{
    DIDDocument *document;
    DIDDocumentBuilder *builder;
    int i;

    assert(did);
    assert(controllerdoc);
    assert(store);
    assert(storepass && *storepass);

    builder = DIDDocument_CreateBuilder(did, controllerdoc, store);
    if (!builder)
        return NULL;

    for (i = 0; i < size; i++) {
        if (DIDDocumentBuilder_AddController(builder, controllers[i]) == -1) {
            DIDDocumentBuilder_Destroy(builder);
            return NULL;
        }
    }

    builder->document->multisig = multisig;

    if (DIDDocumentBuilder_SetExpires(builder, 0) == -1) {
        DIDDocumentBuilder_Destroy(builder);
        return NULL;
    }

    document = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    if (!document)
        return NULL;

    DIDMetadata_SetDeactivated(&document->metadata, false);
    memcpy(&document->did.metadata, &document->metadata, sizeof(DIDMetadata));
    return document;
}

DIDDocument *DIDDocument_NewCustomizedDID(DIDDocument *controllerdoc,
        const char *customizeddid, DID **controllers, size_t size, int multisig,
        bool force, const char *storepass)
{
    DIDDocument *doc;
    DIDStore *store;
    DIDURL *key;
    DID **checkcontrollers = NULL, did;
    int status, i, checksize = 0;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!controllerdoc, "No controller document argument.", NULL);
    CHECK_ARG(!customizeddid || !*customizeddid, "No customized did string.", NULL);
    CHECK_ARG(multisig < 0, "Invalid multisig.", NULL);
    CHECK_PASSWORD(storepass, NULL);

    if (!DIDMetadata_AttachedStore(&controllerdoc->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with controller document.");
        return NULL;
    }

    store = controllerdoc->metadata.base.store;
    if (!controllers && size != 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Please check the size of controlle array.");
        return NULL;
    }

    if (DIDDocument_IsCustomizedDID(controllerdoc)) {
        DIDError_Set(DIDERR_INVALID_CONTROLLER, "The controller must be normal DID.");
        return NULL;
    }

    if (DID_Init(&did, customizeddid) == -1)
        return NULL;

    //check the controllers if it has the same DID and the controller is include in the contrllers.
    if (controllers && size > 0) {
        checkcontrollers = (DID**)alloca(size * sizeof(DID*));
        if (!checkcontrollers) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for check controllers failed.");
            return NULL;
        }

        for (i = 0; i < size; i++) {
            if (DID_Equals(controllers[i], &controllerdoc->did) ||
                    Contains_DID(checkcontrollers, checksize, controllers[i]))
               continue;

            checkcontrollers[checksize++] = controllers[i];
        }
    }

    if (checksize == 0) {
        checkcontrollers = NULL;
    } else {
        if (multisig > checksize + 1) {
            DIDError_Set(DIDERR_INVALID_ARGS, "Please specify multisig which isn't larger than %d.", checksize + 1);
            return NULL;
        }
    }

    //check the DID
    doc = DIDStore_LoadDID(store, &did);
    if (doc) {
        DIDError_Set(DIDERR_ALREADY_EXISTS, "Customized did already exists.");
        DIDDocument_Destroy(doc);
        return NULL;
    }

    if (!force) {
        doc = DID_Resolve(&did, &status, true);
        if (doc) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Customized did already exists.");
            DIDDocument_Destroy(doc);
            return NULL;
        }
    }

    key = DIDDocument_GetDefaultPublicKey(controllerdoc);
    if (!key) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No default key of controller document.");
        return NULL;
    }

    if (!DIDStore_ContainsPrivateKey(store, &controllerdoc->did, key)) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No private key about default key in store.");
        return NULL;
    }

    doc = create_customized_document(&did, checkcontrollers, checksize,
            controllerdoc, multisig, store, storepass);
    if (!doc)
        return NULL;

    if (DIDStore_StoreDID(store, doc) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Store customized document failed.");
        DIDDocument_Destroy(doc);
        return NULL;
    }

    DIDDocument_SetStore(doc, store);
    return doc;

    DIDERROR_FINALIZE();
}

DIDURL *PublicKey_GetId(PublicKey *publickey)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!publickey, "No publickey argument.", NULL);
    return &publickey->id;

    DIDERROR_FINALIZE();
}

DID *PublicKey_GetController(PublicKey *publickey)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!publickey, "No publickey argument.", NULL);
    return &publickey->controller;

    DIDERROR_FINALIZE();
}

const char *PublicKey_GetPublicKeyBase58(PublicKey *publickey)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!publickey, "No publickey argument.", NULL);
    return publickey->publicKeyBase58;

    DIDERROR_FINALIZE();
}

const char *PublicKey_GetType(PublicKey *publickey)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!publickey, "No publickey argument.", NULL);
    return publickey->type;

    DIDERROR_FINALIZE();
}

int PublicKey_IsAuthenticationKey(PublicKey *publickey)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!publickey, "No publickey argument.", -1);
    return publickey->authenticationKey;

    DIDERROR_FINALIZE();
}

int PublicKey_IsAuthorizationKey(PublicKey *publickey)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!publickey, "No publickey argument.", -1);
    return publickey->authorizationKey;

    DIDERROR_FINALIZE();
}

DIDURL *Service_GetId(Service *service)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!service, "No service argument.", NULL);
    return &service->id;

    DIDERROR_FINALIZE();
}

const char *Service_GetEndpoint(Service *service)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!service, "No service argument.", NULL);
    return service->endpoint;

    DIDERROR_FINALIZE();
}

const char *Service_GetType(Service *service)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!service, "No service argument.", NULL);
    return service->type;

    DIDERROR_FINALIZE();
}

ssize_t Service_GetPropertyCount(Service *service)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!service, "No service argument.", -1);
    if (!service->properties)
        return 0;

    return json_object_size(service->properties);

    DIDERROR_FINALIZE();
}

const char *Service_GetProperties(Service *service)
{
    const char *data;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!service, "No service argument.", NULL);
    if (!service->properties)
        return NULL;

    data = json_dumps(service->properties, JSON_COMPACT);
    if (!data)
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Serialize properties to json failed.");

    return data;

    DIDERROR_FINALIZE();
}

const char *Service_GetProperty(Service *service, const char *name)
{
    json_t *item;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!service, "No service argument.", NULL);
    CHECK_ARG(!name || !*name, "No property' key argument.", NULL);

    if (!service->properties)
        return NULL;

    item = json_object_get(service->properties, name);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No this property in subject.");
        return NULL;
    }

    return json_astext(item);

    DIDERROR_FINALIZE();
}

