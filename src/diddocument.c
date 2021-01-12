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
    if (service)
        free(service);
}

static
int PublicKey_ToJson(JsonGenerator *gen, PublicKey *pk, int compact)
{
    char id[ELA_MAX_DIDURL_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(pk);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "id",
        DIDURL_ToString(&pk->id, id, sizeof(id), compact)));
    if (!compact) {
        CHECK(JsonGenerator_WriteStringField(gen, "type", pk->type));
        CHECK(JsonGenerator_WriteStringField(gen, "controller",
                DID_ToString(&pk->controller, id, sizeof(id))));
    } else {
        if (!DID_Equals(&pk->id.did, &pk->controller))
            CHECK(JsonGenerator_WriteStringField(gen, "controller",
                   DID_ToString(&pk->controller, id, sizeof(id))));
    }
    CHECK(JsonGenerator_WriteStringField(gen, "publicKeyBase58", pk->publicKeyBase58));
    CHECK(JsonGenerator_WriteEndObject(gen));

    return 0;
}

static int didurl_func(const void *a, const void *b)
{
    char _stringa[ELA_MAX_DID_LEN], _stringb[ELA_MAX_DID_LEN];
    char *stringa, *stringb;

    PublicKey *keya = *(PublicKey**)a;
    PublicKey *keyb = *(PublicKey**)b;

    stringa = DIDURL_ToString(&keya->id, _stringa, ELA_MAX_DID_LEN, true);
    stringb = DIDURL_ToString(&keyb->id, _stringb, ELA_MAX_DID_LEN, true);

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
    if (!controllers)
        return -1;

    for (i = 0; i < size; i++)
        controllers[i] = DIDDocument_GetSubject(docs[i]);

    qsort(controllers, size, sizeof(DID*), controllers_func);

    if (size != 1)
        CHECK(JsonGenerator_WriteStartArray(gen));

    for (i = 0; i < size; i++ ) {
        CHECK(JsonGenerator_WriteString(gen,
                DID_ToString(controllers[i], _string, sizeof(_string))));
    }

    if (size != 1)
        CHECK(JsonGenerator_WriteEndArray(gen));

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

    CHECK(JsonGenerator_WriteStartArray(gen));
    for (i = 0; i < size; i++ ) {
        char id[ELA_MAX_DIDURL_LEN];

        if ((type == KeyType_Authentication && !PublicKey_IsAuthenticationKey(pks[i])) ||
            (type == KeyType_Authorization && !PublicKey_IsAuthorizationKey(pks[i])))
            continue;

        if (type == KeyType_PublicKey)
            CHECK(PublicKey_ToJson(gen, pks[i], compact));
        else
            CHECK(JsonGenerator_WriteString(gen,
                DIDURL_ToString(&pks[i]->id, id, sizeof(id), compact)));
    }
    CHECK(JsonGenerator_WriteEndArray(gen));

    return 0;
}

static int Service_ToJson(JsonGenerator *gen, Service *service, int compact)
{
    char id[ELA_MAX_DIDURL_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(service);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "id",
        DIDURL_ToString(&service->id, id, sizeof(id), compact)));
    CHECK(JsonGenerator_WriteStringField(gen, "type", service->type));
    CHECK(JsonGenerator_WriteStringField(gen, "serviceEndpoint", service->endpoint));
    CHECK(JsonGenerator_WriteEndObject(gen));

    return 0;
}

static
int ServiceArray_ToJson(JsonGenerator *gen, Service **services, size_t size,
        int compact)
{
    size_t i;

    assert(gen);
    assert(gen->buffer);
    assert(services);
    CHECK(JsonGenerator_WriteStartArray(gen));
    for ( i = 0; i < size; i++ ) {
        CHECK(Service_ToJson(gen, services[i], compact));
    }
    CHECK(JsonGenerator_WriteEndArray(gen));

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

    CHECK(JsonGenerator_WriteStartObject(gen));
    if (!compact)
        CHECK(JsonGenerator_WriteStringField(gen, "type", proof->type));
    CHECK(JsonGenerator_WriteStringField(gen, "created",
            get_time_string(_timestring, sizeof(_timestring), &proof->created)));
    if (!compact || !DID_Equals(&document->did, &proof->creater.did))
        CHECK(JsonGenerator_WriteStringField(gen, "creator",
                DIDURL_ToString(&proof->creater, id, sizeof(id), false)));

    CHECK(JsonGenerator_WriteStringField(gen, "signatureValue", proof->signatureValue));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

static int proof_cmp(const void *a, const void *b)
{
    DocumentProof *proofa = (DocumentProof*)a;
    DocumentProof *proofb = (DocumentProof*)b;

    return (int)(proofa->created - proofb->created);
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
        CHECK(JsonGenerator_WriteStartArray(gen));

    qsort(proofs, size, sizeof(DocumentProof), proof_cmp);

    for (i = 0; i < size; i++)
        CHECK(Proof_ToJson(gen, &proofs[i], document, compact));

    if (size > 1)
        CHECK(JsonGenerator_WriteEndArray(gen));

    return 0;
}

//api don't check if pk is existed in array.
static int add_to_publickeys(DIDDocument *document, PublicKey *pk)
{
    PublicKey **pks, **pk_array;

    assert(document);
    assert(pk);

    pk_array = document->publickeys.pks;

    if (!pk_array)
        pks = (PublicKey**)calloc(1, sizeof(PublicKey*));
    else
        pks = realloc(pk_array,
                     (document->publickeys.size + 1) * sizeof(PublicKey*));

    if (!pks) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Remalloc buffer for public keys failed.");
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

    field = json_object_get(json, "id");
    if (!field) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing public key id.");
        PublicKey_Destroy(pk);
        return -1;
    }

    if (!json_is_string(field) || Parse_DIDURL(&pk->id, json_string_value(field), did) < 0) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid public key id.");
        PublicKey_Destroy(pk);
        return -1;
    }

    assert(strcmp(did->idstring, pk->id.did.idstring) == 0);

    // set default value for 'type'
    strcpy(pk->type, ProofType);

    field = json_object_get(json, "publicKeyBase58");
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
    field = json_object_get(json, "controller");
    if (field) {
        if (!json_is_string(field) || Parse_DID(&pk->controller, json_string_value(field)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid publicKey controller.");
            PublicKey_Destroy(pk);
            return -1;
        }
    }

    if (!field) { // the controller is self did.
        strcpy(pk->controller.idstring, did->idstring);
        *publickey = pk;
        return 0;
    }

    *publickey = pk;
    return 0;
}

static int Parse_Controllers(DIDDocument *document, json_t *json)
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
        if (Parse_DID(&controller, json_string_value(field)) < 0) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Create controller failed.");
            return -1;
        }

        controllerdoc = DID_Resolve(&controller, &status, true);
        if (!controllerdoc)
            return -1;

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
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Public key array is empty.");
        return -1;
    }

    //parse public key(required)
    PublicKey **pks = (PublicKey**)calloc(pk_size, sizeof(PublicKey*));
    if (!pks) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for public keys failed.");
        return -1;
    }

    for (i = 0; i < pk_size; i++) {
        json_t *pk_item, *id_field, *base_field;
        PublicKey *pk;

        pk_item = json_array_get(json, i);
        if (!pk_item)
            continue;

        //check public key's format
        id_field = json_object_get(pk_item, "id");
        base_field = json_object_get(pk_item, "publicKeyBase58");
        if (!id_field || !base_field)              //(required and can't default)
            continue;

        if (Parse_PublicKey(did, pk_item, &pk) == -1)
            continue;

        pks[size++] = pk;
    }

    if (!size) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No invalid public key.");
        free(pks);
        return -1;
    }

    document->publickeys.pks = pks;
    document->publickeys.size = size;

    return 0;
}

static
int Parse_Auth_PublicKeys(DIDDocument *document, json_t *json, KeyType type)
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

        id_field = json_object_get(pk_item, "id");
        if (!id_field) {
            if (Parse_DIDURL(&id, json_string_value(pk_item), &document->did) < 0)
                continue;

            pk = DIDDocument_GetPublicKey(document, &id);
            if (!pk) {
                DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Auth key is not in pulic keys.");
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

        field = json_object_get(item, "id");
        if (!field || !json_is_string(field)) {
            Service_Destroy(service);
            continue;
        }

        if (Parse_DIDURL(&service->id, json_string_value(field), &document->did) < 0) {
            Service_Destroy(service);
            continue;
        }

        if (!*service->id.did.idstring)
            strcpy(service->id.did.idstring, document->did.idstring);

        field = json_object_get(item, "type");
        if (!field || !json_is_string(field)) {
            Service_Destroy(service);
            continue;
        }
        strcpy(service->type, json_string_value(field));

        field = json_object_get(item, "serviceEndpoint");
        if (!field || !json_is_string(field)) {
            Service_Destroy(service);
            continue;
        }
        strcpy(service->endpoint, json_string_value(field));

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

        field = json_object_get(item, "type");
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

        field = json_object_get(item, "created");
        if (!field) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing create document time.");
            return -1;
        }
        if (!json_is_string(field) ||
                parse_time(&proof->created, json_string_value(field)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid create document time.");
            return -1;
        }

        field = json_object_get(item, "creator");
        if (field) {
            if (!json_is_string(field) ||
                    Parse_DIDURL(&proof->creater, json_string_value(field), &document->did) == -1) {
                DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid document creater.");
                return -1;
            }
        }

        if (!field && (!DIDDocument_GetDefaultPublicKey(document) ||
                !DIDURL_Copy(&proof->creater, DIDDocument_GetDefaultPublicKey(document)))) {
            DIDError_Set(DIDERR_MALFORMED_DIDURL, "Set document creater failed.");
            return -1;
        }

        field = json_object_get(item, "signatureValue");
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
    size_t size, i;

    assert(document);
    assert(keyid);

    size = document->publickeys.size;
    pks = document->publickeys.pks;

    if (!Is_CustomizedDID(document) && size == 1) {
        DIDError_Set(DIDERR_INVALID_KEY, "Can't remove the last publickey.");
        return -1;
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

        if (DIDMetaData_AttachedStore(&document->metadata))
            DIDStore_DeletePrivateKey(document->metadata.base.store, &document->did, keyid);

        return 0;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "No this public key.");
    return -1;
}

static int Parse_Credentials_InDoc(DIDDocument *document, json_t *json)
{
    size_t size = 0;

    assert(document);
    assert(json);

    size = json_array_size(json);
    if (size <= 0) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Credential array is empty.");
        return -1;
    }

    Credential **credentials = (Credential**)calloc(size, sizeof(Credential*));
    if (!credentials) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credentials failed.");
        return -1;
    }

    size = Parse_Credentials(DIDDocument_GetSubject(document), credentials, size, json);
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

static size_t get_self_authentication_count(DIDDocument *document)
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

bool Is_CustomizedDID(DIDDocument *document)
{
    DIDURL *signkey;

    assert(document);

    signkey = DIDDocument_GetDefaultPublicKey(document);
    if (signkey && DID_Equals(&signkey->did, &document->did))
        return false;

    return true;
}

bool controllers_check(DIDDocument *document)
{
    int i;

    assert(document);
    assert((document->controllers.size > 0 && document->controllers.docs) ||
            (document->controllers.size == 0 && !document->controllers.docs));

    if (!Is_CustomizedDID(document) && document->controllers.size > 0) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Normal DID should not have controller.");
        return false;
    }

    if (Is_CustomizedDID(document)) {
        if (document->controllers.size == 0) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Customized DID must have one controller at least.");
            return false;
        }

        for (i = 0; i < document->controllers.size; i++) {
            if (Is_CustomizedDID(document->controllers.docs[i])) {
                DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "The controller must be normal DID.");
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
DIDDocument *DIDDocument_FromJson_Internal(json_t *root)
{
    DIDDocument *doc;
    json_t *item;
    int m, n;

    assert(root);

    doc = (DIDDocument*)calloc(1, sizeof(DIDDocument));
    if (!doc) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for document failed.");
        return NULL;
    }

    item = json_object_get(root, "id");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing document subject.");
        goto errorExit;
    }
    if (!json_is_string(item) ||
            Parse_DID(&doc->did, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid document subject.");
        goto errorExit;
    }

    //parse constroller
    item = json_object_get(root, "controller");
    if (item) {
        if (!json_is_string(item) && !json_is_array(item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid controller.");
            goto errorExit;
        }
        if (Parse_Controllers(doc, item) == -1)
            goto errorExit;
    }

    //parser multisig
    item = json_object_get(root, "multisig");
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
    item = json_object_get(root, "publicKey");
    if (!doc->controllers.size && !item) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing publickey.");
        goto errorExit;
    }
    if (item && !json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid publickey.");
        goto errorExit;
    }
    if (item && Parse_PublicKeys(doc, &doc->did, item) < 0)
        goto errorExit;

    //parse authentication
    item = json_object_get(root, "authentication");
    if (!doc->controllers.size && !item) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing authentication key.");
        goto errorExit;
    }
    if (item && !json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid authentication key.");
        goto errorExit;
    }
    if (item && Parse_Auth_PublicKeys(doc, item, KeyType_Authentication) < 0)
        goto errorExit;

    //parse authorization
    item = json_object_get(root, "authorization");
    if (item) {
        if (!json_is_array(item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid authorization key.");
            goto errorExit;
        }
        if (Parse_Auth_PublicKeys(doc, item, KeyType_Authorization) < 0)
            goto errorExit;
    }

    //parse expires
    item = json_object_get(root, "expires");
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
    item = json_object_get(root, "verifiableCredential");
    if (item) {
        if (!json_is_array(item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid credentials.");
            goto errorExit;
        }
        if (Parse_Credentials_InDoc(doc, item) < 0)
            goto errorExit;
    }

    //parse services
    item = json_object_get(root, "service");
    if (item) {
        if (!json_is_array(item)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid services.");
            goto errorExit;
        }
        if (Parse_Services(doc, item) < 0)
            goto errorExit;
    }

    item = json_object_get(root, "proof");
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
    if (!controllers_check(doc))
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

    if (!json) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    root = json_loads(json, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Deserialize document failed, error: %s.", error.text);
        return NULL;
    }

    doc = DIDDocument_FromJson_Internal(root);
    json_decref(root);
    return doc;
}

int DIDDocument_ToJson_Internal(JsonGenerator *gen, DIDDocument *doc,
        bool compact, bool forsign)
{
    char id[ELA_MAX_DIDURL_LEN], _timestring[DOC_BUFFER_LEN];
    char multisig[32] = {0};

    assert(gen);
    assert(gen->buffer);
    assert(doc);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "id",
            DID_ToString(&doc->did, id, sizeof(id))));
    if (doc->controllers.size > 0) {
        CHECK(JsonGenerator_WriteFieldName(gen, "controller"));
        CHECK(ControllerArray_ToJson(gen, doc->controllers.docs, doc->controllers.size));
    }
    if (doc->controllers.size > 1)
        CHECK(JsonGenerator_WriteStringField(gen, "multisig",
                format_multisig(multisig, sizeof(multisig), doc->multisig, doc->controllers.size)));

    if (doc->publickeys.size > 0) {
        CHECK(JsonGenerator_WriteFieldName(gen, "publicKey"));
        CHECK(PublicKeyArray_ToJson(gen, doc->publickeys.pks, doc->publickeys.size,
                compact, KeyType_PublicKey));

        if (get_self_authentication_count(doc) > 0) {
            CHECK(JsonGenerator_WriteFieldName(gen, "authentication"));
            CHECK(PublicKeyArray_ToJson(gen, doc->publickeys.pks, doc->publickeys.size,
                    compact, KeyType_Authentication));
        }

        if (get_self_authorization_count(doc) > 0) {
            CHECK(JsonGenerator_WriteFieldName(gen, "authorization"));
            CHECK(PublicKeyArray_ToJson(gen, doc->publickeys.pks,
                    doc->publickeys.size, compact, KeyType_Authorization));
        }
    }

    if (doc->credentials.size > 0) {
        CHECK(JsonGenerator_WriteFieldName(gen, "verifiableCredential"));
        CHECK(CredentialArray_ToJson(gen, doc->credentials.credentials,
                doc->credentials.size, &doc->did, compact));
    }

    if (doc->services.size > 0) {
        CHECK(JsonGenerator_WriteFieldName(gen, "service"));
        CHECK(ServiceArray_ToJson(gen, doc->services.services,
                doc->services.size, compact));
    }

    CHECK(JsonGenerator_WriteStringField(gen, "expires",
            get_time_string(_timestring, sizeof(_timestring), &doc->expires)));
    if (!forsign) {
        CHECK(JsonGenerator_WriteFieldName(gen, "proof"));
        CHECK(ProofArray_ToJson(gen, doc, compact));
    }
    CHECK(JsonGenerator_WriteEndObject(gen));

    return 0;
}

static const char *diddocument_tojson_forsign(DIDDocument *document, bool compact, bool forsign)
{
    JsonGenerator g, *gen;

    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    gen = JsonGenerator_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator initialize failed.");
        return NULL;
    }

    if (DIDDocument_ToJson_Internal(gen, document, compact, forsign) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize DID document to json failed.");
        JsonGenerator_Destroy(gen);
        return NULL;
    }

    return JsonGenerator_Finish(gen);
}

const char *DIDDocument_ToJson(DIDDocument *document, bool normalized)
{
    return diddocument_tojson_forsign(document, !normalized, false);
}

const char *DIDDocument_ToString(DIDDocument *document, bool normalized)
{
    const char *data;
    json_t *json;
    json_error_t error;

    if (!document){
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

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
}

void DIDDocument_Destroy(DIDDocument *document)
{
    size_t i;

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

    DIDMetaData_Free(&document->metadata);
    free(document);
}

int DIDDocument_SaveMetaData(DIDDocument *document)
{
    if (document && DIDMetaData_AttachedStore(&document->metadata))
        return DIDStore_StoreDIDMetaData(document->metadata.base.store, &document->metadata, &document->did);

    return 0;
}

DIDMetaData *DIDDocument_GetMetaData(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &document->metadata;
}

ssize_t DIDDocument_GetProofCount(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return document->proofs.size;
}

const char *DIDDocument_GetProofType(DIDDocument *document, int index)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (index >= document->proofs.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Index is larger than the count of proofs.");
        return NULL;
    }

    return document->proofs.proofs[index].type;
}

DIDURL *DIDDocument_GetProofCreater(DIDDocument *document, int index)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (index >= document->proofs.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Index is larger than the count of proofs.");
        return NULL;
    }

    return &document->proofs.proofs[index].creater;
}

time_t DIDDocument_GetProofCreatedTime(DIDDocument *document, int index)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    if (index >= document->proofs.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Index is larger than the count of proofs.");
        return 0;
    }

    return document->proofs.proofs[index].created;
}

const char *DIDDocument_GetProofSignature(DIDDocument *document, int index)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (index >= document->proofs.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Index is larger than the count of proofs.");
        return NULL;
    }

    return document->proofs.proofs[index].signatureValue;
}

bool DIDDocument_IsDeactivated(DIDDocument *document)
{
    DIDDocument *resolvedoc;
    bool isdeactived;
    int status;

    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return true;
    }

    isdeactived = DIDMetaData_GetDeactivated(&document->metadata);
    if (isdeactived)
        return isdeactived;

    resolvedoc = DID_Resolve(&document->did, &status, true);
    if (!resolvedoc)
        return false;

    isdeactived = DIDMetaData_GetDeactivated(&resolvedoc->metadata);
    if (isdeactived)
        goto storeexit;

    //todo: check the controller deactivated or not ????
    /*if (document->controllers.size && document->controllers.docs) {
        controller_doc = DID_Resolve(document->controller, true);
        if (!controller_doc) {
            isdeactived = true;
            goto storeexit;
        }

        if (document->controllerdoc)
            DIDDocument_Destroy(document->controllerdoc);
        document->controllerdoc = controller_doc;

        isdeactived = DIDMetaData_GetDeactivated(&controller_doc->metadata);
        if (isdeactived)
            goto storeexit;
    }*/

storeexit:
    if (isdeactived) {
        DIDMetaData_SetDeactivated(&resolvedoc->metadata, true);
        DIDDocument_SaveMetaData(resolvedoc);
    }

    DIDDocument_Destroy(resolvedoc);
    return isdeactived;
}

static bool contains_did(DID **dids, size_t size, DID *did)
{
    int i;

    assert(dids);
    assert(did);

    for (i = 0; i < size; i++) {
        if (DID_Equals(dids[i], did))
            return true;
    }

    return false;
}

static bool DIDDocument_IsGenuine_Internal(DIDDocument *document, bool isqualified)
{
    DIDDocument *proof_doc;
    DocumentProof *proof;
    DID **checksigners;
    const char *data;
    bool isgenuine = false;
    size_t size;
    int i;

    assert(document);

    if (isqualified && !DIDDocument_IsQualified(document)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "The signers are less than multisig number.");
        return false;
    }

    if (document->controllers.size > 0) {
        for(i = 0; i < document->controllers.size; i++) {
            if (!DIDDocument_IsGenuine(document->controllers.docs[i]))
                return false;
        }
    }

    data = diddocument_tojson_forsign(document, false, true);
    if (!data)
        return false;

    size = document->proofs.size;
    checksigners = (DID**)alloca(size * sizeof(DID*));
    if (!checksigners) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for signers failed.");
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
                DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "The signer is not the controller.");
                goto errorExit;
            }
        }

        if (contains_did(checksigners, i, &proof->creater.did)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "There is the same controller signed document two times.");
            goto errorExit;
        }

        if (strcmp(proof->type, ProofType)) {
            DIDError_Set(DIDERR_UNKNOWN, "Unsupported public key type.");
            goto errorExit;
        }

        if (!DIDURL_Equals(DIDDocument_GetDefaultPublicKey(proof_doc), &proof->creater)) {
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT,
                    "The sign key is not controller's default key.");
            goto errorExit;
        }

        if (DIDDocument_Verify(proof_doc, &proof->creater, proof->signatureValue, 1,
                data, strlen(data)) < 0)
            goto errorExit;

        checksigners[i] = &proof->creater.did;
    }

    isgenuine = true;

errorExit:
    free((void*)data);
    return isgenuine;
}

bool DIDDocument_IsGenuine(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return DIDDocument_IsGenuine_Internal(document, true);
}

bool DIDDocument_IsExpired(DIDDocument *document)
{
    time_t curtime;

    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return true;
    }

    curtime = time(NULL);
    if (curtime > document->expires)
        return true;

    return false;
}

bool DIDDocument_IsQualified(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return document->proofs.size == (document->controllers.size > 1 ? document->multisig : 1) ? true : false;
}

bool DIDDocument_IsValid_Internal(DIDDocument *document, bool isqualified)
{
    assert(document);

    if (!controllers_check(document))
        return false;

    if (DIDDocument_IsExpired(document)) {
        DIDError_Set(DIDERR_EXPIRED, "Did is expired.");
        return false;
    }

    if (DIDDocument_IsDeactivated(document)) {
        DIDError_Set(DIDERR_DID_DEACTIVATED, "Did is deactivated.");
        return false;
    }

    if (!DIDDocument_IsGenuine_Internal(document, isqualified))
        return false;

    return true;
}

bool DIDDocument_IsValid(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return DIDDocument_IsValid_Internal(document, true);
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
        memcpy(service, services[i], sizeof(Service));
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
    DIDDocument **documents;
    int i, j;

    assert(document);
    assert(docs);
    assert(size >= 0);

    if (size == 0)
        return 0;

    documents = (DIDDocument**)calloc(size, sizeof(DIDDocument*));
    if (!documents)
        return -1;

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
    DIDMetaData_Copy(&destdoc->metadata, &srcdoc->metadata);
    DIDMetaData_SetLastModified(&destdoc->metadata, 0);
    memcpy(&destdoc->did.metadata, &destdoc->metadata, sizeof(DIDMetaData));
    return 0;
}

DIDDocumentBuilder* DIDDocument_Edit(DIDDocument *document, DIDDocument *controllerdoc)
{
    DIDDocumentBuilder *builder;

    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (Is_CustomizedDID(document) && document->controllers.size > 1 && !controllerdoc) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Specify the controller to edit multi-controller customized DID.");
        return NULL;
    }

    if (!Is_CustomizedDID(document) && controllerdoc) {
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
        builder->controllerdoc = (DIDDocument*)calloc(1, sizeof(DIDDocument));
        if (!builder->controllerdoc) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for controller document failed.");
            DIDDocumentBuilder_Destroy(builder);
            return NULL;
        }

        if (DIDDocument_Copy(builder->controllerdoc, controllerdoc) == -1) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Controller document copy failed.");
            DIDDocumentBuilder_Destroy(builder);
            return NULL;
        }
    }

    return builder;
}

void DIDDocumentBuilder_Destroy(DIDDocumentBuilder *builder)
{
    if (!builder)
        return;

    if (builder->document)
        DIDDocument_Destroy(builder->document);
    if (builder->controllerdoc)
        DIDDocument_Destroy(builder->controllerdoc);

    free(builder);
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
        if (DID_Equals(&doc->did, controller))
            return doc;
    }

    return NULL;
}

static int diddocument_addproof(DIDDocument *document, char *signature, DIDURL *signkey, time_t created)
{
    int i;
    size_t size;
    DocumentProof *dp;

    assert(document);
    assert(signature);
    assert(signkey);

    size = document->proofs.size;
    dp = document->proofs.proofs;
    for (i = 0; i < size && dp; i++) {
        DocumentProof *p = &dp[i];
        if (DID_Equals(&p->creater.did, &signkey->did)) {
            DIDError_Set(DIDERR_INVALID_KEY, "The signkey already exist.");
            return -1;
        }
    }

    if (!dp)
        document->proofs.proofs = (DocumentProof*)calloc(1, sizeof(DocumentProof));
    else
        document->proofs.proofs = realloc(dp, (document->proofs.size + 1) * sizeof(DocumentProof));

    if (!document->proofs.proofs)
        return -1;

    strcpy(document->proofs.proofs[size].signatureValue, signature);
    strcpy(document->proofs.proofs[size].type, ProofType);
    DIDURL_Copy(&document->proofs.proofs[size].creater, signkey);
    document->proofs.proofs[size].created = created;
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

    if (!builder || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    doc = builder->document;
    controllerdoc = builder->controllerdoc;
    assert((doc->controllers.size > 0 && doc->controllers.docs) ||
            (doc->controllers.size == 0 && !doc->controllers.docs));

    //check controller document and multisig
    if (!Is_CustomizedDID(doc)) {
        if (controllerdoc) {
            DIDError_Set(DIDERR_INVALID_CONTROLLER, "Don't specify the controller to seal normal DID.");
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
                DIDError_Set(DIDERR_INVALID_CONTROLLER, "Please specify the controller to seal multi-controller DID Document.");
                return NULL;
            } else {
                controllerdoc = doc->controllers.docs[0];
                DIDMetaData_SetStore(&controllerdoc->metadata, doc->metadata.base.store);
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
        DIDError_Set(DIDERR_INVALID_CONTROLLER, "The signers are enough.");
        return NULL;
    }

    for (i = 0; i < doc->proofs.size; i++) {
        if (DID_Equals(&controllerdoc->did, &doc->proofs.proofs[i].creater.did)) {
            DIDError_Set(DIDERR_INVALID_CONTROLLER, "The controller already signed the DID.");
            return NULL;
        }
    }

    //get sign key
    key = DIDDocument_GetDefaultPublicKey(signdoc);
    if (!key) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Signer has no default key.");
        return NULL;
    }

    //check credential
    for (i = 0; i < doc->credentials.size; i++) {
        cred = doc->credentials.credentials[i];
        if (!Credential_IsValid_Internal(cred, doc))
            return NULL;
    }

    //check and get document data
    if (!DIDDocument_IsValid_Internal(doc, false))
        return NULL;

    data = diddocument_tojson_forsign(doc, false, true);
    if (!data)
        return NULL;

    rc = DIDDocument_Sign(signdoc, key, storepass, signature, 1, (unsigned char*)data, strlen(data));
    free((void*)data);
    if (rc)
        return NULL;

    if (diddocument_addproof(doc, signature, key, time(NULL)) < 0)
        return NULL;

    builder->document = NULL;
    return doc;
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
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for public key failed.");
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

    if (!builder || !builder->document || !keyid || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (strlen(key) >= MAX_PUBLICKEY_BASE58) {
        DIDError_Set(DIDERR_INVALID_KEY, "public key is too long.");
        return -1;
    }
    //check base58 is valid
    if (base58_decode(binkey, sizeof(binkey), key) != PUBLICKEY_BYTES) {
        DIDError_Set(DIDERR_INVALID_KEY, "Decode public key failed.");
        return -1;
    }

    //check keyid is existed in pk array
    document = builder->document;
    if (!DID_Equals(&document->did, DIDURL_GetDid(keyid))) {
        DIDError_Set(DIDERR_INVALID_KEY, "The key id does not owned by this DID.");
        return -1;
    }

    for (i = 0; i < document->publickeys.size; i++) {
        pk = document->publickeys.pks[i];
        if (DIDURL_Equals(&pk->id, keyid) ||
               !strcmp(pk->publicKeyBase58, key)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Public key already exist");
            return -1;
        }
    }

    if (!controller)
        controller = DIDDocument_GetSubject(document);

    pk = create_publickey(keyid, controller, key, KeyType_PublicKey);
    if (!pk)
        return -1;

    if (add_to_publickeys(document, pk) == -1) {
        PublicKey_Destroy(pk);
        return -1;
    }

    clean_proofs(document);
    return 0;
}

int DIDDocumentBuilder_RemovePublicKey(DIDDocumentBuilder *builder, DIDURL *keyid, bool force)
{
    DIDDocument* document;
    DIDURL *key;

    if (!builder || !builder->document || !keyid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    key = DIDDocument_GetDefaultPublicKey(document);
    if (key && DIDURL_Equals(key, keyid)) {
        DIDError_Set(DIDERR_INVALID_KEY, "Can't remove default key!!!!");
        return -1;
    }

    if (!force && (DIDDocument_IsAuthenticationKey(document, keyid) ||
            DIDDocument_IsAuthorizationKey(document, keyid))) {
        DIDError_Set(DIDERR_INVALID_KEY, "Can't remove authenticated or authoritied key!!!!");
        return -1;
    }

    if (!DID_Equals(&document->did, DIDURL_GetDid(keyid))) {
        DIDError_Set(DIDERR_INVALID_KEY, "Can't remove other DID's key or controller's key!!!!");
        return -1;
    }

    if (remove_publickey(document, keyid) < 0)
        return -1;

    clean_proofs(document);
    return 0;
}

//authentication keys are all did's own key.
int DIDDocumentBuilder_AddAuthenticationKey(DIDDocumentBuilder *builder,
        DIDURL *keyid, const char *key)
{
    DIDDocument *document;
    PublicKey *pk;
    uint8_t binkey[PUBLICKEY_BYTES];
    DID *controller;

    if (!builder || !builder->document || !keyid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }
    if (key && strlen (key) >= MAX_PUBLICKEY_BASE58) {
        DIDError_Set(DIDERR_INVALID_KEY, "Authentication key is too long.");
        return -1;
    }

    if (key && base58_decode(binkey, sizeof(binkey), key) != PUBLICKEY_BYTES) {
        DIDError_Set(DIDERR_INVALID_KEY, "Decode authentication key failed.");
        return -1;
    }

    document = builder->document;
    if (!DID_Equals(&document->did, DIDURL_GetDid(keyid))) {
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

    controller = DIDDocument_GetSubject(document);
    if (!controller)
        return -1;

    pk = create_publickey(keyid, controller, key, KeyType_Authentication);
    if (!pk)
        return -1;

    if (add_to_publickeys(document, pk) < 0) {
        PublicKey_Destroy(pk);
        return -1;
    }

    clean_proofs(document);
    return 0;
}

int DIDDocumentBuilder_RemoveAuthenticationKey(DIDDocumentBuilder *builder, DIDURL *keyid)
{
    DIDDocument *document;
    DIDURL *key;
    PublicKey *pk;

    if (!builder || !builder->document || !keyid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    key = DIDDocument_GetDefaultPublicKey(document);
    if (key && DIDURL_Equals(key, keyid)) {
        DIDError_Set(DIDERR_INVALID_KEY, "Can't remove default key!!!!");
        return -1;
    }

    if (!DID_Equals(&document->did, DIDURL_GetDid(keyid))) {
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
}

bool DIDDocument_IsAuthenticationKey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey *pk;

    if (!document || !keyid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk)
        return false;

    return pk->authenticationKey;
}

bool DIDDocument_IsAuthorizationKey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey *pk;

    if (!document || !keyid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk)
        return false;

    return pk->authorizationKey;
}

int DIDDocumentBuilder_AddAuthorizationKey(DIDDocumentBuilder *builder, DIDURL *keyid,
        DID *controller, const char *key)
{
    DIDDocument *document;
    PublicKey *pk = NULL;
    uint8_t binkey[PUBLICKEY_BYTES];

    if (!builder || !builder->document || !keyid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    if (Is_CustomizedDID(document)) {
        DIDError_Set(DIDERR_UNSUPPOTED, "The customized did doesn't support authorization key.");
        return -1;
    }

    if (!DID_Equals(&document->did, DIDURL_GetDid(keyid))) {
        DIDError_Set(DIDERR_INVALID_KEY, "The key id does not owned by this DID.");
        return -1;
    }

    if (controller && DID_Equals(controller, DIDDocument_GetSubject(document))) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Key cannot used for authorizating.");
        return -1;
    }

    if (key && base58_decode(binkey, sizeof(binkey), key) != PUBLICKEY_BYTES) {
        DIDError_Set(DIDERR_INVALID_KEY, "Decode public key failed.");
        return -1;
    }

    //check new authentication key is exist in publickeys
    pk = DIDDocument_GetPublicKey(document, keyid);
    if (pk) {
        if (key && strcmp(pk->publicKeyBase58, key)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Public key already exist.");
            return -1;
        }
        if (controller &&!DID_Equals(controller, &pk->controller)) {
            DIDError_Set(DIDERR_UNSUPPOTED, "Public key cannot used for authorization.");
            return -1;
        }

        if (pk->authenticationKey || pk->authorizationKey) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Public key is already authentication key or authorization key.");
            return -1;
        }

        pk->authorizationKey = true;
        clean_proofs(document);
        return 0;
    }

    if (!controller || !key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Missing controller or public key argument.");
        return -1;
    }

    pk = create_publickey(keyid, controller, key, KeyType_Authorization);
    if (!pk)
        return -1;

    if (add_to_publickeys(document, pk) == -1) {
        PublicKey_Destroy(pk);
        return -1;
    }

    clean_proofs(document);
    return 0;
}

int DIDDocumentBuilder_AuthorizationDid(DIDDocumentBuilder *builder, DIDURL *keyid,
        DID *controller, DIDURL *authorkeyid)
{
    DIDDocument *doc, *document;
    PublicKey *pk;
    int rc, status;

    if (!builder || !builder->document || !keyid || !controller) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    if (!DID_Equals(&document->did, DIDURL_GetDid(keyid))) {
        DIDError_Set(DIDERR_INVALID_KEY, "The key id does not owned by this DID.");
        return -1;
    }

    if (DID_Equals(controller, DIDDocument_GetSubject(document))) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Key cannot used for authorizating.");
        return -1;
    }

    doc = DID_Resolve(controller, &status, false);
    if (!doc)
        return -1;

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
}

int DIDDocumentBuilder_RemoveAuthorizationKey(DIDDocumentBuilder *builder, DIDURL *keyid)
{
    DIDDocument *document;
    PublicKey *pk;
    DIDURL *key;

    if (!builder || !builder->document || !keyid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    key = DIDDocument_GetDefaultPublicKey(document);
    if (key && DIDURL_Equals(key, keyid)) {
        DIDError_Set(DIDERR_INVALID_KEY, "Can't remove default key!!!!");
        return -1;
    }

    if (!DID_Equals(&document->did, DIDURL_GetDid(keyid))) {
        DIDError_Set(DIDERR_INVALID_KEY, "Can't remove other DID's authentication key!!!!");
        return -1;
    }

    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk)
        return -1;

    pk->authorizationKey = false;
    clean_proofs(document);
    return 0;
}

static int diddocument_addcredential(DIDDocument *document, Credential *credential)
{
    Credential **creds;

    assert(document);
    assert(credential);

    if (document->credentials.size == 0)
        creds = (Credential**)calloc(1, sizeof(Credential*));
    else
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

int DIDDocumentBuilder_AddController(DIDDocumentBuilder *builder, DID *controller)
{
    DIDDocument **docs;
    DIDDocument *controllerdoc, *document;
    int i, status;

    if (!builder || !builder->document || !controller) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    //check the normal DID or customized DID
    if (!Is_CustomizedDID(document)) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Unsupported add controller into normal DID.");
        return -1;
    }

    if (DID_Equals(DIDDocument_GetSubject(document), controller)) {
        DIDError_Set(DIDERR_UNSUPPOTED, "DIDDocument does not controlled by itself.");
        return -1;
    }

    for (i = 0; i < document->controllers.size && document->controllers.docs; i++) {
        if (document->controllers.docs[i] && DID_Equals(&document->controllers.docs[i]->did, controller)) {
            DIDError_Set(DIDERR_UNSUPPOTED, "The controller already exists in the document.");
            return -1;
        }
    }

    controllerdoc = DID_Resolve(controller, &status, true);
    if (!controllerdoc)
        return -1;

    if (Is_CustomizedDID(controllerdoc)) {
        DIDDocument_Destroy(controllerdoc);
        DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport adding the customized did as a controller.");
        return -1;
    }

    if (document->controllers.size == 0)
        docs = (DIDDocument**)calloc(1, sizeof(DIDDocument*));
    else
        docs = (DIDDocument**)realloc(document->controllers.docs,
                (document->controllers.size + 1) * sizeof(DIDDocument*));

    if (!docs) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for controllers failed.");
        DIDDocument_Destroy(controllerdoc);
        return -1;
    }

    docs[document->controllers.size++] = controllerdoc;
    document->controllers.docs = docs;

    document->multisig = 0;
    clean_proofs(document);
    return 0;
}

int DIDDocumentBuilder_RemoveController(DIDDocumentBuilder *builder, DID *controller)
{
    DIDDocument *document, *controller_doc;
    Credential *cred;
    size_t size;
    int i, j;

    if (!builder || !builder->document || !controller) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    if (!Is_CustomizedDID(document)) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Normal DID is no controller.");
        return -1;
    }

    assert(builder->controllerdoc);
    if (DID_Equals(controller, &builder->controllerdoc->did)) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Can't remove the controller specified to seal document builder.");
        return -1;
    }

    size = DIDDocument_GetControllerCount(document);
    for (i = 0; i < size; i++) {
        controller_doc = document->controllers.docs[i];
        if (!DID_Equals(controller, &controller_doc->did))
            continue;

        if (size == 1) {
            DIDError_Set(DIDERR_UNSUPPOTED, "Can't remove the last controller.");
            return -1;
        }

        //check if credential is signed by controller.
        for (j = 0; j < document->credentials.size; j++) {
            cred = document->credentials.credentials[j];
            if (Credential_IsSelfProclaimed(cred) &&
                    DID_Equals(controller, &cred->proof.verificationMethod.did)) {
                DIDError_Set(DIDERR_UNSUPPOTED,
                        "There are self-proclaimed credentials signed by controller, please remove or renew these credentials at first.");
                return -1;
            }
        }

        DIDDocument_Destroy(controller_doc);

        if (i != size - 1)
            memmove(document->controllers.docs + i,
                    document->controllers.docs + i + 1,
                    sizeof(DIDDocument*) * (size - i - 1));

        document->controllers.docs[size - 1] = NULL;
        document->controllers.size--;
        document->multisig = 0;
        clean_proofs(document);
        return 0;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "No this controller in document.");
    return -1;
}

int DIDDocumentBuilder_AddCredential(DIDDocumentBuilder *builder, Credential *credential)
{
    DIDDocument *document;
    Credential *temp_cred;
    Credential *cred;
    DIDURL *credid;
    size_t i;

    if (!builder || !builder->document || !credential) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    credid = Credential_GetId(credential);
    if (!DID_Equals(DIDDocument_GetSubject(document), DIDURL_GetDid(credid))) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Credential not owned by self.");
        return -1;
    }

    for (i = 0; i < document->credentials.size; i++) {
        temp_cred = document->credentials.credentials[i];
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

    if (!builder || !builder->document || !credid || !properties || propsize <= 0 ||
            !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    if (!DID_Equals(&document->did, &credid->did)) {
        DIDError_Set(DIDERR_UNSUPPOTED, "The credential id mismatch with the document.");
        return -1;
    }

    for (i = 0; i < document->credentials.size; i++) {
        cred = document->credentials.credentials[i];
        if (DIDURL_Equals(&cred->id, credid)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Credential already exist.");
            return -1;
        }
    }

    if (!signkey && document->controllers.size > 1) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Must specify the key to sign the credential owned by multi-controller did.");
        return -1;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(document);
        if (!signkey)
            return -1;
    } else {
        if (!DIDDocument_IsAuthenticationKey(document, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "The sign key is not authentication key.");
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
        expires = DIDDocument_GetExpires(document);

    cred = Issuer_CreateCredential(issuer, DIDDocument_GetSubject(document), credid,
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
}

int DIDDocumentBuilder_RenewSelfProclaimedCredential(DIDDocumentBuilder *builder,
        DID *controller, DIDURL *signkey, const char *storepass)
{
    DIDDocument *document;
    Credential *cred;
    Issuer *issuer = NULL;
    int i, rc = -1;

    if (!builder || !builder->document || !controller || !signkey || !storepass
            || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    if (!Is_CustomizedDID(document)) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport renew self-proclaimed Credential owned by normal DID.");
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
}

int DIDDocumentBuilder_RemoveSelfProclaimedCredential(DIDDocumentBuilder *builder,
       DID *controller)
{
    DIDDocument *document;
    Credential *cred;
    int i;

    if (!builder || !builder->document || !controller) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    if (!Is_CustomizedDID(document)) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport renew self-proclaimed Credential owned by normal DID.");
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
}

int DIDDocumentBuilder_RemoveCredential(DIDDocumentBuilder *builder, DIDURL *credid)
{
    DIDDocument *document;
    Credential *cred = NULL;
    size_t size;
    size_t i;

    if (!builder || !builder->document || !credid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    size = DIDDocument_GetCredentialCount(document);
    for ( i = 0; i < size; i++ ) {
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
}

int DIDDocumentBuilder_AddService(DIDDocumentBuilder *builder, DIDURL *serviceid,
        const char *type, const char *endpoint)
{
    DIDDocument *document;
    Service **services = NULL;
    Service *service = NULL;
    size_t i;

    if (!builder || !builder->document || !serviceid || !type || !*type ||
        !endpoint || !*endpoint) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (strlen(type) >= MAX_TYPE_LEN) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Type argument is too long.");
        return -1;
    }
    if (strlen(endpoint) >= MAX_ENDPOINT) {
        DIDError_Set(DIDERR_INVALID_ARGS, "End point argument is too long.");
        return -1;
    }

    document = builder->document;
    if (!DID_Equals(DIDDocument_GetSubject(document), DIDURL_GetDid(serviceid))) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Service not owned by self.");
        return -1;
    }

    for (i = 0; i < document->services.size; i++) {
        service = document->services.services[i];
        if (DIDURL_Equals(&service->id, serviceid)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "This service already exist.");
            return -1;
        }
    }

    service = (Service*)calloc(1, sizeof(Service));
    if (!service) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for service failed.");
        return -1;
    }

    DIDURL_Copy(&service->id, serviceid);
    strcpy(service->type, type);
    strcpy(service->endpoint, endpoint);

    if (document->services.size == 0)
        services = (Service**)calloc(1, sizeof(Service*));
    else
        services = (Service**)realloc(document->services.services,
                            (document->services.size + 1) * sizeof(Service*));

    if (!services) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for services failed.");
        Service_Destroy(service);
        return -1;
    }

    services[document->services.size++] = service;
    document->services.services = services;
    clean_proofs(document);
    return 0;
}

int DIDDocumentBuilder_RemoveService(DIDDocumentBuilder *builder, DIDURL *serviceid)
{
    DIDDocument *document;
    Service *service = NULL;
    size_t size;
    size_t i;

    if (!builder || !builder->document || !serviceid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    size = DIDDocument_GetServiceCount(document);
    for (i = 0; i < size; i++) {
        service = document->services.services[i];
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
}

int DIDDocumentBuilder_RemoveProof(DIDDocumentBuilder *builder, DID *controller)
{
    DIDDocument *document;
    size_t size;
    int i, index = -1;

    if (!builder || !builder->document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    size = document->proofs.size;

    if (Is_CustomizedDID(document)) {
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
    }

    if (!Is_CustomizedDID(document)) {
        if (controller) {
            DIDError_Set(DIDERR_INVALID_CONTROLLER, "Unsupport the specified controller to remove proof.");
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
}

int DIDDocumentBuilder_SetExpires(DIDDocumentBuilder *builder, time_t expires)
{
    time_t max_expires;
    struct tm *tm = NULL;
    DIDDocument *document;

    if (!builder || expires < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    max_expires = time(NULL);
    tm = gmtime(&max_expires);
    tm->tm_year += MAX_EXPIRES;
    max_expires = mktime(tm);

    document = builder->document;
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid document builder.");
        return -1;
    }

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
}

int DIDDocumentBuilder_SetMultisig(DIDDocumentBuilder *builder, int multisig)
{
    DIDDocument *document;

    if (!builder || multisig <= 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    document = builder->document;
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid document builder.");
        return -1;
    }

    if (!Is_CustomizedDID(document)) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport setting multisig for normal DID.");
        return -1;
    }

    if (multisig > document->controllers.size) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport multisig is larger than the count of controllers.");
        return -1;
    }

    document->multisig = multisig;
    clean_proofs(document);
    return 0;
}

//////////////////////////DIDDocument//////////////////////////////////////////
DID* DIDDocument_GetSubject(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &document->did;
}

int DIDDocument_GetMultisig(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (!Is_CustomizedDID(document))
        return 0;

    if (document->controllers.size == 1)
        return 0;

    return document->multisig;
}

ssize_t DIDDocument_GetControllerCount(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return document->controllers.size;
}

ssize_t DIDDocument_GetControllers(DIDDocument *document, DID **controllers, size_t size)
{
    int i;

    if (!document || !controllers || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (size < document->controllers.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    for (i = 0; i < document->controllers.size; i++)
        controllers[i] = DIDDocument_GetSubject(document->controllers.docs[i]);

    return document->controllers.size;
}

bool DIDDocument_ContainsController(DIDDocument *document, DID *controller)
{
    if (!document || !controller) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return !DIDDocument_GetControllerDocument(document, controller) ? false : true;
}

ssize_t DIDDocument_GetPublicKeyCount(DIDDocument *document)
{
    size_t count;
    int i;
    DIDDocument *doc;

    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    count = document->publickeys.size;

    if (document->controllers.size && document->controllers.docs) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            if (doc)
                count += doc->publickeys.size;
        }
    }

    return (ssize_t)count;
}

PublicKey *DIDDocument_GetPublicKey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey *pk;
    DIDDocument *doc;
    size_t i;

    if (!document || !keyid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (!*keyid->fragment || !*keyid->did.idstring) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Malformed key.");
        return NULL;
    }

    if (DID_Equals(&document->did, &keyid->did)) {
        doc = document;
    } else {
        if (document->controllers.size < 0 || !document->controllers.docs) {
            DIDError_Set(DIDERR_NOT_EXISTS, "Document has no controllers.");
            return NULL;
        }
        doc = DIDDocument_GetControllerDocument(document, &keyid->did);
        if (!doc) {
            DIDError_Set(DIDERR_NOT_EXISTS, "The owner of this key is not the controller of document.");
            return NULL;
        }
    }

    for (i = 0; i < doc->publickeys.size && doc->publickeys.pks; i++) {
        pk = doc->publickeys.pks[i];
        if (DIDURL_Equals(keyid, &pk->id))
            return pk;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "No this public key in document.");
    return NULL;
}

ssize_t DIDDocument_GetPublicKeys(DIDDocument *document, PublicKey **pks,
        size_t size)
{
    size_t actual_size, pk_size = 0;
    DIDDocument *doc;
    int i;

    if (!document || !pks || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    actual_size = DIDDocument_GetPublicKeyCount(document);
    if (actual_size > size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
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
}

ssize_t DIDDocument_SelectPublicKeys(DIDDocument *document, const char *type,
        DIDURL *keyid, PublicKey **pks, size_t size)
{
    DIDDocument *doc;
    size_t actual_size = 0, total_size, i;

    if (!document || !pks || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if ((!keyid && !type)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No feature to select key.");
        return -1;
    }

    if (keyid && !*keyid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Key id misses fragment.");
        return -1;
    }

    if (keyid && !*keyid->did.idstring)
        strcpy(keyid->did.idstring, document->did.idstring);

    total_size = document->publickeys.size;
    for (i = 0; i < total_size; i++) {
        PublicKey *pk = document->publickeys.pks[i];

        if (keyid && !DIDURL_Equals(keyid, &pk->id))
            continue;
        if (type && strcmp(type, pk->type))
            continue;

        if (actual_size >= size) {
            DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
            return -1;
        }

        pks[actual_size++] = pk;
    }

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            total_size = DIDDocument_SelectPublicKeys(doc, type, keyid, pks + actual_size, size - actual_size);
            if (total_size > 0)
                actual_size += total_size;
        }
    }

    return (ssize_t)actual_size;
}

DIDURL *DIDDocument_GetDefaultPublicKey(DIDDocument *document)
{
    DIDDocument *doc;
    char idstring[MAX_ID_SPECIFIC_STRING];
    uint8_t binkey[PUBLICKEY_BYTES];
    PublicKey *pk;
    size_t i;

    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

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
        if (DID_Equals(&pk->controller, &doc->did) == 0)
            continue;

        base58_decode(binkey, sizeof(binkey), pk->publicKeyBase58);
        HDKey_PublicKey2Address(binkey, idstring, sizeof(idstring));

        if (!strcmp(idstring, pk->id.did.idstring))
            return &pk->id;
    }

    DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No default public key.");
    return NULL;
}

///////////////////////Authentications/////////////////////////////
ssize_t DIDDocument_GetAuthenticationCount(DIDDocument *document)
{
    size_t size, i, pk_size;
    DIDDocument *doc;

    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    size = get_self_authentication_count(document);
    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            pk_size = get_self_authentication_count(doc);
            if (pk_size > 0)
                size += pk_size;
        }
    }

    return (ssize_t)size;
}

ssize_t DIDDocument_GetAuthenticationKeys(DIDDocument *document, PublicKey **pks,
        size_t size)
{
    size_t actual_size = 0, i, pk_size;
    DIDDocument *doc;

    if (!document || !pks || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (size < DIDDocument_GetAuthenticationCount(document)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
        return -1;
    }

    for (i = 0; i < document->publickeys.size && document->publickeys.pks; i++) {
        if (document->publickeys.pks[i]->authenticationKey) {
            if (actual_size >= size) {
                DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
                return -1;
            }
            pks[actual_size++] = document->publickeys.pks[i];
        }
    }

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            pk_size = DIDDocument_GetAuthenticationKeys(doc, pks + actual_size,
                    (size - actual_size));
            if (pk_size > 0)
                actual_size += pk_size;
        }
    }

    return (ssize_t)actual_size;
}

PublicKey *DIDDocument_GetAuthenticationKey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey *pk;

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
}

ssize_t DIDDocument_SelectAuthenticationKeys(DIDDocument *document,
        const char *type, DIDURL *keyid, PublicKey **pks, size_t size)
{
    size_t actual_size = 0, i, pk_size;
    PublicKey *pk;
    DIDDocument *doc;

    if (!document || !pks || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }
    if (!keyid && !type) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No feature to select key.");
        return -1;
    }

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
            DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
            return -1;
        }

        pks[actual_size++] = pk;
    }

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            pk_size = DIDDocument_SelectAuthenticationKeys(doc, type, keyid,
                    pks + actual_size, size - actual_size);
            if (pk_size > 0)
                actual_size += pk_size;
        }
    }

    return (ssize_t)actual_size;
}

////////////////////////////Authorization//////////////////////////
ssize_t DIDDocument_GetAuthorizationCount(DIDDocument *document)
{
    DIDDocument *doc;
    size_t size, pk_size;
    int i;

    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    size = get_self_authorization_count(document);
    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            pk_size = get_self_authorization_count(doc);
            if (pk_size > 0)
                size += pk_size;
        }
    }

    return (ssize_t)size;
}

ssize_t DIDDocument_GetAuthorizationKeys(DIDDocument *document, PublicKey **pks,
        size_t size)
{
    size_t actual_size = 0, i, pk_size;
    DIDDocument *doc;

    if (!document || !pks || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (size < DIDDocument_GetAuthorizationCount(document)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
        return -1;
    }

    for (i = 0; i < document->publickeys.size && document->publickeys.pks; i++) {
        if (document->publickeys.pks[i]->authorizationKey) {
            if (actual_size >= size) {
                DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
                return -1;
            }
            pks[actual_size++] = document->publickeys.pks[i];
        }
    }

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            pk_size = DIDDocument_GetAuthorizationKeys(doc, pks + actual_size,
                    size - actual_size);
            if (pk_size > 0)
                actual_size += pk_size;
        }
    }

    return (ssize_t)actual_size;
}

PublicKey *DIDDocument_GetAuthorizationKey(DIDDocument *document, DIDURL *keyid)
{
    PublicKey *pk;

    if (!document || !keyid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk)
        return NULL;

    if (!pk->authorizationKey) {
        DIDError_Set(DIDERR_NOT_EXISTS, "This is not authorization key.");
        return NULL;
    }

    return pk;
}

ssize_t DIDDocument_SelectAuthorizationKeys(DIDDocument *document,
        const char *type, DIDURL *keyid, PublicKey **pks, size_t size)
{
    size_t actual_size = 0, i, pk_size;
    PublicKey *pk;
    DIDDocument *doc;

    if (!document || !pks || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }
    if (!keyid && !type) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No feature to select key.");
        return -1;
    }

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
            DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
            return -1;
        }

        pks[actual_size++] = pk;
    }

    if (document->controllers.size > 0) {
        for (i = 0; i < document->controllers.size; i++) {
            doc = document->controllers.docs[i];
            pk_size = DIDDocument_SelectAuthorizationKeys(doc, type, keyid,
                    pks + actual_size, size - actual_size);
            if (pk_size > 0)
                actual_size += pk_size;
        }
    }

    return (ssize_t)actual_size;
}

//////////////////////////Credential///////////////////////////
ssize_t DIDDocument_GetCredentialCount(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return (ssize_t)document->credentials.size;
}

ssize_t DIDDocument_GetCredentials(DIDDocument *document, Credential **creds,
        size_t size)
{
    size_t actual_size;

    if (!document || !creds || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    actual_size = document->credentials.size;
    if (actual_size > size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
        return -1;
    }

    memcpy(creds, document->credentials.credentials, sizeof(Credential*) * actual_size);
    return (ssize_t)actual_size;
}

Credential *DIDDocument_GetCredential(DIDDocument *document, DIDURL *credid)
{
    Credential *credential = NULL;
    size_t size, i;

    if (!document || !credid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (!*credid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Invalid credential id.");
        return NULL;
    }

    size = document->credentials.size;
    if (!size) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No credential in document.");
        return NULL;
    }

    for (i = 0; i < size; i++) {
        credential = document->credentials.credentials[i];
        if (DIDURL_Equals(credid, &credential->id))
            return credential;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "No this credential.");
    return NULL;
}

ssize_t DIDDocument_SelectCredentials(DIDDocument *document, const char *type,
        DIDURL *credid, Credential **creds, size_t size)
{
    size_t actual_size = 0, total_size, i, j;
    bool flag;

    if (!document || !creds || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }
    if (!credid && !type) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No feature to select credential.");
        return -1;
    }

    if (credid && !*credid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Credential id misses fragment.");
        return -1;
    }

    total_size = document->credentials.size;
    if (!total_size) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No credential in document.");
        return -1;
    }

    if (credid && (!*credid->did.idstring))
        strcpy(credid->did.idstring, document->did.idstring);

    for (i = 0; i < total_size; i++) {
        Credential *cred = document->credentials.credentials[i];
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
            DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
            return -1;
        }

        if (flag)
            creds[actual_size++] = cred;
    }

    return (ssize_t)actual_size;
}

////////////////////////////////service//////////////////////
ssize_t DIDDocument_GetServiceCount(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return (ssize_t)document->services.size;
}

ssize_t DIDDocument_GetServices(DIDDocument *document, Service **services,
        size_t size)
{
    size_t actual_size;

    if (!document || !services || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    actual_size = document->services.size;
    if (actual_size > size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
        return -1;
    }

    memcpy(services, document->services.services, sizeof(Service*) * actual_size);
    return (ssize_t)actual_size;
}

Service *DIDDocument_GetService(DIDDocument *document, DIDURL *serviceid)
{
    Service *service = NULL;
    size_t size, i;

    if (!document || !serviceid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (!*serviceid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Service id misses fragment.");
        return NULL;
    }

    size = document->services.size;
    if (!size) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No service in document.");
        return NULL;
    }

    for (i = 0; i < size; i++) {
        service = document->services.services[i];
        if (DIDURL_Equals(serviceid, &service->id))
            return service;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "This service is in document.");
    return NULL;
}

ssize_t DIDDocument_SelectServices(DIDDocument *document,
        const char *type, DIDURL *serviceid, Service **services, size_t size)
{
    size_t actual_size = 0, total_size, i;

    if (!document || !services || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }
    if (!serviceid && !type) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No feature to select service.");
        return -1;
    }

    if (serviceid && !*serviceid->fragment) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Service id misses fragment.");
        return -1;
    }

    total_size = document->services.size;
    if (!total_size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
        return -1;
    }

    if (serviceid && !*serviceid->did.idstring)
        strcpy(serviceid->did.idstring, document->did.idstring);

    for (i = 0; i < total_size; i++) {
        Service *service = document->services.services[i];

        if (serviceid && !DIDURL_Equals(serviceid, &service->id))
            continue;
        if (type && strcmp(type, service->type))
            continue;

        if (actual_size >= size) {
            DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
            return -1;
        }

        services[actual_size++] = service;
    }

    return (ssize_t)actual_size;
}

///////////////////////////////expires////////////////////////
time_t DIDDocument_GetExpires(DIDDocument *document)
{
    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    return document->expires;
}

ssize_t DIDDocument_GetDigest(DIDDocument *document, uint8_t *digest, size_t size)
{
    const char *data;

    assert(document);
    assert(digest);
    assert(size >= SHA256_BYTES);

    data = diddocument_tojson_forsign(document, false, true);
    if (!data)
        return -1;

    return sha256_digest(digest, 1, (unsigned char*)data, strlen(data));
}

int DIDDocument_Sign(DIDDocument *document, DIDURL *keyid, const char *storepass,
        char *sig, int count, ...)
{
    uint8_t digest[SHA256_BYTES];
    va_list inputs;
    ssize_t size;

    if (!document || !storepass || !*storepass || !sig || count <= 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    va_start(inputs, count);
    size = sha256v_digest(digest, count, inputs);
    va_end(inputs);
    if (size == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get digest failed.");
        return -1;
    }

    return DIDDocument_SignDigest(document, keyid, storepass, sig, digest, sizeof(digest));
}

int DIDDocument_SignDigest(DIDDocument *document, DIDURL *keyid,
        const char *storepass, char *sig, uint8_t *digest, size_t size)
{
    DID *signer;
    PublicKey *pk;
    DIDDocument *doc;

    if (!document || !storepass || !*storepass || !sig || !digest || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (!DIDMetaData_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DID, "Not attached with DID store.");
        return -1;
    }

    if (!keyid)
        keyid = DIDDocument_GetDefaultPublicKey(document);

    //confirm the signer
    pk = DIDDocument_GetPublicKey(document, keyid);
    if (!pk || !PublicKey_IsAuthenticationKey(pk))
        return -1;

    if (DID_Equals(&document->did, &pk->controller)) {
       signer = &document->did;
    } else {
        if (document->controllers.size <= 0 || !document->controllers.docs) {
            DIDError_Set(DIDERR_MALFORMED_DID, "There are no controller in document.");
            return -1;
        }
        doc = DIDDocument_GetControllerDocument(document, &keyid->did);
        if (!doc) {
            DIDError_Set(DIDERR_INVALID_KEY, "The sign key does not owned to document.");
            return -1;
        }

        if (!DID_Equals(&doc->did, &pk->controller)) {
            DIDError_Set(DIDERR_INVALID_CONTROLLER, "Invalid sign key.");
            return -1;
        }
        signer = &doc->did;
    }

    return DIDStore_Sign(document->metadata.base.store, storepass,
            signer, keyid, sig, digest, size);
}

int DIDDocument_Verify(DIDDocument *document, DIDURL *keyid, char *sig,
        int count, ...)
{
    va_list inputs;
    uint8_t digest[SHA256_BYTES];
    ssize_t size;

    if (!document || !sig || count <= 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    va_start(inputs, count);
    size = sha256v_digest(digest, count, inputs);
    va_end(inputs);
    if (size == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get digest failed.");
        return -1;
    }

    return DIDDocument_VerifyDigest(document, keyid, sig, digest, sizeof(digest));
}

int DIDDocument_VerifyDigest(DIDDocument *document, DIDURL *keyid,
        char *sig, uint8_t *digest, size_t size)
{
    PublicKey *publickey;
    uint8_t binkey[PUBLICKEY_BYTES];

    if (!document || !sig || !digest || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (!keyid) {
        keyid = DIDDocument_GetDefaultPublicKey(document);
        if (!keyid) {
            DIDError_Set(DIDERR_INVALID_ARGS, "Document does have default key, so please provide key to verify.");
            return -1;
        }
    }

    publickey = DIDDocument_GetPublicKey(document, keyid);
    if (!publickey) {
        DIDError_Set(DIDERR_INVALID_KEY, "No this sign key.");
        return -1;
    }

    if (!PublicKey_IsAuthenticationKey(publickey)) {
        DIDError_Set(DIDERR_INVALID_KEY, "The key is not an authentication key.");
        return -1;
    }

    base58_decode(binkey, sizeof(binkey), PublicKey_GetPublicKeyBase58(publickey));

    if (ecdsa_verify_base64(sig, binkey, digest, size) == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Ecdsa verify failed.");
        return -1;
    }

    return 0;
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
    DID *did;
    JWTBuilder *builder;

    if (!document) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    did = DIDDocument_GetSubject(document);
    if (!did)
        return NULL;

    builder = JWTBuilder_Create(did);
    if (!builder)
        return NULL;

    return builder;
}

JWSParser *DIDDocument_GetJwsParser(DIDDocument *document)
{
    return JWSParser_Create(document);
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

    if (sha256_digest(digest, 1, identifier, strlen(identifier)) < 0)
        return -1;

    for (int i = 0; i < size; i++)
        paths[i] = UInt32GetBE(digest + i*4);

    return 0;
}

const char *DIDDocument_Derive(DIDDocument *document, const char *identifier,
        int securityCode, const char *storepass)
{
    uint8_t extendedkey[EXTENDEDKEY_BYTES];
    int paths[8];
    HDKey *hdkey, *derivedkey, _hdkey, _dkey;
    char extendedkeyBase58[512];

    if (!document || !identifier || !*identifier || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (!DIDMetaData_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
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

    if (map_to_derivepath(paths, 8, identifier) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get derived path failed.");
        return NULL;
    }

    derivedkey = HDKey_GetDerivedKey(hdkey, &_dkey, 9, paths[0], paths[1], paths[2], paths[3],
           paths[4], paths[5], paths[6], paths[7], securityCode);
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

DIDDocument *DIDDocument_SignDIDDocument(DIDDocument* controllerdoc,
        const char *document, const char *storepass)
{
    DIDDocument *doc;
    DIDDocumentBuilder *builder;

    if (!controllerdoc || !document || !*document || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    doc = DIDDocument_FromJson(document);
    if (!doc)
        return NULL;

    if (DIDDocument_IsQualified(doc)) {
        DIDDocument_Destroy(doc);
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "The signers are enough.");
        return NULL;
    }

    builder = DIDDocument_Edit(doc, controllerdoc);
    DIDDocument_Destroy(doc);
    if (!builder)
        return NULL;

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    return doc;
}

const char *DIDDocument_MergeDIDDocuments(int count, ...)
{
    va_list list;
    const char *doc = NULL, *merged_doc = NULL;
    DIDDocument *document = NULL, **documents;
    uint8_t digest[SHA256_BYTES], digest1[SHA256_BYTES];
    int i, actual_count = 0;

    if (count <= 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    documents = (DIDDocument**)alloca(count * sizeof(DIDDocument*));
    if (!documents) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DID Documents array failed.");
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

        if (!DIDDocument_IsValid_Internal(document, false)) {
            DIDDocument_Destroy(document);
            continue;
        }

        if (DIDDocument_GetDigest(document, digest1, sizeof(digest1)) < 0) {
            DIDDocument_Destroy(document);
            DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Get digest from did document failed.");
            continue;
        }

        if (actual_count == 0)
            memcpy(digest, digest1, sizeof(digest));

        if (actual_count > 0 && memcmp(digest, digest1, sizeof(digest))) {
            DIDDocument_Destroy(document);
            continue;
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
}

TransferTicket *DIDDocument_CreateTransferTicket(DIDDocument *controllerdoc, DID *owner,
        DID *to, const char *storepass)
{
    TransferTicket *ticket;

    if (!controllerdoc || !owner || !to || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    ticket = TransferTicket_Construct(owner, to);
    if (!ticket)
        return NULL;

    if (TransferTicket_Seal(ticket, controllerdoc, storepass) < 0) {
        TransferTicket_Destroy(ticket);
        return NULL;
    }

    return ticket;
}

int DIDDocument_SignTransferTicket(DIDDocument *controllerdoc,
        TransferTicket *ticket, const char *storepass)
{
    if (!controllerdoc || !ticket || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return TransferTicket_Seal(ticket, controllerdoc, storepass);
}

bool DIDDocument_PublishDID(DIDDocument *document, DIDURL *signkey, bool force,
        const char *storepass)
{
    const char *last_txid, *local_signature, *local_prevsignature, *resolve_signature = NULL;
    DIDDocument *resolve_doc = NULL;
    DIDStore *store;
    bool successed;
    int rc = -1, status;

    if (!document || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (!DIDMetaData_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    store = document->metadata.base.store;
    if (Is_CustomizedDID(document) && document->controllers.size > 1 && !signkey) {
        DIDError_Set(DIDERR_INVALID_KEY, "Multi-controller customized DID must have sign key to publish.");
        return false;
    }

    if (!DIDDocument_IsQualified(document)) {
        DIDError_Set(DIDERR_NOT_GENUINE, "Did document is not qualified.");
        return false;
    }

    if (!DIDDocument_IsGenuine(document)) {
        DIDError_Set(DIDERR_NOT_GENUINE, "Did document is not genuine.");
        return false;
    }

    if (DIDDocument_IsDeactivated(document)) {
        DIDError_Set(DIDERR_DID_DEACTIVATED, "Did is already deactivated.");
        return false;
    }

    if (!force && DIDDocument_IsExpired(document)) {
        DIDError_Set(DIDERR_EXPIRED, "Did is already expired, use force mode to publish anyway.");
        return false;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(document);
        if (!signkey)
            return false;
    } else {
        if (!DIDDocument_IsAuthenticationKey(document, signkey))
            return false;
    }

    resolve_doc = DID_Resolve(&document->did, &status, true);
    if (!resolve_doc) {
        if (status == DIDStatus_NotFound)
            successed = DIDBackend_CreateDID(document, signkey, storepass);
        else
            return false;
    } else {
        if (DIDDocument_IsDeactivated(resolve_doc)) {
            DIDError_Set(DIDERR_EXPIRED, "Did is already deactivated.");
            goto errorExit;
        }

        if (Is_CustomizedDID(document) && document->controllers.size != resolve_doc->controllers.size) {
            DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport publishing DID which is changed controller, please transfer it.");
            goto errorExit;
        }

        resolve_signature = resolve_doc->proofs.proofs[0].signatureValue;
        if (!resolve_signature || !*resolve_signature) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing resolve signature.");
            goto errorExit;
        }
        last_txid = DIDMetaData_GetTxid(&resolve_doc->metadata);

        if (!force) {
            local_signature = DIDMetaData_GetSignature(&document->metadata);
            local_prevsignature = DIDMetaData_GetPrevSignature(&document->metadata);
            if ((!local_signature || !*local_signature) && (!local_prevsignature || !*local_prevsignature)) {
                DIDError_Set(DIDERR_DIDSTORE_ERROR,
                        "Missing signatures information, DID SDK dosen't know how to handle it, use force mode to ignore checks.");
                goto errorExit;
            } else if (!local_signature || !local_prevsignature) {
                const char *sig = local_signature != NULL ? local_signature : local_prevsignature;
                if (strcmp(sig, resolve_signature)) {
                    DIDError_Set(DIDERR_DIDSTORE_ERROR,
                            "Current copy not based on the lastest on-chain copy.");
                    goto errorExit;
                }
            } else {
                if (strcmp(local_signature, resolve_signature) &&
                        strcmp(local_prevsignature, resolve_signature)) {
                    DIDError_Set(DIDERR_DIDSTORE_ERROR,
                            "Current copy not based on the lastest on-chain copy.");
                    goto errorExit;
                }

            }
        }

        DIDMetaData_SetTxid(&document->metadata, last_txid);
        successed = DIDBackend_UpdateDID(document, signkey, storepass);
    }

    if (!successed)
        goto errorExit;

    ResolveCache_InvalidateDID(&document->did);
    //Meta stores the resolved txid and local signature.
    DIDMetaData_SetSignature(&document->metadata, DIDDocument_GetProofSignature(document, 0));
    if (resolve_signature)
        DIDMetaData_SetPrevSignature(&document->metadata, resolve_signature);
    rc = DIDStore_WriteDIDMetaData(store, &document->metadata, &document->did);

errorExit:
    DIDDocument_Destroy(resolve_doc);
    return rc == -1 ? false : true;
}

bool DIDDocument_TransferDID(DIDDocument *document, TransferTicket *ticket,
        DIDURL *signkey, const char *storepass)
{
    DIDDocument *resolve_doc = NULL;
    DocumentProof *proof;
    DIDStore *store;
    bool bequals = false;
    int rc = -1, i, status;

    if (!document || !storepass || !*storepass || !ticket || !signkey) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (!DIDMetaData_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    store = document->metadata.base.store;
    resolve_doc = DID_Resolve(&document->did, &status, true);
    if (!resolve_doc) {
        if (status == DIDStatus_NotFound)
             DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport transfering DID which isn't published.");
        return false;
    }

    if (!Is_CustomizedDID(resolve_doc)) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport transfering normal DID.");
        goto errorExit;
    }

    if (!TransferTicket_IsValid(ticket))
       goto errorExit;

    if (strcmp(ticket->txid, DIDMetaData_GetTxid(&resolve_doc->metadata))) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Transaction id of ticket mismatches with the chain one.");
        goto errorExit;
    }

    //check ticket "to"
    for (i = 0; i < document->proofs.size; i++) {
        proof = &document->proofs.proofs[i];
        if (DID_Equals(&ticket->to, &proof->creater.did)) {
            bequals = true;
            break;
        }
    }

    if (!bequals) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "The DID to receive ticket is not the document's signer.");
        goto errorExit;
    }

    if (!DIDDocument_IsAuthenticationKey(document, signkey))
        goto errorExit;

    DIDMetaData_SetTxid(&document->metadata, DIDMetaData_GetTxid(&resolve_doc->metadata));
    DIDMetaData_SetTxid(&document->did.metadata, DIDMetaData_GetTxid(&resolve_doc->metadata));
    if (!DIDBackend_TransferDID(document, ticket, signkey, storepass))
        goto errorExit;

    ResolveCache_InvalidateDID(&document->did);
    //Meta stores the resolved txid and local signature.
    DIDMetaData_SetSignature(&document->metadata, DIDDocument_GetProofSignature(document, 0));
    if (*resolve_doc->proofs.proofs[0].signatureValue)
        DIDMetaData_SetPrevSignature(&document->metadata, resolve_doc->proofs.proofs[0].signatureValue);
    rc = DIDStore_WriteDIDMetaData(store, &document->metadata, &document->did);

errorExit:
    DIDDocument_Destroy(resolve_doc);
    return rc == -1 ? false : true;
}

bool DIDDocument_DeactivateDID(DIDDocument *document, DIDURL *signkey, const char *storepass)
{
    DIDDocument *resolve_doc;
    DIDStore *store;
    bool localcopy = false;
    int rc = 0, status;
    bool successed;

    if (!document || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    resolve_doc = DID_Resolve(&document->did, &status, true);
    if (!resolve_doc) {
        if (status == DIDStatus_NotFound)
            DIDError_Set(DIDERR_NOT_EXISTS, "DID doesn't already exist.");
        return false;
    }

    if (!DIDMetaData_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    store = document->metadata.base.store;
    DIDMetaData_SetStore(&resolve_doc->metadata, store);

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(resolve_doc);
        if (!signkey) {
            DIDDocument_Destroy(resolve_doc);
            DIDError_Set(DIDERR_INVALID_KEY, "Not default key.");
            return false;
        }
    } else {
        if (!DIDDocument_IsAuthenticationKey(resolve_doc, signkey)) {
            DIDDocument_Destroy(resolve_doc);
            DIDError_Set(DIDERR_INVALID_KEY, "Invalid authentication key.");
            return false;
        }
    }

    successed = DIDBackend_DeactivateDID(document, NULL, signkey, storepass);
    DIDDocument_Destroy(resolve_doc);
    if (successed)
        ResolveCache_InvalidateDID(&document->did);

    return successed;
}

bool DIDDocument_DeactivateDIDByAuthorizor(DIDDocument *document, DID *target,
        DIDURL *signkey, const char *storepass)
{
    DIDDocument *targetdoc = NULL;
    DIDStore *store;
    PublicKey **candidatepks;
    PublicKey *candidatepk, *pk;
    bool successed = false, bexist = false;
    size_t size;
    int i, j, status;

    if (!document || !target || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    targetdoc = DID_Resolve(target, &status, true);
    if (!targetdoc) {
        if (status == DIDStatus_NotFound)
            DIDError_Set(DIDERR_NOT_EXISTS, "DID doesn't already exist.");
        return false;
    }

    if (!DIDMetaData_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
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
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for candidate public keys failed.");
            goto errorExit;
        }
        candidatepks[0] = DIDDocument_GetAuthenticationKey(document, signkey);
        if (!candidatepks[0]) {
            DIDError_Set(DIDERR_INVALID_KEY, "Sign key is not authentication key.");
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

            bexist = true;
            break;
        }
        if (bexist)
            break;
    }

    if (!bexist) {
        DIDError_Set(DIDERR_INVALID_KEY, "No invalid authorization key to deactivate did.");
        goto errorExit;
    }

    successed = DIDBackend_DeactivateDID(document, target, &candidatepk->id, storepass);
    if (successed)
        ResolveCache_InvalidateDID(&document->did);

errorExit:
    DIDDocument_Destroy(targetdoc);
    return successed;
}

DIDURL *PublicKey_GetId(PublicKey *publickey)
{
    if (!publickey) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &publickey->id;
}

DID *PublicKey_GetController(PublicKey *publickey)
{
    if (!publickey) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &publickey->controller;
}

const char *PublicKey_GetPublicKeyBase58(PublicKey *publickey)
{
    if (!publickey) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return publickey->publicKeyBase58;
}

const char *PublicKey_GetType(PublicKey *publickey)
{
    if (!publickey) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return publickey->type;
}

bool PublicKey_IsAuthenticationKey(PublicKey *publickey)
{
    if (!publickey) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (!publickey->authenticationKey)
        DIDError_Set(DIDERR_INVALID_KEY, "This is not an authentication key.");

    return publickey->authenticationKey;
}

bool PublicKey_IsAuthorizationKey(PublicKey *publickey)
{
    if (!publickey) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (!publickey->authorizationKey)
        DIDError_Set(DIDERR_INVALID_KEY, "This is not an authorization key.");

    return publickey->authorizationKey;
}

DIDURL *Service_GetId(Service *service)
{
    if (!service) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &service->id;
}

const char *Service_GetEndpoint(Service *service)
{
    if (!service) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return service->endpoint;
}

const char *Service_GetType(Service *service)
{
    if (!service) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return service->type;
}
