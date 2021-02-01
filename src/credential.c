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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <jansson.h>

#include "ela_did.h"
#include "diderror.h"
#include "common.h"
#include "crypto.h"
#include "JsonGenerator.h"
#include "JsonHelper.h"
#include "did.h"
#include "diddocument.h"
#include "didstore.h"
#include "credential.h"
#include "didbackend.h"
#include "credentialbiography.h"

static const char *PresentationsType = "VerifiablePresentation";
extern const char *ProofType;

static void free_subject(Credential *cred)
{
    assert(cred);

    if (cred->subject.properties)
        json_decref(cred->subject.properties);
}

static void free_types(Credential *credential)
{
    size_t i;

    assert(credential);

    if (!credential->type.types)
        return;

    for (i = 0; i < credential->type.size; i++) {
        char *type = credential->type.types[i];
        if (type)
            free(type);
    }
    free(credential->type.types);
}

static int parse_types(json_t *json, Credential *credential)
{
    size_t i, size, index = 0;
    char **types;

    assert(json);
    assert(credential);

    size = json_array_size(json);
    if (!size) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No credential type.");
        return -1;
    }

    types = (char**)calloc(size, sizeof(char*));
    if (!types) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credential types failed.");
        return -1;
    }

    for (i = 0; i < size; i++) {
        json_t *item;
        char *typestr;

        item = json_array_get(json, i);
        if (!item)
            continue;

        typestr = (char*)calloc(1, strlen(json_string_value(item)) + 1);
        if (!typestr)
            continue;

        strcpy(typestr, json_string_value(item));
        types[index++] = typestr;
    }

    if (!index) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No credential type.");
        free(types);
        return -1;
    }

    credential->type.types = types;
    credential->type.size = index;
    return 0;

}

static int type_compr(const void *a, const void *b)
{
    const char *typea = *(const char**)a;
    const char *typeb = *(const char**)b;

    return strcmp(typea, typeb);
}

static int types_toJson(JsonGenerator *generator, Credential *cred)
{
    char **types;
    size_t i, size;

    assert(generator);
    assert(generator->buffer);
    assert(cred);

    size = cred->type.size;
    types = cred->type.types;
    qsort(types, size, sizeof(const char*), type_compr);

    CHECK(JsonGenerator_WriteStartArray(generator));
    for (i = 0; i < size; i++)
        CHECK(JsonGenerator_WriteString(generator, types[i]));
    CHECK(JsonGenerator_WriteEndArray(generator));

    return 0;
}

static int subject_toJson(JsonGenerator *generator, Credential *cred, DID *did, int compact)
{
    char id[ELA_MAX_DID_LEN];

    assert(generator);
    assert(generator->buffer);
    assert(cred);

    CHECK(JsonGenerator_WriteStartObject(generator));
    if (!compact || !did)
        CHECK(JsonGenerator_WriteStringField(generator, "id",
                DID_ToString(&cred->subject.id, id, sizeof(id))));

    CHECK(JsonHelper_ToJson(generator, cred->subject.properties, true));
    CHECK(JsonGenerator_WriteEndObject(generator));
    return 0;
}

static int proof_toJson(JsonGenerator *generator, Credential *cred, int compact)
{
    char id[ELA_MAX_DIDURL_LEN];
    char _timestring[DOC_BUFFER_LEN];

    assert(generator);
    assert(generator->buffer);
    assert(cred);

    CHECK(JsonGenerator_WriteStartObject(generator));
    if (!compact)
        CHECK(JsonGenerator_WriteStringField(generator, "type", cred->proof.type));
    if (cred->proof.created != 0)
        CHECK(JsonGenerator_WriteStringField(generator, "created",
                get_time_string(_timestring, sizeof(_timestring), &cred->proof.created)));
    if (DID_Equals(&cred->issuer, &cred->proof.verificationMethod.did))
        CHECK(JsonGenerator_WriteStringField(generator, "verificationMethod",
                DIDURL_ToString(&cred->proof.verificationMethod, id, sizeof(id), compact)));
    else
        CHECK(JsonGenerator_WriteStringField(generator, "verificationMethod",
                DIDURL_ToString(&cred->proof.verificationMethod, id, sizeof(id), false)));
    CHECK(JsonGenerator_WriteStringField(generator, "signature", cred->proof.signatureValue));
    CHECK(JsonGenerator_WriteEndObject(generator));
    return 0;
}

int Credential_ToJson_Internal(JsonGenerator *gen, Credential *cred, DID *did,
        bool compact, bool forsign)
{
    char buf[MAX(DOC_BUFFER_LEN, ELA_MAX_DIDURL_LEN)];

    assert(gen);
    assert(gen->buffer);
    assert(cred);

    DIDURL_ToString(&cred->id, buf, sizeof(buf), did ? compact: false);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "id", buf));
    CHECK(JsonGenerator_WriteFieldName(gen, "type"));
    CHECK(types_toJson(gen, cred));

    if (!compact || !DID_Equals(&cred->issuer, &cred->subject.id)) {
        CHECK(JsonGenerator_WriteStringField(gen, "issuer",
                DID_ToString(&cred->issuer, buf, sizeof(buf))));
    }

    CHECK(JsonGenerator_WriteStringField(gen, "issuanceDate",
        get_time_string(buf, sizeof(buf), &cred->issuanceDate)));
    if (cred->expirationDate != 0)
        CHECK(JsonGenerator_WriteStringField(gen, "expirationDate",
                get_time_string(buf, sizeof(buf), &cred->expirationDate)));
    CHECK(JsonGenerator_WriteFieldName(gen, "credentialSubject"));
    CHECK(subject_toJson(gen, cred, did, compact));
    if (!forsign) {
        CHECK(JsonGenerator_WriteFieldName(gen, "proof"));
        CHECK(proof_toJson(gen, cred, compact));
    }
    CHECK(JsonGenerator_WriteEndObject(gen));

    return 0;
}

///////////////////////////////////////////////////////////////////////////
void Credential_Destroy(Credential *cred)
{
    if (!cred)
        return;

    free_types(cred);
    if (cred->subject.properties)
        json_decref(cred->subject.properties);

    CredentialMetadata_Free(&cred->metadata);
    free(cred);
}

bool Credential_IsSelfProclaimed(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return DID_Equals(&cred->subject.id, &cred->issuer);
}

DIDURL *Credential_GetId(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &cred->id;
}

DID *Credential_GetOwner(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &cred->subject.id;
}

ssize_t Credential_GetTypeCount(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return cred->type.size;
}

ssize_t Credential_GetTypes(Credential *cred, const char **types, size_t size)
{
    size_t actual_size;

    if (!cred || !types || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    actual_size = cred->type.size;
    if (actual_size > size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
        return -1;
    }

    memcpy((void*)types, cred->type.types, sizeof(char*) * actual_size);
    return (ssize_t)actual_size;
}

DID *Credential_GetIssuer(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &cred->issuer;
}

time_t Credential_GetIssuanceDate(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return cred->issuanceDate;
}

time_t Credential_GetExpirationDate_Internal(Credential *cred, DIDDocument *document)
{
    DIDDocument *doc;
    time_t _expire, expire;
    int status;

    assert(cred);
    assert(document);

    expire = DIDDocument_GetExpires(document);
    if (!expire)
        return 0;

    if (cred->expirationDate != 0)
        expire = MIN(expire, cred->expirationDate);

    if (Credential_IsSelfProclaimed(cred))
        return expire;

    doc = DID_Resolve(&cred->issuer, &status, false);
    if (!doc)
        return 0;

    _expire = DIDDocument_GetExpires(doc);
    DIDDocument_Destroy(doc);
    if (!_expire)
        return 0;

    return MIN(expire, _expire);
}

time_t Credential_GetExpirationDate(Credential *cred)
{
    DIDDocument *doc;
    int status;
    time_t t;

    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    doc = DID_Resolve(&cred->id.did, &status, false);
    if (!doc)
        return 0;

    t = Credential_GetExpirationDate_Internal(cred, doc);
    DIDDocument_Destroy(doc);
    return t;
}

ssize_t Credential_GetPropertyCount(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }
    if (!cred->subject.properties) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No subjects in credential.");
        return -1;
    }

    return json_object_size(cred->subject.properties);
}

const char *Credential_GetProperties(Credential *cred)
{
    const char *data;

    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }
    if (!cred->subject.properties) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No subjects in credential.");
        return NULL;
    }

    data = JsonHelper_ToString(cred->subject.properties);
    if (!data)
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Serialize properties to json failed.");

    return data;
}

static const char *item_astext(json_t *item)
{
    const char *value;
    char buffer[64];

    assert(item);

    if (json_is_object(item) || json_is_array(item)) {
        value = (char*)JsonHelper_ToString(item);
        if (!value)
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Serialize credential subject to json failed.");

        return value;
    }

    if (json_is_string(item)) {
        value = json_string_value(item);
    } else if (json_is_false(item)) {
        value = "false";
    } else if (json_is_true(item)) {
        value = "true";
    } else if (json_is_null(item)) {
        value = "null";
    } else if (json_is_integer(item)) {
        snprintf(buffer, sizeof(buffer), "%" JSON_INTEGER_FORMAT, json_integer_value(item));
        value = buffer;
    } else if (json_is_real(item)) {
        snprintf(buffer, sizeof(buffer), "%g", json_real_value(item));
        value = buffer;
    } else {
        value = "";
    }

    return strdup(value);
}

const char *Credential_GetProperty(Credential *cred, const char *name)
{
    json_t *item;

    if (!cred || !name || !*name) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (!cred->subject.properties) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No subjects in credential.");
        return NULL;
    }

    item = json_object_get(cred->subject.properties, name);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No this property in subject.");
        return NULL;
    }

    return item_astext(item);
}

time_t Credential_GetProofCreatedTime(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    return cred->proof.created;
}

DIDURL *Credential_GetProofMethod(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &cred->proof.verificationMethod;
}

const char *Credential_GetProofType(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return cred->proof.type;
}

const char *Credential_GetProofSignture(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return cred->proof.signatureValue;
}

Credential *Parse_Credential(json_t *json, DID *did)
{
    Credential *credential;
    json_t *item, *field;

    assert(json);

    credential = (Credential*)calloc(1, sizeof(Credential));
    if (!credential) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credential failed.");
        return NULL;
    }

    //id
    item = json_object_get(json, "id");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing id.");
        goto errorExit;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid id.");
        goto errorExit;
    }
    if (Parse_DIDURL(&credential->id, json_string_value(item), did) < 0) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid credential id.");
        goto errorExit;
    }

    if (did && strcmp(credential->id.did.idstring, did->idstring) != 0) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Credential owner is not match with DID.");
        goto errorExit;
    }

    //issuer
    item = json_object_get(json, "issuer");
    if (!item) {
        if (!did) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No issuer.");
            goto errorExit;
        } else {
            DID_Copy(&credential->issuer, did);
        }
    } else {
        if (!json_is_string(item) || Parse_DID(&credential->issuer, json_string_value(item)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid issuer.");
            goto errorExit;
        }
    }

    //issuanceDate
    item = json_object_get(json, "issuanceDate");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing issuance data.");
        goto errorExit;
    }
    if (!json_is_string(item) ||
            parse_time(&credential->issuanceDate, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid issuance data.");
        goto errorExit;
    }

    //expirationdate
    item = json_object_get(json, "expirationDate");
    if (item && parse_time(&credential->expirationDate, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid expiration date.");
        goto errorExit;
    }

    if (!item)
        credential->expirationDate = 0;

    //proof
    item = json_object_get(json, "proof");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing proof.");
        goto errorExit;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid proof.");
        goto errorExit;
    }

    field = json_object_get(item, "type");
    if (!field)
        strcpy(credential->proof.type, ProofType);
    else {
        if (strlen(json_string_value(field)) + 1 > sizeof(credential->proof.type)) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Unknow proof type.");
            goto errorExit;
        }
        else
            strcpy((char*)credential->proof.type, json_string_value(field));
    }

    //compatible for no "created"
    field = json_object_get(item, "created");
    if (field) {
        if (!json_is_string(field) ||
                parse_time(&credential->proof.created, json_string_value(field)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid create credential time.");
            goto errorExit;
        }
    }

    field = json_object_get(item, "verificationMethod");
    if (!field) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing verification method.");
        goto errorExit;
    }
    if (!json_is_string(field) ||
            Parse_DIDURL(&credential->proof.verificationMethod,
            json_string_value(field), &credential->issuer) < 0) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid verification method.");
        goto errorExit;
    }

    field = json_object_get(item, "signature");
    if (!field) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing signature.");
        goto errorExit;
    }
    if (!json_is_string(field)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid signature.");
        goto errorExit;
    }
    if (strlen(json_string_value(field)) + 1 > sizeof(credential->proof.signatureValue)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Signature is too long.");
        goto errorExit;
    }
    strcpy((char*)credential->proof.signatureValue, json_string_value(field));

    //subject
    item = json_object_get(json, "credentialSubject");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing credential subject.");
        goto errorExit;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid credential subject.");
        goto errorExit;
    }

    field = json_object_get(item, "id");
    if (!field) {
        if (!did || !DID_Copy(&credential->subject.id, did)) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No credential subject did.");
            goto errorExit;
        }
    } else {
        if (Parse_DID(&credential->subject.id, json_string_value(field)) == -1) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid subject id.");
            goto errorExit;
        }

        if (did && !DID_Equals(&credential->subject.id, did)) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Credential subject did is not match with did.");
            goto errorExit;
        }
    }

    // properties exclude "id".
    json_object_del(item, "id");
    credential->subject.properties = json_deep_copy(item);

    //type
    item = json_object_get(json, "type");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing types.");
        goto errorExit;
    }
    if (!json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid types.");
        goto errorExit;
    }
    if (parse_types(item, credential) == -1)
        goto errorExit;

    return credential;

errorExit:
    Credential_Destroy(credential);
    return NULL;
}

ssize_t Parse_Credentials(DID *did, Credential **creds, size_t size, json_t *json)
{
    size_t i, index = 0;
    json_t *item;

    assert(creds);
    assert(size > 0);
    assert(json);

    if (!json_is_array(json)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid credential array.");
        return -1;
    }

    for (i = 0; i < size; i++) {
        item = json_array_get(json, i);
        if(!item)
            continue;

        Credential *cred = Parse_Credential(item, did);
        if (cred)
            creds[index++] = cred;
    }

    return index;
}

static int didurl_func(const void *a, const void *b)
{
    char _stringa[ELA_MAX_DID_LEN], _stringb[ELA_MAX_DID_LEN];
    char *stringa, *stringb;

    Credential *creda = *(Credential**)a;
    Credential *credb = *(Credential**)b;

    stringa = DIDURL_ToString(&creda->id, _stringa, ELA_MAX_DID_LEN, true);
    stringb = DIDURL_ToString(&credb->id, _stringb, ELA_MAX_DID_LEN, true);

    return strcmp(stringa, stringb);
}

int CredentialArray_ToJson(JsonGenerator *gen, Credential **creds, size_t size,
        DID *did, bool compact)
{
    size_t i;

    assert(gen);
    assert(gen->buffer);

    qsort(creds, size, sizeof(Credential*), didurl_func);

    CHECK(JsonGenerator_WriteStartArray(gen));
    for (i = 0; i < size; i++)
        CHECK(Credential_ToJson_Internal(gen, creds[i], did, compact, false));
    CHECK(JsonGenerator_WriteEndArray(gen));

    return 0;
}

const char* Credential_ToJson_ForSign(Credential *cred, bool compact, bool forsign)
{
    JsonGenerator g, *gen;

    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    gen = JsonGenerator_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator initialize failed.");
        return NULL;
    }

    if (Credential_ToJson_Internal(gen, cred, NULL, compact, forsign) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize credential to json failed.");
        JsonGenerator_Destroy(gen);
        return NULL;
    }

    return JsonGenerator_Finish(gen);
}

const char* Credential_ToJson(Credential *cred, bool normalized)
{
    return Credential_ToJson_ForSign(cred, !normalized, false);
}

const char *Credential_ToString(Credential *cred, bool normalized)
{
    const char *data;
    json_t *json;
    json_error_t error;

    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    data = Credential_ToJson_ForSign(cred, !normalized, false);
    if (!data)
        return NULL;

    json = json_loads(data, JSON_COMPACT, &error);
    free((void*)data);
    if (!json){
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Get credential json failed: %s", error.text);
        return NULL;
    }

    return json_dumps(json, JSON_COMPACT);
}

Credential *Credential_FromJson(const char *json, DID *owner)
{
    json_t *root;
    json_error_t error;
    Credential *cred;

    if (!json) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    root = json_loads(json, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Deserialize credential failed, error: %s.", error.text);
        return NULL;
    }

    cred = Parse_Credential(root, owner);
    json_decref(root);

    return cred;
}

DIDURL *Credential_GetVerificationMethod(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &cred->proof.verificationMethod;
}

int Credential_Verify(Credential *cred)
{
    DIDDocument *doc;
    const char *data;
    int rc, status;

    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    doc = DID_Resolve(&cred->issuer, &status, false);
    if (!doc)
        return -1;

    data = Credential_ToJson_ForSign(cred, false, true);
    if (!data) {
        DIDDocument_Destroy(doc);
        return -1;
    }

    rc = DIDDocument_Verify(doc, &cred->proof.verificationMethod,
            cred->proof.signatureValue, 1, data, strlen(data));
    free((void *)data);
    DIDDocument_Destroy(doc);

    return rc;
}

bool Credential_IsExpired_Internal(Credential *cred, DIDDocument *document)
{
    time_t expires;
    time_t now;

    assert(cred);
    assert(document);

    expires = Credential_GetExpirationDate_Internal(cred, document);
    now = time(NULL);

    if (now > expires)
        return true;

    return false;
}

bool Credential_IsExpired(Credential *cred)
{
    time_t expires;
    time_t now;

    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return true;
    }

    expires = Credential_GetExpirationDate(cred);
    now = time(NULL);

    if (now > expires)
        return true;

    return false;
}

bool Credential_IsGenuine_Internal(Credential *cred, DIDDocument *document)
{
    DIDDocument *issuerdoc = NULL;
    bool bgenuine = false;
    const char *data;
    int rc, status;

    assert(cred);

    if (!document) {
        issuerdoc = DID_Resolve(&cred->issuer, &status, false);
    } else {
        issuerdoc = document;
    }

    if (!issuerdoc)
        return false;

    if (!DIDDocument_IsAuthenticationKey(issuerdoc, &cred->proof.verificationMethod))
        goto errorExit;

    if (strcmp(cred->proof.type, ProofType)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Unknow credential proof type.");
        goto errorExit;
    }

    data = Credential_ToJson_ForSign(cred, false, true);
    if (!data)
        goto errorExit;

    rc = DIDDocument_Verify(issuerdoc, &cred->proof.verificationMethod,
            cred->proof.signatureValue, 1, data, strlen(data));
    free((void *)data);

    bgenuine = (rc == -1 ? false : true);
errorExit:
    if (issuerdoc != document)
        DIDDocument_Destroy(issuerdoc);
    return bgenuine;
}

bool Credential_IsGenuine(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return Credential_IsGenuine_Internal(cred, NULL);
}

bool Credential_IsValid_Internal(Credential *cred, DIDDocument *document)
{
    DIDDocument *issuerdoc;
    bool valid;
    int status;

    assert(cred);
    assert(document);

    if (!DID_Equals(&cred->id.did, &cred->subject.id)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Credential's id mismatch with Credential subject's owner.");
        return false;
    }

    if (!Credential_IsSelfProclaimed(cred)) {
        issuerdoc = DID_Resolve(&cred->issuer, &status, false);
        if (!issuerdoc)
            return false;

        valid = DIDDocument_IsValid(issuerdoc);
        if (!valid) {
            DIDDocument_Destroy(issuerdoc);
            return false;
        }
    } else {
        issuerdoc = document;
    }

    valid = Credential_IsGenuine_Internal(cred, issuerdoc) && !Credential_IsExpired_Internal(cred, document);
    if (issuerdoc != document)
        DIDDocument_Destroy(issuerdoc);
    return valid;
}

bool Credential_IsValid(Credential *cred)
{
    DIDDocument *doc;
    bool valid;
    int status;

    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    doc = DID_Resolve(&cred->subject.id, &status, false);
    if (!doc)
        return false;

    if (!DIDDocument_IsValid(doc)) {
        DIDDocument_Destroy(doc);
        return false;
    }

    valid = Credential_IsValid_Internal(cred, doc);
    DIDDocument_Destroy(doc);
    return valid;
}

int Credential_SaveMetadata(Credential *cred)
{
    return (!cred || !CredentialMetadata_AttachedStore(&cred->metadata)) ? 0:
            DIDStore_StoreCredMeta(cred->metadata.base.store, &cred->metadata, &cred->id);
}

CredentialMetadata *Credential_GetMetadata(Credential *cred)
{
    if (!cred) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &cred->metadata;
}

int Credential_Copy(Credential *dest, Credential *src)
{
    size_t i;

    assert(dest);
    assert(src);

    DIDURL_Copy(&dest->id, &src->id);

    dest->type.types = (char**)calloc(src->type.size, sizeof(char*));
    if (!dest->type.types) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for type failed.");
        return -1;
    }

    for (i = 0; i < src->type.size; i++)
        dest->type.types[i] = strdup(src->type.types[i]);

    dest->type.size = src->type.size;

    DID_Copy(&dest->issuer, &src->issuer);

    dest->issuanceDate = src->issuanceDate;
    dest->expirationDate = src->expirationDate;

    DID_Copy(&dest->subject.id, &src->subject.id);

    dest->subject.properties = json_deep_copy(src->subject.properties);

    memcpy(&dest->proof, &src->proof, sizeof(CredentialProof));
    CredentialMetadata_Copy(&dest->metadata, &src->metadata);

    return 0;
}

bool Credential_Declare(Credential *credential, DIDURL *signkey, const char *storepass)
{
    DIDDocument *doc = NULL;
    DIDStore *store;
    bool successed = false;
    int status;

    if (!credential || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (!CredentialMetadata_AttachedStore(&credential->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Not attached with Credential.");
        return false;
    }

    if (!Credential_IsValid(credential))
        return false;

    if (Credential_IsRevoked(credential)) {
        DIDError_Set(DIDERR_CREDENTIAL_REVOKED, "The credential is revoked.");
        return false;
    }

    if (Credential_WasDeclared(&credential->id)) {
        DIDError_Set(DIDERR_ALREADY_EXISTS, "The credential already exist.");
        return false;
    }

    store = credential->metadata.base.store;
    doc = DIDStore_LoadDID(store, &credential->subject.id);
    if (!doc) {
        doc = DID_Resolve(&credential->subject.id, &status, false);
        if (!doc) {
            if (status == DIDStatus_NotFound)
                DIDError_Set(DIDERR_NOT_EXISTS, "The owner of Credential doesn't already exist.");
            return false;
        }
        DIDMetadata_SetStore(&doc->metadata, store);
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(doc);
        if (!signkey) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please give the specificed sign key.");
            goto errorExit;
        }
    } else {
        if(!DIDDocument_IsAuthenticationKey(doc, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please give the authentication key.");
            goto errorExit;
        }
    }

    successed = DIDBackend_DeclareCredential(credential, signkey, doc, storepass);

errorExit:
    DIDDocument_Destroy(doc);
    return successed;
}

bool Credential_Revoke(Credential *credential, DIDURL *signkey, const char *storepass)
{
    DIDDocument *doc = NULL;
    DIDStore *store;
    bool successed = false, brevoked;
    DID *signer;
    int status;

    if (!credential || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (!CredentialMetadata_AttachedStore(&credential->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Not attached with Credential.");
        return false;
    }

    if (!Credential_IsSelfProclaimed(credential) && !signkey) {
        DIDError_Set(DIDERR_INVALID_KEY, "Please specify the sign key for non-selfproclaimed credential.");
        return false;
    }

    if (!signkey) {
        signer = &credential->subject.id;
    } else {
        signer = &signkey->did;
        if (!DID_Equals(signer, &credential->subject.id) && !DID_Equals(signer, &credential->issuer))
            return false;
    }

    if (!Credential_IsValid(credential))
        return false;

    if (Credential_IsRevoked(credential)) {
        DIDError_Set(DIDERR_CREDENTIAL_REVOKED, "The credential is revoked.");
        return false;
    }

    store = credential->metadata.base.store;
    doc = DIDStore_LoadDID(store, signer);
    if (!doc) {
        doc = DID_Resolve(signer, &status, false);
        if (!doc) {
            if (status == DIDStatus_NotFound)
                DIDError_Set(DIDERR_NOT_EXISTS, "The owner of Credential doesn't already exist.");
            return false;
        }
        DIDMetadata_SetStore(&doc->metadata, store);
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(doc);
        if (!signkey) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please give the specificed sign key.");
            goto errorExit;
        }
    } else {
        if(!DIDDocument_IsAuthenticationKey(doc, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please give the authentication key to sign.");
            goto errorExit;
        }
    }

    successed = DIDBackend_RevokeCredential(&credential->id, signkey, doc, storepass);

errorExit:
    DIDDocument_Destroy(doc);
    return successed;
}

bool Credential_RevokeById(DIDURL *id, DIDDocument *document, DIDURL *signkey,
        const char *storepass)
{
    DIDDocument *doc = NULL;
    DIDStore *store;
    Credential *local_vc;
    bool successed = false, brevoked;
    DID *signer;
    int status;

    if (!id || !document || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Document does not attached with DID store.");
        return false;
    }

    store = document->metadata.base.store;
    local_vc = DIDStore_LoadCredential(store, &id->did, id);
    if (local_vc) {
        brevoked = Credential_IsRevoked(local_vc);
        Credential_Destroy(local_vc);
        if (brevoked) {
            DIDError_Set(DIDERR_CREDENTIAL_REVOKED, "Credential is already revoked.");
            return false;
        }
    }

    if (Credential_ResolveRevocation(id, &document->did)) {
        DIDError_Set(DIDERR_CREDENTIAL_REVOKED, "Credential is already revoked.");
        return false;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(document);
        if (!signkey) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please give the specificed sign key.");
            return false;
        }
    } else {
        if (!DIDDocument_IsAuthenticationKey(document, signkey))
            return false;
    }

    return DIDBackend_RevokeCredential(id, signkey, document, storepass);
}

Credential *Credential_Resolve(DIDURL *id, int *status, bool force)
{
    if (!id) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return DIDBackend_ResolveCredential(id, status, force);
}

bool Credential_ResolveRevocation(DIDURL *id, DID *issuer)
{
    if (!id) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return DIDBackend_ResolveRevocation(id, issuer);
}

CredentialBiography *Credential_ResolveBiography(DIDURL *id, DID *issuer)
{
    if (!id) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return DIDBackend_ResolveCredentialBiography(id, issuer);
}
bool Credential_WasDeclared(DIDURL *id)
{
    Credential *credential;
    int status;

    if (!id) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    credential = Credential_Resolve(id, &status, true);
    if (!credential)
        return false;

    Credential_Destroy(credential);
    return true;
}

bool Credential_IsRevoked(Credential *credential)
{
    if (!credential) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (CredentialMetadata_GetRevoke(&credential->metadata))
        return true;

    return Credential_ResolveRevocation(&credential->id, &credential->issuer) ||
            Credential_ResolveRevocation(&credential->id, &credential->subject.id);
}

ssize_t Credential_List(DID *did, DIDURL **buffer, size_t size, int skip, int limit)
{
    if (!did || !buffer || size == 0 || skip < 0 || limit <= 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (limit > size) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Buffer to put credentials is smaller than 'limit' number.");
        return -1;
    }

    return DIDBackend_ListCredentials(did, buffer, size, skip, limit);
}
