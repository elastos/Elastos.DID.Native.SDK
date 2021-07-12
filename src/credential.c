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

static const char *ID = "id";
static const char *TYPE = "type";
static const char *ISSUER = "issuer";
static const char *ISSUANCE_DATE = "issuanceDate";
static const char *EXPIRATION_DATE = "expirationDate";
static const char *CREDENTIAL_SUBJECT = "credentialSubject";
static const char *PROOF = "proof";
static const char *VERIFICATION_METHOD = "verificationMethod";
static const char *CREATED = "created";
static const char *SIGNATURE = "signature";

static void free_subject(Credential *credential)
{
    assert(credential);

    if (credential->subject.properties)
        json_decref(credential->subject.properties);
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

static int parse_types(Credential *credential, json_t *json)
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

static int types_toJson(JsonGenerator *generator, Credential *credential)
{
    char **types;
    size_t i, size;

    assert(generator);
    assert(generator->buffer);
    assert(credential);

    size = credential->type.size;
    types = credential->type.types;
    qsort(types, size, sizeof(const char*), type_compr);

    CHECK(DIDJG_WriteStartArray(generator));
    for (i = 0; i < size; i++)
        CHECK(DIDJG_WriteString(generator, types[i]));
    CHECK(DIDJG_WriteEndArray(generator));

    return 0;
}

static int subject_toJson(JsonGenerator *generator, Credential *credential, DID *did, int compact)
{
    char id[ELA_MAX_DID_LEN];

    assert(generator);
    assert(generator->buffer);
    assert(credential);

    CHECK(DIDJG_WriteStartObject(generator));
    CHECK(DIDJG_WriteStringField(generator, ID,
            DID_ToString(&credential->subject.id, id, sizeof(id))));

    CHECK(JsonHelper_ToJson(generator, credential->subject.properties, true));
    CHECK(DIDJG_WriteEndObject(generator));
    return 0;
}

static int proof_toJson(JsonGenerator *generator, Credential *credential, int compact)
{
    char id[ELA_MAX_DIDURL_LEN];
    char _timestring[DOC_BUFFER_LEN];

    assert(generator);
    assert(generator->buffer);
    assert(credential);

    CHECK(DIDJG_WriteStartObject(generator));
    if (!compact)
        CHECK(DIDJG_WriteStringField(generator, TYPE, credential->proof.type));
    if (credential->proof.created != 0)
        CHECK(DIDJG_WriteStringField(generator, CREATED,
                get_time_string(_timestring, sizeof(_timestring), &credential->proof.created)));
    if (DID_Equals(&credential->id.did, &credential->proof.verificationMethod.did))
        CHECK(DIDJG_WriteStringField(generator, VERIFICATION_METHOD,
                DIDURL_ToString(&credential->proof.verificationMethod, id, sizeof(id), compact)));
    else
        CHECK(DIDJG_WriteStringField(generator, VERIFICATION_METHOD,
                DIDURL_ToString(&credential->proof.verificationMethod, id, sizeof(id), false)));
    CHECK(DIDJG_WriteStringField(generator, SIGNATURE, credential->proof.signatureValue));
    CHECK(DIDJG_WriteEndObject(generator));
    return 0;
}

int Credential_ToJson_Internal(JsonGenerator *gen, Credential *credential, DID *did,
        bool compact, bool forsign)
{
    char buf[MAX(DOC_BUFFER_LEN, ELA_MAX_DIDURL_LEN)];

    assert(gen);
    assert(gen->buffer);
    assert(credential);

    DIDURL_ToString(&credential->id, buf, sizeof(buf), compact);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, ID, buf));
    CHECK(DIDJG_WriteFieldName(gen, TYPE));
    CHECK(types_toJson(gen, credential));

    if (!compact || !DID_Equals(&credential->issuer, &credential->subject.id)) {
        CHECK(DIDJG_WriteStringField(gen, ISSUER,
                DID_ToString(&credential->issuer, buf, sizeof(buf))));
    }

    CHECK(DIDJG_WriteStringField(gen, ISSUANCE_DATE,
        get_time_string(buf, sizeof(buf), &credential->issuanceDate)));
    if (credential->expirationDate != 0)
        CHECK(DIDJG_WriteStringField(gen, EXPIRATION_DATE,
                get_time_string(buf, sizeof(buf), &credential->expirationDate)));
    CHECK(DIDJG_WriteFieldName(gen, CREDENTIAL_SUBJECT));
    CHECK(subject_toJson(gen, credential, did, compact));
    if (!forsign) {
        CHECK(DIDJG_WriteFieldName(gen, PROOF));
        CHECK(proof_toJson(gen, credential, compact));
    }
    CHECK(DIDJG_WriteEndObject(gen));

    return 0;
}

///////////////////////////////////////////////////////////////////////////
void Credential_Destroy(Credential *credential)
{
    DIDERROR_INITIALIZE();

    if (!credential)
        return;

    free_types(credential);
    if (credential->subject.properties)
        json_decref(credential->subject.properties);

    CredentialMetadata_Free(&credential->metadata);
    free(credential);

    DIDERROR_FINALIZE();
}

int Credential_IsSelfProclaimed(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to check.", -1);
    return DID_Equals(&credential->subject.id, &credential->issuer);

    DIDERROR_FINALIZE();
}

DIDURL *Credential_GetId(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get id.", NULL);
    return &credential->id;

    DIDERROR_FINALIZE();
}

DID *Credential_GetOwner(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get owner.", NULL);
    return &credential->subject.id;

    DIDERROR_FINALIZE();
}

ssize_t Credential_GetTypeCount(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get type count.", -1);
    return credential->type.size;

    DIDERROR_FINALIZE();
}

ssize_t Credential_GetTypes(Credential *credential, const char **types, size_t size)
{
    DIDERROR_INITIALIZE();

    size_t actual_size;

    CHECK_ARG(!credential, "No credential to get types.", -1);
    CHECK_ARG(!types || size == 0, "No buffer for types.", -1);

    actual_size = credential->type.size;
    CHECK_ARG(actual_size > size, "The buffer is too small.", -1);

    memcpy((void*)types, credential->type.types, sizeof(char*) * actual_size);
    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

DID *Credential_GetIssuer(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get issuer.", NULL);
    return &credential->issuer;

    DIDERROR_FINALIZE();
}

time_t Credential_GetIssuanceDate(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get issuance date.", 0);
    return credential->issuanceDate;

    DIDERROR_FINALIZE();
}

time_t Credential_GetExpirationDate_Internal(Credential *credential, DIDDocument *document)
{
    DIDDocument *doc;
    time_t _expire, expire;
    int status;

    assert(credential);
    assert(document);

    expire = DIDDocument_GetExpires(document);
    if (!expire)
        return 0;

    if (credential->expirationDate != 0)
        expire = MIN(expire, credential->expirationDate);

    if (Credential_IsSelfProclaimed(credential))
        return expire;

    doc = DID_Resolve(&credential->issuer, &status, false);
    if (!doc) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Issuer of credential %s %s.",
                DIDSTR(&credential->issuer), DIDSTATUS_MSG(status));
        return 0;
    }

    _expire = DIDDocument_GetExpires(doc);
    DIDDocument_Destroy(doc);
    if (!_expire)
        return 0;

    return MIN(expire, _expire);
}

time_t Credential_GetExpirationDate(Credential *credential)
{
    DIDDocument *doc;
    int status;
    time_t t;

    CHECK_ARG(!credential, "No credential to get expires date.", 0);

    doc = DID_Resolve(&credential->id.did, &status, false);
    if (!doc) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Owner of credential %s %s.",
                DIDSTR(&credential->id.did), DIDSTATUS_MSG(status));
        return 0;
    }

    t = Credential_GetExpirationDate_Internal(credential, doc);
    DIDDocument_Destroy(doc);
    return t;
}

ssize_t Credential_GetPropertyCount(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get property count.", -1);

    if (!credential->subject.properties) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No subjects in credential.");
        return -1;
    }

    return json_object_size(credential->subject.properties);

    DIDERROR_FINALIZE();
}

const char *Credential_GetProperties(Credential *credential)
{
    const char *data;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get properties.", NULL);

    if (!credential->subject.properties) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No subject in credential.");
        return NULL;
    }

    data = json_dumps(credential->subject.properties, JSON_COMPACT);
    if (!data)
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Serialize properties to json failed.");

    return data;

    DIDERROR_FINALIZE();
}

const char *Credential_GetProperty(Credential *credential, const char *name)
{
    json_t *item;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get property.", NULL);
    CHECK_ARG(!name || !*name, "No name argument.", NULL);

    if (!credential->subject.properties) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No subjects in credential.");
        return NULL;
    }

    item = json_object_get(credential->subject.properties, name);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "No this property in subject.");
        return NULL;
    }

    return json_astext(item);

    DIDERROR_FINALIZE();
}

time_t Credential_GetProofCreatedTime(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get created time.", 0);
    return credential->proof.created;

    DIDERROR_FINALIZE();
}

DIDURL *Credential_GetProofMethod(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get proof method.", NULL);
    return &credential->proof.verificationMethod;

    DIDERROR_FINALIZE();
}

const char *Credential_GetProofType(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get proof type.", NULL);
    return credential->proof.type;

    DIDERROR_FINALIZE();
}

const char *Credential_GetProofSignture(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get signature.", NULL);
    return credential->proof.signatureValue;

    DIDERROR_FINALIZE();
}

Credential *Credential_From_Internal(json_t *json, DID *did)
{
    Credential *credential;
    json_t *item, *field;

    assert(json);

    credential = (Credential*)calloc(1, sizeof(Credential));
    if (!credential) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credential failed.");
        return NULL;
    }

    item = json_object_get(json, CREDENTIAL_SUBJECT);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing credential subject.");
        goto errorExit;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid credential subject.");
        goto errorExit;
    }

    field = json_object_get(item, ID);
    if (!field) {
        if (!did) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing subject id.");
            goto errorExit;
        }
        DID_Copy(&credential->subject.id, did);
    } else {
        if (!json_is_string(field)) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid subject id.");
            goto errorExit;
        }
        if (DID_Parse(&credential->subject.id, json_string_value(field)) == -1) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid subject id.");
            goto errorExit;
        }
    }

    // properties exclude "id".
    json_object_del(item, ID);
    credential->subject.properties = json_deep_copy(item);

    //id
    item = json_object_get(json, ID);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing id.");
        goto errorExit;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid id.");
        goto errorExit;
    }
    if (DIDURL_Parse(&credential->id, json_string_value(item), &credential->subject.id) < 0) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid credential id.");
        goto errorExit;
    }

    if (!DID_Equals(&credential->id.did, &credential->subject.id)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Credential owner is not match with DID.");
        goto errorExit;
    }

    //issuer
    item = json_object_get(json, ISSUER);
    if (!item) {
        DID_Copy(&credential->issuer, &credential->id.did);
    } else {
        if (!json_is_string(item) || DID_Parse(&credential->issuer, json_string_value(item)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid issuer.");
            goto errorExit;
        }
    }

    //issuanceDate
    item = json_object_get(json, ISSUANCE_DATE);
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
    item = json_object_get(json, EXPIRATION_DATE);
    if (item && parse_time(&credential->expirationDate, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid expiration date.");
        goto errorExit;
    }

    if (!item)
        credential->expirationDate = 0;

    //proof
    item = json_object_get(json, PROOF);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing proof.");
        goto errorExit;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid proof.");
        goto errorExit;
    }

    field = json_object_get(item, TYPE);
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
    field = json_object_get(item, CREATED);
    if (field) {
        if (!json_is_string(field) ||
                parse_time(&credential->proof.created, json_string_value(field)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid create credential time.");
            goto errorExit;
        }
    }

    field = json_object_get(item, VERIFICATION_METHOD);
    if (!field) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing verification method.");
        goto errorExit;
    }
    if (!json_is_string(field) ||
            DIDURL_Parse(&credential->proof.verificationMethod,
            json_string_value(field), &credential->issuer) < 0) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid verification method.");
        goto errorExit;
    }

    field = json_object_get(item, SIGNATURE);
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

    //type
    item = json_object_get(json, TYPE);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Missing types.");
        goto errorExit;
    }
    if (!json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Invalid types.");
        goto errorExit;
    }
    if (parse_types(credential, item) == -1)
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

        Credential *credential = Credential_From_Internal(item, did);
        if (credential)
            creds[index++] = credential;
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

    CHECK(DIDJG_WriteStartArray(gen));
    for (i = 0; i < size; i++)
        CHECK(Credential_ToJson_Internal(gen, creds[i], did, compact, false));
    CHECK(DIDJG_WriteEndArray(gen));

    return 0;
}

const char* Credential_ToJson_ForSign(Credential *credential, bool compact, bool forsign)
{
    JsonGenerator g, *gen;

    CHECK_ARG(!credential, "No credential to generate data.", NULL);

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator for credential initialize failed.");
        return NULL;
    }

    if (Credential_ToJson_Internal(gen, credential, NULL, compact, forsign) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize credential to json failed.");
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

const char* Credential_ToJson(Credential *credential, bool normalized)
{
    DIDERROR_INITIALIZE();

    return Credential_ToJson_ForSign(credential, !normalized, false);

    DIDERROR_FINALIZE();
}

const char *Credential_ToString(Credential *credential, bool normalized)
{
    const char *data;
    json_t *json;
    json_error_t error;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to be string.", NULL);

    data = Credential_ToJson_ForSign(credential, !normalized, false);
    if (!data)
        return NULL;

    json = json_loads(data, JSON_COMPACT, &error);
    free((void*)data);
    if (!json){
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Deserialize credential failed, error: %s.", error.text);
        return NULL;
    }

    return json_dumps(json, JSON_COMPACT);

    DIDERROR_FINALIZE();
}

Credential *Credential_FromJson(const char *json, DID *did)
{
    json_t *root;
    json_error_t error;
    Credential *credential;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!json, "No credential json.", NULL);

    root = json_loads(json, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Deserialize credential failed, error: %s.", error.text);
        return NULL;
    }

    credential = Credential_From_Internal(root, did);
    json_decref(root);
    return credential;

    DIDERROR_FINALIZE();
}

DIDURL *Credential_GetVerificationMethod(Credential *credential)
{
    CHECK_ARG(!credential, "No credential to get verification method.", NULL);
    return &credential->proof.verificationMethod;
}

int Credential_Verify(Credential *credential)
{
    DIDDocument *doc;
    const char *data;
    int rc = -1, status;

    CHECK_ARG(!credential, "No credential to verify.", -1);

    doc = DID_Resolve(&credential->issuer, &status, false);
    if (!doc) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Issuer of credential %s %s.",
                DIDSTR(&credential->issuer), DIDSTATUS_MSG(status));
        return -1;
    }

    data = Credential_ToJson_ForSign(credential, false, true);
    if (!data)
        goto errorExit;

    rc = DIDDocument_Verify(doc, &credential->proof.verificationMethod,
            credential->proof.signatureValue, 1, data, strlen(data));
    free((void *)data);
    if (rc < 0)
        DIDError_Set(DIDERR_VERIFY_ERROR, "Verify credential failed.");

errorExit:
    DIDDocument_Destroy(doc);
    return rc;
}

int Credential_IsExpired_Internal(Credential *credential, DIDDocument *document)
{
    time_t expires;
    time_t now;

    assert(credential);
    assert(document);

    expires = Credential_GetExpirationDate_Internal(credential, document);
    now = time(NULL);

    if (now > expires)
        return true;

    return false;
}

int Credential_IsExpired(Credential *credential)
{
    time_t expires, now;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to check expired.", -1);

    expires = Credential_GetExpirationDate(credential);
    now = time(NULL);

    return now > expires ? 1 : 0;

    DIDERROR_FINALIZE();
}

int Credential_IsGenuine_Internal(Credential *credential, DIDDocument *document)
{
    DIDDocument *issuerdoc = NULL;
    const char *data;
    int genuine = 0, rc, status;

    assert(credential);

    issuerdoc = document;
    if (!issuerdoc) {
        issuerdoc = DID_Resolve(&credential->issuer, &status, false);
        if (!issuerdoc) {
            DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Issuer of credential %s %s.",
                    DIDSTR(&credential->issuer), DIDSTATUS_MSG(status));
            return -1;
        }
    }

    if (DIDDocument_IsAuthenticationKey(issuerdoc, &credential->proof.verificationMethod) != 1) {
        DIDError_Set(DIDERR_INVALID_KEY, "Verification key isn't an authentication key.");
        goto errorExit;
    }

    if (strcmp(credential->proof.type, ProofType)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Unknow credential proof type.");
        goto errorExit;
    }

    data = Credential_ToJson_ForSign(credential, false, true);
    if (!data) {
        genuine = -1;
        goto errorExit;
    }

    rc = DIDDocument_Verify(issuerdoc, &credential->proof.verificationMethod,
            credential->proof.signatureValue, 1, data, strlen(data));
    free((void *)data);
    if (rc < 0)
        DIDError_Set(DIDERR_VERIFY_ERROR, "Verify credential failed.");

    genuine = (rc == -1 ? 0 : 1);

errorExit:
    if (issuerdoc != document)
        DIDDocument_Destroy(issuerdoc);
    return genuine;
}

int Credential_IsGenuine(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to check genuine.", -1);
    return Credential_IsGenuine_Internal(credential, NULL);

    DIDERROR_FINALIZE();
}

int Credential_IsValid_Internal(Credential *credential, DIDDocument *document)
{
    DIDDocument *issuerdoc;
    int valid = 0, status;

    assert(credential);
    assert(document);

    if (!DID_Equals(&credential->id.did, &credential->subject.id)) {
        DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Credential id mismatch with Credential subject's owner.");
        return 0;
    }

    if (!Credential_IsSelfProclaimed(credential)) {
        issuerdoc = DID_Resolve(&credential->issuer, &status, false);
        if (!issuerdoc) {
            DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Issuer %s %s.", DIDSTR(&credential->issuer), DIDSTATUS_MSG(status));
            return -1;
        }

        if (DIDDocument_IsValid(issuerdoc) != 1) {
            DIDDocument_Destroy(issuerdoc);
            return 0;
        }
    } else {
        issuerdoc = document;
    }

    if (Credential_IsExpired_Internal(credential, document))
        goto errorExit;

    valid = Credential_IsGenuine_Internal(credential, issuerdoc);

errorExit:
    if (issuerdoc != document)
        DIDDocument_Destroy(issuerdoc);
    return valid;
}

int Credential_IsValid(Credential *credential)
{
    DIDDocument *doc;
    int valid, status;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to check validity.", -1);

    doc = DID_Resolve(&credential->subject.id, &status, false);
    if (!doc) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Owner of credential %s %s.",
                DIDSTR(&credential->subject.id), DIDSTATUS_MSG(status));
        return -1;
    }

    if (DIDDocument_IsValid(doc) != 1) {
        DIDDocument_Destroy(doc);
        return 0;
    }

    valid = Credential_IsValid_Internal(credential, doc);
    DIDDocument_Destroy(doc);
    return valid;

    DIDERROR_FINALIZE();
}

CredentialMetadata *Credential_GetMetadata(Credential *credential)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to get metadata.", NULL);
    return &credential->metadata;

    DIDERROR_FINALIZE();
}

int Credential_Copy(Credential *dest, Credential *src)
{
    size_t i;

    assert(dest);
    assert(src);

    DIDURL_Copy(&dest->id, &src->id);

    dest->type.types = (char**)calloc(src->type.size, sizeof(char*));
    if (!dest->type.types) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for types failed.");
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

int Credential_Declare(Credential *credential, DIDURL *signkey, const char *storepass)
{
    DIDDocument *doc = NULL;
    DIDStore *store;
    int success = -1, status, check;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to declare.", -1);
    CHECK_PASSWORD(storepass, -1);

    if (!CredentialMetadata_AttachedStore(&credential->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with credential.");
        return -1;
    }

    check = Credential_IsValid(credential);
    if (check != 1)
        return -1;

    if (Credential_IsRevoked(credential)) {
        DIDError_Set(DIDERR_CREDENTIAL_REVOKED, "Credential is revoked.");
        return -1;
    }

    if (Credential_WasDeclared(&credential->id)) {
        DIDError_Set(DIDERR_ALREADY_EXISTS, "Credential was already declared.");
        return -1;
    }

    store = credential->metadata.base.store;
    doc = DIDStore_LoadDID(store, &credential->subject.id);
    if (!doc) {
        doc = DID_Resolve(&credential->subject.id, &status, false);
        if (!doc) {
            DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "The owner of Credential %s %s.",
                    DIDSTR(&credential->subject.id), DIDSTATUS_MSG(status));
            return -1;
        }
        DIDMetadata_SetStore(&doc->metadata, store);
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(doc);
        if (!signkey) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please specify signkey.");
            goto errorExit;
        }
    } else {
        if(!DIDDocument_IsAuthenticationKey(doc, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Signkey isn't an authentication key.");
            goto errorExit;
        }
    }

    success = DIDBackend_DeclareCredential(credential, signkey, doc, storepass);

errorExit:
    DIDDocument_Destroy(doc);
    return success;

    DIDERROR_FINALIZE();
}

int Credential_Revoke(Credential *credential, DIDURL *signkey, const char *storepass)
{
    DIDDocument *ownerdoc = NULL, *issuerdoc = NULL, *signerdoc = NULL;
    DIDStore *store;
    int success = -1, status;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to be revoked.", -1);
    CHECK_PASSWORD(storepass, -1);

    if (!CredentialMetadata_AttachedStore(&credential->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with credential.");
        return -1;
    }

    if (!Credential_IsSelfProclaimed(credential) && !signkey) {
        DIDError_Set(DIDERR_INVALID_KEY, "Please specify the signkey for non-selfproclaimed credential.");
        return -1;
    }

    if (Credential_IsValid(credential) != 1)
        return -1;

    if (Credential_IsRevoked(credential) == 1) {
        DIDError_Set(DIDERR_CREDENTIAL_REVOKED, "The credential is revoked.");
        return -1;
    }

    store = credential->metadata.base.store;
    ownerdoc = DIDStore_LoadDID(store, &credential->id.did);
    if (!ownerdoc) {
        ownerdoc = DID_Resolve(&credential->id.did, &status, false);
        if (!ownerdoc) {
            DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "The owner of credential %s %s.",
                    DIDSTR(&credential->id.did), DIDSTATUS_MSG(status));
            return -1;
        }
        DIDMetadata_SetStore(&ownerdoc->metadata, store);
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(ownerdoc);
        if (!signkey) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please specify signkey.");
            goto errorExit;
        }
    } else {
        issuerdoc = DID_Resolve(&credential->issuer, &status, false);
        if (!issuerdoc) {
            DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "The issuer of Credential %s %s.",
                    DIDSTR(&credential->issuer), DIDSTATUS_MSG(status));
            goto errorExit;
        }

        if(!DIDDocument_IsAuthenticationKey(ownerdoc, signkey) &&
                !DIDDocument_IsAuthenticationKey(issuerdoc, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please specify an authentication key to sign.");
            goto errorExit;
        }
    }

    signerdoc = DID_Resolve(&credential->proof.verificationMethod.did, &status, false);
    if (!signerdoc) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "The signer of Credential %s %s.",
                DIDSTR(&credential->proof.verificationMethod.did), DIDSTATUS_MSG(status));
        goto errorExit;
    }
    DIDMetadata_SetStore(&signerdoc->metadata, store);

    success = DIDBackend_RevokeCredential(&credential->id, signkey, signerdoc, storepass);

errorExit:
    DIDDocument_Destroy(ownerdoc);
    DIDDocument_Destroy(issuerdoc);
    DIDDocument_Destroy(signerdoc);
    return success;

    DIDERROR_FINALIZE();
}

int Credential_RevokeById(DIDURL *id, DIDDocument *document, DIDURL *signkey,
        const char *storepass)
{
    DIDDocument *doc = NULL;
    DIDStore *store;
    Credential *local_vc;
    int brevoked, check;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No credential id to be revoked.", -1);
    CHECK_ARG(!document, "No document argument.", -1);
    CHECK_PASSWORD(storepass, -1);

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with document.");
        return -1;
    }

    store = document->metadata.base.store;
    local_vc = DIDStore_LoadCredential(store, &id->did, id);
    if (local_vc) {
        brevoked = Credential_IsRevoked(local_vc);
        Credential_Destroy(local_vc);
        if (brevoked != 0) {
            if (brevoked == 1)
                DIDError_Set(DIDERR_CREDENTIAL_REVOKED, "Credential is revoked.");
            return -1;
        }
    }

    check = Credential_ResolveRevocation(id, &document->did);
    if (check != 0) {
        if (check == 1)
            DIDError_Set(DIDERR_CREDENTIAL_REVOKED, "Credential is revoked.");
        return -1;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(document);
        if (!signkey) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please specify signkey.");
            return -1;
        }
    } else {
        if (!DIDDocument_IsAuthenticationKey(document, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please specify an authentication key.");
            return -1;
        }
    }

    return DIDBackend_RevokeCredential(id, signkey, document, storepass);

    DIDERROR_FINALIZE();
}

Credential *Credential_Resolve(DIDURL *id, int *status, bool force)
{
    DIDERROR_INITIALIZE();

    *status = -1;
    CHECK_ARG(!id, "No credential id to resolve.", NULL);
    return DIDBackend_ResolveCredential(id, status, force);

    DIDERROR_FINALIZE();
}

int Credential_ResolveRevocation(DIDURL *id, DID *issuer)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No credential id to get revoked status.", -1);
    return DIDBackend_ResolveRevocation(id, issuer);

    DIDERROR_FINALIZE();
}

CredentialBiography *Credential_ResolveBiography(DIDURL *id, DID *issuer)
{
    CHECK_ARG(!id, "No credential id to resolve biography.", NULL);
    return DIDBackend_ResolveCredentialBiography(id, issuer);
}

int Credential_WasDeclared(DIDURL *id)
{
    Credential *credential;
    int status, declared;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No credential id to check declared status.", -1);

    credential = Credential_Resolve(id, &status, true);
    declared = !credential ? 0 : 1;
    Credential_Destroy(credential);
    return declared;

    DIDERROR_FINALIZE();
}

int Credential_IsRevoked(Credential *credential)
{
    int revoke;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!credential, "No credential to check revoked status.", -1);

    revoke = CredentialMetadata_GetRevoke(&credential->metadata);
    if (revoke != 0)
        return revoke;

    return Credential_ResolveRevocation(&credential->id, &credential->issuer) ||
            Credential_ResolveRevocation(&credential->id, &credential->subject.id);

    DIDERROR_FINALIZE();
}

ssize_t Credential_List(DID *did, DIDURL **buffer, size_t size, int skip, int limit)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did to list credentials.", -1);
    CHECK_ARG(!buffer || size == 0, "Invalid buffer to list credentials.", -1);
    CHECK_ARG(skip < 0, "Invalid 'skip'.", -1);
    CHECK_ARG(limit < 0, "Invalid 'limit'.", -1);

    if (limit > size) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Buffer to put credentials is smaller than 'limit' number.");
        return -1;
    }

    return DIDBackend_ListCredentials(did, buffer, size, skip, limit);

    DIDERROR_FINALIZE();
}
