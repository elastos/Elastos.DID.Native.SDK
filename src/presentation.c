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
#include "did.h"
#include "diddocument.h"
#include "credential.h"
#include "presentation.h"
#include "didmeta.h"

static const char *PresentationType = "VerifiablePresentation";
extern const char *ProofType;

static int proof_toJson(JsonGenerator *gen, Presentation *pre, int compact)
{
    char id[ELA_MAX_DIDURL_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(pre);

    CHECK(DIDJG_WriteStartObject(gen));
    if (!compact)
        CHECK(DIDJG_WriteStringField(gen, "type", pre->proof.type));
    CHECK(DIDJG_WriteStringField(gen, "verificationMethod",
        DIDURL_ToString(&pre->proof.verificationMethod, id, sizeof(id), compact)));
    CHECK(DIDJG_WriteStringField(gen, "realm", pre->proof.realm));
    CHECK(DIDJG_WriteStringField(gen, "nonce", pre->proof.nonce));
    CHECK(DIDJG_WriteStringField(gen, "signature", pre->proof.signatureValue));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static int types_toJson(JsonGenerator *gen, Presentation *pre)
{
    char **types;
    size_t i, size;

    assert(gen);
    assert(pre);

    size = pre->type.size;
    types = pre->type.types;

    if (size != 1)
        CHECK(DIDJG_WriteStartArray(gen));

    for (i = 0; i < size; i++ )
        CHECK(DIDJG_WriteString(gen, types[i]));

    if (size != 1)
        CHECK(DIDJG_WriteEndArray(gen));

    return 0;
}

static int presentation_tojson_internal(JsonGenerator *gen, Presentation *pre,
        bool compact, bool forsign)
{
    char _timestring[DOC_BUFFER_LEN], idstring[ELA_MAX_DIDURL_LEN], *id;

    assert(gen);
    assert(gen->buffer);
    assert(pre);

    CHECK(DIDJG_WriteStartObject(gen));
    if (*pre->id.did.idstring) {
        id = DIDURL_ToString(&pre->id, idstring, sizeof(idstring), false);
        CHECK(DIDJG_WriteStringField(gen, "id", id));
    }
    if (pre->type.size > 1) {
        CHECK(DIDJG_WriteFieldName(gen, "type"));
        CHECK(types_toJson(gen, pre));
    } else {
        CHECK(DIDJG_WriteStringField(gen, "type", PresentationType));
    }

    if (*pre->holder.idstring)
        CHECK(DIDJG_WriteStringField(gen, "holder",
                DID_ToString(&pre->holder, idstring, sizeof(idstring))));

    CHECK(DIDJG_WriteStringField(gen, "created",
            get_time_string(_timestring, sizeof(_timestring), &pre->created)));

    CHECK(DIDJG_WriteFieldName(gen, "verifiableCredential"));
    CredentialArray_ToJson(gen, pre->credentials.credentials,
            pre->credentials.size, Presentation_GetHolder(pre), compact);
    if (!forsign) {
        CHECK(DIDJG_WriteFieldName(gen, "proof"));
        CHECK(proof_toJson(gen, pre, compact));
    }
    CHECK(DIDJG_WriteEndObject(gen));

    return 0;
}

static int parse_credentials_inpre(Presentation *pre, json_t *json, DID *holder)
{
    size_t size = 0;
    Credential **credentials = NULL;
    DID *did = NULL;
    bool equals = true;
    int i;

    assert(pre);
    assert(json);
    assert(holder);

    size = json_array_size(json);
    if (size < 0)
        return -1;

    if (size > 0) {
        credentials = (Credential**)calloc(size, sizeof(Credential*));
        if (!credentials)
            return -1;

        size = Parse_Credentials(NULL, credentials, size, json);
        if (size <= 0) {
            free(credentials);
            return -1;
        }
    }

    for (i = 0; i < size; i++) {
        if (!did) {
            did = &credentials[i]->subject.id;
        } else {
            if (!DID_Equals(did, &credentials[i]->subject.id)) {
                equals = false;
                break;
            }
        }
    }

    if (!equals || (did && !DID_Equals(did, holder))) {
        for (i = 0; i < size; i++)
            Credential_Destroy(credentials[i]);
        if (credentials)
            free((void*)credentials);

        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "The owner of credentials is not same or mismatch with holder.");
        return -1;
    }

    pre->credentials.credentials = credentials;
    pre->credentials.size = size;

    return 0;
}

static int parse_types(Presentation *pre, json_t *json)
{
    size_t i, size = 1, index = 0;
    json_t *item;
    char **types, *typestr;

    assert(pre);
    assert(json);

    if (json_is_array(json))
        size = json_array_size(json);

    types = (char**)calloc(size, sizeof(char*));
    if (!types) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credential types failed.");
        return -1;
    }

    for (i = 0; i < size; i++) {
        if (json_is_string(json))
            item = json;
        else
            item = json_array_get(json, i);

        if (!item || !json_is_string(item))
            continue;

        typestr = (char*)calloc(1, strlen(json_string_value(item)) + 1);
        if (!typestr)
            continue;

        strcpy(typestr, json_string_value(item));
        types[index++] = typestr;
    }

    if (!index) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "No credential type.");
        free(types);
        return -1;
    }

    pre->type.types = types;
    pre->type.size = index;
    return 0;
}

static int parse_proof(Presentation *pre, json_t *json)
{
    json_t *item;
    DIDURL *keyid, *signkey;

    assert(pre);
    assert(json);

    strcpy(pre->proof.type, ProofType);

    item = json_object_get(json, "verificationMethod");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing sign key for presentation.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid sign key for presentation.");
        return -1;
    }

    keyid = DIDURL_FromString(json_string_value(item), NULL);
    if (!keyid) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid sign key for presentation.");
        return -1;
    }

    signkey = DIDURL_Copy(&pre->proof.verificationMethod, keyid);
    DIDURL_Destroy(keyid);
    if (!signkey) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Copy sign key failed.");
        return -1;
    }

    item = json_object_get(json, "nonce");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing nonce.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid nonce.");
        return -1;
    }
    strcpy(pre->proof.nonce, json_string_value(item));

    item = json_object_get(json, "realm");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing realm.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid realm.");
        return -1;
    }
    strcpy(pre->proof.realm, json_string_value(item));

    item = json_object_get(json, "signature");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing signature.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid signature.");
        return -1;
    }
    strcpy(pre->proof.signatureValue, json_string_value(item));

    return 0;
}

static Presentation *parse_presentation(json_t *json)
{
    json_t *item;
    Presentation *pre = NULL;
    DIDURL *id;

    assert(json);

    pre = (Presentation*)calloc(1, sizeof(Presentation));
    if (!pre) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for presentation failed.");
        return NULL;
    }

    item = json_object_get(json, "id");
    if (item) {
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid id.");
            goto errorExit;
        }

        if (DIDURL_Parse(&pre->id, json_string_value(item), NULL) < 0) {
            DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid id.");
            goto errorExit;
        }
    }

    item = json_object_get(json, "type");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing type.");
        goto errorExit;
    }

    if (!json_is_string(item) && !json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid type.");
        goto errorExit;
    }

    if (parse_types(pre, item) < 0)
        goto errorExit;

    item = json_object_get(json, "created");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing time created presentation.");
        goto errorExit;
    }
    if (!json_is_string(item) || parse_time(&pre->created, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid time created presentation.");
        goto errorExit;
    }

    item = json_object_get(json, "proof");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing presentation proof.");
        goto errorExit;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid presentation proof.");
        goto errorExit;
    }
    if (parse_proof(pre, item) == -1)
        goto errorExit;

    item = json_object_get(json, "holder");
    if (item) {
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid holder.");
            goto errorExit;
        }

        if (DID_Parse(&pre->holder, json_string_value(item)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid holder.");
            goto errorExit;
        }
    }

    item = json_object_get(json, "verifiableCredential");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing Credentials.");
        goto errorExit;
    }
    if (!json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid Credentials.");
        goto errorExit;
    }

    if (parse_credentials_inpre(pre, item, Presentation_GetHolder(pre)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid credential error[%d]: %s", DIDERRCODE, DIDERRMSG);
        goto errorExit;
    }

    id = Presentation_GetId(pre);
    if ( id && !DID_Equals(Presentation_GetHolder(pre), &id->did)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "The holder mismatch with the id of persentation.");
        goto errorExit;
    }

    return pre;

errorExit:
    Presentation_Destroy(pre);
    return NULL;
}

static int add_credential(Credential **creds, int index, Credential *cred)
{
    Credential *_cred;

    assert(creds);
    assert(cred);

    _cred = (Credential*)calloc(1, sizeof(Credential));
    if (!_cred)
        return -1;

    if (Credential_Copy(_cred, cred) < 0) {
        Credential_Destroy(_cred);
        return -1;
    }

    creds[index] = _cred;
    return 0;
}

static const char* presentation_tojson_forsign(Presentation *pre, bool compact, bool forsign)
{
    JsonGenerator g, *gen;

    if (!pre)
        return NULL;

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator initialize failed.");
        return NULL;
    }

    if (presentation_tojson_internal(gen, pre, compact, forsign) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize presentation to json failed.");
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

static int add_credentialarray_to_presentation(Presentation *pre, int count, Credential **creds)
{
    Credential **credentials = NULL, *cred;
    int i;

    assert(pre);
    assert(count >= 0);
    assert(creds);

    if (count > 0) {
        for (i = 0; i < count; i++) {
            cred = creds[i];
            if (!DID_Equals(&cred->subject.id, &pre->holder)) {
                DIDError_Set(DIDERR_ILLEGALUSAGE, "Credentials does not owned to holder.");
                return -1;
            }
        }

        credentials = (Credential**)calloc(count, sizeof(Credential*));
        if (!credentials) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credentials failed.");
            return -1;
        }

        for (i = 0; i < count && creds[i]; i++) {
            if (Credential_Verify(creds[i]) == -1 || Credential_IsExpired(creds[i])) {
                free(credentials);
                return -1;
            }

            add_credential(credentials, i, creds[i]);
        }
    }

    pre->credentials.credentials = credentials;
    pre->credentials.size = count;
    return 0;
}

static int seal_presentation(Presentation *pre, DIDDocument *doc, DIDURL *signkey,
        const char *storepass, const char *nonce, const char *realm)
{
    DIDDocument *signerdoc;
    const char *data;
    char signature[SIGNATURE_BYTES * 2 + 16];
    int rc;

    assert(pre);
    assert(doc);
    assert(signkey);
    assert(storepass && *storepass);
    assert(nonce && *nonce);
    assert(realm && *realm);

    time(&pre->created);

    data = presentation_tojson_forsign(pre, false, true);
    if (!data)
        return -1;

    if (!DIDDocument_IsCustomizedDID(doc)) {
        signerdoc = doc;
    } else {
        signerdoc = DIDDocument_GetControllerDocument(doc, &signkey->did);
        if (!signerdoc) {
            free((void*)data);
            DIDError_Set(DIDERR_INVALID_KEY, "The sign key is not ");
            return -1;
        }
        DIDMetadata_SetStore(&signerdoc->metadata, DIDMetadata_GetStore(&doc->metadata));
    }

    rc = DIDDocument_Sign(signerdoc, signkey, storepass, signature, 3,
            (unsigned char*)data, strlen(data),
            (unsigned char*)realm, strlen(realm),
            (unsigned char*)nonce, strlen(nonce));
    free((void*)data);
    if (rc < 0)
        return -1;

    strcpy(pre->proof.type, ProofType);
    DIDURL_Copy(&pre->proof.verificationMethod, signkey);
    strcpy(pre->proof.nonce, nonce);
    strcpy(pre->proof.realm, realm);
    strcpy(pre->proof.signatureValue, signature);

    return 0;
}

////////////////////////////////////////////////////////////////////////////
static Presentation *create_presentation(DIDURL *id, DID *holder,
        const char **types, size_t size, const char *nonce, const char *realm,
        Credential **creds, size_t count, DIDURL *signkey, DIDStore *store,
        const char *storepass)
{
    Presentation *pre = NULL;
    DIDDocument *doc = NULL;
    int rc, i;

    assert(id);
    assert(holder);
    assert(nonce);
    assert(realm);
    assert(store);
    assert(storepass && *storepass);

    if (!DID_Equals(&id->did, holder)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The id mismatch with holder.");
        return NULL;
    }

    doc = DIDStore_LoadDID(store, holder);
    if (!doc) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Can not load DID.");
        return NULL;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(doc);
        if (!signkey) {
            DIDError_Set(DIDERR_INVALID_ARGS, "Please specify the sign key.");
            goto errorExit;
        }
    } else {
        if (!DIDDocument_IsAuthenticationKey(doc, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Invalid sign key.");
            goto errorExit;
        }
    }

    if (!DIDStore_ContainsPrivateKey(store, &signkey->did, signkey)) {
        DIDError_Set(DIDERR_INVALID_KEY, "No private key.");
        goto errorExit;
    }

    pre = (Presentation*)calloc(1, sizeof(Presentation));
    if (!pre) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for presentation failed.");
        goto errorExit;
    }

    DIDURL_Copy(&pre->id, id);
    DID_Copy(&pre->holder, holder);

    if (!types)
        size = 1;

    pre->type.types = (char **)calloc(size, sizeof(char *));
    if (!pre->type.types) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for types failed.");
        goto errorExit;
    }

    if (!types) {
        pre->type.types[0] = strdup(PresentationType);
    } else {
        for (i = 0; i < size; i++)
            pre->type.types[i] = strdup(types[i]);
    }
    pre->type.size = size;

    if (creds && add_credentialarray_to_presentation(pre, count, creds) < 0)
        goto errorExit;

    rc = seal_presentation(pre, doc, signkey, storepass, nonce, realm);
    if (rc < 0)
        goto errorExit;

    DIDDocument_Destroy(doc);
    return pre;

errorExit:
    DIDDocument_Destroy(doc);
    Presentation_Destroy(pre);
    return NULL;
}

Presentation *Presentation_Create(DIDURL *id, DID *holder,
        const char **types, size_t size, const char *nonce, const char *realm,
        DIDURL *signkey, DIDStore *store, const char *storepass, int count, ...)
{
    va_list list;
    Credential **creds;
    int i;

    DIDERROR_INITIALIZE();

    if (!id || !holder || !nonce || !*nonce || !realm || !*realm || !store ||
            !storepass || !*storepass || count < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (count == 0) {
        creds = NULL;
    } else {
        creds = (Credential **)alloca(sizeof(Credential*) * count);
        if (!creds) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credentials failed.");
            return NULL;
        }
    }

    va_start(list, count);
    for (i = 0; i < count; i++)
        creds[i] = va_arg(list, Credential*);

    va_end(list);

    return create_presentation(id, holder, types, size, nonce, realm, creds, count,
            signkey, store, storepass);

    DIDERROR_FINALIZE();
}

Presentation *Presentation_CreateByCredentials(DIDURL *id, DID *holder,
        const char **types, size_t size, const char *nonce, const char *realm,
        Credential **creds, size_t count, DIDURL *signkey, DIDStore *store,
        const char *storepass)
{
    DIDERROR_INITIALIZE();

    if (!id || !holder || !nonce || !*nonce || !realm || !*realm || count < 0 ||
            !store || !storepass || !*storepass ) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return create_presentation(id, holder, types, size, nonce, realm, creds, count,
            signkey, store, storepass);

    DIDERROR_FINALIZE();
}

void Presentation_Destroy(Presentation *pre)
{
    size_t i;

    DIDERROR_INITIALIZE();

    if (!pre)
        return;

    if (pre->type.size > 0) {
        for (i = 0; i < pre->type.size; i++)
            free((void*)pre->type.types[i]);
        free((void*)pre->type.types);
    }

    if (pre->credentials.credentials) {
        for (i = 0; i < pre->credentials.size; i++) {
            Credential *cred = pre->credentials.credentials[i];
            if (cred)
                Credential_Destroy(cred);
        }

        free(pre->credentials.credentials);
    }
    free(pre);

    DIDERROR_FINALIZE();
}

const char* Presentation_ToJson(Presentation *pre, bool normalized)
{
    DIDERROR_INITIALIZE();

    return presentation_tojson_forsign(pre, !normalized, false);

    DIDERROR_FINALIZE();
}

Presentation *Presentation_FromJson(const char *json)
{
    json_t *root;
    json_error_t error;
    Presentation *pre;

    DIDERROR_INITIALIZE();

    if (!json) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    root = json_loads(json, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Deserialize presentation failed, error: %s.", error.text);
        return NULL;
    }

    pre = parse_presentation(root);
    if (!pre) {
        json_decref(root);
        return NULL;
    }

    json_decref(root);
    return pre;

    DIDERROR_FINALIZE();
}

DIDURL *Presentation_GetId(Presentation *pre)
{
    DIDERROR_INITIALIZE();

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (*pre->id.did.idstring && *pre->id.fragment)
        return &pre->id;

    return NULL;

    DIDERROR_FINALIZE();
}

DID *Presentation_GetHolder(Presentation *pre)
{
    DIDERROR_INITIALIZE();

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (*pre->holder.idstring)
        return &pre->holder;

    return &pre->proof.verificationMethod.did;

    DIDERROR_FINALIZE();
}

ssize_t Presentation_GetCredentialCount(Presentation *pre)
{
    DIDERROR_INITIALIZE();

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return pre->credentials.size;

    DIDERROR_FINALIZE();
}

ssize_t Presentation_GetCredentials(Presentation *pre, Credential **creds, size_t size)
{
    size_t actual_size;

    DIDERROR_INITIALIZE();

    if (!pre || !creds || size < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    actual_size = pre->credentials.size;
    if (actual_size == 0)
        return 0;

    if (actual_size > size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
        return -1;
    }

    memcpy(creds, pre->credentials.credentials, sizeof(Credential*) * actual_size);
    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

Credential *Presentation_GetCredential(Presentation *pre, DIDURL *credid)
{
    DIDERROR_INITIALIZE();

    Credential *cred;
    size_t i;

    if (!pre || !credid) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }
    if (pre->credentials.size <= 0) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "No credentials in presentation.");
        return NULL;
    }

    for (i = 0; i < pre->credentials.size; i++) {
        cred = pre->credentials.credentials[i];
        if (DIDURL_Equals(Credential_GetId(cred), credid))
            return cred;
    }

    return NULL;

    DIDERROR_FINALIZE();
}

ssize_t Presentation_GetTypeCount(Presentation *pre)
{
    DIDERROR_INITIALIZE();

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return pre->type.size;

    DIDERROR_FINALIZE();
}

ssize_t Presentation_GetTypes(Presentation *pre, const char **types, size_t size)
{
    size_t actual_size;

    DIDERROR_INITIALIZE();

    if (!pre || !types || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    actual_size = pre->type.size;
    if (actual_size > size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The size of buffer is small.");
        return -1;
    }

    memcpy((void*)types, pre->type.types, sizeof(char*) * actual_size);
    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

time_t Presentation_GetCreatedTime(Presentation *pre)
{
    DIDERROR_INITIALIZE();

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    return pre->created;

    DIDERROR_FINALIZE();
}

DIDURL *Presentation_GetVerificationMethod(Presentation *pre)
{
    DIDERROR_INITIALIZE();

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &pre->proof.verificationMethod;

    DIDERROR_FINALIZE();
}

const char *Presentation_GetNonce(Presentation *pre)
{
    DIDERROR_INITIALIZE();

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return pre->proof.nonce;

    DIDERROR_FINALIZE();
}

const char *Presentation_GetRealm(Presentation *pre)
{
    DIDERROR_INITIALIZE();

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return pre->proof.realm;

    DIDERROR_FINALIZE();
}

static bool check_presentation(Presentation *pre, bool validtype)
{
    DIDDocument *doc = NULL;
    int rc = -1, status, i;
    const char *data;

    assert(pre);

    doc = DID_Resolve(Presentation_GetHolder(pre), &status, false);
    if (!doc) {
        if (status == DIDStatus_NotFound)
            DIDError_Set(DIDERR_NOT_EXISTS, "Presentation holder is not a published did.");
        return false;
    }

    if (validtype) {
        if (!DIDDocument_IsValid(doc))
            goto errorExit;
    } else {
        if (!DIDDocument_IsGenuine(doc)) {
            DIDError_Set(DIDERR_NOT_GENUINE, "Signer is not genuine.");
            goto errorExit;
        }
    }

    if (!DIDDocument_IsAuthenticationKey(doc, &pre->proof.verificationMethod)) {
        DIDError_Set(DIDERR_INVALID_KEY, "Invalid authentication key.");
        goto errorExit;
    }

    if (pre->credentials.size > 0 && !pre->credentials.credentials) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing credentials.");
        goto errorExit;
    }

    for (i = 0; i < pre->credentials.size; i++) {
        Credential *cred = pre->credentials.credentials[i];
        if (!cred) {
            DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing credential.");
            goto errorExit;
        }
        if (!DID_Equals(&cred->subject.id, Presentation_GetHolder(pre))) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Credential is not match with signer.");
            goto errorExit;
        }
        if (validtype) {
            if (!Credential_IsValid(cred))
                goto errorExit;
        } else {
            if (!Credential_IsGenuine(cred)) {
                DIDError_Set(DIDERR_NOT_GENUINE, "Credential is not genuine.");
                goto errorExit;
            }
        }
    }

    data = presentation_tojson_forsign(pre, false, true);
    if (!data)
        goto errorExit;

    rc = DIDDocument_Verify(doc, &pre->proof.verificationMethod,
            pre->proof.signatureValue, 3, (unsigned char*)data, strlen(data),
            pre->proof.realm, strlen(pre->proof.realm),
            pre->proof.nonce, strlen(pre->proof.nonce));
    free((void*)data);

errorExit:
    DIDDocument_Destroy(doc);
    return rc == 0;
}

bool Presentation_IsGenuine(Presentation *pre)
{
    DIDERROR_INITIALIZE();

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return check_presentation(pre, false);

    DIDERROR_FINALIZE();
}

bool Presentation_IsValid(Presentation *pre)
{
    DIDERROR_INITIALIZE();

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    return check_presentation(pre, true);

    DIDERROR_FINALIZE();
}
