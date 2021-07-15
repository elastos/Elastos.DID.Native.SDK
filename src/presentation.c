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
#include "did.h"
#include "diddocument.h"
#include "credential.h"
#include "presentation.h"
#include "didmeta.h"

static const char *PresentationType = "VerifiablePresentation";
extern const char *ProofType;

static const char *ID = "id";
static const char *TYPE = "type";
static const char *HOLDER = "holder";
static const char *VERIFIABLE_CREDENTIAL = "verifiableCredential";
static const char *CREATED = "created";
static const char *PROOF = "proof";
static const char *NONCE = "nonce";
static const char *REALM = "realm";
static const char *VERIFICATION_METHOD = "verificationMethod";
static const char *SIGNATURE = "signature";

static int proof_toJson(JsonGenerator *gen, Presentation *presentation, int compact)
{
    char id[ELA_MAX_DIDURL_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(presentation);

    CHECK(DIDJG_WriteStartObject(gen));
    if (!compact)
        CHECK(DIDJG_WriteStringField(gen, TYPE, presentation->proof.type));
    CHECK(DIDJG_WriteStringField(gen, VERIFICATION_METHOD,
        DIDURL_ToString(&presentation->proof.verificationMethod, id, sizeof(id), compact)));
    CHECK(DIDJG_WriteStringField(gen, REALM, presentation->proof.realm));
    CHECK(DIDJG_WriteStringField(gen, NONCE, presentation->proof.nonce));
    CHECK(DIDJG_WriteStringField(gen, SIGNATURE, presentation->proof.signatureValue));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static int types_toJson(JsonGenerator *gen, Presentation *presentation)
{
    char **types;
    size_t i, size;

    assert(gen);
    assert(presentation);

    size = presentation->type.size;
    types = presentation->type.types;

    if (size != 1)
        CHECK(DIDJG_WriteStartArray(gen));

    for (i = 0; i < size; i++ )
        CHECK(DIDJG_WriteString(gen, types[i]));

    if (size != 1)
        CHECK(DIDJG_WriteEndArray(gen));

    return 0;
}

static int presentation_tojson_internal(JsonGenerator *gen, Presentation *presentation,
        bool compact, bool forsign)
{
    char _timestring[DOC_BUFFER_LEN], idstring[ELA_MAX_DIDURL_LEN], *id;

    assert(gen);
    assert(gen->buffer);
    assert(presentation);

    CHECK(DIDJG_WriteStartObject(gen));
    if (*presentation->id.did.idstring) {
        id = DIDURL_ToString(&presentation->id, idstring, sizeof(idstring), false);
        CHECK(DIDJG_WriteStringField(gen, ID, id));
    }
    if (presentation->type.size > 1) {
        CHECK(DIDJG_WriteFieldName(gen, TYPE));
        CHECK(types_toJson(gen, presentation));
    } else {
        CHECK(DIDJG_WriteStringField(gen, TYPE, PresentationType));
    }

    if (*presentation->holder.idstring)
        CHECK(DIDJG_WriteStringField(gen, HOLDER,
                DID_ToString(&presentation->holder, idstring, sizeof(idstring))));

    CHECK(DIDJG_WriteStringField(gen, CREATED,
            get_time_string(_timestring, sizeof(_timestring), &presentation->created)));

    CHECK(DIDJG_WriteFieldName(gen, VERIFIABLE_CREDENTIAL));
    CredentialArray_ToJson(gen, presentation->credentials.credentials,
            presentation->credentials.size, Presentation_GetHolder(presentation), compact);
    if (!forsign) {
        CHECK(DIDJG_WriteFieldName(gen, PROOF));
        CHECK(proof_toJson(gen, presentation, compact));
    }
    CHECK(DIDJG_WriteEndObject(gen));

    return 0;
}

static int parse_credentials_inpre(Presentation *presentation, json_t *json, DID *holder)
{
    size_t size = 0;
    Credential **credentials = NULL;
    DID *did = NULL;
    bool equals = true;
    int i;

    assert(presentation);
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

    presentation->credentials.credentials = credentials;
    presentation->credentials.size = size;

    return 0;
}

static int parse_types(Presentation *presentation, json_t *json)
{
    size_t i, size = 1, index = 0;
    json_t *item;
    char **types, *typestr;

    assert(presentation);
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

    presentation->type.types = types;
    presentation->type.size = index;
    return 0;
}

static int parse_proof(Presentation *presentation, json_t *json)
{
    json_t *item;
    DIDURL *keyid, *signkey;

    assert(presentation);
    assert(json);

    strcpy(presentation->proof.type, ProofType);

    item = json_object_get(json, VERIFICATION_METHOD);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing signkey for presentation.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid signkey for presentation.");
        return -1;
    }

    keyid = DIDURL_FromString(json_string_value(item), NULL);
    if (!keyid) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid signkey for presentation.");
        return -1;
    }

    signkey = DIDURL_Copy(&presentation->proof.verificationMethod, keyid);
    DIDURL_Destroy(keyid);
    if (!signkey) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Copy signkey failed.");
        return -1;
    }

    item = json_object_get(json, NONCE);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing nonce.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid nonce.");
        return -1;
    }
    strcpy(presentation->proof.nonce, json_string_value(item));

    item = json_object_get(json, REALM);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing realm.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid realm.");
        return -1;
    }
    strcpy(presentation->proof.realm, json_string_value(item));

    item = json_object_get(json, SIGNATURE);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing signature.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid signature.");
        return -1;
    }
    strcpy(presentation->proof.signatureValue, json_string_value(item));

    return 0;
}

static Presentation *parse_presentation(json_t *json)
{
    json_t *item;
    Presentation *presentation = NULL;
    DIDURL *id;

    assert(json);

    presentation = (Presentation*)calloc(1, sizeof(Presentation));
    if (!presentation) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for presentation failed.");
        return NULL;
    }

    item = json_object_get(json, ID);
    if (item) {
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid id.");
            goto errorExit;
        }

        if (DIDURL_Parse(&presentation->id, json_string_value(item), NULL) < 0) {
            DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid id.");
            goto errorExit;
        }
    }

    item = json_object_get(json, TYPE);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing type.");
        goto errorExit;
    }

    if (!json_is_string(item) && !json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid type.");
        goto errorExit;
    }

    if (parse_types(presentation, item) < 0)
        goto errorExit;

    item = json_object_get(json, CREATED);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing time created presentation.");
        goto errorExit;
    }
    if (!json_is_string(item) || parse_time(&presentation->created, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid time created presentation.");
        goto errorExit;
    }

    item = json_object_get(json, PROOF);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing presentation proof.");
        goto errorExit;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid presentation proof.");
        goto errorExit;
    }
    if (parse_proof(presentation, item) == -1)
        goto errorExit;

    item = json_object_get(json, HOLDER);
    if (item) {
        if (!json_is_string(item)) {
            DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid holder.");
            goto errorExit;
        }

        if (DID_Parse(&presentation->holder, json_string_value(item)) < 0) {
            DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid holder.");
            goto errorExit;
        }
    }

    item = json_object_get(json, VERIFIABLE_CREDENTIAL);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing Credentials.");
        goto errorExit;
    }
    if (!json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid Credentials.");
        goto errorExit;
    }

    if (parse_credentials_inpre(presentation, item, Presentation_GetHolder(presentation)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid credential error[%d]: %s", DIDERRCODE, DIDERRMSG);
        goto errorExit;
    }

    id = Presentation_GetId(presentation);
    if ( id && !DID_Equals(Presentation_GetHolder(presentation), &id->did)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "The holder mismatch with the id of persentation.");
        goto errorExit;
    }

    return presentation;

errorExit:
    Presentation_Destroy(presentation);
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

static const char* presentation_tojson_forsign(Presentation *presentation, bool compact, bool forsign)
{
    JsonGenerator g, *gen;

    assert(presentation);

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator for presentation initialize failed.");
        return NULL;
    }

    if (presentation_tojson_internal(gen, presentation, compact, forsign) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize presentation to json failed.");
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

static int add_credentialarray_to_presentation(Presentation *presentation, int count, Credential **creds)
{
    Credential **credentials = NULL, *cred;
    int i;

    assert(presentation);
    assert(count >= 0);
    assert(creds);

    if (count > 0) {
        for (i = 0; i < count; i++) {
            cred = creds[i];
            if (!DID_Equals(&cred->subject.id, &presentation->holder)) {
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
            if (Credential_Verify(creds[i]) == -1) {
                DIDError_Set(DIDERR_VERIFY_ERROR, "Verify credential(%s) failed.", DIDURLSTR(&creds[i]->id));
                free(credentials);
                return -1;
            }
            if (Credential_IsExpired(creds[i])) {
                DIDError_Set(DIDERR_EXPIRED, "Credential(%s) is expired.", DIDURLSTR(&creds[i]->id));
                free(credentials);
                return -1;
            }

            add_credential(credentials, i, creds[i]);
        }
    }

    presentation->credentials.credentials = credentials;
    presentation->credentials.size = count;
    return 0;
}

static int seal_presentation(Presentation *presentation, DIDDocument *doc, DIDURL *signkey,
        const char *storepass, const char *nonce, const char *realm)
{
    DIDDocument *signerdoc;
    const char *data;
    char signature[SIGNATURE_BYTES * 2 + 16];
    int rc;

    assert(presentation);
    assert(doc);
    assert(signkey);
    assert(storepass && *storepass);
    assert(nonce && *nonce);
    assert(realm && *realm);

    time(&presentation->created);

    data = presentation_tojson_forsign(presentation, false, true);
    if (!data)
        return -1;

    if (!DIDDocument_IsAuthenticationKey(doc, signkey)) {
        free((void*)data);
        DIDError_Set(DIDERR_INVALID_KEY, "Signkey isn't an authentication key.");
        return -1;
    }

    if (!DIDDocument_IsCustomizedDID(doc)) {
        signerdoc = doc;
    } else {
        signerdoc = DIDDocument_GetControllerDocument(doc, &signkey->did);
        if (!signerdoc)
            signerdoc = doc;

        DIDMetadata_SetStore(&signerdoc->metadata, DIDMetadata_GetStore(&doc->metadata));
    }

    rc = DIDDocument_Sign(signerdoc, signkey, storepass, signature, 3,
            (unsigned char*)data, strlen(data),
            (unsigned char*)realm, strlen(realm),
            (unsigned char*)nonce, strlen(nonce));
    free((void*)data);
    if (rc < 0) {
        DIDError_Set(DIDERR_SIGN_ERROR, "Sign presentation failed.");
        return -1;
    }

    strcpy(presentation->proof.type, ProofType);
    DIDURL_Copy(&presentation->proof.verificationMethod, signkey);
    strcpy(presentation->proof.nonce, nonce);
    strcpy(presentation->proof.realm, realm);
    strcpy(presentation->proof.signatureValue, signature);

    return 0;
}

////////////////////////////////////////////////////////////////////////////
static Presentation *create_presentation(DIDURL *id, DID *holder,
        const char **types, size_t size, const char *nonce, const char *realm,
        Credential **creds, size_t count, DIDURL *signkey, DIDStore *store,
        const char *storepass)
{
    Presentation *presentation = NULL;
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
        DIDError_Set(DIDERR_NOT_EXISTS, "No valid holder document in store.");
        return NULL;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(doc);
        if (!signkey) {
            DIDError_Set(DIDERR_INVALID_KEY, "Please specify signkey.");
            goto errorExit;
        }
    } else {
        if (!DIDDocument_IsAuthenticationKey(doc, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "Invalid signkey.");
            goto errorExit;
        }
    }

    if (!DIDStore_ContainsPrivateKey(store, &signkey->did, signkey)) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No privatekey of signkey.");
        goto errorExit;
    }

    presentation = (Presentation*)calloc(1, sizeof(Presentation));
    if (!presentation) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for presentation failed.");
        goto errorExit;
    }

    DIDURL_Copy(&presentation->id, id);
    DID_Copy(&presentation->holder, holder);

    if (!types)
        size = 1;

    presentation->type.types = (char **)calloc(size, sizeof(char *));
    if (!presentation->type.types) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for types failed.");
        goto errorExit;
    }

    if (!types) {
        presentation->type.types[0] = strdup(PresentationType);
    } else {
        for (i = 0; i < size; i++)
            presentation->type.types[i] = strdup(types[i]);
    }
    presentation->type.size = size;

    if (creds && add_credentialarray_to_presentation(presentation, count, creds) < 0)
        goto errorExit;

    rc = seal_presentation(presentation, doc, signkey, storepass, nonce, realm);
    if (rc < 0)
        goto errorExit;

    DIDDocument_Destroy(doc);
    return presentation;

errorExit:
    DIDDocument_Destroy(doc);
    Presentation_Destroy(presentation);
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

    CHECK_ARG(!id, "No presentation id.", NULL);
    CHECK_ARG(!holder, "No holder argument for presentation.", NULL);
    CHECK_ARG(!nonce || !*nonce, "No nonce string.", NULL);
    CHECK_ARG(!realm || !*realm, "No realm string.", NULL);
    CHECK_ARG(!store, "No store argument.", NULL);
    CHECK_PASSWORD(storepass, NULL);
    CHECK_ARG(count < 0, "Invalid count.", NULL);

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

    CHECK_ARG(!id, "No presentation id.", NULL);
    CHECK_ARG(!holder, "No holder argument for presentation.", NULL);
    CHECK_ARG(!nonce || !*nonce, "No nonce string.", NULL);
    CHECK_ARG(!realm || !*realm, "No realm string.", NULL);
    CHECK_ARG(!store, "No store argument.", NULL);
    CHECK_PASSWORD(storepass, NULL);

    return create_presentation(id, holder, types, size, nonce, realm, creds, count,
            signkey, store, storepass);

    DIDERROR_FINALIZE();
}

void Presentation_Destroy(Presentation *presentation)
{
    size_t i;

    DIDERROR_INITIALIZE();

    if (!presentation)
        return;

    if (presentation->type.size > 0) {
        for (i = 0; i < presentation->type.size; i++)
            free((void*)presentation->type.types[i]);
        free((void*)presentation->type.types);
    }

    if (presentation->credentials.credentials) {
        for (i = 0; i < presentation->credentials.size; i++) {
            Credential *cred = presentation->credentials.credentials[i];
            if (cred)
                Credential_Destroy(cred);
        }

        free(presentation->credentials.credentials);
    }
    free(presentation);

    DIDERROR_FINALIZE();
}

const char* Presentation_ToJson(Presentation *presentation, bool normalized)
{
    DIDERROR_INITIALIZE();

    return presentation_tojson_forsign(presentation, !normalized, false);

    DIDERROR_FINALIZE();
}

Presentation *Presentation_FromJson(const char *json)
{
    json_t *root;
    json_error_t error;
    Presentation *presentation;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!json, "No json string.", NULL);

    root = json_loads(json, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Deserialize presentation failed, error: %s.", error.text);
        return NULL;
    }

    presentation = parse_presentation(root);
    if (!presentation) {
        json_decref(root);
        return NULL;
    }

    json_decref(root);
    return presentation;

    DIDERROR_FINALIZE();
}

DIDURL *Presentation_GetId(Presentation *presentation)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", NULL);

    if (*presentation->id.did.idstring && *presentation->id.fragment)
        return &presentation->id;

    return NULL;

    DIDERROR_FINALIZE();
}

DID *Presentation_GetHolder(Presentation *presentation)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", NULL);

    if (*presentation->holder.idstring)
        return &presentation->holder;

    return &presentation->proof.verificationMethod.did;

    DIDERROR_FINALIZE();
}

ssize_t Presentation_GetCredentialCount(Presentation *presentation)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", -1);
    return presentation->credentials.size;

    DIDERROR_FINALIZE();
}

ssize_t Presentation_GetCredentials(Presentation *presentation, Credential **creds, size_t size)
{
    size_t actual_size;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", -1);
    CHECK_ARG(!creds || size < 0, "Invalid buffer to get credentials.", -1);

    actual_size = presentation->credentials.size;
    if (actual_size == 0)
        return 0;

    CHECK_ARG(actual_size > size, "The buffer is too small.", -1);

    memcpy(creds, presentation->credentials.credentials, sizeof(Credential*) * actual_size);
    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

Credential *Presentation_GetCredential(Presentation *presentation, DIDURL *credid)
{
    Credential *credential;
    size_t i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", NULL);
    CHECK_ARG(!credid, "No credential id.", NULL);

    if (presentation->credentials.size <= 0) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "No credentials in presentation.");
        return NULL;
    }

    for (i = 0; i < presentation->credentials.size; i++) {
        credential = presentation->credentials.credentials[i];
        if (DIDURL_Equals(Credential_GetId(credential), credid))
            return credential;
    }

    DIDError_Set(DIDERR_NOT_EXISTS, "No credential(%s) in presentation.", DIDURLSTR(credid));
    return NULL;

    DIDERROR_FINALIZE();
}

ssize_t Presentation_GetTypeCount(Presentation *presentation)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", -1);
    return presentation->type.size;

    DIDERROR_FINALIZE();
}

ssize_t Presentation_GetTypes(Presentation *presentation, const char **types, size_t size)
{
    size_t actual_size;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", -1);
    CHECK_ARG(!types || size == 0, "Invalid buffer for types.", -1);

    actual_size = presentation->type.size;
    CHECK_ARG(actual_size > size, "The buffer is too small.", -1);

    memcpy((void*)types, presentation->type.types, sizeof(char*) * actual_size);
    return (ssize_t)actual_size;

    DIDERROR_FINALIZE();
}

time_t Presentation_GetCreatedTime(Presentation *presentation)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", 0);
    return presentation->created;

    DIDERROR_FINALIZE();
}

DIDURL *Presentation_GetVerificationMethod(Presentation *presentation)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", NULL);
    return &presentation->proof.verificationMethod;

    DIDERROR_FINALIZE();
}

const char *Presentation_GetNonce(Presentation *presentation)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", NULL);
    return presentation->proof.nonce;

    DIDERROR_FINALIZE();
}

const char *Presentation_GetRealm(Presentation *presentation)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", NULL);
    return presentation->proof.realm;

    DIDERROR_FINALIZE();
}

static int check_presentation(Presentation *presentation, bool validtype)
{
    DIDDocument *doc = NULL;
    int rc = 0, status, i, check;
    const char *data;

    assert(presentation);

    doc = DID_Resolve(Presentation_GetHolder(presentation), &status, false);
    if (!doc) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, " * VP %s : holder %s %s.",
                DIDURLSTR(Presentation_GetId(presentation)),
                DIDSTR(Presentation_GetHolder(presentation)), DIDSTATUS_MSG(status));
        return -1;
    }

    if (validtype) {
        rc = DIDDocument_IsValid(doc);
        if (rc != 1) {
            DIDError_Set(DIDERR_NOT_VALID, " * VP %s : holder's document is invalid.",
                    DIDURLSTR(Presentation_GetId(presentation)));
            goto errorExit;
        }
    } else {
        rc = DIDDocument_IsGenuine(doc);
        if (rc != 1) {
            DIDError_Set(DIDERR_NOT_GENUINE, " * VP %s : signer's document is not genuine.",
                    DIDURLSTR(Presentation_GetId(presentation)));
            goto errorExit;
        }
    }

    if (!DIDDocument_IsAuthenticationKey(doc, &presentation->proof.verificationMethod)) {
        DIDError_Set(DIDERR_INVALID_KEY, " * VP %s : invalid authentication key.",
                DIDURLSTR(Presentation_GetId(presentation)));
        goto errorExit;
    }

    if (presentation->credentials.size > 0 && !presentation->credentials.credentials) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, " * VP %s : missing credentials.",
                DIDURLSTR(Presentation_GetId(presentation)));
        goto errorExit;
    }

    for (i = 0; i < presentation->credentials.size; i++) {
        Credential *cred = presentation->credentials.credentials[i];
        if (!cred) {
            DIDError_Set(DIDERR_MALFORMED_PRESENTATION, " * VP %s : missing credential.",
                    DIDURLSTR(Presentation_GetId(presentation)));
            goto errorExit;
        }
        if (!DID_Equals(&cred->subject.id, Presentation_GetHolder(presentation))) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL,
                    " * VP %s : credential %s doesn't match with signer.",
                    DIDURLSTR(Presentation_GetId(presentation)), DIDURLSTR(&cred->id));
            goto errorExit;
        }
        if (validtype) {
            rc = Credential_IsValid(cred);
            if (rc != 1) {
                DIDError_Set(DIDERR_NOT_VALID,
                        " * VP %s : credential %s doesn't match with signer.",
                        DIDURLSTR(Presentation_GetId(presentation)), DIDURLSTR(&cred->id));
                goto errorExit;
            }
        } else {
            rc = Credential_IsGenuine(cred);
            if (rc != 1) {
                DIDError_Set(DIDERR_NOT_GENUINE, " * VP %s : credential %s isn't genuine.",
                        DIDURLSTR(Presentation_GetId(presentation)), DIDURLSTR(&cred->id));
                goto errorExit;
            }
        }
    }

    data = presentation_tojson_forsign(presentation, false, true);
    if (!data) {
        DIDError_Set(DIDERRCODE, " * VP %s : %s.",
                DIDURLSTR(Presentation_GetId(presentation)), DIDERRMSG);
        goto errorExit;
    }

    check = DIDDocument_Verify(doc, &presentation->proof.verificationMethod,
            presentation->proof.signatureValue, 3, (unsigned char*)data, strlen(data),
            presentation->proof.realm, strlen(presentation->proof.realm),
            presentation->proof.nonce, strlen(presentation->proof.nonce));
    free((void*)data);
    if (check < 0) {
        DIDError_Set(DIDERR_VERIFY_ERROR, " * VP %s : verify persentation failed.",
                DIDURLSTR(Presentation_GetId(presentation)));
        goto errorExit;
    }

    rc = 1;

errorExit:
    DIDDocument_Destroy(doc);
    return rc;
}

int Presentation_IsGenuine(Presentation *presentation)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", -1);
    int rc = check_presentation(presentation, false);
    if (rc != 1)
        DIDError_Set(DIDERR_NOT_GENUINE, " * VP %s : is not genuine.",
                DIDURLSTR(Presentation_GetId(presentation)));

    return rc;

    DIDERROR_FINALIZE();
}

int Presentation_IsValid(Presentation *presentation)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!presentation, "No persentation argument.", -1);
    int rc = check_presentation(presentation, true);
    if (rc != 1)
        DIDError_Set(DIDERR_NOT_VALID, " * VP %s : is invalid.",
                DIDURLSTR(Presentation_GetId(presentation)));

    return rc;

    DIDERROR_FINALIZE();
}
