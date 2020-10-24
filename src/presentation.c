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

static const char *PresentationType = "VerifiablePresentation";
extern const char *ProofType;

static int proof_toJson(JsonGenerator *gen, Presentation *pre, int compact)
{
    char id[ELA_MAX_DIDURL_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(pre);

    CHECK(JsonGenerator_WriteStartObject(gen));
    if (!compact)
        CHECK(JsonGenerator_WriteStringField(gen, "type", pre->proof.type));
    CHECK(JsonGenerator_WriteStringField(gen, "verificationMethod",
        DIDURL_ToString(&pre->proof.verificationMethod, id, sizeof(id), compact)));
    CHECK(JsonGenerator_WriteStringField(gen, "realm", pre->proof.realm));
    CHECK(JsonGenerator_WriteStringField(gen, "nonce", pre->proof.nonce));
    CHECK(JsonGenerator_WriteStringField(gen, "signature", pre->proof.signatureValue));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

static int presentation_tojson_internal(JsonGenerator *gen, Presentation *pre,
        bool compact, bool forsign)
{
    char _timestring[DOC_BUFFER_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(pre);

    CHECK(JsonGenerator_WriteStartObject(gen));
    if (!compact)
        CHECK(JsonGenerator_WriteStringField(gen, "type", pre->type));
    CHECK(JsonGenerator_WriteStringField(gen, "created",
            get_time_string(_timestring, sizeof(_timestring), &pre->created)));
    CHECK(JsonGenerator_WriteFieldName(gen, "verifiableCredential"));
    CredentialArray_ToJson(gen, pre->credentials.credentials,
            pre->credentials.size, Presentation_GetSigner(pre), compact);
    if (!forsign) {
        CHECK(JsonGenerator_WriteFieldName(gen, "proof"));
        CHECK(proof_toJson(gen, pre, compact));
    }
    CHECK(JsonGenerator_WriteEndObject(gen));

    return 0;
}

static int parse_credentials_inpre(DID *signer, Presentation *pre, json_t *json)
{
    size_t size = 0;
    Credential **credentials = NULL;

    assert(pre);
    assert(json);

    size = json_array_size(json);
    if (size < 0)
        return -1;

    if (size > 0) {
        credentials = (Credential**)calloc(size, sizeof(Credential*));
        if (!credentials)
            return -1;

        size = Parse_Credentials(signer, credentials, size, json);
        if (size <= 0) {
            free(credentials);
            return -1;
        }
    }
    pre->credentials.credentials = credentials;
    pre->credentials.size = size;

    return 0;
}

static int parse_proof(DID *signer, Presentation *pre, json_t *json)
{
    json_t *item;
    DIDURL *keyid;

    assert(signer);
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

    keyid = DIDURL_FromString(json_string_value(item), signer);
    if (!keyid) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid sign key for presentation.");
        return -1;
    }

    if (!DIDURL_Copy(&pre->proof.verificationMethod, keyid) ||
            !DID_Copy(signer, &keyid->did)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Copy signer failed.");
        DIDURL_Destroy(keyid);
        return -1;
    }

    DIDURL_Destroy(keyid);
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
    DID subject;

    assert(json);

    Presentation *pre = (Presentation*)calloc(1, sizeof(Presentation));
    if (!pre) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for presentation failed.");
        return NULL;
    }

    item = json_object_get(json, "type");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing type.");
        Presentation_Destroy(pre);
        return NULL;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid type.");
        Presentation_Destroy(pre);
        return NULL;
    }

    if (strcmp(json_string_value(item), PresentationType)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Unknow presentation type.");
        Presentation_Destroy(pre);
        return NULL;
    }

    if (strlen(json_string_value(item)) + 1 > sizeof(pre->type)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Presentation type is too long.");
        Presentation_Destroy(pre);
        return NULL;
    }

    strcpy(pre->type, json_string_value(item));

    item = json_object_get(json, "created");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing time created presentation.");
        Presentation_Destroy(pre);
        return NULL;
    }
    if (!json_is_string(item) || parse_time(&pre->created, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid time created presentation.");
        Presentation_Destroy(pre);
        return NULL;
    }

    item = json_object_get(json, "proof");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing presentation proof.");
        Presentation_Destroy(pre);
        return NULL;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid presentation proof.");
        Presentation_Destroy(pre);
        return NULL;
    }
    if (parse_proof(&subject, pre, item) == -1) {
        Presentation_Destroy(pre);
        return NULL;
    }

    item = json_object_get(json, "verifiableCredential");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing Credentials.");
        Presentation_Destroy(pre);
        return NULL;
    }
    if (!json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid Credentials.");
        Presentation_Destroy(pre);
        return NULL;
    }
    if (parse_credentials_inpre(&subject, pre, item) == -1) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid credential error[%d]: %s", DIDERRCODE, DIDERRMSG);
        Presentation_Destroy(pre);
        return NULL;
    }

    return pre;
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

    gen = JsonGenerator_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator initialize failed.");
        return NULL;
    }

    if (presentation_tojson_internal(gen, pre, compact, forsign) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize presentation to json failed.");
        JsonGenerator_Destroy(gen);
        return NULL;
    }

    return JsonGenerator_Finish(gen);
}

static Presentation *create_presentation(DIDDocument *doc, DIDURL *signkey, DIDStore *store)
{
    Presentation *pre = NULL;

    assert(doc);
    assert(store);

    if (!DIDDocument_IsAuthenticationKey(doc, signkey)) {
        DIDError_Set(DIDERR_INVALID_KEY, "Invalid authentication key.");
        return NULL;
    }

    if (!DIDStore_ContainsPrivateKey(store, &doc->did, signkey)) {
        DIDError_Set(DIDERR_INVALID_KEY, "No private key.");
        return NULL;
    }

    pre = (Presentation*)calloc(1, sizeof(Presentation));
    if (!pre) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for presentation failed.");
        return NULL;
    }

    strcpy(pre->type, PresentationType);

    return pre;
}

static int add_credentials_to_presentation(Presentation *pre, int count, va_list list)
{
    Credential **creds = NULL, *cred;
    int i;

    assert(pre);
    assert(count >= 0);

    if (count > 0) {
        creds = (Credential**)calloc(count, sizeof(Credential*));
        if (!creds) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credentials failed.");
            return -1;
        }

        for (i = 0; i < count; i++) {
            cred = va_arg(list, Credential*);
            if (Credential_Verify(cred) == -1 || Credential_IsExpired(cred)) {
                free(creds);
                va_end(list);
                return -1;
            }

            add_credential(creds, i, cred);
        }
    }

    pre->credentials.credentials = creds;
    pre->credentials.size = count;
    return 0;
}

static int add_credentialarray_to_presentation(Presentation *pre, int count, Credential **creds)
{
    Credential **credentials = NULL;
    int i;

    assert(pre);
    assert(count >= 0);
    assert(creds);

    if (count > 0) {
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

    rc = DIDDocument_Sign(doc, signkey, storepass, signature, 3, (unsigned char*)data, strlen(data),
            (unsigned char*)realm, strlen(realm), (unsigned char*)nonce, strlen(nonce));
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
Presentation *Presentation_Create(DID *did, DIDURL *signkey, DIDStore *store,
        const char *storepass, const char *nonce, const char *realm, int count, ...)
{
    va_list list;
    Presentation *pre = NULL;
    DIDDocument *doc;
    int rc;

    if (!did || !store || !storepass || !*storepass || !nonce || !*nonce ||
            !realm || !*realm || count < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    doc = DIDStore_LoadDID(store, did);
    if (!doc) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Can not load DID.");
        return NULL;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(doc);
        if (!signkey)
            goto errorExit;
    }

    pre = create_presentation(doc, signkey, store);
    if (!pre)
        goto errorExit;

    va_start(list, count);
    rc = add_credentials_to_presentation(pre, count, list);
    va_end(list);
    if (rc < 0)
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

Presentation *Presentation_CreateByCredentials(DID *did, DIDURL *signkey,
        DIDStore *store, const char *storepass, const char *nonce, const char *realm,
        Credential **creds, size_t count)
{
    Presentation *pre = NULL;
    DIDDocument *doc;
    int rc;

    if (!did || !store || !storepass || !*storepass || !nonce || !*nonce ||
            !realm || !*realm || count < 0 || !creds) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    doc = DIDStore_LoadDID(store, did);
    if (!doc) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Can not load DID.");
        return NULL;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(doc);
        if (!signkey)
            goto errorExit;
    }

    pre = create_presentation(doc, signkey, store);
    if (!pre)
        goto errorExit;

    rc = add_credentialarray_to_presentation(pre, count, creds);
    if (rc < 0)
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

void Presentation_Destroy(Presentation *pre)
{
    size_t i;

    if (!pre)
        return;

    if (pre->credentials.credentials) {
        for (i = 0; i < pre->credentials.size; i++) {
            Credential *cred = pre->credentials.credentials[i];
            if (cred)
                Credential_Destroy(cred);
        }

        free(pre->credentials.credentials);
    }
    free(pre);
}

int Presentation_Verify(Presentation *pre)
{
    DID *signer;
    DIDDocument *doc;
    const char *data;
    size_t i;
    int rc;

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (pre->credentials.size < 0) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Invalid presentation.");
        return -1;
    }

    signer = Presentation_GetSigner(pre);
    if (!signer) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "No signer.");
        return -1;
    }

    if (pre->credentials.size > 0 && !pre->credentials.credentials) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "Missing credentials.");
        return -1;
    }

    for (i = 0; i < pre->credentials.size; i++) {
        Credential *cred = pre->credentials.credentials[i];
        DIDURL *credid = Credential_GetId(cred);
        if (!DID_Equals(DIDURL_GetDid(credid), signer)) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Credential is not owned by signer.");
            return -1;
        }
        if (Credential_Verify(cred) == -1) {
            DIDError_Set(DIDERR_NOT_GENUINE, "Credential is not genuine.");
            return -1;
        }
        if (Credential_IsExpired(cred)) {
            DIDError_Set(DIDERR_EXPIRED, "Credential is expired.");
            return -1;
        }
    }

    doc = DID_Resolve(signer, false);
    if (!doc) {
        DIDError_Set(DIDERR_MALFORMED_DID, "Presentation signer is not a published did.");
        return -1;
    }

    data = presentation_tojson_forsign(pre, false, true);
    if (!data) {
        DIDDocument_Destroy(doc);
        return -1;
    }

    rc = DIDDocument_Verify(doc, &pre->proof.verificationMethod,
            pre->proof.signatureValue, 3, (unsigned char*)data, strlen(data),
            pre->proof.realm, strlen(pre->proof.realm),
            pre->proof.nonce, strlen(pre->proof.nonce));

    free((void*)data);
    DIDDocument_Destroy(doc);
    return rc;
}

const char* Presentation_ToJson(Presentation *pre, bool normalized)
{
    return presentation_tojson_forsign(pre, !normalized, false);
}

Presentation *Presentation_FromJson(const char *json)
{
    json_t *root;
    json_error_t error;
    Presentation *pre;

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
}

DID *Presentation_GetSigner(Presentation *pre)
{
    DIDURL *verificationMethod;

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    verificationMethod = Presentation_GetVerificationMethod(pre);
    if (!verificationMethod) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "No signing key.");
        return NULL;
    }

    return DIDURL_GetDid(verificationMethod);

}

ssize_t Presentation_GetCredentialCount(Presentation *pre)
{
    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return pre->credentials.size;
}

ssize_t Presentation_GetCredentials(Presentation *pre, Credential **creds, size_t size)
{
    size_t actual_size;

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
}

Credential *Presentation_GetCredential(Presentation *pre, DIDURL *credid)
{
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
}

const char *Presentation_GetType(Presentation *pre)
{
    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return pre->type;
}

time_t Presentation_GetCreatedTime(Presentation *pre)
{
    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    return pre->created;
}

DIDURL *Presentation_GetVerificationMethod(Presentation *pre)
{
    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &pre->proof.verificationMethod;
}

const char *Presentation_GetNonce(Presentation *pre)
{
    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return pre->proof.nonce;
}

const char *Presentation_GetRealm(Presentation *pre)
{
    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return pre->proof.realm;
}

bool Presentation_IsGenuine(Presentation *pre)
{
    DID *signer;
    DIDDocument *doc = NULL;
    size_t i;
    int rc;

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (strcmp(pre->type, PresentationType)) {
        DIDError_Set(DIDERR_UNKNOWN, "Unknow presentation type.");
        return false;
    }

    signer = Presentation_GetSigner(pre);
    if (!signer) {
        DIDError_Set(DIDERR_MALFORMED_PRESENTATION, "No signer for presentation.");
        return false;
    }

    doc = DID_Resolve(signer, false);
    if (!doc) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Presentation signer is not a published did.");
        return false;
    }

    if (!DIDDocument_IsGenuine(doc)) {
        DIDError_Set(DIDERR_NOT_GENUINE, "Signer is not genuine.");
        goto errorExit;
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
        if (!DID_Equals(Credential_GetOwner(cred), Presentation_GetSigner(pre))) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Credential is not match with signer.");
            goto errorExit;
        }
        if (!Credential_IsGenuine(cred)) {
            DIDError_Set(DIDERR_NOT_GENUINE, "Credential is not genuine.");
            goto errorExit;
        }
    }

    rc = Presentation_Verify(pre);
    DIDDocument_Destroy(doc);
    return rc == 0;

errorExit:
    DIDDocument_Destroy(doc);
    return false;
}

bool Presentation_IsValid(Presentation *pre)
{
    DID *signer;
    DIDDocument *doc = NULL;
    size_t i;
    int rc;

    if (!pre) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (strcmp(pre->type, PresentationType)) {
        DIDError_Set(DIDERR_UNKNOWN, "Unknow presentation type.");
        return false;
    }

    signer = Presentation_GetSigner(pre);
    if (!signer)
        return false;

    doc = DID_Resolve(signer, false);
    if (!doc) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Presentation signer is not a published did.");
        return false;
    }

    if (!DIDDocument_IsValid(doc))
        goto errorExit;

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
        if (!DID_Equals(Credential_GetOwner(cred), Presentation_GetSigner(pre))) {
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Credential is not match with signer.");
            goto errorExit;
        }
        if (!Credential_IsGenuine(cred)) {
            DIDError_Set(DIDERR_NOT_GENUINE, "Credential is not genuine.");
            goto errorExit;
        }
    }

    rc = Presentation_Verify(pre);
    DIDDocument_Destroy(doc);
    return rc == 0;

errorExit:
    DIDDocument_Destroy(doc);
    return false;

}
