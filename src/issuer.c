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

#include "ela_did.h"
#include "diderror.h"
#include "did.h"
#include "credential.h"
#include "crypto.h"
#include "issuer.h"
#include "didstore.h"
#include "diddocument.h"

extern const char *ProofType;
static const char *DEFAULT_CREDENTIAL_TYPE = "VerifiableCredential";

extern const char *W3C_CREDENTIAL_CONTEXT;
extern const char *ELASTOS_CREDENTIAL_CONTEXT;

Issuer *Issuer_Create(DID *did, DIDURL *signkey, DIDStore *store)
{
    Issuer *issuer;
    DIDDocument *doc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did to create issuer.", NULL);
    CHECK_ARG(!store, "No store argument.", NULL);

    doc = DIDStore_LoadDID(store, did);
    if (!doc) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No issuer document in the store.");
        return NULL;
    }

    if (!signkey) {
        signkey = DIDDocument_GetDefaultPublicKey(doc);
        if (!signkey) {
            DIDError_Set(DIDERR_NOT_EXISTS, "No default key of issuer.");
            DIDDocument_Destroy(doc);
            return NULL;
        }
    } else {
        if (!DIDDocument_IsAuthenticationKey(doc, signkey)) {
            DIDError_Set(DIDERR_INVALID_KEY, "The issuer's signkey isn't an authentication key.");
            DIDDocument_Destroy(doc);
            return NULL;
        }
    }

    if (DIDDocument_HasPrivateKey(doc, signkey)!= 1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Missing private key paired with signkey of issuer.");
        DIDDocument_Destroy(doc);
        return NULL;
    }

    issuer = (Issuer*)calloc(1, sizeof(Issuer));
    if (!issuer) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for issuer failed.");
        DIDDocument_Destroy(doc);
        return NULL;
    }

    issuer->signer = doc;
    DIDURL_Copy(&issuer->signkey, signkey);
    return issuer;

    DIDERROR_FINALIZE();
}

void Issuer_Destroy(Issuer *issuer)
{
    DIDERROR_INITIALIZE();

    if (!issuer)
        return;

    if (issuer->signer)
        DIDDocument_Destroy(issuer->signer);

    free(issuer);

    DIDERROR_FINALIZE();
}

DID *Issuer_GetSigner(Issuer *issuer)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!issuer, "No issuer argument.", NULL);
    return &issuer->signer->did;

    DIDERROR_FINALIZE();
}

DIDURL *Issuer_GetSignKey(Issuer *issuer)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!issuer, "No issuer argument.", NULL);
    return &issuer->signkey;

    DIDERROR_FINALIZE();
}

static void add_type(Credential *credential, const char *type)
{
    char *pos, *copy;

    assert(credential);
    assert(type && *type);

    pos = strstr(type, "#");
    if (pos) {
        if (Features_IsEnabledJsonLdContext() &&
                !contains_content(credential->context.contexts, credential->context.size, copy)) {
            credential->context.contexts[credential->context.size++] = (char*)calloc(1, pos - type + 1);
            strncpy(credential->context.contexts[credential->context.size++], type, pos - type);
        }
        copy = pos + 1;
    } else {
        copy = (char*)type;
    }

    if (!contains_content(credential->type.types, credential->type.size, copy))
        credential->type.types[credential->type.size++] = strdup(copy);
}

static int add_default_type(Credential *credential)
{
    const char *defaults[2] = { W3C_CREDENTIAL_CONTEXT, ELASTOS_CREDENTIAL_CONTEXT };
    assert(credential);

    if (Features_IsEnabledJsonLdContext()) {
        credential->context.contexts[0] = strdup(defaults[0]);
        credential->context.contexts[1] = strdup(defaults[1]);
        credential->context.size = 2;
    }

    credential->type.types[credential->type.size++] = strdup(DEFAULT_CREDENTIAL_TYPE);
    return 0;
}

static bool check_types(const char **types, size_t size)
{
    int i;

    assert(types);
    assert(size > 0);

    for (i = 0; i < size; i++) {
        if (Features_IsEnabledJsonLdContext()) {
            if (!strstr(types[i], "#")) {
                return false;
            }
        }
    }
    return true;
}

Credential *Issuer_Generate_Credential(Issuer *issuer, DID *owner,
        DIDURL *credid, const char **types, size_t typesize, json_t *json,
        time_t expires, const char *storepass)
{
    Credential *cred = NULL;
    const char *data;
    char signature[SIGNATURE_BYTES * 2];
    DIDDocument *doc = NULL;
    size_t i;
    int rc;

    assert(issuer && owner && credid);
    assert(types && typesize > 0);
    assert(json);
    assert(expires > 0);
    assert(storepass && *storepass);

    if (!DID_Equals(owner, &credid->did)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Credential owner isn't match with credential did.");
        goto errorExit;
    }

    //check types
    if (!check_types(types, typesize)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The type must has context.");
        goto errorExit;
    }

    cred = (Credential*)calloc(1, sizeof(Credential));
    if (!cred) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for credential failed.");
        goto errorExit;
    }

    if (!DIDURL_Copy(&cred->id, credid))
        goto errorExit;

    //subject
    DID_Copy(&cred->subject.id, owner);
    cred->subject.properties = json_deep_copy(json);

    //add types
    if (Features_IsEnabledJsonLdContext()) {
        cred->context.contexts = (char**)calloc(typesize + 2, sizeof(char*));
        if (!cred->context.contexts) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for contexts failed.");
            goto errorExit;
        }
    }

    cred->type.types = (char**)calloc(typesize + 1, sizeof(char*));
    if (!cred->type.types) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for types failed.");
        goto errorExit;
    }

    if (add_default_type(cred) == -1)
        goto errorExit;

    for (i = 0; i < typesize; i++)
        add_type(cred, types[i]);

    //set issuer
    DID_Copy(&cred->issuer, &issuer->signer->did);

    //expire and issue date
    cred->expirationDate = expires;
    time(&cred->issuanceDate);

    //proof
    data = Credential_ToJson_ForSign(cred, false, true);
    if (!data)
        goto errorExit;

    rc = DIDDocument_Sign(issuer->signer, &issuer->signkey, storepass, signature,
            1, (unsigned char*)data, strlen(data));
    free((void*)data);
    if (rc) {
        DIDError_Set(DIDERR_SIGN_ERROR, "Sign credential failed.");
        goto errorExit;
    }

    strcpy(cred->proof.type, ProofType);
    DIDURL_Copy(&cred->proof.verificationMethod, &issuer->signkey);
    strcpy(cred->proof.signatureValue, signature);
    return cred;

errorExit:
    if (cred)
        Credential_Destroy(cred);
    else
        json_decref(json);

    if (doc)
        DIDDocument_Destroy(doc);

    return NULL;
}

Credential *Issuer_CreateCredential(Issuer *issuer, DID *owner, DIDURL *credid,
        const char **types, size_t typesize, Property *subject, int size,
        time_t expires, const char *storepass)
{
    Credential *cred;
    json_t *root;
    int i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!issuer, "No issuer object.", NULL);
    CHECK_ARG(!owner, "No owner of credential.", NULL);
    CHECK_ARG(!credid, "No credential id.", NULL);
    CHECK_ARG(!types || typesize == 0, "No types for credential.", NULL);
    CHECK_ARG(!subject || size <= 0, "No subject for credential.", NULL);
    CHECK_ARG(expires <= 0, "No expires time for credential, please specify one.", NULL);
    CHECK_PASSWORD(storepass, NULL);

    root = json_object();
    if (!root) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Create credential's property json failed.");
        return NULL;
    }

    for (i = 0; i < size; i++) {
        int rc = json_object_set_new(root, subject[i].key, json_string(subject[i].value));
        if (rc < 0) {
           DIDError_Set(DIDERR_OUT_OF_MEMORY, "Add credential's property failed.");
           json_decref(root);
           return NULL;
        }
    }

    cred = Issuer_Generate_Credential(issuer, owner, credid, types, typesize, root,
            expires, storepass);
    json_decref(root);
    return cred;

    DIDERROR_FINALIZE();
}

Credential *Issuer_CreateCredentialByString(Issuer *issuer, DID *owner,
        DIDURL *credid, const char **types, size_t typesize, const char *subject,
        time_t expires, const char *storepass)
{
    Credential *cred;
    json_t *root;
    json_error_t error;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!issuer, "No issuer object.", NULL);
    CHECK_ARG(!owner, "No owner of credential.", NULL);
    CHECK_ARG(!credid, "No credential id.", NULL);
    CHECK_ARG(!types || typesize == 0, "No types for credential.", NULL);
    CHECK_ARG(!subject || !*subject, "No subject for credential.", NULL);
    CHECK_ARG(expires <= 0, "No expires time for credential, please specify one.", NULL);
    CHECK_PASSWORD(storepass, NULL);

    root = json_loads(subject, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Deserialize property failed, error: %s.", error.text);
        return NULL;
    }

    cred = Issuer_Generate_Credential(issuer, owner, credid, types, typesize, root,
            expires, storepass);
    json_decref(root);
    return cred;

    DIDERROR_FINALIZE();
}
