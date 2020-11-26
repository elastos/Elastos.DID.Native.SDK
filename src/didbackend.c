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

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <jansson.h>

#include "ela_did.h"
#include "common.h"
#include "did.h"
#include "didrequest.h"
#include "didbackend.h"
#include "didmeta.h"
#include "diddocument.h"
#include "didresolver.h"
#include "resolveresult.h"
#include "resolvercache.h"
#include "diderror.h"
#include "didhistory.h"

#define DEFAULT_TTL    (24 * 60 * 60 * 1000)

static DIDResolver *resolverInstance;
static bool defaultInstance;
static DIDLocalResovleHandle *gLocalResolveHandle;

long ttl = DEFAULT_TTL;

static void DIDBackend_Deinitialize(void)
{
    if (resolverInstance && defaultInstance) {
        DefaultResolver_Destroy(resolverInstance);
        resolverInstance = NULL;
    }
}

int DIDBackend_InitializeDefault(const char *url, const char *cachedir)
{
    if (!url || !*url || !cachedir || !*cachedir) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (strlen(url) >= URL_LEN) {
        DIDError_Set(DIDERR_INVALID_ARGS, "URL is too long.");
        return -1;
    }

    DIDBackend_Deinitialize();

    resolverInstance = DefaultResolver_Create(url);
    if (!resolverInstance)
        return -1;

    if (ResolverCache_SetCacheDir(cachedir) < 0) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Set resolve cache failed.");
        return -1;
    }

    defaultInstance = true;
    atexit(DIDBackend_Deinitialize);
    return 0;
}

int DIDBackend_Initialize(DIDResolver *resolver, const char *cachedir)
{
    if (!resolver || !cachedir || !*cachedir) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    DIDBackend_Deinitialize();

    resolverInstance = resolver;
    if (ResolverCache_SetCacheDir(cachedir) < 0) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Set resolve cache failed.");
        return -1;
    }

    defaultInstance = false;
    return 0;
}

bool DIDBackend_Create(DIDBackend *backend, DIDDocument *document,
        DIDURL *signkey, const char *storepass)
{
    const char *reqstring;
    bool successed;

    assert(backend);
    assert(document);
    assert(signkey);
    assert(storepass && *storepass);

    if (!backend->adapter.CreateIdRequest) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not adapter to create transaction.\
                Please reopen didstore to add adapter.");
        return false;
    }

    if (!DIDMetaData_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    reqstring = DIDRequest_Sign(RequestType_Create, document, signkey, storepass);
    if (!reqstring)
        return false;

   successed = backend->adapter.CreateIdRequest(&backend->adapter, reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(create) failed.");

    return successed;
}

bool DIDBackend_Update(DIDBackend *backend, DIDDocument *document, DIDURL *signkey,
        const char *storepass)
{
    const char *reqstring;
    bool successed;

    assert(backend);
    assert(document);
    assert(signkey);
    assert(storepass && *storepass);

    if (!backend->adapter.CreateIdRequest) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not adapter to create transaction.\
                Please reopen didstore to add adapter.");
        return false;
    }

    if (!DIDMetaData_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    reqstring = DIDRequest_Sign(RequestType_Update, document, signkey, storepass);
    if (!reqstring)
        return false;

    successed = backend->adapter.CreateIdRequest(&backend->adapter, reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(update) failed.");

    return successed;
}

bool DIDBackend_Deactivate(DIDBackend *backend, DID *did, DIDURL *signkey,
        const char *storepass)
{
    const char *reqstring;
    DIDDocument *document;
    bool successed;

    assert(backend);
    assert(did);
    assert(signkey);
    assert(storepass && *storepass);

    if (!backend->adapter.CreateIdRequest) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not adapter to create transaction.\
                Please reopen didstore to add adapter.");
        return false;
    }

    if (!DIDMetaData_AttachedStore(&did->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    document = DIDStore_LoadDID(did->metadata.base.store, did);
    if (!document)
        return false;

    reqstring = DIDRequest_Sign(RequestType_Deactivate, document, signkey, storepass);
    DIDDocument_Destroy(document);
    if (!reqstring)
        return false;

    successed = backend->adapter.CreateIdRequest(&backend->adapter, reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(deactivated) failed.");

    return successed;
}

static int resolve_from_backend(ResolveResult *result, DID *did, bool all)
{
    const char *data = NULL;
    json_t *root = NULL, *item, *field;
    json_error_t error;
    char _idstring[ELA_MAX_DID_LEN];
    int code = -1, rc = -1;

    assert(result);
    assert(did);

    data = resolverInstance->ResolveDID(resolverInstance,
            DID_ToString(did, _idstring, sizeof(_idstring)), all);
    if (!data) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Resolve did %s failed.", did->idstring);
        return rc;
    }

    root = json_loads(data, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Deserialize resolved data failed, error: %s.", error.text);
        goto errorExit;
    }

    item = json_object_get(root, "result");
    if (!item || !json_is_object(item)) {
        item = json_object_get(root, "error");
        if (!item || !json_is_null(item)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing or invalid error field.");
        } else {
            field = json_object_get(item, "code");
            if (field && json_is_integer(field)) {
                code = json_integer_value(field);
                field = json_object_get(item, "message");
                if (field && json_is_string(field))
                    DIDError_Set(DIDERR_RESOLVE_ERROR, "Resolve did error(%d): %s", code, json_string_value(field));
            }
        }
        goto errorExit;
    }

    if (ResolveResult_FromJson(result, item, all) == -1)
        goto errorExit;

    if (ResolveResult_GetStatus(result) != DIDStatus_NotFound && !all && ResolveCache_StoreDID(result, did) == -1)
        goto errorExit;

    rc = 0;

errorExit:
    if (root)
        json_decref(root);
    if (data)
        free((void*)data);
    return rc;
}

static int vcresolve_from_backend(VcResolveResult *result, DIDURL *id, bool all)
{
    const char *data = NULL;
    json_t *root = NULL, *item, *field;
    json_error_t error;
    char _idstring[ELA_MAX_DID_LEN], *idstring;
    int code = -1, rc = -1;

    assert(result);
    assert(id);

    idstring = DIDURL_ToString(id, _idstring, sizeof(_idstring), false);
    if (!idstring)
        return rc;

    data = resolverInstance->ResolveCredential(resolverInstance, idstring, all);
    if (!data) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Resolve data %s from chain failed.", idstring);
        return rc;
    }

    root = json_loads(data, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Deserialize resolved data failed, error: %s.", error.text);
        goto errorExit;
    }

    item = json_object_get(root, "result");
    if (!item || !json_is_object(item)) {
        item = json_object_get(root, "error");
        if (!item || !json_is_null(item)) {
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing or invalid error field.");
        } else {
            field = json_object_get(item, "code");
            if (field && json_is_integer(field)) {
                code = json_integer_value(field);
                field = json_object_get(item, "message");
                if (field && json_is_string(field))
                    DIDError_Set(DIDERR_RESOLVE_ERROR, "Resolve did error(%d): %s", code, json_string_value(field));
            }
        }
        goto errorExit;
    }

    if (VcResolveResult_FromJson(result, item, all) == -1)
        goto errorExit;

    if (VcResolveResult_GetStatus(result) != CredentialStatus_NotFound && !all && ResolveCache_StoreCredential(result, id) == -1)
        goto errorExit;

    rc = 0;

errorExit:
    if (root)
        json_decref(root);
    if (data)
        free((void*)data);
    return rc;
}

static int resolve_internal(ResolveResult *result, DID *did, bool all, bool force)
{
    assert(result);
    assert(did);
    assert(!all || (all && force));

    if (!force && ResolverCache_LoadDID(result, did, ttl) == 0)
        return 0;

    if (resolve_from_backend(result, did, all) < 0)
        return -1;

    return 0;
}

static int vcresolve_internal(VcResolveResult *result, DIDURL *id, bool all, bool force)
{
    assert(result);
    assert(id);
    assert(!all || (all && force));

    if (!force && ResolverCache_LoadCredential(result, id, ttl) == 0)
        return 0;

    if (vcresolve_from_backend(result, id, all) < 0)
        return -1;

    return 0;
}

DIDDocument *DIDBackend_ResolveDID(DID *did, bool force)
{
    DIDDocument *doc = NULL;
    ResolveResult result;
    size_t i;

    if (!did) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    //If user give did document to verify, sdk use it first.
    if (gLocalResolveHandle) {
        doc = gLocalResolveHandle(did);
        if (doc)
            return doc;
    }

    if (!resolverInstance || !resolverInstance->ResolveDID) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "DID resolver not initialized.");
        return NULL;
    }

    memset(&result, 0, sizeof(ResolveResult));
    if (resolve_internal(&result, did, false, force) == -1) {
        ResolveResult_Destroy(&result);
        return NULL;
    }

    if (ResolveResult_GetStatus(&result) == DIDStatus_NotFound) {
        ResolveResult_Destroy(&result);
        DIDError_Set(DIDERR_NOT_EXISTS, "DID not exists.");
        return NULL;
    } else if (ResolveResult_GetStatus(&result) == DIDStatus_Deactivated) {
        ResolveResult_Destroy(&result);
        DIDError_Set(DIDERR_DID_DEACTIVATED, "DID is deactivated.");
        return NULL;
    } else {
        doc = result.txinfos.infos[0].request.doc;
        for (i = 1; i < result.txinfos.size; i++)
            DIDDocument_Destroy(result.txinfos.infos[i].request.doc);
        ResolveResult_Free(&result);
        if (!doc)
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Malformed resolver response.");
    }

    return doc;
}

DIDHistory *DIDBackend_ResolveDIDHistory(DID *did)
{
    ResolveResult result;

    if (!did) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (!resolverInstance || !resolverInstance->ResolveDID) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "DID resolver not initialized.");
        return NULL;
    }

    memset(&result, 0, sizeof(ResolveResult));
    if (resolve_internal(&result, did, true, true) == -1) {
        ResolveResult_Destroy(&result);
        return NULL;
    }

    if (ResolveResult_GetStatus(&result) == DIDStatus_NotFound) {
        ResolveResult_Destroy(&result);
        DIDError_Set(DIDERR_NOT_EXISTS, "DID not exists.");
        return NULL;
    }

    return ResolveResult_ToDIDHistory(&result);
}

void DIDBackend_SetTTL(long _ttl)
{
    ttl = _ttl;
}

void DIDBackend_SetLocalResolveHandle(DIDLocalResovleHandle *handle)
{
    gLocalResolveHandle = handle;
}

//*****Credential
bool DIDBackend_Declear(DIDBackend *backend, Credential *vc, DIDURL *signkey,
        DIDDocument *document, const char *storepass)
{
    const char *reqstring;
    bool successed;

    assert(backend);
    assert(vc);
    assert(signkey);
    assert(document);
    assert(storepass && *storepass);

    if (!backend->adapter.CreateCredentialRequest) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "No adapter to create credential transaction.\
                Please init adapter to add the method to create credential transaction.");
        return false;
    }

    if (!DIDMetaData_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    reqstring = CredentialRequest_Sign(RequestType_Declear, NULL, vc, signkey, document, storepass);
    if (!reqstring)
        return false;

    successed = backend->adapter.CreateCredentialRequest(&backend->adapter, reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(deactivated) failed.");

    return successed;
}

bool DIDBackend_Revoke(DIDBackend *backend, DIDURL *credid, DIDURL *signkey, DIDDocument *document,
        const char *storepass)
{
    const char *reqstring;
    bool successed;

    assert(backend);
    assert(credid);
    assert(signkey);
    assert(document);
    assert(storepass && *storepass);

    if (!backend->adapter.CreateCredentialRequest) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "No adapter to create credential transaction.\
                Please init adapter to add the method to create credential transaction.");
        return false;
    }

    if (!DIDMetaData_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    reqstring = CredentialRequest_Sign(RequestType_Revoke, credid, NULL, signkey, document, storepass);
    if (!reqstring)
        return false;

    successed = backend->adapter.CreateCredentialRequest(&backend->adapter, reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(deactivated) failed.");

    return successed;
}

Credential *DIDBackend_ResolveCredential(DIDURL *id, int *status, bool force)
{
    Credential *credential = NULL;
    VcResolveResult result;
    size_t i;

    if (!id) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (!resolverInstance || !resolverInstance->ResolveCredential) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "DID resolver not initialized.");
        return NULL;
    }

    memset(&result, 0, sizeof(VcResolveResult));
    if (vcresolve_internal(&result, id, false, force) == -1) {
        *status = CredentialStatus_Error;
        VcResolveResult_Destroy(&result);
        return NULL;
    }

    if (VcResolveResult_GetStatus(&result) == CredentialStatus_NotFound) {
        *status = CredentialStatus_NotFound;
        VcResolveResult_Destroy(&result);
        DIDError_Set(DIDERR_NOT_EXISTS, "Credential does not exist.");
        return NULL;
    } else if (VcResolveResult_GetStatus(&result) == CredentialStatus_Revoke) {
        *status = CredentialStatus_Revoke;
        VcResolveResult_Destroy(&result);
        DIDError_Set(DIDERR_DID_DEACTIVATED, "Credential is revoke.");
        return NULL;
    } else {
        credential = result.txinfos.infos[0].request.vc;
        VcResolveResult_Free(&result);
        if (!credential) {
            *status = CredentialStatus_Error;
            DIDError_Set(DIDERR_RESOLVE_ERROR, "Malformed resolver response.");
        } else {
            *status = CredentialStatus_Valid;
        }
    }

    return credential;
}
