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

bool DIDBackend_PublishDID(DIDBackend *backend, const char *payload)
{
    DIDRequest *request;
    bool isvalid;

    assert(backend);
    assert(payload && *payload);

    request = DIDRequest_FromJson(payload);
    if (!request) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Payload is invalid.");
        return false;
    }

    isvalid = DIDRequest_IsValid(request, true);
    DIDRequest_Destroy(request);
    if (!isvalid)
        return false;

    isvalid = backend->adapter->createIdTransaction(backend->adapter, payload, "");
    if (!isvalid)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction failed.");

    return isvalid;
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

    if (!backend->adapter) {
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

   successed = backend->adapter->createIdTransaction(backend->adapter, reqstring, "");
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

    if (!backend->adapter) {
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

    successed = backend->adapter->createIdTransaction(backend->adapter, reqstring, "");
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

    if (!backend->adapter) {
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

    successed = backend->adapter->createIdTransaction(backend->adapter, reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(deactivated) failed.");

    return successed;
}

static int resolve_from_backend(ResolveResult *result, DID *did, const char *txid, bool all)
{
    const char *data = NULL;
    json_t *root = NULL, *item, *field;
    json_error_t error;
    char _idstring[ELA_MAX_DID_LEN];
    int code = -1, rc = -1;

    assert(result);
    assert(did);

    data = resolverInstance->resolve(resolverInstance,
            DID_ToString(did, _idstring, sizeof(_idstring)), txid, all);
    if (!data) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Resolve data %s from chain failed.", did->idstring);
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

    if (ResolveResult_GetStatus(result) != DIDStatus_NotFound && !all && ResolveCache_Store(result, did) == -1)
        goto errorExit;

    rc = 0;

errorExit:
    if (root)
        json_decref(root);
    if (data)
        free((void*)data);
    return rc;
}

static int resolve_internal(ResolveResult *result, DID *did, const char *txid, bool all, bool force)
{
    assert(result);
    assert(did);
    //Don't remove!
    //assert(!all || (all && force));

    if (!force && !txid && ResolverCache_Load(result, did, ttl) == 0)
        return 0;

    if (resolve_from_backend(result, did, txid, all) < 0)
        return -1;

    return 0;
}

DIDDocument *DIDBackend_Resolve(DID *did, const char *txid, bool force)
{
    DIDDocument *doc = NULL;
    DIDDocument *docs[1] = {0};
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

    if (!resolverInstance || !resolverInstance->resolve) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "DID resolver not initialized.");
        return NULL;
    }

    memset(&result, 0, sizeof(ResolveResult));
    if (DIDBackend_ResolvePayload(did, txid, docs, 1, force) < 0)
        return NULL;

    return docs[0];
}

DIDHistory *DIDBackend_ResolveHistory(DID *did)
{
    ResolveResult result;

    if (!did) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (!resolverInstance || !resolverInstance->resolve) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "DID resolver not initialized.");
        return NULL;
    }

    memset(&result, 0, sizeof(ResolveResult));
    if (resolve_internal(&result, did, NULL, true, true) == -1) {
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

ssize_t DIDBackend_ResolvePayload(DID *did, const char* txid, DIDDocument **docs, int count, bool force)
{
    DIDTransactionInfo **infos;
    ssize_t size;
    int i;

    assert(did);
    assert(docs);
    assert(count > 0);

    infos = (DIDTransactionInfo**)alloca(count * sizeof(DIDTransactionInfo*));
    if (!infos) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for didrequests failed.");
        return -1;
    }

    size = DIDBackend_ResolveDIDTransactions(did, txid, infos, count, force);
    if (size < 0)
        return -1;

    for (i = 0; i < count; i++) {
        docs[i] = infos[i]->request->doc;
        DIDTransactionInfo_Free(infos[i]);
    }

    return count;
}

ssize_t DIDBackend_ResolveDIDTransactions(DID *did, const char *txid, DIDTransactionInfo **infos, int count, bool force)
{
    DIDDocument *doc = NULL;
    ResolveResult result;
    size_t i;

    assert(did);
    assert(infos);
    assert(count > 0);

    if (!resolverInstance || !resolverInstance->resolve) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "DID resolver not initialized.");
        return -1;
    }

    memset(&result, 0, sizeof(ResolveResult));
    //todo: when the chain support the count transaction, it must be modify.
    if (resolve_internal(&result, did, txid, true, force) == -1) {
        ResolveResult_Destroy(&result);
        return -1;
    }

    return ResolveResult_GetTransactions(&result, infos, count);
}

void DIDBackend_SetTTL(long _ttl)
{
    ttl = _ttl;
}

void DIDBackend_SetLocalResolveHandle(DIDLocalResovleHandle *handle)
{
    gLocalResolveHandle = handle;
}

