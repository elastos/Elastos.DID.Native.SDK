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
#include "didbiography.h"
#include "credentialbiography.h"

#define DEFAULT_TTL    (24 * 60 * 60 * 1000)
#define DID_RESOLVE_REQUEST "{\"method\":\"resolvedid\",\"params\":{\"did\":\"%s\",\"all\":%s}}"
#define DID_RESOLVEVC_REQUEST "{\"method\":\"listcredentials\",\"params\":{\"did\":\"%s\",\"skip\":%d,\"limit\":%d}}"
#define VC_RESOLVE_REQUEST "{\"method\":\"resolvecredential\",\"params\":{\"id\":\"%s\"}}"
#define VC_RESOLVE_WITH_ISSUER_REQUEST "{\"method\":\"resolvecredential\",\"params\":{\"id\":\"%s\", \"issuer\":\"%s\"}}"

static DIDLocalResovleHandle *gLocalResolveHandle;
static CreateIdTransaction_Callback *gCreateIdTransaction;
static Resolve_Callback *gResolve;

long ttl = DEFAULT_TTL;

int DIDBackend_InitializeDefault(CreateIdTransaction_Callback *createtransaction,
        const char *url, const char *cachedir)
{
    if (!url || !*url || !cachedir || !*cachedir) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (strlen(url) >= URL_LEN) {
        DIDError_Set(DIDERR_INVALID_ARGS, "URL is too long.");
        return -1;
    }

    if (DefaultResolve_Init(url) < 0)
        return -1;

    if (createtransaction)
        gCreateIdTransaction = createtransaction;

    gResolve = DefaultResolve_Resolve;

    if (ResolverCache_SetCacheDir(cachedir) < 0) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Set resolve cache failed.");
        return -1;
    }

    return 0;
}

int DIDBackend_Initialize(CreateIdTransaction_Callback *createtransaction,
        Resolve_Callback *resolve, const char *cachedir)
{
    if (!cachedir || !*cachedir) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (createtransaction)
       gCreateIdTransaction = createtransaction;
    if (resolve)
       gResolve = resolve;

    if (ResolverCache_SetCacheDir(cachedir) < 0) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Set resolve cache failed.");
        return -1;
    }

    return 0;
}

bool DIDBackend_CreateDID(DIDDocument *document, DIDURL *signkey, const char *storepass)
{
    const char *reqstring;
    bool successed;

    assert(document);
    assert(signkey);
    assert(storepass && *storepass);

    if (!gCreateIdTransaction) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Not method to create transaction.\
                Please set method by initialize backend.");
        return false;
    }

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    reqstring = DIDRequest_Sign(RequestType_Create, document, signkey, NULL, NULL, storepass);
    if (!reqstring)
        return false;

    successed = gCreateIdTransaction(reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(create) failed.");

    return successed;
}

bool DIDBackend_UpdateDID(DIDDocument *document, DIDURL *signkey, const char *storepass)
{
    const char *reqstring;
    bool successed;

    assert(document);
    assert(signkey);
    assert(storepass && *storepass);

    if (!gCreateIdTransaction) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Not method to create transaction.\
                Please set method by initialize backend.");
        return false;
    }

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    reqstring = DIDRequest_Sign(RequestType_Update, document, signkey, NULL, NULL, storepass);
    if (!reqstring)
        return false;

    successed = gCreateIdTransaction(reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(update) failed.");

    return successed;
}

bool DIDBackend_TransferDID(DIDDocument *document, TransferTicket *ticket,
        DIDURL *signkey, const char *storepass)
{
    const char *reqstring;
    bool successed;

    assert(document);
    assert(ticket);
    assert(signkey);
    assert(storepass && *storepass);

    if (!gCreateIdTransaction) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Not method to create transaction.\
                Please set method by initialize backend.");
        return false;
    }

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    reqstring = DIDRequest_Sign(RequestType_Transfer, document, signkey, NULL, ticket, storepass);
    if (!reqstring)
        return false;

    successed = gCreateIdTransaction(reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(create) failed.");

    return successed;
}

//signkey provides sk, creater is real key in proof. If did is deactivated by ownerself, signkey and
//creater is same.
bool DIDBackend_DeactivateDID(DIDDocument *signerdoc, DIDURL *signkey,
        DIDURL *creater, const char *storepass)
{
    const char *reqstring;
    bool successed;

    assert(signerdoc);
    assert(signkey);
    assert(storepass && *storepass);

    if (!gCreateIdTransaction) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Not method to create transaction.\
                Please set method by initialize backend.");
        return false;
    }

    if (!DIDMetadata_AttachedStore(&signerdoc->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    reqstring = DIDRequest_Sign(RequestType_Deactivate, signerdoc, signkey, creater, NULL, storepass);
    if (!reqstring)
        return false;

    successed = gCreateIdTransaction(reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(deactivated) failed.");

    return successed;
}

static json_t *get_resolve_result(json_t *json)
{
    json_t *item, *field;
    int code;

    assert(json);

    item = json_object_get(json, "result");
    if (!item || !json_is_object(item)) {
        item = json_object_get(json, "error");
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
        return NULL;
    }

    return item;
}

static int resolvedid_from_backend(ResolveResult *result, DID *did, bool all)
{
    const char *data = NULL, *forAll;
    json_t *root = NULL, *item;
    json_error_t error;
    char _idstring[ELA_MAX_DID_LEN], request[256], *didstring;
    int rc = -1;

    assert(result);
    assert(did);

    didstring = DID_ToString(did, _idstring, sizeof(_idstring));
    if (!didstring)
        return rc;

    forAll = !all ? "false" : "true";
    if (sprintf(request, DID_RESOLVE_REQUEST, didstring, forAll) == -1)
        return rc;

    data = gResolve(request);
    if (!data) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Resolve data %s from chain failed.", did->idstring);
        return rc;
    }

    root = json_loads(data, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Deserialize resolved data failed, error: %s.", error.text);
        goto errorExit;
    }

    item = get_resolve_result(root);
    if (!item)
        goto errorExit;

    if (ResolveResult_FromJson(result, item, all) == -1)
        goto errorExit;

    if (ResolveResult_GetStatus(result) != DIDStatus_NotFound && ResolveCache_StoreDID(result, did) == -1)
        goto errorExit;

    rc = 0;

errorExit:
    if (root)
        json_decref(root);
    if (data)
        free((void*)data);
    return rc;
}

static ssize_t listvcs_result_fromjson(json_t *json, DIDURL **buffer, size_t size, const char *did)
{
    json_t *item, *field;
    DIDURL *id;
    size_t len = 0;
    int i;

    assert(json);
    assert(buffer);

    item = json_object_get(json, "did");
    if (!item) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Missing did filed.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid did filed.");
        return -1;
    }
    if (strcmp(did, json_string_value(item))) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Response is not for this DID.");
        return -1;
    }

    item = json_object_get(json, "credentials");
    if (!item)
        return 0;

    if (!json_is_array(item)) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Invalid credentials.");
        return -1;
    }

    for (i = 0; i < json_array_size(item); i++) {
        field = json_array_get(item, i);
        if (field) {
            id = DIDURL_FromString(json_string_value(field), NULL);
            if (id)
                buffer[len++] = id;
        }
    }
    return len;
}

static ssize_t listvcs_from_backend(DID *did, DIDURL **buffer, size_t size, int skip, int limit)
{
    const char *data = NULL;
    json_t *root = NULL, *item;
    json_error_t error;
    char _idstring[ELA_MAX_DID_LEN], request[256], *didstring;
    ssize_t rc = -1, len = 0;

    assert(buffer);
    assert(did);
    assert(size > 0);
    assert(skip >= 0);
    assert(limit > 0);

    didstring = DID_ToString(did, _idstring, sizeof(_idstring));
    if (!didstring)
        return rc;

    if (sprintf(request, DID_RESOLVEVC_REQUEST, didstring, skip, limit) == -1)
        return rc;

    data = gResolve(request);
    if (!data) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Resolve did %s failed.", did->idstring);
        return rc;
    }

    root = json_loads(data, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Deserialize resolved data failed, error: %s.", error.text);
        goto errorExit;
    }

    item = get_resolve_result(root);
    if (!item)
        goto errorExit;

    rc = listvcs_result_fromjson(item, buffer, size, didstring);

errorExit:
    if (root)
        json_decref(root);
    if (data)
        free((void*)data);
    return rc;
}

static CredentialBiography *resolvevc_from_backend(DIDURL *id, DID *issuer)
{
    CredentialBiography *biography = NULL;
    const char *data = NULL;
    json_t *root = NULL, *item;
    json_error_t error;
    char _idstring[ELA_MAX_DIDURL_LEN], _didstring[ELA_MAX_DID_LEN], request[256], *idstring, *didstring = NULL;

    assert(id);

    idstring = DIDURL_ToString(id, _idstring, sizeof(_idstring), false);
    if (!idstring)
        return NULL;

    if (issuer) {
        didstring = DID_ToString(issuer, _didstring, sizeof(_didstring));
        if (!didstring || sprintf(request, VC_RESOLVE_WITH_ISSUER_REQUEST, idstring, didstring) == -1)
            return NULL;
    } else {
        if (sprintf(request, VC_RESOLVE_REQUEST, idstring) == -1)
            return NULL;
    }

    data = gResolve(request);
    if (!data) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Resolve data %s from chain failed.", idstring);
        return NULL;
    }

    root = json_loads(data, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_RESOLVE_ERROR, "Deserialize resolved data failed, error: %s.", error.text);
        goto errorExit;
    }

    item = get_resolve_result(root);
    if (!item)
        goto errorExit;

    biography = CredentialBiography_FromJson(item);
    if (!biography)
        goto errorExit;

    if (CredentialBiography_GetStatus(biography) != CredentialStatus_NotFound &&
            ResolveCache_StoreCredential(biography, id) == -1) {
        CredentialBiography_Destroy(biography);
        biography = NULL;
    }

errorExit:
    if (root)
        json_decref(root);
    if (data)
        free((void*)data);
    return biography;
}

static int resolve_internal(ResolveResult *result, DID *did, bool all, bool force)
{
    assert(result);
    assert(did);
    assert(!all || (all && force));

    if (!force && ResolverCache_LoadDID(result, did, ttl) == 0)
        return 0;

    if (resolvedid_from_backend(result, did, all) < 0)
        return -1;

    return 0;
}

static CredentialBiography *resolvevc_internal(DIDURL *id, DID *issuer, bool force)
{
    CredentialBiography *biography;

    assert(id);

    if (!force) {
        biography = ResolverCache_LoadCredential(id, issuer, ttl);
        if (biography)
            return biography;
    }

    return resolvevc_from_backend(id, issuer);
}

DIDDocument *DIDBackend_ResolveDID(DID *did, int *status, bool force)
{
    DIDDocument *doc = NULL;
    ResolveResult result;
    DIDTransaction *info = NULL;
    const char *op;
    size_t i;

    assert(did);

    //If user give did document to verify, sdk use it first.
    if (gLocalResolveHandle) {
        doc = gLocalResolveHandle(did);
        if (doc)
            return doc;
    }

    if (!gResolve) {
        *status = DIDStatus_Error;
        DIDError_Set(DIDERR_INVALID_BACKEND, "Resolver not initialized.");
        return NULL;
    }

    memset(&result, 0, sizeof(ResolveResult));
    if (resolve_internal(&result, did, false, force) == -1)
        goto errorExit;

    switch (result.status) {
        case DIDStatus_NotFound:
            *status = DIDStatus_NotFound;
            ResolveResult_Destroy(&result);
            return NULL;

        case DIDStatus_Deactivated:
            if (result.txs.size != 2) {
                DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Invalid DID biography, wrong transaction count.");
                goto errorExit;
            }

            if (strcmp("deactivate", result.txs.txs[0].request.header.op) ||
                    !strcmp("deactivate", result.txs.txs[1].request.header.op)) {
                DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Invalid DID biography, wrong status.");
                goto errorExit;
            }

            info = &result.txs.txs[1];
            doc = info->request.doc;
            if (!doc) {
                DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Invalid DID biography, missing document.");
                goto errorExit;
            }

            if (!DIDRequest_IsValid(&result.txs.txs[0].request, doc)) {
                DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Document is not valid.");
                goto errorExit;
            }

            *status = DIDStatus_Deactivated;
            i = 2;
            break;

        case DIDStatus_Valid:
            info = &result.txs.txs[0];
            doc = info->request.doc;
            if (!doc) {
                DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Invalid DID biography, missing document.");
                goto errorExit;
            }

            *status = DIDStatus_Valid;
            i = 1;
            break;

        default:
            DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport other transaction status.");
            goto errorExit;
    }

    op = info->request.header.op;
    if (strcmp("create", op) && strcmp("update", op) && strcmp("transfer", op)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Wrong transaction status.");
        goto errorExit;
    }

    if (!DIDRequest_IsValid(&info->request, doc)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESULT, "Invalid transaction.");
        goto errorExit;
    }

    for (; i < result.txs.size; i++)
        DIDDocument_Destroy(result.txs.txs[i].request.doc);
    ResolveResult_Free(&result);
    return doc;

errorExit:
    *status = DIDStatus_Error;
    ResolveResult_Destroy(&result);
    return NULL;
}

DIDBiography *DIDBackend_ResolveDIDBiography(DID *did)
{
    ResolveResult result;

    assert(did);

    if (!gResolve) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Resolver not initialized.");
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

    return ResolveResult_ToDIDBiography(&result);
}

ssize_t DIDBackend_ListCredentials(DID *did, DIDURL **buffer, size_t size,
        int skip, int limit)
{
    assert(did);
    assert(buffer);
    assert(size > 0);
    assert(skip >= 0 && limit > 0);

    if (!gResolve) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Resolver not initialized.");
        return -1;
    }

    return listvcs_from_backend(did, buffer, size, skip, limit);
}

//*****Credential
bool DIDBackend_DeclareCredential(Credential *vc, DIDURL *signkey,
        DIDDocument *document, const char *storepass)
{
    const char *reqstring;
    bool successed;

    assert(vc);
    assert(signkey);
    assert(document);
    assert(storepass && *storepass);

    if (!gCreateIdTransaction) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Not method to create transaction.\
                Please set method by initialize backend.");
        return false;
    }

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    reqstring = CredentialRequest_Sign(RequestType_Declare, NULL, vc, signkey, document, storepass);
    if (!reqstring)
        return false;

    successed = gCreateIdTransaction(reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(deactivated) failed.");

    return successed;
}

bool DIDBackend_RevokeCredential(DIDURL *credid, DIDURL *signkey, DIDDocument *document,
        const char *storepass)
{
    const char *reqstring;
    bool successed;

    assert(credid);
    assert(signkey);
    assert(document);
    assert(storepass && *storepass);

    if (!gCreateIdTransaction) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Not method to create transaction.\
                Please set method by initialize backend.");
        return false;
    }

    if (!DIDMetadata_AttachedStore(&document->metadata)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Not attached with DID store.");
        return false;
    }

    reqstring = CredentialRequest_Sign(RequestType_Revoke, credid, NULL, signkey, document, storepass);
    if (!reqstring)
        return false;

    successed = gCreateIdTransaction(reqstring, "");
    free((void*)reqstring);
    if (!successed)
        DIDError_Set(DIDERR_INVALID_BACKEND, "create Id transaction(deactivated) failed.");

    return successed;
}

Credential *DIDBackend_ResolveCredential(DIDURL *id, int *status, bool force)
{
    CredentialBiography *biography;
    CredentialTransaction *info;
    Credential *cred = NULL;
    DIDDocument *issuerdoc = NULL;
    int i;

    assert(id);

    if (!gResolve) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Resolver not initialized.");
        return NULL;
    }

    biography = resolvevc_internal(id, NULL, false);
    if (!biography) {
        *status = CredentialStatus_Error;
        return NULL;
    }

    switch (biography->status) {
        case CredentialStatus_NotFound:
            *status = CredentialStatus_NotFound;
            CredentialBiography_Destroy(biography);
            return NULL;

        case CredentialStatus_Revoked:
            if (biography->txs.size > 2 || biography->txs.size == 0) {
                DIDError_Set(DIDERR_TRANSACTION_ERROR, "Invalid Credential biography, wrong transaction count.");
                break;
            }

            for (i = biography->txs.size - 1; i >= 0 ; i--) {
                info = &biography->txs.txs[i];
                if (!strcmp("declare", info->request.header.op)) {
                    if (i == 0) {
                        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Invalid declare transaction.");
                        goto errorExit;
                    }
                    cred = info->request.vc;
                    if (!cred) {
                        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Miss credential in transaction.");
                        goto errorExit;
                    }
                }

                if (!strcmp("revoke", info->request.header.op)) {
                    if (info->request.vc) {
                        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Invalid revoke transaction.");
                        goto errorExit;
                    }
                }

                if (!CredentialRequest_IsValid(&info->request, cred))
                    goto errorExit;
            }
            *status = CredentialStatus_Revoked;
            CredentialBiography_Free(biography);
            return cred;

        case CredentialStatus_Valid:
            if (biography->txs.size != 1) {
                DIDError_Set(DIDERR_TRANSACTION_ERROR, "Invalid Credential biography, wrong transaction count.");
                goto errorExit;
            }

            info = &biography->txs.txs[0];
            if (strcmp("declare", info->request.header.op)) {
                DIDError_Set(DIDERR_TRANSACTION_ERROR, "Invalid Credential biography, wrong transaction status.");
                goto errorExit;
            }

            cred = info->request.vc;
            if (!cred) {
                DIDError_Set(DIDERR_TRANSACTION_ERROR, "Declare transaction must have credential.");
                goto errorExit;
            }

            if (!CredentialRequest_IsValid(&info->request, cred))
                goto errorExit;

            *status = CredentialStatus_Valid;
            CredentialBiography_Free(biography);
            return cred;

        default:
            DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport other status.");
            break;
    }

errorExit:
    *status = CredentialStatus_Error;
    CredentialBiography_Destroy(biography);
    return NULL;
}

bool DIDBackend_ResolveRevocation(DIDURL *id, DID *issuer)
{
    CredentialBiography *biography;

    bool isexist;

    assert(id);
    assert(issuer);

    if (!gResolve) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Resolver not initialized.");
        return false;
    }

    biography = resolvevc_from_backend(id, issuer);
    if (!biography)
        return false;

    isexist = (CredentialBiography_GetStatus(biography) == CredentialStatus_Revoked) ? true : false;
    CredentialBiography_Destroy(biography);
    return isexist;
}

CredentialBiography *DIDBackend_ResolveCredentialBiography(DIDURL *id, DID *issuer)
{
    CredentialBiography *biography;

    assert(id);

    if (!gResolve) {
        DIDError_Set(DIDERR_INVALID_BACKEND, "Resolver not initialized.");
        return NULL;
    }

    biography = resolvevc_internal(id, issuer, true);
    if (biography && CredentialBiography_GetStatus(biography) == CredentialStatus_NotFound) {
        CredentialBiography_Destroy(biography);
        return NULL;
    }

    return biography;
}

void DIDBackend_SetTTL(long _ttl)
{
    ttl = _ttl;
}

void DIDBackend_SetLocalResolveHandle(DIDLocalResovleHandle *handle)
{
    gLocalResolveHandle = handle;
}
