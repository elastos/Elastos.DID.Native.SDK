#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <assert.h>
#include <time.h>
#include <jansson.h>

#include "ela_did.h"
#include "dummyadapter.h"
#include "didtransactioninfo.h"
#include "vctransactioninfo.h"
#include "didrequest.h"
#include "vcrequest.h"
#include "crypto.h"
#include "common.h"
#include "diderror.h"

#define TXID_LEN            32

static const char elastos_did_prefix[] = "did:elastos:";

static DummyAdapter adapterInstance;
static DIDTransactionInfo *infos[256];
static CredentialTransaction *vcinfos[256];
static int num;
static int vcnum;

static int get_txid(char *txid)
{
    static char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    int i;

    assert(txid);

    for (i = 0; i < TXID_LEN; i++)
        txid[i] = chars[rand() % 62];

    txid[TXID_LEN] = 0;
    return 0;
}

static DIDTransactionInfo *get_lasttransaction(DID *did)
{
    DIDTransactionInfo *info;
    int i;

    assert(did);

    for (i = num - 1; i >= 0; i--) {
        info = infos[i];
        if (DID_Equals(did, DIDTransactionInfo_GetOwner(info)))
            return info;
    }
    return NULL;
}

static DIDTransactionInfo *get_transaction(DID *did, int index)
{
    DIDTransactionInfo *info;

    assert(did);
    assert(index >= 0 && index < num);

    info = infos[index];
    return DID_Equals(did, DIDTransactionInfo_GetOwner(info)) ? info : NULL;
}

static bool DummyAdapter_CreateIdTransaction(DIDAdapter *_adapter, const char *payload, const char *memo)
{
    DIDTransactionInfo *info = NULL, *lastinfo;
    json_t *root;
    json_error_t error;
    DIDDocument *doc;

    assert(_adapter);
    assert(payload);

    if (num >= sizeof(infos)) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "The DIDTransactionInfo array should be larger.");
        return false;
    }

    root = json_loads(payload, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Get payload json failed, error: %s.", error.text);
        return false;
    }

    info = (DIDTransactionInfo*)calloc(1, sizeof(DIDTransactionInfo));
    if (!info) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DIDTransactionInfo failed.");
        return false;
    }

    doc = DIDRequest_FromJson(&info->request, root);
    if (strcmp(info->request.header.op, "deactivate")) {
        if (!doc || !DIDDocument_IsValid(doc))
        goto errorExit;
    }

    lastinfo = get_lasttransaction(&info->request.did);
    if (!strcmp(info->request.header.op, "create")) {
        if (lastinfo) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID already exist.");
            goto errorExit;
        }
    } else if (!strcmp(info->request.header.op, "update")) {
        if (!lastinfo) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID not exist.");
            goto errorExit;
        }
        if (!strcmp(lastinfo->request.header.op, "deactivate")) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID already deactivate.");
            goto errorExit;
        }
        if (strcmp(info->request.header.prevtxid, lastinfo->txid)) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "Previous transaction id missmatch.");
            goto errorExit;
        }
    } else if (!strcmp(info->request.header.op, "deactivate")) {
        if (!lastinfo) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID not exist.");
            goto errorExit;
        }
        if (!strcmp(lastinfo->request.header.op, "deactivate")) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID already dactivated.");
            goto errorExit;
        }
    } else {
        DIDError_Set(DIDERR_UNSUPPOTED, "No this operation.");
        goto errorExit;
    }

    if (get_txid(info->txid) == -1) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Generate transaction id failed.");
        goto errorExit;
    }

    info->timestamp = time(NULL);
    infos[num++] = info;
    json_decref(root);
    return true;

errorExit:
    if (info)
        DIDTransactionInfo_Destroy(info);
    if (root)
        json_decref(root);

    return false;
}

static int result_tojson(JsonGenerator *gen, DID *did, bool all)
{
    DIDTransactionInfo *info;
    char idstring[ELA_MAX_DID_LEN];
    int status;

    assert(gen);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "did",
            DID_ToString(did, idstring, sizeof(idstring))));

    info = get_lasttransaction(did);
    if (!info) {
        status = 3;
    } else {
        if (!strcmp(info->request.header.op, "deactivate")) {
            status = 2;
        } else {
            if (DIDDocument_IsExpires(info->request.doc))
                status = 1;
            else
                status = 0;
        }
    }

    CHECK(JsonGenerator_WriteFieldName(gen, "status"));
    CHECK(JsonGenerator_WriteNumber(gen, status));

    if (status == 3) {
        CHECK(JsonGenerator_WriteEndObject(gen));
        return 0;
    }

    CHECK(JsonGenerator_WriteFieldName(gen, "transaction"));
    CHECK(JsonGenerator_WriteStartArray(gen));
    if (all) {
        int i;
        for (i = num - 1; i >= 0; i--) {
            info = get_transaction(did, i);
            if (info)
                CHECK(DIDTransactionInfo_ToJson_Internal(gen, info));
        }
    } else {
        info = get_lasttransaction(did);
        CHECK(DIDTransactionInfo_ToJson_Internal(gen, info));
    }
    CHECK(JsonGenerator_WriteEndArray(gen));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

static int resolve_tojson(JsonGenerator *gen, DID *did, bool all)
{
    assert(gen);
    assert(did);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "jsonrpc", "2.0"));
    CHECK(JsonGenerator_WriteFieldName(gen, "result"));
    CHECK(result_tojson(gen, did, all));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

const char* DummyAdapter_ResolveDID(DIDResolver *resolver, const char *did, int all)
{
    JsonGenerator g, *gen;
    DID *_did;
    int rc;

    if (!resolver || !did) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (strncmp(did, elastos_did_prefix, strlen(elastos_did_prefix))) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport this did.");
        return NULL;
    }

    _did = DID_FromString(did);
    if (!_did)
        return NULL;

    gen = JsonGenerator_Initialize(&g);
    if (!gen)
        return NULL;

    rc = resolve_tojson(gen, _did, all);
    DID_Destroy(_did);
    if (rc < 0) {
        JsonGenerator_Destroy(gen);
        return NULL;
    }

    return JsonGenerator_Finish(gen);
}

static void DummyAdapter_Reset(DummyAdapter *adapter)
{
    int i;
    for (i = 0; i < num; i++) {
        DIDTransactionInfo_Destroy(infos[i]);
        free(infos[i]);
    }
    memset(infos, 0, sizeof(infos));
    num = 0;
}

//---------- Credential ------------
static CredentialTransaction *get_lastvctransaction(DIDURL *id)
{
    CredentialTransaction *info;
    int i;

    assert(id);

    for (i = vcnum - 1; i >= 0; i--) {
        info = vcinfos[i];
        if (DIDURL_Equals(id, CredentialTransaction_GetId(info)))
            return info;
    }
    return NULL;
}

static CredentialTransaction *get_vctransaction(DIDURL *id, int index)
{
    CredentialTransaction *info;

    assert(id);
    assert(index >= 0 && index < vcnum);

    info = vcinfos[index];
    return DIDURL_Equals(id, CredentialTransaction_GetId(info)) ? info : NULL;
}

static bool DummyAdapter_CreateVcTransaction(DIDAdapter *_adapter, const char *payload, const char *memo)
{
    CredentialTransaction *info = NULL, *lastinfo;
    json_t *root;
    json_error_t error;
    Credential *vc;

    assert(_adapter);
    assert(payload);

    if (vcnum >= sizeof(vcinfos)) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "The CredentialTransaction array should be larger.");
        return false;
    }

    root = json_loads(payload, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Get payload json failed, error: %s.", error.text);
        return false;
    }

    info = (CredentialTransaction*)calloc(1, sizeof(CredentialTransaction));
    if (!info) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for CredentialTransaction failed.");
        return false;
    }

    vc = CredentialRequest_FromJson(&info->request, root);
    lastinfo = get_lastvctransaction(&info->request.id);

    if (!strcmp(info->request.header.op, "declear")) {
        if (!vc || !Credential_IsValid(vc))
            goto errorExit;

        if (lastinfo) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "Credential already exist.");
            goto errorExit;
        }
    } else if (!strcmp(info->request.header.op, "revoke")) {
        if (vc)
            goto errorExit;

        if (lastinfo) {
            if (!strcmp(lastinfo->request.header.op, "revoke")) {
                DIDError_Set(DIDERR_TRANSACTION_ERROR, "Don't revoke the inexistence credential.");
                goto errorExit;
            }
        }
    } else {
        DIDError_Set(DIDERR_UNSUPPOTED, "No this operation.");
        goto errorExit;
    }

    if (get_txid(info->txid) == -1) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Generate transaction id failed.");
        goto errorExit;
    }

    info->timestamp = time(NULL);
    vcinfos[vcnum++] = info;
    json_decref(root);
    return true;

errorExit:
    if (info)
        CredentialTransaction_Destroy(info);
    if (root)
        json_decref(root);

    return false;
}

static int vcresult_tojson(JsonGenerator *gen, DIDURL *id, bool all)
{
    CredentialTransaction *info;
    char idstring[ELA_MAX_DID_LEN];
    int status;

    assert(gen);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "id",
            DIDURL_ToString(id, idstring, sizeof(idstring), false)));

    info = get_lastvctransaction(id);
    if (!info) {
        status = 2;
    } else {
        if (!strcmp(info->request.header.op, "revoke")) {
            status = 1;
        } else {
            status = 0;
        }
    }

    CHECK(JsonGenerator_WriteFieldName(gen, "status"));
    CHECK(JsonGenerator_WriteNumber(gen, status));

    if (status == 2) {
        CHECK(JsonGenerator_WriteEndObject(gen));
        return 0;
    }

    CHECK(JsonGenerator_WriteFieldName(gen, "transaction"));
    CHECK(JsonGenerator_WriteStartArray(gen));
    if (all) {
        int i;
        for (i = vcnum - 1; i >= 0; i--) {
            info = get_vctransaction(id, i);
            if (info)
                CHECK(CredentialTransaction_ToJson_Internal(gen, info));
        }
    } else {
        info = get_lastvctransaction(id);
        CHECK(CredentialTransaction_ToJson_Internal(gen, info));
    }
    CHECK(JsonGenerator_WriteEndArray(gen));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

static int vcresolve_tojson(JsonGenerator *gen, DIDURL *id, bool all)
{
    assert(gen);
    assert(id);

    CHECK(JsonGenerator_WriteStartObject(gen));
    CHECK(JsonGenerator_WriteStringField(gen, "jsonrpc", "2.0"));
    CHECK(JsonGenerator_WriteFieldName(gen, "result"));
    CHECK(vcresult_tojson(gen, id, all));
    CHECK(JsonGenerator_WriteEndObject(gen));
    return 0;
}

const char* DummyAdapter_ResolveVc(DIDResolver *resolver, const char *id, int all)
{
    JsonGenerator g, *gen;
    DIDURL *_id;
    int rc;

    if (!resolver || !id) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (strncmp(id, elastos_did_prefix, strlen(elastos_did_prefix))) {
        DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport this did.");
        return NULL;
    }

    _id = DIDURL_FromString(id, NULL);
    if (!_id)
        return NULL;

    gen = JsonGenerator_Initialize(&g);
    if (!gen)
        return NULL;

    rc = vcresolve_tojson(gen, _id, all);
    DIDURL_Destroy(_id);
    if (rc < 0) {
        JsonGenerator_Destroy(gen);
        return NULL;
    }

    return JsonGenerator_Finish(gen);
}

static void DummyAdapter_ResetVc(DummyAdapter *adapter)
{
    int i;
    for (i = 0; i < num; i++) {
        CredentialTransaction_Destroy(vcinfos[i]);
        free(vcinfos[i]);
    }
    memset(vcinfos, 0, sizeof(vcinfos));
    vcnum = 0;
}

DummyAdapter *DummyAdapter_Create(void)
{
    adapterInstance.adapter.CreateIdRequest = DummyAdapter_CreateIdTransaction;
    adapterInstance.adapter.CreateCredentialRequest = DummyAdapter_CreateVcTransaction;
    adapterInstance.resolver.ResolveDID = DummyAdapter_ResolveDID;
    adapterInstance.resolver.ResolveCredential = DummyAdapter_ResolveVc;
    adapterInstance.resetdid = DummyAdapter_Reset;
    adapterInstance.resetvc = DummyAdapter_ResetVc;
    return &adapterInstance;
}

void DummyAdapter_Destroy(void)
{
    int i;
    for (i = 0; i < num; i++) {
        DIDTransactionInfo_Destroy(infos[i]);
        free(infos[i]);
    }

    for (i = 0; i < vcnum; i++) {
        CredentialTransaction_Destroy(vcinfos[i]);
        free(vcinfos[i]);
    }

    memset(infos, 0, sizeof(infos));
    memset(vcinfos, 0, sizeof(vcinfos));
    num = 0;
    vcnum = 0;
}


