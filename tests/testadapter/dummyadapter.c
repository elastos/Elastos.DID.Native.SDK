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
#include "didbiography.h"
#include "diddocument.h"
#include "credential.h"

#define TXID_LEN            32
static const char elastos_did_prefix[] = "did:elastos:";
static const char *didspec = "elastos/did/1.0";
static const char *vcspec = "elastos/credential/1.0";
static const char *methods[3] = {"resolvedid", "listcredentials", "resolvecredential"};

static DIDTransaction *infos[256];
static CredentialTransaction *vcinfos[1500];
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

static DIDTransaction *get_lasttransaction(DID *did)
{
    DIDTransaction *info;
    int i;

    if (did) {
        for (i = num - 1; i >= 0; i--) {
            info = infos[i];
            if (DID_Equals(did, DIDTransaction_GetOwner(info)))
                return info;
        }
    }
    return NULL;
}

static DIDDocument *get_lastdocument(DID *did)
{
    DIDTransaction *info;
    int i;

    if (did) {
        for (i = num - 1; i >= 0; i--) {
            info = infos[i];
            if (DID_Equals(did, DIDTransaction_GetOwner(info))) {
                if (strcmp(info->request.header.op, "deactivate"))
                    return info->request.doc;
            }
        }
    }
    return NULL;
}

static DIDDocument *get_issuerdoc(DIDURL *id)
{
    int i;
    DID *issuer = NULL;
    DIDDocument *doc = NULL;
    CredentialTransaction *info;

    assert(id);

    for (i = 0; i < vcnum; i++) {
        info = vcinfos[i];
        if (DIDURL_Equals(id, &info->request.id)) {
            if (!strcmp("declare", info->request.header.op))
                issuer = &info->request.vc->issuer;
        }
    }

    return get_lastdocument(issuer);
}

bool credential_readyrevoke(DIDURL *id, DIDURL *signkey, DIDDocument *ownerdoc,
        DIDDocument *issuerdoc)
{
    CredentialTransaction *info;
    DIDURL *_signkey;
    int i;

    assert(id);
    assert(signkey);
    assert(ownerdoc);

    for (i = vcnum - 1; i >= 0; i--) {
        info = vcinfos[i];
        if (DIDURL_Equals(id, &info->request.id)) {
            if (strcmp("revoke", info->request.header.op))
                continue;

            _signkey = &info->request.proof.verificationMethod;
            if (DIDURL_Equals(_signkey, signkey) || DIDDocument_IsAuthenticationKey(ownerdoc, _signkey))
                return false;

            if (issuerdoc && DIDDocument_IsAuthenticationKey(issuerdoc, _signkey))
                return false;
        }
    }

    //no revoke tx
    if (issuerdoc) {
        if (!DIDDocument_IsAuthenticationKey(ownerdoc, signkey) &&
                !DIDDocument_IsAuthenticationKey(issuerdoc, signkey))
            return false;
    }

    return true;
}

bool credential_readydeclare(DIDURL *id, DID *issuer)
{
    CredentialTransaction *info;
    DID *signer;
    int i;

    assert(id);
    assert(issuer);

    for (i = 0; i < vcnum; i++) {
        info = vcinfos[i];
        if (DIDURL_Equals(id, &info->request.id)) {
            if (!strcmp("declare", info->request.header.op))
                return false;

            if (!strcmp("revoke", info->request.header.op)) {
                signer = &info->request.proof.verificationMethod.did;
                if (DID_Equals(&id->did, signer) || DID_Equals(issuer, signer)) {
                    return false;
                }
            }
        }
    }

    return true;
}

static int get_method(const char *method)
{
    int i;

    assert(method && *method);

    for (i = 0; i < 3; i++) {
        if (!strcmp(method, methods[i]))
            return i;
    }

    return -1;
}

static bool check_ticket(const char* data, DIDDocument *doc, char *txid)
{
    size_t len;
    char *ticketJson;
    TransferTicket *ticket;
    bool check = false;

    assert(data);

    len = strlen(data) + 1;
    ticketJson = (char*)malloc(len);
    len = b64_url_decode((uint8_t *)ticketJson, data);
    if (len <= 0) {
        free((void*)ticketJson);
        return false;
    }
    ticketJson[len] = 0;

    ticket = TransferTicket_FromJson(ticketJson);
    free((void*)ticketJson);
    if (!ticket)
        return false;

    check = (!strcmp(ticket->txid, txid)) && TransferTicket_IsValid(ticket) &&
            DIDDocument_GetControllerDocument(doc, &ticket->to);
    TransferTicket_Destroy(ticket);
    return check;
}

static bool controllers_equals(DIDDocument *doc1, DIDDocument *doc2)
{
    int i;
    DID *controller;

    assert(doc1);
    assert(doc2);

    if (doc1->controllers.size != doc2->controllers.size)
        return false;

    for (i = 0; i < doc2->controllers.size; i++) {
        controller = &doc2->controllers.docs[i]->did;
        if (!DIDDocument_GetControllerDocument(doc1, controller))
            return false;
    }

    return true;
 }

static bool create_didtransaction(json_t *json)
{
    DIDTransaction *info = NULL, *lastinfo;

    assert(json);

    info = (DIDTransaction*)calloc(1, sizeof(DIDTransaction));
    if (!info) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DIDTransaction failed.");
        return false;
    }

    if (DIDRequest_FromJson(&info->request, json) < 0)
        goto errorExit;

    lastinfo = get_lasttransaction(&info->request.did);
    //create
    if (!strcmp(info->request.header.op, "create")) {
        if (lastinfo) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID already exist.");
            goto errorExit;
        }
        if (!DIDRequest_IsValid(&info->request, NULL)) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID transaction is not valid.");
            goto errorExit;
        }
    //update
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
        if (DIDDocument_IsCustomizedDID(info->request.doc) &&
                !controllers_equals(info->request.doc, lastinfo->request.doc))
            goto errorExit;

        if (!DIDRequest_IsValid(&info->request, NULL)) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID transaction is not valid.");
            goto errorExit;
        }
    //transfer
    } else if (!strcmp(info->request.header.op, "transfer")) {
        if (!lastinfo) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID not exist.");
            goto errorExit;
        }
        if (!strcmp(lastinfo->request.header.op, "deactivate")) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID already deactivate.");
            goto errorExit;
        }
        if (!info->request.header.ticket) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "Transfer operation must attach the ticket.");
            goto errorExit;
        }
        if (controllers_equals(info->request.doc, lastinfo->request.doc)) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "Transfer operation is only for changing controller.");
            goto errorExit;
        }
        //check ticket
        if (!check_ticket(info->request.header.ticket, info->request.doc, lastinfo->txid))
            goto errorExit;

        if (!DIDRequest_IsValid(&info->request, NULL)) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID transaction is not valid.");
            goto errorExit;
        }
    //deactivate
    } else if (!strcmp(info->request.header.op, "deactivate")) {
        if (!lastinfo) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID not exist.");
            goto errorExit;
        }
        if (!strcmp(lastinfo->request.header.op, "deactivate")) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID already dactivated.");
            goto errorExit;
        }
        if (!DIDRequest_IsValid(&info->request, lastinfo->request.doc)) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "DID transaction is not valid.");
            goto errorExit;
        }
    } else {
        DIDError_Set(DIDERR_UNSUPPOTED, "Unknown operation.");
        goto errorExit;
    }

    if (get_txid(info->txid) == -1) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Generate transaction id failed.");
        goto errorExit;
    }

    info->timestamp = time(NULL);
    infos[num++] = info;
    return true;

errorExit:
    if (info) {
        DIDTransaction_Destroy(info);
        free((void*)info);
    }
    return false;
}

static bool create_vctransaction(json_t *json)
{
    CredentialTransaction *info;
    DIDDocument *ownerdoc, *issuerdoc;

    assert(json);

    info = (CredentialTransaction*)calloc(1, sizeof(CredentialTransaction));
    if (!info) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for CredentialTransaction failed.");
        return false;
    }

    if (CredentialRequest_FromJson(&info->request, json) < 0)
        goto errorExit;

    if (!strcmp(info->request.header.op, "declare")) {
        if (!info->request.vc || !CredentialRequest_IsValid(&info->request, NULL))
            goto errorExit;

        if (!credential_readydeclare(&info->request.vc->id, &info->request.vc->issuer)) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "Credential already exist.");
            goto errorExit;
        }
    } else if (!strcmp(info->request.header.op, "revoke")) {
        if (info->request.vc)
            goto errorExit;

        ownerdoc = get_lastdocument(&info->request.id.did);
        if (!ownerdoc) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "The owner of credential is not in chain.");
            goto errorExit;
        }

        issuerdoc = get_issuerdoc(&info->request.id);
        if (!credential_readyrevoke(&info->request.id,
                &info->request.proof.verificationMethod, ownerdoc, issuerdoc)) {
            DIDError_Set(DIDERR_TRANSACTION_ERROR, "Don't revoke the inexistence credential.");
            goto errorExit;
        }
    } else {
        DIDError_Set(DIDERR_UNSUPPOTED, "Unknown operation.");
        goto errorExit;
    }

    if (get_txid(info->txid) == -1) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Generate transaction id failed.");
        goto errorExit;
    }

    info->timestamp = time(NULL);
    vcinfos[vcnum++] = info;
    return true;

errorExit:
    if (info) {
        CredentialTransaction_Destroy(info);
        free((void*)info);
    }

    return false;
}

static bool DummyAdapter_CreateIdTransaction(const char *payload, const char *memo)
{
    json_t *root, *item, *field;
    json_error_t error;
    bool success = false;

    assert(payload);

    if (num >= sizeof(infos)) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "The DIDTransaction array should be larger.");
        return false;
    }

    root = json_loads(payload, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Get payload json failed, error: %s.", error.text);
        return false;
    }

    item = json_object_get(root, "header");
    if (!item || !json_is_object(item))
       goto errorExit;

    field = json_object_get(item, "specification");
    if (!field || !json_is_string(field))
       goto errorExit;

    if (!strcmp(json_string_value(field), didspec))
        success = create_didtransaction(root);
    if (!strcmp(json_string_value(field), vcspec))
        success = create_vctransaction(root);

errorExit:
    json_decref(root);
    return success;
}

static int didresult_tojson(JsonGenerator *gen, DID *did, bool all)
{
    DIDTransaction *info;
    char idstring[ELA_MAX_DID_LEN];
    int i, status;

    assert(gen);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "did",
            DID_ToString(did, idstring, sizeof(idstring))));

    info = get_lasttransaction(did);
    if (!info) {
        status = DIDStatus_NotFound;
    } else {
        if (!strcmp(info->request.header.op, "deactivate"))
            status = DIDStatus_Deactivated;
        else
            status = DIDStatus_Valid;
    }

    CHECK(DIDJG_WriteFieldName(gen, "status"));
    CHECK(DIDJG_WriteNumber(gen, status));

    if (status == DIDStatus_NotFound) {
        CHECK(DIDJG_WriteEndObject(gen));
        return 0;
    }

    info = NULL;
    CHECK(DIDJG_WriteFieldName(gen, "transaction"));
    CHECK(DIDJG_WriteStartArray(gen));
    if (all) {
        for (i = num - 1; i >= 0; i--) {
            info = infos[i];
            if (info && DID_Equals(did, DIDTransaction_GetOwner(info)))
                CHECK(DIDTransaction_ToJson_Internal(gen, info));
        }
    } else {
        if (status != DIDStatus_Deactivated) {
            info = get_lasttransaction(did);
            CHECK(DIDTransaction_ToJson_Internal(gen, info));
        } else {
            for (i = num - 1; i >= 0; i--) {
                if (infos[i] && DID_Equals(did, DIDTransaction_GetOwner(infos[i]))) {
                    if (!strcmp(infos[i]->request.header.op, "deactivate")) {
                        info = infos[i];
                    }
                    else {
                        if (info) {
                            CHECK(DIDTransaction_ToJson_Internal(gen, info));
                            CHECK(DIDTransaction_ToJson_Internal(gen, infos[i]));
                        }
                        break;
                    }
                }
            }
        }
    }
    CHECK(DIDJG_WriteEndArray(gen));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static int resolvedid_tojson(JsonGenerator *gen, DID *did, bool all)
{
    assert(gen);
    assert(did);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "jsonrpc", "2.0"));
    CHECK(DIDJG_WriteFieldName(gen, "result"));
    CHECK(didresult_tojson(gen, did, all));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static const char *parse_resolvedid(json_t *json)
{
    JsonGenerator g, *gen;
    json_t *item;
    DID *did;
    bool all;
    int rc;

    assert(json);

    item = json_object_get(json, "did");
    if (!item || !json_is_string(item))
        return NULL;

    did = DID_FromString(json_string_value(item));
    if (!did)
        return NULL;

    item = json_object_get(json, "all");
    if (!item || !json_is_boolean(item)) {
        DID_Destroy(did);
        return NULL;
    }

    all = (json_is_false(item) ? false : true);
    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DID_Destroy(did);
        return NULL;
    }

    rc = resolvedid_tojson(gen, did, all);
    DID_Destroy(did);
    if (rc < 0) {
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

static int listvcs_result_tojson(JsonGenerator *gen, DID *did, int skip, int _limit)
{
    CredentialTransaction *ct;
    DIDURL *vcs, *vcid;
    DID *vcowner;
    int i, j, count = 0, limit, size = 0;
    bool equal = false;
    char idstring[ELA_MAX_DIDURL_LEN];

    assert(gen);
    assert(did);
    assert(skip >= 0);
    assert(_limit >= 0);

    if (_limit > 1500)
        return -1;

    limit = _limit;

    if (_limit == 0)
        limit = 128;
    if (limit > 512)
        limit = 512;

    vcs = (DIDURL*)alloca(limit * sizeof(DIDURL));
    if (!vcs)
        return -1;

    for (i = vcnum - 1; i >= 0; i--) {
        ct = vcinfos[i];
        vcid = &ct->request.id;
        vcowner = &vcid->did;
        if (!DID_Equals(did, vcowner))
            continue;

        if (count >= skip + limit || size >= limit)
            break;

        if (count++ < skip)
            continue;

        if (!strcmp("declare", ct->request.header.op))
            DIDURL_Copy(&vcs[size++], vcid);
    }

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "did",
            DID_ToString(did, idstring, sizeof(idstring))));
    if (size > 0) {
        CHECK(DIDJG_WriteFieldName(gen, "credentials"));
        CHECK(DIDJG_WriteStartArray(gen));
        for (i = 0; i < size; i++)
            CHECK(DIDJG_WriteString(gen, DIDURL_ToString(&vcs[i], idstring, sizeof(idstring), false)));
        CHECK(DIDJG_WriteEndArray(gen));
    }

    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static int listvcs_tojson(JsonGenerator *gen, DID *did, int skip, int limit)
{
    assert(gen);
    assert(did);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "jsonrpc", "2.0"));
    CHECK(DIDJG_WriteFieldName(gen, "result"));
    CHECK(listvcs_result_tojson(gen, did, skip, limit));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static const char *parse_listvcs(json_t *json)
{
    JsonGenerator g, *gen;
    json_t *item;
    int skip, limit;
    DID *did;
    int rc;

    assert(json);

    item = json_object_get(json, "did");
    if (!item || !json_is_string(item))
        return NULL;

    did = DID_FromString(json_string_value(item));
    if (!did)
        return NULL;

    item = json_object_get(json, "skip");
    if (!item || !json_is_number(item)) {
        DID_Destroy(did);
        return NULL;
    }
    skip = json_integer_value(item);

    item = json_object_get(json, "limit");
    if (!item || !json_is_number(item)) {
        DID_Destroy(did);
        return NULL;
    }
    limit = json_integer_value(item);

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DID_Destroy(did);
        return NULL;
    }

    rc = listvcs_tojson(gen, did, skip, limit);
    DID_Destroy(did);
    if (rc < 0) {
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

static int vcresult_tojson(JsonGenerator *gen, DIDURL *id, DID *issuer)
{
    CredentialTransaction *infos[2] = {0};
    CredentialTransaction *info;
    DIDDocument *ownerdoc, *issuerdoc = NULL;
    char idstring[ELA_MAX_DID_LEN];
    int i, size = 0, status = CredentialStatus_NotFound;
    DID *signer;
    DIDURL *signkey;

    assert(gen);
    assert(id);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "id",
            DIDURL_ToString(id, idstring, sizeof(idstring), false)));

    for (i = 0; i < vcnum; i++) {
        info = vcinfos[i];
        if (info && DIDURL_Equals(id, CredentialTransaction_GetId(info))) {
            if (!strcmp("declare", info->request.header.op)) {
                if (size > 0)
                    return -1;

                if (!issuer)
                    issuer = &info->request.vc->issuer;

                infos[size++] = info;
                status = CredentialStatus_Valid;
            }

            if (!strcmp("revoke", info->request.header.op)) {
                signkey = &info->request.proof.verificationMethod;
                ownerdoc = get_lastdocument(&id->did);
                if (!ownerdoc)
                    return -1;

                if (issuer) {
                    issuerdoc = get_lastdocument(issuer);
                    if (!issuerdoc)
                        return -1;
                }

                if (!DIDDocument_IsAuthenticationKey(ownerdoc, signkey) &&
                           !DIDDocument_IsAuthenticationKey(issuerdoc, signkey))
                    break;

                infos[size++] = info;
                status = CredentialStatus_Revoked;
            }
        }
    }

    CHECK(DIDJG_WriteFieldName(gen, "status"));
    CHECK(DIDJG_WriteNumber(gen, status));

    if (status == CredentialStatus_NotFound) {
        CHECK(DIDJG_WriteEndObject(gen));
        return 0;
    }

    CHECK(DIDJG_WriteFieldName(gen, "transaction"));
    CHECK(DIDJG_WriteStartArray(gen));
    for (i = size - 1; i >= 0; i--) {
        info = infos[i];
        if (info)
            CHECK(CredentialTransaction_ToJson_Internal(gen, info));
    }

    CHECK(DIDJG_WriteEndArray(gen));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static int resolvevc_tojson(JsonGenerator *gen, DIDURL *id, DID *issuer)
{
    assert(gen);
    assert(id);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, "jsonrpc", "2.0"));
    CHECK(DIDJG_WriteFieldName(gen, "result"));
    CHECK(vcresult_tojson(gen, id, issuer));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static const char *parse_resolvevc(json_t *json)
{
    JsonGenerator g, *gen;
    json_t *item;
    DIDURL *id = NULL;
    DID *issuer = NULL;
    const char *data = NULL;
    int rc;

    assert(json);

    item = json_object_get(json, "id");
    if (!item || !json_is_string(item))
        return NULL;

    id = DIDURL_FromString(json_string_value(item), NULL);
    if (!id)
        return NULL;

    item = json_object_get(json, "issuer");
    if (item) {
        if (!json_is_string(item))
            goto errorExit;

        issuer = DID_FromString(json_string_value(item));
        if (!issuer)
            goto errorExit;
    }

    gen = DIDJG_Initialize(&g);
    if (!gen)
        goto errorExit;

    rc = resolvevc_tojson(gen, id, issuer);
    if (rc < 0) {
        DIDJG_Destroy(gen);
        goto errorExit;
    }

    data = DIDJG_Finish(gen);

errorExit:
    DIDURL_Destroy(id);
    DID_Destroy(issuer);
    return data;
}

const char* DummyAdapter_Resolve(const char *request)
{
    json_t *root = NULL, *item;
    const char *method, *data = NULL;
    json_error_t error;

    assert(request && *request);

    root = json_loads(request, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_TRANSACTION_ERROR, "Get payload json failed, error: %s.", error.text);
        return NULL;
    }

    item = json_object_get(root, "method");
    if (!item || !json_is_string(item))
       goto errorExit;

    method = json_string_value(item);
    item = json_object_get(root, "params");
    if (!item || !json_is_object(item))
       goto errorExit;

    switch (get_method(method)) {
        case 0:
           data = parse_resolvedid(item);
           break;
        case 1:
           data = parse_listvcs(item);
           break;
        case 2:
           data = parse_resolvevc(item);
           break;
        default:
           break;
    }

errorExit:
    if(root)
        json_decref(root);
    return data;
}

int DummyAdapter_Set(const char *cachedir)
{
    DummyAdapter_Cleanup(0);
    return DIDBackend_Initialize(DummyAdapter_CreateIdTransaction, DummyAdapter_Resolve, cachedir);
}

static void DummyAdapter_DidCleanup(void)
{
    int i;
    for (i = 0; i < num; i++) {
        DIDTransaction_Destroy(infos[i]);
        free(infos[i]);
    }

    memset(infos, 0, sizeof(infos));
    num = 0;
}

static void DummyAdapter_VcCleanup(void)
{
    int i;
    for (i = 0; i < vcnum; i++) {
        CredentialTransaction_Destroy(vcinfos[i]);
        free(vcinfos[i]);
    }
    memset(vcinfos, 0, sizeof(vcinfos));
    vcnum = 0;
}

void DummyAdapter_Cleanup(int type)
{
    if (type == 0) {
        DummyAdapter_DidCleanup();
        DummyAdapter_VcCleanup();
    }
    if (type == 1)
        DummyAdapter_DidCleanup();
    if (type == 2)
        DummyAdapter_VcCleanup();
}


