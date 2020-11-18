#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <CUnit/Basic.h>
#include <limits.h>
#include <crystal.h>

#include "ela_did.h"
#include "constant.h"
#include "loader.h"
#include "did.h"
#include "didmeta.h"
#include "diddocument.h"

#define MAX_PUBLICKEY_BASE58      64
#define MAX_DOC_SIGN              128

static DIDStore *store;
static DIDDocument *controller1_doc;
static DIDDocument *controller2_doc;
static DIDDocument *controller3_doc;
static DID controller1;  //issuer doc
static DID controller2;  //controller doc
static DID controller3;  //doc

static void test_publish_ctmdid_withonecontroller(void)
{
    const char *customized_string = "littlefish", *keybase;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolve_doc, *customized_doc, *resolve_doc1;
    DID *controller, customizedid;
    DIDURL *keyid;
    DIDDocumentBuilder *builder;
    int rc, multisig_m, multisig_n;

    DID *controllers[1] = {0};
    controllers[0] = &controller1;

    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, NULL, controllers, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    DID_Copy(&customizedid, &customized_doc->did);
    DIDDocument_Destroy(customized_doc);

    CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, &customizedid, NULL, true));

    resolve_doc = DID_Resolve(&customizedid, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    rc = DIDStore_StoreDID(store, resolve_doc);
    DIDDocument_Destroy(resolve_doc);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    customized_doc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    //update
    builder = DIDDocument_Edit(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(customized_doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid = DIDURL_NewByDid(&customizedid, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *credid = DIDURL_NewByDid(&customizedid, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "John";

    rc = DIDDocumentBuilder_AddSelfClaimedCredential(builder, credid, types, 2,
            props, 1, 0, NULL, storepass);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    customized_doc = DIDDocumentBuilder_Seal(builder, NULL, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));
    DIDDocumentBuilder_Destroy(builder);

    //check: keyid(not default key) to sign, failed.
    rc = DIDStore_StoreDID(store, customized_doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_FALSE_FATAL(DIDStore_PublishDID(store, storepass, &customizedid, keyid, false));
    DIDURL_Destroy(keyid);

    //check: multisig larger than the count of controllers, failed.
    const char *idrequest = DIDStore_SignDIDRequest(store, &customizedid, 2, NULL, storepass, false);
    CU_ASSERT_PTR_NULL(idrequest);
    CU_ASSERT_STRING_EQUAL("Multisig is larger than the count of controllers.", DIDError_GetMessage());

    idrequest = DIDStore_SignDIDRequest(store, &customizedid, 0, NULL, storepass, false);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idrequest);
    CU_ASSERT_TRUE_FATAL(DIDStore_PublishIdRequest(store, idrequest));
    free((void*)idrequest);

    //resolve history
    DIDHistory *history = DID_ResolveHistory(&customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(history);
    CU_ASSERT_EQUAL_FATAL(2, DIDHistory_GetTransactionCount(history));

    DIDTransactionInfo *info = DIDHistory_GetTransaction(history, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    DIDRequest *request = DIDTransactionInfo_GetRequest(info);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);

    rc = DIDRequest_GetMultisig(request, &multisig_m, &multisig_n);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    CU_ASSERT_STRING_EQUAL("update", DIDRequest_GetOperation(request));
    CU_ASSERT_EQUAL_FATAL(1, DIDRequest_GetProofCount(request));

    time_t created;
    char signature[128] = {0};
    DIDURL key;
    rc = DIDRequest_GetProof(request, 0, &key, &created, signature, sizeof(signature));
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller1_doc)));

    resolve_doc = DIDRequest_GetDIDDocument(request);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    resolve_doc1 = DID_Resolve(&customizedid, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    Credential *cred = DIDDocument_GetCredential(resolve_doc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);
    DIDURL_Destroy(credid);

    const char *data1 = DIDDocument_ToJson(customized_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data1);
    const char *data2 = DIDDocument_ToJson(resolve_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data2);
    const char *data3 = DIDDocument_ToJson(resolve_doc1, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data3);
    CU_ASSERT_STRING_EQUAL(data1, data2);
    CU_ASSERT_STRING_EQUAL(data3, data2);

    free((void*)data1);
    free((void*)data2);
    free((void*)data3);
    DIDHistory_Destroy(history);
    DIDDocument_Destroy(resolve_doc1);
    DIDDocument_Destroy(customized_doc);
}

//create - resolve - edit document - update - resolve
static void test_publish_ctmdid_with_multicontroller(void)
{
    const char *customized_string = "cici", *keybase, *idrequest, *idrequest1;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolve_doc, *customized_doc, *resolve_doc1;
    DID *controller, customizedid;
    DIDURL *keyid, *signkey1, *signkey2, *signkey3;
    DIDDocumentBuilder *builder;
    int rc, multisig_m, multisig_n;

    DID *controllers[3] = {0};
    controllers[0] = &controller1;
    controllers[1] = &controller2;
    controllers[2] = &controller3;

    //create
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, &controller2, controllers, 3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    DID_Copy(&customizedid, &customized_doc->did);
    DIDDocument_Destroy(customized_doc);

    CU_ASSERT_FALSE_FATAL(DIDStore_PublishDID(store, storepass, &customizedid, NULL, true));

    //check: use the default key for multi-controller document, failed.
    idrequest = DIDStore_SignDIDRequest(store, &customizedid, 2, NULL, storepass, false);
    CU_ASSERT_PTR_NULL(idrequest);
    CU_ASSERT_STRING_EQUAL("Multipe controllers, so no default public key.", DIDError_GetMessage());

    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey1);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey2);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey3);

    idrequest = DIDStore_SignDIDRequest(store, &customizedid, 2, signkey1, storepass, false);
    CU_ASSERT_PTR_NOT_NULL(idrequest);

    //check: reuse the same key to sign id request, failed.
    idrequest1 = DIDStore_CounterSignDIDRequest(store, idrequest, signkey1, storepass);
    CU_ASSERT_PTR_NULL(idrequest1);
    CU_ASSERT_STRING_EQUAL("Already signed by the controller.", DIDError_GetMessage());

    idrequest1 = DIDStore_CounterSignDIDRequest(store, idrequest, signkey2, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idrequest1);
    free((void*)idrequest);

    //check: the count of signer is more than multisig, failed.
    idrequest = DIDStore_CounterSignDIDRequest(store, idrequest1, signkey3, storepass);
    CU_ASSERT_PTR_NULL_FATAL(idrequest);
    CU_ASSERT_STRING_EQUAL("The id request reach the count of proof, no need to more signature.",
            DIDError_GetMessage());

    CU_ASSERT_TRUE_FATAL(DIDStore_PublishIdRequest(store, idrequest1));
    free((void*)idrequest1);

    //resolve
    DIDHistory *history = DID_ResolveHistory(&customizedid);
    CU_ASSERT_PTR_NOT_NULL(history);
    CU_ASSERT_EQUAL_FATAL(1, DIDHistory_GetTransactionCount(history));

    DIDTransactionInfo *info = DIDHistory_GetTransaction(history, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    DIDRequest *request = DIDTransactionInfo_GetRequest(info);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);

    rc = DIDRequest_GetMultisig(request, &multisig_m, &multisig_n);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_EQUAL(2, multisig_m);
    CU_ASSERT_EQUAL(3, multisig_n);

    CU_ASSERT_STRING_EQUAL("create", DIDRequest_GetOperation(request));
    CU_ASSERT_EQUAL_FATAL(2, DIDRequest_GetProofCount(request));

    //check the signkey of proof
    time_t created;
    char signature[128] = {0};
    DIDURL key;
    rc = DIDRequest_GetProof(request, 0, &key, &created, signature, sizeof(signature));
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller1_doc)) ||
        DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller2_doc)));

    rc = DIDRequest_GetProof(request, 1, &key, &created, signature, sizeof(signature));
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller1_doc)) ||
        DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller2_doc)));

    rc = DIDStore_StoreDID(store, DIDRequest_GetDIDDocument(request));
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    DIDHistory_Destroy(history);

    customized_doc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    //update
    builder = DIDDocument_Edit(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(customized_doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid = DIDURL_NewByDid(&customizedid, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *credid = DIDURL_NewByDid(&customizedid, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "John";

    rc = DIDDocumentBuilder_AddSelfClaimedCredential(builder, credid, types, 2,
            props, 1, 0, signkey2, storepass);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    customized_doc = DIDDocumentBuilder_Seal(builder, &controller3, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL(9, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(7, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, customized_doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    CU_ASSERT_PTR_NULL(DIDStore_SignDIDRequest(store, &customizedid, 0, keyid, storepass, false));
    CU_ASSERT_STRING_EQUAL("The key is not the default key.", DIDError_GetMessage());

    idrequest = DIDStore_SignDIDRequest(store, &customizedid, 0, signkey2, storepass, false);
    CU_ASSERT_PTR_NOT_NULL(idrequest);

    idrequest1 = DIDStore_CounterSignDIDRequest(store, idrequest, signkey3, storepass);
    CU_ASSERT_PTR_NOT_NULL(idrequest1);
    free((void*)idrequest);

    idrequest = DIDStore_CounterSignDIDRequest(store, idrequest1, signkey1, storepass);
    CU_ASSERT_PTR_NULL_FATAL(idrequest);
    CU_ASSERT_STRING_EQUAL("The id request reach the count of proof, no need to more signature.", DIDError_GetMessage());

    CU_ASSERT_TRUE_FATAL(DIDStore_PublishIdRequest(store, idrequest1));
    free((void*)idrequest1);
    DIDURL_Destroy(keyid);

    //resolve history again
    history = DID_ResolveHistory(&customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(history);
    CU_ASSERT_EQUAL_FATAL(2, DIDHistory_GetTransactionCount(history));

    info = DIDHistory_GetTransaction(history, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    request = DIDTransactionInfo_GetRequest(info);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);

    rc = DIDRequest_GetMultisig(request, &multisig_m, &multisig_n);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(2, multisig_m);
    CU_ASSERT_EQUAL(3, multisig_n);

    CU_ASSERT_STRING_EQUAL("create", DIDRequest_GetOperation(request));
    CU_ASSERT_EQUAL_FATAL(2, DIDRequest_GetProofCount(request));

    info = DIDHistory_GetTransaction(history, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    request = DIDTransactionInfo_GetRequest(info);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);

    rc = DIDRequest_GetMultisig(request, &multisig_m, &multisig_n);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(2, multisig_m);
    CU_ASSERT_EQUAL(3, multisig_n);

    CU_ASSERT_STRING_EQUAL("update", DIDRequest_GetOperation(request));
    CU_ASSERT_EQUAL_FATAL(2, DIDRequest_GetProofCount(request));

    rc = DIDRequest_GetProof(request, 0, &key, &created, signature, sizeof(signature));
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller2_doc)) ||
            DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller3_doc)));

    rc = DIDRequest_GetProof(request, 1, &key, &created, signature, sizeof(signature));
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller2_doc)) ||
            DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller3_doc)));

    resolve_doc = DIDRequest_GetDIDDocument(request);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    resolve_doc1 = DID_Resolve(&customizedid, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    Credential *cred = DIDDocument_GetCredential(resolve_doc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);
    DIDURL_Destroy(credid);

    const char *data1 = DIDDocument_ToJson(customized_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data1);
    const char *data2 = DIDDocument_ToJson(resolve_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data2);
    const char *data3 = DIDDocument_ToJson(resolve_doc1, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data3);
    CU_ASSERT_STRING_EQUAL(data1, data2);
    CU_ASSERT_STRING_EQUAL(data3, data2);

    free((void*)data1);
    free((void*)data2);
    free((void*)data3);
    DIDHistory_Destroy(history);
    DIDDocument_Destroy(resolve_doc1);
    DIDDocument_Destroy(customized_doc);
}

//remove controller and change multisig
static void test_publish_ctmdid_with_multicontroller_after_removecontroller(void)
{
    const char *customized_string = "jack", *keybase;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolve_doc, *customized_doc, *resolve_doc1;
    DID customizedid;
    DIDURL *keyid, *signkey1, *signkey2, *signkey3;
    DIDDocumentBuilder *builder;
    int rc, multisig_m, multisig_n;

    DID *controllers[3] = {0};
    controllers[0] = &controller1;
    controllers[1] = &controller2;
    controllers[2] = &controller3;

    //create
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, &controller2, controllers, 3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    DID_Copy(&customizedid, &customized_doc->did);
    DIDDocument_Destroy(customized_doc);

    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey1);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey2);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey3);

    keyid = DIDURL_NewByDid(&controller2, "pk1");
    CU_ASSERT_PTR_NOT_NULL(keyid);

    //3:3
    const char *idrequest = DIDStore_SignDIDRequest(store, &customizedid, 3, signkey1, storepass, false);
    CU_ASSERT_PTR_NOT_NULL(idrequest);

    const char *idrequest1 = DIDStore_CounterSignDIDRequest(store, idrequest, keyid, storepass);
    CU_ASSERT_PTR_NULL(idrequest1);
    CU_ASSERT_STRING_EQUAL("The key is not valid key.", DIDError_GetMessage());
    DIDURL_Destroy(keyid);

    idrequest1 = DIDStore_CounterSignDIDRequest(store, idrequest, signkey2, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idrequest1);
    free((void*)idrequest);

    //check：the count of signer is less than multisig, publishing request failed.
    CU_ASSERT_FALSE_FATAL(DIDStore_PublishIdRequest(store, idrequest1));
    CU_ASSERT_STRING_EQUAL("The count of signer is less than mulitsig.", DIDError_GetMessage());

    idrequest = DIDStore_CounterSignDIDRequest(store, idrequest1, signkey3, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idrequest);
    free((void*)idrequest1);

    CU_ASSERT_TRUE_FATAL(DIDStore_PublishIdRequest(store, idrequest));
    free((void*)idrequest);

    //resolve
    DIDHistory *history = DID_ResolveHistory(&customizedid);
    CU_ASSERT_PTR_NOT_NULL(history);
    CU_ASSERT_EQUAL_FATAL(1, DIDHistory_GetTransactionCount(history));

    DIDTransactionInfo *info = DIDHistory_GetTransaction(history, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    DIDRequest *request = DIDTransactionInfo_GetRequest(info);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);

    rc = DIDRequest_GetMultisig(request, &multisig_m, &multisig_n);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_EQUAL(3, multisig_m);
    CU_ASSERT_EQUAL(3, multisig_n);

    CU_ASSERT_STRING_EQUAL("create", DIDRequest_GetOperation(request));
    CU_ASSERT_EQUAL_FATAL(3, DIDRequest_GetProofCount(request));

    //check the signkey of proof
    time_t created;
    char signature[128] = {0};
    DIDURL key;
    for (int i = 0; i < 3; i++) {
        rc = DIDRequest_GetProof(request, i, &key, &created, signature, sizeof(signature));
        CU_ASSERT_NOT_EQUAL(rc, -1);
        CU_ASSERT_TRUE_FATAL(DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller1_doc)) ||
                DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller2_doc)) ||
                DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller3_doc)));
    }

    rc = DIDStore_StoreDID(store, DIDRequest_GetDIDDocument(request));
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    DIDHistory_Destroy(history);

    customized_doc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    //update
    builder = DIDDocument_Edit(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(customized_doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid = DIDURL_NewByDid(&customizedid, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *credid = DIDURL_NewByDid(&customizedid, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "John";

    rc = DIDDocumentBuilder_AddSelfClaimedCredential(builder, credid, types, 2,
            props, 1, 0, signkey1, storepass);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    //remove controller
    rc = DIDDocumentBuilder_RemoveController(builder, &controller2);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    customized_doc = DIDDocumentBuilder_Seal(builder, &controller2, storepass);
    CU_ASSERT_PTR_NULL(customized_doc);
    CU_ASSERT_STRING_EQUAL("Does not a controller of the DIDDocument.", DIDError_GetMessage());

    customized_doc = DIDDocumentBuilder_Seal(builder, &controller3, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(customized_doc))
    CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, customized_doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    CU_ASSERT_PTR_NULL(DIDStore_SignDIDRequest(store, &customizedid, 0, signkey1, storepass, false));
    CU_ASSERT_STRING_EQUAL("The count of controller is different from the last document, \
                     so the default multisig is invalid. Please provide the new multisig.", DIDError_GetMessage());

    idrequest = DIDStore_SignDIDRequest(store, &customizedid, 1, signkey3, storepass, false);
    CU_ASSERT_PTR_NOT_NULL(idrequest);

    idrequest1 = DIDStore_CounterSignDIDRequest(store, idrequest, signkey1, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idrequest1);
    free((void*)idrequest);

    CU_ASSERT_FALSE_FATAL(DIDStore_PublishIdRequest(store, idrequest1));
    CU_ASSERT_STRING_EQUAL("The count of signer is less than mulitsig.", DIDError_GetMessage());

    idrequest = DIDStore_CounterSignDIDRequest(store, idrequest1, signkey2, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idrequest);
    free((void*)idrequest1);

    CU_ASSERT_TRUE_FATAL(DIDStore_PublishIdRequest(store, idrequest));
    free((void*)idrequest);
    DIDURL_Destroy(keyid);

    //resolve history again
    history = DID_ResolveHistory(&customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(history);
    CU_ASSERT_EQUAL_FATAL(2, DIDHistory_GetTransactionCount(history));

    info = DIDHistory_GetTransaction(history, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    request = DIDTransactionInfo_GetRequest(info);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);

    rc = DIDRequest_GetMultisig(request, &multisig_m, &multisig_n);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(3, multisig_m);
    CU_ASSERT_EQUAL(3, multisig_n);

    CU_ASSERT_STRING_EQUAL("create", DIDRequest_GetOperation(request));
    CU_ASSERT_EQUAL_FATAL(3, DIDRequest_GetProofCount(request));

    info = DIDHistory_GetTransaction(history, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    request = DIDTransactionInfo_GetRequest(info);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);

    rc = DIDRequest_GetMultisig(request, &multisig_m, &multisig_n);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(1, multisig_m);
    CU_ASSERT_EQUAL(2, multisig_n);

    CU_ASSERT_STRING_EQUAL("update", DIDRequest_GetOperation(request));
    CU_ASSERT_EQUAL_FATAL(3, DIDRequest_GetProofCount(request));

    rc = DIDRequest_GetProof(request, 0, &key, &created, signature, sizeof(signature));
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(&key, DIDDocument_GetDefaultPublicKey(controller3_doc)));

    resolve_doc = DIDRequest_GetDIDDocument(request);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    resolve_doc1 = DID_Resolve(&customizedid, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    Credential *cred = DIDDocument_GetCredential(resolve_doc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);
    DIDURL_Destroy(credid);

    const char *data1 = DIDDocument_ToJson(customized_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data1);
    const char *data2 = DIDDocument_ToJson(resolve_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data2);
    const char *data3 = DIDDocument_ToJson(resolve_doc1, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data3);
    CU_ASSERT_STRING_EQUAL(data1, data2);
    CU_ASSERT_STRING_EQUAL(data3, data2);

    free((void*)data1);
    free((void*)data2);
    free((void*)data3);
    DIDHistory_Destroy(history);
    DIDDocument_Destroy(resolve_doc1);
    DIDDocument_Destroy(customized_doc);
}

//add controller
static void test_publish_ctmdid_with_onecontroller_after_addcontroller(void)
{
    const char *customized_string = "bannie", *keybase;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolve_doc, *customized_doc, *resolve_doc1;
    DID customizedid;
    DIDURL *keyid, *signkey1, *signkey2, *signkey3;
    DIDDocumentBuilder *builder;
    int rc, multisig_m, multisig_n;

    DID *controllers[3] = {0};
    controllers[0] = &controller1;

    //create
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, NULL, controllers, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    DID_Copy(&customizedid, &customized_doc->did);
    DIDDocument_Destroy(customized_doc);

    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey1);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey2);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey3);

    //1:1
    const char *idrequest = DIDStore_SignDIDRequest(store, &customizedid, 0, NULL, storepass, false);
    CU_ASSERT_PTR_NOT_NULL(idrequest);
    CU_ASSERT_TRUE_FATAL(DIDStore_PublishIdRequest(store, idrequest));
    free((void*)idrequest);

    //resolve
    resolve_doc = DID_Resolve(&customizedid, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_doc);
    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDStore_StoreDID(store, resolve_doc));
    DIDDocument_Destroy(resolve_doc);

    customized_doc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    //update
    builder = DIDDocument_Edit(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(customized_doc);

    //remove controller
    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDDocumentBuilder_AddController(builder, &controller2));
    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDDocumentBuilder_AddController(builder, &controller3));

    customized_doc = DIDDocumentBuilder_Seal(builder, &controller3, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized_doc))
    CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(6, DIDDocument_GetAuthenticationCount(customized_doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, customized_doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    CU_ASSERT_PTR_NULL(DIDStore_SignDIDRequest(store, &customizedid, 0, signkey1, storepass, false));
    CU_ASSERT_STRING_EQUAL("The count of controller is different from the last document, \
                     so the default multisig is invalid. Please provide the new multisig.", DIDError_GetMessage());

    idrequest = DIDStore_SignDIDRequest(store, &customizedid, 2, signkey3, storepass, false);
    CU_ASSERT_PTR_NULL(idrequest);

    idrequest = DIDStore_SignDIDRequest(store, &customizedid, 2, signkey1, storepass, false);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idrequest);

    CU_ASSERT_TRUE_FATAL(DIDStore_PublishIdRequest(store, idrequest));
    free((void*)idrequest);

    //resolve history again
    DIDHistory *history = DID_ResolveHistory(&customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(history);
    CU_ASSERT_EQUAL_FATAL(2, DIDHistory_GetTransactionCount(history));

    DIDTransactionInfo *info = DIDHistory_GetTransaction(history, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    DIDRequest *request = DIDTransactionInfo_GetRequest(info);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);

    rc = DIDRequest_GetMultisig(request, &multisig_m, &multisig_n);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    CU_ASSERT_STRING_EQUAL("create", DIDRequest_GetOperation(request));
    CU_ASSERT_EQUAL_FATAL(1, DIDRequest_GetProofCount(request));

    info = DIDHistory_GetTransaction(history, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    request = DIDTransactionInfo_GetRequest(info);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);

    rc = DIDRequest_GetMultisig(request, &multisig_m, &multisig_n);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(2, multisig_m);
    CU_ASSERT_EQUAL(3, multisig_n);

    CU_ASSERT_STRING_EQUAL("update", DIDRequest_GetOperation(request));
    CU_ASSERT_EQUAL_FATAL(1, DIDRequest_GetProofCount(request));

    time_t created;
    char signature[128] = {0};
    DIDURL key;

    rc = DIDRequest_GetProof(request, 0, &key, &created, signature, sizeof(signature));
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(&key, signkey3) || DIDURL_Equals(&key, signkey1));

    resolve_doc = DIDRequest_GetDIDDocument(request);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    resolve_doc1 = DID_Resolve(&customizedid, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    const char *data1 = DIDDocument_ToJson(customized_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data1);
    const char *data2 = DIDDocument_ToJson(resolve_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data2);
    const char *data3 = DIDDocument_ToJson(resolve_doc1, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data3);
    CU_ASSERT_STRING_EQUAL(data1, data2);
    CU_ASSERT_STRING_EQUAL(data3, data2);

    free((void*)data1);
    free((void*)data2);
    free((void*)data3);
    DIDHistory_Destroy(history);
    DIDDocument_Destroy(resolve_doc1);
    DIDDocument_Destroy(customized_doc);
}

static void test_publish_ctmdid_merge_request(void)
{
    const char *customized_string = "linda";
    char publickeybase58[MAX_PUBLICKEY_BASE58], *keybase;
    DIDDocument *resolve_doc, *customized_doc, *resolve_doc1;
    DID customizedid;
    DIDURL *keyid, *signkey1, *signkey2, *signkey3;
    DIDDocumentBuilder *builder;
    int rc, multisig_m, multisig_n;
    bool successed;

    DID *controllers[3] = {0};
    controllers[0] = &controller1;
    controllers[1] = &controller2;
    controllers[2] = &controller3;

    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey1);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey2);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey3);

    //create
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, &controller3, controllers, 3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    DID_Copy(&customizedid, &customized_doc->did);

    //3:3
    const char *idrequest = DIDStore_SignDIDRequest(store, &customizedid, 3, signkey1, storepass, false);
    CU_ASSERT_PTR_NOT_NULL(idrequest);

    const char *idrequest1 = DIDStore_CounterSignDIDRequest(store, idrequest, signkey2, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idrequest1);

    const char *idrequest2 = DIDStore_CounterSignDIDRequest(store, idrequest, signkey3, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idrequest2);
    free((void*)idrequest);

    idrequest = DIDDtore_MergeMultisigDIDRequest(2, idrequest1, idrequest2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(idrequest);
    free((void*)idrequest1);
    free((void*)idrequest2);

    CU_ASSERT_TRUE(DIDStore_PublishIdRequest(store, idrequest));
    free((void*)idrequest);

    //resolve
    DIDHistory *history = DID_ResolveHistory(&customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(history);
    CU_ASSERT_EQUAL_FATAL(1, DIDHistory_GetTransactionCount(history));

    DIDTransactionInfo *info = DIDHistory_GetTransaction(history, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    DIDRequest *request = DIDTransactionInfo_GetRequest(info);
    CU_ASSERT_PTR_NOT_NULL_FATAL(request);

    rc = DIDRequest_GetMultisig(request, &multisig_m, &multisig_n);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(3, multisig_m);
    CU_ASSERT_EQUAL(3, multisig_n);

    CU_ASSERT_STRING_EQUAL("create", DIDRequest_GetOperation(request));
    CU_ASSERT_EQUAL_FATAL(3, DIDRequest_GetProofCount(request));

    info = DIDHistory_GetTransaction(history, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(info);

    time_t created;
    char signature[128] = {0};
    DIDURL key;

    for (int i = 0; i < 3; i++) {
        rc = DIDRequest_GetProof(request, i, &key, &created, signature, sizeof(signature));
        CU_ASSERT_NOT_EQUAL(rc, -1);
        CU_ASSERT_TRUE_FATAL(DIDURL_Equals(&key, signkey2) || DIDURL_Equals(&key, signkey1)
                || DIDURL_Equals(&key, signkey3));
    }

    resolve_doc = DIDRequest_GetDIDDocument(request);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    resolve_doc1 = DID_Resolve(&customizedid, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    const char *data1 = DIDDocument_ToJson(customized_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data1);
    const char *data2 = DIDDocument_ToJson(resolve_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data2);
    const char *data3 = DIDDocument_ToJson(resolve_doc1, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data3);
    CU_ASSERT_STRING_EQUAL(data1, data2);
    CU_ASSERT_STRING_EQUAL(data3, data2);

    free((void*)data1);
    free((void*)data2);
    free((void*)data3);
    DIDHistory_Destroy(history);
    DIDDocument_Destroy(resolve_doc1);
    DIDDocument_Destroy(customized_doc);
}

static int idchain_dummyadapter_forctmdid_test_suite_init(void)
{
    DIDDocument *doc;

    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    if (TestData_InitIdentity(store) < 0) {
        TestData_Free();
        return -1;
    }

    controller1_doc = TestData_LoadIssuerDoc();
    if (!controller1_doc) {
        TestData_Free();
        return -1;
    }
    DID_Copy(&controller1, &controller1_doc->did);

    controller2_doc = TestData_LoadControllerDoc();
    if (!controller2_doc) {
        TestData_Free();
        return -1;
    }
    DID_Copy(&controller2, &controller2_doc->did);

    controller3_doc = TestData_LoadDoc();
    if (!controller3_doc) {
        TestData_Free();
        return -1;
    }
    DID_Copy(&controller3, &controller3_doc->did);

    return 0;
}

static int idchain_dummyadapter_forctmdid_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_publish_ctmdid_withonecontroller",                           test_publish_ctmdid_withonecontroller                           },
    { "test_publish_ctmdid_with_multicontroller",                        test_publish_ctmdid_with_multicontroller                        },
    { "test_publish_ctmdid_with_multicontroller_after_removecontroller", test_publish_ctmdid_with_multicontroller_after_removecontroller },
    { "test_publish_ctmdid_with_onecontroller_after_addcontroller",      test_publish_ctmdid_with_onecontroller_after_addcontroller      },
    { "test_publish_ctmdid_merge_request",                               test_publish_ctmdid_merge_request                               },
    {  NULL,                                                          NULL                                                               }
};

static CU_SuiteInfo suite[] = {
    { "customized did dummyadapter test", idchain_dummyadapter_forctmdid_test_suite_init, idchain_dummyadapter_forctmdid_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                              NULL,                                            NULL,                                             NULL, NULL, NULL  }
};

CU_SuiteInfo* idchain_dummyadapter_forctmdid_test_suite_info(void)
{
    return suite;
}
