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
#include "backend/didrequest.h"

#define MAX_PUBLICKEY_BASE58      64
#define MAX_DOC_SIGN              128

static DIDStore *store;
static DIDDocument *controller1_doc;
static DIDDocument *controller2_doc;
static DIDDocument *controller3_doc;
static DID controller1;  //doc
static DID controller2;  //controller doc
static DID controller3;  //issuer doc

static void test_publish_ctmdid_with_onecontroller(void)
{
    const char *customized_string = "whisper", *keybase;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolve_doc, *customized_doc;
    DID *controller, customizedid;
    DIDURL *keyid1, *keyid2, *credid;
    DIDDocumentBuilder *builder;
    HDKey _dkey, *dkey;
    const char *data;
    int status;

    DID *controllers[1] = {0};
    controllers[0] = &controller1;

    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, NULL, controllers, 1, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    DID_Copy(&customizedid, &customized_doc->did);

    CU_ASSERT_TRUE(DIDDocument_PublishDID(customized_doc, NULL, true, storepass));
    DIDDocument_Destroy(customized_doc);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(resolve_doc));
    CU_ASSERT_TRUE(DIDDocument_ContainsController(resolve_doc, &controller1));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolve_doc));
    DIDDocument_Destroy(resolve_doc);

    customized_doc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    //update
    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(customized_doc);

    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);

    keyid1 = DIDURL_NewByDid(&customizedid, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StorePrivateKey(store, storepass, &customizedid, keyid1,
            HDKey_GetPrivateKey(dkey), PRIVATEKEY_BYTES));

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid1, keybase));

    credid = DIDURL_NewByDid(&customizedid, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "whisper";

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid, types, 2,
            props, 1, 0, NULL, storepass));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(5, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    CU_ASSERT_TRUE(DIDDocument_PublishDID(customized_doc, keyid1, false, storepass));
    DIDDocument_Destroy(customized_doc);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_doc);

    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(resolve_doc, credid))
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid1));

    //update again
    builder = DIDDocument_Edit(resolve_doc, controller1_doc);
    DIDDocument_Destroy(resolve_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    memset(&_dkey, 0, sizeof(HDKey));
    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid2 = DIDURL_NewByDid(&customizedid, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StorePrivateKey(store, storepass, &customizedid, keyid2,
            HDKey_GetPrivateKey(dkey), PRIVATEKEY_BYTES));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid2, keybase));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    CU_ASSERT_TRUE(DIDDocument_PublishDID(customized_doc, keyid2, false, storepass));
    DIDDocument_Destroy(customized_doc);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_doc);
    CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(resolve_doc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(resolve_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(resolve_doc));

    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetPublicKey(resolve_doc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetPublicKey(resolve_doc, keyid2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(resolve_doc, credid));

    DIDURL_Destroy(keyid1);
    DIDURL_Destroy(keyid2);
    DIDURL_Destroy(credid);

    DIDDocument_Destroy(resolve_doc);
}

//create - resolve - edit document - update - resolve
static void test_publish_ctmdid_with_multicontroller(void)
{
    const char *customized_string = "cici", *keybase, *idrequest, *idrequest1;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolve_doc, *customized_doc;
    DID *controller, customizedid;
    DIDURL *keyid1, *keyid2, *credid, *signkey1, *signkey2, *signkey3;
    DIDDocumentBuilder *builder;
    HDKey _dkey, *dkey;
    const char *data;
    int status;

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
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, &controller2, controllers, 3, 0);
    CU_ASSERT_PTR_NULL(customized_doc);

    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, &controller2, controllers, 3, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_FALSE(DIDDocument_IsValid(customized_doc));
    DID_Copy(&customizedid, &customized_doc->did);

    data = DIDDocument_ToJson(customized_doc, true);
    CU_ASSERT_PTR_NOT_NULL(data);
    DIDDocument_Destroy(customized_doc);

    customized_doc = DIDDocument_SignDIDDocument(controller1_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));
    CU_ASSERT_TRUE(DIDDocument_PublishDID(customized_doc, signkey1, true, storepass));
    DIDDocument_Destroy(customized_doc);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(resolve_doc));
    CU_ASSERT_TRUE(DIDDocument_ContainsController(resolve_doc, &controller1));
    CU_ASSERT_TRUE(DIDDocument_ContainsController(resolve_doc, &controller2));
    CU_ASSERT_TRUE(DIDDocument_ContainsController(resolve_doc, &controller3));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolve_doc));
    DIDDocument_Destroy(resolve_doc);

    customized_doc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    //update
    builder = DIDDocument_Edit(customized_doc, controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(customized_doc);

    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);

    keyid1 = DIDURL_NewByDid(&customizedid, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StorePrivateKey(store, storepass, &customizedid, keyid1,
            HDKey_GetPrivateKey(dkey), PRIVATEKEY_BYTES));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid1, keybase));

    credid = DIDURL_NewByDid(&customizedid, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "cici";

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid, types, 2,
            props, 1, 0, signkey3, storepass));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    DIDDocumentBuilder_Destroy(builder);

    data = DIDDocument_ToJson(customized_doc, true);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized_doc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    //the count of signers is larger than multisig, fail.
    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    CU_ASSERT_PTR_NULL(DIDDocumentBuilder_Seal(builder, storepass));
    CU_ASSERT_STRING_EQUAL("The signers are enough.", DIDError_GetMessage());
    DIDDocumentBuilder_Destroy(builder);

    //must be sepcify the sign key
    CU_ASSERT_FALSE(DIDDocument_PublishDID(customized_doc, NULL, true, storepass));
    CU_ASSERT_STRING_EQUAL("Multi-controller customized DID must have sign key to publish.",
            DIDError_GetMessage());
    CU_ASSERT_TRUE(DIDDocument_PublishDID(customized_doc, signkey1, true, storepass));
    DIDDocument_Destroy(customized_doc);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_doc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolve_doc));

    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(resolve_doc, credid));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid1));
    DIDDocument_Destroy(resolve_doc);

    //update again
    customized_doc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);

    builder = DIDDocument_Edit(customized_doc, controller3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(customized_doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid2 = DIDURL_NewByDid(&customizedid, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid2, keybase));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);

    data = DIDDocument_ToJson(customized_doc, true);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized_doc = DIDDocument_SignDIDDocument(controller2_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    CU_ASSERT_EQUAL(10, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(8, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));

    CU_ASSERT_TRUE(DIDDocument_PublishDID(customized_doc, signkey3, false, storepass));
    DIDDocument_Destroy(customized_doc);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(resolve_doc, credid));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid2));

    DIDURL_Destroy(keyid1);
    DIDURL_Destroy(keyid2);
    DIDURL_Destroy(credid);

    DIDDocument_Destroy(resolve_doc);
}

static void test_transfer_ctmdid_with_onecontroller(void)
{
    const char *customized_string = "tristan", *keybase;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolve_doc, *customized_doc;
    DID *controller, customizedid;
    DIDURL *keyid1, *keyid2, *credid, *signkey1, *signkey2;
    DIDDocumentBuilder *builder;
    TransferTicket *ticket;
    HDKey _dkey, *dkey;
    const char *data;
    int status;

    DID *controllers[1] = {0};
    controllers[0] = &controller1;

    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey1);

    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey2);

    //create
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, NULL, controllers, 1, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    DID_Copy(&customizedid, &customized_doc->did);

    builder = DIDDocument_Edit(customized_doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(customized_doc);

    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);

    keyid1 = DIDURL_NewByDid(&customizedid, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StorePrivateKey(store, storepass, &customizedid, keyid1,
            HDKey_GetPrivateKey(dkey), PRIVATEKEY_BYTES));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid1, keybase));

    credid = DIDURL_NewByDid(&customizedid, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "tristan";

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid, types, 2,
            props, 1, 0, NULL, storepass));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(5, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    CU_ASSERT_TRUE(DIDDocument_PublishDID(customized_doc, keyid1, false, storepass));
    DIDDocument_Destroy(customized_doc);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(resolve_doc));
    CU_ASSERT_TRUE(DIDDocument_ContainsController(resolve_doc, &controller1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(resolve_doc, credid));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolve_doc));
    DIDDocument_Destroy(resolve_doc);

    customized_doc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    //update
    //Not set controller doc, fail.
    builder = DIDDocument_Edit(customized_doc, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, &controller2));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 1));
    CU_ASSERT_PTR_NULL(DIDDocumentBuilder_Seal(builder, storepass));
    CU_ASSERT_STRING_EQUAL("Please specify the controller to seal multi-controller DID Document.",
           DIDError_GetMessage());
    DIDDocumentBuilder_Destroy(builder);

    //Not set multisig for multi-controller DID, fail.
    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, &controller2));
    CU_ASSERT_PTR_NULL(DIDDocumentBuilder_Seal(builder, storepass));
    CU_ASSERT_STRING_EQUAL("Please set multisig first for multi-controller DID.",
           DIDError_GetMessage());
    DIDDocumentBuilder_Destroy(builder);

    //success
    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, &controller2));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 1));

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid2 = DIDURL_NewByDid(&customizedid, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid2, keybase));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);

    //check
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetMultisig(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customized_doc));
    CU_ASSERT_EQUAL(9, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(7, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    //create ticket
    ticket = DIDDocument_CreateTransferTicket(controller1_doc, &customizedid,
            &controller1, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_TRUE(TransferTicket_IsValid(ticket));

    CU_ASSERT_TRUE(DIDDocument_TransferDID(customized_doc, ticket, signkey1, storepass));
    DIDDocument_Destroy(customized_doc);
    TransferTicket_Destroy(ticket);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_doc);

    CU_ASSERT_TRUE(DIDDocument_IsValid(resolve_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(resolve_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetMultisig(resolve_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(resolve_doc));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(resolve_doc, credid));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolve_doc));

    //update again
    builder = DIDDocument_Edit(resolve_doc, controller2_doc);
    DIDDocument_Destroy(resolve_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller1));
    CU_ASSERT_STRING_EQUAL("There are self-proclaimed credentials signed by controller, please remove or renew these credentials at first.", DIDError_GetMessage());
    CU_ASSERT_NOT_EQUAL(-1,
            DIDDocumentBuilder_RenewSelfProclaimedCredential(builder, &controller1, signkey2, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller1));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, keyid1));

    //controller1 is removed, selfclaimed credential signed by controller1 is invalid.
    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);

    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetMultisig(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customized_doc));
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(customized_doc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customized_doc, keyid2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customized_doc, credid));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    ticket = DIDDocument_CreateTransferTicket(controller1_doc, &customizedid,
            &controller2, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    CU_ASSERT_TRUE(DIDDocument_TransferDID(customized_doc, ticket, signkey2, storepass));
    DIDDocument_Destroy(customized_doc);
    TransferTicket_Destroy(ticket);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_doc);

    CU_ASSERT_TRUE(DIDDocument_IsValid(resolve_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(resolve_doc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetMultisig(resolve_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(resolve_doc));
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(resolve_doc, credid));

    DIDURL_Destroy(keyid1);
    DIDURL_Destroy(keyid2);
    DIDURL_Destroy(credid);
    DIDDocument_Destroy(resolve_doc);
}

//add controller
static void test_transfer_ctmdid_with_multicontroller(void)
{
    const char *customized_string = "jack", *keybase, *idrequest, *idrequest1;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolve_doc, *customized_doc;
    DID *controller, customizedid;
    DIDURL *keyid1, *keyid2, *credid, *signkey1, *signkey2, *signkey3, *creater;
    DIDDocumentBuilder *builder;
    TransferTicket *ticket;
    Credential *cred;
    HDKey _dkey, *dkey;
    const char *data;
    size_t size;
    int i, status;

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

    //create -----------------------------------------
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, &controller2, controllers, 3, 0);
    CU_ASSERT_PTR_NULL(customized_doc);

    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customized_string, &controller2, controllers, 3, 2);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_FALSE(DIDDocument_IsValid(customized_doc));
    DID_Copy(&customizedid, &customized_doc->did);

    builder = DIDDocument_Edit(customized_doc, controller2_doc);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid1 = DIDURL_NewByDid(&customizedid, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid1, keybase));

    credid = DIDURL_NewByDid(&customizedid, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "jack";

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid, types, 2,
            props, 1, 0, signkey1, storepass));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);

    data = DIDDocument_ToJson(customized_doc, true);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized_doc = DIDDocument_SignDIDDocument(controller2_doc, data, storepass);
    CU_ASSERT_PTR_NULL(customized_doc);
    CU_ASSERT_STRING_EQUAL("The controller already signed the DID.",
           DIDError_GetMessage());

    customized_doc = DIDDocument_SignDIDDocument(controller1_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customized_doc, credid));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customized_doc, keyid1));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    CU_ASSERT_TRUE(DIDDocument_PublishDID(customized_doc, signkey1, true, storepass));
    DIDDocument_Destroy(customized_doc);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_doc);

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(resolve_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetMultisig(resolve_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetProofCount(resolve_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(resolve_doc));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(resolve_doc, credid));
    CU_ASSERT_TRUE(DIDDocument_ContainsController(resolve_doc, &controller1));
    CU_ASSERT_TRUE(DIDDocument_ContainsController(resolve_doc, &controller2));
    CU_ASSERT_TRUE(DIDDocument_ContainsController(resolve_doc, &controller3));

    size = DIDDocument_GetProofCount(resolve_doc);
    CU_ASSERT_EQUAL(2, size);

    for (i = 0; i < size; i++) {
        creater = DIDDocument_GetProofCreater(resolve_doc, i);
        CU_ASSERT_PTR_NOT_NULL(creater);
        CU_ASSERT_TRUE(DID_Equals(&creater->did, &controller1) || DID_Equals(&creater->did, &controller2));
    }

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolve_doc));
    DIDDocument_Destroy(resolve_doc);

    customized_doc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    //update ——-------------------------------------------------
    builder = DIDDocument_Edit(customized_doc, controller2_doc);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller1));
    CU_ASSERT_STRING_EQUAL("There are self-proclaimed credentials signed by controller, please remove or renew these credentials at first.", DIDError_GetMessage());
    CU_ASSERT_NOT_EQUAL(-1,
            DIDDocumentBuilder_RenewSelfProclaimedCredential(builder, &controller1, signkey2, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller1));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 2));

    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid2 = DIDURL_NewByDid(&customizedid, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StorePrivateKey(store, storepass, &customizedid, keyid2,
            HDKey_GetPrivateKey(dkey), PRIVATEKEY_BYTES));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid2, keybase));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    DIDDocumentBuilder_Destroy(builder);

    data = DIDDocument_ToJson(customized_doc, true);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    CU_ASSERT_PTR_NULL(DIDDocument_SignDIDDocument(controller1_doc, data, storepass));
    customized_doc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);

    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetMultisig(customized_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetProofCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));
    cred = DIDDocument_GetCredential(customized_doc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);
    CU_ASSERT_TRUE(DIDURL_Equals(signkey2, Credential_GetProofMethod(cred)));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    //publish DID after changing controller, fail.
    CU_ASSERT_FALSE(DIDDocument_PublishDID(customized_doc, signkey2, false, storepass));

    CU_ASSERT_STRING_EQUAL("Unsupport publishing DID which is changed controller, please transfer it.",
            DIDError_GetMessage());

    //the DID sign ticket is only one, fail.
    ticket = DIDDocument_CreateTransferTicket(controller1_doc, &customizedid,
            &controller2, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_FALSE(TransferTicket_IsValid(ticket));

    CU_ASSERT_FALSE(DIDDocument_TransferDID(customized_doc, ticket, signkey2, storepass));
    TransferTicket_Destroy(ticket);
    CU_ASSERT_STRING_EQUAL("Ticket is not qualified.", DIDError_GetMessage());

    //controller1 is removed, fail.
    ticket = DIDDocument_CreateTransferTicket(controller1_doc, &customizedid,
            &controller1, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignTransferTicket(controller3_doc, ticket, storepass));
    CU_ASSERT_TRUE(TransferTicket_IsValid(ticket));

    CU_ASSERT_FALSE(DIDDocument_TransferDID(customized_doc, ticket, signkey2, storepass));
    TransferTicket_Destroy(ticket);
    CU_ASSERT_STRING_EQUAL("The DID to receive ticket is not the document's signer.",
            DIDError_GetMessage());

    //success
    ticket = DIDDocument_CreateTransferTicket(controller1_doc, &customizedid,
            &controller2, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignTransferTicket(controller2_doc, ticket, storepass));
    CU_ASSERT_TRUE(TransferTicket_IsValid(ticket));

    CU_ASSERT_TRUE(DIDDocument_TransferDID(customized_doc, ticket, signkey2, storepass));
    DIDDocument_Destroy(customized_doc);
    TransferTicket_Destroy(ticket);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_doc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolve_doc));

    CU_ASSERT_TRUE(DIDDocument_IsValid(resolve_doc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(resolve_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(resolve_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetMultisig(resolve_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetProofCount(resolve_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(resolve_doc));
    cred = DIDDocument_GetCredential(resolve_doc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);
    CU_ASSERT_TRUE(DIDURL_Equals(signkey2, Credential_GetProofMethod(cred)));
    DIDDocument_Destroy(resolve_doc);

    //update again ------------------------------------------------------------
    customized_doc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);

    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(customized_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, &controller1));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller3));
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller2));
    CU_ASSERT_STRING_EQUAL("There are self-proclaimed credentials signed by controller, please remove or renew these credentials at first.", DIDError_GetMessage());
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveSelfProclaimedCredential(builder,
            &controller2));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller2));

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 2));
    CU_ASSERT_STRING_EQUAL("Unsupport multisig is larger than the count of controllers.",
            DIDError_GetMessage());

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, keyid1));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetMultisig(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customized_doc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetCredentialCount(customized_doc));
    CU_ASSERT_PTR_NULL(DIDDocument_GetCredential(customized_doc, credid));
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(customized_doc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customized_doc, keyid2));

    //create ticket
    ticket = DIDDocument_CreateTransferTicket(controller2_doc, &customizedid,
            &controller1, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_FALSE(TransferTicket_IsValid(ticket));

    CU_ASSERT_FALSE(DIDDocument_TransferDID(customized_doc, ticket, keyid2, storepass));
    CU_ASSERT_STRING_EQUAL("Ticket is not qualified.", DIDError_GetMessage());

    CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignTransferTicket(controller3_doc, ticket, storepass));
    CU_ASSERT_TRUE(TransferTicket_IsValid(ticket));
    CU_ASSERT_TRUE(DIDDocument_TransferDID(customized_doc, ticket, keyid2, storepass));
    DIDDocument_Destroy(customized_doc);
    TransferTicket_Destroy(ticket);

    resolve_doc = DID_Resolve(&customizedid, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_doc);

    CU_ASSERT_TRUE(DIDDocument_IsValid(resolve_doc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetAuthenticationCount(resolve_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(resolve_doc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetMultisig(resolve_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(resolve_doc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetCredentialCount(resolve_doc));
    CU_ASSERT_PTR_NULL(DIDDocument_GetCredential(resolve_doc, credid));
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(resolve_doc, keyid2));

    DIDURL_Destroy(keyid1);
    DIDURL_Destroy(keyid2);
    DIDURL_Destroy(credid);

    DIDDocument_Destroy(resolve_doc);
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

    controller1_doc = TestData_LoadDoc();
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

    controller3_doc = TestData_LoadIssuerDoc();
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
    { "test_publish_ctmdid_with_onecontroller",        test_publish_ctmdid_with_onecontroller        },
    { "test_publish_ctmdid_with_multicontroller",      test_publish_ctmdid_with_multicontroller      },
    { "test_transfer_ctmdid_with_onecontroller",       test_transfer_ctmdid_with_onecontroller       },
    { "test_transfer_ctmdid_with_multicontroller",     test_transfer_ctmdid_with_multicontroller     },
    {  NULL,                                           NULL                                          }
};

static CU_SuiteInfo suite[] = {
    { "customized did dummyadapter test", idchain_dummyadapter_forctmdid_test_suite_init, idchain_dummyadapter_forctmdid_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                              NULL,                                            NULL,                                             NULL, NULL, NULL  }
};

CU_SuiteInfo* idchain_dummyadapter_forctmdid_test_suite_info(void)
{
    return suite;
}
