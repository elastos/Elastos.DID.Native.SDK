#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <CUnit/Basic.h>
#include <limits.h>
#include <assert.h>

#include "constant.h"
#include "loader.h"
#include "ela_did.h"
#include "diddocument.h"
#include "didstore.h"
#include "crypto.h"
#include "HDkey.h"

static const char *customizedid = "littlefish";

static bool contains_did(DID **dids, size_t size, DID *did)
{
    int i;

    assert(dids);
    assert(size > 0);
    assert(did);

    for(i = 0; i < size; i++) {
        if(DID_Equals(dids[i], did))
            return true;
    }

    return false;
}

static void test_new_customizedid_with_onecontroller(void)
{
    DIDDocument *controller_doc, *customized_doc;
    RootIdentity *rootidentity;
    DID *controller, *subject;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);
    rootidentity = TestData_InitIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    controller_doc = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller_doc);

    controller = DIDDocument_GetSubject(controller_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller);
    CU_ASSERT_TRUE_FATAL(DIDDocument_PublishDID(controller_doc, NULL, true, storepass));

    DID *controllers[1] = {0};
    controllers[0] = controller;

    customized_doc = DIDDocument_NewCustomizedDID(controller_doc, customizedid, NULL, 0, 0, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    DIDDocument_Destroy(customized_doc);

    subject = DID_New(customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(subject);

    customized_doc = DIDStore_LoadDID(store, subject);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    DID_Destroy(subject);

    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    subject = DIDDocument_GetSubject(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(subject);
    CU_ASSERT_STRING_EQUAL(DID_GetMethodSpecificId(subject), customizedid);

    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_TRUE(DID_Equals(&(customized_doc->controllers.docs[0]->did), controller));

    DIDURL *creater = DIDDocument_GetProofCreater(customized_doc, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater);
    CU_ASSERT_TRUE(DIDURL_Equals(creater, DIDDocument_GetDefaultPublicKey(controller_doc)));

    DIDDocument_Destroy(customized_doc);
    DIDDocument_Destroy(controller_doc);
    TestData_Free();
}

static void test_new_customizedid_with_multicontrollers(void)
{
    RootIdentity *rootidentity;
    DIDDocument *controller1_doc, *controller2_doc, *customized_doc, *resolve_doc;
    DID *controller1, *controller2, *_controller, *subject;
    DIDURL *signkey1, *signkey2;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rootidentity = TestData_InitIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    controller1_doc = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);

    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);
    CU_ASSERT_TRUE_FATAL(DIDDocument_PublishDID(controller1_doc, NULL, true, storepass));

    controller2_doc = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);

    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);
    CU_ASSERT_TRUE_FATAL(DIDDocument_PublishDID(controller2_doc, NULL, true, storepass));

    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey1);

    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey2);

    DID *controllers[2] = {0};
    controllers[0] = controller1;
    controllers[1] = controller2;

    subject = DID_New(customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(subject);

    customized_doc = DIDDocument_NewCustomizedDID(controller1_doc, customizedid, controllers, 2, 1, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    CU_ASSERT_TRUE(DIDDocument_IsQualified(customized_doc));

    rc = DIDStore_StoreDID(store, customized_doc);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    DIDDocument_Destroy(customized_doc);

    customized_doc = DIDStore_LoadDID(store, subject);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    DID_Destroy(subject);

    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    subject = DIDDocument_GetSubject(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(subject);
    CU_ASSERT_STRING_EQUAL(DID_GetMethodSpecificId(subject), customizedid);

    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(customized_doc));

    memset(controllers, 0, 2 *sizeof(DID*));
    rc = DIDDocument_GetControllers(customized_doc, controllers, 2);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_TRUE(contains_did(controllers, 2, controller1));
    CU_ASSERT_TRUE(contains_did(controllers, 2, controller2));

    DIDDocument_Destroy(customized_doc);
    DIDDocument_Destroy(controller1_doc);
    DIDDocument_Destroy(controller2_doc);
    TestData_Free();
}

static void test_new_customizedid_with_multicontrollers2(void)
{
    RootIdentity *rootidentity;
    DIDDocument *controller1_doc, *controller2_doc, *customized_doc, *resolve_doc;
    DIDDocumentBuilder *builder;
    DID *controller1, *controller2;
    DIDURL *signkey1, *signkey2;
    const char *data;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rootidentity = TestData_InitIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    controller1_doc = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);

    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);
    CU_ASSERT_TRUE_FATAL(DIDDocument_PublishDID(controller1_doc, NULL, true, storepass));

    controller2_doc = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);

    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);
    CU_ASSERT_TRUE_FATAL(DIDDocument_PublishDID(controller2_doc, NULL, true, storepass));

    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey1);

    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey2);

    DID *controllers[2] = {0};
    controllers[0] = controller1;
    controllers[1] = controller2;

    customized_doc = DIDDocument_NewCustomizedDID(controller1_doc, customizedid, controllers, 2, 2, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);

    //counter sign
    data = DIDDocument_ToJson(customized_doc, true);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);
    customized_doc = DIDDocument_SignDIDDocument(controller2_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    DIDDocument_Destroy(customized_doc);
    DIDDocument_Destroy(controller1_doc);
    DIDDocument_Destroy(controller2_doc);
    TestData_Free();
}

//generate json file and check the function
static void test_new_customizedid_with_existcontrollers(void)
{
    DIDDocument *controller1_doc, *controller2_doc, *controller3_doc;
    DIDDocument *customized1_doc, *customized2_doc, *customized3_doc;
    DID *controller1, *controller2, *controller3, customized_did;
    DIDURL *signkey1, *signkey2, *signkey3;
    DIDURL *creater1, *creater2, *creater3;
    const char *data;
    DID *dids[3] = {0}, *controllers[3] = {0};
    char *path, _path[PATH_MAX];
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    strcpy(customized_did.idstring, customizedid);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);
    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey1);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey2);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);
    controller3 = DIDDocument_GetSubject(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey3);

    dids[0] = controller1;
    dids[1] = controller2;
    dids[2] = controller3;

    //1:3 ----------------------------------------------------------------------
    customized1_doc = DIDDocument_NewCustomizedDID(controller1_doc, customizedid, dids, 3, 1, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized1_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized1_doc));

    //Don't remove
    //printf("customized1_empty_doc:\n%s\n", DIDDocument_ToString(customized1_doc, true));

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized1_doc));

    rc = DIDDocument_GetControllers(customized1_doc, controllers, 3);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller1));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller2));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller3));

    CU_ASSERT_EQUAL(1, DIDDocument_GetMultisig(customized1_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customized1_doc));
    creater1 = DIDDocument_GetProofCreater(customized1_doc, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater1);
    CU_ASSERT_TRUE(DIDURL_Equals(creater1, signkey1));
    DIDDocument_Destroy(customized1_doc);
    DIDStore_DeleteDID(store, &customized_did);

    //2:3 ----------------------------------------------------------------------
    customized2_doc = DIDDocument_NewCustomizedDID(controller1_doc, customizedid, dids, 3, 2, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized2_doc);

    data = DIDDocument_ToJson(customized2_doc, true);
    DIDDocument_Destroy(customized2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data);

    customized2_doc = DIDDocument_SignDIDDocument(controller2_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized2_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized2_doc));

    //Don't remove
    //printf("customized2_empty_doc:\n%s\n", DIDDocument_ToString(customized2_doc, true));

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized2_doc));

    memset(controllers, 0, 3 *sizeof(DID*));
    rc = DIDDocument_GetControllers(customized2_doc, controllers, 3);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller1));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller2));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller3));

    CU_ASSERT_EQUAL(2, DIDDocument_GetMultisig(customized2_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetProofCount(customized2_doc));
    creater1 = DIDDocument_GetProofCreater(customized2_doc, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater1);
    creater2 = DIDDocument_GetProofCreater(customized2_doc, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater2);
    CU_ASSERT_TRUE(DIDURL_Equals(creater1, signkey1) || DIDURL_Equals(creater1, signkey2));
    CU_ASSERT_TRUE(DIDURL_Equals(creater2, signkey1) || DIDURL_Equals(creater2, signkey2));
    DIDDocument_Destroy(customized2_doc);
    DIDStore_DeleteDID(store, &customized_did);

    //3:3 ----------------------------------------------------------------------
    customized3_doc = DIDDocument_NewCustomizedDID(controller1_doc, customizedid, dids, 3, 3, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized3_doc);

    data = DIDDocument_ToJson(customized3_doc, true);
    DIDDocument_Destroy(customized3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data);

    customized3_doc = DIDDocument_SignDIDDocument(controller2_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized3_doc);

    data = DIDDocument_ToJson(customized3_doc, true);
    DIDDocument_Destroy(customized3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data);

    customized3_doc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized3_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized3_doc));

    //Don't remove
    //printf("customized3_empty_doc:\n%s\n", DIDDocument_ToString(customized3_doc, true));

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized3_doc));

    memset(controllers, 0, 3 *sizeof(DID*));
    rc = DIDDocument_GetControllers(customized3_doc, controllers, 3);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller1));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller2));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller3));

    CU_ASSERT_EQUAL(3, DIDDocument_GetMultisig(customized3_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetProofCount(customized3_doc));
    creater1 = DIDDocument_GetProofCreater(customized3_doc, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater1);
    creater2 = DIDDocument_GetProofCreater(customized3_doc, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater2);
    creater3 = DIDDocument_GetProofCreater(customized3_doc, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater3);
    CU_ASSERT_TRUE(DIDURL_Equals(creater1, signkey1) || DIDURL_Equals(creater1, signkey2) || DIDURL_Equals(creater1, signkey3));
    CU_ASSERT_TRUE(DIDURL_Equals(creater2, signkey1) || DIDURL_Equals(creater2, signkey2) || DIDURL_Equals(creater2, signkey3));
    CU_ASSERT_TRUE(DIDURL_Equals(creater3, signkey1) || DIDURL_Equals(creater3, signkey2) || DIDURL_Equals(creater3, signkey3));
    DIDDocument_Destroy(customized3_doc);

    TestData_Free();
}

static void test_new_customizedid_with_existcontrollers2(void)
{
    DIDDocument *controller1_doc, *controller2_doc, *controller3_doc;
    DIDDocument *customized1_doc, *customized2_doc, *customized3_doc;
    DID *controller1, *controller2, *controller3, customized_did;
    DIDURL *signkey1, *signkey2, *signkey3;
    DIDURL *creater1, *creater2, *creater3;
    DIDDocumentBuilder *builder;
    DID *dids[3] = {0}, *controllers[3] = {0}, controller;
    DIDURL *id1, *id2, *serviceid1, *serviceid2, *credid, *keyid;
    HDKey *hdkey, _hdkey;
    PublicKey *pk;
    char publickeybase58[PUBLICKEY_BASE58_BYTES], privatekeybase58[256];
    char publickeybase58_a[PUBLICKEY_BASE58_BYTES];
    char publickeybase58_b[PUBLICKEY_BASE58_BYTES];
    const char *keybase1, *keybase2, *keybase3, *data;
    time_t expires;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);
    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey1);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey2);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);
    controller3 = DIDDocument_GetSubject(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey3);

    dids[0] = controller1;
    dids[1] = controller2;
    dids[2] = controller3;

    //1:3 ----------------------------------------------------------------------
    customized1_doc = DIDDocument_NewCustomizedDID(controller1_doc, customizedid, dids, 3, 1, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized1_doc);
    DID_Copy(&customized_did, &customized1_doc->did);

    expires = DIDDocument_GetExpires(customized1_doc);

    builder = DIDDocument_Edit(customized1_doc, controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(customized1_doc);

    //add one public key
    id1 = DIDURL_NewByDid(&customized_did, "k1");
    CU_ASSERT_PTR_NOT_NULL(id1);
    hdkey = Generater_KeyPair(&_hdkey);
    CU_ASSERT_PTR_NOT_NULL(hdkey);
    keybase1 = HDKey_GetPublicKeyBase58(hdkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase1);

    //Don't remove
    //b58_encode(privatekeybase58, sizeof(privatekeybase58), HDKey_GetPrivateKey(hdkey), PRIVATEKEY_BYTES);
    //printf("k1 sk: %s\n", privatekeybase58);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id1, &customized_did, keybase1));

    //add one authentication key
    memset(&_hdkey, 0, sizeof(HDKey));
    id2 = DIDURL_NewByDid(&customized_did, "k2");
    CU_ASSERT_PTR_NOT_NULL(id2);
    hdkey = Generater_KeyPair(&_hdkey);
    CU_ASSERT_PTR_NOT_NULL(hdkey);
    keybase2 = HDKey_GetPublicKeyBase58(hdkey, publickeybase58_a, sizeof(publickeybase58_a));
    CU_ASSERT_PTR_NOT_NULL(keybase2);

    //Don't remove
    //b58_encode(privatekeybase58, sizeof(privatekeybase58), HDKey_GetPrivateKey(hdkey), PRIVATEKEY_BYTES);
    //printf("k2 sk: %s\n", privatekeybase58);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id2, keybase2));

    //add two services
    serviceid1 = DIDURL_NewByDid(&customized_did, "test-svc-1");
    CU_ASSERT_PTR_NOT_NULL(serviceid1);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, serviceid1, "Service.Testing",
            "https://www.elastos.org/testing1", NULL, 0));

    serviceid2 = DIDURL_NewByDid(&customized_did, "test-svc-2");
    CU_ASSERT_PTR_NOT_NULL(serviceid2);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, serviceid2, "Service.Testing",
            "https://www.elastos.org/testing2", NULL, 0));

    //add one credential
    credid = DIDURL_NewByDid(&customized_did, "vc-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfProclaimedCredential"};
    Property props[2];
    props[0].key = "nation";
    props[0].value = "Singapore";
    props[1].key = "passport";
    props[1].value = "S653258Z07";

    rc = DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid,
            types, 2, props, 2, expires, signkey1, storepass);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    customized1_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized1_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized1_doc));

    //Don't remove
    //printf("customized1_doc:\n%s\n", DIDDocument_ToString(customized1_doc, true));

    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetPublicKey(customized1_doc, id1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customized1_doc, id2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customized1_doc, credid));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetService(customized1_doc, serviceid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetService(customized1_doc, serviceid2));

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized1_doc));
    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDDocument_GetControllers(customized1_doc, controllers, 3));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller1));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller2));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller3));

    CU_ASSERT_EQUAL(1, DIDDocument_GetMultisig(customized1_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customized1_doc));
    creater1 = DIDDocument_GetProofCreater(customized1_doc, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater1);
    CU_ASSERT_TRUE(DIDURL_Equals(creater1, signkey2));
    DIDDocument_Destroy(customized1_doc);
    DIDStore_DeleteDID(store, &customized_did);

    //2:3 ----------------------------------------------------------------------
    customized2_doc = DIDDocument_NewCustomizedDID(controller1_doc, customizedid, dids, 3, 2, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized2_doc);

    expires = DIDDocument_GetExpires(customized2_doc);

    builder = DIDDocument_Edit(customized2_doc, controller2_doc);
    DIDDocument_Destroy(customized2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    //add two keys
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id1, &customized_did, keybase1));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id2, keybase2));

    //add two services
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, serviceid1, "Service.Testing",
            "https://www.elastos.org/testing1", NULL, 0));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, serviceid2, "Service.Testing",
            "https://www.elastos.org/testing2", NULL, 0));

    //add one credential
    rc = DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid,
            types, 2, props, 2, expires, signkey1, storepass);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    customized2_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized2_doc);
    CU_ASSERT_FALSE(DIDDocument_IsValid(customized2_doc));

    data = DIDDocument_ToJson(customized2_doc, true);
    DIDDocument_Destroy(customized2_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized2_doc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized2_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized2_doc));

    //Don't remove
    //printf("customized2_doc:\n%s\n", DIDDocument_ToString(customized2_doc, true));

    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetPublicKey(customized2_doc, id1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customized2_doc, id2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customized2_doc, credid));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetService(customized2_doc, serviceid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetService(customized2_doc, serviceid2));

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized2_doc));
    memset(controllers, 0, 3 * sizeof(DID*));
    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDDocument_GetControllers(customized2_doc, controllers, 3));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller1));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller2));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller3));

    CU_ASSERT_EQUAL(2, DIDDocument_GetMultisig(customized2_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetProofCount(customized2_doc));
    creater1 = DIDDocument_GetProofCreater(customized2_doc, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater1);
    creater2 = DIDDocument_GetProofCreater(customized2_doc, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater2);
    CU_ASSERT_TRUE(DIDURL_Equals(creater1, signkey2));
    CU_ASSERT_TRUE(DIDURL_Equals(creater1, signkey3) || DIDURL_Equals(creater1, signkey2));
    CU_ASSERT_TRUE(DIDURL_Equals(creater2, signkey3) || DIDURL_Equals(creater2, signkey2));
    DIDDocument_Destroy(customized2_doc);
    DIDStore_DeleteDID(store, &customized_did);

    //3:3 ----------------------------------------------------------------------
    customized3_doc = DIDDocument_NewCustomizedDID(controller1_doc, customizedid, dids, 3, 3, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized3_doc);

    expires = DIDDocument_GetExpires(customized3_doc);

    builder = DIDDocument_Edit(customized3_doc, controller2_doc);
    DIDDocument_Destroy(customized3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    //add two authentication keys
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id1, &customized_did, keybase1));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id2, keybase2));

    //add two services
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, serviceid1, "Service.Testing",
            "https://www.elastos.org/testing1", NULL, 0));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, serviceid2, "Service.Testing",
            "https://www.elastos.org/testing2", NULL, 0));

    //add one credential
    rc = DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid,
            types, 2, props, 2, expires, signkey3, storepass);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    customized3_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized3_doc);
    CU_ASSERT_FALSE(DIDDocument_IsValid(customized3_doc));

    data = DIDDocument_ToJson(customized3_doc, true);
    DIDDocument_Destroy(customized3_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized3_doc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized3_doc);

    data = DIDDocument_ToJson(customized3_doc, true);
    DIDDocument_Destroy(customized3_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized3_doc = DIDDocument_SignDIDDocument(controller1_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized3_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized3_doc));

    //Don't remove
    //printf("customized3_doc:\n%s\n", DIDDocument_ToString(customized3_doc, true));

    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetPublicKey(customized3_doc, id1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customized3_doc, id2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customized3_doc, credid));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetService(customized3_doc, serviceid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetService(customized3_doc, serviceid2));

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized3_doc));
    memset(controllers, 0, 3 * sizeof(DID*));
    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDDocument_GetControllers(customized3_doc, controllers, 3));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller1));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller2));
    CU_ASSERT_TRUE(contains_did(controllers, 3, controller3));

    CU_ASSERT_EQUAL(3, DIDDocument_GetMultisig(customized3_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetProofCount(customized3_doc));
    creater1 = DIDDocument_GetProofCreater(customized3_doc, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater1);
    creater2 = DIDDocument_GetProofCreater(customized3_doc, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater2);
    creater3 = DIDDocument_GetProofCreater(customized3_doc, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater3);
    CU_ASSERT_TRUE(DIDURL_Equals(creater1, signkey2));
    CU_ASSERT_TRUE(DIDURL_Equals(creater1, signkey1) || DIDURL_Equals(creater1, signkey2) || DIDURL_Equals(creater1, signkey3));
    CU_ASSERT_TRUE(DIDURL_Equals(creater2, signkey1) || DIDURL_Equals(creater2, signkey2) || DIDURL_Equals(creater2, signkey3));
    CU_ASSERT_TRUE(DIDURL_Equals(creater3, signkey1) || DIDURL_Equals(creater3, signkey2) || DIDURL_Equals(creater3, signkey3));
    DIDDocument_Destroy(customized3_doc);

    DIDURL_Destroy(credid);
    DIDURL_Destroy(id1);
    DIDURL_Destroy(id2);
    DIDURL_Destroy(serviceid1);
    DIDURL_Destroy(serviceid2);

    TestData_Free();
}

static int didstore_customized_did_test_suite_init(void)
{
    return 0;
}

static int didstore_customized_did_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    {  "test_new_customizedid_with_onecontroller",    test_new_customizedid_with_onecontroller     },
    {  "test_new_customizedid_with_multicontrollers", test_new_customizedid_with_multicontrollers  },
    {  "test_new_customizedid_with_multicontrollers2",test_new_customizedid_with_multicontrollers2 },
    {  "test_new_customizedid_with_existcontrollers", test_new_customizedid_with_existcontrollers  },
    {  "test_new_customizedid_with_existcontrollers2",test_new_customizedid_with_existcontrollers2 },
    {  NULL,                                          NULL                                         }
};

static CU_SuiteInfo suite[] = {
    {"didstore customized did test", didstore_customized_did_test_suite_init, didstore_customized_did_test_suite_cleanup, NULL, NULL, cases },
    {NULL,                          NULL,                               NULL,                                  NULL, NULL, NULL  }
};

CU_SuiteInfo* didstore_customized_did_test_suite_info(void)
{
    return suite;
}
