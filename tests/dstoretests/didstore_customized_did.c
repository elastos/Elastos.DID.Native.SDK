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
    DIDDocument *controller_doc, *customized_doc, *resolve_doc;
    DID *controller, *_controller, *subject;
    bool bEquals;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rc = TestData_InitIdentity(store);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    controller_doc = DIDStore_NewDID(store, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller_doc);

    controller = DIDDocument_GetSubject(controller_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller);
    CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, controller, NULL, true));

    DID *controllers[1] = {0};
    controllers[0] = controller;

    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customizedid, NULL, controllers, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    DIDDocument_Destroy(customized_doc);

    subject = DID_New(customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(subject);
    CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, subject, NULL, true));

    customized_doc = DID_Resolve(subject, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);

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

    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customized_doc));

    bEquals = DID_Equals(&(customized_doc->controllers.docs[0]->did), controller);
    CU_ASSERT_TRUE(bEquals);

    DIDURL *creater = DIDDocument_GetProofCreater(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater);

    bEquals = DIDURL_Equals(creater, DIDDocument_GetDefaultPublicKey(controller_doc));
    CU_ASSERT_TRUE(bEquals);

    CU_ASSERT_EQUAL(DIDDocument_GetExpires(customized_doc), DIDDocument_GetExpires(controller_doc));

    //update
    rc = DIDStore_PublishDID(store, storepass, subject, NULL, false);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    resolve_doc = DID_Resolve(subject, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    const char *data1 = DIDDocument_ToJson(customized_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data1);
    const char *data2 = DIDDocument_ToJson(resolve_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data2);
    CU_ASSERT_STRING_EQUAL(data1, data2);

    free((void*)data1);
    free((void*)data2);
    DIDDocument_Destroy(resolve_doc);
    DIDDocument_Destroy(customized_doc);
    DIDDocument_Destroy(controller_doc);
    TestData_Free();
}

static void test_new_customizedid_with_multicontrollers(void)
{
    DIDDocument *controller1_doc, *controller2_doc, *customized_doc, *resolve_doc;
    DID *controller1, *controller2, *_controller, *subject;
    bool bEquals;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rc = TestData_InitIdentity(store);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    controller1_doc = DIDStore_NewDID(store, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);

    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);
    CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, controller1, NULL, true));

    controller2_doc = DIDStore_NewDID(store, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);

    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);
    CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, controller2, NULL, true));

    DID *controllers[2] = {0};
    controllers[0] = controller1;
    controllers[1] = controller2;

    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customizedid, NULL, controllers, 2);
    CU_ASSERT_PTR_NULL(customized_doc);
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customizedid, controller1, controllers, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    DIDDocument_Destroy(customized_doc);

    subject = DID_New(customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(subject);
    //CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, subject, NULL, true));

    //customized_doc = DID_Resolve(subject, true);
    //CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);

    //rc = DIDStore_StoreDID(store, customized_doc);
    //CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    //DIDDocument_Destroy(customized_doc);

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

    DIDURL *creater = DIDDocument_GetProofCreater(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater);
    CU_ASSERT_TRUE(DIDURL_Equals(creater, DIDDocument_GetDefaultPublicKey(controller1_doc)));

    //update
    /*rc = DIDStore_PublishDID(store, storepass, subject, NULL, false);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    resolve_doc = DID_Resolve(subject, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    const char *data1 = DIDDocument_ToJson(customized_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data1);
    const char *data2 = DIDDocument_ToJson(resolve_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data2);
    CU_ASSERT_STRING_EQUAL(data1, data2);

    free((void*)data1);
    free((void*)data2);
    DIDDocument_Destroy(resolve_doc);*/
    DIDDocument_Destroy(customized_doc);
    DIDDocument_Destroy(controller1_doc);
    DIDDocument_Destroy(controller2_doc);
    TestData_Free();
}

static void test_new_customizedid_with_multicontrollers2(void)
{
    DIDDocument *controller1_doc, *controller2_doc, *customized_doc, *resolve_doc;
    DID *controller1, *controller2, *_controller, *subject;
    bool bEquals;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rc = TestData_InitIdentity(store);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    controller1_doc = DIDStore_NewDID(store, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);

    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);
    CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, controller1, NULL, true));

    controller2_doc = DIDStore_NewDID(store, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);

    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);
    CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, controller2, NULL, true));

    DID *controllers[2] = {0};
    controllers[0] = controller1;
    controllers[1] = controller2;

    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customizedid, NULL, controllers, 2);
    CU_ASSERT_PTR_NULL(customized_doc);
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customizedid, controller1, controllers, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    DIDDocument_Destroy(customized_doc);

    subject = DID_New(customizedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(subject);
    //CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, subject, NULL, true));

    //customized_doc = DID_Resolve(subject, true);
    //CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);

    //rc = DIDStore_StoreDID(store, customized_doc);
    //CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    //DIDDocument_Destroy(customized_doc);

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

    DIDURL *creater = DIDDocument_GetProofCreater(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater);
    CU_ASSERT_TRUE(DIDURL_Equals(creater, DIDDocument_GetDefaultPublicKey(controller1_doc)));

    //update
    /*rc = DIDStore_PublishDID(store, storepass, subject, NULL, false);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    resolve_doc = DID_Resolve(subject, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    const char *data1 = DIDDocument_ToJson(customized_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data1);
    const char *data2 = DIDDocument_ToJson(resolve_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data2);
    CU_ASSERT_STRING_EQUAL(data1, data2);

    free((void*)data1);
    free((void*)data2);
    DIDDocument_Destroy(resolve_doc);*/
    DIDDocument_Destroy(customized_doc);
    DIDDocument_Destroy(controller1_doc);
    DIDDocument_Destroy(controller2_doc);
    TestData_Free();
}

static void test_new_customizedid_with_existcontrollers(void)
{
    DIDDocument *controller1_doc, *controller2_doc, *customized_doc;
    DID *controller1, *controller2, *customized_did;
    DID *dids[2] = {0};
    char *path, _path[PATH_MAX];
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rc = TestData_InitIdentity(store);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    controller1_doc = TestData_LoadDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);

    controller2_doc = TestData_LoadControllerDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);

    dids[0] = controller1;
    dids[1] = controller2;

    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customizedid, NULL, dids, 2);
    CU_ASSERT_PTR_NULL(customized_doc);
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customizedid, controller1, dids, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    //Don't remove
    //printf("customized_empty_doc:\n%s\n", DIDDocument_ToString(customized_doc, false));

    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(customized_doc));

    memset(dids, 0, 2 *sizeof(DID*));
    rc = DIDDocument_GetControllers(customized_doc, dids, 2);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_TRUE(contains_did(dids, 2, controller1));
    CU_ASSERT_TRUE(contains_did(dids, 2, controller2));

    DIDURL *creater = DIDDocument_GetProofCreater(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater);
    CU_ASSERT_TRUE(DIDURL_Equals(creater, DIDDocument_GetDefaultPublicKey(controller1_doc)));

    TestData_Free();
}

static void test_new_customizedid_with_existcontrollers2(void)
{
    DIDDocument *controller1_doc, *controller2_doc, *customized_doc;
    DID *controller1, *controller2, customized_did;
    DID *dids[2] = {0};
    char publickeybase58[MAX_PUBLICKEY_BASE58], privatekeybase58[256];
    HDKey *hdkey, _hdkey;
    const char *keybase;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rc = TestData_InitIdentity(store);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    controller1_doc = TestData_LoadDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);

    controller2_doc = TestData_LoadControllerDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);

    dids[0] = controller1;
    dids[1] = controller2;

    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customizedid, NULL, dids, 2);
    CU_ASSERT_PTR_NULL(customized_doc);
    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customizedid, controller1, dids, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));

    DID_Copy(&customized_did, &customized_doc->did);

    DIDURL *creater = DIDDocument_GetProofCreater(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater);
    CU_ASSERT_TRUE(DIDURL_Equals(creater, DIDDocument_GetDefaultPublicKey(controller1_doc)));

    DIDDocumentBuilder *builder = DIDDocument_Edit(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(customized_doc);

    //add authentication key
    DIDURL *id1 = DIDURL_NewByDid(&customized_did, "k1");
    CU_ASSERT_PTR_NOT_NULL(id1);
    hdkey = Generater_KeyPair(&_hdkey);
    CU_ASSERT_PTR_NOT_NULL(hdkey);
    keybase = HDKey_GetPublicKeyBase58(hdkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);

    //Don't remove
    base58_encode(privatekeybase58, sizeof(privatekeybase58), HDKey_GetPrivateKey(hdkey), PRIVATEKEY_BYTES);
    //printf("k1 sk: %s\n", privatekeybase58);

    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, id1, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    memset(&_hdkey, 0, sizeof(HDKey));
    DIDURL *id2 = DIDURL_NewByDid(&customized_did, "k2");
    CU_ASSERT_PTR_NOT_NULL(id2);
    hdkey = Generater_KeyPair(&_hdkey);
    CU_ASSERT_PTR_NOT_NULL(hdkey);
    keybase = HDKey_GetPublicKeyBase58(hdkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);

    //Don't remove
    base58_encode(privatekeybase58, sizeof(privatekeybase58), HDKey_GetPrivateKey(hdkey), PRIVATEKEY_BYTES);
    //printf("k2 sk: %s\n", privatekeybase58);

    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, id2, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    customized_doc = DIDDocumentBuilder_Seal(builder, controller2, storepass);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(customized_doc));
    DIDDocumentBuilder_Destroy(builder);

    creater = DIDDocument_GetProofCreater(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater);
    CU_ASSERT_TRUE(DIDURL_Equals(creater, DIDDocument_GetDefaultPublicKey(controller2_doc)));

    //Don't remove
    //printf("customized_doc:\n%s\n", DIDDocument_ToString(customized_doc, false));

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
    {  "test_new_customizedid_with_onecontroller",    test_new_customizedid_with_onecontroller    },
    {  "test_new_customizedid_with_multicontrollers", test_new_customizedid_with_multicontrollers },
    {  "test_new_customizedid_with_multicontrollers2",test_new_customizedid_with_multicontrollers2 },
    {  "test_new_customizedid_with_existcontrollers", test_new_customizedid_with_existcontrollers },
    {  "test_new_customizedid_with_existcontrollers2",test_new_customizedid_with_existcontrollers2 },
    {  NULL,                                          NULL                                        }
};

static CU_SuiteInfo suite[] = {
    {"didstore customized did test", didstore_customized_did_test_suite_init, didstore_customized_did_test_suite_cleanup, NULL, NULL, cases },
    {NULL,                          NULL,                               NULL,                                  NULL, NULL, NULL  }
};

CU_SuiteInfo* didstore_customized_did_test_suite_info(void)
{
    return suite;
}
