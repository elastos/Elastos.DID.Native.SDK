#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <CUnit/Basic.h>
#include <limits.h>

#include "constant.h"
#include "loader.h"
#include "ela_did.h"
#include "diddocument.h"
#include "didstore.h"

static const char *customizedid = "littlefish";

static void test_new_customizedid(void)
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

    customized_doc = DIDStore_NewCustomizedDID(store, storepass, customizedid, controllers, 1, NULL);
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

static int didstore_customized_did_test_suite_init(void)
{
    return 0;
}

static int didstore_customized_did_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    {  "test_new_customizedid",   test_new_customizedid },
    {  NULL,                     NULL                 }
};

static CU_SuiteInfo suite[] = {
    {"didstore customized did test", didstore_customized_did_test_suite_init, didstore_customized_did_test_suite_cleanup, NULL, NULL, cases },
    {NULL,                          NULL,                               NULL,                                  NULL, NULL, NULL  }
};

CU_SuiteInfo* didstore_customized_did_test_suite_info(void)
{
    return suite;
}
