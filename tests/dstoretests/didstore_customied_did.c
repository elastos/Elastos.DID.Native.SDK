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

static const char *customiedid = "littlefish";

static void test_new_customiedid(void)
{
    DIDDocument *controller_doc, *customied_doc, *resolve_doc;
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

    rc = DIDStore_PublishDID(store, storepass, controller, NULL, true);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    customied_doc = DIDStore_NewCustomiedDID(store, storepass, customiedid, controller, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customied_doc);
    DIDDocument_Destroy(customied_doc);

    subject = DID_New(customiedid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(subject);
    CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, subject, NULL, true));

    customied_doc = DID_Resolve(subject, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customied_doc);

    rc = DIDStore_StoreDID(store, customied_doc);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    DIDDocument_Destroy(customied_doc);

    customied_doc = DIDStore_LoadDID(store, subject);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customied_doc);
    DID_Destroy(subject);

    CU_ASSERT_TRUE(DIDDocument_IsValid(customied_doc));

    subject = DIDDocument_GetSubject(customied_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(subject);
    CU_ASSERT_STRING_EQUAL(DID_GetMethodSpecificId(subject), customiedid);

    _controller = DIDDocument_GetController(customied_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(_controller);

    bEquals = DID_Equals(_controller, controller);
    CU_ASSERT_TRUE(bEquals);

    DIDURL *creater = DIDDocument_GetProofCreater(customied_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(creater);

    bEquals = DIDURL_Equals(creater, DIDDocument_GetDefaultPublicKey(controller_doc));
    CU_ASSERT_TRUE(bEquals);

    CU_ASSERT_EQUAL(DIDDocument_GetExpires(customied_doc), DIDDocument_GetExpires(controller_doc));

    //update
    rc = DIDStore_PublishDID(store, storepass, subject, NULL, false);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);

    resolve_doc = DID_Resolve(subject, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(resolve_doc);

    const char *data1 = DIDDocument_ToJson(customied_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data1);
    const char *data2 = DIDDocument_ToJson(resolve_doc, true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data2);
    CU_ASSERT_STRING_EQUAL(data1, data2);

    free((void*)data1);
    free((void*)data2);
    DIDDocument_Destroy(resolve_doc);
    DIDDocument_Destroy(customied_doc);
    DIDDocument_Destroy(controller_doc);
    TestData_Free();
}

static int didstore_customied_did_test_suite_init(void)
{
    return 0;
}

static int didstore_customied_did_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    {  "test_new_customiedid",   test_new_customiedid },
    {  NULL,                     NULL                 }
};

static CU_SuiteInfo suite[] = {
    {"didstore customied did test", didstore_customied_did_test_suite_init, didstore_customied_did_test_suite_cleanup, NULL, NULL, cases },
    {NULL,                          NULL,                               NULL,                                  NULL, NULL, NULL  }
};

CU_SuiteInfo* didstore_customied_did_test_suite_info(void)
{
    return suite;
}
