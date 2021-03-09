#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>
#include <crystal.h>

#include <CUnit/Basic.h>
#include "constant.h"
#include "loader.h"
#include "ela_did.h"
#include "did.h"

static DataParam params[] = {
    { 1, "issuer", NULL, NULL },      { 1, "user1", NULL, NULL },
    { 1, "user2", NULL, NULL },       { 1, "user3", NULL, NULL },
    { 2, "examplecorp", NULL, NULL }, { 2, "foobar", NULL, NULL },
    { 2, "foo", NULL, NULL },         { 2, "bar", NULL, NULL },
    { 2, "baz", NULL, NULL },         { 0, "document", NULL, NULL }
};

static void test_diddoc_json_operateion(void)
{
    DIDDocument *compactdoc, *normalizedoc, *doc;
    const char *data, *compactJson, *normalizedJson;
    int i;

    for (i = 0; i < 10; i++) {
        //compactdoc = DIDDocument_FromJson(TestData_GetDocumentJson("document", "compact", 0));
        compactJson = TestData_GetDocumentJson(params[i].did, "compact", params[i].version);
        CU_ASSERT_PTR_NOT_NULL(compactJson);
        compactdoc = DIDDocument_FromJson(compactJson);
        CU_ASSERT_PTR_NOT_NULL(compactdoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(compactdoc));

        normalizedJson = TestData_GetDocumentJson(params[i].did, "normalized", params[i].version);
        CU_ASSERT_PTR_NOT_NULL(compactJson);
        normalizedoc = DIDDocument_FromJson(normalizedJson);
        CU_ASSERT_PTR_NOT_NULL(normalizedoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(normalizedoc));

        doc = TestData_GetDocument(params[i].did, NULL, params[i].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(doc));

        data = DIDDocument_ToJson(compactdoc, true);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(normalizedJson, data);
        free((void*)data);
        data = DIDDocument_ToJson(normalizedoc, true);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(normalizedJson, data);
        free((void*)data);
        data = DIDDocument_ToJson(doc, true);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(normalizedJson, data);
        free((void*)data);
        data = DIDDocument_ToJson(compactdoc, false);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(compactJson, data);
        free((void*)data);
        data = DIDDocument_ToJson(normalizedoc, false);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(compactJson, data);
        free((void*)data);
        data = DIDDocument_ToJson(doc, false);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(compactJson, data);
        free((void*)data);
    }
}

static int diddoc_json_op_test_suite_init(void)
{
    DIDStore *store = TestData_SetupStore(true);
    if (!store)
        return -1;

    return 0;
}

static int diddoc_json_op_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_diddoc_json_operateion",   test_diddoc_json_operateion   },
    { NULL,                            NULL                          }
};

static CU_SuiteInfo suite[] = {
    { "diddoc json operation test",  diddoc_json_op_test_suite_init,  diddoc_json_op_test_suite_cleanup, NULL, NULL, cases },
    { NULL,                          NULL,                            NULL,                              NULL, NULL, NULL  }
};


CU_SuiteInfo* diddoc_json_op_test_suite_info(void)
{
    return suite;
}
