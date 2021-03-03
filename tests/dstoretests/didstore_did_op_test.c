#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <CUnit/Basic.h>
#include <limits.h>

#include "constant.h"
#include "utility.h"
#include "loader.h"
#include "ela_did.h"
#include "did.h"
#include "didmeta.h"
#include "didstore.h"

static int get_did(DID *did, void *context)
{
    int *count = (int*)context;

    if (!did)
        return 0;

    (*count)++;
    return 0;
}

static void test_didstore_bulk_newdid(void)
{
    RootIdentity *rootidentity;
    char alias[ELA_MAX_ALIAS_LEN], _path[PATH_MAX];
    const char *gAlias;
    DIDStore *store;
    int rc, i, count = 0;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rootidentity = TestData_InitIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    for (i = 0; i < 100; i++) {
        int size = snprintf(alias, sizeof(alias), "my did %d", i);
        if (size < 0 || size > sizeof(alias))
            continue;

        DIDDocument *doc = RootIdentity_NewDID(rootidentity, storepass, alias);
        if (!doc)
            continue;
        CU_ASSERT_TRUE(DIDDocument_IsValid(doc));

        DID *did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        const char *path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP,
                DATA_DIR, PATH_STEP,IDS_DIR, PATH_STEP, did->idstring, PATH_STEP, DOCUMENT_FILE);
        CU_ASSERT_TRUE(file_exist(path));

        path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
                PATH_STEP, IDS_DIR, PATH_STEP, did->idstring, PATH_STEP, META_FILE);
        CU_ASSERT_TRUE(file_exist(path));

        DIDDocument *loaddoc = DIDStore_LoadDID(store, did);
        CU_ASSERT_PTR_NOT_NULL(loaddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(loaddoc));

        DIDMetadata *metadata = DIDDocument_GetMetadata(loaddoc);
        CU_ASSERT_PTR_NOT_NULL(loaddoc);
        gAlias = DIDMetadata_GetAlias(metadata);
        CU_ASSERT_PTR_NOT_NULL(gAlias);
        CU_ASSERT_STRING_EQUAL(alias, gAlias);
        CU_ASSERT_STRING_EQUAL(DIDDocument_GetProofSignature(doc, 0),
                DIDDocument_GetProofSignature(loaddoc, 0));

        CU_ASSERT_TRUE(DID_Equals(did, DIDDocument_GetSubject(loaddoc)));

        DIDDocument_Destroy(doc);
        DIDDocument_Destroy(loaddoc);
    }

    rc = DIDStore_ListDIDs(store, 0, get_did, (void*)&count);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(count, 100);

    count = 0;
    rc = DIDStore_ListDIDs(store, 1, get_did, (void*)&count);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(count, 100);

    count = 0;
    rc = DIDStore_ListDIDs(store, 2, get_did, (void*)&count);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(count, 0);

    TestData_Free();
}

static void test_didstore_op_deletedid(void)
{
    RootIdentity *rootidentity;
    DID dids[100];
    char alias[ELA_MAX_ALIAS_LEN], _path[PATH_MAX];
    DIDStore *store;
    int rc, i, count = 0;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rootidentity = TestData_InitIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    for(i = 0; i < 100; i++) {
        int size = snprintf(alias, sizeof(alias), "my did %d", i);
        if (size < 0 || size > sizeof(alias))
            continue;

        DIDDocument *doc = RootIdentity_NewDID(rootidentity, storepass, alias);
        CU_ASSERT_PTR_NOT_NULL(doc);

        DID *did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        DID_Copy(&dids[i], did);
        DIDDocument_Destroy(doc);
    }

    for (i = 0; i < 100; i++) {
        if (i % 5 != 0)
            continue;

        CU_ASSERT_TRUE(DIDStore_DeleteDID(store, &dids[i]));

        const char *path = get_file_path(_path, PATH_MAX, 7, store->root, PATH_STEP,
                DATA_DIR, PATH_STEP, IDS_DIR, PATH_STEP, dids[i].idstring);
        CU_ASSERT_FALSE_FATAL(file_exist(path));
    }

    rc = DIDStore_ListDIDs(store, 0, get_did, (void*)&count);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_EQUAL(count, 80);

    count = 0;
    rc = DIDStore_ListDIDs(store, 1, get_did, (void*)&count);

    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_EQUAL(count, 80);

    count = 0;
    rc = DIDStore_ListDIDs(store, 2, get_did, (void*)&count);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_EQUAL(count, 0);

    TestData_Free();
}

static void test_didstore_op_store_load_did(void)
{
    DIDDocument *issuerdoc, *doc, *loaddoc;
    DIDStore *store;
    int rc, count = 0;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    issuerdoc = TestData_GetDocument("issuer", NULL, 0);
    doc = TestData_GetDocument("document", NULL, 0);

    loaddoc = DIDStore_LoadDID(store, DIDDocument_GetSubject(issuerdoc));
    CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(issuerdoc), DIDDocument_GetSubject(loaddoc)));
    CU_ASSERT_STRING_EQUAL(DIDDocument_GetProofSignature(issuerdoc, 0), DIDDocument_GetProofSignature(loaddoc, 0));
    CU_ASSERT_TRUE(DIDDocument_IsValid(loaddoc));
    DIDDocument_Destroy(loaddoc);

    loaddoc = DIDStore_LoadDID(store, DIDDocument_GetSubject(doc));
    CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), DIDDocument_GetSubject(loaddoc)));
    CU_ASSERT_STRING_EQUAL(DIDDocument_GetProofSignature(doc, 0), DIDDocument_GetProofSignature(loaddoc, 0));
    CU_ASSERT_TRUE(DIDDocument_IsValid(loaddoc));
    DIDDocument_Destroy(loaddoc);

    rc = DIDStore_ListDIDs(store, 0, get_did, (void*)&count);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_EQUAL(count, 2);

    count = 0;
    rc = DIDStore_ListDIDs(store, 1, get_did, (void*)&count);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_EQUAL(count, 2);

    count = 0;
    rc = DIDStore_ListDIDs(store, 2, get_did, (void*)&count);
    CU_ASSERT_NOT_EQUAL_FATAL(rc, -1);
    CU_ASSERT_EQUAL(count, 0);

    TestData_Free();
}

static int didstore_did_op_test_suite_init(void)
{
    return 0;
}

static int didstore_did_op_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    {  "test_didstore_bulk_newdid",       test_didstore_bulk_newdid          },
    {  "test_didstore_op_deletedid",      test_didstore_op_deletedid         },
    {  "test_didstore_op_store_load_did", test_didstore_op_store_load_did    },
    {  NULL,                              NULL                               }
};

static CU_SuiteInfo suite[] = {
    { "didstore did operation test", didstore_did_op_test_suite_init, didstore_did_op_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                        NULL,                                 NULL,                                    NULL, NULL, NULL  }
};

CU_SuiteInfo* didstore_did_op_test_suite_info(void)
{
    return suite;
}