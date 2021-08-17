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

static const char *alias = "littlefish";

static int get_did(DID *did, void *context)
{
    int *count = (int*)context;

    if (!did)
        return 0;

    (*count)++;
    return 0;
}

static void test_didstore_change_password(void)
{
    char alias[ELA_MAX_ALIAS_LEN], _path[PATH_MAX];
    const char *gAlias;
    DIDStore *store;
    RootIdentity *rootidentity;
    int i, count = 0;
    DIDDocument *newdoc;
    int status;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rootidentity = TestData_InitIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    for (i = 0; i < 10; i++) {
        int size = snprintf(alias, sizeof(alias), "my did %d", i);
        if (size < 0 || size > sizeof(alias))
            continue;

        DIDDocument *doc = RootIdentity_NewDID(rootidentity, storepass, alias, false);
        if (!doc)
            continue;

        DID *did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        char *path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP,
                DATA_DIR, PATH_STEP, IDS_DIR, PATH_STEP, did->idstring, PATH_STEP, DOCUMENT_FILE);
        CU_ASSERT_TRUE(file_exist(path));

        path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
                PATH_STEP, IDS_DIR, PATH_STEP, did->idstring, PATH_STEP, META_FILE);
        CU_ASSERT_TRUE(file_exist(path));

        CU_ASSERT_TRUE_FATAL(DIDDocument_PublishDID(doc, NULL, false, storepass));
        DIDDocument *loaddoc = DID_Resolve(did, &status, true);
        CU_ASSERT_PTR_NOT_NULL(loaddoc);
        CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDStore_StoreDID(store, loaddoc));
        DIDDocument_Destroy(loaddoc);

        loaddoc = DIDStore_LoadDID(store, did);
        CU_ASSERT_PTR_NOT_NULL(loaddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(loaddoc));

        DIDMetadata *metadata = DIDDocument_GetMetadata(loaddoc);
        CU_ASSERT_PTR_NOT_NULL(metadata);
        gAlias = DIDMetadata_GetAlias(metadata);
        CU_ASSERT_PTR_NOT_NULL(gAlias);

        CU_ASSERT_STRING_EQUAL(alias, gAlias);
        CU_ASSERT_STRING_EQUAL(DIDDocument_GetProofSignature(doc, 0),
                DIDDocument_GetProofSignature(loaddoc, 0));

        CU_ASSERT_TRUE(DID_Equals(did, DIDDocument_GetSubject(loaddoc)));

        DIDDocument_Destroy(doc);
        DIDDocument_Destroy(loaddoc);
    }

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&count));
    CU_ASSERT_EQUAL(count, 10);

    count = 0;
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 1, get_did, (void*)&count));
    CU_ASSERT_EQUAL(count, 10);

    count = 0;
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 2, get_did, (void*)&count));
    CU_ASSERT_EQUAL(count, 0);

    //change password
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ChangePassword(store, "newpasswd", storepass));

    count = 0;
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&count));
    CU_ASSERT_EQUAL(count, 10);

    count = 0;
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 1, get_did, (void*)&count));
    CU_ASSERT_EQUAL(count, 10);

    count = 0;
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 2, get_did, (void*)&count));
    CU_ASSERT_EQUAL(count, 0);

    newdoc = RootIdentity_NewDID(rootidentity, "newpasswd", "new", false);
    CU_ASSERT_PTR_NOT_NULL(newdoc);
    DIDDocument_Destroy(newdoc);

    TestData_Free();
}

static void test_didstore_change_with_wrongpassword(void)
{
    char alias[ELA_MAX_ALIAS_LEN], _path[PATH_MAX];
    RootIdentity *rootidentity;
    const char *gAlias;
    DIDStore *store;
    int rc, i, count = 0;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rootidentity = TestData_InitIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    for (i = 0; i < 10; i++) {
        int size = snprintf(alias, sizeof(alias), "my did %d", i);
        if (size < 0 || size > sizeof(alias))
            continue;

        DIDDocument *doc = RootIdentity_NewDID(rootidentity, storepass, alias, false);
        if (!doc)
            continue;
        CU_ASSERT_TRUE(DIDDocument_IsValid(doc));

        DID *did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        char *path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP,
                DATA_DIR, PATH_STEP,IDS_DIR, PATH_STEP, did->idstring, PATH_STEP, DOCUMENT_FILE);
        CU_ASSERT_TRUE(file_exist(path));

        path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
                PATH_STEP, IDS_DIR, PATH_STEP, did->idstring, PATH_STEP, META_FILE);
        CU_ASSERT_TRUE(file_exist(path));

        DIDDocument *loaddoc = DIDStore_LoadDID(store, did);
        CU_ASSERT_PTR_NOT_NULL(loaddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(loaddoc));

        DIDMetadata *metadata = DIDDocument_GetMetadata(loaddoc);
        CU_ASSERT_PTR_NOT_NULL(metadata);
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
    CU_ASSERT_EQUAL(count, 10);

    count = 0;
    rc = DIDStore_ListDIDs(store, 1, get_did, (void*)&count);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(count, 10);

    count = 0;
    rc = DIDStore_ListDIDs(store, 2, get_did, (void*)&count);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(count, 0);

    //change password
    rc = DIDStore_ChangePassword(store, "newpasswd", "wrongpasswd");
    CU_ASSERT_EQUAL(rc, -1);

    TestData_Free();
}


static int didstore_change_password_test_suite_init(void)
{
    return 0;
}

static int didstore_change_password_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    {  "test_didstore_change_password",            test_didstore_change_password               },
    {  "test_didstore_change_with_wrongpassword",  test_didstore_change_with_wrongpassword     },
    {  NULL,                                       NULL                                        }
};

static CU_SuiteInfo suite[] = {
    {  "didstore change password test",  didstore_change_password_test_suite_init,  didstore_change_password_test_suite_cleanup,   NULL, NULL, cases },
    {  NULL,                     NULL,                              NULL,                                  NULL, NULL, NULL  }
};

CU_SuiteInfo* didstore_change_password_test_suite_info(void)
{
    return suite;
}
