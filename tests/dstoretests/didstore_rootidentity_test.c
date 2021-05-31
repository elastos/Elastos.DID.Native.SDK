#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <crystal.h>
#include <CUnit/Basic.h>
#include <limits.h>

#include "loader.h"
#include "constant.h"
#include "ela_did.h"
#include "didstore.h"
#include "rootidentity.h"

static int get_identity(RootIdentity *identity, void *context)
{
    int *count = (int*)context;

    if (!identity)
        return 0;

    (*count)++;
    return 0;
}

static void test_didstore_loadidentity_emptystore(void)
{
    DIDStore *store;
    const char *id;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    id = DIDStore_GetDefaultRootIdentity(store);
    CU_ASSERT_PTR_NULL(id);
    if (id)
        free((void*)id);

    TestData_Free();
}

static void test_didstore_fileexists(void)
{
    DIDStore *store;
    char _path[PATH_MAX], *path;
    const char *mnemonic;
    RootIdentity *rootidentity;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL(store);

    mnemonic = Mnemonic_Generate(language);
    CU_ASSERT_PTR_NOT_NULL(mnemonic);

    rootidentity = RootIdentity_Create(mnemonic, "1234", true, store, storepass);
    Mnemonic_Free((void*)mnemonic);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, ROOTS_DIR, PATH_STEP, rootidentity->id, PATH_STEP, INDEX_FILE);
    CU_ASSERT_TRUE(file_exist(path));

    path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, ROOTS_DIR, PATH_STEP, rootidentity->id, PATH_STEP, PRIVATE_FILE);
    CU_ASSERT_TRUE(file_exist(path));

    path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, ROOTS_DIR, PATH_STEP, rootidentity->id, PATH_STEP, MNEMONIC_FILE);
    CU_ASSERT_TRUE(file_exist(path));

    path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, ROOTS_DIR, PATH_STEP, rootidentity->id, PATH_STEP, PUBLIC_FILE);
    CU_ASSERT_TRUE(file_exist(path));

    RootIdentity_Destroy(rootidentity);

    TestData_Free();
}

static int delete_identity(RootIdentity *identity, void *context)
{
    int *count = (int*)context;
    DIDStore *store;

    if (!identity)
        return 0;

    (*count)++;

    store = IdentityMetadata_GetStore(&identity->metadata);
    return DIDStore_DeleteRootIdentity(store, identity->id);
}

static void test_didstore_listrootidentity(void)
{
    DIDStore *store;
    RootIdentity *rootidentity;
    const char *mnemonic;
    int i, count = 0;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL(store);

    for (i = 0; i < 50; i++) {
        mnemonic = Mnemonic_Generate(language);
        CU_ASSERT_PTR_NOT_NULL(mnemonic);

        rootidentity = RootIdentity_Create(mnemonic, "1234", true, store, storepass);
        Mnemonic_Free((void*)mnemonic);
        CU_ASSERT_PTR_NOT_NULL(rootidentity);
        RootIdentity_Destroy(rootidentity);
    }

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListRootIdentities(store, delete_identity, (void*)&count));
    CU_ASSERT_EQUAL(50, count);
    TestData_Free();
}

static void test_didstore_rootidentity(void)
{
    const char *mnemonic1, *mnemonic2;
    RootIdentity *rootidentity1, *rootidentity2, *rootidentity3, *rootidentity;
    const char *defaultid;
    DIDStore *store;
    char mnemonic[ELA_MAX_MNEMONIC_LEN + 1];
    int count = 0;

    const char *ExtendedkeyBase = "xprv9s21ZrQH143K4biiQbUq8369meTb1R8KnstYFAKtfwk3vF8uvFd1EC2s49bMQsbdbmdJxUWRkuC48CXPutFfynYFVGnoeq8LJZhfd9QjvUt";

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL(store);

    CU_ASSERT_FALSE(DIDStore_ContainsRootIdentities(store));

    mnemonic1 = Mnemonic_Generate(language);
    CU_ASSERT_PTR_NOT_NULL(mnemonic1);

    mnemonic2 = Mnemonic_Generate(language);
    CU_ASSERT_PTR_NOT_NULL(mnemonic2);

    rootidentity1 = RootIdentity_Create(mnemonic1, "1234", true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity1);
    CU_ASSERT_TRUE(DIDStore_ContainsRootIdentities(store));

    rootidentity2 = RootIdentity_Create(mnemonic2, "1234", true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity2);

    rootidentity3 = RootIdentity_CreateFromRootKey(ExtendedkeyBase, true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity2);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListRootIdentities(store, get_identity, (void*)&count));
    CU_ASSERT_EQUAL(3, count);

    //get default root identity
    defaultid = DIDStore_GetDefaultRootIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(defaultid);
    CU_ASSERT_STRING_EQUAL(rootidentity1->id, defaultid);
    free((void*)defaultid);

    CU_ASSERT_TRUE(DIDStore_ContainsRootIdentity(store, rootidentity1->id));
    CU_ASSERT_TRUE(DIDStore_ContainsRootIdentity(store, rootidentity2->id));
    CU_ASSERT_TRUE(DIDStore_ContainsRootIdentity(store, rootidentity3->id));

    CU_ASSERT_TRUE(DIDStore_ContainsRootIdentityMnemonic(store, rootidentity1->id));
    CU_ASSERT_TRUE(DIDStore_ContainsRootIdentityMnemonic(store, rootidentity2->id));
    CU_ASSERT_NOT_EQUAL(1, DIDStore_ContainsRootIdentityMnemonic(store, rootidentity3->id));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ExportRootIdentityMnemonic(store, storepass,
            rootidentity1->id, mnemonic, sizeof(mnemonic)));
    CU_ASSERT_STRING_EQUAL(mnemonic1, mnemonic);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ExportRootIdentityMnemonic(store, storepass,
            rootidentity2->id, mnemonic, sizeof(mnemonic)));
    CU_ASSERT_STRING_EQUAL(mnemonic2, mnemonic);

    //load rootidentity
    rootidentity = DIDStore_LoadRootIdentity(store, rootidentity1->id);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);
    CU_ASSERT_STRING_EQUAL(rootidentity->id, rootidentity1->id);
    RootIdentity_Destroy(rootidentity);

    rootidentity = DIDStore_LoadRootIdentity(store, rootidentity2->id);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);
    CU_ASSERT_STRING_EQUAL(rootidentity->id, rootidentity2->id);
    RootIdentity_Destroy(rootidentity);

    rootidentity = DIDStore_LoadRootIdentity(store, rootidentity3->id);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);
    CU_ASSERT_STRING_EQUAL(rootidentity->id, rootidentity3->id);
    RootIdentity_Destroy(rootidentity);

    //delete default rootidentity
    CU_ASSERT_TRUE(DIDStore_DeleteRootIdentity(store, rootidentity1->id));
    CU_ASSERT_PTR_NULL(DIDStore_GetDefaultRootIdentity(store));
    CU_ASSERT_STRING_EQUAL(
           "There is no default rootidentity, but one more rootidentities in didstore.Please specify one.", DIDError_GetLastErrorMessage());

    count = 0;
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListRootIdentities(store, get_identity, (void*)&count));
    CU_ASSERT_EQUAL(2, count);

    //set one not-existed root identity to default, failed.
    CU_ASSERT_EQUAL(-1, RootIdentity_SetAsDefault(rootidentity1));

    CU_ASSERT_NOT_EQUAL(-1, RootIdentity_SetAsDefault(rootidentity3));
    defaultid = DIDStore_GetDefaultRootIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(defaultid);
    CU_ASSERT_STRING_EQUAL(rootidentity3->id, defaultid);
    free((void*)defaultid);

    //delete root identity 2
    CU_ASSERT_TRUE(DIDStore_DeleteRootIdentity(store, rootidentity2->id));
    count = 0;
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListRootIdentities(store, get_identity, (void*)&count));
    CU_ASSERT_EQUAL(1, count);

    RootIdentity_Destroy(rootidentity1);
    RootIdentity_Destroy(rootidentity2);
    RootIdentity_Destroy(rootidentity3);

    Mnemonic_Free((void*)mnemonic1);
    Mnemonic_Free((void*)mnemonic2);
    TestData_Free();
}

static int didstore_rootidentity_test_suite_init(void)
{
    return 0;
}

static int didstore_rootidentity_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_didstore_loadidentity_emptystore",    test_didstore_loadidentity_emptystore },
    { "test_didstore_fileexists",                 test_didstore_fileexists              },
    { "test_didstore_listrootidentity",           test_didstore_listrootidentity        },
    { "test_didstore_rootidentity",               test_didstore_rootidentity            },
    { NULL,                                       NULL                            }
};

static CU_SuiteInfo suite[] = {
    { "didstore rootidentity test", didstore_rootidentity_test_suite_init, didstore_rootidentity_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                      NULL,                               NULL,                               NULL, NULL, NULL  }
};

CU_SuiteInfo* didstore_rootidentity_test_suite_info(void)
{
    return suite;
}
