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

static const char *alias = "littlefish";
static const char *password = "passwd";

static int get_did(DID *did, void *context)
{
    DID *d = (DID*)context;

    if (!did)
        return 0;

    if (strlen(d->idstring) == 0)
        strcpy(d->idstring, did->idstring);

    return 0;
}

static char *get_tmp_file(char *path, const char *filename)
{
    assert(filename && *filename);

    return get_file_path(path, PATH_MAX, 7, "..", PATH_STEP, "etc", PATH_STEP,
           "tmp", PATH_STEP, filename);
}

static void test_didstore_export_import_did(void)
{
    DIDStore *store, *store2;
    char _path[PATH_MAX], _path2[PATH_MAX], command[512];
    char *path, *path2, *file;
    DID did;

    store = TestData_SetupTestStore(true, 2);
    CU_ASSERT_PTR_NOT_NULL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, 2));

    memset(&did, 0, sizeof(did));
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&did));

    file = get_tmp_file(_path, "didexport.json");
    CU_ASSERT_PTR_NOT_NULL(file);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ExportDID(store, password, &did, file, "1234"));

    //create new store
    path = get_store_path(_path2, "restore");
    CU_ASSERT_PTR_NOT_NULL(path);
    delete_file(path);

    store2 = DIDStore_Open(path);
    CU_ASSERT_PTR_NOT_NULL(store2);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ImportDID(store2, password, file, "1234"));
    delete_file(file);

    path = get_file_path(_path, PATH_MAX, 7, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, IDS_DIR, PATH_STEP, did.idstring);
    CU_ASSERT_TRUE_FATAL(dir_exist(path));

    path2 = get_file_path(_path2, PATH_MAX, 7, store2->root, PATH_STEP, DATA_DIR,
            PATH_STEP, IDS_DIR, PATH_STEP, did.idstring);
    CU_ASSERT_TRUE_FATAL(dir_exist(path));

    // to diff directory
    sprintf(command, "diff -r %s %s", path, path2);
    CU_ASSERT_EQUAL(system(command), 0);

    DIDStore_Close(store2);
    TestData_Free();
}

static void test_didstore_export_import_rootidentity(void)
{
    DIDStore *store, *store2;
    char _path[PATH_MAX], _path2[PATH_MAX], command[512];
    char *path, *path2, *file;
    const char *defaultidentity;

    store = TestData_SetupTestStore(true, 2);
    CU_ASSERT_PTR_NOT_NULL(store);

    defaultidentity = DIDStore_GetDefaultRootIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(defaultidentity);

    file = get_tmp_file(_path, "idexport.json");
    CU_ASSERT_PTR_NOT_NULL(file);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ExportRootIdentity(store, password, defaultidentity, file, "1234"));

    //create new store
    path = get_store_path(_path2, "restore");
    CU_ASSERT_PTR_NOT_NULL(path);
    delete_file(path);

    store2 = DIDStore_Open(path);
    CU_ASSERT_PTR_NOT_NULL(store2);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ImportRootIdentity(store2, password, file, "1234"));
    delete_file(file);

    path = get_file_path(_path, PATH_MAX, 7, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, ROOTS_DIR, PATH_STEP, defaultidentity);
    CU_ASSERT_TRUE_FATAL(dir_exist(path));

    path2 = get_file_path(_path2, PATH_MAX, 7, store2->root, PATH_STEP, DATA_DIR,
            PATH_STEP, ROOTS_DIR, PATH_STEP, defaultidentity);
    CU_ASSERT_TRUE_FATAL(dir_exist(path));

    // to diff directory
    sprintf(command, "diff -r %s %s", path, path2);
    CU_ASSERT_EQUAL(system(command), 0);

    free((void*)defaultidentity);
    DIDStore_Close(store2);
    TestData_Free();
}

static void test_didstore_export_import_store(void)
{
    DIDStore *store, *store2;
    char _path[PATH_MAX], _path2[PATH_MAX], command[512];
    char *path, *path2, *file;

    store = TestData_SetupTestStore(true, 2);
    CU_ASSERT_PTR_NOT_NULL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 2));

    file = get_tmp_file(_path, "storeexport.zip");
    CU_ASSERT_PTR_NOT_NULL(file);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ExportStore(store, password, file, "1234"));

    //create new store
    path = get_store_path(_path2, "restore");
    CU_ASSERT_PTR_NOT_NULL(path);
    delete_file(path);

    store2 = DIDStore_Open(path);
    CU_ASSERT_PTR_NOT_NULL(store2);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ImportStore(store2, password, file, "1234"));

    path = get_file_path(_path, PATH_MAX, 3, store->root, PATH_STEP, DATA_DIR);
    CU_ASSERT_TRUE_FATAL(dir_exist(path));

    path2 = get_file_path(_path2, PATH_MAX, 3, store2->root, PATH_STEP, DATA_DIR);
    CU_ASSERT_TRUE_FATAL(dir_exist(path));

    // to diff directory
    sprintf(command, "diff -r %s %s", path, path2);
    CU_ASSERT_EQUAL(system(command), 0);

    DIDStore_Close(store2);
    TestData_Free();
}

static int didstore_export_store_test_suite_init(void)
{
    return 0;
}

static int didstore_export_store_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    {  "test_didstore_export_import_did",              test_didstore_export_import_did              },
    {  "test_didstore_export_import_rootidentity",     test_didstore_export_import_rootidentity     },
    {  "test_didstore_export_import_store",            test_didstore_export_import_store            },
    {  NULL,                                           NULL                                         }
};

static CU_SuiteInfo suite[] = {
    {  "didstore export store test",  didstore_export_store_test_suite_init,  didstore_export_store_test_suite_cleanup,   NULL, NULL, cases },
    {  NULL,                          NULL,                                   NULL,                                  NULL, NULL, NULL  }
};

CU_SuiteInfo* didstore_export_store_test_suite_info(void)
{
    return suite;
}
