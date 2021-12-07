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
#include "rootidentity.h"

static const char *alias = "littlefish";
static const char *password = "passwd";

static const char *user1Did = "iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y";
static const char *user2Did = "idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g";
static const char *user3Did = "igXiyCJEUjGJV1DMsMa4EbWunQqVg97GcS";
static const char *user4Did = "igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d";
static const char *issuerDid = "imUUPBfrZ1yZx6nWXe6LNN59VeX2E6PPKj";
static const char *exampleDid = "example";
static const char *fooDid = "foo";
static const char *foobarDid = "foobar";
static const char *barDid = "bar";
static const char *bazDid = "baz";

typedef struct List_Helper {
    DIDStore *store;
    int count;
} List_Helper;

static int get_did(DID *did, void *context)
{
    DID *d = (DID*)context;

    if (!did)
        return 0;

    if (DID_IsEmpty(d))
        DID_Copy(d, did);

    return 0;
}

static int get_rootidentity(RootIdentity *rootidentity, void *context)
{
    int *count = (int*)context;

    if (!rootidentity)
        return 0;

    if (strcmp("d2f3c0f07eda4e5130cbdc59962426b1", rootidentity->id) || rootidentity->index != 5)
        return -1;

    (*count)++;
    return 0;
}

static int get_dids(DID *did, void *context)
{
    int *count = (int*)context;

    if (!did)
        return 0;

    if (!strcmp(user1Did, did->idstring) || !strcmp(user2Did, did->idstring) ||
            !strcmp(user3Did, did->idstring) || !strcmp(user4Did, did->idstring) ||
            !strcmp(issuerDid, did->idstring) || !strcmp(exampleDid, did->idstring) ||
            !strcmp(fooDid, did->idstring) || !strcmp(foobarDid, did->idstring) ||
            !strcmp(barDid, did->idstring) || !strcmp(bazDid, did->idstring)) {
        (*count)++;
        return 0;
    }

    return -1;
}

static int get_user1vcs(DIDURL *id, void *context)
{
    List_Helper *helper = (List_Helper*)context;

    if (!id)
        return 0;

    DIDStore *store = helper->store;

    if (!strcmp("email", id->fragment) || !strcmp("json", id->fragment) ||
            !strcmp("passport", id->fragment) || !strcmp("profile", id->fragment) ||
            !strcmp("twitter", id->fragment)) {
        Credential *vc = DIDStore_LoadCredential(store, &id->did, id);
        if (vc) {
            helper->count++;
            Credential_Destroy(vc);
            return 0;
        }
    }

    return -1;
}

static int get_user2vcs(DIDURL *id, void *context)
{
    List_Helper *helper = (List_Helper*)context;

    if (!id)
        return 0;

    if (strcmp("profile", id->fragment))
        return -1;

    Credential *vc = DIDStore_LoadCredential(helper->store, &id->did, id);
    if (!vc)
        return -1;

    helper->count++;
    Credential_Destroy(vc);
    return 0;
}

static int get_user3vcs(DIDURL *id, void *context)
{
    List_Helper *helper = (List_Helper*)context;

    if (!id)
        return 0;

    if (strcmp("email", id->fragment))
        return -1;

    Credential *vc = DIDStore_LoadCredential(helper->store, &id->did, id);
    if (!vc)
        return -1;

    helper->count++;
    Credential_Destroy(vc);
    return 0;
}

static int get_user4vcs(DIDURL *id, void *context)
{
    List_Helper *helper = (List_Helper*)context;

    if (!id)
        return 0;

    DIDStore *store = helper->store;

    if (!strcmp("email", id->fragment) || !strcmp("license", id->fragment) ||
            !strcmp("services", id->fragment) || !strcmp("profile", id->fragment)) {
        Credential *vc = DIDStore_LoadCredential(store, &id->did, id);
        if (vc) {
            helper->count++;
            Credential_Destroy(vc);
            return 0;
        }
    }

    return -1;
}

static char *get_tmp_file(char *path, const char *filename)
{
    assert(filename && *filename);

    return get_file_path(path, PATH_MAX, 7, "..", PATH_STEP, "etc", PATH_STEP,
           "tmp", PATH_STEP, filename);
}

static char *get_current_path(char* path)
{
    assert(path);

    if(!getcwd(path, PATH_MAX)) {
        printf("\nCan't get current dir.");
        return NULL;
    }

    return path;
}

static void test_didstore_export_import_did(void)
{
    DIDStore *store, *store2;
    char _path[PATH_MAX], _path2[PATH_MAX], command[512];
    char current[PATH_MAX], *_current;
    char *path, *path2, *file;
    DID did;
    int version;

    _current = get_current_path(current);

    for (version = 2; version < 4; version++) {
        store = TestData_SetupTestStore(true, version);
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
    #if defined(_WIN32) || defined(_WIN64)
        sprintf(command, "set PATH=%s/../../host/usr/bin;%%windir%%;%%windir%%/SYSTEM32 && diff -r %s %s", _current, path, path2);
    #else
        sprintf(command, "diff -r %s %s", path, path2);
    #endif
        CU_ASSERT_EQUAL(system(command), 0);

        DIDStore_Close(store2);
        TestData_Free();
    }
}

static void test_didstore_export_import_rootidentity(void)
{
    DIDStore *store, *store2;
    char _path[PATH_MAX], _path2[PATH_MAX], command[512];
    char current[PATH_MAX], *_current;
    char *path, *path2, *file;
    const char *defaultidentity;
    int version;

    _current = get_current_path(current);

    for (version = 2; version < 4; version++) {
        store = TestData_SetupTestStore(true, version);
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
    #if defined(_WIN32) || defined(_WIN64)
        sprintf(command, "set PATH=%s/../../host/usr/bin;%%windir%%;%%windir%%/SYSTEM32 && diff -r %s %s", _current, path, path2);
    #else
        sprintf(command, "diff -r %s %s", path, path2);
    #endif
        CU_ASSERT_EQUAL(system(command), 0);

        free((void*)defaultidentity);
        DIDStore_Close(store2);
        TestData_Free();
    }
}

static void test_didstore_export_import_store(void)
{
    DIDStore *store, *store2;
    char _path[PATH_MAX], _path2[PATH_MAX], command[512];
    char current[PATH_MAX], *_current;
    char *path, *path2, *file;
    int version;

    _current = get_current_path(current);

    for (version = 2; version < 4; version++) {
        store = TestData_SetupTestStore(true, version);
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
    #if defined(_WIN32) || defined(_WIN64)
        sprintf(command, "set PATH=%s/../../host/usr/bin;%%windir%%;%%windir%%/SYSTEM32 && diff -r %s %s", _current, path, path2);
    #else
        sprintf(command, "diff -r %s %s", path, path2);
    #endif
        CU_ASSERT_EQUAL(system(command), 0);

        DIDStore_Close(store2);
        TestData_Free();
    }
}

static void testImportCompatible(void)
{
    char path[PATH_MAX], _storepath[PATH_MAX];
    const char *storepath;
    DIDStore *store2, *store;
    DIDMetadata *metadata;
    DIDDocument *doc, *user1Doc;
    List_Helper helper;
    DID *did;
    int count = 0, version;

    TestData_SetupStore(true);

    for (version = 2; version < 4; version++) {
        get_testdata_path(path, "store-export.zip", version);

        //create new store
        storepath = get_store_path(_storepath, "imported-store");
        CU_ASSERT_PTR_NOT_NULL(storepath);
        delete_file(storepath);

        store2 = DIDStore_Open(storepath);
        CU_ASSERT_PTR_NOT_NULL(store2);

        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ImportStore(store2, storepass, path, "password"));

        // Root identity
        count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListRootIdentities(store2, get_rootidentity, (void*)&count));
        CU_ASSERT_EQUAL(1, count);

        // DIDs
        count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store2, 0, get_dids, (void*)&count));
        CU_ASSERT_EQUAL(10, count);

        // DID: User1
        did = DID_New(user1Did);
        CU_ASSERT_PTR_NOT_NULL(did);

        user1Doc = DIDStore_LoadDID(store2, did);
        CU_ASSERT_PTR_NOT_NULL(user1Doc);

        metadata = DIDDocument_GetMetadata(user1Doc);
        CU_ASSERT_PTR_NOT_NULL(metadata);
        CU_ASSERT_STRING_EQUAL("User1", DIDMetadata_GetAlias(metadata));
        CU_ASSERT_TRUE(DIDDocument_PublishDID(user1Doc, NULL, true, storepass));

        helper.store = store2;
        helper.count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store2, did,
            get_user1vcs, (void*)&helper));
        CU_ASSERT_EQUAL(5, helper.count);
        DID_Destroy(did);

        // DID: User2
        did = DID_New(user2Did);
        CU_ASSERT_PTR_NOT_NULL(did);

        doc = DIDStore_LoadDID(store2, did);
        CU_ASSERT_PTR_NOT_NULL(doc);

        metadata = DIDDocument_GetMetadata(doc);
        CU_ASSERT_PTR_NOT_NULL(metadata);
        CU_ASSERT_STRING_EQUAL("User2", DIDMetadata_GetAlias(metadata));
        CU_ASSERT_TRUE(DIDDocument_PublishDID(doc, NULL, true, storepass));
        DIDDocument_Destroy(doc);

        helper.store = store2;
        helper.count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store2, did,
            get_user2vcs, (void*)&helper));
        CU_ASSERT_EQUAL(1, helper.count);
        DID_Destroy(did);

        // DID: User3
        did = DID_New(user3Did);
        CU_ASSERT_PTR_NOT_NULL(did);

        doc = DIDStore_LoadDID(store2, did);
        CU_ASSERT_PTR_NOT_NULL(doc);

        metadata = DIDDocument_GetMetadata(doc);
        CU_ASSERT_PTR_NOT_NULL(metadata);
        CU_ASSERT_STRING_EQUAL("User3", DIDMetadata_GetAlias(metadata));
        CU_ASSERT_TRUE(DIDDocument_PublishDID(doc, NULL, true, storepass));
        DIDDocument_Destroy(doc);

        helper.store = store2;
        helper.count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store2, did,
            get_user2vcs, (void*)&helper));
        CU_ASSERT_EQUAL(0, helper.count);
        DID_Destroy(did);

        // DID: User4
        did = DID_New(user4Did);
        CU_ASSERT_PTR_NOT_NULL(did);

        doc = DIDStore_LoadDID(store2, did);
        CU_ASSERT_PTR_NOT_NULL(doc);

        metadata = DIDDocument_GetMetadata(doc);
        CU_ASSERT_PTR_NOT_NULL(metadata);
        CU_ASSERT_STRING_EQUAL("User4", DIDMetadata_GetAlias(metadata));
        CU_ASSERT_TRUE(DIDDocument_PublishDID(doc, NULL, true, storepass));
        DIDDocument_Destroy(doc);

        helper.store = store2;
        helper.count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store2, did,
            get_user2vcs, (void*)&helper));
        CU_ASSERT_EQUAL(0, helper.count);
        DID_Destroy(did);

        // DID: Issuer
        did = DID_New(issuerDid);
        CU_ASSERT_PTR_NOT_NULL(did);

        doc = DIDStore_LoadDID(store2, did);
        CU_ASSERT_PTR_NOT_NULL(doc);

        metadata = DIDDocument_GetMetadata(doc);
        CU_ASSERT_PTR_NOT_NULL(metadata);
        CU_ASSERT_STRING_EQUAL("Issuer", DIDMetadata_GetAlias(metadata));
        CU_ASSERT_TRUE(DIDDocument_PublishDID(doc, NULL, true, storepass));
        DIDDocument_Destroy(doc);

        helper.store = store2;
        helper.count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store2, did,
            get_user2vcs, (void*)&helper));
        CU_ASSERT_EQUAL(1, helper.count);
        DID_Destroy(did);

        // DID: Example
        did = DID_New(exampleDid);
        CU_ASSERT_PTR_NOT_NULL(did);

        doc = DIDStore_LoadDID(store2, did);
        CU_ASSERT_PTR_NOT_NULL(doc);

        CU_ASSERT_TRUE(DIDDocument_PublishDID(doc, NULL, true, storepass));
        DIDDocument_Destroy(doc);

        helper.store = store2;
        helper.count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store2, did,
            get_user2vcs, (void*)&helper));
        CU_ASSERT_EQUAL(1, helper.count);
        DID_Destroy(did);

        // DID: Foo
        did = DID_New(fooDid);
        CU_ASSERT_PTR_NOT_NULL(did);

        doc = DIDStore_LoadDID(store2, did);
        CU_ASSERT_PTR_NOT_NULL(doc);

        CU_ASSERT_TRUE(DIDDocument_PublishDID(doc, DIDDocument_GetDefaultPublicKey(user1Doc), true, storepass));
        DIDDocument_Destroy(doc);

        helper.store = store2;
        helper.count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store2, did,
            get_user3vcs, (void*)&helper));
        CU_ASSERT_EQUAL(1, helper.count);
        DID_Destroy(did);

        // DID: FooBar
        did = DID_New(foobarDid);
        CU_ASSERT_PTR_NOT_NULL(did);

        doc = DIDStore_LoadDID(store2, did);
        CU_ASSERT_PTR_NOT_NULL(doc);

        CU_ASSERT_TRUE(DIDDocument_PublishDID(doc, DIDDocument_GetDefaultPublicKey(user1Doc), true, storepass));
        DIDDocument_Destroy(doc);

        helper.store = store2;
        helper.count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store2, did,
            get_user4vcs, (void*)&helper));
        CU_ASSERT_EQUAL(4, helper.count);
        DID_Destroy(did);

        // DID: Bar
        did = DID_New(barDid);
        CU_ASSERT_PTR_NOT_NULL(did);

        doc = DIDStore_LoadDID(store2, did);
        CU_ASSERT_PTR_NOT_NULL(doc);

        CU_ASSERT_TRUE(DIDDocument_PublishDID(doc, DIDDocument_GetDefaultPublicKey(user1Doc), true, storepass));
        DIDDocument_Destroy(doc);

        helper.store = store2;
        helper.count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store2, did,
            get_user4vcs, (void*)&helper));
        CU_ASSERT_EQUAL(0, helper.count);
        DID_Destroy(did);

        // DID: Baz
        did = DID_New(bazDid);
        CU_ASSERT_PTR_NOT_NULL(did);

        doc = DIDStore_LoadDID(store2, did);
        CU_ASSERT_PTR_NOT_NULL(doc);

        CU_ASSERT_TRUE(DIDDocument_PublishDID(doc, DIDDocument_GetDefaultPublicKey(user1Doc), true, storepass));
        DIDDocument_Destroy(doc);

        helper.store = store2;
        helper.count = 0;
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store2, did,
            get_user4vcs, (void*)&helper));
        CU_ASSERT_EQUAL(0, helper.count);
        DID_Destroy(did);

        DIDDocument_Destroy(user1Doc);
        DIDStore_Close(store2);

        TestData_Free();
    }
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
    {  "testImportCompatible",                         testImportCompatible            },
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
