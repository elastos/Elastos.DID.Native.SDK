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

static const char *getpassword(const char *walletDir, const char *walletId)
{
    return walletpass;
}

static int get_rootidentity(RootIdentity *rootidentity, void *context)
{
    int *count = (int*)context;

    if (!rootidentity)
        return 0;

    (*count)++;
    return 0;
}

static void test_didstore_newdid(void)
{
    char _path[PATH_MAX], *path;
    const char *newalias, *id;
    DIDDocument *doc, *loaddoc;
    RootIdentity *rootidentity;
    DIDStore *store;
    bool hasidentity;
    int rc;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    path = get_file_path(_path, PATH_MAX, 5, store->root, PATH_STEP, DATA_DIR, PATH_STEP, META_FILE);
    CU_ASSERT_TRUE_FATAL(file_exist(path));

    const char *newmnemonic = Mnemonic_Generate(language);
    rootidentity = RootIdentity_Create(newmnemonic, "", language, false, store, storepass);
    Mnemonic_Free((void*)newmnemonic);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    id = RootIdentity_GetId(rootidentity);
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_TRUE(DIDStore_ContainsRootIdentity(store, id));

    //doc = DIDStore_NewDID(store, storepass, alias);
    doc = RootIdentity_NewDID(rootidentity, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    DID *did = DIDDocument_GetSubject(doc);
    const char *idstring = DID_GetMethodSpecificId(did);

    path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, IDS_DIR, PATH_STEP, (char*)idstring, PATH_STEP, DOCUMENT_FILE);
    CU_ASSERT_TRUE_FATAL(file_exist(path));

    path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, IDS_DIR, PATH_STEP, (char*)idstring, PATH_STEP, META_FILE);
    CU_ASSERT_TRUE_FATAL(file_exist(path));

    DIDMetadata *metadata = DIDDocument_GetMetadata(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    newalias = DIDMetadata_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(newalias);
    CU_ASSERT_STRING_EQUAL(newalias, alias);

    loaddoc = DIDStore_LoadDID(store, did);
    CU_ASSERT_PTR_NOT_NULL_FATAL(loaddoc);

    CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), DIDDocument_GetSubject(loaddoc)));

    rc = strcmp(doc->proofs.proofs[0].signatureValue, loaddoc->proofs.proofs[0].signatureValue);
    CU_ASSERT_EQUAL_FATAL(rc, 0);

    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(loaddoc));

    RootIdentity_Destroy(rootidentity);
    DIDDocument_Destroy(doc);
    DIDDocument_Destroy(loaddoc);
    TestData_Free();
}

static void test_didstore_newdid_byindex(void)
{
    RootIdentity *rootidentity;
    char _path[PATH_MAX], *path;
    DIDDocument *doc;
    DIDStore *store;
    DID did, *ndid;
    int rc;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    path = get_file_path(_path, PATH_MAX, 5, store->root, PATH_STEP, DATA_DIR, PATH_STEP, META_FILE);
    CU_ASSERT_TRUE_FATAL(file_exist(path));

    const char *mnemonic = Mnemonic_Generate(language);
    rootidentity = RootIdentity_Create(mnemonic, "", language, false, store, storepass);
    Mnemonic_Free((void*)mnemonic);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    doc = RootIdentity_NewDIDByIndex(rootidentity, 0, storepass, "did0 by index");
    CU_ASSERT_PTR_NOT_NULL(doc);
    DID_Copy(&did, DIDDocument_GetSubject(doc));

    ndid = RootIdentity_GetDIDByIndex(rootidentity, 0);
    CU_ASSERT_PTR_NOT_NULL(ndid);

    CU_ASSERT_TRUE(DID_Equals(&did, ndid));
    DIDDocument_Destroy(doc);

    doc = DIDStore_LoadDID(store, ndid);
    CU_ASSERT_PTR_NOT_NULL(doc);
    DID_Destroy(ndid);
    DIDDocument_Destroy(doc);

    doc = RootIdentity_NewDID(rootidentity, storepass, "did0");
    CU_ASSERT_PTR_NULL(doc);
    CU_ASSERT_TRUE(DIDStore_DeleteDID(store, &did));
    DIDDocument_Destroy(doc);

    doc = RootIdentity_NewDID(rootidentity, storepass, "did0");
    CU_ASSERT_PTR_NOT_NULL(doc);

    CU_ASSERT_TRUE(DID_Equals(&did, DIDDocument_GetSubject(doc)));
    DIDDocument_Destroy(doc);

    RootIdentity_Destroy(rootidentity);
    TestData_Free();
}

static void test_didstore_newdid_withouAlias(void)
{
    RootIdentity *rootidentity;
    char _path[PATH_MAX], *path;
    const char *newalias, *id;
    DIDDocument *doc, *loaddoc;
    DIDStore *store;
    int rc;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    path = get_file_path(_path, PATH_MAX, 5, store->root, PATH_STEP, DATA_DIR, PATH_STEP, META_FILE);
    CU_ASSERT_TRUE_FATAL(file_exist(path));

    const char *newmnemonic = Mnemonic_Generate(language);
    rootidentity = RootIdentity_Create(newmnemonic, "", language, false, store, storepass);
    Mnemonic_Free((void*)newmnemonic);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    id = RootIdentity_GetId(rootidentity);
    CU_ASSERT_PTR_NOT_NULL(id);

    CU_ASSERT_TRUE_FATAL(DIDStore_ContainsRootIdentity(store, id));

    path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, ROOTS_DIR, PATH_STEP, id, PATH_STEP, INDEX_FILE);
    CU_ASSERT_TRUE_FATAL(file_exist(path));

    path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, ROOTS_DIR, PATH_STEP, id, PATH_STEP, PRIVATE_FILE);
    CU_ASSERT_TRUE_FATAL(file_exist(path));

    doc = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    DID *did = DIDDocument_GetSubject(doc);
    const char *idstring = DID_GetMethodSpecificId(did);

    path = get_file_path(_path, PATH_MAX, 9, store->root, PATH_STEP, DATA_DIR,
            PATH_STEP, IDS_DIR, PATH_STEP, (char*)idstring, PATH_STEP, DOCUMENT_FILE);
    CU_ASSERT_TRUE_FATAL(file_exist(path));

    DIDMetadata *metadata = DIDDocument_GetMetadata(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    newalias = DIDMetadata_GetAlias(metadata);
    CU_ASSERT_PTR_NULL(newalias);

    rc = DIDMetadata_SetAlias(metadata, "testdoc");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDMetadata_SetExtra(metadata, "name", "littlefish");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDMetadata_SetExtraWithBoolean(metadata, "femal", false);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    loaddoc = DIDStore_LoadDID(store, did);
    CU_ASSERT_PTR_NOT_NULL(loaddoc);
    metadata = DIDDocument_GetMetadata(loaddoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    CU_ASSERT_STRING_EQUAL("testdoc", DIDMetadata_GetAlias(metadata));
    CU_ASSERT_STRING_EQUAL("littlefish", DIDMetadata_GetExtra(metadata, "name"));
    CU_ASSERT_FALSE(DIDMetadata_GetExtraAsBoolean(metadata, "femal"));

    RootIdentity_Destroy(rootidentity);
    DIDDocument_Destroy(doc);
    DIDDocument_Destroy(loaddoc);

    TestData_Free();
}

static void test_didstore_initial_error(void)
{
    char _path[PATH_MAX];
    const char *storePath;
    DIDStore *store;

    storePath = get_store_path(_path, "DIDStore");
    store = DIDStore_Open(storePath);
    CU_ASSERT_PTR_NOT_NULL(store);
    DIDStore_Close(store);

    store = DIDStore_Open("");
    CU_ASSERT_PTR_NULL(store);

    DIDStore_Close(store);
}

static void test_didstore_privateIdentity_error(void)
{
    RootIdentity *rootidentity;
    char _temp[PATH_MAX];
    char *path;
    DIDStore *store;
    int count = 0;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NULL(RootIdentity_Create("", "", language, false, store, storepass));
    CU_ASSERT_PTR_NULL(RootIdentity_Create(mnemonic, "", language, false, store, ""));

    CU_ASSERT_EQUAL(-1, DIDStore_ListRootIdentities(store, get_rootidentity, (void*)&count));
    CU_ASSERT_EQUAL(0, count);

    TestData_Free();
}

static void test_didstore_newdid_emptystore(void)
{
    DIDStore *store;
    DIDDocument *doc;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    doc = RootIdentity_NewDID(NULL, storepass, "little fish");
    CU_ASSERT_PTR_NULL_FATAL(doc);
    DIDDocument_Destroy(doc);

    TestData_Free();
}

static void test_didstore_privateidentity_compatibility(void)
{
    RootIdentity *rootidentity;
    DIDStore *store;
    DIDDocument *doc;
    DID did;
    int rc;

    const char *mnemonic = "pact reject sick voyage foster fence warm luggage cabbage any subject carbon";
    const char *ExtendedkeyBase = "xprv9s21ZrQH143K4biiQbUq8369meTb1R8KnstYFAKtfwk3vF8uvFd1EC2s49bMQsbdbmdJxUWRkuC48CXPutFfynYFVGnoeq8LJZhfd9QjvUt";
    const char *passphrase = "helloworld";

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    rootidentity = RootIdentity_Create(mnemonic, passphrase, language, false, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    doc = RootIdentity_NewDID(rootidentity, storepass, "identity test1");
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, &doc->did);
    DIDStore_DeleteDID(store, &did);
    DIDDocument_Destroy(doc);
    RootIdentity_Destroy(rootidentity);

    rootidentity = RootIdentity_CreateFromRootKey(ExtendedkeyBase, true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    doc = RootIdentity_NewDID(rootidentity, storepass, "identity test2");
    RootIdentity_Destroy(rootidentity);
    CU_ASSERT_PTR_NOT_NULL(doc);

    CU_ASSERT_TRUE(DID_Equals(&did, &doc->did));
    DIDDocument_Destroy(doc);

    TestData_Free();
}

static int didstore_initial_test_suite_init(void)
{
    return 0;
}

static int didstore_initial_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    {  "test_didstore_newdid",                test_didstore_newdid               },
    {  "test_didstore_newdid_byindex",        test_didstore_newdid_byindex       },
    {  "test_didstore_newdid_withouAlias",    test_didstore_newdid_withouAlias   },
    {  "test_didstore_initial_error",         test_didstore_initial_error        },
    {  "test_didstore_privateIdentity_error", test_didstore_privateIdentity_error},
    {  "test_didstore_newdid_emptystore",     test_didstore_newdid_emptystore    },
    {  "test_didstore_privateidentity_compatibility", test_didstore_privateidentity_compatibility},
    {  NULL,                                  NULL                               }
};

static CU_SuiteInfo suite[] = {
    {  "didstore initial test",  didstore_initial_test_suite_init,  didstore_initial_test_suite_cleanup,   NULL, NULL, cases },
    {  NULL,                     NULL,                              NULL,                                  NULL, NULL, NULL  }
};

CU_SuiteInfo* didstore_initial_test_suite_info(void)
{
    return suite;
}
