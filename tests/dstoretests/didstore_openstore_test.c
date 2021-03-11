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
#include "did.h"
#include "diddocument.h"
#include "credential.h"

static const char *password = "passwd";

typedef struct List_Helper {
    DIDStore *store;
    int count;
    int version;
} List_Helper;

static int get_cred1(DIDURL *id, void *context)
{
    List_Helper *helper = (List_Helper*)context;

    Credential *cred;

    if (!id)
        return 0;

    if (!strcmp("email", id->fragment) || !strcmp("json", id->fragment) ||
            !strcmp("passport", id->fragment) || !strcmp("twitter", id->fragment) ||
            !strcmp("profile", id->fragment)) {
        cred = DIDStore_LoadCredential(helper->store, &id->did, id);
        if (!cred)
            return -1;

        helper->count++;
        Credential_Destroy(cred);
        return 0;
    }

    return -1;
}

static int get_cred2(DIDURL *id, void *context)
{
    List_Helper *helper = (List_Helper*)context;

    Credential *cred;

    if (!id)
        return 0;

    if (!strcmp("profile", id->fragment) || !strcmp("email", id->fragment)) {
        cred = DIDStore_LoadCredential(helper->store, &id->did, id);
        if (!cred)
            return -1;

        helper->count++;
        Credential_Destroy(cred);
        return 0;
    }

    return -1;
}

static int get_cred3(DIDURL *id, void *context)
{
    List_Helper *helper = (List_Helper*)context;

    Credential *cred;

    if (!id)
        return 0;

    if (!strcmp("email", id->fragment) || !strcmp("license", id->fragment) ||
            !strcmp("services", id->fragment) || !strcmp("profile", id->fragment)) {
        cred = DIDStore_LoadCredential(helper->store, &id->did, id);
        if (!cred)
            return -1;

        helper->count++;
        Credential_Destroy(cred);
        return 0;
    }

    return -1;
}

static int get_did(DID *did, void *context)
{
    List_Helper *helper = (List_Helper*)context;

    DIDDocument *doc;
    DIDStore *store;
    const char *_alias;
    char alias[ELA_MAX_ALIAS_LEN] = {0};
    List_Helper vchelper;

    if (!did)
        return 0;

    store = helper->store;
    doc = DIDStore_LoadDID(store, did);
    if (!doc)
        return -1;

    _alias = DIDMetadata_GetAlias(&doc->metadata);
    if (_alias)
        strcpy(alias, _alias);

    DIDDocument_Destroy(doc);

    vchelper.store = store;
    vchelper.count = 0;
    vchelper.version = helper->version;

    if (!strcmp("bar", did->idstring) || !strcmp("baz", did->idstring)) {
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_cred2, (void*)&vchelper));
        CU_ASSERT_EQUAL(0, vchelper.count);
        helper->count++;
        return 0;
    }

    if (!strcmp("example", did->idstring) || !strcmp("foo", did->idstring)) {
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_cred2, (void*)&vchelper));
        CU_ASSERT_EQUAL(1, vchelper.count);
        helper->count++;
        return 0;
    }

    if (!strcmp("foobar", did->idstring)) {
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_cred3, (void*)&vchelper));
        CU_ASSERT_EQUAL(4, vchelper.count);
        helper->count++;
        return 0;
    }

    if (!*alias)
        return -1;

   if (!strcmp("User1", alias)) {
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_cred1, (void*)&vchelper));
        if (helper->version == 1) {
            CU_ASSERT_TRUE(vchelper.count == 4);
        } else {
            CU_ASSERT_TRUE(vchelper.count == 5);
        }
        helper->count++;
        return 0;
    }

    if (!strcmp("User2", alias) || !strcmp("Issuer", alias)) {
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_cred2, (void*)&vchelper));
        CU_ASSERT_EQUAL(1, vchelper.count);
        helper->count++;
        return 0;
    }

    if (!strcmp("User3", alias) || !strcmp("User4", alias)) {
        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_cred2, (void*)&vchelper));
        CU_ASSERT_EQUAL(0, vchelper.count);
        helper->count++;
        return 0;
    }

    return -1;
}

static int get_identity(RootIdentity *identity, void *context)
{
    int *count = (int*)context;
    const char *id;

    if (!identity)
        return 0;

    (*count)++;
    return 0;
}

static void test_openstore_compatibility(void)
{
    RootIdentity *rootidentity;
    DIDDocument *doc;
    const char *id;
    DIDStore *store;
    List_Helper helper;
    int count = 0, version;
    DID *did;

    for(version = 1; version <= 2; version++) {
        store = TestData_SetupTestStore(true, version);
        CU_ASSERT_PTR_NOT_NULL(store);

        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, version));
        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, version));
        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, version));
        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, version));

        if (version == 2) {
            CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListRootIdentities(store, get_identity, (void*)&count));
            CU_ASSERT_EQUAL(1, count);
        }

        helper.store = store;
        helper.count = 0;
        helper.version = version;

        CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&helper));
        if (version == 2) {
            CU_ASSERT_EQUAL(10, helper.count);
        } else {
            CU_ASSERT_EQUAL(4, helper.count);
        }

        id = DIDStore_GetDefaultRootIdentity(store);
        CU_ASSERT_PTR_NOT_NULL(id);

        rootidentity = DIDStore_LoadRootIdentity(store, id);
        free((void*)id);
        CU_ASSERT_PTR_NOT_NULL(rootidentity);

        doc = RootIdentity_NewDIDByIndex(rootidentity, 100, password, "");
        CU_ASSERT_PTR_NOT_NULL(doc);

        did = RootIdentity_GetDIDByIndex(rootidentity, 100);
        CU_ASSERT_PTR_NOT_NULL(did);
        CU_ASSERT_TRUE(DID_Equals(did, &doc->did));

        CU_ASSERT_TRUE(DIDStore_DeleteDID(store, &doc->did));

        RootIdentity_Destroy(rootidentity);
        DIDDocument_Destroy(doc);
        DID_Destroy(did);

        TestData_Free();
    }
}

static void test_openstore_newdid_with_wrongpw(void)
{
    RootIdentity *rootidentity;
    DIDStore *store;
    DIDDocument *doc;
    const char *id;

    store = TestData_SetupTestStore(true, 2);
    CU_ASSERT_PTR_NOT_NULL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 2));

    id = DIDStore_GetDefaultRootIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(id);

    rootidentity = DIDStore_LoadRootIdentity(store, id);
    free((void*)id);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    doc = RootIdentity_NewDID(rootidentity, "1234", "");
    RootIdentity_Destroy(rootidentity);
    CU_ASSERT_PTR_NULL(doc);
    DIDDocument_Destroy(doc);

    TestData_Free();
}

static void didstore_openstore_emptyfolder(void)
{
    char _path[PATH_MAX];
    char *root;
    DIDStore *store;

    root = get_store_path(_path, "DIDTest-EmptyStore");
    delete_file(root);
    mkdirs(root, S_IRWXU);

    store = DIDStore_Open(root);
    CU_ASSERT_PTR_NOT_NULL(store);

    DIDStore_Close(store);
}

static void didstore_openmultistore(void)
{
    char cwd[PATH_MAX], path[PATH_MAX * 2];
    DIDStore *stores[10] = {0};
    DIDDocument *docs[10] = {0}, *doc;
    const char *mnemonic, *docsJson, *docJson, *id;
    RootIdentity *rootidentity;
    int i;

    CU_ASSERT_PTR_NOT_NULL(getcwd(cwd, PATH_MAX));

    for(i = 0; i < 10; i++) {
        sprintf(path, "%s%s%s%d", cwd, PATH_STEP, "DIDTestStore", i);
        delete_file(path);

        stores[i] = DIDStore_Open(path);
        CU_ASSERT_PTR_NOT_NULL(stores[i]);

        mnemonic = Mnemonic_Generate(language);
        CU_ASSERT_PTR_NOT_NULL(stores[i]);

        rootidentity = RootIdentity_Create(mnemonic, "", language, true, stores[i], storepass);
        Mnemonic_Free((void*)mnemonic);
        CU_ASSERT_PTR_NOT_NULL(rootidentity);

        RootIdentity_Destroy(rootidentity);
    }

    for (i = 0; i < 10; i++) {
        id = DIDStore_GetDefaultRootIdentity(stores[i]);
        CU_ASSERT_PTR_NOT_NULL(id);

        rootidentity = DIDStore_LoadRootIdentity(stores[i], id);
        CU_ASSERT_PTR_NOT_NULL(rootidentity);

        docs[i] = RootIdentity_NewDID(rootidentity, storepass, NULL);
        RootIdentity_Destroy(rootidentity);
        CU_ASSERT_PTR_NOT_NULL(docs[i]);
    }

    for (i = 0; i < 10; i++) {
        doc = DIDStore_LoadDID(stores[i], &docs[i]->did);
        CU_ASSERT_PTR_NOT_NULL(doc);

        docsJson = DIDDocument_ToJson(docs[i], true);
        CU_ASSERT_PTR_NOT_NULL(docsJson);

        docJson = DIDDocument_ToJson(doc, true);
        CU_ASSERT_PTR_NOT_NULL(docJson);
        CU_ASSERT_STRING_EQUAL(docJson, docsJson);

        free((void*)docsJson);
        free((void*)docJson);
        DIDDocument_Destroy(doc);
    }

    for (i = 0; i < 10; i++) {
        DIDDocument_Destroy(docs[i]);
        DIDStore_Close(stores[i]);
    }
}

static int didstore_openstore_test_suite_init(void)
{
    return 0;
}

static int didstore_openstore_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_openstore_compatibility",         test_openstore_compatibility       },
    { "test_openstore_newdid_with_wrongpw",   test_openstore_newdid_with_wrongpw },
    { "didstore_openstore_emptyfolder",       didstore_openstore_emptyfolder     },
    { "didstore_openmultistore",              didstore_openmultistore            },
    { NULL,                                   NULL                               }
};

static CU_SuiteInfo suite[] = {
    { "didstore open store test", didstore_openstore_test_suite_init, didstore_openstore_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                      NULL,                               NULL,                               NULL, NULL, NULL  }
};

CU_SuiteInfo* didstore_openstore_test_suite_info(void)
{
    return suite;
}
