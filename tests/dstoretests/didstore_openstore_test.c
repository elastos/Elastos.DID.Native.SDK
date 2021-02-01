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

static DIDStore *store;

static int get_user1_cred(DIDURL *id, void *context)
{
    int *count = (int*)context;

    Credential *cred;

    if (!id) {
        return 0;
    }

    if (!strcmp("email", id->fragment) || !strcmp("json", id->fragment) ||
            !strcmp("passport", id->fragment) || !strcmp("twitter", id->fragment) ||
            !strcmp("profile", id->fragment)) {
        cred = DIDStore_LoadCredential(store, &id->did, id);
        if (!cred)
            return -1;

        (*count)++;
        Credential_Destroy(cred);
        return 0;
    }

    return -1;
}

static int get_user2_cred(DIDURL *id, void *context)
{
    int *count = (int*)context;
    Credential *cred;

    if (!id)
        return 0;

    if (!strcmp("profile", id->fragment)) {
        cred = DIDStore_LoadCredential(store, &id->did, id);
        if (!cred)
            return -1;

        (*count)++;
        Credential_Destroy(cred);
        return 0;
    }

    return -1;
}

static int get_did(DID *did, void *context)
{
    int *count = (int*)context;

    DIDDocument *doc;
    const char *alias;
    char id[ELA_MAX_DID_LEN];
    int rc, vc_count;

    if (!did)
        return 0;

    if (!strcmp("bar", did->idstring) || !strcmp("baz", did->idstring) ||
            !strcmp("example", did->idstring) || !strcmp("foo", did->idstring) ||
            !strcmp("foobar", did->idstring)) {
            (*count)++;
            return 0;
    } else {
        alias = DIDMetadata_GetAlias(&did->metadata);
        if (!alias)
            return -1;

       if (!strcmp("User1", alias)) {
            vc_count = 0;
            CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_user1_cred, (void*)&vc_count));
            CU_ASSERT_EQUAL(5, vc_count);
            (*count)++;
            return 0;
        }

        if (!strcmp("User2", alias) || !strcmp("Issuer", alias)) {
            vc_count = 0;
            CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_user2_cred, (void*)&vc_count));
            CU_ASSERT_EQUAL(1, vc_count);
            (*count)++;
            return 0;
        }

        if (!strcmp("User3", alias) || !strcmp("User4", alias)) {
            vc_count = 0;
            CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_user2_cred, (void*)&vc_count));
            CU_ASSERT_EQUAL(0, vc_count);
            (*count)++;
            return 0;
        }
    }

    return -1;
}

static int get_identity(RootIdentity *identity, void *context)
{
    int *count = (int*)context;
    DIDStore *store;
    const char *id;

    if (!identity)
        return 0;

    (*count)++;
    return 0;
}

static void test_openstore_file_exist(void)
{
    char _path[PATH_MAX], mnemonic[ELA_MAX_MNEMONIC_LEN];
    const char *defaultIdentity;
    RootIdentity *rootidentity;
    char *path;
    int rc, count = 0;

    path = get_file_path(_path, PATH_MAX, 15, "..", PATH_STEP, "etc", PATH_STEP,
            "did", PATH_STEP, "resources", PATH_STEP, "v2", PATH_STEP, "teststore", PATH_STEP,
            DATA_DIR, PATH_STEP, META_FILE);
    CU_ASSERT_TRUE_FATAL(file_exist(path));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListRootIdentities(store, get_identity, (void*)&count));
    CU_ASSERT_EQUAL(1, count);

    count = 0;
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&count));
    CU_ASSERT_EQUAL(10, count);
}

static void test_openstore_newdid(void)
{
    RootIdentity *rootidentity;
    DIDDocument *doc;
    const char *id;

    id = DIDStore_GetDefaultRootIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(id);

    rootidentity = DIDStore_LoadRootIdentity(store, id);
    free((void*)id);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    doc = RootIdentity_NewDID(rootidentity, password, "");
    CU_ASSERT_PTR_NOT_NULL(doc);
    CU_ASSERT_TRUE(DIDStore_DeleteDID(store, &doc->did));

    RootIdentity_Destroy(rootidentity);
    DIDDocument_Destroy(doc);
}

static void test_openstore_newdid_with_wrongpw(void)
{
    RootIdentity *rootidentity;
    DIDDocument *doc;
    const char *id;

    id = DIDStore_GetDefaultRootIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(id);

    rootidentity = DIDStore_LoadRootIdentity(store, id);
    free((void*)id);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    doc = RootIdentity_NewDID(rootidentity, "1234", "");
    RootIdentity_Destroy(rootidentity);
    CU_ASSERT_PTR_NULL(doc);
    DIDDocument_Destroy(doc);
}

static int didstore_openstore_test_suite_init(void)
{
    store = TestData_SetupTestStore(false);
    if (!store)
        return -1;

    return 0;
}

static int didstore_openstore_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_openstore_file_exist",            test_openstore_file_exist           },
    { "test_openstore_newdid_with_wrongpw",   test_openstore_newdid_with_wrongpw },
    { "test_openstore_newdid",                test_openstore_newdid              },
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
