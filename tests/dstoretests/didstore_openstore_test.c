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
} List_Helper;

static int get_user1_cred(DIDURL *id, void *context)
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

static int get_user2_cred(DIDURL *id, void *context)
{
    List_Helper *helper = (List_Helper*)context;

    Credential *cred;

    if (!id)
        return 0;

    if (!strcmp("profile", id->fragment)) {
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

    if (!strcmp("bar", did->idstring) || !strcmp("baz", did->idstring) ||
            !strcmp("example", did->idstring) || !strcmp("foo", did->idstring) ||
            !strcmp("foobar", did->idstring)) {
            helper->count++;
            return 0;
    } else {
        if (!*alias)
            return -1;

       vchelper.store = store;
       vchelper.count = 0;
       if (!strcmp("User1", alias)) {
            CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_user1_cred, (void*)&vchelper));
            CU_ASSERT_TRUE(vchelper.count == 4 || vchelper.count == 5);
            helper->count++;
            return 0;
        }

        if (!strcmp("User2", alias) || !strcmp("Issuer", alias)) {
            CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_user2_cred, (void*)&vchelper));
            CU_ASSERT_EQUAL(1, vchelper.count);
            helper->count++;
            return 0;
        }

        if (!strcmp("User3", alias) || !strcmp("User4", alias)) {
            CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListCredentials(store, did, get_user2_cred, (void*)&vchelper));
            CU_ASSERT_EQUAL(0, vchelper.count);
            helper->count++;
            return 0;
        }
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

static void test_openstore_newdid(void)
{
    RootIdentity *rootidentity;
    DIDDocument *doc;
    const char *id;
    DIDStore *store;
    List_Helper helper;
    int count = 0;

    store = TestData_SetupTestStore(true, 2);
    CU_ASSERT_PTR_NOT_NULL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 2));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListRootIdentities(store, get_identity, (void*)&count));
    CU_ASSERT_EQUAL(1, count);

    helper.store = store;
    helper.count = 0;
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&helper));
    CU_ASSERT_EQUAL(10, helper.count);

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

    TestData_Free();
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

static void test_openstore_upgradev2(void)
{
    RootIdentity *rootidentity;
    DIDDocument *doc;
    DIDStore *store;
    List_Helper helper;
    int count = 0;
    const char *id;

    store = TestData_SetupTestStore(true, 1);
    CU_ASSERT_PTR_NOT_NULL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 2));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListRootIdentities(store, get_identity, (void*)&count));
    CU_ASSERT_EQUAL(1, count);

    helper.store = store;
    helper.count = 0;
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&helper));
    CU_ASSERT_EQUAL(4, helper.count);

    id = DIDStore_GetDefaultRootIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(id);

    rootidentity = DIDStore_LoadRootIdentity(store, id);
    free((void*)id);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    doc = RootIdentity_NewDID(rootidentity, password, "");
    CU_ASSERT_PTR_NOT_NULL(doc);

    RootIdentity_Destroy(rootidentity);
    DIDDocument_Destroy(doc);

    TestData_Free();
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
    { "test_openstore_newdid",                test_openstore_newdid              },
    { "test_openstore_newdid_with_wrongpw",   test_openstore_newdid_with_wrongpw },
    { "test_openstore_upgradev2",             test_openstore_upgradev2           },
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
