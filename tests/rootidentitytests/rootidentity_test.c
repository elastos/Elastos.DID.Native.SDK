#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>
#include <CUnit/Basic.h>
#include <time.h>
#include <crystal.h>

#include "ela_did.h"
#include "ela_jwt.h"
#include "loader.h"
#include "constant.h"
#include "did.h"
#include "rootidentity.h"
#include "diddocument.h"

static const char *ExtendedkeyBase = "xprv9s21ZrQH143K4biiQbUq8369meTb1R8KnstYFAKtfwk3vF8uvFd1EC2s49bMQsbdbmdJxUWRkuC48CXPutFfynYFVGnoeq8LJZhfd9QjvUt";
static const char *expectedIDString = "iYbPqEA98rwvDyA5YT6a3mu8UZy87DLEMR";
static const char *nmnemonic = "pact reject sick voyage foster fence warm luggage cabbage any subject carbon";

static void test_rootidentity_createid(void)
{
    DIDStore *store;
    const char *id1, *id2;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL(store);
    CU_ASSERT_FALSE(DIDStore_ContainsRootIdentities(store));

    id1 = RootIdentity_CreateId(nmnemonic, "helloworld");
    CU_ASSERT_PTR_NOT_NULL(id1);
    id2 = RootIdentity_CreateIdFromRootKey(ExtendedkeyBase);
    CU_ASSERT_PTR_NOT_NULL(id2);
    CU_ASSERT_STRING_EQUAL(id1, id2);

    CU_ASSERT_FALSE(DIDStore_ContainsRootIdentities(store));

    free((void*)id1);
    free((void*)id2);

    TestData_Free();
}

static void test_rootidentity_newdid(void)
{
    DIDStore *store;
    RootIdentity *rootidentity, *_rootidentity;
    DIDDocument *doc1, *doc2;
    DID *did;
    const char *alias = "my identity";

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL(store);
    CU_ASSERT_FALSE(DIDStore_ContainsRootIdentities(store));

    rootidentity = RootIdentity_Create(nmnemonic, "helloworld", true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);
    CU_ASSERT_TRUE(DIDStore_ContainsRootIdentities(store));

    _rootidentity = DIDStore_LoadRootIdentity(store, rootidentity->id);
    CU_ASSERT_PTR_NOT_NULL(_rootidentity);
    CU_ASSERT_STRING_EQUAL(RootIdentity_GetId(rootidentity), RootIdentity_GetId(_rootidentity));
    CU_ASSERT_PTR_NULL(RootIdentity_GetDefaultDID(_rootidentity));

    doc1 = RootIdentity_NewDID(_rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL(doc1);

    did = RootIdentity_GetDefaultDID(_rootidentity);
    CU_ASSERT_PTR_NOT_NULL(did);
    CU_ASSERT_TRUE(DID_Equals(did, &doc1->did));
    CU_ASSERT_STRING_EQUAL(did->idstring, expectedIDString);
    DID_Destroy(did);

    //set alias for root identity
    CU_ASSERT_NOT_EQUAL(-1, RootIdentity_SetAlias(_rootidentity, alias));
    CU_ASSERT_STRING_EQUAL(alias, RootIdentity_GetAlias(_rootidentity));

    //new did2
    doc2 = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL(doc2);

    //get did by index 1
    did = RootIdentity_GetDIDByIndex(_rootidentity, 1);
    CU_ASSERT_PTR_NOT_NULL(did);
    CU_ASSERT_TRUE(DID_Equals(did, &doc2->did));

    //set did2 to default
    CU_ASSERT_NOT_EQUAL(-1, RootIdentity_SetDefaultDID(_rootidentity, did));
    DID_Destroy(did);

    did = RootIdentity_GetDefaultDID(_rootidentity);
    CU_ASSERT_PTR_NOT_NULL(did);
    CU_ASSERT_TRUE(DID_Equals(did, &doc2->did));
    DID_Destroy(did);

    DIDDocument_Destroy(doc1);
    DIDDocument_Destroy(doc2);
    RootIdentity_Destroy(_rootidentity);
    RootIdentity_Destroy(rootidentity);

    TestData_Free();
}

static void test_rootidentitybyrootkey_newdid(void)
{
    DIDStore *store;
    RootIdentity *rootidentity, *_rootidentity;
    DIDDocument *doc;
    DID *did;
    int i;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL(store);
    CU_ASSERT_FALSE(DIDStore_ContainsRootIdentities(store));

    rootidentity = RootIdentity_CreateFromRootKey(ExtendedkeyBase, true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    doc = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL(doc);
    CU_ASSERT_STRING_EQUAL(doc->did.idstring, expectedIDString);
    DIDDocument_Destroy(doc);

    for (i = 1; i < 20; i++) {
        doc = RootIdentity_NewDIDByIndex(rootidentity, i, storepass, NULL);
        CU_ASSERT_PTR_NOT_NULL(doc);

        did = RootIdentity_GetDIDByIndex(rootidentity, i);
        CU_ASSERT_PTR_NOT_NULL(did);
        CU_ASSERT_TRUE(DID_Equals(did, &doc->did));

        DIDDocument_Destroy(doc);
        DID_Destroy(did);
    }

    RootIdentity_Destroy(rootidentity);

    TestData_Free();
}

static int rootidentity_test_suite_init(void)
{
    return 0;
}

static int rootidentity_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_rootidentity_createid",           test_rootidentity_createid          },
    { "test_rootidentity_newdid",             test_rootidentity_newdid            },
    { "test_rootidentitybyrootkey_newdid",    test_rootidentitybyrootkey_newdid   },
    { NULL,                                    NULL                               }
};

static CU_SuiteInfo suite[] = {
    { "rootidentity test", rootidentity_test_suite_init, rootidentity_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,               NULL,                         NULL,                            NULL, NULL, NULL  }
};

CU_SuiteInfo* rootidentity_test_suite_info(void)
{
    return suite;
}
