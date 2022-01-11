#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <crystal.h>
#include <CUnit/Basic.h>
#include <limits.h>

#include "constant.h"
#include "loader.h"
#include "ela_did.h"
#include "did.h"

static DIDStore *store;
static DID dids[5];
static const char *newmnemonic;

static int didcount = 0;

typedef struct DIDs {
    DID dids[5];
    int index;
} DIDs;

static bool contain_did(DID *dids, DID *did)
{
    int i;

    if (!dids || !did)
        return -1;

    for (i = 0; i < 5; i++) {
        if (DID_Equals(&dids[i], did))
            return true;
    }
    return false;
}

static int get_did(DID *did, void *context)
{
    DIDs *dids = (DIDs*)context;

    if (!did)
        return 0;

    if (dids->index >= 10)
        return -1;

    DID_Copy(&(dids->dids[dids->index++]), did);
    return 0;
}

static DIDDocument* merge_to_localcopy(DIDDocument *chaincopy, DIDDocument *localcopy)
{
    if (!chaincopy && !localcopy)
        return NULL;

    if (!chaincopy)
        return chaincopy;

    return localcopy;
}

static DIDDocument* merge_to_chaincopy(DIDDocument *chaincopy, DIDDocument *localcopy)
{
    if (!chaincopy && !localcopy)
        return NULL;

    if (chaincopy)
        return chaincopy;

    return NULL;
}

static void test_idchain_restore(void)
{
    char _path[PATH_MAX];
    RootIdentity *rootidentity;
    const char *path;
    DIDStore *cleanstore;
    DIDs redids;
    int i;

    path = get_store_path(_path, "cleanstore");
    delete_file(path);
    cleanstore = DIDStore_Open(path);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cleanstore);

    rootidentity = RootIdentity_Create(newmnemonic, "", true, cleanstore, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    printf("\nSynchronizing from IDChain...");
    CU_ASSERT_TRUE(RootIdentity_Synchronize(rootidentity, NULL));
    printf("OK!\n");

    memset(&redids, 0, sizeof(DIDs));
    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&redids));
    CU_ASSERT_EQUAL(5, redids.index);

    const char *types[] = {"https://elastos.org/credentials/v1#SelfProclaimedCredential",
            "https://elastos.org/credentials/profile/v1#ProfileCredential"};
    Property props[2];
    props[0].key = "name";
    props[0].value = "John";
    props[1].key = "gender";
    props[1].value = "Male";

    for(i = 0; i < redids.index; i++) {
        DID *did = &redids.dids[i];
        CU_ASSERT_TRUE(contain_did(dids, did));

        DIDDocument *doc = DIDStore_LoadDID(cleanstore, did);
        CU_ASSERT_PTR_NOT_NULL(doc);
        CU_ASSERT_EQUAL_FATAL(1, DID_Equals(did, DIDDocument_GetSubject(doc)));

        time_t expires = DIDDocument_GetExpires(doc);

        DIDURL *credid = DIDURL_NewFromDid(did, "selfcredential");
        CU_ASSERT_PTR_NOT_NULL(credid);

        Issuer *issuer = Issuer_Create(did, NULL, cleanstore);
        CU_ASSERT_PTR_NOT_NULL(issuer);

        Credential *vc = Issuer_CreateCredential(issuer, did, credid, types, 2,
            props, 2, expires, storepass);
        Issuer_Destroy(issuer);
        DIDURL_Destroy(credid);
        CU_ASSERT_PTR_NOT_NULL(vc);

        const char *provalue = Credential_GetProperty(vc, "name");
        CU_ASSERT_STRING_EQUAL(provalue, "John");
        free((void*)provalue);

        Credential_Destroy(vc);
        DIDDocument_Destroy(doc);
    }
    RootIdentity_Destroy(rootidentity);
    DIDStore_Close(cleanstore);
}

static void test_sync_with_localmodification1(void)
{
    RootIdentity *rootidentity;
    char _path[PATH_MAX], modified_signature[MAX_SIGNATURE_LEN];
    const char *path;
    DIDStore *cleanstore;
    DIDs redids;
    int i;

    path = get_store_path(_path, "cleanstore");
    delete_file(path);
    cleanstore = DIDStore_Open(path);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cleanstore);

    rootidentity = RootIdentity_Create(newmnemonic, "", true, cleanstore, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    printf("\nSynchronizing from IDChain...");
    CU_ASSERT_TRUE(RootIdentity_Synchronize(rootidentity, merge_to_localcopy));
    printf("OK!\n");

    memset(&redids, 0, sizeof(DIDs));
    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDStore_ListDIDs(cleanstore, 0, get_did, (void*)&redids));
    CU_ASSERT_EQUAL(5, redids.index);

    DID *modified_did = &redids.dids[0];
    DIDDocument *modified_doc = DIDStore_LoadDID(cleanstore, modified_did);
    CU_ASSERT_PTR_NOT_NULL(modified_doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(modified_doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(modified_doc);

    DIDURL *serviceid = DIDURL_NewFromDid(modified_did, "test1");
    CU_ASSERT_PTR_NOT_NULL(serviceid);

    CU_ASSERT_NOT_EQUAL_FATAL(-1,
            DIDDocumentBuilder_AddService(builder, serviceid, "TestType", "http://test.com/", NULL, 0));
    DIDURL_Destroy(serviceid);

    modified_doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(modified_doc);
    DIDDocumentBuilder_Destroy(builder);

    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDStore_StoreDID(cleanstore, modified_doc));
    strcpy(modified_signature, DIDDocument_GetProofSignature(modified_doc, 0));
    DIDDocument_Destroy(modified_doc);

    printf("Synchronizing again from IDChain...");
    CU_ASSERT_TRUE(RootIdentity_Synchronize(rootidentity, merge_to_localcopy));

    memset(&redids, 0, sizeof(DIDs));
    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&redids));
    CU_ASSERT_EQUAL(5, redids.index);

    for(i = 0; i < redids.index; i++) {
        DID *did = &redids.dids[i];
        CU_ASSERT_TRUE(contain_did(dids, did));

        DIDDocument *doc = DIDStore_LoadDID(cleanstore, did);
        CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
        CU_ASSERT_EQUAL_FATAL(1, DID_Equals(did, DIDDocument_GetSubject(doc)));

        DIDDocument_Destroy(doc);
    }

    modified_doc = DIDStore_LoadDID(cleanstore, modified_did);
    CU_ASSERT_PTR_NOT_NULL(modified_doc);
    CU_ASSERT_STRING_EQUAL(modified_signature, DIDDocument_GetProofSignature(modified_doc, 0));
    DIDDocument_Destroy(modified_doc);

    RootIdentity_Destroy(rootidentity);
    DIDStore_Close(cleanstore);
}

static void test_sync_with_localmodification2(void)
{
    RootIdentity *rootidentity;
    char _path[PATH_MAX], origin_signature[MAX_SIGNATURE_LEN];
    const char *path;
    DIDStore *cleanstore;
    DIDs redids;
    int i;

    path = get_store_path(_path, "DIDStore");
    delete_file(path);
    cleanstore = DIDStore_Open(path);
    CU_ASSERT_PTR_NOT_NULL(cleanstore);

    rootidentity = RootIdentity_Create(newmnemonic, "", true, cleanstore, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    printf("\nSynchronizing from IDChain...");
    CU_ASSERT_TRUE(RootIdentity_Synchronize(rootidentity, merge_to_localcopy));
    printf("OK!\n");

    memset(&redids, 0, sizeof(DIDs));
    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&redids));
    CU_ASSERT_EQUAL(5, redids.index);

    DID *modified_did = &redids.dids[0];
    DIDDocument *modified_doc = DIDStore_LoadDID(cleanstore, modified_did);
    CU_ASSERT_PTR_NOT_NULL_FATAL(modified_doc);
    strcpy(origin_signature, DIDDocument_GetProofSignature(modified_doc, 0));

    DIDDocumentBuilder *builder = DIDDocument_Edit(modified_doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(modified_doc);

    DIDURL *serviceid = DIDURL_NewFromDid(modified_did, "test1");
    CU_ASSERT_PTR_NOT_NULL_FATAL(serviceid);

    CU_ASSERT_NOT_EQUAL(-1,
           DIDDocumentBuilder_AddService(builder, serviceid, "TestType", "http://test.com/", NULL, 0));
    DIDURL_Destroy(serviceid);

    modified_doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(modified_doc);
    DIDDocumentBuilder_Destroy(builder);

    CU_ASSERT_NOT_EQUAL_FATAL(-1, DIDStore_StoreDID(store, modified_doc));
    DIDDocument_Destroy(modified_doc);

    printf("Synchronizing again from IDChain...");
    CU_ASSERT_TRUE(RootIdentity_Synchronize(rootidentity, merge_to_chaincopy));

    memset(&redids, 0, sizeof(DIDs));
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_ListDIDs(store, 0, get_did, (void*)&redids));
    CU_ASSERT_EQUAL(5, redids.index);

    for(i = 0; i < redids.index; i++) {
        DID *did = &redids.dids[i];
        CU_ASSERT_TRUE(contain_did(dids, did));

        DIDDocument *doc = DIDStore_LoadDID(cleanstore, did);
        CU_ASSERT_PTR_NOT_NULL(doc);
        CU_ASSERT_EQUAL(1, DID_Equals(did, DIDDocument_GetSubject(doc)));

        DIDDocument_Destroy(doc);
    }

    modified_doc = DIDStore_LoadDID(cleanstore, modified_did);
    CU_ASSERT_PTR_NOT_NULL(modified_doc);
    CU_ASSERT_STRING_EQUAL(origin_signature, DIDDocument_GetProofSignature(modified_doc, 0));
    DIDDocument_Destroy(modified_doc);

    RootIdentity_Destroy(rootidentity);
    DIDStore_Close(cleanstore);
}

static int idchain_restore_test_suite_init(void)
{
    RootIdentity *rootidentity;
    DIDDocument *doc;
    int i;

    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    newmnemonic = Mnemonic_Generate(language);
    if (!newmnemonic) {
        TestData_Free();
        return -1;
    }

    rootidentity = RootIdentity_Create(newmnemonic, "", true, store, storepass);
    if (!rootidentity) {
        Mnemonic_Free((void*)newmnemonic);
        TestData_Free();
        return -1;
    }

    for (i = 0; i < 5; i++) {
        doc = RootIdentity_NewDID(rootidentity, storepass, NULL, false);
        if (!doc) {
            RootIdentity_Destroy(rootidentity);
            Mnemonic_Free((void*)newmnemonic);
            TestData_Free();
            return -1;
        }
        if (!DIDDocument_PublishDID(doc, NULL, true, storepass)) {
            DIDDocument_Destroy(doc);
            RootIdentity_Destroy(rootidentity);
            Mnemonic_Free((void*)newmnemonic);
            TestData_Free();
            return -1;
        }
        DID_Copy(&dids[i], DIDDocument_GetSubject(doc));
        DIDDocument_Destroy(doc);
    }

    RootIdentity_Destroy(rootidentity);
    return 0;
}

static int idchain_restore_test_suite_cleanup(void)
{
    Mnemonic_Free((void*)newmnemonic);
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    {   "test_idchain_restore",              test_idchain_restore              },
    {   "test_sync_with_localmodification1", test_sync_with_localmodification1 },
    {   "test_sync_with_localmodification2", test_sync_with_localmodification2 },
    {   NULL,                                NULL                              }
};

static CU_SuiteInfo suite[] = {
    { "id chain restore test", idchain_restore_test_suite_init, idchain_restore_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                   NULL,                            NULL,                               NULL, NULL, NULL  }
};

CU_SuiteInfo* idchain_restore_test_suite_info(void)
{
    return suite;
}