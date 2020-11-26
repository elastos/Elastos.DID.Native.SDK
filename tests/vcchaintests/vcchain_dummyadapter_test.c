#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <CUnit/Basic.h>
#include <limits.h>
#include <crystal.h>

#include "ela_did.h"
#include "constant.h"
#include "loader.h"
#include "credential.h"
#include "diddocument.h"

static DIDStore *store;

static bool has_type(const char **types, size_t size, const char *type)
{
    int i;

    if (!types || size <= 0 || !type || !*type)
        return false;

    for (i = 0; i < size; i++) {
        if (!strcmp(types[i], type))
            return true;
    }

    return false;
}

static void test_vcchain_declearvc(void)
{
    Credential *vc, *resolve_vc;
    int status;

    TestData_LoadDoc();
    TestData_LoadIssuerDoc();

    vc = TestData_LoadEmailVc();
    CU_ASSERT_PTR_NOT_NULL(vc);

    CU_ASSERT_TRUE(DIDStore_DeclearCredential(store, storepass, &vc->id, NULL));

    resolve_vc = Credential_Resolve(&vc->id, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_vc);

    const char *data1 = Credential_ToJson(vc, true);
    const char *data2 = Credential_ToJson(resolve_vc, true);
    CU_ASSERT_STRING_EQUAL(data1, data2);
    free((void*)data1);
    free((void*)data2);

    Credential_Destroy(resolve_vc);
}

static void test_vcchain_revokevc(void)
{
    Credential *vc, *resolve_vc;
    int status;

    TestData_LoadDoc();
    TestData_LoadIssuerDoc();

    vc = TestData_LoadTwitterVc();
    CU_ASSERT_PTR_NOT_NULL(vc);

    CU_ASSERT_TRUE(DIDStore_RevokeCredential(store, storepass, &vc->id, NULL));
    CU_ASSERT_FALSE(DIDStore_RevokeCredential(store, storepass, &vc->id, NULL));
    CU_ASSERT_STRING_EQUAL("The credential is already revoked.", DIDError_GetMessage());
    CU_ASSERT_FALSE(DIDStore_DeclearCredential(store, storepass, &vc->id, NULL));
    CU_ASSERT_STRING_EQUAL("The credential is already revoked.", DIDError_GetMessage());

    vc = Credential_Resolve(&vc->id, &status, true);
    CU_ASSERT_PTR_NULL(vc);
}

static void test_vcchain_publishvc(void)
{
    Credential *vc, *resolve_vc;
    DIDDocument *document, *issuer_doc, *resolve_doc;
    DID did, issuerid;
    time_t expires;
    const char* provalue;
    int rc, status;

    CU_ASSERT_NOT_EQUAL(TestData_InitIdentity(store), -1);

    //create owner document
    document = DIDStore_NewDID(store, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL(document);
    DID_Copy(&did, &document->did);

    DIDDocumentBuilder *builder = DIDDocument_Edit(document);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(document);

    DIDURL *credid1 = DIDURL_NewByDid(&did, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid1);

    const char *types[2] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "John";

    rc = DIDDocumentBuilder_AddSelfClaimedCredential(builder, credid1, types, 2, props, 1, 0, storepass);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    document = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(document);
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, document);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    expires = DIDDocument_GetExpires(document);

    CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, &did, NULL, true));

    //create issuer
    issuer_doc = DIDStore_NewDID(store, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL(issuer_doc);
    DID_Copy(&issuerid, &issuer_doc->did);
    DIDDocument_Destroy(issuer_doc);
    CU_ASSERT_TRUE_FATAL(DIDStore_PublishDID(store, storepass, &issuerid, NULL, true));

    Issuer *issuer = Issuer_Create(&issuerid, NULL, store);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);

    DIDURL *credid2 = DIDURL_NewByDid(&did, "kyccredential");
    CU_ASSERT_PTR_NOT_NULL(credid2);

    types[0] = "BasicProfileCredential";
    types[1] = "PhoneCredential";
    Property properties[7];
    properties[0].key = "name";
    properties[0].value = "jack";
    properties[1].key = "gender";
    properties[1].value = "Male";
    properties[2].key = "nation";
    properties[2].value = "Singapore";
    properties[3].key = "language";
    properties[3].value = "English";
    properties[4].key = "email";
    properties[4].value = "john@example.com";
    properties[5].key = "twitter";
    properties[5].value = "@john";
    properties[6].key = "phone";
    properties[6].value = "132780456";

    vc = Issuer_CreateCredential(issuer, &did, credid2, types, 2, properties, 7,
            expires, storepass);
    Issuer_Destroy(issuer);
    DIDDocument_Destroy(document);

    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreCredential(store, vc));
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));
    CU_ASSERT_TRUE(DIDStore_DeclearCredential(store, storepass, credid2, NULL));
    Credential_Destroy(vc);

    //check credid1
    resolve_doc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_doc);

    vc = DIDDocument_GetCredential(resolve_doc, credid1);
    CU_ASSERT_PTR_NOT_NULL(vc);

    CU_ASSERT_TRUE(DIDURL_Equals(Credential_GetId(vc), credid1));
    CU_ASSERT_TRUE(DID_Equals(Credential_GetOwner(vc), &did));
    CU_ASSERT_TRUE(DID_Equals(Credential_GetIssuer(vc), &did));

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size_t size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "SelfClaimedCredential"));

    CU_ASSERT_EQUAL(Credential_GetPropertyCount(vc), 1);
    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "John");
    free((void*)provalue);
    DIDDocument_Destroy(resolve_doc);

    //check credid2
    resolve_vc = Credential_Resolve(credid2, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_vc);

    CU_ASSERT_TRUE(DIDURL_Equals(Credential_GetId(resolve_vc), credid2));
    CU_ASSERT_TRUE(DID_Equals(Credential_GetOwner(resolve_vc), &did));
    CU_ASSERT_TRUE(DID_Equals(Credential_GetIssuer(resolve_vc), &issuerid));

    CU_ASSERT_EQUAL(Credential_GetTypeCount(resolve_vc), 2);
    memset(tmptypes, 0, sizeof(tmptypes));
    size = Credential_GetTypes(resolve_vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "PhoneCredential"));

    CU_ASSERT_EQUAL(Credential_GetPropertyCount(resolve_vc), 7);
    provalue = Credential_GetProperty(resolve_vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "jack");
    free((void*)provalue);
    provalue = Credential_GetProperty(resolve_vc, "gender");
    CU_ASSERT_STRING_EQUAL(provalue, "Male");
    free((void*)provalue);
    provalue = Credential_GetProperty(resolve_vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(resolve_vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(resolve_vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);
    provalue = Credential_GetProperty(resolve_vc, "twitter");
    CU_ASSERT_STRING_EQUAL(provalue, "@john");
    free((void*)provalue);
    provalue = Credential_GetProperty(resolve_vc, "phone");
    CU_ASSERT_STRING_EQUAL(provalue, "132780456");
    free((void*)provalue);

    Credential_Destroy(resolve_vc);
    DIDURL_Destroy(credid1);
    DIDURL_Destroy(credid2);
}

static int vcchain_dummyadapter_test_suite_init(void)
{
    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    return 0;
}

static int vcchain_dummyadapter_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_vcchain_declearvc",         test_vcchain_declearvc        },
    { "test_vcchain_revokevc",          test_vcchain_revokevc         },
    { "test_vcchain_publishvc",         test_vcchain_publishvc        },
    {  NULL,                            NULL                          }
};

static CU_SuiteInfo suite[] = {
    { "vcchain dummyadapter test", vcchain_dummyadapter_test_suite_init, vcchain_dummyadapter_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                      NULL,                              NULL,                                 NULL, NULL, NULL  }
};

CU_SuiteInfo* vcchain_dummyadapter_test_suite_info(void)
{
    return suite;
}
