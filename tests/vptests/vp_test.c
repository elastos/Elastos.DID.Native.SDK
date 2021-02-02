#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>
#include <CUnit/Basic.h>
#include <crystal.h>

#include "ela_did.h"
#include "loader.h"
#include "constant.h"
#include "did.h"
#include "credential.h"

static const char *PresentationType = "VerifiablePresentation";
static DIDDocument *issuerdoc;
static DIDDocument *testdoc;
static DIDStore *store;

static void test_vp_getelem(void)
{
    Presentation *vp;
    ssize_t size;
    Credential *creds[4], **cred;
    DIDURL*id;
    DID *signer;
    int i;

    vp = TestData_LoadVp();
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);

    CU_ASSERT_NOT_EQUAL_FATAL(Presentation_GetType(vp), PresentationType);
    CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(testdoc), Presentation_GetSigner(vp)));

    size = Presentation_GetCredentialCount(vp);
    CU_ASSERT_EQUAL(size, 4);

    size = Presentation_GetCredentials(vp, creds, sizeof(creds));
    CU_ASSERT_EQUAL(size, 4);

    cred = creds;
    for (i = 0; i < size; i++, cred++) {
        CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(testdoc), Credential_GetOwner(*cred)));

        const char *fragment = DIDURL_GetFragment(Credential_GetId(*cred));
        CU_ASSERT_PTR_NOT_NULL(fragment);

        CU_ASSERT_TRUE(!strcmp(fragment, "profile") || !strcmp(fragment, "email") ||
                 !strcmp(fragment, "twitter") || !strcmp(fragment, "passport"));
    }

    signer = Presentation_GetSigner(vp);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signer);

    id = DIDURL_NewByDid(signer, "profile");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "email");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "twitter");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "passport");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "notexist");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));
}

static void test_vp_parse(void)
{
    Presentation *vp, *normvp;
    const char *data;

    vp = TestData_LoadVp();
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);
    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    normvp = Presentation_FromJson(TestData_LoadVpNormJson());
    CU_ASSERT_PTR_NOT_NULL_FATAL(normvp);
    CU_ASSERT_TRUE(Presentation_IsGenuine(normvp));
    CU_ASSERT_TRUE(Presentation_IsValid(normvp));

    data = Presentation_ToJson(normvp, true);
    CU_ASSERT_TRUE(!strcmp(TestData_LoadVpNormJson(), data));
    free((void*)data);
    data = Presentation_ToJson(vp, true);
    CU_ASSERT_TRUE(!strcmp(TestData_LoadVpNormJson(), data));
    free((void*)data);

    Presentation_Destroy(normvp);
}

static void test_vp_create(void)
{
    Presentation *vp;
    DID *did;
    Credential *creds[4], **cred;
    bool equal;
    ssize_t size;
    DIDURL *id;
    DID *signer;
    int i;

    did = DIDDocument_GetSubject(testdoc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(did);

    vp = Presentation_Create(did, NULL, store, storepass, "873172f58701a9ee686f0630204fee59",
            "https://example.com/", 4, TestData_LoadProfileVc(), TestData_LoadEmailVc(),
            TestData_LoadPassportVc(), TestData_LoadTwitterVc());
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);

    CU_ASSERT_NOT_EQUAL_FATAL(Presentation_GetType(vp), PresentationType);
    equal = DID_Equals(did, Presentation_GetSigner(vp));
    CU_ASSERT_TRUE(equal);

    size = Presentation_GetCredentialCount(vp);
    CU_ASSERT_EQUAL(size, 4);

    size = Presentation_GetCredentials(vp, creds, sizeof(creds));
    CU_ASSERT_EQUAL(size, 4);

    cred = creds;
    for (i = 0; i < size; i++, cred++) {
        equal = DID_Equals(DIDDocument_GetSubject(testdoc), Credential_GetOwner(*cred));
        CU_ASSERT_TRUE(equal);

        const char *fragment = DIDURL_GetFragment(Credential_GetId(*cred));
        CU_ASSERT_PTR_NOT_NULL(fragment);

        CU_ASSERT_TRUE(!strcmp(fragment, "profile") || !strcmp(fragment, "email") ||
                 !strcmp(fragment, "twitter") || !strcmp(fragment, "passport"));
    }

    signer = Presentation_GetSigner(vp);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signer);

    id = DIDURL_NewByDid(signer, "profile");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "email");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "twitter");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "passport");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "notexist");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    Presentation_Destroy(vp);
}

static void test_vp_create_by_credarray(void)
{
    Presentation *vp;
    DID *did;
    Credential *creds[4], **cred, *vcs[4] = {0};
    ssize_t size;
    DIDURL *id;
    DID *signer;
    int i;

    did = DIDDocument_GetSubject(testdoc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(did);

    vcs[0] = TestData_LoadProfileVc();
    vcs[1] = TestData_LoadEmailVc();
    vcs[2] = TestData_LoadPassportVc();
    vcs[3] = TestData_LoadTwitterVc();
    vp = Presentation_CreateByCredentials(did, NULL, store, storepass,
            "873172f58701a9ee686f0630204fee59", "https://example.com/", vcs, 4);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);

    CU_ASSERT_NOT_EQUAL_FATAL(Presentation_GetType(vp), PresentationType);
    CU_ASSERT_TRUE(DID_Equals(did, Presentation_GetSigner(vp)));

    size = Presentation_GetCredentialCount(vp);
    CU_ASSERT_EQUAL(size, 4);

    size = Presentation_GetCredentials(vp, creds, sizeof(creds));
    CU_ASSERT_EQUAL(size, 4);

    cred = creds;
    for (i = 0; i < size; i++, cred++) {
        CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(testdoc), Credential_GetOwner(*cred)));

        const char *fragment = DIDURL_GetFragment(Credential_GetId(*cred));
        CU_ASSERT_PTR_NOT_NULL(fragment);

        CU_ASSERT_TRUE(!strcmp(fragment, "profile") || !strcmp(fragment, "email") ||
                 !strcmp(fragment, "twitter") || !strcmp(fragment, "passport"));
    }

    signer = Presentation_GetSigner(vp);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signer);

    id = DIDURL_NewByDid(signer, "profile");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "email");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "twitter");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "passport");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "notexist");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_PTR_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    Presentation_Destroy(vp);
}

static void test_vp_create_without_creds(void)
{
    Presentation *vp;
    DID *did;
    Credential *creds[4];
    ssize_t size;
    DID *signer;

    did = DIDDocument_GetSubject(testdoc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(did);

    vp = Presentation_Create(did, NULL, store, storepass, "873172f58701a9ee686f0630204fee59",
            "https://example.com/", 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);

    CU_ASSERT_NOT_EQUAL_FATAL(Presentation_GetType(vp), PresentationType);
    CU_ASSERT_TRUE(DID_Equals(did, Presentation_GetSigner(vp)));

    size = Presentation_GetCredentialCount(vp);
    CU_ASSERT_EQUAL(size, 0);

    size = Presentation_GetCredentials(vp, creds, sizeof(creds));
    CU_ASSERT_EQUAL(size, 0);

    signer = Presentation_GetSigner(vp);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signer);

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    Presentation_Destroy(vp);
}

static int vp_test_suite_init(void)
{
    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    testdoc = TestData_LoadDoc();
    if (!testdoc) {
        TestData_Free();
        return -1;
    }

    issuerdoc = TestData_LoadIssuerDoc();
    if (!issuerdoc) {
        TestData_Free();
        return -1;
    }

    if (DIDStore_StoreDID(store, testdoc) == -1) {
        TestData_Free();
        return -1;
    }

    return 0;
}

static int vp_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_vp_getelem",                          test_vp_getelem                  },
    { "test_vp_parse",                            test_vp_parse                    },
    { "test_vp_create",                           test_vp_create                   },
    { "test_vp_create_by_credarray",              test_vp_create_by_credarray      },
    { "test_vp_create_without_creds",             test_vp_create_without_creds     },
    { NULL,                                       NULL                             }
};

static CU_SuiteInfo suite[] = {
    { "presentation test",  vp_test_suite_init, vp_test_suite_cleanup,  NULL, NULL, cases },
    {  NULL,                NULL,               NULL,                   NULL, NULL, NULL  }
};


CU_SuiteInfo* vp_test_suite_info(void)
{
    return suite;
}
