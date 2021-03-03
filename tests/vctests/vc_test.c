#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <CUnit/Basic.h>
#include <limits.h>
#include <crystal.h>

#include "loader.h"
#include "ela_did.h"
#include "constant.h"
#include "credential.h"

static DIDDocument *document;
static DID *did;
static DIDStore *store;

static void test_vc_kycvc(void)
{
    DIDDocument *issuerdoc;
    Credential *cred;
    DIDURL *id;
    ssize_t size;
    const char *types[3], *data;
    int i;

    issuerdoc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuerdoc);

    cred = TestData_GetCredential(NULL, "vc-email", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cred);

    id = DIDURL_NewByDid(did, "email");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_TRUE(DIDURL_Equals(id, Credential_GetId(cred)));
    DIDURL_Destroy(id);

    size = Credential_GetTypes(cred, types, sizeof(types));
    CU_ASSERT_EQUAL(size, 3);

    for (i = 0; i < size; i++) {
        const char *type = types[i];
        CU_ASSERT_TRUE(!strcmp(type, "BasicProfileCredential") ||
                !strcmp(type, "InternetAccountCredential") ||
                !strcmp(type, "EmailCredential"));
    }

    CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(issuerdoc), Credential_GetIssuer(cred)));
    CU_ASSERT_TRUE(DID_Equals(did, Credential_GetOwner(cred)));

    data = Credential_GetProperty(cred, "email");
    CU_ASSERT_STRING_EQUAL("john@example.com", data);
    free((void*)data);

    CU_ASSERT_NOT_EQUAL(0, Credential_GetIssuanceDate(cred));
    CU_ASSERT_NOT_EQUAL(0, Credential_GetExpirationDate(cred));

    CU_ASSERT_FALSE(Credential_IsExpired(cred));
    CU_ASSERT_TRUE(Credential_IsGenuine(cred));
    CU_ASSERT_TRUE(Credential_IsValid(cred));
}

static void test_vc_selfclaimvc(void)
{
    Credential *cred;
    DIDURL *id;
    ssize_t size;
    const char *types[2], *prop;
    int i;

    cred = TestData_GetCredential(NULL, "vc-profile", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cred);

    id = DIDURL_NewByDid(did, "profile");
    CU_ASSERT_PTR_NOT_NULL_FATAL(id);
    CU_ASSERT_TRUE(DIDURL_Equals(id, Credential_GetId(cred)));
    DIDURL_Destroy(id);

    size = Credential_GetTypes(cred, types, sizeof(types));
    CU_ASSERT_EQUAL(size, 2);

    for (i = 0; i < size; i++) {
        const char *type = types[i];
        CU_ASSERT_TRUE(!strcmp(type, "BasicProfileCredential") ||
                !strcmp(type, "SelfProclaimedCredential"));
    }

    CU_ASSERT_TRUE(DID_Equals(did, Credential_GetIssuer(cred)));
    CU_ASSERT_TRUE(DID_Equals(did, Credential_GetOwner(cred)));

    prop = Credential_GetProperty(cred, "name");
    CU_ASSERT_STRING_EQUAL("John", prop);
    free((void*)prop);
    prop = Credential_GetProperty(cred, "gender");
    CU_ASSERT_STRING_EQUAL("Male", prop);
    free((void*)prop);
    prop = Credential_GetProperty(cred, "nation");
    CU_ASSERT_STRING_EQUAL("Singapore", prop);
    free((void*)prop);
    prop = Credential_GetProperty(cred, "language");
    CU_ASSERT_STRING_EQUAL("English", prop);
    free((void*)prop);
    prop = Credential_GetProperty(cred, "email");
    CU_ASSERT_STRING_EQUAL("john@example.com", prop);
    free((void*)prop);
    prop = Credential_GetProperty(cred, "twitter");
    CU_ASSERT_STRING_EQUAL("@john", prop);
    free((void*)prop);

    CU_ASSERT_NOT_EQUAL(0, Credential_GetIssuanceDate(cred));
    CU_ASSERT_NOT_EQUAL(0, Credential_GetExpirationDate(cred));

    CU_ASSERT_FALSE(Credential_IsExpired(cred));
    CU_ASSERT_TRUE(Credential_IsGenuine(cred));
    CU_ASSERT_TRUE(Credential_IsValid(cred));
}

static void test_vc_parse_kycvc(void)
{
    const char *data;
    Credential *compactvc, *normvc, *cred;

    data = TestData_GetCredentialJson(NULL, "vc-twitter", "normalized", 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data);
    normvc = Credential_FromJson(data, did);
    CU_ASSERT_PTR_NOT_NULL_FATAL(normvc);

    data = TestData_GetCredentialJson(NULL, "vc-twitter", "compact", 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data);
    compactvc = Credential_FromJson(data, did);
    CU_ASSERT_PTR_NOT_NULL_FATAL(compactvc);

    cred = TestData_GetCredential(NULL, "vc-twitter", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cred);

    data = Credential_ToJson(normvc, true);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-twitter", "normalized", 0), data);
    free((void*)data);
    data = Credential_ToJson(compactvc, true);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-twitter", "normalized", 0), data);
    free((void*)data);
    data = Credential_ToJson(cred, true);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-twitter", "normalized", 0), data);
    free((void*)data);

    data = Credential_ToJson(normvc, false);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-twitter", "compact", 0), data);
    free((void*)data);
    data = Credential_ToJson(compactvc, false);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-twitter", "compact", 0), data);
    free((void*)data);
    data = Credential_ToJson(cred, false);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-twitter", "compact", 0), data);
    free((void*)data);

    Credential_Destroy(compactvc);
    Credential_Destroy(normvc);
}

static void test_vc_parse_selfclaimvc(void)
{
    const char *data;
    Credential *compactvc, *normvc, *cred;

    data = TestData_GetCredentialJson(NULL, "vc-profile", "normalized", 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data);
    normvc = Credential_FromJson(data, did);
    CU_ASSERT_PTR_NOT_NULL_FATAL(normvc);

    data = TestData_GetCredentialJson(NULL, "vc-profile", "compact", 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data);
    compactvc = Credential_FromJson(data, did);
    CU_ASSERT_PTR_NOT_NULL_FATAL(compactvc);

    cred = TestData_GetCredential(NULL, "vc-profile", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cred);

    data = Credential_ToJson(normvc, true);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-profile", "normalized", 0), data);
    free((void*)data);
    data = Credential_ToJson(compactvc, true);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-profile", "normalized", 0), data);
    free((void*)data);
    data = Credential_ToJson(cred, true);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-profile", "normalized", 0), data);
    free((void*)data);

    data = Credential_ToJson(normvc, false);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-profile", "compact", 0), data);
    free((void*)data);
    data = Credential_ToJson(compactvc, false);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-profile", "compact", 0), data);
    free((void*)data);
    data = Credential_ToJson(cred, false);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-profile", "compact", 0), data);
    free((void*)data);

    Credential_Destroy(compactvc);
    Credential_Destroy(normvc);
}

static void test_vc_parse_jsonvc(void)
{
    const char *data;
    Credential *compactvc, *normvc, *cred;

    data = TestData_GetCredentialJson(NULL, "vc-json", "normalized", 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data);
    normvc = Credential_FromJson(data, did);
    CU_ASSERT_PTR_NOT_NULL_FATAL(normvc);

    data = TestData_GetCredentialJson(NULL, "vc-json", "compact", 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data);
    compactvc = Credential_FromJson(data, did);
    CU_ASSERT_PTR_NOT_NULL_FATAL(compactvc);

    cred = TestData_GetCredential(NULL, "vc-json", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cred);

    data = Credential_ToJson(normvc, true);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-json", "normalized", 0), data);
    free((void*)data);
    data = Credential_ToJson(compactvc, true);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-json", "normalized", 0), data);
    free((void*)data);
    data = Credential_ToJson(cred, true);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-json", "normalized", 0), data);
    free((void*)data);

    data = Credential_ToJson(normvc, false);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-json", "compact", 0), data);
    free((void*)data);
    data = Credential_ToJson(compactvc, false);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-json", "compact", 0), data);
    free((void*)data);
    data = Credential_ToJson(cred, false);
    CU_ASSERT_STRING_EQUAL(TestData_GetCredentialJson(NULL, "vc-json", "compact", 0), data);
    free((void*)data);

    Credential_Destroy(compactvc);
    Credential_Destroy(normvc);
}

static int vc_test_suite_init(void)
{
    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    document = TestData_GetDocument("document", NULL, 0);
    if(!document) {
        TestData_Free();
        return -1;
    }

    did = DIDDocument_GetSubject(document);
    if (!did) {
        TestData_Free();
        return -1;
    }

    return 0;
}

static int vc_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_vc_kycvc",                 test_vc_kycvc                },
    { "test_vc_selfclaimvc",           test_vc_selfclaimvc          },
    { "test_vc_parse_kycvc",           test_vc_parse_kycvc          },
    { "test_vc_parse_selfclaimvc",     test_vc_parse_selfclaimvc    },
    { "test_vc_parse_jsonvc",          test_vc_parse_jsonvc         },
    { NULL,                            NULL                         }
};

static CU_SuiteInfo suite[] = {
    {  "credential test",  vc_test_suite_init,  vc_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,               NULL,                NULL,                  NULL, NULL, NULL  }
};


CU_SuiteInfo* vc_test_suite_info(void)
{
    return suite;
}
