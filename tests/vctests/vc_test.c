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


static void test_vc_kycvc(void)
{
    DIDDocument *issuerdoc, *doc;
    Credential *cred;
    DID *did;
    DIDURL *id;
    ssize_t size;
    const char *types[2], *data;
    int i, version;

    for (version = 1; version <= 2; version++) {
        issuerdoc = TestData_GetDocument("issuer", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(issuerdoc);
        doc = TestData_GetDocument("user1", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(doc);

        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        cred = TestData_GetCredential("user1", "twitter", NULL, version);
        CU_ASSERT_PTR_NOT_NULL_FATAL(cred);

        id = DIDURL_NewByDid(did, "twitter");
        CU_ASSERT_PTR_NOT_NULL_FATAL(id);
        CU_ASSERT_TRUE(DIDURL_Equals(id, Credential_GetId(cred)));
        DIDURL_Destroy(id);

        size = Credential_GetTypes(cred, types, sizeof(types));
        CU_ASSERT_EQUAL(size, 2);

        for (i = 0; i < size; i++) {
            const char *type = types[i];
            CU_ASSERT_TRUE(!strcmp(type, "InternetAccountCredential") ||
                    !strcmp(type, "TwitterCredential"));
        }

        CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(issuerdoc), Credential_GetIssuer(cred)));
        CU_ASSERT_TRUE(DID_Equals(did, Credential_GetOwner(cred)));

        data = Credential_GetProperty(cred, "twitter");
        CU_ASSERT_STRING_EQUAL("@john", data);
        free((void*)data);

        CU_ASSERT_NOT_EQUAL(0, Credential_GetIssuanceDate(cred));
        CU_ASSERT_NOT_EQUAL(0, Credential_GetExpirationDate(cred));

        CU_ASSERT_FALSE(Credential_IsSelfProclaimed(cred));
        CU_ASSERT_FALSE(Credential_IsExpired(cred));
        CU_ASSERT_TRUE(Credential_IsGenuine(cred));
        CU_ASSERT_TRUE(Credential_IsValid(cred));
    }
}

static void test_vc_selfclaimvc(void)
{
    DIDDocument *doc;
    Credential *cred;
    DID *did;
    DIDURL *id;
    ssize_t size;
    const char *types[2], *prop;
    int i, version;

    for (version = 1; version <= 2; version++) {
        doc = TestData_GetDocument("user1", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(doc);

        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        cred = TestData_GetCredential("user1", "passport", NULL, version);
        CU_ASSERT_PTR_NOT_NULL_FATAL(cred);

        id = DIDURL_NewByDid(did, "passport");
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

        prop = Credential_GetProperty(cred, "nation");
        CU_ASSERT_STRING_EQUAL("Singapore", prop);
        free((void*)prop);
        prop = Credential_GetProperty(cred, "passport");
        CU_ASSERT_STRING_EQUAL("S653258Z07", prop);
        free((void*)prop);

        CU_ASSERT_NOT_EQUAL(0, Credential_GetIssuanceDate(cred));
        CU_ASSERT_NOT_EQUAL(0, Credential_GetExpirationDate(cred));

        CU_ASSERT_TRUE(Credential_IsSelfProclaimed(cred));
        CU_ASSERT_FALSE(Credential_IsExpired(cred));
        CU_ASSERT_TRUE(Credential_IsGenuine(cred));
        CU_ASSERT_TRUE(Credential_IsValid(cred));
    }
}

static void test_vc_parse_selfclaimvc(void)
{
    const char *data, *normJson, *compactJson;
    Credential *compactvc, *normvc, *cred;
    DIDDocument *doc, *issuerdoc;
    DID *did;
    int version;

    for (version = 1; version <= 2; version++) {
        issuerdoc = TestData_GetDocument("issuer", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(issuerdoc);
        doc = TestData_GetDocument("user1", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(doc);

        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        normJson = TestData_GetCredentialJson("user1", "passport", "normalized", version);
        CU_ASSERT_PTR_NOT_NULL(normJson);
        normvc = Credential_FromJson(normJson, did);
        CU_ASSERT_PTR_NOT_NULL(normvc);

        compactJson = TestData_GetCredentialJson("user1", "passport", "compact", version);
        CU_ASSERT_PTR_NOT_NULL(compactJson);
        compactvc = Credential_FromJson(compactJson, did);
        CU_ASSERT_PTR_NOT_NULL(compactvc);

        cred = TestData_GetCredential("user1", "passport", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(cred);

        data = Credential_ToJson(normvc, true);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);
        data = Credential_ToJson(compactvc, true);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);
        data = Credential_ToJson(cred, true);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);

        if (version == 2) {
            data = Credential_ToJson(normvc, false);
            CU_ASSERT_STRING_EQUAL(compactJson, data);
            free((void*)data);
            data = Credential_ToJson(compactvc, false);
            CU_ASSERT_STRING_EQUAL(compactJson, data);
            free((void*)data);
            data = Credential_ToJson(cred, false);
            CU_ASSERT_STRING_EQUAL(compactJson, data);
            free((void*)data);
        }
        Credential_Destroy(compactvc);
        Credential_Destroy(normvc);
    }
}

static void test_vc_parse_kycvc(void)
{
    const char *data, *normJson, *compactJson;
    Credential *compactvc, *normvc, *cred;
    DIDDocument *doc, *issuerdoc;
    DID *did;
    int version;

    for (version = 1; version <= 2; version++) {
        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, version));

        doc = TestData_GetDocument("user1", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(doc);

        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        normJson = TestData_GetCredentialJson("user1", "json", "normalized", version);
        CU_ASSERT_PTR_NOT_NULL(normJson);
        normvc = Credential_FromJson(normJson, did);
        CU_ASSERT_PTR_NOT_NULL(normvc);

        compactJson = TestData_GetCredentialJson("user1", "json", "compact", version);
        CU_ASSERT_PTR_NOT_NULL(compactJson);
        compactvc = Credential_FromJson(compactJson, did);
        CU_ASSERT_PTR_NOT_NULL(compactvc);

        cred = TestData_GetCredential("user1", "json", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(cred);

        data = Credential_ToJson(normvc, true);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);
        data = Credential_ToJson(compactvc, true);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);
        data = Credential_ToJson(cred, true);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);

        if (version == 2) {
            data = Credential_ToJson(normvc, false);
            CU_ASSERT_STRING_EQUAL(compactJson, data);
            free((void*)data);
            data = Credential_ToJson(compactvc, false);
            CU_ASSERT_STRING_EQUAL(compactJson, data);
            free((void*)data);
            data = Credential_ToJson(cred, false);
            CU_ASSERT_STRING_EQUAL(compactJson, data);
            free((void*)data);
        }

        Credential_Destroy(compactvc);
        Credential_Destroy(normvc);
    }
}

static void test_vc_keycvc_tocid(void)
{
    DIDDocument *issuerdoc, *foodoc;
    DID *did;
    Credential *cred;
    DIDURL *id;
    const char *types[2], *data;
    size_t size;
    int i;

    issuerdoc = TestData_GetDocument("issuer", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(issuerdoc);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));

    foodoc = TestData_GetDocument("foo", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(foodoc);

    did = DIDDocument_GetSubject(foodoc);
    CU_ASSERT_PTR_NOT_NULL(did);

    cred = TestData_GetCredential("foo", "email", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(cred);

    id = DIDURL_NewByDid(did, "email");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_TRUE(DIDURL_Equals(id, Credential_GetId(cred)));
    DIDURL_Destroy(id);

    size = Credential_GetTypes(cred, types, sizeof(types));
    CU_ASSERT_EQUAL(1, size);

    for (i = 0; i < size; i++)
        CU_ASSERT_STRING_EQUAL("InternetAccountCredential", types[i]);

    CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(issuerdoc), Credential_GetIssuer(cred)));
    CU_ASSERT_TRUE(DID_Equals(did, Credential_GetOwner(cred)));

    data = Credential_GetProperty(cred, "email");
    CU_ASSERT_STRING_EQUAL("foo@example.com", data);
    free((void*)data);

    CU_ASSERT_NOT_EQUAL(0, Credential_GetIssuanceDate(cred));
    CU_ASSERT_NOT_EQUAL(0, Credential_GetExpirationDate(cred));

    CU_ASSERT_FALSE(Credential_IsSelfProclaimed(cred));
    CU_ASSERT_FALSE(Credential_IsExpired(cred));
    CU_ASSERT_TRUE(Credential_IsGenuine(cred));
    CU_ASSERT_TRUE(Credential_IsValid(cred));
}

static void test_vc_kycvc_fromcid(void)
{
    DIDDocument *issuerdoc, *foobardoc;
    DID *did;
    DIDURL *id;
    Credential *cred;
    const char *types[2], *data;
    size_t size;
    int i;

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 2));

    issuerdoc = TestData_GetDocument("examplecorp", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(issuerdoc);
    foobardoc = TestData_GetDocument("foobar", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(foobardoc);

    did = DIDDocument_GetSubject(foobardoc);
    CU_ASSERT_PTR_NOT_NULL(did);

    cred = TestData_GetCredential("foobar", "license", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(cred);

    id = DIDURL_NewByDid(did, "license");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_TRUE(DIDURL_Equals(id, Credential_GetId(cred)));
    DIDURL_Destroy(id);

    size = Credential_GetTypes(cred, types, sizeof(types));
    CU_ASSERT_EQUAL(1, size);

    for (i = 0; i < size; i++)
        CU_ASSERT_STRING_EQUAL("LicenseCredential", types[i]);

    CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(issuerdoc), Credential_GetIssuer(cred)));
    CU_ASSERT_TRUE(DID_Equals(did, Credential_GetOwner(cred)));

    data = Credential_GetProperty(cred, "license-id");
    CU_ASSERT_STRING_EQUAL("20201021C889", data);
    free((void*)data);
    data = Credential_GetProperty(cred, "scope");
    CU_ASSERT_STRING_EQUAL("Consulting", data);
    free((void*)data);

    CU_ASSERT_NOT_EQUAL(0, Credential_GetIssuanceDate(cred));
    CU_ASSERT_NOT_EQUAL(0, Credential_GetExpirationDate(cred));

    CU_ASSERT_FALSE(Credential_IsSelfProclaimed(cred));
    CU_ASSERT_FALSE(Credential_IsExpired(cred));
    CU_ASSERT_TRUE(Credential_IsGenuine(cred));
    CU_ASSERT_TRUE(Credential_IsValid(cred));
}

static void test_vc_selfclaimvc_fromcid(void)
{
    DIDDocument *foobardoc;
    DID *did;
    DIDURL *id;
    Credential *cred;
    const char *types[2], *data;
    size_t size;
    int i;

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, 2));

    foobardoc = TestData_GetDocument("foobar", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(foobardoc);

    did = DIDDocument_GetSubject(foobardoc);
    CU_ASSERT_PTR_NOT_NULL(did);

    cred = TestData_GetCredential("foobar", "services", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(cred);

    id = DIDURL_NewByDid(did, "services");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_TRUE(DIDURL_Equals(id, Credential_GetId(cred)));
    DIDURL_Destroy(id);

    size = Credential_GetTypes(cred, types, sizeof(types));
    CU_ASSERT_EQUAL(size, 2);

    for (i = 0; i < size; i++) {
        const char *type = types[i];
        CU_ASSERT_TRUE(!strcmp(type, "SelfProclaimedCredential") ||
                !strcmp(type, "BasicProfileCredential"));
    }

    CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(foobardoc), Credential_GetIssuer(cred)));
    CU_ASSERT_TRUE(DID_Equals(did, Credential_GetOwner(cred)));

    data = Credential_GetProperty(cred, "Outsourceing");
    CU_ASSERT_STRING_EQUAL("https://foobar.com/outsourcing", data);
    free((void*)data);
    data = Credential_GetProperty(cred, "consultation");
    CU_ASSERT_STRING_EQUAL("https://foobar.com/consultation", data);
    free((void*)data);

    CU_ASSERT_NOT_EQUAL(0, Credential_GetIssuanceDate(cred));
    CU_ASSERT_NOT_EQUAL(0, Credential_GetExpirationDate(cred));

    CU_ASSERT_TRUE(Credential_IsSelfProclaimed(cred));
    CU_ASSERT_FALSE(Credential_IsExpired(cred));
    CU_ASSERT_TRUE(Credential_IsGenuine(cred));
    CU_ASSERT_TRUE(Credential_IsValid(cred));
}

static void test_vc_parse_vcs(void)
{
    DataParam params[] = {
        { 1, "user1", "twitter", NULL  }, { 1, "user1", "passport", NULL  },
        { 1, "user1", "json", NULL     }, { 2, "user1", "twitter", NULL   },
        { 2, "user1", "passport", NULL }, { 2, "user1", "json", NULL      },
        { 2, "foobar", "license", NULL }, { 2, "foobar", "services", NULL },
        { 2, "foo", "email", NULL }
    };
    const char *normJson, *compactJson, *data;
    Credential *normvc, *compactvc, *cred;
    DataParam *param;
    int i;

    for (i = 0; i < 9; i++) {
        param = &params[i];
        normJson = TestData_GetCredentialJson(param->did, param->param, "normalized", param->version);
        CU_ASSERT_PTR_NOT_NULL(normJson);
        normvc = Credential_FromJson(normJson, NULL);
        CU_ASSERT_PTR_NOT_NULL(normvc);

        compactJson = TestData_GetCredentialJson(param->did, param->param, "compact", param->version);
        CU_ASSERT_PTR_NOT_NULL(compactJson);
        compactvc = Credential_FromJson(compactJson, NULL);
        CU_ASSERT_PTR_NOT_NULL(compactvc);

        cred = TestData_GetCredential(param->did, param->param, NULL, param->version);
        CU_ASSERT_PTR_NOT_NULL(cred);

        CU_ASSERT_FALSE(Credential_IsExpired(cred));
        CU_ASSERT_TRUE(Credential_IsGenuine(cred));
        CU_ASSERT_TRUE(Credential_IsValid(cred));

        data = Credential_ToJson(normvc, true);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);
        data = Credential_ToJson(compactvc, true);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);
        data = Credential_ToJson(cred, true);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);

        if (param->version == 2) {
            data = Credential_ToJson(normvc, false);
            CU_ASSERT_PTR_NOT_NULL(data);
            CU_ASSERT_STRING_EQUAL(compactJson, data);
            free((void*)data);
            data = Credential_ToJson(compactvc, false);
            CU_ASSERT_PTR_NOT_NULL(data);
            CU_ASSERT_STRING_EQUAL(compactJson, data);
            free((void*)data);
            data = Credential_ToJson(cred, false);
            CU_ASSERT_PTR_NOT_NULL(data);
            CU_ASSERT_STRING_EQUAL(compactJson, data);
            free((void*)data);
        }

        Credential_Destroy(normvc);
        Credential_Destroy(compactvc);
    }
}

static int vc_test_suite_init(void)
{
    if (!TestData_SetupStore(true))
        return -1;

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
    { "test_vc_keycvc_tocid",          test_vc_keycvc_tocid         },
    { "test_vc_kycvc_fromcid",         test_vc_kycvc_fromcid        },
    { "test_vc_selfclaimvc_fromcid",   test_vc_selfclaimvc_fromcid  },
    { "test_vc_parse_vcs",             test_vc_parse_vcs            },
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
