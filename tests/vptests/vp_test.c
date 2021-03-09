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
#include "diddocument.h"

static DIDStore *store;
static const char *PresentationType = "VerifiablePresentation";

static void test_vp_getelem(void)
{
    Presentation *vp;
    DIDDocument *doc;
    ssize_t size;
    Credential *creds[4], **cred;
    DIDURL*id;
    DID *signer;
    int i, version;

    for (version = 1; version <= 2; version++) {
        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, version));

        doc = TestData_GetDocument("user1", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(doc);

        vp = TestData_GetPresentation("user1", "nonempty", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(vp);

        CU_ASSERT_STRING_EQUAL(Presentation_GetType(vp), PresentationType);
        CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), Presentation_GetSigner(vp)));

        CU_ASSERT_EQUAL(4, Presentation_GetCredentialCount(vp));

        size = Presentation_GetCredentials(vp, creds, sizeof(creds));
        CU_ASSERT_EQUAL(size, 4);

        cred = creds;
        for (i = 0; i < size; i++, cred++) {
            CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), Credential_GetOwner(*cred)));

            const char *fragment = DIDURL_GetFragment(Credential_GetId(*cred));
            CU_ASSERT_PTR_NOT_NULL(fragment);

            CU_ASSERT_TRUE(!strcmp(fragment, "profile") || !strcmp(fragment, "email") ||
                     !strcmp(fragment, "twitter") || !strcmp(fragment, "passport"));
        }

        signer = Presentation_GetSigner(vp);
        CU_ASSERT_PTR_NOT_NULL(signer);

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
}

static void test_vp_getelem_ctmid(void)
{
    DIDDocument *owner;
    Presentation *vp;
    DIDDocument *doc;
    ssize_t size;
    Credential *creds[4], **cred;
    DIDURL*id;
    DID *signer;
    int i, version;

    doc = TestData_GetDocument("foobar", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(doc);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("example", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 2));

    vp = TestData_GetPresentation("foobar", "nonempty", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(vp);

    CU_ASSERT_STRING_EQUAL(Presentation_GetType(vp), PresentationType);

    CU_ASSERT_EQUAL(4, Presentation_GetCredentialCount(vp));

    size = Presentation_GetCredentials(vp, creds, sizeof(creds));
    CU_ASSERT_EQUAL(size, 4);

    cred = creds;
    for (i = 0; i < size; i++, cred++) {
        CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), Credential_GetOwner(*cred)));

        const char *fragment = DIDURL_GetFragment(Credential_GetId(*cred));
        CU_ASSERT_PTR_NOT_NULL(fragment);

        CU_ASSERT_TRUE(!strcmp(fragment, "profile") || !strcmp(fragment, "license") ||
                 !strcmp(fragment, "services") || !strcmp(fragment, "email"));

        CU_ASSERT_TRUE(Credential_IsValid(*cred));
    }

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));
}

static void test_vp_getelem_withemptyvp(void)
{
    DIDDocument *doc;
    Presentation *vp;
    DIDURL *id;
    DID *signer;
    int version;

    for (version = 1; version <= 2; version++) {
        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, version));

        doc = TestData_GetDocument("user1", NULL, version);
        CU_ASSERT_PTR_NULL(doc);

        vp = TestData_GetPresentation("user1", "empty", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(vp);

        CU_ASSERT_NOT_EQUAL_FATAL(Presentation_GetType(vp), PresentationType);
        CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), Presentation_GetSigner(vp)));

        CU_ASSERT_EQUAL(0, Presentation_GetCredentialCount(vp));

        signer = Presentation_GetSigner(vp);
        CU_ASSERT_PTR_NOT_NULL(signer);

        id = DIDURL_NewByDid(signer, "notexist");
        CU_ASSERT_PTR_NOT_NULL_FATAL(id);
        CU_ASSERT_PTR_NULL(Presentation_GetCredential(vp, id));
        DIDURL_Destroy(id);

        CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
        CU_ASSERT_TRUE(Presentation_IsValid(vp));
    }
}

static void test_vp_getelem_withemptyvp_ctmid(void)
{
    DIDDocument *doc;
    Presentation *vp;
    DIDURL *id;
    DID *signer;

    doc = TestData_GetDocument("foobar", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(doc);

    vp = TestData_GetPresentation("foobar", "empty", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(vp);

    CU_ASSERT_NOT_EQUAL_FATAL(Presentation_GetType(vp), PresentationType);
    //CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), Presentation_GetSigner(vp)));

    CU_ASSERT_EQUAL(0, Presentation_GetCredentialCount(vp));

    signer = Presentation_GetSigner(vp);
    CU_ASSERT_PTR_NOT_NULL(signer);

    id = DIDURL_NewByDid(signer, "notexist");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));
}

static void test_vp_parse(void)
{
    Presentation *vp, *normvp;
    const char *data, *normJson;
    int version;

    for (version = 1; version <= 2; version++) {
        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, version));
        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, version));

        vp = TestData_GetPresentation("user1", "nonempty", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(vp);
        CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
        CU_ASSERT_TRUE(Presentation_IsValid(vp));

        normJson = TestData_GetPresentationJson("user1", "nonempty", "normalized", version);
        CU_ASSERT_PTR_NOT_NULL(normJson);
        normvp = Presentation_FromJson(normJson);
        CU_ASSERT_PTR_NOT_NULL(normvp);
        CU_ASSERT_TRUE(Presentation_IsGenuine(normvp));
        CU_ASSERT_TRUE(Presentation_IsValid(normvp));

        data = Presentation_ToJson(normvp, true);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);
        data = Presentation_ToJson(vp, true);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);

        Presentation_Destroy(normvp);
    }
}

static void test_vp_parse_ctmid(void)
{
    Presentation *vp, *normvp;
    const char *data, *normJson;

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("example", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("foobar", NULL, 2));

    vp = TestData_GetPresentation("foobar", "nonempty", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(vp);
    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    normJson = TestData_GetPresentationJson("foobar", "nonempty", "normalized", 2);
    CU_ASSERT_PTR_NOT_NULL(normJson);
    normvp = Presentation_FromJson(normJson);
    CU_ASSERT_PTR_NOT_NULL(normvp);
    CU_ASSERT_TRUE(Presentation_IsGenuine(normvp));
    CU_ASSERT_TRUE(Presentation_IsValid(normvp));

    data = Presentation_ToJson(normvp, true);
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL(normJson, data);
    free((void*)data);
    data = Presentation_ToJson(vp, true);
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL(normJson, data);
    free((void*)data);

    Presentation_Destroy(normvp);
}

static void test_vp_parse_withemptyvp(void)
{
    Presentation *vp, *normvp;
    const char *data, *normJson;
    int version;

    for (version = 1; version <= 2; version++) {
        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, version));
        CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user1", NULL, version));

        vp = TestData_GetPresentation("user1", "empty", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(vp);
        CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
        CU_ASSERT_TRUE(Presentation_IsValid(vp));

        normJson = TestData_GetPresentationJson("user1", "empty", "normalized", 2);
        CU_ASSERT_PTR_NOT_NULL(normJson);
        normvp = Presentation_FromJson(normJson);
        CU_ASSERT_PTR_NOT_NULL(normvp);
        CU_ASSERT_TRUE(Presentation_IsGenuine(normvp));
        CU_ASSERT_TRUE(Presentation_IsValid(normvp));

        data = Presentation_ToJson(normvp, true);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);
        data = Presentation_ToJson(vp, true);
        CU_ASSERT_PTR_NOT_NULL(data);
        CU_ASSERT_STRING_EQUAL(normJson, data);
        free((void*)data);

        Presentation_Destroy(normvp);
    }
}

static void test_vp_parse_withemptyvp_ctmid(void)
{
    Presentation *vp, *normvp;
    const char *data, *normJson;

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("foobar", NULL, 2));

    vp = TestData_GetPresentation("foobar", "empty", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(vp);
    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    normJson = TestData_GetPresentationJson("foobar", "empty", "normalized", 2);
    CU_ASSERT_PTR_NOT_NULL(normJson);
    normvp = Presentation_FromJson(normJson);
    CU_ASSERT_PTR_NOT_NULL(normvp);
    CU_ASSERT_TRUE(Presentation_IsGenuine(normvp));
    CU_ASSERT_TRUE(Presentation_IsValid(normvp));

    data = Presentation_ToJson(normvp, true);
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL(normJson, data);
    free((void*)data);
    data = Presentation_ToJson(vp, true);
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL(normJson, data);
    free((void*)data);

    Presentation_Destroy(normvp);
}

static void test_vp_create(void)
{
    DIDDocument *doc;
    Presentation *vp;
    DID *did;
    Credential *creds[4], **cred;
    ssize_t size;
    DIDURL *id;
    DID *signer;
    int i;

    doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(doc);

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(did);

    vp = Presentation_Create(did, NULL, store, storepass, "873172f58701a9ee686f0630204fee59",
            "https://example.com/", 4, TestData_GetCredential(NULL, "vc-profile", NULL, 0),
            TestData_GetCredential(NULL, "vc-email", NULL, 0),
            TestData_GetCredential(NULL, "vc-passport", NULL, 0),
            TestData_GetCredential(NULL, "vc-twitter", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);

    CU_ASSERT_NOT_EQUAL(Presentation_GetType(vp), PresentationType);
    CU_ASSERT_TRUE(DID_Equals(did, Presentation_GetSigner(vp)));
    CU_ASSERT_EQUAL(4, Presentation_GetCredentialCount(vp));

    size = Presentation_GetCredentials(vp, creds, sizeof(creds));
    CU_ASSERT_EQUAL(size, 4);

    cred = creds;
    for (i = 0; i < size; i++, cred++) {
        CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), Credential_GetOwner(*cred)));

        const char *fragment = DIDURL_GetFragment(Credential_GetId(*cred));
        CU_ASSERT_PTR_NOT_NULL(fragment);

        CU_ASSERT_TRUE(!strcmp(fragment, "profile") || !strcmp(fragment, "email") ||
                 !strcmp(fragment, "twitter") || !strcmp(fragment, "passport"));
    }

    signer = Presentation_GetSigner(vp);
    CU_ASSERT_PTR_NOT_NULL(signer);

    id = DIDURL_NewByDid(signer, "profile");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "email");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "twitter");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "passport");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "notexist");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    Presentation_Destroy(vp);
}

static void test_vp_create_ctmid(void)
{
    DIDDocument *doc, *user1doc;
    Presentation *vp;
    DID *did;
    DIDURL *signkey, *credid1, *credid2;
    Credential *creds[4], **cred;
    ssize_t size;
    DIDURL *id;
    DID *signer;
    int i;

    user1doc = TestData_GetDocument("user1", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(user1doc);

    doc = TestData_GetDocument("foobar", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(doc);

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    signkey = DIDURL_NewByDid(&user1doc->did, "key2");
    CU_ASSERT_PTR_NOT_NULL(signkey);

    credid1 = DIDURL_NewByDid(&user1doc->did, "profile");
    CU_ASSERT_PTR_NOT_NULL(credid1);

    credid2 = DIDURL_NewByDid(&user1doc->did, "email");
    CU_ASSERT_PTR_NOT_NULL(credid2);

    vp = Presentation_Create(did, signkey, store, storepass, "873172f58701a9ee686f0630204fee59",
            "https://example.com/", 4, TestData_GetCredential("foobar", "license", NULL, 2),
            TestData_GetCredential("foobar", "services", NULL, 2),
            DIDDocument_GetCredential(doc, credid1),
            DIDDocument_GetCredential(doc, credid2));
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);

    CU_ASSERT_NOT_EQUAL(Presentation_GetType(vp), PresentationType);
    //CU_ASSERT_TRUE(DID_Equals(did, Presentation_GetSigner(vp)));
    CU_ASSERT_EQUAL(4, Presentation_GetCredentialCount(vp));

    size = Presentation_GetCredentials(vp, creds, sizeof(creds));
    CU_ASSERT_EQUAL(size, 4);

    cred = creds;
    for (i = 0; i < size; i++, cred++) {
        CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), Credential_GetOwner(*cred)));

        const char *fragment = DIDURL_GetFragment(Credential_GetId(*cred));
        CU_ASSERT_PTR_NOT_NULL(fragment);

        CU_ASSERT_TRUE(!strcmp(fragment, "profile") || !strcmp(fragment, "email") ||
                 !strcmp(fragment, "license") || !strcmp(fragment, "services"));
    }

    signer = Presentation_GetSigner(vp);
    CU_ASSERT_PTR_NOT_NULL(signer);
    CU_ASSERT_TRUE(DID_Equals(signer, &signkey->did));
    DIDURL_Destroy(signkey);

    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, credid1));
    DIDURL_Destroy(credid1);

    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, credid2));
    DIDURL_Destroy(credid2);

    id = DIDURL_NewByDid(&doc->did, "services");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(&doc->did, "license");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(&doc->did, "notexist");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    Presentation_Destroy(vp);
}

static void test_vp_create_by_credarray(void)
{
    DIDDocument *doc;
    Presentation *vp;
    DID *did;
    Credential *creds[4], **cred, *vcs[4] = {0};
    ssize_t size;
    DIDURL *id;
    DID *signer;
    int i;

    doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(doc);

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(did);

    vcs[0] = TestData_GetCredential(NULL, "vc-profile", NULL, 0);
    vcs[1] = TestData_GetCredential(NULL, "vc-email", NULL, 0);
    vcs[2] = TestData_GetCredential(NULL, "vc-passport", NULL, 0);
    vcs[3] = TestData_GetCredential(NULL, "vc-twitter", NULL, 0);
    vp = Presentation_CreateByCredentials(did, NULL, store, storepass,
            "873172f58701a9ee686f0630204fee59", "https://example.com/", vcs, 4);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);

    CU_ASSERT_NOT_EQUAL_FATAL(Presentation_GetType(vp), PresentationType);
    CU_ASSERT_TRUE(DID_Equals(did, Presentation_GetSigner(vp)));
    CU_ASSERT_EQUAL(4, Presentation_GetCredentialCount(vp));

    size = Presentation_GetCredentials(vp, creds, sizeof(creds));
    CU_ASSERT_EQUAL(size, 4);

    cred = creds;
    for (i = 0; i < size; i++, cred++) {
        CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), Credential_GetOwner(*cred)));

        const char *fragment = DIDURL_GetFragment(Credential_GetId(*cred));
        CU_ASSERT_PTR_NOT_NULL(fragment);

        CU_ASSERT_TRUE(!strcmp(fragment, "profile") || !strcmp(fragment, "email") ||
                 !strcmp(fragment, "twitter") || !strcmp(fragment, "passport"));
    }

    signer = Presentation_GetSigner(vp);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signer);

    id = DIDURL_NewByDid(signer, "profile");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "email");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "twitter");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "passport");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(signer, "notexist");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    Presentation_Destroy(vp);
}

static void test_vp_create_by_credarray_ctmid(void)
{
    DIDDocument *doc;
    Presentation *vp;
    DID *did;
    Credential *creds[4], **cred, *vcs[4] = {0};
    ssize_t size;
    DIDURL *id, *credid1, *credid2;
    DID *signer;
    int i;

    doc = TestData_GetDocument("foobar", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(doc);

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    credid1 = DIDURL_NewByDid(&doc->did, "email");
    CU_ASSERT_PTR_NOT_NULL(credid1);

    credid2 = DIDURL_NewByDid(&doc->did, "profile");
    CU_ASSERT_PTR_NOT_NULL(credid2);

    vcs[0] = TestData_GetCredential("foobar", "license", NULL, 2);
    vcs[1] = TestData_GetCredential("foobar", "services", NULL, 2);
    vcs[2] = DIDDocument_GetCredential(doc, credid1);
    vcs[3] = DIDDocument_GetCredential(doc, credid2);
    vp = Presentation_CreateByCredentials(did, NULL, store, storepass,
            "873172f58701a9ee686f0630204fee59", "https://example.com/", vcs, 4);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vp);

    CU_ASSERT_NOT_EQUAL_FATAL(Presentation_GetType(vp), PresentationType);
    CU_ASSERT_TRUE(DID_Equals(did, Presentation_GetSigner(vp)));
    CU_ASSERT_EQUAL(4, Presentation_GetCredentialCount(vp));

    size = Presentation_GetCredentials(vp, creds, sizeof(creds));
    CU_ASSERT_EQUAL(size, 4);

    cred = creds;
    for (i = 0; i < size; i++, cred++) {
        //CU_ASSERT_TRUE(DID_Equals(DIDDocument_GetSubject(doc), Credential_GetOwner(*cred)));

        const char *fragment = DIDURL_GetFragment(Credential_GetId(*cred));
        CU_ASSERT_PTR_NOT_NULL(fragment);

        CU_ASSERT_TRUE(!strcmp(fragment, "profile") || !strcmp(fragment, "email") ||
                 !strcmp(fragment, "license") || !strcmp(fragment, "services"));
    }

    //signer = Presentation_GetSigner(vp);
    //CU_ASSERT_PTR_NOT_NULL_FATAL(signer);

    id = DIDURL_NewByDid(&doc->did, "profile");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(&doc->did, "email");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(&doc->did, "twitter");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(&doc->did, "passport");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NOT_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(&doc->did, "notexist");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NULL(Presentation_GetCredential(vp, id));
    DIDURL_Destroy(id);

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    Presentation_Destroy(vp);
}

static void test_vp_create_without_creds(void)
{
    DIDDocument *doc;
    Presentation *vp;
    DID *did;
    Credential *creds[4];
    ssize_t size;
    DID *signer;

    doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(doc);

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    vp = Presentation_Create(did, NULL, store, storepass, "873172f58701a9ee686f0630204fee59",
            "https://example.com/", 0);
    CU_ASSERT_PTR_NOT_NULL(vp);

    CU_ASSERT_NOT_EQUAL(Presentation_GetType(vp), PresentationType);
    CU_ASSERT_TRUE(DID_Equals(did, Presentation_GetSigner(vp)));

    CU_ASSERT_EQUAL(0, Presentation_GetCredentialCount(vp));
    CU_ASSERT_EQUAL(0, Presentation_GetCredentials(vp, creds, sizeof(creds)));

    CU_ASSERT_TRUE(Presentation_IsGenuine(vp));
    CU_ASSERT_TRUE(Presentation_IsValid(vp));

    Presentation_Destroy(vp);
}

static int vp_test_suite_init(void)
{
    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    return 0;
}

static int vp_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_vp_getelem",                          test_vp_getelem                  },
    { "test_vp_getelem_ctmid",                    test_vp_getelem_ctmid            },
    { "test_vp_getelem_withemptyvp",              test_vp_getelem_withemptyvp      },
    { "test_vp_getelem_withemptyvp_ctmid",        test_vp_getelem_withemptyvp_ctmid },
    { "test_vp_parse",                            test_vp_parse                    },
    { "test_vp_parse_ctmid",                      test_vp_parse_ctmid                    },
    { "test_vp_create",                           test_vp_create                   },
    { "test_vp_create_ctmid",                     test_vp_create_ctmid             },
    { "test_vp_create_by_credarray",              test_vp_create_by_credarray      },
    { "test_vp_create_by_credarray_ctmid",        test_vp_create_by_credarray_ctmid },
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
