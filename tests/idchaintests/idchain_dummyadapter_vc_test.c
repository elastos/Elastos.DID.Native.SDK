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
#include "HDkey.h"
#include "constant.h"
#include "loader.h"
#include "did.h"
#include "didmeta.h"
#include "diddocument.h"
#include "credential.h"

static DIDStore *store;

static void test_idchain_declarevc(void)
{
    CredentialBiography *biography;
    DIDDocument *issuerdoc, *doc, *repealerdoc, *user1doc = NULL;
    Credential *vc, *resolve_vc1, *resolve_vc2;
    DIDURL *signkey1, *signkey2, *signkey3;
    const char *data1, *data2;
    int status, i, j, size;
    DataParam *param, *paramlist;

    DataParam params1[] = {
        { 1, "user1", "twitter", NULL  },   { 1, "user1", "passport", NULL  },
        { 1, "user1", "json", NULL     }
    };

    DataParam params2[] = {
        { 2, "user1", "twitter", NULL   }, { 2, "user1", "passport", NULL },
        { 2, "user1", "json", NULL      }, { 2, "foobar", "license", NULL },
        { 2, "foobar", "services", NULL }, { 2, "foo", "email", NULL}
    };

    DataParam *params[] = { params1, params2 };

    repealerdoc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(repealerdoc);
    signkey3 = DIDDocument_GetDefaultPublicKey(repealerdoc);
    CU_ASSERT_PTR_NOT_NULL(signkey3);

    for (i = 0; i < 2; i++) {
        TestData_Reset(2);

        size = (i == 0 ? 3 : 6);
        paramlist = params[i];

        for (j = 0; j < size; j++) {
            param = &paramlist[j];

            signkey1 = NULL;

            if (!strcmp("foobar", param->did) || !strcmp("foo", param->did)) {
                user1doc = TestData_GetDocument("user1", NULL, param->version);
                CU_ASSERT_PTR_NOT_NULL(user1doc);
                CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, param->version));
                CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, param->version));
                signkey1 = DIDDocument_GetDefaultPublicKey(user1doc);
                CU_ASSERT_PTR_NOT_NULL(signkey1);
            }

            issuerdoc = TestData_GetDocument("issuer", NULL, param->version);
            CU_ASSERT_PTR_NOT_NULL(issuerdoc);
            signkey2 = DIDDocument_GetDefaultPublicKey(issuerdoc);
            CU_ASSERT_PTR_NOT_NULL(signkey2);

            if (!strcmp("license", param->param))
                CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("examplecorp", NULL, param->version));

            doc = TestData_GetDocument(param->did, NULL, param->version);
            CU_ASSERT_PTR_NOT_NULL(doc);

            vc = TestData_GetCredential(param->did, param->param, param->type, param->version);
            CU_ASSERT_PTR_NOT_NULL(vc);

            //declare
            CU_ASSERT_PTR_NULL(Credential_Resolve(&vc->id, &status, true));
            CU_ASSERT_EQUAL(status, CredentialStatus_NotFound);

            CU_ASSERT_TRUE(Credential_Declare(vc, signkey1, storepass));
            CU_ASSERT_TRUE(Credential_WasDeclared(&vc->id));
            CU_ASSERT_NOT_EQUAL(1, Credential_IsRevoked(vc));

            resolve_vc1 = Credential_Resolve(&vc->id, &status, true);
            CU_ASSERT_PTR_NOT_NULL(resolve_vc1);
            CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreCredential(store, resolve_vc1));

            data1 = Credential_ToJson(vc, true);
            CU_ASSERT_PTR_NOT_NULL(data1);

            data2 = Credential_ToJson(resolve_vc1, true);
            CU_ASSERT_PTR_NOT_NULL(data2);
            CU_ASSERT_STRING_EQUAL(data1, data2);
            free((void*)data1);
            free((void*)data2);

            CU_ASSERT_NOT_EQUAL(0, CredentialMetadata_GetPublished(&resolve_vc1->metadata));
            CU_ASSERT_PTR_NOT_NULL(CredentialMetadata_GetTxid(&resolve_vc1->metadata));
            CU_ASSERT_NOT_EQUAL(1, Credential_IsRevoked(resolve_vc1));
            CU_ASSERT_TRUE(Credential_WasDeclared(&resolve_vc1->id));

            //declare again, fail.
            CU_ASSERT_NOT_EQUAL(1, Credential_Declare(vc, signkey1, storepass));
            CU_ASSERT_STRING_EQUAL("Credential was already declared.", DIDError_GetLastErrorMessage());

            //revoke by random DID at first, success.
            CU_ASSERT_NOT_EQUAL(1, Credential_RevokeById(&vc->id, repealerdoc, signkey3, storepass));
            CU_ASSERT_NOT_EQUAL(1, Credential_IsRevoked(vc));
            //revoke by owner again, success.
            CU_ASSERT_TRUE(Credential_RevokeById(&vc->id, doc, signkey1, storepass));
            CU_ASSERT_TRUE(Credential_IsRevoked(vc));
            //revoke by issuer again, fail.
            CU_ASSERT_NOT_EQUAL(1, Credential_RevokeById(&vc->id, issuerdoc, signkey2, storepass));
            CU_ASSERT_STRING_EQUAL("Credential is revoked.", DIDError_GetLastErrorMessage());

            //try to declare again, fail.
            CU_ASSERT_NOT_EQUAL(1, Credential_Declare(resolve_vc1, signkey1, storepass));
            CU_ASSERT_STRING_EQUAL("Credential is revoked.", DIDError_GetLastErrorMessage());

            resolve_vc2 = Credential_Resolve(&vc->id, &status, true);
            CU_ASSERT_PTR_NOT_NULL(resolve_vc2);
            CU_ASSERT_EQUAL(status, CredentialStatus_Revoked);

            const char *data1 = Credential_ToJson(resolve_vc1, true);
            const char *data2 = Credential_ToJson(resolve_vc2, true);
            CU_ASSERT_STRING_EQUAL(data1, data2);
            free((void*)data1);
            free((void*)data2);

            Credential_Destroy(resolve_vc1);
            Credential_Destroy(resolve_vc2);

            biography = Credential_ResolveBiography(&vc->id, NULL);
            CU_ASSERT_PTR_NOT_NULL(biography);
            CU_ASSERT_EQUAL(CredentialStatus_Revoked, CredentialBiography_GetStatus(biography));
            CU_ASSERT_EQUAL(2, CredentialBiography_GetTransactionCount(biography));

            CU_ASSERT_STRING_EQUAL("revoke", CredentialBiography_GetOperationByIndex(biography, 0));
            CU_ASSERT_STRING_EQUAL("declare", CredentialBiography_GetOperationByIndex(biography, 1));
            if (!signkey1) {
                signkey1 = DIDDocument_GetDefaultPublicKey(doc);
                CU_ASSERT_PTR_NOT_NULL(signkey1);
            }
            CU_ASSERT_TRUE(DIDURL_Equals(signkey1, CredentialBiography_GetTransactionSignkeyByIndex(biography, 0)));
            CU_ASSERT_TRUE(DIDURL_Equals(signkey1, CredentialBiography_GetTransactionSignkeyByIndex(biography, 1)));

            CredentialBiography_Destroy(biography);
        }
    }
}

static void test_idchain_revokevc(void)
{
    DIDDocument *issuerdoc, *doc, *repealerdoc, *user1doc;
    Credential *vc, *resolvevc;
    DIDURL *signkey1, *signkey2, *signkey3;
    DataParam *param, *paramlist;
    int status, i, j, size;

    DataParam params1[] = {
        { 1, "user1", "twitter", NULL  },   { 1, "user1", "passport", NULL  },
        { 1, "user1", "json", NULL     }
    };

    DataParam params2[] = {
        { 2, "user1", "twitter", NULL   }, { 2, "user1", "passport", NULL },
        { 2, "user1", "json", NULL      }, { 2, "foobar", "license", NULL },
        { 2, "foobar", "services", NULL }, { 2, "foo", "email", NULL      }
    };

    DataParam *params[] = { params1, params2 };

    repealerdoc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(repealerdoc);
    signkey3 = DIDDocument_GetDefaultPublicKey(repealerdoc);
    CU_ASSERT_PTR_NOT_NULL(signkey3);

    for (i = 0; i < 2; i++) {
        TestData_Reset(2);

        size = (i == 0 ? 3 : 6);
        paramlist = params[i];

        for (j = 0; j < size; j++) {
            param = &paramlist[j];

            signkey1 = NULL;

            if (!strcmp("foobar", param->did) || !strcmp("foo", param->did)) {
                user1doc = TestData_GetDocument("user1", NULL, param->version);
                CU_ASSERT_PTR_NOT_NULL(user1doc);
                CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, param->version));
                CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, param->version));
                signkey1 = DIDDocument_GetDefaultPublicKey(user1doc);
                CU_ASSERT_PTR_NOT_NULL(signkey1);
            }

            issuerdoc = TestData_GetDocument("issuer", NULL, param->version);
            CU_ASSERT_PTR_NOT_NULL(issuerdoc);
            signkey2 = DIDDocument_GetDefaultPublicKey(issuerdoc);
            CU_ASSERT_PTR_NOT_NULL(signkey2);

            if (!strcmp("license", param->param))
                CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("examplecorp", NULL, param->version));

            doc = TestData_GetDocument(param->did, NULL, param->version);
            CU_ASSERT_PTR_NOT_NULL(doc);

            vc = TestData_GetCredential(param->did, param->param, param->type, param->version);
            CU_ASSERT_PTR_NOT_NULL(vc);

            if (strcmp("passport", param->param) && strcmp("services", param->param)) {
                CU_ASSERT_NOT_EQUAL(1, Credential_Revoke(vc, NULL, storepass));
                CU_ASSERT_STRING_EQUAL("Please specify the signkey for non-selfproclaimed credential.", DIDError_GetLastErrorMessage());
            }

            if (!strcmp("services", param->param) || !strcmp("passport", param->param))
                signkey2 = signkey1;

            //revoke random did
            CU_ASSERT_NOT_EQUAL(1, Credential_Revoke(vc, signkey3, storepass));
            CU_ASSERT_NOT_EQUAL(1, Credential_IsRevoked(vc));

            CU_ASSERT_TRUE(Credential_Revoke(vc, signkey2, storepass));
            CU_ASSERT_TRUE(Credential_IsRevoked(vc));

            resolvevc = Credential_Resolve(&vc->id, &status, true);
            CU_ASSERT_PTR_NULL(resolvevc);
            CU_ASSERT_EQUAL(status, CredentialStatus_Revoked);
            CU_ASSERT_TRUE(Credential_ResolveRevocation(&vc->id, &issuerdoc->did));

            CU_ASSERT_NOT_EQUAL(1, Credential_Declare(vc, signkey1, storepass));
            CU_ASSERT_STRING_EQUAL("Credential is revoked.", DIDError_GetLastErrorMessage());

            CU_ASSERT_EQUAL(status, CredentialStatus_Revoked);
            CU_ASSERT_TRUE(Credential_ResolveRevocation(&vc->id, &issuerdoc->did));
            CU_ASSERT_TRUE(Credential_IsRevoked(vc));
            CU_ASSERT_NOT_EQUAL(1, Credential_WasDeclared(&vc->id));
        }
    }
}

static void test_idchain_listvc(void)
{
    Credential *vc, *resolvevc;
    RootIdentity *rootidentity;
    DIDDocument *document, *issuerdoc, *resolvedoc;
    DIDDocumentBuilder *builder;
    DIDURL *credid1, *credid2;
    DIDURL *buffer[2] = {0};
    Issuer *issuer;
    DID did, issuerid;
    time_t expires;
    const char* provalue;
    int i, status;

    rootidentity = TestData_InitIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    //create owner document
    document = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL(document);
    DID_Copy(&did, &document->did);

    expires = DIDDocument_GetExpires(document);

    //create issuer
    issuerdoc = RootIdentity_NewDID(rootidentity, storepass, NULL);
    RootIdentity_Destroy(rootidentity);
    CU_ASSERT_PTR_NOT_NULL(issuerdoc);
    DID_Copy(&issuerid, &issuerdoc->did);
    CU_ASSERT_TRUE(DIDDocument_PublishDID(issuerdoc, NULL, true, storepass));
    DIDDocument_Destroy(issuerdoc);

    issuer = Issuer_Create(&issuerid, NULL, store);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);

    //create kyc credential
    credid1 = DIDURL_NewByDid(&did, "kyccredential");
    CU_ASSERT_PTR_NOT_NULL(credid1);

    const char *types[2];
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

    vc = Issuer_CreateCredential(issuer, &did, credid1, types, 2, properties, 7,
            expires, storepass);
    CU_ASSERT_PTR_NOT_NULL(vc);
    Issuer_Destroy(issuer);

    builder = DIDDocument_Edit(document, NULL);
    DIDDocument_Destroy(document);
    CU_ASSERT_PTR_NOT_NULL(builder);

    credid2 = DIDURL_NewByDid(&did, "selfvc");
    CU_ASSERT_PTR_NOT_NULL(credid2);

    types[0] = "BasicProfileCredential";
    types[1] = "SelfClaimedCredential";

    Property props[1];
    props[0].key = "name";
    props[0].value = "John";

    CU_ASSERT_NOT_EQUAL(-1,
            DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid2, types, 2, props, 1, 0, NULL, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddCredential(builder, vc));
    Credential_Destroy(vc);

    document = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(document);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, document));
    CU_ASSERT_TRUE(DIDDocument_PublishDID(document, NULL, true, storepass));

    vc = DIDStore_LoadCredential(store, &did, credid2);
    CU_ASSERT_PTR_NOT_NULL(vc);

    //declare credid2
    CU_ASSERT_TRUE(Credential_Declare(vc, NULL, storepass));
    Credential_Destroy(vc);
    CU_ASSERT_TRUE(Credential_WasDeclared(credid2));
    CU_ASSERT_NOT_EQUAL(1, Credential_ResolveRevocation(credid2, &issuerid));

    //revoke credid1
    CU_ASSERT_TRUE(Credential_RevokeById(credid1, document, NULL, storepass));
    CU_ASSERT_NOT_EQUAL(1, Credential_WasDeclared(credid1));
    CU_ASSERT_TRUE(Credential_ResolveRevocation(credid1, &issuerid));

    //resolve did
    resolvedoc = DID_Resolve(&did, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    //check credid1
    vc = DIDDocument_GetCredential(resolvedoc, credid1);
    CU_ASSERT_PTR_NOT_NULL(vc);
    CU_ASSERT_EQUAL(Credential_GetPropertyCount(vc), 7);
    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "jack");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "gender");
    CU_ASSERT_STRING_EQUAL(provalue, "Male");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "twitter");
    CU_ASSERT_STRING_EQUAL(provalue, "@john");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "phone");
    CU_ASSERT_STRING_EQUAL(provalue, "132780456");
    free((void*)provalue);

    CU_ASSERT_NOT_EQUAL(1, Credential_WasDeclared(credid1));
    CU_ASSERT_TRUE(Credential_IsRevoked(vc));

    //resolve credid1(revoked)
    resolvevc = Credential_Resolve(credid1, &status, true);
    CU_ASSERT_PTR_NULL(resolvevc);
    CU_ASSERT_EQUAL(status, CredentialStatus_Revoked);
    CU_ASSERT_TRUE(Credential_ResolveRevocation(credid1, &issuerid));

    //check credid2
    vc = DIDDocument_GetCredential(resolvedoc, credid2);
    CU_ASSERT_PTR_NOT_NULL(vc);

    resolvevc = Credential_Resolve(credid2, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolvevc);
    CU_ASSERT_TRUE(Credential_WasDeclared(credid2));
    CU_ASSERT_NOT_EQUAL(1, Credential_IsRevoked(vc));

    CU_ASSERT_TRUE(DIDURL_Equals(Credential_GetId(resolvevc), credid2));
    CU_ASSERT_TRUE(DID_Equals(Credential_GetOwner(resolvevc), &did));
    CU_ASSERT_TRUE(DID_Equals(Credential_GetIssuer(resolvevc), &did));

    Credential_Destroy(resolvevc);
    DIDDocument_Destroy(resolvedoc);

    CU_ASSERT_EQUAL(1, Credential_List(&did, buffer, sizeof(buffer), 0, 2));
    CU_ASSERT_TRUE(DIDURL_Equals(buffer[0], credid1) || DIDURL_Equals(buffer[0], credid2));

    for (i = 0; i < 1; i++)
        DIDURL_Destroy(buffer[i]);

    DIDDocument_Destroy(document);
    DIDURL_Destroy(credid1);
    DIDURL_Destroy(credid2);
}

static void test_idchain_listvc2(void)
{
    DIDDocument *user1doc, *issuerdoc, *doc;
    Credential *vc, *resolvevc;
    DIDURL *signkey1, *signkey2, *signkey;
    DIDURL *buffer[3];
    DID *did;
    DataParam *param;
    int i, status = 0;
    ssize_t size;

    DataParam params[] = {
        { 2, "user1", "twitter", NULL   },   { 2, "user1", "passport", NULL  },
        { 2, "user1", "json", NULL      },   { 2, "foobar", "license", NULL  },
        { 2, "foobar", "services", NULL },   { 2, "foo", "email", NULL       }
    };

    TestData_Reset(2);

    for (i = 0; i < 6; i++) {
        param = &params[i];
        signkey1 = NULL;

        issuerdoc = TestData_GetDocument("issuer", NULL, param->version);
        CU_ASSERT_PTR_NOT_NULL(issuerdoc);
        signkey2 = DIDDocument_GetDefaultPublicKey(issuerdoc);
        CU_ASSERT_PTR_NOT_NULL(signkey2);

        if (!strcmp("license", param->param))
            CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("examplecorp", NULL, param->version));

        if (!strcmp("foobar", param->did) || !strcmp("foo", param->did)) {
            user1doc = TestData_GetDocument("user1", NULL, param->version);
            CU_ASSERT_PTR_NOT_NULL(user1doc);
            CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, param->version));
            CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, param->version));
            signkey1 = DIDDocument_GetDefaultPublicKey(user1doc);
            CU_ASSERT_PTR_NOT_NULL(signkey1);
            signkey = DIDURL_NewByDid(&user1doc->did, "key2");
            CU_ASSERT_PTR_NOT_NULL(signkey);

            doc = TestData_GetDocument(param->did, NULL, param->version);
            CU_ASSERT_PTR_NOT_NULL(doc);
        } else {
            doc = TestData_GetDocument(param->did, NULL, param->version);
            CU_ASSERT_PTR_NOT_NULL(doc);

            signkey = DIDURL_NewByDid(&doc->did, "key2");
            CU_ASSERT_PTR_NOT_NULL(signkey);
        }

        vc = TestData_GetCredential(param->did, param->param, param->type, param->version);
        CU_ASSERT_PTR_NOT_NULL(vc);

        CU_ASSERT_TRUE(Credential_Declare(vc, signkey, storepass));

        resolvevc = Credential_Resolve(&vc->id, &status, true);
        CU_ASSERT_PTR_NOT_NULL(resolvevc);
        CU_ASSERT_EQUAL(status, CredentialStatus_Valid);

        Credential_Destroy(resolvevc);
        DIDURL_Destroy(signkey);
    }

    size = Credential_List(&user1doc->did, buffer, 3, 0, 4);
    CU_ASSERT_NOT_EQUAL(3, size);
    for (i = 0; i < size; i++)
        CU_ASSERT_TRUE(!strcmp("twitter", buffer[i]->fragment) ||
                !strcmp("passport", buffer[i]->fragment) ||
                !strcmp("json", buffer[i]->fragment));

    did = DID_New("foobar");
    CU_ASSERT_PTR_NOT_NULL(did);
    size = Credential_List(did, buffer, 3, 0, 4);
    CU_ASSERT_NOT_EQUAL(2, size);
    for (i = 0; i < size; i++)
        CU_ASSERT_TRUE(!strcmp("license", buffer[i]->fragment) ||
                !strcmp("services", buffer[i]->fragment));
    DID_Destroy(did);

    did = DID_New("foo");
    CU_ASSERT_PTR_NOT_NULL(did);
    size = Credential_List(did, buffer, 3, 0, 4);
    CU_ASSERT_NOT_EQUAL(1, size);
    for (i = 0; i < size; i++)
        CU_ASSERT_TRUE(!strcmp("email", buffer[i]->fragment));
    DID_Destroy(did);
}

static void test_idchain_listvc_pagination(void)
{
    Credential *vc;
    RootIdentity *rootidentity;
    DIDDocument *document, *issuerdoc;
    DIDURL *credid, *vcid;
    DIDURL *buffer[560] = {0};
    char fragment[120] = {0};
    Issuer *issuer;
    DID did, issuerid;
    time_t expires;
    int i, status = 0, skip, limit, index;
    ssize_t size;

    TestData_Reset(0);

    rootidentity = TestData_InitIdentity(store);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);

    //create owner document
    document = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL(document);
    DID_Copy(&did, &document->did);
    CU_ASSERT_TRUE(DIDDocument_PublishDID(document, NULL, true, storepass));

    expires = DIDDocument_GetExpires(document);
    DIDDocument_Destroy(document);

    //create issuer
    issuerdoc = RootIdentity_NewDID(rootidentity, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL(issuerdoc);
    DID_Copy(&issuerid, &issuerdoc->did);
    CU_ASSERT_TRUE(DIDDocument_PublishDID(issuerdoc, NULL, true, storepass));
    DIDDocument_Destroy(issuerdoc);

    issuer = Issuer_Create(&issuerid, NULL, store);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);

    //create credential
    printf("\n------------------------------------------------------------\ncreate 1028 credentials, please wait...\n");
    for (i = 0; i < 1028; i++) {
        sprintf(fragment, "test%d", i);
        credid = DIDURL_NewByDid(&did, fragment);
        CU_ASSERT_PTR_NOT_NULL(credid);

        const char *types[1];
        types[0] = "BasicProfileCredential";
        Property properties[1];
        properties[0].key = "name";
        properties[0].value = "jack";

        vc = Issuer_CreateCredential(issuer, &did, credid, types, 1, properties, 1,
                expires, storepass);
        CU_ASSERT_PTR_NOT_NULL(vc);
        CredentialMetadata_SetStore(&vc->metadata, store);
        CU_ASSERT_TRUE(Credential_Declare(vc, NULL, storepass));
        CU_ASSERT_TRUE(Credential_WasDeclared(credid));

        Credential_Destroy(vc);
        DIDURL_Destroy(credid);
    }

    printf("successfully!\n------------------------------------------------------------\nlist credential 'skip = 0, limit = 0', wait...\n");
    size = Credential_List(&did, buffer, 560, 0, 0);
    CU_ASSERT_EQUAL(128, size);
    for (i = 0; i < size; i++) {
        vcid = buffer[i];
        sprintf(fragment, "test%d", 1027 - i);
        credid = DIDURL_NewByDid(&did, fragment);
        CU_ASSERT_PTR_NOT_NULL(credid);
        CU_ASSERT_TRUE(DIDURL_Equals(credid, vcid));

        vc = Credential_Resolve(credid, &status, true);
        CU_ASSERT_PTR_NOT_NULL(vc);
        CU_ASSERT_EQUAL(status, CredentialStatus_Valid);

        Credential_Destroy(vc);
        DIDURL_Destroy(credid);
        DIDURL_Destroy(vcid);
    }

    printf("successfully!\n------------------------------------------------------------\nlist credential 'skip = 0, limit = 560', wait...\n");
    size = Credential_List(&did, buffer, 560, 0, 560);
    CU_ASSERT_EQUAL(512, size);

    for (i = 0; i < size; i++) {
        vcid = buffer[i];
        sprintf(fragment, "test%d", 1027 - i);
        credid = DIDURL_NewByDid(&did, fragment);
        CU_ASSERT_PTR_NOT_NULL(credid);
        CU_ASSERT_TRUE(DIDURL_Equals(credid, vcid));

        vc = Credential_Resolve(credid, &status, true);
        CU_ASSERT_PTR_NOT_NULL(vc);
        CU_ASSERT_EQUAL(status, CredentialStatus_Valid);

        Credential_Destroy(vc);
        DIDURL_Destroy(credid);
        DIDURL_Destroy(vcid);
    }

    printf("successfully!\n------------------------------------------------------------\nlist all credentials with 'skip = 0, limit = 256', wait...\n");

    CU_ASSERT_EQUAL(0, Credential_List(&did, buffer, 560, 1028, 100));

    skip = 0;
    limit = 256;
    index = 1028;
    while(true) {
        int resultsize = index >= limit ? limit : index;
        size = Credential_List(&did, buffer, 560, skip, limit);
        if (size == 0)
            break;

        CU_ASSERT_EQUAL(resultsize, size);
        for (i = 0; i < size; i++) {
            vcid = buffer[i];
            sprintf(fragment, "test%d", --index);
            credid = DIDURL_NewByDid(&did, fragment);
            CU_ASSERT_PTR_NOT_NULL(credid);
            CU_ASSERT_TRUE(DIDURL_Equals(credid, vcid));

            vc = Credential_Resolve(credid, &status, true);
            CU_ASSERT_PTR_NOT_NULL(vc);
            CU_ASSERT_EQUAL(status, CredentialStatus_Valid);

            Credential_Destroy(vc);
            DIDURL_Destroy(credid);
            DIDURL_Destroy(vcid);
        }
        skip += size;
    }

    printf("successfully!\n------------------------------------------------------------\nlist all credentials with 'skip = 200, limit = 100' , wait...\n");
    CU_ASSERT_EQUAL(0, index);

    skip = 200;
    limit = 100;
    index = 828;
    while(true) {
        int resultsize = index >= limit ? limit : index;
        size = Credential_List(&did, buffer, 560, skip, limit);
        if (size == 0)
            break;

        CU_ASSERT_EQUAL(resultsize, size);
        for (i = 0; i < size; i++) {
            vcid = buffer[i];
            sprintf(fragment, "test%d", --index);
            credid = DIDURL_NewByDid(&did, fragment);
            CU_ASSERT_PTR_NOT_NULL(credid);
            CU_ASSERT_TRUE(DIDURL_Equals(credid, vcid));

            vc = Credential_Resolve(credid, &status, true);
            CU_ASSERT_PTR_NOT_NULL(vc);
            CU_ASSERT_EQUAL(status, CredentialStatus_Valid);

            Credential_Destroy(vc);
            DIDURL_Destroy(credid);
            DIDURL_Destroy(vcid);
        }
        skip += size;
    }

    printf("successfully!\n");

    CU_ASSERT_EQUAL(0, index);
    Issuer_Destroy(issuer);
}

static int idchain_dummyadapter_forvc_test_suite_init(void)
{
    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    return 0;
}

static int idchain_dummyadapter_forvc_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_idchain_declarevc",          test_idchain_declarevc            },
    { "test_idchain_revokevc",           test_idchain_revokevc             },
    { "test_idchain_listvc",             test_idchain_listvc               },
    { "test_idchain_listvc2",            test_idchain_listvc2              },
    { "test_idchain_listvc_pagination",  test_idchain_listvc_pagination    },
    {  NULL,                             NULL                              }
};

static CU_SuiteInfo suite[] = {
    { "idchain dummyadapter test", idchain_dummyadapter_forvc_test_suite_init, idchain_dummyadapter_forvc_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                      NULL,                              NULL,                                 NULL, NULL, NULL  }
};

CU_SuiteInfo* idchain_dummyadapter_forvc_test_suite_info(void)
{
    return suite;
}
