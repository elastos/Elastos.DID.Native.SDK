#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <CUnit/Basic.h>
#include <limits.h>
#include <crystal.h>

#include "constant.h"
#include "loader.h"
#include "ela_did.h"
#include "did.h"
#include "didmeta.h"
#include "diddocument.h"
#include "credential.h"

static DIDStore *store;
static DIDDocument *document;
static RootIdentity *rootidentity;
static DIDDocument *controller1_doc;
static DIDDocument *controller2_doc;
static DIDDocument *controller3_doc;
static DIDDocument *controller4_doc;
static DIDDocument *controller5_doc;
static DIDDocument *customized_doc;
static DIDDocument *multicustomized_doc;
static DID controller1;
static DID controller2;
static DID controller3;
static DID controller4;
static DID controller5;
static DID customized_did;
static DID multicustomized_did;

extern const char *I18N[];

static int get_customizedid(char *customized_did, size_t len)
{
    static char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    int i;

    assert(customized_did);

    for (i = 0; i < len - 1; i++)
        customized_did[i] = chars[rand() % 62];

    customized_did[len - 1] = 0;
    return 0;
}

static DIDDocument* resolve_doc(DID *did, char* previous_txid)
{
    const char *txid;
    DIDDocument *resolvedoc = NULL;
    DIDMetadata *metadata;
    int i = 0, status;

    assert(did);

    txid = previous_txid;
    while(!resolvedoc || !strcmp(txid, previous_txid)) {
        if (resolvedoc)
            DIDDocument_Destroy(resolvedoc);

        sleep(3);
        resolvedoc = DID_Resolve(did, &status, true);
        if (!resolvedoc) {
            break;
        } else {
            metadata = DIDDocument_GetMetadata(resolvedoc);
            txid = DIDMetadata_GetTxid(metadata);
            printf(".");
        }

        if (++i >= 20) {
            if (resolvedoc)
                DIDDocument_Destroy(resolvedoc);

            CU_FAIL_FATAL("publish did timeout!!!!\n");
        }
    }

    strcpy(previous_txid, txid);
    return resolvedoc;
}

static DIDURL *add_authentication_key(DIDDocumentBuilder *builder, const char *key)
{
    HDKey _dkey, *dkey;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    const char *keybase;
    DIDURL *keyid;

    assert(builder);

    memset(&_dkey, 0, sizeof(HDKey));
    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);

    keyid = DIDURL_NewFromDid(&builder->document->did, key);
    CU_ASSERT_PTR_NOT_NULL(keyid);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StorePrivateKey(store, storepass, keyid,
            HDKey_GetPrivateKey(dkey), PRIVATEKEY_BYTES));

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase));
    return keyid;
}

//create controller1: one create op, two update op.
//controller1 has default key, key1 and key2.
static void test_idchain_controller1(void)
{
    char txid[ELA_MAX_TXID_LEN] = {0};
    bool success;
    char *signs[3] = {0};
    const char *sign;
    DIDDocument *doc;

    //create
    controller1_doc = RootIdentity_NewDID(rootidentity, storepass, "controller1", false);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);

    DID_Copy(&controller1, DIDDocument_GetSubject(controller1_doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    success = DIDDocument_PublishDID(controller1_doc, NULL, false, storepass);
    DIDDocument_Destroy(controller1_doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish controller1 result:\n   did = %s\n -- resolve begin(create)", controller1.idstring);

    controller1_doc = resolve_doc(&controller1, txid);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller1_doc));
    sign = DIDDocument_GetProofSignature(controller1_doc, 0);
    signs[0] = alloca(strlen(sign) + 1);
    strcpy(signs[0], sign);

    DIDDocument_Destroy(controller1_doc);
    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);

    //update
    controller1_doc = DIDStore_LoadDID(store, &controller1);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(controller1_doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(controller1_doc);

    DIDURL *keyid = add_authentication_key(builder, "key1");

    controller1_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller1_doc));

    success = DIDDocument_PublishDID(controller1_doc, keyid, false, storepass);
    DIDURL_Destroy(keyid);
    DIDDocument_Destroy(controller1_doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", controller1.idstring);

    controller1_doc = resolve_doc(&controller1, txid);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller1_doc));

    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(controller1_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(controller1_doc));

    sign = DIDDocument_GetProofSignature(controller1_doc, 0);
    signs[1] = alloca(strlen(sign) + 1);
    strcpy(signs[1], sign);

    DIDDocument_Destroy(controller1_doc);
    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update) again, waiting...\n", txid);

    //update again
    controller1_doc = DIDStore_LoadDID(store, &controller1);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);

    builder = DIDDocument_Edit(controller1_doc, NULL);
    DIDDocument_Destroy(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    keyid = add_authentication_key(builder, "key2");
    DIDURL_Destroy(keyid);

    controller1_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(controller1_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(controller1_doc));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller1_doc));

    success = DIDDocument_PublishDID(controller1_doc, NULL, false, storepass);
    DIDDocument_Destroy(controller1_doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update) again", controller1.idstring);

    controller1_doc = resolve_doc(&controller1, txid);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller1_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(controller1_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(controller1_doc));

    sign = DIDDocument_GetProofSignature(controller1_doc, 0);
    signs[2] = alloca(strlen(sign) + 1);
    strcpy(signs[2], sign);
    printf("\n   txid = %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);

    //DIDBiography
    DIDBiography *biography = DID_ResolveBiography(&controller1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(biography);
    CU_ASSERT_EQUAL(3, DIDBiography_GetTransactionCount(biography));
    CU_ASSERT_EQUAL(0, DIDBiography_GetStatus(biography));

    DID *owner = DIDBiography_GetOwner(biography);
    CU_ASSERT_PTR_NOT_NULL_FATAL(owner);
    CU_ASSERT_EQUAL_FATAL(1, DID_Equals(&controller1, owner));

    for (int i = 0; i < 3; i++) {
        doc = DIDBiography_GetDocumentByIndex(biography, i);
        CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
        CU_ASSERT_STRING_EQUAL(signs[2-i], DIDDocument_GetProofSignature(doc, 0));
        DIDDocument_Destroy(doc);
    }
    DIDBiography_Destroy(biography);
}

//create controller2: one create op and one update op.
//controller2 has one credential.
static void test_idchain_controller2(void)
{
    char txid[ELA_MAX_TXID_LEN] = {0};
    Credential *cred;
    int status;
    bool success;

    controller2_doc = RootIdentity_NewDID(rootidentity, storepass, "controller2", false);
    CU_ASSERT_PTR_NOT_NULL(controller2_doc);

    DID_Copy(&controller2, DIDDocument_GetSubject(controller2_doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    success = DIDDocument_PublishDID(controller2_doc, NULL, false, storepass);
    DIDDocument_Destroy(controller2_doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish controller2 result:\n   did = %s\n -- resolve begin(create)", controller2.idstring);

    controller2_doc = resolve_doc(&controller2, txid);
    CU_ASSERT_PTR_NOT_NULL(controller2_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller2_doc));
    DIDDocument_Destroy(controller2_doc);
    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);

    controller2_doc = DIDStore_LoadDID(store, &controller2);
    CU_ASSERT_PTR_NOT_NULL(controller2_doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(controller2_doc, NULL);
    DIDDocument_Destroy(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    DIDURL *credid = DIDURL_NewFromDid(&controller2, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "John";

    CU_ASSERT_NOT_EQUAL(-1,
            DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid, types, 2, props, 1, 0, NULL, storepass));

    controller2_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller2_doc));

    cred = DIDDocument_GetCredential(controller2_doc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);

    //update
    success = DIDDocument_PublishDID(controller2_doc, NULL, true, storepass);
    DIDDocument_Destroy(controller2_doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", controller2.idstring);

    controller2_doc = resolve_doc(&controller2, txid);
    CU_ASSERT_PTR_NOT_NULL(controller2_doc);
    printf("\n   txid = %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller2_doc));

    cred = DIDDocument_GetCredential(controller2_doc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);

    DIDURL_Destroy(credid);
}

//create controller3: one create op and two update op.
//controller3 has three keys, one selfclaimed credentials, one kyc credential and two services.
//controllers has context field.
static void test_idchain_controller3(void)
{
    DIDDocumentBuilder *builder = NULL;
    char txid[ELA_MAX_TXID_LEN] = {0};
    DIDURL *keyid1, *keyid2, *svcid1, *svcid2, *credid1, *credid2;
    Credential *vc;
    const char *props;
    bool success;
    int status;

    Features_EnableJsonLdContext(true);

    controller3_doc = RootIdentity_NewDID(rootidentity, storepass, "controller3", false);
    CU_ASSERT_PTR_NOT_NULL(controller3_doc);

    DID_Copy(&controller3, &controller3_doc->did);

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");

    builder = DIDDocument_Edit(controller3_doc, NULL);
    DIDDocument_Destroy(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    keyid1 = add_authentication_key(builder, "key1");
    keyid2 = add_authentication_key(builder, "key2");

    svcid1 = DIDURL_NewFromDid(&controller3, "test-svc-1");
    CU_ASSERT_PTR_NOT_NULL(svcid1);

    props = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\"}";
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddServiceByString(builder, svcid1, "Service.Testing1",
            "https://www.elastos.org/testing1", props));
    DIDURL_Destroy(svcid1);

    Property props1[4];
    props1[0].key = "abc";
    props1[0].value = "helloworld";
    props1[1].key = "bar";
    props1[1].value = "foobar";
    props1[2].key = "lalala...";
    props1[2].value = "ABC";
    props1[3].key = "Helloworld";
    props1[3].value = "English";

    svcid2 = DIDURL_NewFromDid(&controller3, "test-svc-2");
    CU_ASSERT_PTR_NOT_NULL(svcid2);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, svcid2, "Service.Testing2",
            "https://www.elastos.org/testing2", props1, 4));
    DIDURL_Destroy(svcid2);

    controller3_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller3_doc));

    success = DIDDocument_PublishDID(controller3_doc, keyid2, false, storepass);
    DIDDocument_Destroy(controller3_doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish controller3 result:\n   did = %s\n -- resolve begin(update) again", controller3.idstring);

    controller3_doc = resolve_doc(&controller3, txid);
    CU_ASSERT_PTR_NOT_NULL(controller3_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller3_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(controller3_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetServiceCount(controller3_doc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetCredentialCount(controller3_doc));
    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update) again, waiting...\n", txid);

    //update
    builder = DIDDocument_Edit(controller3_doc, NULL);
    DIDDocument_Destroy(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    credid1 = DIDURL_NewFromDid(&controller3, "test-cred1");
    CU_ASSERT_PTR_NOT_NULL(credid1);

    const char *types[] = {"https://elastos.org/credentials/v1#SelfProclaimedCredential",
            "https://elastos.org/credentials/profile/v1#ProfileCredential",
            "https://elastos.org/credentials/email/v1#EmailCredential",
            "https://elastos.org/credentials/social/v1#SocialCredential"};

    Property props2[1];
    props2[0].key = "name";
    props2[0].value = "John";

    CU_ASSERT_NOT_EQUAL(-1,
            DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid1, types, 4, props2, 1, 0, NULL, storepass));
    DIDURL_Destroy(credid1);

    controller3_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller3_doc));

    success = DIDDocument_PublishDID(controller3_doc, keyid1, false, storepass);
    DIDDocument_Destroy(controller3_doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update) again", controller3.idstring);

    controller3_doc = resolve_doc(&controller3, txid);
    CU_ASSERT_PTR_NOT_NULL(controller3_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller3_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(controller3_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(controller3_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetServiceCount(controller3_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(controller3_doc));
    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update) again, waiting...\n", txid);

    //update again
    builder = DIDDocument_Edit(controller3_doc, NULL);
    DIDDocument_Destroy(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    //create kyc credential
    Issuer *issuer = Issuer_Create(&controller1, NULL, store);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);

    credid2 = DIDURL_NewFromDid(&controller3, "test-cred2");
    CU_ASSERT_PTR_NOT_NULL(credid2);

    Property props3[5];
    props3[0].key = "name";
    props3[0].value = "John";
    props3[1].key = "gender";
    props3[1].value = "Male";
    props3[2].key = "nationality";
    props3[2].value = "Singapore";
    props3[3].key = "email";
    props3[3].value = "john@example.com";
    props3[4].key = "twitter";
    props3[4].value = "@john";

    vc = Issuer_CreateCredential(issuer, &controller3, credid2, types, 4, props3, 5,
            builder->document->expires, storepass);
    CU_ASSERT_PTR_NOT_NULL(vc);
    Issuer_Destroy(issuer);
    DIDURL_Destroy(credid2);
    CU_ASSERT_PTR_NOT_NULL(vc);
    CU_ASSERT_EQUAL(0, Credential_IsExpired(vc));
    CU_ASSERT_EQUAL(1, Credential_IsGenuine(vc));
    CU_ASSERT_EQUAL(1, Credential_IsValid(vc));
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreCredential(store, vc));

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddCredential(builder, vc));

    controller3_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller3_doc));

    success = DIDDocument_PublishDID(controller3_doc, keyid1, false, storepass);
    DIDDocument_Destroy(controller3_doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update) again", controller3.idstring);

    controller3_doc = resolve_doc(&controller3, txid);
    CU_ASSERT_PTR_NOT_NULL(controller3_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller3_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(controller3_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(controller3_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetServiceCount(controller3_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetCredentialCount(controller3_doc));

    printf("\n   txid = %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);

    DIDURL_Destroy(keyid1);
    DIDURL_Destroy(keyid2);

    //declare credential ----------------------------------------------
    DIDURL *signkey = DIDDocument_GetDefaultPublicKey(controller3_doc);

    CU_ASSERT_PTR_NULL(Credential_Resolve(&vc->id, &status, true));
    CU_ASSERT_EQUAL(status, CredentialStatus_NotFound);

    CU_ASSERT_EQUAL(1, Credential_Declare(vc, signkey, storepass));
    CU_ASSERT_EQUAL(1, Credential_WasDeclared(&vc->id));
    CU_ASSERT_NOT_EQUAL(1, Credential_IsRevoked(vc));

    Credential *resolve_vc1 = Credential_Resolve(&vc->id, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_vc1);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreCredential(store, resolve_vc1));

    const char *data1 = Credential_ToJson(vc, true);
    CU_ASSERT_PTR_NOT_NULL(data1);

    const char *data2 = Credential_ToJson(resolve_vc1, true);
    CU_ASSERT_PTR_NOT_NULL(data2);
    CU_ASSERT_STRING_EQUAL(data1, data2);
    free((void*)data1);
    free((void*)data2);

    CU_ASSERT_NOT_EQUAL(0, CredentialMetadata_GetPublished(&resolve_vc1->metadata));
    CU_ASSERT_PTR_NOT_NULL(CredentialMetadata_GetTxid(&resolve_vc1->metadata));
    CU_ASSERT_NOT_EQUAL(1, Credential_IsRevoked(resolve_vc1));
    CU_ASSERT_EQUAL(1, Credential_WasDeclared(&resolve_vc1->id));

    //declare again, fail.
    CU_ASSERT_NOT_EQUAL(1, Credential_Declare(vc, signkey, storepass));
    CU_ASSERT_STRING_EQUAL("Credential was already declared.", DIDError_GetLastErrorMessage());

    //revoke by random DID at first, success.
    CU_ASSERT_NOT_EQUAL(1, Credential_RevokeById(&vc->id, controller2_doc, NULL, storepass));
    CU_ASSERT_NOT_EQUAL(1, Credential_IsRevoked(vc));
    //revoke by owner again, success.
    CU_ASSERT_EQUAL(1, Credential_RevokeById(&vc->id, controller3_doc, signkey, storepass));
    CU_ASSERT_EQUAL(1, Credential_IsRevoked(vc));
    //revoke by issuer again, fail.
    CU_ASSERT_NOT_EQUAL(1, Credential_RevokeById(&vc->id, controller1_doc, NULL, storepass));
    CU_ASSERT_STRING_EQUAL("Credential is revoked.", DIDError_GetLastErrorMessage());

    //try to declare again, fail.
    CU_ASSERT_NOT_EQUAL(1, Credential_Declare(resolve_vc1, signkey, storepass));

    Credential *resolve_vc2 = Credential_Resolve(&vc->id, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_vc2);
    CU_ASSERT_EQUAL(status, CredentialStatus_Revoked);

    data1 = Credential_ToJson(resolve_vc1, true);
    data2 = Credential_ToJson(resolve_vc2, true);
    CU_ASSERT_STRING_EQUAL(data1, data2);
    free((void*)data1);
    free((void*)data2);

    Credential_Destroy(resolve_vc1);
    Credential_Destroy(resolve_vc2);

    CredentialBiography *biography = Credential_ResolveBiography(&vc->id, NULL);
    CU_ASSERT_PTR_NOT_NULL(biography);
    CU_ASSERT_EQUAL(CredentialStatus_Revoked, CredentialBiography_GetStatus(biography));
    CU_ASSERT_EQUAL(2, CredentialBiography_GetTransactionCount(biography));

    CU_ASSERT_STRING_EQUAL("revoke", CredentialBiography_GetOperationByIndex(biography, 0));
    CU_ASSERT_STRING_EQUAL("declare", CredentialBiography_GetOperationByIndex(biography, 1));
    CU_ASSERT_EQUAL(1,DIDURL_Equals(signkey, CredentialBiography_GetTransactionSignkeyByIndex(biography, 0)));
    CU_ASSERT_EQUAL(1,DIDURL_Equals(signkey, CredentialBiography_GetTransactionSignkeyByIndex(biography, 1)));

    CredentialBiography_Destroy(biography);
    Credential_Destroy(vc);

    Features_EnableJsonLdContext(false);
}

//create controller4: one create op.
//controller4 has one key and two services.
static void test_idchain_controller4(void)
{
    DIDDocumentBuilder *builder = NULL;
    char txid[ELA_MAX_TXID_LEN] = {0};
    DIDURL *keyid1, *keyid2, *svcid1, *svcid2, *credid1, *credid2;
    const char *props2;
    bool success;

    controller4_doc = RootIdentity_NewDID(rootidentity, storepass, "controller4", false);
    CU_ASSERT_PTR_NOT_NULL(controller4_doc);

    DID_Copy(&controller4, &controller4_doc->did);

    builder = DIDDocument_Edit(controller4_doc, NULL);
    DIDDocument_Destroy(controller4_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    keyid1 = add_authentication_key(builder, "key1");
    keyid2 = add_authentication_key(builder, "key2");

    svcid1 = DIDURL_NewFromDid(&controller4, "test-svc-1");
    CU_ASSERT_PTR_NOT_NULL(svcid1);

    props2 = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\"}";
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddServiceByString(builder, svcid1, "Service.Testing1",
            "https://www.elastos.org/testing1", props2));
    DIDURL_Destroy(svcid1);

    Property props1[4];
    props1[0].key = "abc";
    props1[0].value = "helloworld";
    props1[1].key = "bar";
    props1[1].value = "foobar";
    props1[2].key = "lalala...";
    props1[2].value = "ABC";
    props1[3].key = "Helloworld";
    props1[3].value = "English";

    svcid2 = DIDURL_NewFromDid(&controller4, "test-svc-2");
    CU_ASSERT_PTR_NOT_NULL(svcid2);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, svcid2, "Service.Testing2",
            "https://www.elastos.org/testing2", props1, 4));
    DIDURL_Destroy(svcid2);

    controller4_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller4_doc));

    success = DIDDocument_PublishDID(controller4_doc, keyid2, false, storepass);
    DIDDocument_Destroy(controller4_doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish controller4 result:\n   did = %s\n -- resolve begin(update) again", controller4.idstring);

    controller4_doc = resolve_doc(&controller4, txid);
    CU_ASSERT_PTR_NOT_NULL(controller4_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller4_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(controller4_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetServiceCount(controller4_doc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetCredentialCount(controller4_doc));
    printf("\n   txid = %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);

    DIDURL_Destroy(keyid1);
    DIDURL_Destroy(keyid2);
}

//create controller5: one create op.
//controller5 has one key.
static void test_idchain_controller5(void)
{
    DIDDocumentBuilder *builder = NULL;
    char txid[ELA_MAX_TXID_LEN] = {0};
    DIDURL *keyid1, *keyid2, *svcid1, *svcid2, *credid1, *credid2;
    const char *props2;
    bool success;

    controller5_doc = RootIdentity_NewDID(rootidentity, storepass, "controller5", false);
    CU_ASSERT_PTR_NOT_NULL(controller5_doc);

    DID_Copy(&controller5, &controller5_doc->did);

    success = DIDDocument_PublishDID(controller5_doc, NULL, false, storepass);
    DIDDocument_Destroy(controller5_doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish controller5 result:\n   did = %s\n -- resolve begin(update) again", controller5.idstring);

    controller5_doc = resolve_doc(&controller5, txid);
    CU_ASSERT_PTR_NOT_NULL(controller5_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, controller5_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetPublicKeyCount(controller5_doc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetServiceCount(controller5_doc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetCredentialCount(controller5_doc));
    printf("\n   txid = %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);
}

//customized did: one create and one update op.
//customized did has one own key, one service and one selfclaimed credential.
static void test_idchain_ctmdid_with_onecontroller(void)
{
    char customized_string[32] = {0};
    char txid[ELA_MAX_TXID_LEN] = {0};
    DIDURL *keyid1, *keyid2, *credid, *svcid1;
    DIDDocumentBuilder *builder;
    const char *props1;

    DID *controllers[1] = {0};
    controllers[0] = &controller1;

    CU_ASSERT_NOT_EQUAL(-1, get_customizedid(customized_string, sizeof(customized_string)));

    customized_doc = DIDDocument_NewCustomizedDID(controller1_doc, customized_string,
            NULL, 0, 0, false, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customized_doc));
    DID_Copy(&customized_did, &customized_doc->did);

    CU_ASSERT_EQUAL(1, DIDDocument_PublishDID(customized_doc, NULL, true, storepass));
    DIDDocument_Destroy(customized_doc);

    customized_doc = resolve_doc(&customized_did, txid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);

    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(customized_doc, &controller1));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));
    DIDDocument_Destroy(customized_doc);

    customized_doc = DIDStore_LoadDID(store, &customized_did);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customized_doc));

    //update
    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    keyid1 = add_authentication_key(builder, "key1");

    credid = DIDURL_NewFromDid(&customized_did, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "whisper";

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid, types, 2,
            props, 1, 0, NULL, storepass));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(4, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    CU_ASSERT_EQUAL(1, DIDDocument_PublishDID(customized_doc, keyid1, false, storepass));
    DIDDocument_Destroy(customized_doc);

    customized_doc = resolve_doc(&customized_did, txid);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customized_doc, credid))
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customized_doc, keyid1));

    //update again
    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    svcid1 = DIDURL_NewFromDid(&customized_did, "test-svc-1");
    CU_ASSERT_PTR_NOT_NULL(svcid1);

    props1 = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\"}";
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddServiceByString(builder, svcid1, "Service.Testing1",
            "https://www.elastos.org/testing1", props1));
    DIDURL_Destroy(svcid1);

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));

    CU_ASSERT_EQUAL(1, DIDDocument_PublishDID(customized_doc, keyid1, false, storepass));
    DIDDocument_Destroy(customized_doc);

    customized_doc = resolve_doc(&customized_did, txid);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customized_doc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetServiceCount(customized_doc));

    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetPublicKey(customized_doc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customized_doc, credid));

    DIDURL_Destroy(keyid1);
    DIDURL_Destroy(credid);
}

//create mulitig(2:3) document
//it has one own key, one service, one selfclaimed credential and kyc credential.
static void test_idchain_ctmdid_with_multicontroller(void)
{
    char customized_string[32] = {0};
    char txid[ELA_MAX_TXID_LEN] = {0};
    DIDURL *keyid1, *keyid2, *credid1, *credid2, *signkey1, *signkey2, *signkey3;
    DIDDocumentBuilder *builder;
    const char *data;
    char *signs[3] = {0};
    const char *sign;
    DIDDocument *doc;
    int status;

    DID *controllers[3] = {0};
    controllers[0] = &controller1;
    controllers[1] = &controller2;
    controllers[2] = &controller3;

    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey1);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey2);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey3);

    CU_ASSERT_NOT_EQUAL(-1, get_customizedid(customized_string, sizeof(customized_string)));

    //create
    multicustomized_doc = DIDDocument_NewCustomizedDID(controller2_doc, customized_string,
            controllers, 3, 0, false, storepass);
    CU_ASSERT_PTR_NULL(multicustomized_doc);

    multicustomized_doc = DIDDocument_NewCustomizedDID(controller2_doc, customized_string,
            controllers, 3, 2, false, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(multicustomized_doc);
    CU_ASSERT_NOT_EQUAL(1, DIDDocument_IsValid(multicustomized_doc));
    DID_Copy(&multicustomized_did, &multicustomized_doc->did);

    data = DIDDocument_ToJson(multicustomized_doc, true);
    CU_ASSERT_PTR_NOT_NULL(data);
    DIDDocument_Destroy(multicustomized_doc);

    multicustomized_doc = DIDDocument_SignDIDDocument(controller1_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(multicustomized_doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, multicustomized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_PublishDID(multicustomized_doc, signkey1, true, storepass));
    DIDDocument_Destroy(multicustomized_doc);

    multicustomized_doc = resolve_doc(&multicustomized_did, txid);

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(multicustomized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(multicustomized_doc, &controller1));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(multicustomized_doc, &controller2));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(multicustomized_doc, &controller3));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, multicustomized_doc));

    sign = DIDDocument_GetProofSignature(multicustomized_doc, 0);
    signs[0] = alloca(strlen(sign) + 1);
    strcpy(signs[0], sign);

    DIDDocument_Destroy(multicustomized_doc);

    multicustomized_doc = DIDStore_LoadDID(store, &multicustomized_did);
    CU_ASSERT_PTR_NOT_NULL(multicustomized_doc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(multicustomized_doc));

    //update
    builder = DIDDocument_Edit(multicustomized_doc, controller2_doc);
    DIDDocument_Destroy(multicustomized_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    keyid1 = add_authentication_key(builder, "key1");

    credid1 = DIDURL_NewFromDid(&multicustomized_did, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid1);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "cici";

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid1, types, 2,
            props, 1, 0, signkey3, storepass));

    //create kyc credential
    DIDURL *signkey = DIDURL_NewFromDid(&customized_did, "key1");
    Issuer *issuer = Issuer_Create(&customized_did, signkey, store);
    DIDURL_Destroy(signkey);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);

    credid2 = DIDURL_NewFromDid(&multicustomized_did, "cred-2");
    CU_ASSERT_PTR_NOT_NULL(credid2);

    const char *types2[] = { "https://elastos.org/credentials/v1#SelfProclaimedCredential",
            "https://elastos.org/credentials/profile/v1#ProfileCredential",
            "https://elastos.org/credentials/email/v1#EmailCredential",
            "https://elastos.org/credentials/social/v1#SocialCredential" };

    Property props2[5];
    props2[0].key = "name";
    props2[0].value = "John";
    props2[1].key = "gender";
    props2[1].value = "Male";
    props2[2].key = "nationality";
    props2[2].value = "Singapore";
    props2[3].key = "email";
    props2[3].value = "john@example.com";
    props2[4].key = "twitter";
    props2[4].value = "@john";

    Credential *vc = Issuer_CreateCredential(issuer, &multicustomized_did, credid2, types2, 4, props2, 5,
            builder->document->expires, storepass);
    CU_ASSERT_PTR_NOT_NULL(vc);
    Issuer_Destroy(issuer);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddCredential(builder, vc));
    Credential_Destroy(vc);

    multicustomized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(multicustomized_doc);

    data = DIDDocument_ToJson(multicustomized_doc, true);
    DIDDocument_Destroy(multicustomized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    multicustomized_doc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(multicustomized_doc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, multicustomized_doc));

    //the count of signers is larger than multisig, fail.
    builder = DIDDocument_Edit(multicustomized_doc, controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    CU_ASSERT_PTR_NULL(DIDDocumentBuilder_Seal(builder, storepass));
    CU_ASSERT_STRING_EQUAL("The signers are enough.", DIDError_GetLastErrorMessage());
    DIDDocumentBuilder_Destroy(builder);

    //must be sepcify the sign key
    CU_ASSERT_NOT_EQUAL(1, DIDDocument_PublishDID(multicustomized_doc, NULL, true, storepass));
    CU_ASSERT_STRING_EQUAL("Multi-controller customized DID must have signkey to publish.",
            DIDError_GetLastErrorMessage());
    CU_ASSERT_EQUAL(1, DIDDocument_PublishDID(multicustomized_doc, keyid1, true, storepass));
    DIDDocument_Destroy(multicustomized_doc);

    multicustomized_doc = resolve_doc(&multicustomized_did, txid);
    CU_ASSERT_PTR_NOT_NULL(multicustomized_doc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, multicustomized_doc));

    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(multicustomized_doc, credid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(multicustomized_doc, credid2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(multicustomized_doc, keyid1));

    sign = DIDDocument_GetProofSignature(multicustomized_doc, 0);
    signs[1] = alloca(strlen(sign) + 1);
    strcpy(signs[1], sign);

    DIDDocument_Destroy(multicustomized_doc);

    //update again
    multicustomized_doc = DIDStore_LoadDID(store, &multicustomized_did);
    CU_ASSERT_PTR_NOT_NULL(multicustomized_doc);

    builder = DIDDocument_Edit(multicustomized_doc, controller3_doc);
    DIDDocument_Destroy(multicustomized_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    keyid2 = add_authentication_key(builder, "key2");

    multicustomized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(multicustomized_doc);

    data = DIDDocument_ToJson(multicustomized_doc, true);
    DIDDocument_Destroy(multicustomized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    multicustomized_doc = DIDDocument_SignDIDDocument(controller2_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(multicustomized_doc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, multicustomized_doc));

    CU_ASSERT_EQUAL(9, DIDDocument_GetPublicKeyCount(multicustomized_doc));
    CU_ASSERT_EQUAL(9, DIDDocument_GetAuthenticationCount(multicustomized_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetCredentialCount(multicustomized_doc));

    CU_ASSERT_EQUAL(1, DIDDocument_PublishDID(multicustomized_doc, signkey3, false, storepass));
    DIDDocument_Destroy(multicustomized_doc);

    multicustomized_doc = resolve_doc(&multicustomized_did, txid);

    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(multicustomized_doc, credid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(multicustomized_doc, credid2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(multicustomized_doc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(multicustomized_doc, keyid2));

    sign = DIDDocument_GetProofSignature(multicustomized_doc, 0);
    signs[2] = alloca(strlen(sign) + 1);
    strcpy(signs[2], sign);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, multicustomized_doc));

    //DIDBiography
    DIDBiography *biography = DID_ResolveBiography(&multicustomized_did);
    CU_ASSERT_PTR_NOT_NULL_FATAL(biography);
    CU_ASSERT_EQUAL(3, DIDBiography_GetTransactionCount(biography));
    CU_ASSERT_EQUAL(0, DIDBiography_GetStatus(biography));

    DID *owner = DIDBiography_GetOwner(biography);
    CU_ASSERT_PTR_NOT_NULL_FATAL(owner);
    CU_ASSERT_EQUAL_FATAL(1, DID_Equals(&multicustomized_did, owner));

    for (int i = 0; i < 3; i++) {
        doc = DIDBiography_GetDocumentByIndex(biography, i);
        CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
        CU_ASSERT_STRING_EQUAL(signs[2-i], DIDDocument_GetProofSignature(doc, 0));
        DIDDocument_Destroy(doc);
    }
    DIDBiography_Destroy(biography);

    //revoke credid1: ----------------------------------------
    vc = DIDStore_LoadCredential(store, &credid1->did, credid1);
    //revoke random did
    signkey = DIDDocument_GetDefaultPublicKey(controller5_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey);
    CU_ASSERT_NOT_EQUAL(1, Credential_Revoke(vc, signkey, storepass));
    CU_ASSERT_NOT_EQUAL(1, Credential_IsRevoked(vc));

    //revoke by owner
    signkey = DIDURL_NewFromDid(&controller3, "key1");
    CU_ASSERT_PTR_NOT_NULL(signkey);
    CU_ASSERT_EQUAL(1, Credential_Revoke(vc, signkey, storepass));
    CU_ASSERT_EQUAL(1, Credential_IsRevoked(vc));

    Credential *resolvevc = Credential_Resolve(&vc->id, &status, true);
    CU_ASSERT_PTR_NULL(resolvevc);
    CU_ASSERT_EQUAL(status, CredentialStatus_Revoked);
    CU_ASSERT_EQUAL(1, Credential_ResolveRevocation(&vc->id, &vc->issuer));

    CU_ASSERT_NOT_EQUAL(1, Credential_Declare(vc, signkey, storepass));

    CU_ASSERT_EQUAL(status, CredentialStatus_Revoked);
    CU_ASSERT_EQUAL(1, Credential_ResolveRevocation(&vc->id, &vc->issuer));
    CU_ASSERT_EQUAL(1, Credential_IsRevoked(vc));
    CU_ASSERT_NOT_EQUAL(1, Credential_WasDeclared(&vc->id));
    Credential_Destroy(vc);

    //resolve credid1 biography
    CredentialBiography *vc_biography = Credential_ResolveBiography(credid1, NULL);
    CU_ASSERT_PTR_NOT_NULL(vc_biography);
    CU_ASSERT_EQUAL(CredentialStatus_Revoked, CredentialBiography_GetStatus(vc_biography));
    CU_ASSERT_EQUAL(1, CredentialBiography_GetTransactionCount(vc_biography));

    CU_ASSERT_STRING_EQUAL("revoke", CredentialBiography_GetOperationByIndex(vc_biography, 0));
    CU_ASSERT_EQUAL(1,DIDURL_Equals(signkey, CredentialBiography_GetTransactionSignkeyByIndex(vc_biography, 0)));
    DIDURL_Destroy(signkey);
    CredentialBiography_Destroy(vc_biography);

    //revoke credid2: ------------------------------------------
    vc = DIDStore_LoadCredential(store, &credid2->did, credid2);
    CU_ASSERT_PTR_NOT_NULL(vc);
    CU_ASSERT_EQUAL(0, Credential_IsRevoked(vc));

    //revoke vc by random did, failed.
    signkey = DIDDocument_GetDefaultPublicKey(controller5_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey);
    CU_ASSERT_NOT_EQUAL(1, Credential_Revoke(vc, signkey, storepass));
    CU_ASSERT_NOT_EQUAL(1, Credential_IsRevoked(vc));

    //revoke id by random did, success.
    CU_ASSERT_EQUAL(1, Credential_RevokeById(credid2, controller5_doc, signkey, storepass));
    CU_ASSERT_EQUAL(0, Credential_IsRevoked(vc));
    CU_ASSERT_EQUAL(1, Credential_ResolveRevocation(credid2, &controller5));

    //revoke id by issuer, success.
    signkey = DIDURL_NewFromDid(&customized_did, "key1");
    CU_ASSERT_PTR_NOT_NULL(signkey);

    CU_ASSERT_EQUAL(1, Credential_RevokeById(credid2, customized_doc, signkey, storepass));
    CU_ASSERT_EQUAL(1, Credential_IsRevoked(vc));
    CU_ASSERT_EQUAL(1, Credential_ResolveRevocation(credid2, &customized_did));

    //revoke id by owner, success.
    CU_ASSERT_EQUAL(1, Credential_RevokeById(credid2, multicustomized_doc, keyid1, storepass));
    CU_ASSERT_EQUAL(1, Credential_IsRevoked(vc));

    CU_ASSERT_PTR_NULL(Credential_Resolve(credid1, &status, true));
    CU_ASSERT_EQUAL(CredentialStatus_Revoked, status);

    CU_ASSERT_PTR_NULL(Credential_Resolve(credid2, &status, true));
    CU_ASSERT_EQUAL(CredentialStatus_Revoked, status);

    //resolve credid1 biography
    vc_biography = Credential_ResolveBiography(credid2, &customized_did);
    CU_ASSERT_PTR_NOT_NULL(vc_biography);
    CU_ASSERT_EQUAL(CredentialStatus_Revoked, CredentialBiography_GetStatus(vc_biography));
    CU_ASSERT_EQUAL(1, CredentialBiography_GetTransactionCount(vc_biography));

    CU_ASSERT_STRING_EQUAL("revoke", CredentialBiography_GetOperationByIndex(vc_biography, 0));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(signkey, CredentialBiography_GetTransactionSignkeyByIndex(vc_biography, 0)));
    DIDURL_Destroy(signkey);

    Credential_Destroy(vc);
    CredentialBiography_Destroy(vc_biography);

    DIDURL_Destroy(keyid1);
    DIDURL_Destroy(keyid2);
    DIDURL_Destroy(credid1);
    DIDURL_Destroy(credid2);
}

static void test_transfer_ctmdid_with_onecontroller(void)
{
    char customized_string[32] = {0}, txid[ELA_MAX_TXID_LEN] = {0};
    DIDDocument *customizedoc;
    DID customizedid;
    DIDURL *keyid1, *keyid2, *credid, *signkey1, *signkey2;
    DIDDocumentBuilder *builder;
    TransferTicket *ticket;
    const char *data, *sub;
    int count = 0, i, status;

    Features_EnableJsonLdContext(true);

    DID *controllers[1] = {0};
    controllers[0] = &controller1;

    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey1);

    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey2);

    CU_ASSERT_NOT_EQUAL(-1, get_customizedid(customized_string, sizeof(customized_string)));

    //create
    customizedoc = DIDDocument_NewCustomizedDID(controller1_doc, customized_string,
            controllers, 1, 0, false, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customizedoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    DID_Copy(&customizedid, &customizedoc->did);

    builder = DIDDocument_Edit(customizedoc, NULL);
    DIDDocument_Destroy(customizedoc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    keyid1 = add_authentication_key(builder, "key1");

    credid = DIDURL_NewFromDid(&customizedid, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types1[] = { "https://elastos.org/credentials/v1#SelfProclaimedCredential",
            "https://elastos.org/credentials/profile/v1#ProfileCredential",
            "https://elastos.org/credentials/email/v1#EmailCredential",
            "https://elastos.org/credentials/social/v1#SocialCredential" };

    Property props[8];
    for (i = 0; i < 8; i++) {
        sub = get_i18n_content(I18N[i]);
        if (!sub)
            continue;

        props[i].key = (char*)I18N[i];
        props[i].value = (char*)sub;
        count++;
    }

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid, types1, 4,
            props, count, 0, NULL, storepass));

    for (i = 0; i < count; i++)
        free((void*)props[i].value);

    customizedoc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);
    CU_ASSERT_EQUAL(4, DIDDocument_GetPublicKeyCount(customizedoc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetAuthenticationCount(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customizedoc));
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customizedoc));

    CU_ASSERT_EQUAL(1, DIDDocument_PublishDID(customizedoc, keyid1, false, storepass));
    DIDDocument_Destroy(customizedoc);

    customizedoc = resolve_doc(&customizedid, txid);

    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(customizedoc, &controller1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customizedoc, credid));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customizedoc));
    DIDDocument_Destroy(customizedoc);

    customizedoc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));

    //update
    //Not set controller doc, fail.
    builder = DIDDocument_Edit(customizedoc, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, &controller2));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 1));
    CU_ASSERT_PTR_NULL(DIDDocumentBuilder_Seal(builder, storepass));
    CU_ASSERT_STRING_EQUAL("Please specify the controller to seal multi-controller document.",
           DIDError_GetLastErrorMessage());
    DIDDocumentBuilder_Destroy(builder);

    //Not set multisig for multi-controller DID, fail.
    builder = DIDDocument_Edit(customizedoc, controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, &controller2));
    CU_ASSERT_PTR_NULL(DIDDocumentBuilder_Seal(builder, storepass));
    CU_ASSERT_STRING_EQUAL("Please set multisig first for multi-controller DID.",
           DIDError_GetLastErrorMessage());
    DIDDocumentBuilder_Destroy(builder);

    //success
    builder = DIDDocument_Edit(customizedoc, controller1_doc);
    DIDDocument_Destroy(customizedoc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, &controller2));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 1));

    keyid2 = add_authentication_key(builder, "key2");

    customizedoc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);

    //check
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetMultisig(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customizedoc));
    CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(customizedoc));
    CU_ASSERT_EQUAL(6, DIDDocument_GetAuthenticationCount(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customizedoc));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customizedoc));

    //create ticket
    ticket = DIDDocument_CreateTransferTicket(controller1_doc, &customizedid,
            &controller1, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_EQUAL(1, TransferTicket_IsValid(ticket));

    CU_ASSERT_EQUAL(1, DIDDocument_TransferDID(customizedoc, ticket, signkey1, storepass));
    DIDDocument_Destroy(customizedoc);
    TransferTicket_Destroy(ticket);

    customizedoc = resolve_doc(&customizedid, txid);

    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetMultisig(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customizedoc));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customizedoc, credid));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customizedoc));

    //update again
    builder = DIDDocument_Edit(customizedoc, controller2_doc);
    DIDDocument_Destroy(customizedoc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller1));
    CU_ASSERT_STRING_EQUAL("There are self-proclaimed credentials signed by controller, please remove or renew these credentials at first.", DIDError_GetLastErrorMessage());
    CU_ASSERT_NOT_EQUAL(-1,
            DIDDocumentBuilder_RenewSelfProclaimedCredential(builder, &controller1, signkey2, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller1));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, keyid1));

    //controller1 is removed, selfclaimed credential signed by controller1 is invalid.
    customizedoc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);

    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customizedoc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetMultisig(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customizedoc));
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid2));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customizedoc, credid));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customizedoc));

    ticket = DIDDocument_CreateTransferTicket(controller1_doc, &customizedid,
            &controller2, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_EQUAL(1, TransferTicket_IsValid(ticket));

    CU_ASSERT_EQUAL(1, DIDDocument_TransferDID(customizedoc, ticket, signkey2, storepass));
    DIDDocument_Destroy(customizedoc);
    TransferTicket_Destroy(ticket);

    customizedoc = resolve_doc(&customizedid, txid);

    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customizedoc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetMultisig(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customizedoc));
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid2));

    //declare vc
    Credential *cred = DIDStore_LoadCredential(store, &credid->did, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);

    CU_ASSERT_EQUAL(1, Credential_Declare(cred, signkey2, storepass));

    data = Credential_ToJson(cred, true);
    CU_ASSERT_PTR_NOT_NULL(data);

    Credential *vc = Credential_Resolve(credid, &status, true);
    CU_ASSERT_PTR_NOT_NULL(vc);
    CU_ASSERT_EQUAL(1, Credential_IsValid(vc));

    const char *data1 = Credential_ToJson(vc, true);
    CU_ASSERT_PTR_NOT_NULL(data1);
    CU_ASSERT_STRING_EQUAL(data, data1);
    free((void*)data);
    free((void*)data1);

    DIDURL_Destroy(keyid1);
    DIDURL_Destroy(keyid2);
    DIDURL_Destroy(credid);
    Credential_Destroy(cred);
    Credential_Destroy(vc);
    DIDDocument_Destroy(customizedoc);

    Features_EnableJsonLdContext(false);
}

//add controller
static void test_transfer_ctmdid_with_multicontroller(void)
{
    char customized_string[32] = {0}, txid[ELA_MAX_TXID_LEN] = {0};
    DIDDocument *customizedoc;
    DID customizedid;
    DIDURL *keyid1, *keyid2, *credid, *signkey1, *signkey2, *signkey3, *creater;
    DIDDocumentBuilder *builder;
    TransferTicket *ticket;
    Credential *cred;
    const char *data;
    size_t size;
    int i;

    DID *controllers[3] = {0};
    controllers[0] = &controller1;
    controllers[1] = &controller2;
    controllers[2] = &controller3;

    CU_ASSERT_NOT_EQUAL(-1, get_customizedid(customized_string, sizeof(customized_string)));

    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey1);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey2);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey3);

    //create -----------------------------------------
    customizedoc = DIDDocument_NewCustomizedDID(controller2_doc, customized_string,
            controllers, 3, 0, false, storepass);
    CU_ASSERT_PTR_NULL(customizedoc);

    customizedoc = DIDDocument_NewCustomizedDID(controller2_doc, customized_string,
            controllers, 3, 2, false, storepass);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);
    CU_ASSERT_NOT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    DID_Copy(&customizedid, &customizedoc->did);

    builder = DIDDocument_Edit(customizedoc, controller2_doc);
    DIDDocument_Destroy(customizedoc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    keyid1 = add_authentication_key(builder, "key1");

    credid = DIDURL_NewFromDid(&customizedid, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "jack";

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid, types, 2,
            props, 1, 0, signkey1, storepass));

    customizedoc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);

    data = DIDDocument_ToJson(customizedoc, true);
    DIDDocument_Destroy(customizedoc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customizedoc = DIDDocument_SignDIDDocument(controller2_doc, data, storepass);
    CU_ASSERT_PTR_NULL(customizedoc);
    CU_ASSERT_STRING_EQUAL("The controller already signed the DID.",
           DIDError_GetLastErrorMessage());

    customizedoc = DIDDocument_SignDIDDocument(controller1_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customizedoc));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customizedoc, credid));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid1));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customizedoc));

    CU_ASSERT_EQUAL(1, DIDDocument_PublishDID(customizedoc, signkey1, true, storepass));
    DIDDocument_Destroy(customizedoc);

    customizedoc = resolve_doc(&customizedid, txid);

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customizedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetMultisig(customizedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetProofCount(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customizedoc));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customizedoc, credid));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(customizedoc, &controller1));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(customizedoc, &controller2));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(customizedoc, &controller3));

    size = DIDDocument_GetProofCount(customizedoc);
    CU_ASSERT_EQUAL(2, size);

    for (i = 0; i < size; i++) {
        creater = DIDDocument_GetProofCreater(customizedoc, i);
        CU_ASSERT_PTR_NOT_NULL(creater);
        CU_ASSERT_EQUAL(1, DID_Equals(&creater->did, &controller1) || DID_Equals(&creater->did, &controller2));
    }

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customizedoc));
    DIDDocument_Destroy(customizedoc);

    customizedoc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));

    //update ——-------------------------------------------------
    builder = DIDDocument_Edit(customizedoc, controller2_doc);
    DIDDocument_Destroy(customizedoc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller1));
    CU_ASSERT_STRING_EQUAL("There are self-proclaimed credentials signed by controller, please remove or renew these credentials at first.", DIDError_GetLastErrorMessage());
    CU_ASSERT_NOT_EQUAL(-1,
            DIDDocumentBuilder_RenewSelfProclaimedCredential(builder, &controller1, signkey2, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller1));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 2));

    keyid2 = add_authentication_key(builder, "key2");

    customizedoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);
    DIDDocumentBuilder_Destroy(builder);

    data = DIDDocument_ToJson(customizedoc, true);
    DIDDocument_Destroy(customizedoc);
    CU_ASSERT_PTR_NOT_NULL(data);

    CU_ASSERT_PTR_NULL(DIDDocument_SignDIDDocument(controller1_doc, data, storepass));
    customizedoc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);

    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    CU_ASSERT_EQUAL(6, DIDDocument_GetAuthenticationCount(customizedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(customizedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetMultisig(customizedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetProofCount(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customizedoc));
    cred = DIDDocument_GetCredential(customizedoc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);
    CU_ASSERT_EQUAL(1,DIDURL_Equals(signkey2, Credential_GetProofMethod(cred)));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customizedoc));

    //publish DID after changing controller, fail.
    CU_ASSERT_NOT_EQUAL(1, DIDDocument_PublishDID(customizedoc, signkey2, false, storepass));

    CU_ASSERT_STRING_EQUAL("Can't publish DID which is changed controller, please transfer it.",
            DIDError_GetLastErrorMessage());

    //the DID sign ticket is only one, fail.
    ticket = DIDDocument_CreateTransferTicket(controller1_doc, &customizedid,
            &controller2, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_NOT_EQUAL(1, TransferTicket_IsValid(ticket));

    CU_ASSERT_NOT_EQUAL(1, DIDDocument_TransferDID(customizedoc, ticket, signkey2, storepass));
    CU_ASSERT_STRING_EQUAL("Ticket isn't valid.", DIDError_GetLastErrorMessage());
    TransferTicket_Destroy(ticket);

    //controller1 is removed, fail.
    ticket = DIDDocument_CreateTransferTicket(controller1_doc, &customizedid,
            &controller1, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignTransferTicket(controller3_doc, ticket, storepass));
    CU_ASSERT_EQUAL(1, TransferTicket_IsValid(ticket));

    CU_ASSERT_NOT_EQUAL(1, DIDDocument_TransferDID(customizedoc, ticket, signkey2, storepass));
    CU_ASSERT_STRING_EQUAL("DID to receive ticket isn't document's signer.",
            DIDError_GetLastErrorMessage());
    TransferTicket_Destroy(ticket);

    //success
    ticket = DIDDocument_CreateTransferTicket(controller1_doc, &customizedid,
            &controller2, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignTransferTicket(controller2_doc, ticket, storepass));
    CU_ASSERT_EQUAL(1, TransferTicket_IsValid(ticket));

    CU_ASSERT_EQUAL(1, DIDDocument_TransferDID(customizedoc, ticket, signkey2, storepass));
    DIDDocument_Destroy(customizedoc);
    TransferTicket_Destroy(ticket);

    customizedoc = resolve_doc(&customizedid, txid);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customizedoc));

    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    CU_ASSERT_EQUAL(6, DIDDocument_GetAuthenticationCount(customizedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(customizedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetMultisig(customizedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetProofCount(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customizedoc));
    cred = DIDDocument_GetCredential(customizedoc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);
    CU_ASSERT_EQUAL(1,DIDURL_Equals(signkey2, Credential_GetProofMethod(cred)));
    DIDDocument_Destroy(customizedoc);

    //update again ------------------------------------------------------------
    customizedoc = DIDStore_LoadDID(store, &customizedid);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);

    builder = DIDDocument_Edit(customizedoc, controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(customizedoc);

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller3));
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller2));
    CU_ASSERT_STRING_EQUAL("There are self-proclaimed credentials signed by controller, please remove or renew these credentials at first.", DIDError_GetLastErrorMessage());
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveSelfProclaimedCredential(builder,
            &controller2));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, &controller2));

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 2));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, keyid1));

    customizedoc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, customizedoc));

    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetAuthenticationCount(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customizedoc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetMultisig(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customizedoc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetCredentialCount(customizedoc));
    CU_ASSERT_PTR_NULL(DIDDocument_GetCredential(customizedoc, credid));
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid2));

    //create ticket
    ticket = DIDDocument_CreateTransferTicket(controller2_doc, &customizedid,
            &controller3, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);

    data = TransferTicket_ToJson(ticket);
    TransferTicket_Destroy(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_NOT_EQUAL(1, TransferTicket_IsValid(ticket));

    CU_ASSERT_NOT_EQUAL(1, DIDDocument_TransferDID(customizedoc, ticket, keyid2, storepass));
    CU_ASSERT_STRING_EQUAL("Ticket isn't valid.", DIDError_GetLastErrorMessage());

    CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignTransferTicket(controller3_doc, ticket, storepass));
    CU_ASSERT_EQUAL(1, TransferTicket_IsValid(ticket));
    CU_ASSERT_EQUAL(1, DIDDocument_TransferDID(customizedoc, ticket, keyid2, storepass));
    DIDDocument_Destroy(customizedoc);
    TransferTicket_Destroy(ticket);

    customizedoc = resolve_doc(&customizedid, txid);
    CU_ASSERT_PTR_NOT_NULL(customizedoc);

    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customizedoc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetAuthenticationCount(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customizedoc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetMultisig(customizedoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetProofCount(customizedoc));
    CU_ASSERT_EQUAL(0, DIDDocument_GetCredentialCount(customizedoc));
    CU_ASSERT_PTR_NULL(DIDDocument_GetCredential(customizedoc, credid));
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid1));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customizedoc, keyid2));

    DIDURL_Destroy(keyid1);
    DIDURL_Destroy(keyid2);
    DIDURL_Destroy(credid);

    DIDDocument_Destroy(customizedoc);
}

static void test_idchain_deactivedid_after_create(void)
{
    char txid[ELA_MAX_TXID_LEN] = {0};
    DIDDocument *resolvedoc = NULL, *doc;
    const char *mnemonic;
    bool success;
    DID did;
    int i = 0, status;

    doc = RootIdentity_NewDID(rootidentity, storepass, "littlefish", false);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    success = DIDDocument_PublishDID(doc, NULL, false, storepass);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = resolve_doc(&did, txid);

    const char *data1 = DIDDocument_ToJson(doc, true);
    const char *data2 = DIDDocument_ToJson(resolvedoc, true);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;
    CU_ASSERT_STRING_EQUAL(data1, data2);
    free((void*)data1);
    free((void*)data2);

    success = DIDDocument_DeactivateDID(doc, NULL, storepass);
    DIDDocument_Destroy(doc);
    CU_ASSERT_EQUAL(1, success);

    i = 0;
    while(!resolvedoc || status != DIDStatus_Deactivated) {
        if (resolvedoc)
            DIDDocument_Destroy(resolvedoc);

        sleep(5);
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            break;
        } else {
            printf(".");
        }

        if (++i >= 20)
            CU_FAIL_FATAL("deactive did timeout!!!!\n");
    }

    printf("\n-- resolve result: successfully!\n------------------------------------------------------------\n");
    DIDDocument_Destroy(resolvedoc);
}

static void test_idchain_deactivedid_after_update(void)
{
    DIDURL *signkey;
    DIDDocument *resolvedoc = NULL, *doc;
    char txid[ELA_MAX_TXID_LEN] = {0}, *alias = "littlefish";
    bool success;
    DID did;
    int i = 0, status;

    //create
    doc = RootIdentity_NewDID(rootidentity, storepass, alias, false);
    CU_ASSERT_PTR_NOT_NULL(doc);

    signkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    success = DIDDocument_PublishDID(doc, signkey, false, storepass);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = resolve_doc(&did, txid);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolvedoc));

    CU_ASSERT_STRING_EQUAL(DIDDocument_GetProofSignature(doc, 0), DIDDocument_GetProofSignature(resolvedoc, 0));
    DIDDocument_Destroy(doc);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    DIDURL *keyid = add_authentication_key(builder, "key1");
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, doc));

    success = DIDDocument_PublishDID(doc, NULL, false, storepass);
    DIDDocument_Destroy(doc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    doc = resolve_doc(&did, txid);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    printf("\n-- resolve result: successfully!\n-- deactive did begin, waiting...\n");

    success = DIDDocument_DeactivateDID(doc, NULL, storepass);
    CU_ASSERT_EQUAL_FATAL(1, success);
    DIDDocument_Destroy(doc);
    doc = NULL;
    printf("-- deactive did result:\n   did = %s\n -- resolve begin(deactive)", did.idstring);

    i = 0;
    while(!doc || status != DIDStatus_Deactivated) {
        if (doc)
            DIDDocument_Destroy(doc);

        sleep(5);
        doc = DID_Resolve(&did, &status, true);
        if (!doc) {
            break;
        } else {
            printf(".");
        }

        if (++i >= 20)
            CU_FAIL_FATAL("deactive did timeout!!!!\n");
    }

    printf("\n-- resolve result: successfully!\n------------------------------------------------------------\n");
    DIDDocument_Destroy(doc);
}

static void test_idchain_deactivedid_with_authorization1(void)
{
    DIDDocument *resolvedoc = NULL, *targetdoc, *authorizordoc = NULL;
    const char *alias = "littlefish";
    char txid[ELA_MAX_TXID_LEN] = {0};
    DID controller, did;
    PublicKey *pks[1];
    bool success;
    int i = 0, status;

    authorizordoc = RootIdentity_NewDID(rootidentity, storepass, alias, false);
    CU_ASSERT_PTR_NOT_NULL(authorizordoc);

    DID_Copy(&controller, DIDDocument_GetSubject(authorizordoc));

    printf("\n------------------------------------------------------------\n-- publish authorization did begin(create), waiting....\n");
    success = DIDDocument_PublishDID(authorizordoc, NULL, false, storepass);
    DIDDocument_Destroy(authorizordoc);
    authorizordoc = NULL;
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", controller.idstring);

    authorizordoc = resolve_doc(&controller, txid);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, authorizordoc));

    printf("\n   txid: %s\n-- resolve authorization result: successfully!\n", txid);

    targetdoc = RootIdentity_NewDID(rootidentity, storepass, alias, false);
    CU_ASSERT_PTR_NOT_NULL(targetdoc);

    DID_Copy(&did, DIDDocument_GetSubject(targetdoc));

    DIDDocumentBuilder *builder = DIDDocument_Edit(targetdoc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(targetdoc);

    DIDURL *keyid = DIDURL_NewFromDid(&did, "recovery");
    CU_ASSERT_PTR_NOT_NULL(keyid);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AuthorizeDid(builder, keyid, &controller, NULL));
    DIDURL_Destroy(keyid);

    targetdoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(targetdoc);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(targetdoc));

    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationKeys(targetdoc, pks, sizeof(pks)/sizeof(PublicKey*)));
    CU_ASSERT_EQUAL(1, DID_Equals(&did, &pks[0]->id.did));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, targetdoc));

    printf("-- publish target did begin(create), waiting....\n");
    success = DIDDocument_PublishDID(targetdoc, NULL, false, storepass);
    DIDDocument_Destroy(targetdoc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    *txid = 0;
    targetdoc = resolve_doc(&did, txid);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, targetdoc));
    DIDDocument_Destroy(targetdoc);
    targetdoc = NULL;
    printf("\n-- resolve authorization result: successfully!\n");

    success = DIDDocument_DeactivateDIDByAuthorizor(authorizordoc, &did, NULL, storepass);
    CU_ASSERT_EQUAL(1, success);
    DIDDocument_Destroy(authorizordoc);
    printf("-- deactive did result:\n   did = %s\n -- resolve begin(deactive)", did.idstring);

    i = 0;
    while(!targetdoc || status != DIDStatus_Deactivated) {
        if (targetdoc)
            DIDDocument_Destroy(targetdoc);

        sleep(5);
        targetdoc = DID_Resolve(&did, &status, true);
        if (!targetdoc) {
            break;
        } else {
            printf(".");
        }

        if (++i >= 20)
            CU_FAIL_FATAL("deactive did timeout!!!!\n");
    }

    printf("\n-- resolve target result: successfully!\n------------------------------------------------------------\n");
    DIDDocument_Destroy(targetdoc);
}

static void test_idchain_deactivedid_with_authorization2(void)
{
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    DIDDocument *resolvedoc = NULL, *authorizordoc = NULL, *targetdoc;
    const char *keybase, *alias = "littlefish";
    char txid[ELA_MAX_TXID_LEN] = {0};
    HDKey _dkey, *dkey;
    DID controller, did;
    PublicKey *pks[1];
    bool equal, success;
    int i = 0, status;

    authorizordoc = RootIdentity_NewDID(rootidentity, storepass, alias, false);
    CU_ASSERT_PTR_NOT_NULL(authorizordoc);

    DID_Copy(&controller, DIDDocument_GetSubject(authorizordoc));

    DIDDocumentBuilder *builder = DIDDocument_Edit(authorizordoc, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(authorizordoc);

    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);

    DIDURL *signkey = DIDURL_NewFromDid(&controller, "key2");
    CU_ASSERT_PTR_NOT_NULL(signkey);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StorePrivateKey(store, storepass, signkey,
            HDKey_GetPrivateKey(dkey), PRIVATEKEY_BYTES));

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, signkey, keybase));

    authorizordoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(authorizordoc);
    DIDDocumentBuilder_Destroy(builder);

    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(authorizordoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(authorizordoc));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, authorizordoc));

    printf("\n------------------------------------------------------------\n-- publish authorization did begin(create), waiting....\n");
    success = DIDDocument_PublishDID(authorizordoc, NULL, false, storepass);
    DIDDocument_Destroy(authorizordoc);
    authorizordoc = NULL;
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", controller.idstring);

    authorizordoc = resolve_doc(&controller, txid);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, authorizordoc));
    printf("\n   txid: %s\n-- resolve authorization result: successfully!\n", txid);

    targetdoc = RootIdentity_NewDID(rootidentity, storepass, alias, false);
    CU_ASSERT_PTR_NOT_NULL(targetdoc);

    builder = DIDDocument_Edit(targetdoc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);

    DID_Copy(&did, DIDDocument_GetSubject(targetdoc));
    DIDDocument_Destroy(targetdoc);

    DIDURL *keyid = DIDURL_NewFromDid(&did, "recovery");
    CU_ASSERT_PTR_NOT_NULL(keyid);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, keyid, &controller, keybase));

    targetdoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(targetdoc);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(targetdoc));

    size_t size = DIDDocument_GetAuthorizationKeys(targetdoc, pks, sizeof(pks));
    CU_ASSERT_EQUAL(1, size);
    CU_ASSERT_EQUAL(1, DID_Equals(&did, &pks[0]->id.did));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, targetdoc));

    printf("-- publish target did begin(create), waiting....\n");
    success = DIDDocument_PublishDID(targetdoc, NULL, false, storepass);
    DIDDocument_Destroy(targetdoc);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    *txid = 0;
    targetdoc = resolve_doc(&did, txid);

    printf("\n   txid: %s\n-- resolve target result: successfully!", txid);
    DIDDocument_Destroy(targetdoc);
    targetdoc = NULL;

    success = DIDDocument_DeactivateDIDByAuthorizor(authorizordoc, &did, signkey, storepass);
    CU_ASSERT_EQUAL_FATAL(1, success);
    printf("-- deactive did result:\n   did = %s\n -- resolve begin(deactive)", did.idstring);

    i = 0;
    while(!targetdoc || status != DIDStatus_Deactivated) {
        if (targetdoc)
            DIDDocument_Destroy(targetdoc);

        sleep(5);
        targetdoc = DID_Resolve(&did, &status, true);
        if (!targetdoc) {
            break;
        } else {
            printf(".");
        }

        if (++i >= 20)
            CU_FAIL_FATAL("deactive did timeout!!!!\n");
    }

    printf("\n-- resolve result: successfully!\n------------------------------------------------------------\n");
    DIDDocument_Destroy(targetdoc);
    DIDDocument_Destroy(authorizordoc);
    DIDURL_Destroy(signkey);
    DIDURL_Destroy(keyid);
}

static void test_idchain_listvc_pagination(void)
{
    Credential *vc;
    DIDDocument *document, *issuerdoc;
    DIDURL *credid, *vcid;
    DIDURL *buffer[560] = {0};
    char fragment[120] = {0};
    Issuer *issuer;
    DID did, issuerid;
    time_t expires;
    int i, status = 0, skip, limit, index;
    ssize_t size;

    //create owner document
    document = RootIdentity_NewDID(rootidentity, storepass, NULL, false);
    CU_ASSERT_PTR_NOT_NULL(document);
    DID_Copy(&did, &document->did);
    CU_ASSERT_EQUAL(1, DIDDocument_PublishDID(document, NULL, true, storepass));

    expires = DIDDocument_GetExpires(document);
    DIDDocument_Destroy(document);

    //create issuer
    issuerdoc = RootIdentity_NewDID(rootidentity, storepass, NULL, false);
    CU_ASSERT_PTR_NOT_NULL(issuerdoc);
    DID_Copy(&issuerid, &issuerdoc->did);
    CU_ASSERT_EQUAL(1, DIDDocument_PublishDID(issuerdoc, NULL, true, storepass));
    DIDDocument_Destroy(issuerdoc);

    issuer = Issuer_Create(&issuerid, NULL, store);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);

    //create credential
    printf("\n------------------------------------------------------------\ncreate 1028 credentials, please wait...\n");
    for (i = 0; i < 1028; i++) {
        sprintf(fragment, "test%d", i);
        credid = DIDURL_NewFromDid(&did, fragment);
        CU_ASSERT_PTR_NOT_NULL(credid);

        const char *types[2] = {"https://elastos.org/credentials/v1#SelfProclaimedCredential",
                "https://elastos.org/credentials/profile/v1#ProfileCredential"};
        Property properties[1];
        properties[0].key = "name";
        properties[0].value = "jack";

        vc = Issuer_CreateCredential(issuer, &did, credid, types, 2, properties, 1,
                expires, storepass);
        CU_ASSERT_PTR_NOT_NULL(vc);
        CredentialMetadata_SetStore(&vc->metadata, store);
        CU_ASSERT_EQUAL(1, Credential_Declare(vc, NULL, storepass));
        CU_ASSERT_EQUAL(1, Credential_WasDeclared(credid));

        Credential_Destroy(vc);
        DIDURL_Destroy(credid);
    }

    printf("successfully!\n------------------------------------------------------------\nlist credential 'skip = 0, limit = 0', wait...\n");
    size = Credential_List(&did, buffer, 560, 0, 0);
    CU_ASSERT_EQUAL(128, size);
    for (i = 0; i < size; i++) {
        vcid = buffer[i];
        sprintf(fragment, "test%d", 1027 - i);
        credid = DIDURL_NewFromDid(&did, fragment);
        CU_ASSERT_PTR_NOT_NULL(credid);
        CU_ASSERT_EQUAL(1,DIDURL_Equals(credid, vcid));

        vc = Credential_Resolve(credid, &status, true);
        CU_ASSERT_PTR_NOT_NULL(vc);
        CU_ASSERT_EQUAL(status, CredentialStatus_Valid);

        Credential_Destroy(vc);
        DIDURL_Destroy(credid);
        DIDURL_Destroy(vcid);
    }

    printf("successfully!\n------------------------------------------------------------\nlist credential 'skip = 0, limit = 560', wait...\n");
    size = Credential_List(&did, buffer, 560, 0, 560);
    CU_ASSERT_EQUAL(256, size);

    for (i = 0; i < size; i++) {
        vcid = buffer[i];
        sprintf(fragment, "test%d", 1027 - i);
        credid = DIDURL_NewFromDid(&did, fragment);
        CU_ASSERT_PTR_NOT_NULL(credid);
        CU_ASSERT_EQUAL(1,DIDURL_Equals(credid, vcid));

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
            credid = DIDURL_NewFromDid(&did, fragment);
            CU_ASSERT_PTR_NOT_NULL(credid);
            CU_ASSERT_EQUAL(1,DIDURL_Equals(credid, vcid));

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
            credid = DIDURL_NewFromDid(&did, fragment);
            CU_ASSERT_PTR_NOT_NULL(credid);
            CU_ASSERT_EQUAL(1,DIDURL_Equals(credid, vcid));

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

static int idchain_operation_new_test_suite_init(void)
{
    const char *mnemonic;

    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    mnemonic = Mnemonic_Generate(language);
    rootidentity = RootIdentity_Create(mnemonic, "", true, store, storepass);
    Mnemonic_Free((void*)mnemonic);
    if (!rootidentity)
        return -1;

    return 0;
}

static int idchain_operation_new_test_suite_cleanup(void)
{
    DIDDocument_Destroy(controller1_doc);
    DIDDocument_Destroy(controller2_doc);
    DIDDocument_Destroy(controller3_doc);
    DIDDocument_Destroy(controller4_doc);
    DIDDocument_Destroy(controller5_doc);
    DIDDocument_Destroy(customized_doc);
    DIDDocument_Destroy(multicustomized_doc);

    RootIdentity_Destroy(rootidentity);
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_idchain_controller1",                     test_idchain_controller1                     },
    { "test_idchain_controller2",                     test_idchain_controller2                     },
    { "test_idchain_controller3",                     test_idchain_controller3                     },
    { "test_idchain_controller4",                     test_idchain_controller4                     },
    { "test_idchain_controller5",                     test_idchain_controller5                     },
    { "test_idchain_ctmdid_with_onecontroller",       test_idchain_ctmdid_with_onecontroller       },
    { "test_idchain_ctmdid_with_multicontroller",     test_idchain_ctmdid_with_multicontroller     },
    { "test_transfer_ctmdid_with_onecontroller",      test_transfer_ctmdid_with_onecontroller      },
    { "test_transfer_ctmdid_with_multicontroller",    test_transfer_ctmdid_with_multicontroller    },
    { "test_idchain_deactivedid_after_create",        test_idchain_deactivedid_after_create        },
    { "test_idchain_deactivedid_after_update",        test_idchain_deactivedid_after_update        },
    { "test_idchain_deactivedid_with_authorization1", test_idchain_deactivedid_with_authorization1 },
    { "test_idchain_deactivedid_with_authorization2", test_idchain_deactivedid_with_authorization2 },
    { "test_idchain_listvc_pagination",               test_idchain_listvc_pagination               },
    {   NULL,                                         NULL                                          }
};

static CU_SuiteInfo suite[] = {
    { "idchain operateion new test", idchain_operation_new_test_suite_init, idchain_operation_new_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                            NULL,                                   NULL,                                 NULL, NULL, NULL  }
};

CU_SuiteInfo* idchain_operation_new_test_suite_info(void)
{
    return suite;
}
