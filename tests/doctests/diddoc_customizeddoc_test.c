#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>
#include <crystal.h>

#include <CUnit/Basic.h>
#include "ela_did.h"
#include "loader.h"
#include "constant.h"
#include "diddocument.h"
#include "HDkey.h"
#include "credential.h"

static void test_get_publickey_with_emptycid(void)
{
    PublicKey *pks[4];
    PublicKey *pk;
    DIDURL *id, *defaultkey, *primaryid;
    DID *did, *controller;
    ssize_t size;
    int i;
    bool isEquals;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    DIDDocument *doc = TestData_LoadEmptyCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(doc));
    CU_ASSERT_EQUAL(4, DIDDocument_GetPublicKeyCount(doc));

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    size = DIDDocument_GetPublicKeys(doc, pks, sizeof(pks));
    CU_ASSERT_EQUAL(4, size);

    for (i = 0; i < size; i++) {
        pk = pks[i];
        id = PublicKey_GetId(pk);

        isEquals = DID_Equals(controller, &(id->did));
        CU_ASSERT_TRUE(isEquals);
        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

        isEquals = DID_Equals(controller, PublicKey_GetController(pk));
        if (!strcmp(id->fragment, "recovery")) {
            CU_ASSERT_FALSE(isEquals);
        } else {
            CU_ASSERT_TRUE(isEquals);
        }

        CU_ASSERT_TRUE(!strcmp(id->fragment, "primary") ||
                !strcmp(id->fragment, "key2") || !strcmp(id->fragment, "key3") ||
                !strcmp(id->fragment, "recovery"));
    }

    //PublicKey getter.
    defaultkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL(defaultkey);

    primaryid = DIDURL_NewByDid(controller, "primary");
    CU_ASSERT_PTR_NOT_NULL(primaryid);
    pk = DIDDocument_GetPublicKey(doc, primaryid);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(primaryid, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    isEquals = DIDURL_Equals(primaryid, defaultkey);
    CU_ASSERT_TRUE(isEquals);

    id = DIDURL_NewByDid(controller, "key2");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id);

    //Key not exist, should fail.
    id = DIDURL_NewByDid(did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id);

    // Selector
    size = DIDDocument_SelectPublicKeys(doc, default_type, defaultkey, pks, 4);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid);
    CU_ASSERT_TRUE(isEquals);

    size = DIDDocument_SelectPublicKeys(doc, NULL, defaultkey, pks, 4);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid);
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(primaryid);

    size = DIDDocument_SelectPublicKeys(doc, default_type, NULL, pks, 4);
    CU_ASSERT_EQUAL(size, 4);

    id = DIDURL_NewByDid(did, "key2");
    CU_ASSERT_PTR_NOT_NULL(id);
    size = DIDDocument_SelectPublicKeys(doc, default_type, id, pks, 4);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), id);
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(did, "key3");
    CU_ASSERT_PTR_NOT_NULL(id);
    size = DIDDocument_SelectPublicKeys(doc, NULL, id, pks, 4);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), id);
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id);

    TestData_Free();
}

static void test_get_publickey_with_cid(void)
{
    PublicKey *pks[6];
    PublicKey *pk;
    DIDURL *id, *defaultkey, *primaryid;
    DID *did, *controller;
    ssize_t size;
    int i;
    bool isEquals;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    DIDDocument *doc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(doc));

    size = DIDDocument_GetPublicKeys(doc, pks, 6);
    CU_ASSERT_EQUAL(6, size);

    for (i = 0; i < size; i++) {
        pk = pks[i];
        id = PublicKey_GetId(pk);

        //isEquals = DID_Equals(doc->controller, &(id->did));
        CU_ASSERT_TRUE(DID_Equals(controller, &(id->did)) ||
                DID_Equals(&doc->did, &(id->did)));
        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

        //isEquals = DID_Equals(doc->controller, PublicKey_GetController(pk));
        if (!strcmp(id->fragment, "recovery")) {
            CU_ASSERT_FALSE(DID_Equals(controller, PublicKey_GetController(pk)));
        } else {
            CU_ASSERT_TRUE(DID_Equals(&doc->did, PublicKey_GetController(pk)) ||
                   DID_Equals(controller, PublicKey_GetController(pk)));
            CU_ASSERT_TRUE(!strcmp(id->fragment, "k1") ||
                    !strcmp(id->fragment, "k2") || !strcmp(id->fragment, "primary") ||
                    !strcmp(id->fragment, "key2") || !strcmp(id->fragment, "key3") ||
                    !strcmp(id->fragment, "recovery"));
        }
    }

    //PublicKey getter.
    defaultkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL(defaultkey);

    id = DIDURL_NewByDid(&doc->did, "k1");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id);

    primaryid = DIDURL_NewByDid(controller, "primary");
    CU_ASSERT_PTR_NOT_NULL(primaryid);
    pk = DIDDocument_GetPublicKey(doc, primaryid);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(primaryid, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    isEquals = DIDURL_Equals(primaryid, defaultkey);
    CU_ASSERT_TRUE(isEquals);

    id = DIDURL_NewByDid(controller, "key2");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id);

    //Key not exist, should fail.
    id = DIDURL_NewByDid(did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(controller, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id);

    // Selector
    size = DIDDocument_SelectPublicKeys(doc, default_type, defaultkey, pks, 6);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid);
    CU_ASSERT_TRUE(isEquals);

    size = DIDDocument_SelectPublicKeys(doc, NULL, defaultkey, pks, 6);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid);
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(primaryid);

    size = DIDDocument_SelectPublicKeys(doc, default_type, NULL, pks, 6);
    CU_ASSERT_EQUAL(size, 6);

    id = DIDURL_NewByDid(did, "k2");
    CU_ASSERT_PTR_NOT_NULL(id);
    size = DIDDocument_SelectPublicKeys(doc, default_type, id, pks, 6);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), id);
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(controller, "key3");
    CU_ASSERT_PTR_NOT_NULL(id);
    size = DIDDocument_SelectPublicKeys(doc, NULL, id, pks, 6);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), id);
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id);

    TestData_Free();
}

static void test_add_publickey_with_cid(void)
{
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    DID *did;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    const char *keybase;
    bool isEquals;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    DIDDocument *doc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Add 2 public keys
    DIDURL *id1 = DIDURL_NewByDid(did, "test1");
    CU_ASSERT_PTR_NOT_NULL(id1);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    rc = DIDDocumentBuilder_AddPublicKey(builder, id1, did, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *id2 = DIDURL_NewByDid(did, "test2");
    CU_ASSERT_PTR_NOT_NULL(id2);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    rc = DIDDocumentBuilder_AddPublicKey(builder, id2, did, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    sealeddoc = DIDDocumentBuilder_Seal(builder, NULL, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    PublicKey *pk = DIDDocument_GetPublicKey(sealeddoc, id1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id1, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id1);

    pk = DIDDocument_GetPublicKey(sealeddoc, id2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id2, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id2);

    // Check the final count.
    CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_remove_publickey_with_cid(void)
{
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    DIDURL *recoveryid, *keyid1, *keyid2, *keyid;
    PublicKey *pk;
    DID *did, *controller;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    DIDDocument *doc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // can not remove the controller's key
    keyid = DIDURL_NewByDid(controller, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_RemovePublicKey(builder, keyid, false);
    CU_ASSERT_EQUAL(rc, -1);
    rc = DIDDocumentBuilder_RemovePublicKey(builder, keyid, true);
    CU_ASSERT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    keyid1 = DIDURL_NewByDid(did, "k1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    rc = DIDDocumentBuilder_RemovePublicKey(builder, keyid1, false);
    CU_ASSERT_EQUAL(rc, -1);
    rc = DIDDocumentBuilder_RemovePublicKey(builder, keyid1, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    keyid2 = DIDURL_NewByDid(did, "k2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    rc = DIDDocumentBuilder_RemovePublicKey(builder, keyid2, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    rc = DIDDocumentBuilder_RemovePublicKey(builder,
            DIDDocument_GetDefaultPublicKey(doc), true);
    CU_ASSERT_EQUAL(rc, -1);

    sealeddoc = DIDDocumentBuilder_Seal(builder, NULL, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    recoveryid = DIDURL_NewByDid(did, "recovery");
    CU_ASSERT_PTR_NOT_NULL(recoveryid);
    pk = DIDDocument_GetPublicKey(sealeddoc, recoveryid);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(recoveryid);

    pk = DIDDocument_GetPublicKey(sealeddoc, keyid1);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(keyid1);

    pk = DIDDocument_GetPublicKey(sealeddoc, keyid2);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(keyid2);

    // Check the final count.
    CU_ASSERT_EQUAL(4, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_get_authentication_key_with_cid(void)
{
    PublicKey *pks[5];
    ssize_t size;
    PublicKey *pk;
    DIDURL *keyid1, *keyid2, *keyid3, *id;
    DID *did, *controller;
    bool isEquals;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);
    CU_ASSERT_NOT_EQUAL(TestData_InitIdentity(store), -1);

    DIDDocument *doc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(doc));

    size = DIDDocument_GetAuthenticationKeys(doc, pks, 5);
    CU_ASSERT_EQUAL(5, size);

    for (i = 0; i < size; i++) {
        pk = pks[i];
        id = PublicKey_GetId(pk);

        //isEquals = DID_Equals(did, &id->did);
        CU_ASSERT_TRUE(DID_Equals(did, &id->did) ||
               DID_Equals(controller, &id->did));
        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

        //isEquals = DID_Equals(did, PublicKey_GetController(pk));
        CU_ASSERT_TRUE(DID_Equals(did, PublicKey_GetController(pk)) ||
               DID_Equals(controller, PublicKey_GetController(pk)));

        CU_ASSERT_TRUE(!strcmp(id->fragment, "primary") ||
                !strcmp(id->fragment, "key2") || !strcmp(id->fragment, "key3") ||
                !strcmp(id->fragment, "k1") || !strcmp(id->fragment, "k2"));
    }

    // AuthenticationKey getter
    id = DIDURL_NewByDid(controller, "primary");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetAuthenticationKey(doc, id);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id);

    keyid3 = DIDURL_NewByDid(controller, "key3");
    CU_ASSERT_PTR_NOT_NULL(keyid3);
    pk = DIDDocument_GetAuthenticationKey(doc, keyid3);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(keyid3, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);

    keyid1 = DIDURL_NewByDid(did, "k1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    pk = DIDDocument_GetAuthenticationKey(doc, keyid1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(keyid1, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);

    keyid2 = DIDURL_NewByDid(did, "k2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    pk = DIDDocument_GetAuthenticationKey(doc, keyid2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(keyid2, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);

    //key not exist, should fail.
    id = DIDURL_NewByDid(did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetAuthenticationKey(doc, id);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(controller, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetAuthenticationKey(doc, id);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id);

    // Selector
    size = DIDDocument_SelectAuthenticationKeys(doc, default_type, keyid3, pks, 5);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), keyid3);
    CU_ASSERT_TRUE(isEquals);

    size = DIDDocument_SelectAuthenticationKeys(doc, NULL, keyid3, pks, 5);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), keyid3);
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(keyid3);

    size = DIDDocument_SelectAuthenticationKeys(doc, default_type, NULL, pks, 5);
    CU_ASSERT_EQUAL(size, 5);

    size = DIDDocument_SelectAuthenticationKeys(doc, default_type, keyid1, pks, 5);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), keyid1);
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(keyid1);

    size = DIDDocument_SelectAuthenticationKeys(doc, NULL, keyid2, pks, 5);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), keyid2);
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(keyid2);

    TestData_Free();
}

static void test_add_authentication_key_with_cid(void)
{
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    DID *did, *controller;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    const char *keybase;
    bool isEquals;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    DIDDocument *doc = TestData_LoadEmptyCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Add 2 public keys
    DIDURL *id1 = DIDURL_NewByDid(did, "test1");
    CU_ASSERT_PTR_NOT_NULL(id1);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    rc = DIDDocumentBuilder_AddPublicKey(builder, id1, did, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, id1, NULL);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *id2 = DIDURL_NewByDid(did, "test2");
    CU_ASSERT_PTR_NOT_NULL(id2);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    rc = DIDDocumentBuilder_AddPublicKey(builder, id2, did, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, id2, NULL);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    // Add new keys
    DIDURL *id3 = DIDURL_NewByDid(did, "test3");
    CU_ASSERT_PTR_NOT_NULL(id3);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, id3, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *id4 = DIDURL_NewByDid(did, "test4");
    CU_ASSERT_PTR_NOT_NULL(id4);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, id4, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    // Try to add the controller's key, should fail.
    DIDURL *id = DIDURL_NewByDid(did, "key3");
    CU_ASSERT_PTR_NOT_NULL(id);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, id, NULL);
    CU_ASSERT_EQUAL(rc, -1);
    DIDURL_Destroy(id);

    // Try to add a non existing key, should fail.
    id = DIDURL_NewByDid(did, "notExistKey");
    CU_ASSERT_PTR_NOT_NULL(id);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, id, NULL);
    CU_ASSERT_EQUAL(rc, -1);
    DIDURL_Destroy(id);

    // Try to add a key not owned by self, should fail.
    id = DIDURL_NewByDid(controller, "recovery");
    CU_ASSERT_PTR_NOT_NULL(id);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, id, NULL);
    CU_ASSERT_EQUAL(rc, -1);
    DIDURL_Destroy(id);

    sealeddoc = DIDDocumentBuilder_Seal(builder, NULL, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    PublicKey *pk = DIDDocument_GetPublicKey(sealeddoc, id1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id1, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id1);

    pk = DIDDocument_GetPublicKey(sealeddoc, id2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id2, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id2);

    pk = DIDDocument_GetPublicKey(sealeddoc, id3);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id3, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id3);

    pk = DIDDocument_GetPublicKey(sealeddoc, id4);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id4, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id4);

    // Check the final count.
    CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(7, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_remove_authentication_key_with_cid(void)
{
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    DID *did, *controller;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    const char *keybase;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    DIDDocument *doc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(doc));

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Remove keys
    DIDURL *id1 = DIDURL_NewByDid(did, "k1");
    CU_ASSERT_PTR_NOT_NULL(id1);
    rc = DIDDocumentBuilder_RemoveAuthenticationKey(builder, id1);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *id2 = DIDURL_NewByDid(did, "k2");
    CU_ASSERT_PTR_NOT_NULL(id2);
    rc = DIDDocumentBuilder_RemoveAuthenticationKey(builder, id2);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    // Key not exist, should fail.
    DIDURL *id = DIDURL_NewByDid(did, "notExistKey");
    CU_ASSERT_PTR_NOT_NULL(id);
    rc = DIDDocumentBuilder_RemoveAuthenticationKey(builder, id);
    CU_ASSERT_EQUAL(rc, -1);
    DIDURL_Destroy(id);

    // Remove controller's key, should fail.
    id = DIDURL_NewByDid(controller, "key2");
    CU_ASSERT_PTR_NOT_NULL(id);
    rc = DIDDocumentBuilder_RemoveAuthenticationKey(builder, id);
    CU_ASSERT_EQUAL(rc, -1);
    DIDURL_Destroy(id);

    sealeddoc = DIDDocumentBuilder_Seal(builder, NULL, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    //check existence
    PublicKey *pk = DIDDocument_GetAuthenticationKey(sealeddoc, id1);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id1);

    pk = DIDDocument_GetAuthenticationKey(sealeddoc, id2);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id2);

    // Check the final count.
    CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_get_authorization_key_with_cid(void)
{
    PublicKey *pks[1];
    ssize_t size;
    PublicKey *pk;
    DIDURL *keyid, *id;
    bool isEquals;
    DID *did, *controller;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    DIDDocument *doc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(doc));

    size = DIDDocument_GetAuthorizationKeys(doc, pks, 1);
    CU_ASSERT_EQUAL(1, size);

    for (i = 0; i < size; i++) {
        pk = pks[i];
        id = PublicKey_GetId(pk);

        isEquals = DID_Equals(controller, &id->did);
        CU_ASSERT_TRUE(isEquals);
        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

        isEquals = DID_Equals(controller, PublicKey_GetController(pk));
        CU_ASSERT_FALSE(isEquals);

        CU_ASSERT_TRUE(!strcmp(id->fragment, "recovery"));
    }

    // AuthorizationKey getter
    keyid = DIDURL_NewByDid(controller, "recovery");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    pk = DIDDocument_GetAuthorizationKey(doc, keyid);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(keyid, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);

    //Key not exist, should fail.
    id = DIDURL_NewByDid(did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetAuthorizationKey(doc, id);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id);

    id = DIDURL_NewByDid(controller, "notExistKey");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetAuthorizationKey(doc, id);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id);

    // Selector
    size = DIDDocument_SelectAuthorizationKeys(doc, default_type, keyid, pks, 1);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), keyid);
    CU_ASSERT_TRUE(isEquals);

    size = DIDDocument_SelectAuthorizationKeys(doc, NULL, keyid, pks, 1);
    CU_ASSERT_EQUAL(size, 1);
    isEquals = DIDURL_Equals(PublicKey_GetId(pks[0]), keyid);
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(keyid);

    size = DIDDocument_SelectAuthorizationKeys(doc, default_type, NULL, pks, 1);
    CU_ASSERT_EQUAL(size, 1);

    TestData_Free();
}

static void test_add_authorization_key_with_cid(void)
{
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    HDKey _dkey, *dkey;
    const char *keybase, *idstring;
    DID controller, *did, *_controller;
    bool isEquals;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    DIDDocument *doc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    _controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(_controller);

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Add 2 public keys
    DIDURL *id1 = DIDURL_NewByDid(did, "test1");
    CU_ASSERT_PTR_NOT_NULL(id1);
    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    idstring = HDKey_GetAddress(dkey);
    CU_ASSERT_PTR_NOT_NULL(idstring);
    strncpy(controller.idstring, idstring, sizeof(controller.idstring));
    rc = DIDDocumentBuilder_AddPublicKey(builder, id1, &controller, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDDocumentBuilder_AddAuthorizationKey(builder, id1, &controller, NULL);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *id2 = DIDURL_NewByDid(did, "test2");
    CU_ASSERT_PTR_NOT_NULL(id2);
    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    idstring = HDKey_GetAddress(dkey);
    CU_ASSERT_PTR_NOT_NULL(idstring);
    strncpy(controller.idstring, idstring, sizeof(controller.idstring));
    rc = DIDDocumentBuilder_AddPublicKey(builder, id2, &controller, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDDocumentBuilder_AddAuthorizationKey(builder, id2, NULL, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    // Add new keys
    DIDURL *id3 = DIDURL_NewByDid(did, "test3");
    CU_ASSERT_PTR_NOT_NULL(id3);
    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    idstring = HDKey_GetAddress(dkey);
    CU_ASSERT_PTR_NOT_NULL(idstring);
    strncpy(controller.idstring, idstring, sizeof(controller.idstring));
    rc = DIDDocumentBuilder_AddPublicKey(builder, id3, &controller, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDDocumentBuilder_AddAuthorizationKey(builder, id3, NULL, NULL);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *id4 = DIDURL_NewByDid(did, "test4");
    CU_ASSERT_PTR_NOT_NULL(id4);
    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    idstring = HDKey_GetAddress(dkey);
    CU_ASSERT_PTR_NOT_NULL(idstring);
    strncpy(controller.idstring, idstring, sizeof(controller.idstring));
    rc = DIDDocumentBuilder_AddAuthorizationKey(builder, id4, &controller, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    // Try to add a non existing key, should fail.
    DIDURL *id = DIDURL_NewByDid(did, "notExistKey");
    CU_ASSERT_PTR_NOT_NULL(id);
    rc = DIDDocumentBuilder_AddAuthorizationKey(builder, id, NULL, NULL);
    CU_ASSERT_EQUAL(rc, -1);
    DIDURL_Destroy(id);

    // Try to add controller's key, should fail.
    id = DIDURL_NewByDid(_controller, "recovery");
    CU_ASSERT_PTR_NOT_NULL(id);
    rc = DIDDocumentBuilder_AddAuthorizationKey(builder, id, NULL, NULL);
    CU_ASSERT_EQUAL(rc, -1);
    DIDURL_Destroy(id);

    sealeddoc = DIDDocumentBuilder_Seal(builder, NULL, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    PublicKey *pk = DIDDocument_GetPublicKey(sealeddoc, id1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id1, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id1);

    pk = DIDDocument_GetPublicKey(sealeddoc, id2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id2, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id2);

    pk = DIDDocument_GetPublicKey(sealeddoc, id3);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id3, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id3);

    pk = DIDDocument_GetPublicKey(sealeddoc, id4);
    CU_ASSERT_PTR_NOT_NULL(pk);
    isEquals = DIDURL_Equals(id4, PublicKey_GetId(pk));
    CU_ASSERT_TRUE(isEquals);
    DIDURL_Destroy(id4);

    // Check the final count.
    CU_ASSERT_EQUAL(10, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_remove_authorization_key_with_cid(void)
{
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    HDKey _dkey, *dkey;
    const char *keybase, *idstring;
    DID controller, *did, *_controller;
    int rc;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    DIDDocument *doc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_TRUE_FATAL(DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    _controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(_controller);

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Add 2 public keys
    DIDURL *id1 = DIDURL_NewByDid(did, "test1");
    CU_ASSERT_PTR_NOT_NULL(id1);
    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58,
            sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    idstring = HDKey_GetAddress(dkey);
    CU_ASSERT_PTR_NOT_NULL(idstring);
    strncpy(controller.idstring, idstring, sizeof(controller.idstring));
    rc = DIDDocumentBuilder_AddAuthorizationKey(builder, id1, &controller, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *id2 = DIDURL_NewByDid(did, "test2");
    CU_ASSERT_PTR_NOT_NULL(id2);
    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58,
            sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    idstring = HDKey_GetAddress(dkey);
    CU_ASSERT_PTR_NOT_NULL(idstring);
    strncpy(controller.idstring, idstring, sizeof(controller.idstring));
    rc = DIDDocumentBuilder_AddAuthorizationKey(builder, id2, &controller, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    sealeddoc = DIDDocumentBuilder_Seal(builder, NULL, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthorizationCount(sealeddoc));

    builder = DIDDocument_Edit(sealeddoc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(sealeddoc);

    // Remote keys
    rc = DIDDocumentBuilder_RemoveAuthorizationKey(builder, id1);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    rc = DIDDocumentBuilder_RemoveAuthorizationKey(builder, id2);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDURL *recoveryid = DIDURL_NewByDid(_controller, "recovery");
    CU_ASSERT_PTR_NOT_NULL(recoveryid);
    rc = DIDDocumentBuilder_RemoveAuthorizationKey(builder, recoveryid);
    CU_ASSERT_EQUAL(rc, -1);

    // Key not exist, should fail.
    DIDURL *id = DIDURL_NewByDid(did, "notExistKey");
    CU_ASSERT_PTR_NOT_NULL(id);
    rc = DIDDocumentBuilder_RemoveAuthorizationKey(builder, id);
    CU_ASSERT_EQUAL(rc, -1);
    DIDURL_Destroy(id);

    sealeddoc = DIDDocumentBuilder_Seal(builder, NULL, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    PublicKey *pk = DIDDocument_GetAuthorizationKey(sealeddoc, id1);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id1);

    pk = DIDDocument_GetAuthorizationKey(sealeddoc, id2);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id2);

    pk = DIDDocument_GetAuthorizationKey(sealeddoc, recoveryid);
    CU_ASSERT_PTR_NOT_NULL(pk);
    DIDURL_Destroy(recoveryid);

    // Check the final count.
    CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static int diddoc_customizeddoc_test_suite_init(void)
{
    return  0;
}

static int diddoc_customizeddoc_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_get_publickey_with_cid",                 test_get_publickey_with_cid             },
    { "test_add_publickey_with_cid",                 test_add_publickey_with_cid             },
    { "test_remove_publickey_with_cid",              test_remove_publickey_with_cid          },
    { "test_get_authentication_key_with_cid",        test_get_authentication_key_with_cid    },
    { "test_add_authentication_key_with_cid",        test_add_authentication_key_with_cid    },
    { "test_remove_authentication_key_with_cid",     test_remove_authentication_key_with_cid },
    { "test_get_authorization_key_with_cid",         test_get_authorization_key_with_cid     },
    { "test_add_authorization_key_with_cid",         test_add_authorization_key_with_cid     },
    { "test_remove_authorization_key_with_cid",      test_remove_authorization_key_with_cid  },
    { NULL,                                          NULL                                  }
};

static CU_SuiteInfo suite[] = {
    { "diddoc customized doc test", diddoc_customizeddoc_test_suite_init,  diddoc_customizeddoc_test_suite_cleanup,  NULL, NULL, cases },
    {  NULL,                       NULL,                         NULL,                            NULL, NULL, NULL  }
};

CU_SuiteInfo* diddoc_customizeddoc_test_suite_info(void)
{
    return suite;
}
