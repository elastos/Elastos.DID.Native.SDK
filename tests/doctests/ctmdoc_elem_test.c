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
#include "HDkey.h"
#include "diddocument.h"
#include "did.h"
#include "credential.h"

static DID *contains_DID(DID **dids, size_t size, DID *did)
{
    int i;

    assert(dids);
    assert(size > 0);
    assert(did);

    for (i = 0; i < size; i++) {
        if (DID_Equals(dids[i], did))
            return dids[i];
    }

    return NULL;
}

static void test_emptyctmdoc_get_publickey(void)
{
    PublicKey *pks[4];
    PublicKey *pk;
    DIDURL *id, *defaultkey, *primaryid;
    DID *did, *controller;
    ssize_t size;
    bool equal;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    DIDDocument *doc = TestData_GetDocument("customized-did-empty", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(doc));

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    size = DIDDocument_GetPublicKeys(doc, pks, sizeof(pks));
    CU_ASSERT_EQUAL(3, size);

    for (i = 0; i < size; i++) {
        pk = pks[i];
        id = PublicKey_GetId(pk);

        CU_ASSERT_EQUAL(1, DID_Equals(controller, &(id->did)));
        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

        equal = DID_Equals(controller, PublicKey_GetController(pk));
        if (!strcmp(id->fragment, "recovery")) {
            CU_ASSERT_NOT_EQUAL(1, equal);
        } else {
            CU_ASSERT_EQUAL(1, equal);
        }

        CU_ASSERT_TRUE(!strcmp(id->fragment, "primary") ||
                !strcmp(id->fragment, "key2") || !strcmp(id->fragment, "key3") ||
                !strcmp(id->fragment, "recovery"));
    }

    //PublicKey getter.
    defaultkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL(defaultkey);

    primaryid = DIDURL_NewFromDid(controller, "primary");
    CU_ASSERT_PTR_NOT_NULL(primaryid);
    pk = DIDDocument_GetPublicKey(doc, primaryid);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(primaryid, PublicKey_GetId(pk)));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(primaryid, defaultkey));

    id = DIDURL_NewFromDid(controller, "key2");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(id, PublicKey_GetId(pk)));
    DIDURL_Destroy(id);

    //Key not exist, should fail.
    id = DIDURL_NewFromDid(did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id);

    // Selector
    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, default_type, defaultkey, pks, 4));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid));

    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, NULL, defaultkey, pks, 4));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid));
    DIDURL_Destroy(primaryid);

    CU_ASSERT_EQUAL(4, DIDDocument_SelectPublicKeys(doc, default_type, NULL, pks, 4));

    id = DIDURL_NewFromDid(controller, "key2");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, default_type, id, pks, 4));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), id));
    DIDURL_Destroy(id);

    id = DIDURL_NewFromDid(controller, "key3");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, NULL, id, pks, 4));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), id));
    DIDURL_Destroy(id);

    TestData_Free();
}

static void test_ctmdoc_get_publickey(void)
{
    PublicKey *pks[6];
    PublicKey *pk;
    DIDURL *id, *defaultkey, *primaryid;
    DID *did, *controller;
    ssize_t size;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    DIDDocument *doc = TestData_GetDocument("customized-did", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    CU_ASSERT_EQUAL(5, DIDDocument_GetPublicKeyCount(doc));

    size = DIDDocument_GetPublicKeys(doc, pks, 6);
    CU_ASSERT_EQUAL(5, size);

    for (i = 0; i < size; i++) {
        pk = pks[i];
        id = PublicKey_GetId(pk);

        CU_ASSERT_EQUAL(1, DID_Equals(controller, &(id->did)) == 1 ||
                DID_Equals(&doc->did, &(id->did)) == 1);
        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

        //equal = DID_Equals(doc->controller, PublicKey_GetController(pk));
        if (!strcmp(id->fragment, "recovery")) {
            CU_ASSERT_EQUAL(0, DID_Equals(controller, PublicKey_GetController(pk)));
        } else {
            CU_ASSERT_EQUAL(1, DID_Equals(&doc->did, PublicKey_GetController(pk)) == 1 ||
                   DID_Equals(controller, PublicKey_GetController(pk)) == 1);
            CU_ASSERT_TRUE(!strcmp(id->fragment, "k1") ||
                    !strcmp(id->fragment, "k2") || !strcmp(id->fragment, "primary") ||
                    !strcmp(id->fragment, "key2") || !strcmp(id->fragment, "key3") ||
                    !strcmp(id->fragment, "recovery"));
        }
    }

    //PublicKey getter.
    defaultkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL(defaultkey);

    id = DIDURL_NewFromDid(&doc->did, "k1");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(id, PublicKey_GetId(pk)));
    DIDURL_Destroy(id);

    primaryid = DIDURL_NewFromDid(controller, "primary");
    CU_ASSERT_PTR_NOT_NULL(primaryid);
    pk = DIDDocument_GetPublicKey(doc, primaryid);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(primaryid, PublicKey_GetId(pk)));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(primaryid, defaultkey));

    id = DIDURL_NewFromDid(controller, "key2");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1,DIDURL_Equals(id, PublicKey_GetId(pk)));
    DIDURL_Destroy(id);

    //Key not exist, should fail.
    id = DIDURL_NewFromDid(did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id);

    id = DIDURL_NewFromDid(controller, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetPublicKey(doc, id);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(id);

    // Selector
    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, default_type, defaultkey, pks, 6));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid));

    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, NULL, defaultkey, pks, 6));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid));
    DIDURL_Destroy(primaryid);

    CU_ASSERT_EQUAL(6, DIDDocument_SelectPublicKeys(doc, default_type, NULL, pks, 6));

    id = DIDURL_NewFromDid(did, "k2");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, default_type, id, pks, 6));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), id));
    DIDURL_Destroy(id);

    id = DIDURL_NewFromDid(controller, "key3");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, NULL, id, pks, 6));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), id));
    DIDURL_Destroy(id);

    TestData_Free();
}

static void test_ctmdoc_add_publickey(void)
{
    DIDDocument *sealeddoc, *doc;
    DIDDocumentBuilder *builder;
    DID *did;
    DIDURL *id1, *id2;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    const char *keybase;
    PublicKey *pk;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    doc = TestData_GetDocument("customized-did", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    builder = DIDDocument_Edit(doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Add 2 public keys
    id1 = DIDURL_NewFromDid(did, "test1");
    CU_ASSERT_PTR_NOT_NULL(id1);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id1, did, keybase));

    id2 = DIDURL_NewFromDid(did, "test2");
    CU_ASSERT_PTR_NOT_NULL(id2);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id2, did, keybase));

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    pk = DIDDocument_GetPublicKey(sealeddoc, id1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(id1, PublicKey_GetId(pk)));
    DIDURL_Destroy(id1);

    pk = DIDDocument_GetPublicKey(sealeddoc, id2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(id2, PublicKey_GetId(pk)));
    DIDURL_Destroy(id2);

    // Check the final count.
    CU_ASSERT_EQUAL(7, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_ctmdoc_remove_publickey(void)
{
    DIDDocument *sealeddoc, *doc;
    DIDDocumentBuilder *builder;
    DIDURL *recoveryid, *keyid1, *keyid2, *keyid;
    DID *did, *controller;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    doc = TestData_GetDocument("customized-did", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    builder = DIDDocument_Edit(doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // can not remove the controller's key
    keyid = DIDURL_NewFromDid(controller, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid, false));
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid, true));
    DIDURL_Destroy(keyid);

    keyid1 = DIDURL_NewFromDid(did, "k1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid1, false));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid1, true));

    keyid2 = DIDURL_NewFromDid(did, "k2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid2, true));

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder,
            DIDDocument_GetDefaultPublicKey(doc), true));

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    recoveryid = DIDURL_NewFromDid(did, "recovery");
    CU_ASSERT_PTR_NOT_NULL(recoveryid);
    CU_ASSERT_PTR_NULL(DIDDocument_GetPublicKey(sealeddoc, recoveryid));
    DIDURL_Destroy(recoveryid);

    CU_ASSERT_PTR_NULL(DIDDocument_GetPublicKey(sealeddoc, keyid1));
    DIDURL_Destroy(keyid1);

    CU_ASSERT_PTR_NULL(DIDDocument_GetPublicKey(sealeddoc, keyid2));
    DIDURL_Destroy(keyid2);

    // Check the final count.
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_ctmdoc_get_authentication_key(void)
{
    DIDDocument *doc;
    PublicKey *pks[5];
    ssize_t size;
    PublicKey *pk;
    DIDURL *keyid1, *keyid2, *keyid3, *id;
    DID *did, *controller;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    doc = TestData_GetDocument("customized-did", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(doc));

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

        CU_ASSERT_EQUAL(1, DID_Equals(did, &id->did) == 1 ||
               DID_Equals(controller, &id->did) == 1);
        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

        CU_ASSERT_EQUAL(1, DID_Equals(did, PublicKey_GetController(pk)) == 1 ||
               DID_Equals(controller, PublicKey_GetController(pk)) == 1);

        CU_ASSERT_TRUE(!strcmp(id->fragment, "primary") ||
                !strcmp(id->fragment, "key2") || !strcmp(id->fragment, "key3") ||
                !strcmp(id->fragment, "k1") || !strcmp(id->fragment, "k2"));
    }

    // AuthenticationKey getter
    id = DIDURL_NewFromDid(controller, "primary");
    CU_ASSERT_PTR_NOT_NULL(id);
    pk = DIDDocument_GetAuthenticationKey(doc, id);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(id, PublicKey_GetId(pk)));
    DIDURL_Destroy(id);

    keyid3 = DIDURL_NewFromDid(controller, "key3");
    CU_ASSERT_PTR_NOT_NULL(keyid3);
    pk = DIDDocument_GetAuthenticationKey(doc, keyid3);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid3, PublicKey_GetId(pk)));

    keyid1 = DIDURL_NewFromDid(did, "k1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    pk = DIDDocument_GetAuthenticationKey(doc, keyid1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid1, PublicKey_GetId(pk)));

    keyid2 = DIDURL_NewFromDid(did, "k2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    pk = DIDDocument_GetAuthenticationKey(doc, keyid2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid2, PublicKey_GetId(pk)));

    //key not exist, should fail.
    id = DIDURL_NewFromDid(did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(doc, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewFromDid(controller, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(doc, id));
    DIDURL_Destroy(id);

    // Selector
    CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(doc, default_type, keyid3, pks, 5));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid3));

    CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(doc, NULL, keyid3, pks, 5));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid3));
    DIDURL_Destroy(keyid3);

    CU_ASSERT_EQUAL(5, DIDDocument_SelectAuthenticationKeys(doc, default_type, NULL, pks, 5));

    CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(doc, default_type, keyid1, pks, 5));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid1));
    DIDURL_Destroy(keyid1);

    CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(doc, NULL, keyid2, pks, 5));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid2));
    DIDURL_Destroy(keyid2);

    TestData_Free();
}

static void test_ctmdoc_add_authentication_key(void)
{
    DIDDocument *sealeddoc, *doc;
    DIDDocumentBuilder *builder;
    DID *did, *controller;
    DIDURL *id1, *id2, *id3, *id4, *id;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    const char *keybase;
    PublicKey *pk;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    doc = TestData_GetDocument("customized-did-empty", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    builder = DIDDocument_Edit(doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Add 2 public keys
    id1 = DIDURL_NewFromDid(did, "test1");
    CU_ASSERT_PTR_NOT_NULL(id1);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id1, did, keybase));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id1, NULL));

    id2 = DIDURL_NewFromDid(did, "test2");
    CU_ASSERT_PTR_NOT_NULL(id2);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id2, did, keybase));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id2, NULL));

    // Add new keys
    id3 = DIDURL_NewFromDid(did, "test3");
    CU_ASSERT_PTR_NOT_NULL(id3);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id3, keybase));

    id4 = DIDURL_NewFromDid(did, "test4");
    CU_ASSERT_PTR_NOT_NULL(id4);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id4, keybase));

    // Try to add the controller's key, should fail.
    id = DIDURL_NewFromDid(did, "key3");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id, NULL));
    DIDURL_Destroy(id);

    // Try to add a non existing key, should fail.
    id = DIDURL_NewFromDid(did, "notExistKey");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id, NULL));
    DIDURL_Destroy(id);

    // Try to add a key not owned by self, should fail.
    id = DIDURL_NewFromDid(controller, "recovery");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id, NULL));
    DIDURL_Destroy(id);

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    pk = DIDDocument_GetPublicKey(sealeddoc, id1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(id1, PublicKey_GetId(pk)));
    DIDURL_Destroy(id1);

    pk = DIDDocument_GetPublicKey(sealeddoc, id2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(id2, PublicKey_GetId(pk)));
    DIDURL_Destroy(id2);

    pk = DIDDocument_GetPublicKey(sealeddoc, id3);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(id3, PublicKey_GetId(pk)));
    DIDURL_Destroy(id3);

    pk = DIDDocument_GetPublicKey(sealeddoc, id4);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(id4, PublicKey_GetId(pk)));
    DIDURL_Destroy(id4);

    // Check the final count.
    CU_ASSERT_EQUAL(7, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(7, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_ctmdoc_remove_authentication_key(void)
{
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    DID *did, *controller;
    DIDURL *id1, *id2, *id;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    DIDDocument *doc = TestData_GetDocument("customized-did", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    controller = &(doc->controllers.docs[0]->did);
    CU_ASSERT_PTR_NOT_NULL(controller);

    CU_ASSERT_EQUAL(5, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(doc));

    builder = DIDDocument_Edit(doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Remove keys
    id1 = DIDURL_NewFromDid(did, "k1");
    CU_ASSERT_PTR_NOT_NULL(id1);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, id1));

    id2 = DIDURL_NewFromDid(did, "k2");
    CU_ASSERT_PTR_NOT_NULL(id2);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, id2));

    // Key not exist, should fail.
    id = DIDURL_NewFromDid(did, "notExistKey");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, id));
    DIDURL_Destroy(id);

    // Remove controller's key, should fail.
    id = DIDURL_NewFromDid(controller, "key2");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, id));
    DIDURL_Destroy(id);

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    //check existence
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(sealeddoc, id1));
    DIDURL_Destroy(id1);

    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(sealeddoc, id2));
    DIDURL_Destroy(id2);

    // Check the final count.
    CU_ASSERT_EQUAL(5, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_ctmdoc_get_authorization_key(void)
{
    DIDDocument *doc;
    PublicKey *pks[1];
    ssize_t size;
    PublicKey *pk;
    DIDURL *keyid, *id;
    DID *did, *controller;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    doc = TestData_GetDocument("customized-did", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(doc));

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

        CU_ASSERT_EQUAL(1, DID_Equals(controller, &id->did));
        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));
        CU_ASSERT_NOT_EQUAL(1, DID_Equals(controller, PublicKey_GetController(pk)));
        CU_ASSERT_TRUE(!strcmp(id->fragment, "recovery"));
    }

    // AuthorizationKey getter
    keyid = DIDURL_NewFromDid(controller, "recovery");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    pk = DIDDocument_GetAuthorizationKey(doc, keyid);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid, PublicKey_GetId(pk)));

    //Key not exist, should fail.
    id = DIDURL_NewFromDid(did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthorizationKey(doc, id));
    DIDURL_Destroy(id);

    id = DIDURL_NewFromDid(controller, "notExistKey");
    CU_ASSERT_PTR_NOT_NULL(id);
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthorizationKey(doc, id));
    DIDURL_Destroy(id);

    // Selector
    CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthorizationKeys(doc, default_type, keyid, pks, 1));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid));

    CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthorizationKeys(doc, NULL, keyid, pks, 1));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid));
    DIDURL_Destroy(keyid);

    CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthorizationKeys(doc, default_type, NULL, pks, 1));

    TestData_Free();
}

static void test_ctmdoc_add_authorization_key(void)
{
    DIDDocument *sealeddoc, *doc;
    DIDDocumentBuilder *builder;
    DIDURL *id;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    HDKey _dkey, *dkey;
    const char *keybase, *idstring;
    DID controller, *did;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    doc = TestData_GetDocument("customized-did", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(doc));

    did = DIDDocument_GetSubject(doc);
    CU_ASSERT_PTR_NOT_NULL(did);

    builder = DIDDocument_Edit(doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);

    id = DIDURL_NewFromDid(did, "test1");
    CU_ASSERT_PTR_NOT_NULL(id);
    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    idstring = HDKey_GetAddress(dkey);
    CU_ASSERT_PTR_NOT_NULL(idstring);
    DID_Init(&controller, idstring);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id, &controller, keybase));
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, id, &controller, NULL));

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetPublicKey(sealeddoc, id));
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthorizationKey(sealeddoc, id));

    // Check the final count.
    CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(5, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDURL_Destroy(id);
    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

//--------------------------------------------------------------------------
static void test_empty_multictmdoc_get_publickey(void)
{
    PublicKey *pks[8] = {0};
    PublicKey *pk;
    DIDURL *keyid1, *keyid2, *keyid, *primaryid1, *primaryid2, *primaryid3;
    DID *customized_did, controller1, controller2, controller3;
    ssize_t size;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("controller", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    DIDDocument *customized_doc = TestData_GetDocument("customized-multisigone-empty", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    customized_did = DIDDocument_GetSubject(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(customized_did);

    CU_ASSERT_EQUAL(1, DIDDocument_GetMultisig(customized_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(customized_doc));

    DID *controllers[3] = {0};
    size = DIDDocument_GetControllers(customized_doc, controllers, 3);
    CU_ASSERT_EQUAL(3, size);
    DID_Copy(&controller1, controllers[0]);
    DID_Copy(&controller2, controllers[1]);
    DID_Copy(&controller3, controllers[2]);

    size = DIDDocument_GetPublicKeys(customized_doc, pks, sizeof(pks));
    CU_ASSERT_EQUAL(6, size);

    for (i = 0; i < size; i++) {
        pk = pks[i];
        keyid = PublicKey_GetId(pk);

        DID *controller = contains_DID(controllers, 3, &keyid->did);
        CU_ASSERT_PTR_NOT_NULL(controller);
        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

        if (!strcmp(keyid->fragment, "recovery") || !strcmp(keyid->fragment, "recovery2")) {
            CU_ASSERT_NOT_EQUAL(1, DID_Equals(controller, PublicKey_GetController(pk)));
        } else {
            CU_ASSERT_EQUAL(1, DID_Equals(controller, PublicKey_GetController(pk)));
        }

        CU_ASSERT_TRUE(!strcmp(keyid->fragment, "primary") ||
                !strcmp(keyid->fragment, "key2") || !strcmp(keyid->fragment, "key3") ||
                !strcmp(keyid->fragment, "recovery") || !strcmp(keyid->fragment, "recovery2") ||
                !strcmp(keyid->fragment, "pk1"));
    }

    //PublicKey getter.
    keyid = DIDDocument_GetDefaultPublicKey(customized_doc);
    CU_ASSERT_PTR_NULL(keyid);

    primaryid1 = DIDURL_NewFromDid(&controller1, "primary");
    CU_ASSERT_PTR_NOT_NULL(primaryid1);
    pk = DIDDocument_GetPublicKey(customized_doc, primaryid1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(primaryid1, PublicKey_GetId(pk)));

    primaryid2 = DIDURL_NewFromDid(&controller2, "primary");
    CU_ASSERT_PTR_NOT_NULL(primaryid2);
    pk = DIDDocument_GetPublicKey(customized_doc, primaryid2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(primaryid2, PublicKey_GetId(pk)));

    primaryid3 = DIDURL_NewFromDid(&controller3, "primary");
    CU_ASSERT_PTR_NOT_NULL(primaryid3);
    pk = DIDDocument_GetPublicKey(customized_doc, primaryid3);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1,DIDURL_Equals(primaryid3, PublicKey_GetId(pk)));

    keyid1 = DIDURL_NewFromDid(&controller1, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    pk = DIDDocument_GetPublicKey(customized_doc, keyid1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid1, PublicKey_GetId(pk)));

    keyid2 = DIDURL_NewFromDid(&controller2, "pk1");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    pk = DIDDocument_GetPublicKey(customized_doc, keyid2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid2, PublicKey_GetId(pk)));

    //Key not exist, should fail.
    keyid = DIDURL_NewFromDid(customized_did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    pk = DIDDocument_GetPublicKey(customized_doc, keyid);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(keyid);

    // Selector
    size = DIDDocument_SelectPublicKeys(customized_doc, default_type, NULL, pks, 8);
    CU_ASSERT_EQUAL(8, size);

    size = DIDDocument_SelectPublicKeys(customized_doc, NULL, primaryid1, pks, 8);
    CU_ASSERT_EQUAL(1, size);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid1));
    DIDURL_Destroy(primaryid1);

    size = DIDDocument_SelectPublicKeys(customized_doc, default_type, primaryid2, pks, 8);
    CU_ASSERT_EQUAL(1, size);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid2));
    DIDURL_Destroy(primaryid2);

    size = DIDDocument_SelectPublicKeys(customized_doc, NULL, keyid1, pks, 8);
    CU_ASSERT_EQUAL(1, size);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid1));
    DIDURL_Destroy(keyid1);

    size = DIDDocument_SelectPublicKeys(customized_doc, default_type, keyid2, pks, 8);
    CU_ASSERT_EQUAL(1, size);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid2));
    DIDURL_Destroy(keyid2);

    DIDURL_Destroy(primaryid3);
    TestData_Free();
}

static void test_multictmdoc_get_publickey(void)
{
    PublicKey *pks[10] = {0};
    PublicKey *pk;
    DIDURL *keyid, *keyid1, *keyid2, *keyid3, *primaryid1;
    DID *customized_did, controller1, controller2, controller3;
    ssize_t size;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("controller", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    DIDDocument *customized_doc = TestData_GetDocument("customized-multisigone", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    customized_did = DIDDocument_GetSubject(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(customized_did);

    DID *controllers[3] = {0};
    size = DIDDocument_GetControllers(customized_doc, controllers, 3);
    CU_ASSERT_EQUAL(3, size);
    DID_Copy(&controller1, controllers[0]);
    DID_Copy(&controller2, controllers[1]);
    DID_Copy(&controller3, controllers[2]);

    CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(customized_doc));

    size = DIDDocument_GetPublicKeys(customized_doc, pks, 10);
    CU_ASSERT_EQUAL(8, size);

    for (i = 0; i < size; i++) {
        pk = pks[i];
        keyid = PublicKey_GetId(pk);

        DID *controller = contains_DID(controllers, 3, &keyid->did);
        if (!controller) {
            CU_ASSERT_EQUAL(1, DID_Equals(customized_did, &keyid->did));
            controller = customized_did;
        }

        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

        if (!strcmp(keyid->fragment, "recovery") || !strcmp(keyid->fragment, "recovery2")) {
            CU_ASSERT_NOT_EQUAL(1, DID_Equals(controller, PublicKey_GetController(pk)));
        } else {
            CU_ASSERT_TRUE(contains_DID(controllers, 3, &keyid->did) ||
                   DID_Equals(controller, PublicKey_GetController(pk)));
            CU_ASSERT_TRUE(!strcmp(keyid->fragment, "k1") ||
                    !strcmp(keyid->fragment, "k2") || !strcmp(keyid->fragment, "primary") ||
                    !strcmp(keyid->fragment, "key2") || !strcmp(keyid->fragment, "key3") ||
                    !strcmp(keyid->fragment, "pk1"));
        }
    }

    //PublicKey getter.
    keyid = DIDDocument_GetDefaultPublicKey(customized_doc);
    CU_ASSERT_PTR_NULL(keyid);

    keyid1 = DIDURL_NewFromDid(customized_did, "k1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    pk = DIDDocument_GetPublicKey(customized_doc, keyid1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid1, PublicKey_GetId(pk)));

    primaryid1 = DIDURL_NewFromDid(&controller1, "primary");
    CU_ASSERT_PTR_NOT_NULL(primaryid1);
    pk = DIDDocument_GetPublicKey(customized_doc, primaryid1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(primaryid1, PublicKey_GetId(pk)));

    keyid2 = DIDURL_NewFromDid(&controller1, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    pk = DIDDocument_GetPublicKey(customized_doc, keyid2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid2, PublicKey_GetId(pk)));

    keyid3 = DIDURL_NewFromDid(&controller2, "pk1");
    CU_ASSERT_PTR_NOT_NULL(keyid3);
    pk = DIDDocument_GetPublicKey(customized_doc, keyid3);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid3, PublicKey_GetId(pk)));
    DIDURL_Destroy(keyid3);

    //Key not exist, should fail.
    keyid = DIDURL_NewFromDid(customized_did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    pk = DIDDocument_GetPublicKey(customized_doc, keyid);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(keyid);

    keyid = DIDURL_NewFromDid(&controller1, "notExist");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    pk = DIDDocument_GetPublicKey(customized_doc, keyid);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(keyid);

    keyid = DIDURL_NewFromDid(&controller1, "recovery");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    pk = DIDDocument_GetPublicKey(customized_doc, keyid);
    CU_ASSERT_PTR_NOT_NULL(pk);
    DIDURL_Destroy(keyid);

    // Selector
    CU_ASSERT_EQUAL(10, DIDDocument_SelectPublicKeys(customized_doc, default_type, NULL, pks, 10));

    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(customized_doc, NULL, primaryid1, pks, 10));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid1));
    DIDURL_Destroy(primaryid1);

    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(customized_doc, default_type, keyid1, pks, 10));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid1));
    DIDURL_Destroy(keyid1);

    CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(customized_doc, NULL, keyid2, pks, 10));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid2));
    DIDURL_Destroy(keyid2);

    TestData_Free();
}

static void test_multictmdoc_add_publickey(void)
{
    DIDDocument *sealeddoc, *controller1_doc, *controller2_doc, *controller3_doc, *customized_doc;
    DIDDocumentBuilder *builder;
    DID *customized_did, *controller1, *controller2, *controller3;
    DIDURL *keyid, *keyid1, *keyid2;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    PublicKey *pk;
    const char *keybase;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(controller1);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(controller2);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);
    controller3 = DIDDocument_GetSubject(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(controller3);

    customized_doc = TestData_GetDocument("customized-multisigone", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    customized_did = DIDDocument_GetSubject(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(customized_did);

    DID *controllers[3] = {0};
    CU_ASSERT_EQUAL(3, DIDDocument_GetControllers(customized_doc, controllers, 3));
    CU_ASSERT_PTR_NOT_NULL(contains_DID(controllers, 3, controller1));
    CU_ASSERT_PTR_NOT_NULL(contains_DID(controllers, 3, controller2));
    CU_ASSERT_PTR_NOT_NULL(contains_DID(controllers, 3, controller3));

    builder = DIDDocument_Edit(customized_doc, controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Add 2 public keys
    keyid1 = DIDURL_NewFromDid(customized_did, "test1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, keyid1, customized_did, keybase));

    keyid2 = DIDURL_NewFromDid(customized_did, "test2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid2, keybase));

    //add controller's pk, fail
    keyid = DIDURL_NewFromDid(controller1, "test3");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, keyid, customized_did, keybase));
    CU_ASSERT_STRING_EQUAL("The key id does not owned by this DID.", DIDError_GetLastErrorMessage());
    DIDURL_Destroy(keyid);

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    pk = DIDDocument_GetPublicKey(sealeddoc, keyid1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid1, PublicKey_GetId(pk)));
    CU_ASSERT_EQUAL(1, DID_Equals(customized_did, PublicKey_GetController(pk)));
    DIDURL_Destroy(keyid1);

    pk = DIDDocument_GetAuthenticationKey(sealeddoc, keyid2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid2, PublicKey_GetId(pk)));
    CU_ASSERT_EQUAL(1, DID_Equals(customized_did, PublicKey_GetController(pk)));
    DIDURL_Destroy(keyid2);

    // Check the final count.
    CU_ASSERT_EQUAL(10, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(8, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_multictmdoc_remove_publickey(void)
{
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    DIDURL *recoveryid, *keyid1, *keyid2, *keyid;
    PublicKey *pk;
    DID *customized_did, controller1, controller2, controller3;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    DIDDocument *controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);

    DIDDocument *controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));

    DIDDocument *customized_doc = TestData_GetDocument("customized-multisigone", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    customized_did = DIDDocument_GetSubject(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(customized_did);

    DID *controllers[3] = {0};
    CU_ASSERT_EQUAL(3, DIDDocument_GetControllers(customized_doc, controllers, 3));
    DID_Copy(&controller1, controllers[0]);
    DID_Copy(&controller2, controllers[1]);
    DID_Copy(&controller3, controllers[2]);

    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // can not remove the controller's key
    keyid = DIDURL_NewFromDid(&controller1, "primary");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid, false));
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid, true));
    CU_ASSERT_STRING_EQUAL("Can't remove other DID's key or controller's key!!!!", DIDError_GetLastErrorMessage());
    DIDURL_Destroy(keyid);

    keyid = DIDURL_NewFromDid(&controller2, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid, false));
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid, true));
    CU_ASSERT_STRING_EQUAL("Can't remove other DID's key or controller's key!!!!", DIDError_GetLastErrorMessage());

    keyid1 = DIDURL_NewFromDid(customized_did, "k1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid1, false));

    keyid2 = DIDURL_NewFromDid(customized_did, "k2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid2, true));

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    // Check existence
    recoveryid = DIDURL_NewFromDid(&controller1, "recovery");
    CU_ASSERT_PTR_NOT_NULL(recoveryid);
    pk = DIDDocument_GetPublicKey(sealeddoc, recoveryid);
    CU_ASSERT_PTR_NOT_NULL(pk);
    DIDURL_Destroy(recoveryid);

    CU_ASSERT_PTR_NULL(DIDDocument_GetPublicKey(sealeddoc, keyid));
    DIDURL_Destroy(keyid);

    CU_ASSERT_PTR_NULL(DIDDocument_GetPublicKey(sealeddoc, keyid1));
    DIDURL_Destroy(keyid1);

    CU_ASSERT_PTR_NULL(DIDDocument_GetPublicKey(sealeddoc, keyid2));
    DIDURL_Destroy(keyid2);

    // Check the final count.
    CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(6, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_multictmdoc_get_authentication_key(void)
{
    DIDDocument *customized_doc;
    PublicKey *pks[7];
    ssize_t size;
    PublicKey *pk;
    DIDURL *keyid1, *keyid2, *keyid, *primaryid1;
    DID *customized_did, controller1, controller2, controller3;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("controller", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    customized_doc = TestData_GetDocument("customized-multisigtwo", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    customized_did = DIDDocument_GetSubject(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(customized_did);

    DID *controllers[3] = {0};
    CU_ASSERT_EQUAL(3, DIDDocument_GetControllers(customized_doc, controllers, 3));
    DID_Copy(&controller1, controllers[0]);
    DID_Copy(&controller2, controllers[1]);
    DID_Copy(&controller3, controllers[2]);

    CU_ASSERT_EQUAL(7, DIDDocument_GetAuthenticationCount(customized_doc));

    size = DIDDocument_GetAuthenticationKeys(customized_doc, pks, 7);
    CU_ASSERT_EQUAL(7, size);

    for (i = 0; i < size; i++) {
        pk = pks[i];
        keyid = PublicKey_GetId(pk);

        DID *controller = contains_DID(controllers, 3, &keyid->did);
        if (!controller) {
            CU_ASSERT_EQUAL(1, DID_Equals(customized_did, &keyid->did));
            controller = customized_did;
        }

        CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));
        CU_ASSERT_TRUE(!strcmp(keyid->fragment, "k1") ||
                    !strcmp(keyid->fragment, "k2") || !strcmp(keyid->fragment, "primary") ||
                    !strcmp(keyid->fragment, "key2") || !strcmp(keyid->fragment, "key3") ||
                    !strcmp(keyid->fragment, "pk1"));
    }

    // AuthenticationKey getter
    primaryid1 = DIDURL_NewFromDid(&controller1, "primary");
    CU_ASSERT_PTR_NOT_NULL(primaryid1);
    pk = DIDDocument_GetAuthenticationKey(customized_doc, primaryid1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(primaryid1, PublicKey_GetId(pk)));

    keyid1 = DIDURL_NewFromDid(&controller1, "key3");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    pk = DIDDocument_GetAuthenticationKey(customized_doc, keyid1);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid1, PublicKey_GetId(pk)));
    DIDURL_Destroy(keyid1);

    keyid1 = DIDURL_NewFromDid(customized_did, "k2");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetAuthenticationKey(customized_doc, keyid1));

    keyid2 = DIDURL_NewFromDid(&controller2, "pk1");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    pk = DIDDocument_GetAuthenticationKey(customized_doc, keyid2);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid2, PublicKey_GetId(pk)));

    //key not exist, should fail.
    keyid = DIDURL_NewFromDid(customized_did, "notExist");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    pk = DIDDocument_GetAuthenticationKey(customized_doc, keyid);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(keyid);

    keyid = DIDURL_NewFromDid(&controller2, "notExist");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    pk = DIDDocument_GetAuthenticationKey(customized_doc, keyid);
    CU_ASSERT_PTR_NULL(pk);
    DIDURL_Destroy(keyid);

    // Selector
    CU_ASSERT_EQUAL(7, DIDDocument_SelectAuthenticationKeys(customized_doc, default_type, NULL, pks, 7));

    CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(customized_doc, NULL, keyid1, pks, 7));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid1));
    DIDURL_Destroy(keyid1);

    CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(customized_doc, default_type, keyid2, pks, 7));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), keyid2));
    DIDURL_Destroy(keyid2);

    CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(customized_doc, NULL, primaryid1, pks, 7));
    CU_ASSERT_EQUAL(1, DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid1));
    DIDURL_Destroy(primaryid1);

    TestData_Free();
}

static void test_multictmdoc_add_authentication_key(void)
{
    DIDDocument *sealeddoc, *controller1_doc, *controller2_doc, *controller3_doc, *customized_doc;
    DIDDocumentBuilder *builder;
    DID *customized_did, *controller1, *controller2, *controller3;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    DIDURL *keyid1, *keyid2, *keyid3, *keyid4, *keyid;
    const char *keybase, *data;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(controller1);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(controller2);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);
    controller3 = DIDDocument_GetSubject(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(controller3);

    customized_doc = TestData_GetDocument("customized-multisigtwo-empty", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    customized_did = DIDDocument_GetSubject(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(customized_did);

    DID *controllers[3] = {0};
    CU_ASSERT_EQUAL(3, DIDDocument_GetControllers(customized_doc, controllers, 3));
    CU_ASSERT_PTR_NOT_NULL(contains_DID(controllers, 3, controller1));
    CU_ASSERT_PTR_NOT_NULL(contains_DID(controllers, 3, controller2));
    CU_ASSERT_PTR_NOT_NULL(contains_DID(controllers, 3, controller3));

    builder = DIDDocument_Edit(customized_doc, controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Try to add the controller's key, should fail.
    keyid1 = DIDURL_NewFromDid(controller1, "test1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid1, keybase));

    keyid2 = DIDURL_NewFromDid(controller2, "test2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, keyid2, customized_did, keybase));
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid2, keybase));

    // Add new keys
    keyid3 = DIDURL_NewFromDid(customized_did, "test3");
    CU_ASSERT_PTR_NOT_NULL(keyid3);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid3, keybase));

    keyid4 = DIDURL_NewFromDid(customized_did, "test4");
    CU_ASSERT_PTR_NOT_NULL(keyid4);
    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid4, keybase));

    // Try to add a non existing key, should fail.
    keyid = DIDURL_NewFromDid(customized_did, "notExistKey");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, NULL));
    DIDURL_Destroy(keyid);

    // Try to add a key not owned by self, should fail.
    keyid = DIDURL_NewFromDid(controller1, "recovery");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, NULL));
    DIDURL_Destroy(keyid);

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(0, DIDDocument_IsValid(sealeddoc));
    DIDDocumentBuilder_Destroy(builder);

    data = DIDDocument_ToJson(sealeddoc, true);
    CU_ASSERT_PTR_NOT_NULL(data);
    DIDDocument_Destroy(sealeddoc);

    sealeddoc = DIDDocument_SignDIDDocument(controller1_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));

    // Check existence
    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(sealeddoc, keyid1));
    DIDURL_Destroy(keyid1);

    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(sealeddoc, keyid2));
    DIDURL_Destroy(keyid2);

    PublicKey *pk = DIDDocument_GetPublicKey(sealeddoc, keyid3);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid3, PublicKey_GetId(pk)));
    DIDURL_Destroy(keyid3);

    pk = DIDDocument_GetPublicKey(sealeddoc, keyid4);
    CU_ASSERT_PTR_NOT_NULL(pk);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(keyid4, PublicKey_GetId(pk)));
    DIDURL_Destroy(keyid4);

    // Check the final count.
    CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(8, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_multictmdoc_remove_authentication_key(void)
{
    DIDDocument *sealeddoc, *controller1_doc, *controller2_doc, *controller3_doc, *customized_doc;
    DIDDocumentBuilder *builder;
    DID *customized_did, *controller1, *controller2, *controller3;
    DIDURL *keyid1, *keyid2, *keyid;
    const char *data;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(controller1);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(controller2);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);
    controller3 = DIDDocument_GetSubject(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(controller3);

    customized_doc = TestData_GetDocument("customized-multisigtwo", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    customized_did = DIDDocument_GetSubject(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(customized_did);

    CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(customized_doc));
    CU_ASSERT_EQUAL(7, DIDDocument_GetAuthenticationCount(customized_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthorizationCount(customized_doc));

    builder = DIDDocument_Edit(customized_doc, controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Remove keys
    keyid1 = DIDURL_NewFromDid(customized_did, "k1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, keyid1));

    keyid2 = DIDURL_NewFromDid(customized_did, "k2");
    CU_ASSERT_PTR_NOT_NULL(keyid2);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, keyid2));

    // Key not exist, should fail.
    keyid = DIDURL_NewFromDid(customized_did, "notExistKey");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, keyid));
    DIDURL_Destroy(keyid);

    // Remove controller's key, should fail.
    keyid = DIDURL_NewFromDid(controller1, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, keyid));
    DIDURL_Destroy(keyid);

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(0, DIDDocument_IsValid(sealeddoc));

    data = DIDDocument_ToJson(sealeddoc, true);
    DIDDocument_Destroy(sealeddoc);
    CU_ASSERT_PTR_NOT_NULL(data);

    sealeddoc = DIDDocument_SignDIDDocument(controller1_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));

    //check existence
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetPublicKey(sealeddoc, keyid1));
    DIDURL_Destroy(keyid1);

    CU_ASSERT_PTR_NULL(DIDDocument_GetAuthenticationKey(sealeddoc, keyid2));
    DIDURL_Destroy(keyid2);

    // Check the final count.
    CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(sealeddoc));
    CU_ASSERT_EQUAL(6, DIDDocument_GetAuthenticationCount(sealeddoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthorizationCount(sealeddoc));

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_multictmdoc_add_authorization_key(void)
{
    DIDDocument *customized_doc, *controller2_doc;
    DIDDocumentBuilder *builder;
    DIDURL *keyid1;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    HDKey _dkey, *dkey;
    const char *keybase, *idstring;
    DID *customized_did, controller;
    PublicKey *pks[3];
    ssize_t size;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    customized_doc = TestData_GetDocument("customized-multisigthree", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    customized_did = DIDDocument_GetSubject(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(customized_did);

    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthorizationCount(customized_doc));

    size = DIDDocument_GetAuthorizationKeys(customized_doc, pks, 3);
    CU_ASSERT_EQUAL(2, size);

    for (i = 0; i < size; i++)
        CU_ASSERT_EQUAL(0, DID_Equals(&pks[i]->id.did, customized_did));

    builder = DIDDocument_Edit(customized_doc, controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    // Try to add authorization key, fail.
    keyid1 = DIDURL_NewFromDid(customized_did, "test1");
    CU_ASSERT_PTR_NOT_NULL(keyid1);
    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    idstring = HDKey_GetAddress(dkey);
    CU_ASSERT_PTR_NOT_NULL(idstring);
    DID_Init(&controller, idstring);
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, keyid1, &controller, keybase));
    DIDURL_Destroy(keyid1);

    CU_ASSERT_PTR_NULL(DIDDocumentBuilder_Seal(builder, storepass));
    DIDDocumentBuilder_Destroy(builder);

    TestData_Free();
}

static void test_multictmdoc_get_credential(void)
{
    DIDDocument *customized_doc, *controller1_doc;
    DIDURL *credid;
    DID *controller1;
    Credential *vcs[1];
    ssize_t size;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(controller1);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("controller", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));

    customized_doc = TestData_GetDocument("customized-multisigthree", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));

    size = DIDDocument_GetCredentials(customized_doc, vcs, 1);
    CU_ASSERT_EQUAL(1, size);

    for (i = 0; i < size; i++) {
        CU_ASSERT_EQUAL(1, DID_Equals(&customized_doc->did, &vcs[i]->id.did));
        CU_ASSERT_EQUAL(1, DID_Equals(&customized_doc->did, Credential_GetOwner(vcs[i])));
        CU_ASSERT_TRUE(!strcmp(vcs[i]->id.fragment, "vc-1"));
    }

    credid = DIDURL_NewFromDid(controller1, "recovery");
    CU_ASSERT_PTR_NOT_NULL(credid);
    CU_ASSERT_PTR_NULL(DIDDocument_GetCredential(customized_doc, credid));
    DIDURL_Destroy(credid);

    // Credential selector.
    CU_ASSERT_EQUAL(1, DIDDocument_SelectCredentials(customized_doc, "SelfProclaimedCredential",
            NULL, vcs, sizeof(vcs)/sizeof(Credential*)));

    TestData_Free();
}

static void test_multictmdoc_add_credential(void)
{
    DIDDocument *customized_doc, *controller1_doc, *controller2_doc, *controller3_doc;
    DIDDocumentBuilder *builder;
    DIDURL *credid, *signkey;
    time_t expires;
    const char *data;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);
    signkey = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller2_doc);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);

    customized_doc = TestData_GetDocument("customized-multisigthree", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));

    expires = DIDDocument_GetExpires(customized_doc);

    builder = DIDDocument_Edit(customized_doc, controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    credid = DIDURL_NewFromDid(&customized_doc->did, "vc-2");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfProclaimedCredential"};
    Property props[2];
    props[0].key = "phone";
    props[0].value = "5737837";
    props[1].key = "address";
    props[1].value = "Shanghai";

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid,
            types, 2, props, 2, expires, signkey, storepass));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(0, DIDDocument_IsValid(customized_doc));

    data = DIDDocument_ToJson(customized_doc, true);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized_doc = DIDDocument_SignDIDDocument(controller1_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(0, DIDDocument_IsValid(customized_doc));

    data = DIDDocument_ToJson(customized_doc, true);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized_doc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(2, DIDDocument_GetCredentialCount(customized_doc));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetCredential(customized_doc, credid));
    DIDURL_Destroy(credid);

    DIDDocument_Destroy(customized_doc);
    TestData_Free();
}

static void test_multictmdoc_remove_credential(void)
{
    DIDDocument *customized_doc, *controller1_doc, *controller2_doc, *controller3_doc;
    DIDDocumentBuilder *builder;
    DIDURL *credid, *signkey;
    const char *data;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);
    signkey = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller2_doc);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller3_doc);

    customized_doc = TestData_GetDocument("customized-multisigthree", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));

    builder = DIDDocument_Edit(customized_doc, controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    credid = DIDURL_NewFromDid(&customized_doc->did, "vc-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveCredential(builder, credid));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(0, DIDDocument_IsValid(customized_doc));

    data = DIDDocument_ToJson(customized_doc, true);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized_doc = DIDDocument_SignDIDDocument(controller1_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(0, DIDDocument_IsValid(customized_doc));

    data = DIDDocument_ToJson(customized_doc, true);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized_doc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(0, DIDDocument_GetCredentialCount(customized_doc));
    CU_ASSERT_PTR_NULL(DIDDocument_GetCredential(customized_doc, credid));

    DIDDocument_Destroy(customized_doc);
    DIDURL_Destroy(credid);
    TestData_Free();
}

static void test_multictmdoc_get_service(void)
{
    DIDDocument *customized_doc, *controller1_doc;
    DIDURL *serviceid;
    DID *controller1;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(controller1);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("controller", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));

    customized_doc = TestData_GetDocument("customized-multisigthree", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(2, DIDDocument_GetServiceCount(customized_doc));

    serviceid = DIDURL_NewFromDid(&customized_doc->did, "test-svc-1");
    CU_ASSERT_PTR_NOT_NULL(serviceid);
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetService(customized_doc, serviceid));
    DIDURL_Destroy(serviceid);

    serviceid = DIDURL_NewFromDid(&customized_doc->did, "test-svc-2");
    CU_ASSERT_PTR_NOT_NULL(serviceid);
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetService(customized_doc, serviceid));
    DIDURL_Destroy(serviceid);

    serviceid = DIDURL_NewFromDid(controller1, "carrier");
    CU_ASSERT_PTR_NOT_NULL(serviceid);
    CU_ASSERT_PTR_NULL(DIDDocument_GetService(customized_doc, serviceid));
    DIDURL_Destroy(serviceid);

    TestData_Free();
}

static void test_multictmdoc_add_service(void)
{
    DIDDocument *customized_doc, *controller1_doc, *controller3_doc;
    DIDDocumentBuilder *builder;
    DIDURL *id1, *id2, *id3;
    Property props1[4];
    const char *data, *props2;
    Service *service;

    props1[0].key = "abc";
    props1[0].value = "helloworld";
    props1[1].key = "bar";
    props1[1].value = "foobar";
    props1[2].key = "lalala...";
    props1[2].value = "ABC";
    props1[3].key = "Helloworld";
    props1[3].value = "English";

    props2 = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\"}";

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller3_doc);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("controller", NULL, 0));

    customized_doc = TestData_GetDocument("customized-multisigtwo", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(2, DIDDocument_GetServiceCount(customized_doc));

    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    id1 = DIDURL_NewFromDid(&customized_doc->did, "test-svc-3");
    CU_ASSERT_PTR_NOT_NULL(id1);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, id1, "Service.Testing3",
            "https://www.elastos.org/testing3", NULL, 0));

    id2 = DIDURL_NewFromDid(&customized_doc->did, "test-svc-4");
    CU_ASSERT_PTR_NOT_NULL(id2);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, id2, "Service.Testing",
            "https://www.elastos.org/testing2", props1, 4));

    id3 = DIDURL_NewFromDid(&customized_doc->did, "test-svc-5");
    CU_ASSERT_PTR_NOT_NULL(id3);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddServiceByString(builder, id3, "Service.Testing",
            "https://www.elastos.org/testing3", props2));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(0, DIDDocument_IsValid(customized_doc));

    data = DIDDocument_ToJson(customized_doc, true);
    DIDDocument_Destroy(customized_doc);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized_doc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(5, DIDDocument_GetServiceCount(customized_doc));
    CU_ASSERT_PTR_NOT_NULL(DIDDocument_GetService(customized_doc, id1));
    DIDURL_Destroy(id1);

    service = DIDDocument_GetService(customized_doc, id2);
    CU_ASSERT_PTR_NOT_NULL(service);

    CU_ASSERT_EQUAL(4, Service_GetPropertyCount(service));
    data = Service_GetProperty(service, "abc");
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL("helloworld", data);
    free((void*)data);
    data = Service_GetProperty(service, "bar");
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL("foobar", data);
    free((void*)data);
    data = Service_GetProperty(service, "lalala...");
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL("ABC", data);
    free((void*)data);
    data = Service_GetProperty(service, "Helloworld");
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL("English", data);
    free((void*)data);

    service = DIDDocument_GetService(customized_doc, id3);
    CU_ASSERT_PTR_NOT_NULL(service);

    CU_ASSERT_EQUAL(12, Service_GetPropertyCount(service));
    data = Service_GetProperty(service, "numberValue");
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL("1234", data);
    free((void*)data);

    data = Service_GetProperty(service, "nationality");
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL("Canadian", data);
    free((void*)data);

    data = Service_GetProperty(service, "worksFor");
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_EQUAL(strlen("[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\"]}]"),
            strlen(data));
    free((void*)data);

    data = Service_GetProperty(service, "alternateName");
    CU_ASSERT_PTR_NOT_NULL(data);
    CU_ASSERT_STRING_EQUAL("Jason Holtslander", data);
    free((void*)data);

    DIDURL_Destroy(id3);
    DIDURL_Destroy(id2);
    DIDDocument_Destroy(customized_doc);
    TestData_Free();
}

static void test_multictmdoc_remove_service(void)
{
    DIDDocument *customized_doc, *controllerdoc;
    DIDDocumentBuilder *builder;
    DIDURL *serviceid;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controllerdoc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controllerdoc);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("issuer", NULL, 0));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("document", NULL, 0));

    customized_doc = TestData_GetDocument("customized-multisigone", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(2, DIDDocument_GetServiceCount(customized_doc));

    builder = DIDDocument_Edit(customized_doc, controllerdoc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    serviceid = DIDURL_NewFromDid(&customized_doc->did, "test-svc-2");
    CU_ASSERT_PTR_NOT_NULL(serviceid);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveService(builder, serviceid));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(1, DIDDocument_GetServiceCount(customized_doc));
    CU_ASSERT_PTR_NULL(DIDDocument_GetService(customized_doc, serviceid));

    DIDDocument_Destroy(customized_doc);
    DIDURL_Destroy(serviceid);
    TestData_Free();
}

static void test_multictmdoc_get_controller(void)
{
    DIDDocument *customized_doc, *controller1_doc, *controller2_doc, *controller3_doc;
    DID *controller1, *controller2, *controller3;
    DID *controllers[3];

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(controller1);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(controller2);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller3_doc);
    controller3 = DIDDocument_GetSubject(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(controller3);

    customized_doc = TestData_GetDocument("customized-multisigthree", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetControllers(customized_doc, controllers, 3));

    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(customized_doc, controller1));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(customized_doc, controller2));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(customized_doc, controller3));

    TestData_Free();
}

static void test_multictmdoc_add_controller(void)
{
    DIDDocument *sealeddoc, *controller1_doc, *controller2_doc, *controller3_doc, *customized_doc;
    DIDDocumentBuilder *builder;
    DID *controller1, *controller2, *controller3;
    const char *data;
    ssize_t size;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);
    controller3 = DIDDocument_GetSubject(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3);

    customized_doc = TestData_GetDocument("customized-did", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));

    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(customized_doc));

    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, controller1));
    CU_ASSERT_STRING_EQUAL("The controller already exists in the document.", DIDError_GetLastErrorMessage());
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, controller2));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, controller3));

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NULL(sealeddoc);
    CU_ASSERT_STRING_EQUAL("Please set multisig first for multi-controller DID.", DIDError_GetLastErrorMessage());

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 4));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 2));

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_NOT_EQUAL(1, DIDDocument_IsValid(sealeddoc));

    data = DIDDocument_ToJson(sealeddoc, true);
    CU_ASSERT_PTR_NOT_NULL(data);
    DIDDocument_Destroy(sealeddoc);

    sealeddoc = DIDDocument_SignDIDDocument(controller2_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);
    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));

    data = DIDDocument_ToJson(sealeddoc, true);
    CU_ASSERT_PTR_NOT_NULL(data);

    customized_doc = DIDDocument_SignDIDDocument(controller3_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NULL(customized_doc);
    CU_ASSERT_STRING_EQUAL("The signers are enough.", DIDError_GetLastErrorMessage());

    CU_ASSERT_EQUAL_FATAL(3, DIDDocument_GetControllerCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(sealeddoc, controller1));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(sealeddoc, controller2));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(sealeddoc, controller3));

    size = DIDDocument_GetProofCount(sealeddoc);
    CU_ASSERT_EQUAL(2, size);

    for (i = 0; i < size; i++) {
        DIDURL *creater = DIDDocument_GetProofCreater(sealeddoc, i);
        CU_ASSERT_PTR_NOT_NULL(creater);
        CU_ASSERT_EQUAL(1, DID_Equals(&creater->did, controller1) == 1 || DID_Equals(&creater->did, controller2) == 1);
    }

    DIDDocument_Destroy(sealeddoc);

    TestData_Free();
}

static void test_multictmdoc_remove_controller(void)
{
    DIDDocument *sealeddoc, *controller1_doc, *controller2_doc, *controller3_doc, *customized_doc;
    DIDDocumentBuilder *builder;
    DID customized_did, *controller1, *controller2, *controller3;
    Credential *cred;
    DIDURL *creater, *signkey1, *signkey2, *signkey3, *credid;
    const char *data;
    ssize_t size;
    int i;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);
    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(controller1);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(controller2);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);
    controller3 = DIDDocument_GetSubject(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(controller3);

    customized_doc = TestData_GetDocument("customized-multisigthree", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));
    DID_Copy(&customized_did, &customized_doc->did);

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(customized_doc));

    credid = DIDURL_NewFromDid(&customized_did, "vc-1");
    CU_ASSERT_PTR_NOT_NULL(credid);
    cred = DIDDocument_GetCredential(customized_doc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(signkey3, Credential_GetProofMethod(cred)));

    builder = DIDDocument_Edit(customized_doc, controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, controller3));
    CU_ASSERT_STRING_EQUAL("There are self-proclaimed credentials signed by controller, please remove or renew these credentials at first.", DIDError_GetLastErrorMessage());

    CU_ASSERT_NOT_EQUAL(-1,
            DIDDocumentBuilder_RenewSelfProclaimedCredential(builder, controller3, signkey2, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, controller3));
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, controller2));
    CU_ASSERT_STRING_EQUAL("Can't remove the controller specified to seal document builder.",
           DIDError_GetLastErrorMessage());
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_SetMultisig(builder, 2));

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);

    data = DIDDocument_ToJson(sealeddoc, true);
    DIDDocument_Destroy(sealeddoc);
    CU_ASSERT_PTR_NOT_NULL(data);

    sealeddoc = DIDDocument_SignDIDDocument(controller1_doc, data, storepass);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);

    CU_ASSERT_EQUAL(1, DIDDocument_IsValid(sealeddoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetControllerCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetCredentialCount(sealeddoc));
    cred = DIDDocument_GetCredential(sealeddoc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);
    DIDURL_Destroy(credid);
    CU_ASSERT_EQUAL(1, DIDURL_Equals(signkey2, Credential_GetProofMethod(cred)));
    size = DIDDocument_GetProofCount(sealeddoc);
    CU_ASSERT_EQUAL(2, size);

    for (i = 0; i < size; i++) {
        creater = DIDDocument_GetProofCreater(sealeddoc, i);
        CU_ASSERT_PTR_NOT_NULL(creater);
        CU_ASSERT_EQUAL(1, DID_Equals(&creater->did, controller1) == 1 || DID_Equals(&creater->did, controller2) == 1);
    }

    builder = DIDDocument_Edit(sealeddoc, controller1_doc);
    DIDDocument_Destroy(sealeddoc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);

    CU_ASSERT_NOT_EQUAL(-1,
            DIDDocumentBuilder_RemoveSelfProclaimedCredential(builder, controller2));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, controller2));
    CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveController(builder, controller1));
    CU_ASSERT_STRING_EQUAL("Can't remove the controller specified to seal document builder.", DIDError_GetLastErrorMessage());

    sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(sealeddoc);

    CU_ASSERT_EQUAL(0, DIDDocument_GetCredentialCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_GetControllerCount(sealeddoc));
    CU_ASSERT_EQUAL(1, DIDDocument_ContainsController(sealeddoc, controller1));
    CU_ASSERT_NOT_EQUAL(1, DIDDocument_ContainsController(sealeddoc, controller2));
    CU_ASSERT_NOT_EQUAL(1, DIDDocument_ContainsController(sealeddoc, controller3));

    size = DIDDocument_GetProofCount(sealeddoc);
    CU_ASSERT_EQUAL(1, size);

    for (i = 0; i < size; i++) {
        DIDURL *creater = DIDDocument_GetProofCreater(sealeddoc, i);
        CU_ASSERT_PTR_NOT_NULL(creater);
        CU_ASSERT_EQUAL(1, DID_Equals(&creater->did, controller1));
    }

    DIDDocument_Destroy(sealeddoc);
    TestData_Free();
}

static void test_multictmdoc_remove_proof(void)
{
    DIDDocument *controller1_doc, *controller2_doc, *controller3_doc, *customized_doc;
    DIDDocumentBuilder *builder;
    DID customized_did, *controller1, *controller2, *controller3;
    DIDURL *signkey1, *signkey2, *signkey3;

    DIDStore *store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1_doc);
    controller1 = DIDDocument_GetSubject(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller1);
    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(controller1);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2_doc);
    controller2 = DIDDocument_GetSubject(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller2);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(controller2);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3_doc);
    controller3 = DIDDocument_GetSubject(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(controller3);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(controller3);

    customized_doc = TestData_GetDocument("customized-multisigtwo", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(customized_doc);
    CU_ASSERT_EQUAL_FATAL(1, DIDDocument_IsValid(customized_doc));
    DID_Copy(&customized_did, &customized_doc->did);

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetProofCount(customized_doc));
    CU_ASSERT_EQUAL(1,DIDURL_Equals(signkey2, DIDDocument_GetProofCreater(customized_doc, 0)) == 1 ||
            DIDURL_Equals(signkey3, DIDDocument_GetProofCreater(customized_doc, 0)) == 1);
    CU_ASSERT_EQUAL(1,DIDURL_Equals(signkey2, DIDDocument_GetProofCreater(customized_doc, 1)) == 1 ||
            DIDURL_Equals(signkey3, DIDDocument_GetProofCreater(customized_doc, 1)) == 1);

    builder = DIDDocument_Edit(customized_doc, controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveProof(builder, controller2));

    customized_doc = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(customized_doc);

    CU_ASSERT_EQUAL(3, DIDDocument_GetControllerCount(customized_doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetProofCount(customized_doc));
    CU_ASSERT_EQUAL(1,DIDURL_Equals(signkey1, DIDDocument_GetProofCreater(customized_doc, 0)) == 1||
            DIDURL_Equals(signkey3, DIDDocument_GetProofCreater(customized_doc, 0)) == 1);
    CU_ASSERT_EQUAL(1,DIDURL_Equals(signkey1, DIDDocument_GetProofCreater(customized_doc, 1)) == 1||
            DIDURL_Equals(signkey3, DIDDocument_GetProofCreater(customized_doc, 1)) == 1);

    DIDDocument_Destroy(customized_doc);
    TestData_Free();
}

static int ctmdoc_elem_test_suite_init(void)
{
    return  0;
}

static int ctmdoc_elem_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_emptyctmdoc_get_publickey",            test_emptyctmdoc_get_publickey        },
    { "test_ctmdoc_get_publickey",                 test_ctmdoc_get_publickey             },
    { "test_ctmdoc_add_publickey",                 test_ctmdoc_add_publickey             },
    { "test_ctmdoc_remove_publickey",              test_ctmdoc_remove_publickey          },
    { "test_ctmdoc_get_authentication_key",        test_ctmdoc_get_authentication_key    },
    { "test_ctmdoc_add_authentication_key",        test_ctmdoc_add_authentication_key    },
    { "test_ctmdoc_remove_authentication_key",     test_ctmdoc_remove_authentication_key },
    { "test_ctmdoc_get_authorization_key",         test_ctmdoc_get_authorization_key     },
    { "test_ctmdoc_add_authorization_key",         test_ctmdoc_add_authorization_key     },
    //----------------------------------------------------------------------------------------
    { "test_empty_multictmdoc_get_publickey",      test_empty_multictmdoc_get_publickey  },
    { "test_multictmdoc_get_publickey",            test_multictmdoc_get_publickey        },
    { "test_multictmdoc_add_publickey",            test_multictmdoc_add_publickey        },
    { "test_multictmdoc_remove_publickey",         test_multictmdoc_remove_publickey     },
    { "test_multictmdoc_get_authentication_key",   test_multictmdoc_get_authentication_key},
    { "test_multictmdoc_add_authentication_key",   test_multictmdoc_add_authentication_key},
    { "test_multictmdoc_remove_authentication_key",test_multictmdoc_remove_authentication_key},
    { "test_multictmdoc_add_authorization_key",    test_multictmdoc_add_authorization_key },
    { "test_multictmdoc_get_credential",           test_multictmdoc_get_credential        },
    { "test_multictmdoc_add_credential",           test_multictmdoc_add_credential        },
    { "test_multictmdoc_remove_credential",        test_multictmdoc_remove_credential     },
    { "test_multictmdoc_get_service",              test_multictmdoc_get_service           },
    { "test_multictmdoc_add_service",              test_multictmdoc_add_service           },
    { "test_multictmdoc_remove_service",           test_multictmdoc_remove_service        },
    { "test_multictmdoc_get_controller",           test_multictmdoc_get_controller        },
    { "test_multictmdoc_add_controller",           test_multictmdoc_add_controller        },
    { "test_multictmdoc_remove_controller",        test_multictmdoc_remove_controller     },
    { "test_multictmdoc_remove_proof",             test_multictmdoc_remove_proof          },
    { NULL,                                        NULL                                   }
};

static CU_SuiteInfo suite[] = {
    { "customized doc test", ctmdoc_elem_test_suite_init,  ctmdoc_elem_test_suite_cleanup,  NULL, NULL, cases },
    {  NULL,                 NULL,                         NULL,                            NULL, NULL, NULL  }
};

CU_SuiteInfo* ctmdoc_elem_test_suite_info(void)
{
    return suite;
}
