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

static DataParam params[] = {
    { 0, "document", NULL, NULL },    { 1, "user1", NULL, NULL },
    { 2, "user1", NULL, NULL }
};

static void test_diddoc_get_publickey(void)
{
    DIDDocument *doc;
    DID *did;
    PublicKey *pks[4];
    PublicKey *pk;
    DIDURL *id, *defaultkey, *primaryid;
    ssize_t size;
    int i, j;
    bool equal;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);
        CU_ASSERT_EQUAL(DIDDocument_GetPublicKeyCount(doc), 4);

        size = DIDDocument_GetPublicKeys(doc, pks, 4);
        CU_ASSERT_EQUAL(size, 4);

        for (i = 0; i < size; i++) {
            pk = pks[i];
            id = PublicKey_GetId(pk);

            CU_ASSERT_TRUE(DID_Equals(did, &(id->did)));
            CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

            equal = DID_Equals(did, PublicKey_GetController(pk));
            if (!strcmp(id->fragment, "recovery")) {
                CU_ASSERT_FALSE(equal);
            } else {
                CU_ASSERT_TRUE(equal);
            }

            CU_ASSERT_TRUE(!strcmp(id->fragment, "primary") ||
                    !strcmp(id->fragment, "key2") || !strcmp(id->fragment, "key3") ||
                    !strcmp(id->fragment, "recovery"));
        }

        //PublicKey getter.
        defaultkey = DIDDocument_GetDefaultPublicKey(doc);
        CU_ASSERT_PTR_NOT_NULL(defaultkey);

        primaryid = DIDURL_NewByDid(did, "primary");
        CU_ASSERT_PTR_NOT_NULL(primaryid);
        pk = DIDDocument_GetPublicKey(doc, primaryid);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(primaryid, PublicKey_GetId(pk)));
        CU_ASSERT_TRUE(DIDURL_Equals(primaryid, defaultkey));

        id = DIDURL_NewByDid(did, "key2");
        CU_ASSERT_PTR_NOT_NULL(id);
        pk = DIDDocument_GetPublicKey(doc, id);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id, PublicKey_GetId(pk)));
        DIDURL_Destroy(id);

        //Key not exist, should fail.
        id = DIDURL_NewByDid(did, "notExist");
        CU_ASSERT_PTR_NOT_NULL(id);
        pk = DIDDocument_GetPublicKey(doc, id);
        CU_ASSERT_PTR_NULL(pk);
        DIDURL_Destroy(id);

        // Selector
        CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, default_type, defaultkey, pks, 4));
        CU_ASSERT_TRUE(DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid));

        CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, NULL, defaultkey, pks, 4));
        CU_ASSERT_TRUE(DIDURL_Equals(PublicKey_GetId(pks[0]), primaryid));
        DIDURL_Destroy(primaryid);

        CU_ASSERT_EQUAL(4, DIDDocument_SelectPublicKeys(doc, default_type, NULL, pks, 4));

        id = DIDURL_NewByDid(did, "key2");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, default_type, id, pks, 4));
        CU_ASSERT_TRUE(DIDURL_Equals(PublicKey_GetId(pks[0]), id));
        DIDURL_Destroy(id);

        id = DIDURL_NewByDid(did, "key3");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(1, DIDDocument_SelectPublicKeys(doc, NULL, id, pks, 4));
        CU_ASSERT_TRUE(DIDURL_Equals(PublicKey_GetId(pks[0]), id));
        DIDURL_Destroy(id);
    }
}

static void test_diddoc_add_publickey(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    const char *keybase;
    int j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);

        // Add 2 public keys
        DIDURL *id1 = DIDURL_NewByDid(did, "test1");
        CU_ASSERT_PTR_NOT_NULL(id1);
        keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id1, did, keybase));

        DIDURL *id2 = DIDURL_NewByDid(did, "test2");
        CU_ASSERT_PTR_NOT_NULL(id2);
        keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id2, did, keybase));

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        CU_ASSERT_PTR_NOT_NULL(sealeddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        DIDDocumentBuilder_Destroy(builder);

        // Check existence
        PublicKey *pk = DIDDocument_GetPublicKey(sealeddoc, id1);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id1, PublicKey_GetId(pk)));
        DIDURL_Destroy(id1);

        pk = DIDDocument_GetPublicKey(sealeddoc, id2);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id2, PublicKey_GetId(pk)));
        DIDURL_Destroy(id2);

        // Check the final count.
        CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(sealeddoc));
        CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(sealeddoc));
        CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_remove_publickey(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    DIDURL *recoveryid, *keyid;
    int j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);

        // recovery used by authorization, should failed.
        recoveryid = DIDURL_NewByDid(did, "recovery");
        CU_ASSERT_PTR_NOT_NULL(recoveryid);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, recoveryid, false));
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, recoveryid, true));

        keyid = DIDURL_NewByDid(did, "notExistKey");
        CU_ASSERT_PTR_NOT_NULL(keyid);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid, true));
        DIDURL_Destroy(keyid);

        keyid = DIDURL_NewByDid(did, "key2");
        CU_ASSERT_PTR_NOT_NULL(keyid);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder, keyid, true));

        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemovePublicKey(builder,
                DIDDocument_GetDefaultPublicKey(doc), true));

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        DIDDocumentBuilder_Destroy(builder);
        CU_ASSERT_PTR_NOT_NULL_FATAL(sealeddoc);

        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        // Check existence
        PublicKey *pk = DIDDocument_GetPublicKey(sealeddoc, recoveryid);
        CU_ASSERT_PTR_NULL(pk);
        DIDURL_Destroy(recoveryid);

        pk = DIDDocument_GetPublicKey(sealeddoc, keyid);
        CU_ASSERT_PTR_NULL(pk);
        DIDURL_Destroy(keyid);

        // Check the final count.
        CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(sealeddoc));
        CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(sealeddoc));
        CU_ASSERT_EQUAL(0, DIDDocument_GetAuthorizationCount(sealeddoc));

        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_get_authentication_key(void)
{
    DIDDocument *doc;
    DID *did;
    PublicKey *pks[3];
    ssize_t size;
    PublicKey *pk;
    DIDURL *keyid, *id;
    int i, j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(doc));

        size = DIDDocument_GetAuthenticationKeys(doc, pks, 3);
        CU_ASSERT_EQUAL(3, size);

        for (i = 0; i < size; i++) {
            pk = pks[i];
            id = PublicKey_GetId(pk);

            CU_ASSERT_TRUE(DID_Equals(did, &id->did));
            CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

            CU_ASSERT_TRUE(DID_Equals(did, PublicKey_GetController(pk)));

            CU_ASSERT_TRUE(!strcmp(id->fragment, "primary") ||
                    !strcmp(id->fragment, "key2") || !strcmp(id->fragment, "key3"));
        }

        // AuthenticationKey getter
        id = DIDURL_NewByDid(did, "primary");
        CU_ASSERT_PTR_NOT_NULL(id);
        pk = DIDDocument_GetAuthenticationKey(doc, id);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id, PublicKey_GetId(pk)));
        DIDURL_Destroy(id);

        keyid = DIDURL_NewByDid(did, "key3");
        CU_ASSERT_PTR_NOT_NULL(keyid);
        pk = DIDDocument_GetAuthenticationKey(doc, keyid);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(keyid, PublicKey_GetId(pk)));

        //Key not exist, should fail.
        id = DIDURL_NewByDid(did, "notExist");
        CU_ASSERT_PTR_NOT_NULL(id);
        pk = DIDDocument_GetAuthenticationKey(doc, id);
        CU_ASSERT_PTR_NULL(pk);
        DIDURL_Destroy(id);

        // Selector
        CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(doc, default_type, keyid, pks, 3));
        CU_ASSERT_TRUE(DIDURL_Equals(PublicKey_GetId(pks[0]), keyid));

        CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(doc, NULL, keyid, pks, 3));
        CU_ASSERT_TRUE(DIDURL_Equals(PublicKey_GetId(pks[0]), keyid));
        DIDURL_Destroy(keyid);

        CU_ASSERT_EQUAL(3, DIDDocument_SelectAuthenticationKeys(doc, default_type, NULL, pks, 3));

        id = DIDURL_NewByDid(did, "key2");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(doc, default_type, id, pks, 3));
        CU_ASSERT_TRUE(DIDURL_Equals(PublicKey_GetId(pks[0]), id));

        CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthenticationKeys(doc, NULL, id, pks, 3));
        CU_ASSERT_TRUE(DIDURL_Equals(PublicKey_GetId(pks[0]), id));
        DIDURL_Destroy(id);
    }
}

static void test_diddoc_add_authentication_key(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    const char *keybase;
    int j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);

        // Add 2 public keys
        DIDURL *id1 = DIDURL_NewByDid(did, "test1");
        CU_ASSERT_PTR_NOT_NULL(id1);
        keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id1, did, keybase));
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id1, NULL));

        DIDURL *id2 = DIDURL_NewByDid(did, "test2");
        CU_ASSERT_PTR_NOT_NULL(id2);
        keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id2, did, keybase));
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id2, NULL));

        // Add new keys
        DIDURL *id3 = DIDURL_NewByDid(did, "test3");
        CU_ASSERT_PTR_NOT_NULL(id3);
        keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id3, keybase));

        DIDURL *id4 = DIDURL_NewByDid(did, "test4");
        CU_ASSERT_PTR_NOT_NULL(id4);
        keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id4, keybase));

        // Try to add a non existing key, should fail.
        DIDURL *id = DIDURL_NewByDid(did, "notExistKey");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id, NULL));
        DIDURL_Destroy(id);

        // Try to add a key not owned by self, should fail.
        id = DIDURL_NewByDid(did, "recovery");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id, NULL));
        DIDURL_Destroy(id);

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        CU_ASSERT_PTR_NOT_NULL(sealeddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        DIDDocumentBuilder_Destroy(builder);

        // Check existence
        PublicKey *pk = DIDDocument_GetPublicKey(sealeddoc, id1);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id1, PublicKey_GetId(pk)));
        DIDURL_Destroy(id1);

        pk = DIDDocument_GetPublicKey(sealeddoc, id2);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id2, PublicKey_GetId(pk)));
        DIDURL_Destroy(id2);

        pk = DIDDocument_GetPublicKey(sealeddoc, id3);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id3, PublicKey_GetId(pk)));
        DIDURL_Destroy(id3);

        pk = DIDDocument_GetPublicKey(sealeddoc, id4);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id4, PublicKey_GetId(pk)));
        DIDURL_Destroy(id4);

        // Check the final count.
        CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(sealeddoc));
        CU_ASSERT_EQUAL(7, DIDDocument_GetAuthenticationCount(sealeddoc));
        CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_remove_authentication_key(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    const char *keybase;
    int j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);

        // Add 2 public keys
        DIDURL *id1 = DIDURL_NewByDid(did, "test1");
        CU_ASSERT_PTR_NOT_NULL(id1);
        keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id1, keybase));

        DIDURL *id2 = DIDURL_NewByDid(did, "test2");
        CU_ASSERT_PTR_NOT_NULL(id2);
        keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, id2, keybase));

        // Remote keys
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, id1));
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, id2));

        DIDURL *id3 = DIDURL_NewByDid(did, "key2");
        CU_ASSERT_PTR_NOT_NULL(id3);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, id3));

        // Key not exist, should fail.
        DIDURL *id = DIDURL_NewByDid(did, "notExistKey");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder, id));
        DIDURL_Destroy(id);

        // Default publickey, can not remove, should fail.
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthenticationKey(builder,
                DIDDocument_GetDefaultPublicKey(doc)));

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        CU_ASSERT_PTR_NOT_NULL(sealeddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        DIDDocumentBuilder_Destroy(builder);

        PublicKey *pk = DIDDocument_GetAuthenticationKey(sealeddoc, id1);
        CU_ASSERT_PTR_NULL(pk);
        DIDURL_Destroy(id1);

        pk = DIDDocument_GetAuthenticationKey(sealeddoc, id2);
        CU_ASSERT_PTR_NULL(pk);
        DIDURL_Destroy(id2);

        pk = DIDDocument_GetAuthenticationKey(sealeddoc, id3);
        CU_ASSERT_PTR_NULL(pk);
        DIDURL_Destroy(id3);

        // Check the final count.
        CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(sealeddoc));
        CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(sealeddoc));
        CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_get_authorization_key(void)
{
    DIDDocument *doc;
    DID *did;
    PublicKey *pks[1];
    ssize_t size;
    PublicKey *pk;
    DIDURL *keyid, *id;
    int i, j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(doc));

        size = DIDDocument_GetAuthorizationKeys(doc, pks, 1);
        CU_ASSERT_NOT_EQUAL(size, -1);
        CU_ASSERT_EQUAL(1, size);

        for (i = 0; i < size; i++) {
            pk = pks[i];
            id = PublicKey_GetId(pk);

            CU_ASSERT_TRUE(DID_Equals(did, &id->did));
            CU_ASSERT_STRING_EQUAL(default_type, PublicKey_GetType(pk));

            CU_ASSERT_FALSE(DID_Equals(did, PublicKey_GetController(pk)));

            CU_ASSERT_TRUE(!strcmp(id->fragment, "recovery"));
        }

        // AuthorizationKey getter
        keyid = DIDURL_NewByDid(did, "recovery");
        CU_ASSERT_PTR_NOT_NULL(keyid);
        pk = DIDDocument_GetAuthorizationKey(doc, keyid);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(keyid, PublicKey_GetId(pk)));

        //Key not exist, should fail.
        id = DIDURL_NewByDid(did, "notExist");
        CU_ASSERT_PTR_NOT_NULL(id);
        pk = DIDDocument_GetAuthorizationKey(doc, id);
        CU_ASSERT_PTR_NULL(pk);
        DIDURL_Destroy(id);

        // Selector
        CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthorizationKeys(doc, default_type, keyid, pks, 1));
        CU_ASSERT_TRUE(DIDURL_Equals(PublicKey_GetId(pks[0]), keyid));

        CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthorizationKeys(doc, NULL, keyid, pks, 1));
        CU_ASSERT_TRUE(DIDURL_Equals(PublicKey_GetId(pks[0]), keyid));
        DIDURL_Destroy(keyid);

        CU_ASSERT_EQUAL(1, DIDDocument_SelectAuthorizationKeys(doc, default_type, NULL, pks, 1));
    }
}

static void test_diddoc_add_authorization_key(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    HDKey _dkey, *dkey;
    const char *keybase, *idstring;
    DID controller;
    int j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);

        // Add 2 public keys
        DIDURL *id1 = DIDURL_NewByDid(did, "test1");
        CU_ASSERT_PTR_NOT_NULL(id1);
        dkey = Generater_KeyPair(&_dkey);
        keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        idstring = HDKey_GetAddress(dkey);
        CU_ASSERT_PTR_NOT_NULL(idstring);
        DID_Init(&controller, idstring);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id1, &controller, keybase));
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, id1, &controller, NULL));

        DIDURL *id2 = DIDURL_NewByDid(did, "test2");
        CU_ASSERT_PTR_NOT_NULL(id2);
        dkey = Generater_KeyPair(&_dkey);
        keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        idstring = HDKey_GetAddress(dkey);
        CU_ASSERT_PTR_NOT_NULL(idstring);
        DID_Init(&controller, idstring);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id2, &controller, keybase));
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, id2, NULL, keybase));

        // Add new keys
        DIDURL *id3 = DIDURL_NewByDid(did, "test3");
        CU_ASSERT_PTR_NOT_NULL(id3);
        dkey = Generater_KeyPair(&_dkey);
        keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        idstring = HDKey_GetAddress(dkey);
        CU_ASSERT_PTR_NOT_NULL(idstring);
        DID_Init(&controller, idstring);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddPublicKey(builder, id3, &controller, keybase));
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, id3, NULL, NULL));

        DIDURL *id4 = DIDURL_NewByDid(did, "test4");
        CU_ASSERT_PTR_NOT_NULL(id4);
        dkey = Generater_KeyPair(&_dkey);
        keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        idstring = HDKey_GetAddress(dkey);
        CU_ASSERT_PTR_NOT_NULL(idstring);
        DID_Init(&controller, idstring);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, id4, &controller, keybase));

        // Try to add a non existing key, should fail.
        DIDURL *id = DIDURL_NewByDid(did, "notExistKey");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, id, NULL, NULL));
        DIDURL_Destroy(id);

        // Try to add a key not owned by self, should fail.
        id = DIDURL_NewByDid(did, "key2");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, id, NULL, NULL));
        DIDURL_Destroy(id);

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        CU_ASSERT_PTR_NOT_NULL(sealeddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        DIDDocumentBuilder_Destroy(builder);

        // Check existence
        PublicKey *pk = DIDDocument_GetPublicKey(sealeddoc, id1);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id1, PublicKey_GetId(pk)));
        DIDURL_Destroy(id1);

        pk = DIDDocument_GetPublicKey(sealeddoc, id2);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id2, PublicKey_GetId(pk)));
        DIDURL_Destroy(id2);

        pk = DIDDocument_GetPublicKey(sealeddoc, id3);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id3, PublicKey_GetId(pk)));
        DIDURL_Destroy(id3);

        pk = DIDDocument_GetPublicKey(sealeddoc, id4);
        CU_ASSERT_PTR_NOT_NULL(pk);
        CU_ASSERT_TRUE(DIDURL_Equals(id4, PublicKey_GetId(pk)));
        DIDURL_Destroy(id4);

        // Check the final count.
        CU_ASSERT_EQUAL(8, DIDDocument_GetPublicKeyCount(sealeddoc));
        CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(sealeddoc));
        CU_ASSERT_EQUAL(5, DIDDocument_GetAuthorizationCount(sealeddoc));

        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_remove_authorization_key(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    HDKey _dkey, *dkey;
    const char *keybase, *idstring;
    DID controller;
    int j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        builder = DIDDocument_Edit(doc, NULL);
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
        DID_Init(&controller, idstring);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, id1, &controller, keybase));

        DIDURL *id2 = DIDURL_NewByDid(did, "test2");
        CU_ASSERT_PTR_NOT_NULL(id2);
        dkey = Generater_KeyPair(&_dkey);
        keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58,
                sizeof(publickeybase58));
        CU_ASSERT_PTR_NOT_NULL(keybase);
        idstring = HDKey_GetAddress(dkey);
        CU_ASSERT_PTR_NOT_NULL(idstring);
        DID_Init(&controller, idstring);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, id2, &controller, keybase));

        // Remote keys
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthorizationKey(builder, id1));

        DIDURL *recoveryid = DIDURL_NewByDid(did, "recovery");
        CU_ASSERT_PTR_NOT_NULL(recoveryid);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthorizationKey(builder, recoveryid));

        // Key not exist, should fail.
        DIDURL *id = DIDURL_NewByDid(did, "notExistKey");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveAuthorizationKey(builder, id));
        DIDURL_Destroy(id);

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        CU_ASSERT_PTR_NOT_NULL(sealeddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        DIDDocumentBuilder_Destroy(builder);

        // Check existence
        PublicKey *pk = DIDDocument_GetAuthorizationKey(sealeddoc, id1);
        CU_ASSERT_PTR_NULL(pk);
        DIDURL_Destroy(id1);

        pk = DIDDocument_GetAuthorizationKey(sealeddoc, id2);
        CU_ASSERT_PTR_NOT_NULL(pk);
        DIDURL_Destroy(id2);

        pk = DIDDocument_GetAuthorizationKey(sealeddoc, recoveryid);
        CU_ASSERT_PTR_NULL(pk);
        DIDURL_Destroy(recoveryid);

        // Check the final count.
        CU_ASSERT_EQUAL(6, DIDDocument_GetPublicKeyCount(sealeddoc));
        CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(sealeddoc));
        CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(sealeddoc));

        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_get_credential(void)
{
    DIDDocument *doc;
    DID *did;
    Credential *vcs[2];
    ssize_t size;
    Credential *vc;
    DIDURL *id;
    int i, j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        CU_ASSERT_EQUAL(2, DIDDocument_GetCredentialCount(doc));

        size = DIDDocument_GetCredentials(doc, vcs, 2);
        CU_ASSERT_EQUAL(2, size);

        for (i = 0; i < size; i++) {
            vc = vcs[i];

            id = Credential_GetId(vc);
            CU_ASSERT_TRUE(DID_Equals(did, &id->did));
            CU_ASSERT_TRUE(DID_Equals(did, Credential_GetOwner(vc)));
            CU_ASSERT_TRUE(!strcmp(id->fragment, "profile") || !strcmp(id->fragment, "email"));
        }

        // Credential getter.
        DIDURL *profileid = DIDURL_NewByDid(did, "profile");
        CU_ASSERT_PTR_NOT_NULL(profileid);
        vc = DIDDocument_GetCredential(doc, profileid);
        CU_ASSERT_PTR_NOT_NULL(vc);
        CU_ASSERT_TRUE(DIDURL_Equals(profileid, Credential_GetId(vc)));

        id = DIDURL_NewByDid(did, "email");
        CU_ASSERT_PTR_NOT_NULL(id);
        vc = DIDDocument_GetCredential(doc, id);
        CU_ASSERT_PTR_NOT_NULL(vc);
        CU_ASSERT_TRUE(DIDURL_Equals(id, Credential_GetId(vc)));
        DIDURL_Destroy(id);

        // Credential not exist.
        id = DIDURL_NewByDid(did, "notExist");
        CU_ASSERT_PTR_NOT_NULL(id);
        vc = DIDDocument_GetCredential(doc, id);
        CU_ASSERT_PTR_NULL(vc);
        DIDURL_Destroy(id);

        // Credential selector.
        CU_ASSERT_EQUAL(1, DIDDocument_SelectCredentials(doc, "SelfProclaimedCredential",
                profileid, vcs, sizeof(vcs)));
        CU_ASSERT_TRUE(DIDURL_Equals(Credential_GetId(vcs[0]), profileid));

        CU_ASSERT_EQUAL(1, DIDDocument_SelectCredentials(doc, NULL, profileid, vcs, 2));
        CU_ASSERT_TRUE(DIDURL_Equals(Credential_GetId(vcs[0]), profileid));

        CU_ASSERT_EQUAL(1, DIDDocument_SelectCredentials(doc, "SelfProclaimedCredential",
                NULL, vcs, sizeof(vcs)));
        CU_ASSERT_TRUE(DIDURL_Equals(Credential_GetId(vcs[0]), profileid));
        DIDURL_Destroy(profileid);

        CU_ASSERT_EQUAL(0, DIDDocument_SelectCredentials(doc, "TestingCredential", NULL, vcs, 2));
    }
}

static void test_diddoc_add_credential(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    Credential *vc;
    int j;

    for (j = 1; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);

        // Add credentials.
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddCredential(builder,
                TestData_GetCredential(params[j].did, "passport", NULL, params[j].version)));
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddCredential(builder,
                TestData_GetCredential(params[j].did, "twitter", NULL, params[j].version)));

        // Credential already exist, should fail.
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddCredential(builder,
                TestData_GetCredential(params[j].did, "passport", NULL, params[j].version)));

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        CU_ASSERT_PTR_NOT_NULL(sealeddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        DIDDocumentBuilder_Destroy(builder);

        // Check new added credential.
        DIDURL *id = DIDURL_NewByDid(did, "passport");
        CU_ASSERT_PTR_NOT_NULL(id);
        vc = DIDDocument_GetCredential(sealeddoc, id);
        CU_ASSERT_PTR_NOT_NULL(vc);
        CU_ASSERT_TRUE(DIDURL_Equals(id, Credential_GetId(vc)));
        DIDURL_Destroy(id);

        id = DIDURL_NewByDid(did, "twitter");
        CU_ASSERT_PTR_NOT_NULL(id);
        vc = DIDDocument_GetCredential(sealeddoc, id);
        CU_ASSERT_PTR_NOT_NULL(vc);
        CU_ASSERT_TRUE(DIDURL_Equals(id, Credential_GetId(vc)));
        DIDURL_Destroy(id);

        // Check the final count.
        CU_ASSERT_EQUAL(4, DIDDocument_GetCredentialCount(sealeddoc));

        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_add_selfclaimed_credential(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    Credential *vc;
    int i, j;
    const char *provalue;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        // Add self claim credential.
        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);

        DIDURL *credid = DIDURL_NewByDid(did, "passport");
        CU_ASSERT_PTR_NOT_NULL(credid);

        const char *types[] = {"BasicProfileCredential", "SelfProclaimedCredential"};
        Property props[2];
        props[0].key = "nation";
        props[0].value = "Singapore";
        props[1].key = "passport";
        props[1].value = "S653258Z07";

        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid,
                types, 2, props, 2, DIDDocument_GetExpires(doc), NULL, storepass));

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        CU_ASSERT_PTR_NOT_NULL(sealeddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        DIDDocumentBuilder_Destroy(builder);

        // check credential
        vc = DIDDocument_GetCredential(sealeddoc, credid);
        CU_ASSERT_PTR_NOT_NULL(vc);
        CU_ASSERT_TRUE(Credential_IsSelfProclaimed(vc));
        CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
        CU_ASSERT_EQUAL(Credential_GetPropertyCount(vc), 2);
        provalue = Credential_GetProperty(vc, "passport");
        CU_ASSERT_STRING_EQUAL(provalue, "S653258Z07");
        free((void*)provalue);

        const char *types1[2];
        CU_ASSERT_NOT_EQUAL(-1, Credential_GetTypes(vc, types1, sizeof(types1)));

        for (i = 0; i < 2; i++) {
            const char *type = types1[i];
            CU_ASSERT_TRUE(!strcmp(type, "BasicProfileCredential") ||
                    !strcmp(type, "SelfProclaimedCredential"));
        }

        DIDURL_Destroy(credid);
        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_remove_credential(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    Credential *vc;
    int j;

    for (j = 1; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);

        // Add credentials.
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddCredential(builder,
                TestData_GetCredential(params[j].did, "passport", NULL, params[j].version)));
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddCredential(builder,
                TestData_GetCredential(params[j].did, "twitter", NULL, params[j].version)));

        DIDURL *profileid = DIDURL_NewByDid(did, "profile");
        CU_ASSERT_PTR_NOT_NULL(profileid);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveCredential(builder, profileid));

        DIDURL *twitterid = DIDURL_NewByDid(did, "twitter");
        CU_ASSERT_PTR_NOT_NULL(twitterid);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveCredential(builder, twitterid));

        DIDURL *id = DIDURL_NewByDid(did, "notExistCredential");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveCredential(builder, id));
        DIDURL_Destroy(id);

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        CU_ASSERT_PTR_NOT_NULL(sealeddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        DIDDocumentBuilder_Destroy(builder);

        // Check existence
        vc = DIDDocument_GetCredential(sealeddoc, profileid);
        CU_ASSERT_PTR_NULL(vc);
        DIDURL_Destroy(profileid);

        vc = DIDDocument_GetCredential(sealeddoc, twitterid);
        CU_ASSERT_PTR_NULL(vc);
        DIDURL_Destroy(twitterid);

        // Check the final count.
        CU_ASSERT_EQUAL(2, DIDDocument_GetCredentialCount(sealeddoc));

        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_get_service(void)
{
    DIDDocument *doc;
    DID *did;
    Service *services[3];
    ssize_t size;
    Service *service;
    int i, j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        CU_ASSERT_EQUAL(3, DIDDocument_GetServiceCount(doc));

        size = DIDDocument_GetServices(doc, services, sizeof(services));
        CU_ASSERT_EQUAL(3, size);

        for (i = 0; i < size; i++) {
            service = services[i];

            DIDURL *id = Service_GetId(service);
            CU_ASSERT_TRUE(DID_Equals(did, &id->did));

            CU_ASSERT_TRUE(!strcmp(id->fragment, "openid") ||
                    !strcmp(id->fragment, "vcr") || !strcmp(id->fragment, "carrier"));
        }

        // Service getter, should success.
        DIDURL *openid = DIDURL_NewByDid(did, "openid");
        CU_ASSERT_PTR_NOT_NULL(openid);
        service = DIDDocument_GetService(doc, openid);
        CU_ASSERT_PTR_NOT_NULL(service);
        CU_ASSERT_TRUE(DIDURL_Equals(openid, Service_GetId(service)));
        CU_ASSERT_STRING_EQUAL("OpenIdConnectVersion1.0Service", Service_GetType(service));
        CU_ASSERT_STRING_EQUAL("https://openid.example.com/", Service_GetEndpoint(service));

        DIDURL *vcrid = DIDURL_NewByDid(did, "vcr");
        CU_ASSERT_PTR_NOT_NULL(vcrid);
        service = DIDDocument_GetService(doc, vcrid);
        CU_ASSERT_PTR_NOT_NULL(service);
        CU_ASSERT_TRUE(DIDURL_Equals(vcrid, Service_GetId(service)));

        // Service not exist, should fail.
        DIDURL *notexistid = DIDURL_NewByDid(did, "notExistService");
        CU_ASSERT_PTR_NOT_NULL(notexistid);
        service = DIDDocument_GetService(doc, notexistid);
        CU_ASSERT_PTR_NULL(service);

        // Service selector.
        CU_ASSERT_EQUAL(1, DIDDocument_SelectServices(doc, "CredentialRepositoryService", vcrid,
                services, sizeof(services)));
        CU_ASSERT_TRUE(DIDURL_Equals(Service_GetId(services[0]), vcrid));
        DIDURL_Destroy(vcrid);

        CU_ASSERT_EQUAL(1, DIDDocument_SelectServices(doc, NULL, openid, services, sizeof(services)));
        CU_ASSERT_TRUE(DIDURL_Equals(Service_GetId(services[0]), openid));
        DIDURL_Destroy(openid);

        DIDURL *id = DIDURL_NewByDid(did, "carrier");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(1, DIDDocument_SelectServices(doc, "CarrierAddress", NULL, services, sizeof(services)));
        CU_ASSERT_TRUE(DIDURL_Equals(Service_GetId(services[0]), id));
        DIDURL_Destroy(id);

        // Service not exist, should return a empty list.
        CU_ASSERT_EQUAL(0, DIDDocument_SelectServices(doc, "CredentialRepositoryService",
                notexistid, services, sizeof(services)));
        DIDURL_Destroy(notexistid);

        CU_ASSERT_EQUAL(0, DIDDocument_SelectServices(doc, "notExistType", NULL, services, sizeof(services)));
    }
}

static void test_diddoc_add_service(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    Property props1[4];
    Service *services[3], *service;
    const char *props2, *data;
    int j;

    props1[0].key = "abc";
    props1[0].value = "helloworld";
    props1[1].key = "bar";
    props1[1].value = "foobar";
    props1[2].key = "lalala...";
    props1[2].value = "ABC";
    props1[3].key = "Helloworld";
    props1[3].value = "English";

    props2 = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\"}";

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);

        // Add services.
        DIDURL *id1 = DIDURL_NewByDid(did, "test-svc-1");
        CU_ASSERT_PTR_NOT_NULL(id1);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, id1, "Service.Testing",
                "https://www.elastos.org/testing1", NULL, 0));
        DIDURL_Destroy(id1);

        DIDURL *id2 = DIDURL_NewByDid(did, "test-svc-2");
        CU_ASSERT_PTR_NOT_NULL(id2);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, id2, "Service.Testing",
                "https://www.elastos.org/testing2", props1, 4));


        DIDURL *id3 = DIDURL_NewByDid(did, "test-svc-3");
        CU_ASSERT_PTR_NOT_NULL(id3);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddServiceByString(builder, id3, "Service.Testing",
                "https://www.elastos.org/testing3", props2));

        // Service id already exist, should failed.
        DIDURL *id = DIDURL_NewByDid(did, "vcr");
        CU_ASSERT_PTR_NOT_NULL(id1);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddService(builder, id,
                "test", "https://www.elastos.org/test", NULL, 0));
        DIDURL_Destroy(id);

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        CU_ASSERT_PTR_NOT_NULL(sealeddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        DIDDocumentBuilder_Destroy(builder);

        //  Check the final count
        CU_ASSERT_EQUAL(6, DIDDocument_GetServiceCount(sealeddoc));

        // Try to select new added 2 services
        CU_ASSERT_EQUAL(3, DIDDocument_SelectServices(sealeddoc, "Service.Testing", NULL,
                services, 3));
        CU_ASSERT_STRING_EQUAL("Service.Testing", Service_GetType(services[0]));
        CU_ASSERT_STRING_EQUAL("Service.Testing", Service_GetType(services[1]));

        service = DIDDocument_GetService(sealeddoc, id2);
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

        service = DIDDocument_GetService(sealeddoc, id3);
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
        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_remove_service(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *sealeddoc;
    DIDDocumentBuilder *builder;
    int j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);

        // remove services
        DIDURL *openid = DIDURL_NewByDid(did, "openid");
        CU_ASSERT_PTR_NOT_NULL(openid);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveService(builder, openid));

        DIDURL *vcrid = DIDURL_NewByDid(did, "vcr");
        CU_ASSERT_PTR_NOT_NULL(vcrid);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveService(builder, vcrid));

        // Service not exist, should fail.
        DIDURL *id = DIDURL_NewByDid(did, "notExistService");
        CU_ASSERT_PTR_NOT_NULL(id);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_RemoveService(builder, id));
        DIDURL_Destroy(id);

        sealeddoc = DIDDocumentBuilder_Seal(builder, storepass);
        CU_ASSERT_PTR_NOT_NULL(sealeddoc);
        CU_ASSERT_TRUE(DIDDocument_IsValid(sealeddoc));
        DIDDocumentBuilder_Destroy(builder);

        // Check existence
        Service *service = DIDDocument_GetService(sealeddoc, openid);
        CU_ASSERT_PTR_NULL(service);
        DIDURL_Destroy(openid);

        service = DIDDocument_GetService(sealeddoc, vcrid);
        CU_ASSERT_PTR_NULL(service);
        DIDURL_Destroy(vcrid);

        // Check the final count.
        CU_ASSERT_EQUAL(1, DIDDocument_GetServiceCount(sealeddoc));

        DIDDocument_Destroy(sealeddoc);
    }
}

static void test_diddoc_add_controller(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *controllerdoc;
    DIDDocumentBuilder *builder;
    int j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        controllerdoc = TestData_GetDocument("controller", NULL, 0);
        CU_ASSERT_PTR_NOT_NULL(controllerdoc);

        CU_ASSERT_EQUAL(0, DIDDocument_GetControllerCount(doc));

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);
        CU_ASSERT_EQUAL(-1, DIDDocumentBuilder_AddController(builder, &controllerdoc->did));
        CU_ASSERT_STRING_EQUAL("Can't add controller into normal DID.", DIDError_GetLastErrorMessage());

        CU_ASSERT_PTR_NULL(DIDDocumentBuilder_Seal(builder, storepass));
        DIDDocumentBuilder_Destroy(builder);
    }
}

static void test_diddoc_remove_proof(void)
{
    DIDDocument *doc;
    DID *did;
    DIDDocument *document;
    DIDDocumentBuilder *builder;
    DIDURL *creater;
    int j;

    for (j = 0; j < 3; j++) {
        doc = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(doc);
        did = DIDDocument_GetSubject(doc);
        CU_ASSERT_PTR_NOT_NULL(did);

        creater = DIDDocument_GetProofCreater(doc, 0);
        CU_ASSERT_PTR_NOT_NULL(creater);

        builder = DIDDocument_Edit(doc, NULL);
        CU_ASSERT_PTR_NOT_NULL(builder);
        CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_RemoveProof(builder, NULL));

        document = DIDDocumentBuilder_Seal(builder, storepass);
        DIDDocumentBuilder_Destroy(builder);
        CU_ASSERT_PTR_NOT_NULL(document);
        CU_ASSERT_TRUE(DIDDocument_IsValid(document));
        CU_ASSERT_TRUE(DIDURL_Equals(creater, DIDDocument_GetProofCreater(document, 0)));
        DIDDocument_Destroy(document);
    }
}

static int diddoc_elem_test_suite_init(void)
{
    DIDStore *store = TestData_SetupStore(true);
    if (!store)
        return -1;

    for (int version = 0; version < 3; version++) {
        if (!TestData_GetDocument("issuer", NULL, version)) {
            TestData_Free();
            return -1;
        }
    }
    return 0;
}

static int diddoc_elem_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_diddoc_get_publickey",                 test_diddoc_get_publickey             },
    { "test_diddoc_add_publickey",                 test_diddoc_add_publickey             },
    { "test_diddoc_remove_publickey",              test_diddoc_remove_publickey          },
    { "test_diddoc_get_authentication_key",        test_diddoc_get_authentication_key    },
    { "test_diddoc_add_authentication_key",        test_diddoc_add_authentication_key    },
    { "test_diddoc_remove_authentication_key",     test_diddoc_remove_authentication_key },
    { "test_diddoc_get_authorization_key",         test_diddoc_get_authorization_key     },
    { "test_diddoc_add_authorization_key",         test_diddoc_add_authorization_key     },
    { "test_diddoc_remove_authorization_key",      test_diddoc_remove_authorization_key  },
    { "test_diddoc_get_credential",                test_diddoc_get_credential            },
    { "test_diddoc_add_credential",                test_diddoc_add_credential            },
    { "test_diddoc_add_selfclaimed_credential",    test_diddoc_add_selfclaimed_credential},
    { "test_diddoc_remove_credential",             test_diddoc_remove_credential         },
    { "test_diddoc_get_service",                   test_diddoc_get_service               },
    { "test_diddoc_add_service",                   test_diddoc_add_service               },
    { "test_diddoc_remove_service",                test_diddoc_remove_service            },
    { "test_diddoc_add_controller",                test_diddoc_add_controller            },
    { "test_diddoc_remove_proof",                  test_diddoc_remove_proof              },
    { NULL,                                        NULL                                  }
};

static CU_SuiteInfo suite[] = {
    { "diddoc elem test",  diddoc_elem_test_suite_init,  diddoc_elem_test_suite_cleanup,  NULL, NULL, cases },
    {  NULL,               NULL,                         NULL,                            NULL, NULL, NULL  }
};

CU_SuiteInfo* diddoc_elem_test_suite_info(void)
{
    return suite;
}
