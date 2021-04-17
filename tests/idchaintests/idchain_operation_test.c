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

static DIDDocument *document;
static DIDStore *store;

static void test_idchain_publishdid_and_resolve(void)
{
    DIDURL *signkey;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    RootIdentity *rootidentity;
    char previous_txid[ELA_MAX_TXID_LEN];
    DIDDocument *resolvedoc = NULL, *doc;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool success;
    DID did;
    int i = 0, status;

    mnemonic = Mnemonic_Generate(language);
    rootidentity = RootIdentity_Create(mnemonic, "", language, true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = RootIdentity_NewDID(rootidentity, storepass, alias);
    RootIdentity_Destroy(rootidentity);
    CU_ASSERT_PTR_NOT_NULL(doc);

    signkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    success = DIDDocument_PublishDID(doc, signkey, false, storepass);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    while(!resolvedoc) {
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            printf(".");
            sleep(5);
            if (++i >= 20)
                CU_FAIL_FATAL("publish did timeout!!!!\n");
        }
    }

    CU_ASSERT_STRING_EQUAL(DIDDocument_GetProofSignature(doc, 0), DIDDocument_GetProofSignature(resolvedoc, 0));
    DIDDocument_Destroy(doc);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolvedoc));

    DIDMetadata *metadata = DIDDocument_GetMetadata(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetadata_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);
    strcpy(previous_txid, txid);
    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase));
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, doc));

    success = DIDDocument_PublishDID(doc, NULL, false, storepass);
    DIDDocument_Destroy(doc);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    i = 0;
    txid = previous_txid;
    while(!resolvedoc || !strcmp(previous_txid, txid)) {
        if (resolvedoc)
            DIDDocument_Destroy(resolvedoc);

        sleep(5);
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            break;
        } else {
            metadata = DIDDocument_GetMetadata(resolvedoc);
            txid = DIDMetadata_GetTxid(metadata);
            printf(".");
        }

        ++i;
        if (i >= 20)
            CU_FAIL_FATAL("publish did timeout!!!!\n");
    }

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolvedoc));
    CU_ASSERT_NOT_EQUAL_FATAL(previous_txid, txid);
    strcpy(previous_txid, txid);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(resolvedoc));
    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update) again, waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update again
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    builder = DIDDocument_Edit(doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid = DIDURL_NewByDid(&did, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase));
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, doc));

    success = DIDDocument_PublishDID(doc, NULL, false, storepass);
    DIDDocument_Destroy(doc);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update) again", did.idstring);

    i = 0;
    txid = previous_txid;
    while(!resolvedoc || !strcmp(previous_txid, txid)) {
        if (resolvedoc)
            DIDDocument_Destroy(resolvedoc);

        sleep(5);
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            break;
        } else {
            metadata = DIDDocument_GetMetadata(resolvedoc);
            txid = DIDMetadata_GetTxid(metadata);
            printf(".");
        }

        if (++i >= 20)
            CU_FAIL_FATAL("publish did timeout!!!!\n");
    }

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolvedoc));
    CU_ASSERT_NOT_EQUAL_FATAL(previous_txid, txid);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(resolvedoc));

    printf("\n   txid = %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);
    DIDDocument_Destroy(resolvedoc);
}

static void test_idchain_publishdid_with_credential(void)
{
    DIDDocument *resolvedoc = NULL, *doc;
    RootIdentity *rootidentity;
    char previous_txid[ELA_MAX_TXID_LEN];
    const char *mnemonic, *txid;
    Credential *cred;
    bool success;
    DID did;
    int i = 0, status;

    mnemonic = Mnemonic_Generate(language);
    rootidentity = RootIdentity_Create(mnemonic, "", language, true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);
    Mnemonic_Free((void*)mnemonic);

    doc = RootIdentity_NewDID(rootidentity, storepass, "littlefish");
    RootIdentity_Destroy(rootidentity);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    success = DIDDocument_PublishDID(doc, NULL, false, storepass);
    DIDDocument_Destroy(doc);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    while(!resolvedoc) {
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            printf(".");
            sleep(5);
            ++i;
            if (i >= 20)
                CU_FAIL_FATAL("publish did timeout!!!!\n");
        }
    }
    DIDMetadata *metadata = DIDDocument_GetMetadata(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetadata_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL_FATAL(txid);
    strcpy(previous_txid, txid);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolvedoc));

    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    DIDURL *credid = DIDURL_NewByDid(&did, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "John";

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfProclaimedCredential(builder, credid, types, 2, props, 1, 0, NULL, storepass));

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    DIDDocumentBuilder_Destroy(builder);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, doc));

    cred = DIDDocument_GetCredential(doc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);

    success = DIDDocument_PublishDID(doc, NULL, true, storepass);
    DIDDocument_Destroy(doc);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    i = 0;
    txid = previous_txid;
    while(!resolvedoc || !strcmp(previous_txid, txid)) {
        if (resolvedoc)
            DIDDocument_Destroy(resolvedoc);

        sleep(5);
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            break;
        } else {
            metadata = DIDDocument_GetMetadata(resolvedoc);
            txid = DIDMetadata_GetTxid(metadata);
            printf(".");
        }

        if (++i >= 20)
            CU_FAIL_FATAL("publish did timeout!!!!\n");
    }

    printf("\n   txid = %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);

    cred = DIDDocument_GetCredential(resolvedoc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);

    DIDURL_Destroy(credid);
    DIDDocument_Destroy(resolvedoc);
}

static void test_idchain_deactivedid_after_create(void)
{
    RootIdentity *rootidentity;
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetadata *metadata;
    const char *mnemonic, *txid;
    char previous_txid[ELA_MAX_TXID_LEN];
    bool success;
    DID did;
    int i = 0, status;

    mnemonic = Mnemonic_Generate(language);

    rootidentity = RootIdentity_Create(mnemonic, "", language, true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);
    Mnemonic_Free((void*)mnemonic);

    doc = RootIdentity_NewDID(rootidentity, storepass, "littlefish");
    RootIdentity_Destroy(rootidentity);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    success = DIDDocument_PublishDID(doc, NULL, false, storepass);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    while(!resolvedoc) {
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            printf(".");
            sleep(5);
            ++i;
            if (i >= 20)
                CU_FAIL_FATAL("publish did timeout!!!!\n");
        }
    }

    CU_ASSERT_EQUAL(DIDStatus_Valid, status);

    const char *data1 = DIDDocument_ToJson(doc, true);
    const char *data2 = DIDDocument_ToJson(resolvedoc, true);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;
    CU_ASSERT_STRING_EQUAL(data1, data2);
    free((void*)data1);
    free((void*)data2);

    success = DIDDocument_DeactivateDID(doc, NULL, storepass);
    DIDDocument_Destroy(doc);
    CU_ASSERT_TRUE(success);

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
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    RootIdentity *rootidentity;
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetadata *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    char previous_txid[ELA_MAX_TXID_LEN];
    bool success;
    DID did;
    int i = 0, status;

    mnemonic = Mnemonic_Generate(language);

    rootidentity = RootIdentity_Create(mnemonic, "", language, true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = RootIdentity_NewDID(rootidentity, storepass, alias);
    RootIdentity_Destroy(rootidentity);
    CU_ASSERT_PTR_NOT_NULL(doc);

    signkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    success = DIDDocument_PublishDID(doc, signkey, false, storepass);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    while(!resolvedoc) {
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            printf(".");
            sleep(5);
            ++i;
            if (i >= 20)
                CU_FAIL_FATAL("publish did timeout!!!!\n");
        }
    }

    CU_ASSERT_NOT_EQUAL(status, DIDStatus_Deactivated);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolvedoc));
    metadata = DIDDocument_GetMetadata(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetadata_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);
    strcpy(previous_txid, txid);

    metadata = DIDDocument_GetMetadata(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    const char *nalias = DIDMetadata_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);

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

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase));
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, doc));

    metadata = DIDDocument_GetMetadata(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    nalias = DIDMetadata_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);

    success = DIDDocument_PublishDID(doc, NULL, false, storepass);
    DIDDocument_Destroy(doc);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    i = 0;
    txid = previous_txid;
    while(!resolvedoc || !strcmp(previous_txid, txid)) {
        if (resolvedoc)
            DIDDocument_Destroy(resolvedoc);

        sleep(5);
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            break;
        } else {
            metadata = DIDDocument_GetMetadata(resolvedoc);
            txid = DIDMetadata_GetTxid(metadata);
            printf(".");
        }

        if (++i >= 20)
            CU_FAIL_FATAL("deactive did timeout!!!!\n");
    }

    CU_ASSERT_NOT_EQUAL(status, DIDStatus_Deactivated);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolvedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(resolvedoc));
    printf("\n-- resolve result: successfully!\n-- deactive did begin, waiting...\n");

    success = DIDDocument_DeactivateDID(resolvedoc, NULL, storepass);
    CU_ASSERT_TRUE_FATAL(success);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;
    printf("-- deactive did result:\n   did = %s\n -- resolve begin(deactive)", did.idstring);

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

static void test_idchain_deactivedid_with_authorization1(void)
{
    RootIdentity *rootidentity;
    DIDDocument *resolvedoc = NULL, *targetdoc, *authorizordoc = NULL;
    DIDMetadata *metadata;
    const char *mnemonic, *txid, *alias = "littlefish";
    char previous_txid[ELA_MAX_TXID_LEN];
    DID controller, did;
    PublicKey *pks[1];
    bool success;
    int i = 0, status;

    mnemonic = Mnemonic_Generate(language);
    rootidentity = RootIdentity_Create(mnemonic, "", language, true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);
    Mnemonic_Free((void*)mnemonic);

    authorizordoc = RootIdentity_NewDID(rootidentity, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(authorizordoc);

    DID_Copy(&controller, DIDDocument_GetSubject(authorizordoc));

    printf("\n------------------------------------------------------------\n-- publish authorization did begin(create), waiting....\n");
    success = DIDDocument_PublishDID(authorizordoc, NULL, false, storepass);
    DIDDocument_Destroy(authorizordoc);
    authorizordoc = NULL;
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", controller.idstring);

    while(!authorizordoc) {
        authorizordoc = DID_Resolve(&controller, &status, true);
        if (!authorizordoc) {
            printf(".");
            sleep(5);
            ++i;
            if (i >= 20)
                CU_FAIL_FATAL("publish controller doc timeout!!!!\n");
        }
    }

    CU_ASSERT_NOT_EQUAL(status, DIDStatus_Deactivated);
    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, authorizordoc));

    metadata = DIDDocument_GetMetadata(authorizordoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetadata_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);
    printf("\n   txid: %s\n-- resolve authorization result: successfully!\n", txid);

    targetdoc = RootIdentity_NewDID(rootidentity, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(targetdoc);

    DID_Copy(&did, DIDDocument_GetSubject(targetdoc));

    DIDDocumentBuilder *builder = DIDDocument_Edit(targetdoc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(targetdoc);

    DIDURL *keyid = DIDURL_NewByDid(&did, "recovery");
    CU_ASSERT_PTR_NOT_NULL(keyid);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AuthorizeDid(builder, keyid, &controller, NULL));
    DIDURL_Destroy(keyid);

    targetdoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(targetdoc);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(targetdoc));

    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationKeys(targetdoc, pks, sizeof(pks)));
    CU_ASSERT_TRUE(DID_Equals(&did, &pks[0]->id.did));

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, targetdoc));

    printf("-- publish target did begin(create), waiting....\n");
    success = DIDDocument_PublishDID(targetdoc, NULL, false, storepass);
    DIDDocument_Destroy(targetdoc);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    while(!resolvedoc) {
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            printf(".");
            sleep(5);
            ++i;
            if (i >= 20)
                CU_FAIL_FATAL("publish controller doc timeout!!!!\n");
        }
    }
    CU_ASSERT_NOT_EQUAL(status, DIDStatus_Deactivated);

    metadata = DIDDocument_GetMetadata(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetadata_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);
    strcpy(previous_txid, txid);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, resolvedoc));
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;
    printf("\n-- resolve authorization result: successfully!\n");

    success = DIDDocument_DeactivateDIDByAuthorizor(authorizordoc, &did, NULL, storepass);
    CU_ASSERT_TRUE(success);
    DIDDocument_Destroy(authorizordoc);
    printf("-- deactive did result:\n   did = %s\n -- resolve begin(deactive)", did.idstring);

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

    printf("\n-- resolve target result: successfully!\n------------------------------------------------------------\n");
    RootIdentity_Destroy(rootidentity);
    DIDDocument_Destroy(resolvedoc);
}

static void test_idchain_deactivedid_with_authorization2(void)
{
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    RootIdentity *rootidentity;
    DIDDocument *resolvedoc = NULL, *authorizordoc = NULL, *targetdoc;
    DIDMetadata *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    char previous_txid[ELA_MAX_TXID_LEN];
    HDKey _dkey, *dkey;
    DID controller, did;
    PublicKey *pks[1];
    bool equal, success;
    int i = 0, status;

    mnemonic = Mnemonic_Generate(language);
    rootidentity = RootIdentity_Create(mnemonic, "", language, true, store, storepass);
    CU_ASSERT_PTR_NOT_NULL(rootidentity);
    Mnemonic_Free((void*)mnemonic);

    authorizordoc = RootIdentity_NewDID(rootidentity, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(authorizordoc);

    DID_Copy(&controller, DIDDocument_GetSubject(authorizordoc));

    DIDDocumentBuilder *builder = DIDDocument_Edit(authorizordoc, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(authorizordoc);

    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);

    DIDURL *signkey = DIDURL_NewByDid(&controller, "key-2");
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
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", controller.idstring);

    while(!authorizordoc) {
        authorizordoc = DID_Resolve(&controller, &status, true);
        if (!authorizordoc) {
            printf(".");
            sleep(5);
            ++i;
            if (i >= 20)
                CU_FAIL_FATAL("publish controller doc timeout!!!!\n");
        }
    }

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, authorizordoc));

    metadata = DIDDocument_GetMetadata(authorizordoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetadata_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    printf("\n   txid: %s\n-- resolve authorization result: successfully!\n", txid);

    targetdoc = RootIdentity_NewDID(rootidentity, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(targetdoc);

    builder = DIDDocument_Edit(targetdoc, NULL);
    CU_ASSERT_PTR_NOT_NULL(builder);

    DID_Copy(&did, DIDDocument_GetSubject(targetdoc));
    DIDDocument_Destroy(targetdoc);

    DIDURL *keyid = DIDURL_NewByDid(&did, "recovery");
    CU_ASSERT_PTR_NOT_NULL(keyid);

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddAuthorizationKey(builder, keyid, &controller, keybase));

    targetdoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(targetdoc);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(targetdoc));

    size_t size = DIDDocument_GetAuthorizationKeys(targetdoc, pks, sizeof(pks));
    CU_ASSERT_EQUAL(1, size);
    equal = DID_Equals(&did, &pks[0]->id.did);
    CU_ASSERT_TRUE(equal);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, targetdoc));

    printf("-- publish target did begin(create), waiting....\n");
    success = DIDDocument_PublishDID(targetdoc, NULL, false, storepass);
    DIDDocument_Destroy(targetdoc);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    while(!resolvedoc) {
        resolvedoc = DID_Resolve(&did, &status, true);
        if (!resolvedoc) {
            printf(".");
            sleep(5);
            ++i;
            if (i >= 20)
                CU_FAIL_FATAL("publish controller doc timeout!!!!\n");
        }
    }

    CU_ASSERT_NOT_EQUAL(status, DIDStatus_Deactivated);

    printf("\n   txid: %s\n-- resolve target result: successfully!", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    success = DIDDocument_DeactivateDIDByAuthorizor(authorizordoc, &did, signkey, storepass);
    CU_ASSERT_TRUE_FATAL(success);
    printf("-- deactive did result:\n   did = %s\n -- resolve begin(deactive)", did.idstring);

    i = 0;
    txid = previous_txid;
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
    DIDDocument_Destroy(authorizordoc);
    DIDURL_Destroy(signkey);
    DIDURL_Destroy(keyid);
    RootIdentity_Destroy(rootidentity);
}

static int idchain_operation_test_suite_init(void)
{
    store = TestData_SetupStore(false);
    if (!store)
        return -1;

    return 0;
}

static int idchain_operation_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_idchain_publishdid_and_resolve",            test_idchain_publishdid_and_resolve          },
    { "test_idchain_publishdid_with_credential",        test_idchain_publishdid_with_credential      },
    { "test_idchain_deactivedid_after_create",          test_idchain_deactivedid_after_create        },
    { "test_idchain_deactivedid_after_update",          test_idchain_deactivedid_after_update        },
    { "test_idchain_deactivedid_with_authorization1",   test_idchain_deactivedid_with_authorization1 },
    { "test_idchain_deactivedid_with_authorization2",   test_idchain_deactivedid_with_authorization2 },
    {  NULL,                                            NULL                                         }
};

static CU_SuiteInfo suite[] = {
    { "id chain operateion test", idchain_operation_test_suite_init, idchain_operation_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                      NULL,                              NULL,                                 NULL, NULL, NULL  }
};

CU_SuiteInfo* idchain_operation_test_suite_info(void)
{
    return suite;
}
