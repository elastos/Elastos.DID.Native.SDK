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
#include "constant.h"
#include "loader.h"
#include "did.h"
#include "didmeta.h"
#include "diddocument.h"
#include "credential.h"

#define MAX_PUBLICKEY_BASE58      64
#define MAX_DOC_SIGN              128

static DIDStore *store;

static bool has_type(const char **types, size_t size, const char *type)
{
    int i;

    if (!types || size <= 0 || !type || !*type)
        return false;

    for (i = 0; i < size; i++) {
        if (!strcmp(types[i], type))
            return true;
    }

    return false;
}

static void test_idchain_publishdid(void)
{
    DIDURL *signkey;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    char *signs[3];
    DIDDocument *resolvedoc = NULL, *doc;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish", *sign;
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    signkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, signkey, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n-- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDMetaData *metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);

    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    sign = DIDDocument_GetProofSignature(doc);
    CU_ASSERT_STRING_EQUAL(DIDDocument_GetProofSignature(doc), DIDDocument_GetProofSignature(resolvedoc));
    signs[0] = alloca(strlen(sign) + 1);
    strcpy(signs[0], sign);

    DIDDocument_Destroy(doc);
    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);

    const char *nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);

    sign = DIDDocument_GetProofSignature(doc);
    signs[1] = alloca(strlen(sign) + 1);
    strcpy(signs[1], sign);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n-- resolve begin(update)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(resolvedoc));
    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update) again, waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update again
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid = DIDURL_NewByDid(&did, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    sign = DIDDocument_GetProofSignature(doc);
    signs[2] = alloca(strlen(sign) + 1);
    strcpy(signs[2], sign);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n-- resolve begin(update) again", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(resolvedoc));

    printf("\n   txid = %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);
    DIDDocument_Destroy(resolvedoc);

    //DIDBiography
    DIDBiography *biography = DID_ResolveBiography(&did);
    CU_ASSERT_PTR_NOT_NULL_FATAL(biography);
    CU_ASSERT_EQUAL(3, DIDBiography_GetTransactionCount(biography));
    CU_ASSERT_EQUAL(0, DIDBiography_GetStatus(biography));

    DID *owner = DIDBiography_GetOwner(biography);
    CU_ASSERT_PTR_NOT_NULL_FATAL(owner);
    bool bEqual = DID_Equals(&did, owner);
    CU_ASSERT_TRUE_FATAL(bEqual);

    for (i = 0; i < 3; i++) {
        doc = DIDBiography_GetDocumentByIndex(biography, i);
        CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
        CU_ASSERT_STRING_EQUAL(signs[2-i], DIDDocument_GetProofSignature(doc));
        DIDDocument_Destroy(doc);
    }
    DIDBiography_Destroy(biography);
}

static void test_idchain_publishdid_without_txid(void)
{
    DIDURL *signkey;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    signkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL(signkey);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, signkey, false);
    CU_ASSERT_TRUE_FATAL(successed);
    DIDDocument_Destroy(doc);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);

    rc = DIDMetaData_SetTxid(metadata, "");
    CU_ASSERT_NOT_EQUAL(rc, -1);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    const char *nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_STRING_EQUAL(txid, "");
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    printf("\n   txid = %s\n-- resolve result: successfully!\n-- publish begin(update) again, waiting...\n", txid);
    metadata = DIDDocument_GetMetaData(resolvedoc);
    rc = DIDMetaData_SetTxid(metadata, "");
    CU_ASSERT_NOT_EQUAL(rc, -1);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update again
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid = DIDURL_NewByDid(&did, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update) again", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(resolvedoc));

    printf("\n   txid: %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);
    DIDDocument_Destroy(resolvedoc);
}

static void test_idchain_publishdid_without_signature(void)
{
    DIDURL *signkey;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    signkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, signkey, false);
    CU_ASSERT_TRUE_FATAL(successed);
    DIDDocument_Destroy(doc);

    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    const char *nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDMetaData_SetPrevSignature(metadata, resolvedoc->proof.signatureValue);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDMetaData_SetSignature(metadata, "");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update) again, waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update again
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid = DIDURL_NewByDid(&did, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update) again", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(resolvedoc));

    printf("\n   txid: %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);
    DIDDocument_Destroy(resolvedoc);
}

static void test_idchain_publishdid_without_prevsignature(void)
{
    DIDURL *signkey;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    signkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, signkey, false);
    CU_ASSERT_TRUE_FATAL(successed);
    DIDDocument_Destroy(doc);

    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    const char *nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDMetaData_SetPrevSignature(metadata, "");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update) again, waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update again
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid = DIDURL_NewByDid(&did, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);
    const char *signature = DIDMetaData_GetPrevSignature(metadata);
    CU_ASSERT_PTR_NOT_NULL(signature);
    CU_ASSERT_STRING_EQUAL(signature, "");
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update) again", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(resolvedoc));

    printf("\n   txid: %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);
    DIDDocument_Destroy(resolvedoc);
}

static void test_idchain_publishdid_without_prevsignature_and_signature(void)
{
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));
    DIDDocument_Destroy(doc);

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDMetaData_SetSignature(metadata, "");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDMetaData_SetPrevSignature(metadata, "");
    CU_ASSERT_NOT_EQUAL(rc, -1);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_FALSE(successed);
    CU_ASSERT_STRING_EQUAL("Missing signatures information, DID SDK dosen't know how to handle it, use force mode to ignore checks.",
           DIDError_GetMessage());
}

static void test_force_updatedid_without_prevsignature_and_signature(void)
{
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));
    DIDDocument_Destroy(doc);

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDMetaData_SetSignature(metadata, "");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDMetaData_SetPrevSignature(metadata, "");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    const char *nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, true);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(resolvedoc));

    printf("\n   txid: %s\n-- resolve result: successfully!\n------------------------------------------------------------\n", txid);
    DIDDocument_Destroy(resolvedoc);
}

static void test_updatedid_with_diffprevsignature_only(void)
{
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));
    DIDDocument_Destroy(doc);

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDMetaData_SetPrevSignature(metadata, "123456789");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n-- resolve begin(update)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(resolvedoc));

    DIDDocument_Destroy(resolvedoc);
}

static void test_updatedid_with_diffsignature_only(void)
{
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));
    DIDDocument_Destroy(doc);

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n    txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDMetaData_SetPrevSignature(metadata, resolvedoc->proof.signatureValue);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDMetaData_SetSignature(metadata, "123456789");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update) again, waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update again
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    keyid = DIDURL_NewByDid(&did, "key2");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    const char *nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update) again", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(3, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(3, DIDDocument_GetAuthenticationCount(resolvedoc));

    DIDDocument_Destroy(resolvedoc);
    printf("\n-- resolve result: successfully!\n------------------------------------------------------------\n");
}

static void test_updatedid_with_diff_prevsignature_and_signature(void)
{
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));
    DIDDocument_Destroy(doc);

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDMetaData_SetSignature(metadata, "12345678");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDMetaData_SetPrevSignature(metadata, "12345678");
    CU_ASSERT_NOT_EQUAL(rc, -1);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_FALSE(successed);
    CU_ASSERT_STRING_EQUAL("Current copy not based on the lastest on-chain copy.",
            DIDError_GetMessage());
}

static void test_force_updatedid_with_wrongsignature(void)
{
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));
    DIDDocument_Destroy(doc);

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDMetaData_SetSignature(metadata, "12345678");
    CU_ASSERT_NOT_EQUAL(rc, -1);
    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n  txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    const char *nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, true);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(resolvedoc));

    DIDDocument_Destroy(resolvedoc);
    printf("\n-- resolve result: successfully!\n------------------------------------------------------------\n");
}

static void test_idchain_publishdid_with_credential(void)
{
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid;
    Credential *cred;
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    doc = DIDStore_NewDID(store, storepass, "littlefish");
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));
    DIDDocument_Destroy(doc);

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    DIDURL *credid = DIDURL_NewByDid(&did, "cred-1");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfClaimedCredential"};

    Property props[1];
    props[0].key = "name";
    props[0].value = "John";

    rc = DIDDocumentBuilder_AddSelfClaimedCredential(builder, credid, types, 2, props, 1, 0, storepass);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    cred = DIDDocument_GetCredential(doc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, true);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    printf("\n-- resolve result: successfully!\n------------------------------------------------------------\n");

    cred = DIDDocument_GetCredential(resolvedoc, credid);
    CU_ASSERT_PTR_NOT_NULL(cred);

    DIDURL_Destroy(credid);
    DIDDocument_Destroy(resolvedoc);
}

static void test_idchain_deactivedid_after_create(void)
{
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid;
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    doc = DIDStore_NewDID(store, storepass, "littlefish");
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    const char *data1 = DIDDocument_ToJson(doc, true);
    const char *data2 = DIDDocument_ToJson(resolvedoc, true);
    CU_ASSERT_STRING_EQUAL(data1, data2);
    free((void*)data1);
    free((void*)data2);

    DIDDocument_Destroy(doc);
    DIDDocument_Destroy(resolvedoc);

    successed = DIDStore_DeactivateDID(store, storepass, &did, NULL);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("\n-- deactive did result:\n   did = %s\n -- resolve begin(deactive)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NULL(resolvedoc);

    printf("\n-- resolve result: successfully!\n------------------------------------------------------------\n");
    CU_ASSERT_STRING_EQUAL("DID is deactivated.", DIDError_GetMessage());
    return;
}

static void test_idchain_deactivedid_after_update(void)
{
    DIDURL *signkey;
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    bool successed;
    DID did;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    //create
    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    signkey = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signkey);

    DID_Copy(&did, DIDDocument_GetSubject(doc));

    printf("\n------------------------------------------------------------\n-- publish begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, signkey, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    const char *nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);

    CU_ASSERT_STRING_EQUAL(DIDDocument_GetProofSignature(doc), DIDDocument_GetProofSignature(resolvedoc));
    DIDDocument_Destroy(doc);

    printf("\n   txid: %s\n-- resolve result: successfully!\n-- publish begin(update), waiting...\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    //update
    doc = DIDStore_LoadDID(store, &did);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(doc);

    keybase = Generater_Publickey(publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);
    DIDURL *keyid = DIDURL_NewByDid(&did, "key1");
    CU_ASSERT_PTR_NOT_NULL(keyid);
    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(doc);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));
    DIDDocumentBuilder_Destroy(builder);

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);

    metadata = DIDDocument_GetMetaData(doc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    nalias = DIDMetaData_GetAlias(metadata);
    CU_ASSERT_PTR_NOT_NULL(nalias);
    CU_ASSERT_STRING_EQUAL(alias, nalias);
    DIDDocument_Destroy(doc);

    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(update)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(resolvedoc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(resolvedoc));
    printf("\n-- resolve result: successfully!\n-- deactive did begin, waiting...\n");

    DIDDocument_Destroy(resolvedoc);

    successed = DIDStore_DeactivateDID(store, storepass, &did, NULL);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- deactive did result:\n   did = %s\n -- resolve begin(deactive)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NULL(resolvedoc);

    printf("\n-- resolve result: successfully!\n------------------------------------------------------------\n");
    CU_ASSERT_STRING_EQUAL("DID is deactivated.", DIDError_GetMessage());
    return;
}

static void test_idchain_deactivedid_with_authorization1(void)
{
    DIDDocument *resolvedoc = NULL, *doc, *targetdoc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *alias = "littlefish";
    DID controller, did;
    PublicKey *pks[1];
    bool isEqual, successed;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&controller, DIDDocument_GetSubject(doc));
    DIDDocument_Destroy(doc);

    printf("\n------------------------------------------------------------\n-- publish authorization did begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &controller, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", controller.idstring);

    resolvedoc = DID_Resolve(&controller, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    printf("\n   txid: %s\n-- resolve authorization result: successfully!\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    targetdoc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(targetdoc);

    DID_Copy(&did, DIDDocument_GetSubject(targetdoc));

    DIDDocumentBuilder *builder = DIDDocument_Edit(targetdoc);
    CU_ASSERT_PTR_NOT_NULL(builder);
    DIDDocument_Destroy(targetdoc);

    DIDURL *keyid = DIDURL_NewByDid(&did, "recovery");
    CU_ASSERT_PTR_NOT_NULL(keyid);

    rc = DIDDocumentBuilder_AuthorizationDid(builder, keyid, &controller, NULL);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    targetdoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(targetdoc);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(targetdoc));

    size_t size = DIDDocument_GetAuthorizationKeys(targetdoc, pks, sizeof(pks));
    CU_ASSERT_EQUAL(1, size);
    isEqual = DID_Equals(&did, &pks[0]->id.did);
    CU_ASSERT_TRUE(isEqual);

    rc = DIDStore_StoreDID(store, targetdoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDDocument_Destroy(targetdoc);

    printf("-- publish target did begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    rc = DIDStore_StoreDID(store, resolvedoc);
    DIDDocument_Destroy(resolvedoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    printf("\n-- resolve authorization result: successfully!\n");

    successed = DIDStore_DeactivateDID(store, storepass, &did, NULL);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- deactive did result:\n   did = %s\n -- resolve begin(deactive)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NULL(resolvedoc);

    printf("\n-- resolve target result: successfully!\n------------------------------------------------------------\n");
    CU_ASSERT_STRING_EQUAL("DID is deactivated.", DIDError_GetMessage());
    return;
}

static void test_idchain_deactivedid_with_authorization2(void)
{
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    DIDDocument *resolvedoc = NULL, *doc, *targetdoc;
    DIDMetaData *metadata;
    const char *mnemonic, *txid, *keybase, *alias = "littlefish";
    HDKey _dkey, *dkey;
    DID controller, did;
    PublicKey *pks[1];
    bool isEqual, successed;
    int i = 0, rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, "", language, true);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    Mnemonic_Free((void*)mnemonic);

    doc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(doc);

    DID_Copy(&controller, DIDDocument_GetSubject(doc));

    DIDDocumentBuilder *builder = DIDDocument_Edit(doc);
    CU_ASSERT_PTR_NOT_NULL_FATAL(builder);
    DIDDocument_Destroy(doc);

    dkey = Generater_KeyPair(&_dkey);
    keybase = HDKey_GetPublicKeyBase58(dkey, publickeybase58, sizeof(publickeybase58));
    CU_ASSERT_PTR_NOT_NULL(keybase);

    DIDURL *keyid = DIDURL_NewByDid(&controller, "key-2");
    CU_ASSERT_PTR_NOT_NULL(keyid);

    rc = DIDStore_StorePrivateKey(store, storepass, &controller, keyid,
            HDKey_GetPrivateKey(dkey), sizeof(HDKey_GetPrivateKey(dkey)));
    CU_ASSERT_NOT_EQUAL(rc, -1);

    rc = DIDDocumentBuilder_AddAuthenticationKey(builder, keyid, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    doc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL(doc);
    DIDDocumentBuilder_Destroy(builder);

    CU_ASSERT_EQUAL(2, DIDDocument_GetPublicKeyCount(doc));
    CU_ASSERT_EQUAL(2, DIDDocument_GetAuthenticationCount(doc));

    rc = DIDStore_StoreDID(store, doc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDDocument_Destroy(doc);

    printf("\n------------------------------------------------------------\n-- publish authorization did begin(create), waiting....\n");
    successed = (char *)DIDStore_PublishDID(store, storepass, &controller, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", controller.idstring);

    resolvedoc = DID_Resolve(&controller, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);

    printf("\n   txid: %s\n-- resolve authorization result: successfully!\n", txid);
    DIDDocument_Destroy(resolvedoc);
    resolvedoc = NULL;

    targetdoc = DIDStore_NewDID(store, storepass, alias);
    CU_ASSERT_PTR_NOT_NULL(targetdoc);

    builder = DIDDocument_Edit(targetdoc);
    CU_ASSERT_PTR_NOT_NULL(builder);

    DID_Copy(&did, DIDDocument_GetSubject(targetdoc));
    DIDDocument_Destroy(targetdoc);

    keyid = DIDURL_NewByDid(&did, "recovery");
    CU_ASSERT_PTR_NOT_NULL(keyid);

    rc = DIDDocumentBuilder_AddAuthorizationKey(builder, keyid, &controller, keybase);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDURL_Destroy(keyid);

    targetdoc = DIDDocumentBuilder_Seal(builder, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(targetdoc);
    CU_ASSERT_EQUAL(1, DIDDocument_GetAuthorizationCount(targetdoc));
    DIDDocumentBuilder_Destroy(builder);

    size_t size = DIDDocument_GetAuthorizationKeys(targetdoc, pks, sizeof(pks));
    CU_ASSERT_EQUAL(1, size);
    isEqual = DID_Equals(&did, &pks[0]->id.did);
    CU_ASSERT_TRUE(isEqual);

    rc = DIDStore_StoreDID(store, targetdoc);
    CU_ASSERT_NOT_EQUAL(rc, -1);
    DIDDocument_Destroy(targetdoc);

    printf("-- publish target did begin(create), waiting....\n");
    successed = DIDStore_PublishDID(store, storepass, &did, NULL, false);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- publish result:\n   did = %s\n -- resolve begin(create)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NOT_NULL(resolvedoc);

    metadata = DIDDocument_GetMetaData(resolvedoc);
    CU_ASSERT_PTR_NOT_NULL(metadata);
    txid = DIDMetaData_GetTxid(metadata);
    CU_ASSERT_PTR_NOT_NULL(txid);
    printf("\n   txid: %s\n-- resolve target result: successfully!", txid);
    DIDDocument_Destroy(resolvedoc);

    successed = DIDStore_DeactivateDID(store, storepass, &did, NULL);
    CU_ASSERT_TRUE_FATAL(successed);
    printf("-- deactive did result:\n   did = %s\n -- resolve begin(deactive)", did.idstring);

    resolvedoc = DID_Resolve(&did, true);
    CU_ASSERT_PTR_NULL(resolvedoc);

    printf("\n-- resolve result: successfully!\n------------------------------------------------------------\n");
    CU_ASSERT_STRING_EQUAL("DID is deactivated.", DIDError_GetMessage());
    return;
}

static void test_idchain_declearvc(void)
{
    CredentialBiography *biography;
    DIDDocument *issuerdoc, *doc;
    Credential *vc, *resolve_vc1, *resolve_vc2;
    DIDURL *signkey1, *signkey2;
    int status;

    doc = TestData_LoadDoc();
    issuerdoc = TestData_LoadIssuerDoc();

    //todo: add another did
    vc = TestData_LoadEmailVc();
    CU_ASSERT_PTR_NOT_NULL(vc);

    //declear
    CU_ASSERT_TRUE(DIDStore_DeclearCredential(store, storepass, &vc->id, NULL));
    CU_ASSERT_TRUE(Credential_WasDecleared(&vc->id));
    CU_ASSERT_FALSE(Credential_IsRevoked(vc));

    resolve_vc1 = Credential_Resolve(&vc->id, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_vc1);
    CU_ASSERT_EQUAL(0, status);

    //declear again, fail.
    CU_ASSERT_FALSE(DIDStore_DeclearCredential(store, storepass, &vc->id, NULL));
    CU_ASSERT_STRING_EQUAL("The credential already exist.", DIDError_GetMessage());

    //revoke
    signkey1 = DIDDocument_GetDefaultPublicKey(issuerdoc);
    CU_ASSERT_TRUE(DIDStore_RevokeCredential(store, storepass, &vc->id, signkey1));
    signkey2 = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_FALSE(DIDStore_RevokeCredential(store, storepass, &vc->id, signkey2));
    CU_ASSERT_FALSE(DIDStore_DeclearCredential(store, storepass, &vc->id, NULL));
    CU_ASSERT_STRING_EQUAL("The credential is revoked.", DIDError_GetMessage());

    resolve_vc2 = Credential_Resolve(&vc->id, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolve_vc2);
    CU_ASSERT_EQUAL(0, status);

    const char *data1 = Credential_ToJson(resolve_vc1, true);
    const char *data2 = Credential_ToJson(resolve_vc2, true);
    CU_ASSERT_STRING_EQUAL(data1, data2);
    free((void*)data1);
    free((void*)data2);

    Credential_Destroy(resolve_vc1);
    Credential_Destroy(resolve_vc2);

    biography = Credential_ResolveBiography(&vc->id, NULL);
    CU_ASSERT_PTR_NOT_NULL(biography);
    CU_ASSERT_EQUAL(0, CredentialBiography_GetStatus(biography));
    CU_ASSERT_EQUAL(1, CredentialBiography_GetTransactionCount(biography));
    CredentialBiography_Destroy(biography);

    biography = Credential_ResolveBiography(&vc->id, &issuerdoc->did);
    CU_ASSERT_PTR_NOT_NULL(biography);
    CU_ASSERT_EQUAL(1, CredentialBiography_GetStatus(biography));
    CU_ASSERT_EQUAL(2, CredentialBiography_GetTransactionCount(biography));
    CU_ASSERT_PTR_NULL(CredentialBiography_GetCredentialByIndex(biography, 0));
    vc = CredentialBiography_GetCredentialByIndex(biography, 1);
    CU_ASSERT_PTR_NOT_NULL(vc);
    Credential_Destroy(vc);
    CredentialBiography_Destroy(biography);
}

static void test_idchain_revokevc(void)
{
    DIDDocument *issuerdoc, *doc;
    Credential *vc;
    DIDURL *signkey1, *signkey2;
    int status;

    doc = TestData_LoadDoc();
    issuerdoc = TestData_LoadIssuerDoc();

    vc = TestData_LoadTwitterVc();
    CU_ASSERT_PTR_NOT_NULL(vc);

    signkey1 = DIDDocument_GetDefaultPublicKey(issuerdoc);
    CU_ASSERT_TRUE(DIDStore_RevokeCredential(store, storepass, &vc->id, signkey1));
    CU_ASSERT_TRUE(Credential_IsRevoked(vc));
    signkey2 = DIDDocument_GetDefaultPublicKey(doc);
    CU_ASSERT_FALSE(DIDStore_RevokeCredential(store, storepass, &vc->id, signkey2));
    CU_ASSERT_STRING_EQUAL("Credential is already revoked.", DIDError_GetMessage());

    CU_ASSERT_FALSE(DIDStore_DeclearCredential(store, storepass, &vc->id, NULL));
    CU_ASSERT_STRING_EQUAL("The credential is revoked.", DIDError_GetMessage());

    CU_ASSERT_PTR_NULL(Credential_Resolve(&vc->id, &status, true));
    CU_ASSERT_EQUAL(2, status);

    CU_ASSERT_TRUE(Credential_ResolveRevocation(&vc->id, &issuerdoc->did));
}

static void test_idchain_listvc(void)
{
    Credential *vc, *resolvevc;
    DIDDocument *document, *issuerdoc, *resolvedoc;
    DIDDocumentBuilder *builder;
    DIDURL *credid1, *credid2;
    DIDURL *buffer[2] = {0};
    Issuer *issuer;
    DID did, issuerid;
    time_t expires;
    const char* provalue;
    int rc, status, i;

    CU_ASSERT_NOT_EQUAL(TestData_InitIdentity(store), -1);

    //create owner document
    document = DIDStore_NewDID(store, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL(document);
    DID_Copy(&did, &document->did);

    expires = DIDDocument_GetExpires(document);

    //create issuer
    issuerdoc = DIDStore_NewDID(store, storepass, NULL);
    CU_ASSERT_PTR_NOT_NULL(issuerdoc);
    DID_Copy(&issuerid, &issuerdoc->did);
    DIDDocument_Destroy(issuerdoc);
    CU_ASSERT_TRUE(DIDStore_PublishDID(store, storepass, &issuerid, NULL, true));

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

    builder = DIDDocument_Edit(document);
    DIDDocument_Destroy(document);
    CU_ASSERT_PTR_NOT_NULL(builder);

    credid2 = DIDURL_NewByDid(&did, "selfvc");
    CU_ASSERT_PTR_NOT_NULL(credid1);

    types[0] = "BasicProfileCredential";
    types[1] = "SelfClaimedCredential";

    Property props[1];
    props[0].key = "name";
    props[0].value = "John";

    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddSelfClaimedCredential(builder, credid2, types, 2, props, 1, 0, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocumentBuilder_AddCredential(builder, vc));
    Credential_Destroy(vc);

    document = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    CU_ASSERT_PTR_NOT_NULL(document);

    CU_ASSERT_NOT_EQUAL(-1, DIDStore_StoreDID(store, document));
    DIDDocument_Destroy(document);
    CU_ASSERT_TRUE(DIDStore_PublishDID(store, storepass, &did, NULL, true));

    //declear credid2
    CU_ASSERT_TRUE(DIDStore_DeclearCredential(store, storepass, credid2, NULL));
    CU_ASSERT_TRUE(Credential_WasDecleared(credid2));
    CU_ASSERT_FALSE(Credential_ResolveRevocation(credid2, &issuerid));

    //revoke credid1
    CU_ASSERT_TRUE(DIDStore_RevokeCredential(store, storepass, credid1, NULL));
    CU_ASSERT_FALSE(Credential_WasDecleared(credid1));
    CU_ASSERT_TRUE(Credential_ResolveRevocation(credid1, &issuerid));

    //resolve did
    resolvedoc = DID_Resolve(&did, true);
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

    CU_ASSERT_FALSE(Credential_WasDecleared(&vc->id));
    CU_ASSERT_TRUE(Credential_IsRevoked(vc));

    //resolve credid1(revoked)
    resolvevc = Credential_Resolve(credid1, &status, true);
    CU_ASSERT_PTR_NULL(resolvevc);
    CU_ASSERT_TRUE(Credential_ResolveRevocation(credid1, &issuerid));

    //check credid2
    vc = DIDDocument_GetCredential(resolvedoc, credid2);
    CU_ASSERT_PTR_NOT_NULL(vc);

    resolvevc = Credential_Resolve(credid2, &status, true);
    CU_ASSERT_PTR_NOT_NULL(resolvevc);
    CU_ASSERT_TRUE(Credential_WasDecleared(credid2));
    CU_ASSERT_FALSE(Credential_IsRevoked(vc));

    CU_ASSERT_TRUE(DIDURL_Equals(Credential_GetId(resolvevc), credid2));
    CU_ASSERT_TRUE(DID_Equals(Credential_GetOwner(resolvevc), &did));
    CU_ASSERT_TRUE(DID_Equals(Credential_GetIssuer(resolvevc), &did));

    Credential_Destroy(resolvevc);
    DIDDocument_Destroy(resolvedoc);

    CU_ASSERT_EQUAL(2, Credential_List(&did, buffer, sizeof(buffer), 0, 2));
    CU_ASSERT_TRUE(DIDURL_Equals(buffer[0], credid1) || DIDURL_Equals(buffer[0], credid2));
    CU_ASSERT_TRUE(DIDURL_Equals(buffer[1], credid1) || DIDURL_Equals(buffer[1], credid2));

    for (i = 0; i < 2; i++)
        DIDURL_Destroy(buffer[i]);

    DIDURL_Destroy(credid1);
    DIDURL_Destroy(credid2);
}

static int idchain_dummyadapter_test_suite_init(void)
{
    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    return 0;
}

static int idchain_dummyadapter_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_idchain_publishdid",                                      test_idchain_publishdid                                     },
    { "test_idchain_publishdid_without_txid",                         test_idchain_publishdid_without_txid                        },
    { "test_idchain_publishdid_without_signature",                    test_idchain_publishdid_without_signature                   },
    { "test_idchain_publishdid_without_prevsignature",                test_idchain_publishdid_without_prevsignature               },
    { "test_idchain_publishdid_without_prevsignature_and_signature",  test_idchain_publishdid_without_prevsignature_and_signature },
    { "test_force_updatedid_without_prevsignature_and_signature",     test_force_updatedid_without_prevsignature_and_signature    },
    { "test_updatedid_with_diffprevsignature_only",                   test_updatedid_with_diffprevsignature_only                  },
    { "test_updatedid_with_diffsignature_only",                       test_updatedid_with_diffsignature_only                      },
    { "test_updatedid_with_diff_prevsignature_and_signature",         test_updatedid_with_diff_prevsignature_and_signature        },
    { "test_force_updatedid_with_wrongsignature",                     test_force_updatedid_with_wrongsignature                    },
    { "test_idchain_publishdid_with_credential",                      test_idchain_publishdid_with_credential                     },
    { "test_idchain_deactivedid_after_create",                        test_idchain_deactivedid_after_create                       },
    { "test_idchain_deactivedid_after_update",                        test_idchain_deactivedid_after_update                       },
    { "test_idchain_deactivedid_with_authorization1",                 test_idchain_deactivedid_with_authorization1                },
    { "test_idchain_deactivedid_with_authorization2",                 test_idchain_deactivedid_with_authorization2                },
    { "test_idchain_declearvc",                                       test_idchain_declearvc                                      },
    { "test_idchain_revokevc",                                        test_idchain_revokevc                                       },
    { "test_idchain_listvc",                                          test_idchain_listvc                                      },
    {  NULL,                                                          NULL                                                        }
};

static CU_SuiteInfo suite[] = {
    { "idchain dummyadapter test", idchain_dummyadapter_test_suite_init, idchain_dummyadapter_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                      NULL,                              NULL,                                 NULL, NULL, NULL  }
};

CU_SuiteInfo* idchain_dummyadapter_test_suite_info(void)
{
    return suite;
}
