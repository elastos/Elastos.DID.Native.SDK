/*
 * Copyright (c) 2019 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ela_did.h"
#include "HDkey.h"
#include "crypto.h"
#include "diderror.h"
#include "did.h"
#include "didstore.h"
#include "diddocument.h"
#include "rootidentity.h"
#include "identitymeta.h"

static RootIdentity *create_rootidentity(HDKey *hdkey, DIDStore *store, const char *storepass,
        const char *mnemonic)
{
    RootIdentity *rootidentity = NULL;
    HDKey _derivedkey, *predeviedkey = NULL;

    assert(hdkey);
    assert(store);
    assert(storepass && *storepass);

    rootidentity = (RootIdentity*)calloc(1, sizeof(RootIdentity));
    if (!rootidentity) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for RootIdentity object failed.");
        return NULL;
    }

    //set 'mnemonic'
    if (mnemonic && *mnemonic)
       strcpy(rootidentity->mnemonic, mnemonic);

    //set 'rootPrivateKey'
    if (HDKey_SerializePrv(hdkey, rootidentity->rootPrivateKey, EXTENDEDKEY_BYTES) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Serialize extended private key failed.");
        goto errorExit;
    }

    //set 'preDerivedPublicKey': Pre-derive publickey path: m/44'/0'/0'
    predeviedkey = HDKey_GetDerivedKey(hdkey, &_derivedkey, 3, 44 | HARDENED,
            0 | HARDENED, 0 | HARDENED);
    if (!predeviedkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get derived key failed.");
        goto errorExit;
    }

    if (HDKey_SerializePub(predeviedkey, rootidentity->preDerivedPublicKey, EXTENDEDKEY_BYTES) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Serialize extended public key failed.");
        goto errorExit;
    }

    //set 'id'
    if (to_hexstring((char*)rootidentity->id, sizeof(rootidentity->id), rootidentity->preDerivedPublicKey, EXTENDEDKEY_BYTES) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get rootidentity's id failed.");
        goto errorExit;
    }

    HDKey_Wipe(predeviedkey);
    return rootidentity;

errorExit:
    HDKey_Wipe(predeviedkey);
    RootIdentity_Destroy(rootidentity);
    return NULL;
}

static int store_rootidentity(RootIdentity *rootidentity, DIDStore *store,
        const char *storepass, bool overwrite)
{
    assert(rootidentity);
    assert(store);
    assert(storepass && *storepass);

    if (DIDStore_ContainsRootIdentity(store, rootidentity->id) && !overwrite) {
        DIDError_Set(DIDERR_ALREADY_EXISTS, "Already has private identity.");
        return -1;
    }

    IdentityMetadata_SetStore(&rootidentity->metadata, store);
    if (DIDStore_StoreRootIdentity(store, storepass, rootidentity) < 0) {
        DIDError_Set(DIDERR_ALREADY_EXISTS, "Already has private identity.");
        return -1;
    }

    return 0;
}

RootIdentity *RootIdentity_Create(const char *mnemonic, const char *passphrase,
        const char *language, bool overwrite, DIDStore *store, const char *storepass)
{
    RootIdentity *rootidentity = NULL;
    HDKey _hdkey, *hdkey = NULL;

    if (!mnemonic || !*mnemonic || !store || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (strlen(mnemonic) + 1 > ELA_MAX_MNEMONIC_LEN) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Mnemonic is too long.");
        return NULL;
    }

    if (!passphrase)
        passphrase = "";

    hdkey = HDKey_FromMnemonic(mnemonic, passphrase, language, &_hdkey);
    if (!hdkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get private identity failed.");
        return NULL;
    }

    rootidentity = create_rootidentity(hdkey, store, storepass, mnemonic);
    if (!rootidentity || store_rootidentity(rootidentity, store, storepass, overwrite) < 0)
        goto errorExit;

    HDKey_Wipe(hdkey);
    RootIdentity_Wipe(rootidentity);
    return rootidentity;

errorExit:
    HDKey_Wipe(hdkey);
    RootIdentity_Destroy(rootidentity);
    return NULL;
}

RootIdentity *RootIdentity_CreateByFromRootKey(const char *extendedkey,
        bool overwrite, DIDStore *store, const char *storepass)
{
    RootIdentity *rootidentity = NULL;
    HDKey _hdkey, *hdkey = NULL;

    if (!extendedkey || !*extendedkey || !store || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    hdkey = HDKey_FromExtendedKeyBase58(extendedkey, strlen(extendedkey) + 1, &_hdkey);
    if (!hdkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Initial private identity failed.");
        return NULL;
    }

    rootidentity = create_rootidentity(hdkey, store, storepass, NULL);
    if (!rootidentity || store_rootidentity(rootidentity, store, storepass, overwrite) < 0)
        goto errorExit;

    HDKey_Wipe(hdkey);
    RootIdentity_Wipe(rootidentity);
    return rootidentity;

errorExit:
    HDKey_Wipe(hdkey);
    RootIdentity_Destroy(rootidentity);
    return NULL;
}

void RootIdentity_Destroy(RootIdentity *rootidentity)
{
    if (rootidentity) {
        IdentityMetadata_Free(&rootidentity->metadata);
        memset(rootidentity, 0, sizeof(RootIdentity));
        free((void*)rootidentity);
    }
}

void RootIdentity_Wipe(RootIdentity *rootidentity)
{
    if (rootidentity) {
        *rootidentity->mnemonic = 0;
        memset(rootidentity->rootPrivateKey, 0, EXTENDEDKEY_BYTES);
    }
}

const char *RootIdentity_GetId(RootIdentity *rootidentity)
{
    if (!rootidentity) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No rootidentity.");
        return NULL;
    }

    return rootidentity->id;
}

const char *RootIdentity_GetAlias(RootIdentity *rootidentity)
{
    if (!rootidentity) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No rootidentity.");
        return NULL;
    }

    return IdentityMetadata_GetAlias(&rootidentity->metadata);
}

int RootIdentity_SetAlias(RootIdentity *rootidentity, const char *alias)
{
    if (!rootidentity) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No rootidentity.");
        return -1;
    }

    return IdentityMetadata_SetAlias(&rootidentity->metadata, alias);
}

int RootIdentity_SetDefaultDID(RootIdentity *rootidentity, DID *did)
{
    char idstring[ELA_MAX_DID_LEN];

    if (!rootidentity || !did) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No rootidentity or default DID.");
        return -1;
    }

    return IdentityMetadata_SetDefaultDID(&rootidentity->metadata, DID_ToString(did, idstring, sizeof(idstring)));
}

DID *RootIdentity_GetDefaultDID(RootIdentity *rootidentity)
{
    const char *idstring;

    if (!rootidentity) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No rootidentity or default DID.");
        return NULL;
    }

    idstring = IdentityMetadata_GetDefaultDID(&rootidentity->metadata);
    if (!idstring) {
        DIDError_Set(DIDERR_MALFORMED_ROOTIDENTITY, "No default DID.");
        return NULL;
    }

    return DID_FromString(idstring);
}

static HDKey *get_derivedkey(uint8_t *extendedkey, size_t size, int index,
        HDKey *derivedkey)
{
    HDKey _identity, *identity, *dkey;

    assert(extendedkey);
    assert(size >= EXTENDEDKEY_BYTES);
    assert(index >= 0);
    assert(derivedkey);

    identity = HDKey_FromExtendedKey(extendedkey, sizeof(extendedkey), &_identity);
    if (!identity) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Initial private identity failed.");
        return NULL;
    }

    dkey = HDKey_GetDerivedKey(identity, derivedkey, 5, 44 | HARDENED, 0 | HARDENED,
            0 | HARDENED, 0, index);
    HDKey_Wipe(identity);
    if (!dkey)
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Initial derived private identity failed.");

    return dkey;
}

static HDKey *get_derive(RootIdentity *rootidentity, int index, DIDStore *store,
        const char *storepass, HDKey *derivedkey)
{
    ssize_t size;
    uint8_t extendedkey[EXTENDEDKEY_BYTES];

    assert(rootidentity);
    assert(index >= 0);
    assert(derivedkey);
    assert(store);

    if (storepass) {
        size = DIDStore_LoadRootIdentityPrvkey(store, storepass, rootidentity->id, extendedkey, sizeof(extendedkey));
        if (size < 0) {
            memset(extendedkey, 0, sizeof(extendedkey));
            return NULL;
        }
    } else {
        memcpy(extendedkey, rootidentity->preDerivedPublicKey, sizeof(extendedkey));
    }

    return get_derivedkey(extendedkey, sizeof(extendedkey), index, derivedkey);
}

static DIDDocument *create_document(DID *did, const char *key, const char *alias,
        DIDStore *store, const char *storepass)
{
    DIDDocument *document;
    DIDDocumentBuilder *builder;
    DIDURL id;

    assert(did);
    assert(key && *key);
    assert(store);
    assert(storepass && *storepass);

    if (Init_DIDURL(&id, did, "primary") == -1)
        return NULL;

    builder = DIDDocument_CreateBuilder(did, NULL, store);
    if (!builder)
        return NULL;

    if (DIDDocumentBuilder_AddPublicKey(builder, &id, did, key) == -1) {
        DIDDocumentBuilder_Destroy(builder);
        return NULL;
    }

    if (DIDDocumentBuilder_AddAuthenticationKey(builder, &id, key) == -1) {
        DIDDocumentBuilder_Destroy(builder);
        return NULL;
    }

    if (DIDDocumentBuilder_SetExpires(builder, 0) == -1) {
        DIDDocumentBuilder_Destroy(builder);
        return NULL;
    }

    document = DIDDocumentBuilder_Seal(builder, storepass);
    DIDDocumentBuilder_Destroy(builder);
    if (!document)
        return NULL;

    return document;
}

static DIDDocument *rootidentity_createdid(RootIdentity *rootidentity, int index, const char *alias,
        DIDStore *store, const char *storepass)
{
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    uint8_t extendedkey[EXTENDEDKEY_BYTES];
    HDKey _derivedkey, *derivedkey;
    DIDDocument *document;
    DID did;
    int status;

    assert(rootidentity);
    assert(index >= 0);
    assert(store);

    derivedkey = get_derive(rootidentity, index, store, storepass, &_derivedkey);
    if (!derivedkey)
        return NULL;

    Init_DID(&did, HDKey_GetAddress(derivedkey));

    //check did is exist or not
    document = DIDStore_LoadDID(store, &did);
    if (document) {
        DIDError_Set(DIDERR_ALREADY_EXISTS, "DID already exists.");
        HDKey_Wipe(derivedkey);
        DIDDocument_Destroy(document);
        return NULL;
    }

    document = DID_Resolve(&did, &status, true);
    if (document) {
        DIDError_Set(DIDERR_ALREADY_EXISTS, "DID already exists.");
        HDKey_Wipe(derivedkey);
        DIDDocument_Destroy(document);
        return NULL;
    }

    if (HDKey_SerializePrv(derivedkey, extendedkey, sizeof(extendedkey)) < 0) {
        HDKey_Wipe(derivedkey);
        return NULL;
    }

    if (DIDStore_StoreDefaultPrivateKey(store, storepass, did.idstring,
            extendedkey, sizeof(extendedkey)) == -1) {
        HDKey_Wipe(derivedkey);
        return NULL;
    }

    document = create_document(&did,
            HDKey_GetPublicKeyBase58(derivedkey, publickeybase58, sizeof(publickeybase58)),
            alias, store, storepass);
    HDKey_Wipe(derivedkey);
    if (!document) {
        DIDStore_DeleteDID(store, &did);
        return NULL;
    }

    DIDMetadata_SetRootIdentity(&document->metadata, rootidentity->id);
    DIDMetadata_SetIndex(&document->metadata, index);
    DIDMetadata_SetAlias(&document->metadata, alias);
    DIDMetadata_SetDeactivated(&document->metadata, false);
    memcpy(&document->did.metadata, &document->metadata, sizeof(DIDMetadata));

    if (DIDStore_StoreDID(store, document) == -1) {
        DIDStore_DeleteDID(store, &did);
        DIDDocument_Destroy(document);
        return NULL;
    }

    DIDDocument_SetStore(document, store);
    return document;
}

DIDDocument *RootIdentity_NewDID(RootIdentity *rootidentity, const char *storepass, const char *alias)
{
    DIDDocument *document;
    DIDStore *store;
    char didstring[ELA_MAX_DID_LEN];
    int index;

    if (!rootidentity || !storepass || !*storepass) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    store = rootidentity->metadata.base.store;
    if (!store) {
        DIDError_Set(DIDERR_MALFORMED_ROOTIDENTITY, "No store attached with root identity.");
        return NULL;
    }

    index = DIDStore_LoadIndex(store, rootidentity->id);
    if (index < 0)
        return NULL;

    document = rootidentity_createdid(rootidentity, index++, alias, store, storepass);
    if (!document)
        return NULL;

    if (DIDStore_StoreIndex(store, rootidentity->id, index) == -1) {
        DIDDocument_Destroy(document);
        return NULL;
    }

    if (!IdentityMetadata_GetDefaultDID(&rootidentity->metadata))
        IdentityMetadata_SetDefaultDID(&rootidentity->metadata, DID_ToString(&document->did, didstring, sizeof(didstring)));

    return document;
}

DIDDocument *RootIdentity_NewDIDByIndex(RootIdentity *rootidentity, int index,
        const char *storepass, const char *alias)
{
    DIDStore *store;
    DIDDocument *document;
    char didstring[ELA_MAX_DID_LEN];

    if (!rootidentity || !storepass || !*storepass || index < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    store = rootidentity->metadata.base.store;
    if (!store) {
        DIDError_Set(DIDERR_MALFORMED_ROOTIDENTITY, "No store attached with root identity.");
        return NULL;
    }

    document = rootidentity_createdid(rootidentity, index, alias, store, storepass);
    if (!document)
        return NULL;

    if (!IdentityMetadata_GetDefaultDID(&rootidentity->metadata))
        IdentityMetadata_SetDefaultDID(&rootidentity->metadata, DID_ToString(&document->did, didstring, sizeof(didstring)));

    return document;
}

DID *RootIdentity_GetDIDByIndex(RootIdentity *rootidentity, int index)
{
    DID *did;
    DIDStore *store;
    HDKey _derivedkey, *derivedkey;

    if (!rootidentity || index < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    store = rootidentity->metadata.base.store;
    if (!store) {
        DIDError_Set(DIDERR_MALFORMED_ROOTIDENTITY, "No store attached with root identity.");
        return NULL;
    }

    derivedkey = get_derive(rootidentity, index, store, NULL, &_derivedkey);
    if (!derivedkey)
        return NULL;

    did = DID_New(HDKey_GetAddress(derivedkey));
    HDKey_Wipe(derivedkey);
    return did;
}

int RootIdentity_SetAsDefault(RootIdentity *identity)
{
    if (!identity) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    if (!identity->metadata.base.store) {
        DIDError_Set(DIDERR_MALFORMED_ROOTIDENTITY, "No attache store to root identity.");
        return -1;
    }

    return DIDStore_SetDefaultRootIdentity(identity->metadata.base.store, identity->id);
}

static DIDDocument* diddocument_conflict_merge(DIDDocument *chaincopy, DIDDocument *localcopy)
{
    assert(chaincopy);
    assert(localcopy);

    DIDMetadata_SetPublished(&localcopy->metadata, DIDMetadata_GetPublished(&chaincopy->metadata));
    DIDMetadata_SetSignature(&localcopy->metadata, DIDMetadata_GetSignature(&chaincopy->metadata));
    memcpy(&localcopy->did.metadata, &localcopy->metadata, sizeof(DIDMetadata));

    return localcopy;
}

bool RootIdentity_Synchronize(RootIdentity *rootidentity, DIDDocument_ConflictHandle *handle)
{
    int lastindex, i = 0, blanks = 0;
    bool exists;

     if (!rootidentity) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (!handle)
        handle = diddocument_conflict_merge;

    lastindex = rootidentity->index - 1;
    while (i < lastindex || blanks < 20) {
        exists = RootIdentity_SynchronizeByIndex(rootidentity, i, handle);
        if (exists) {
            if (i > lastindex)
                lastindex = i;

            blanks = 0;
        } else {
            if (i > lastindex)
                blanks++;
        }
    }

    if (lastindex >= rootidentity->index)
        rootidentity->index = lastindex + 1;

    return true;
}

bool RootIdentity_SynchronizeByIndex(RootIdentity *rootidentity, int index,
        DIDDocument_ConflictHandle *handle)
{
    DID *did = NULL;
    DIDStore *store;
    DIDDocument *chaincopy = NULL, *localcopy = NULL, *finalcopy = NULL;
    const char *local_signature;
    int status;
    bool success = false;

    if (!rootidentity || index < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (!handle)
        handle = diddocument_conflict_merge;

    did = RootIdentity_GetDIDByIndex(rootidentity, index);
    if (!did)
        return false;

    chaincopy = DID_Resolve(did, &status, true);
    if (!chaincopy) {
        if (status == DIDStatus_NotFound)
            DIDError_Set(DIDERR_NOT_EXISTS, "Synchronize DID does not exist.");
        goto errorExit;
    }

    store = rootidentity->metadata.base.store;
    finalcopy = chaincopy;
    localcopy = DIDStore_LoadDID(store, did);
    if (localcopy) {
        local_signature = DIDMetadata_GetSignature(&localcopy->metadata);
        if (!*local_signature ||
                strcmp(DIDDocument_GetProofSignature(localcopy, 0), local_signature)) {
            finalcopy = handle(chaincopy, localcopy);
            if (!finalcopy|| !DID_Equals(DIDDocument_GetSubject(finalcopy), did)) {
                DIDError_Set(DIDERR_DIDSTORE_ERROR, "Conflict handle merge the DIDDocument error.");
                goto errorExit;
            }
        }
    }

    DIDMetadata_SetRootIdentity(&finalcopy->metadata, rootidentity->id);
    DIDMetadata_SetIndex(&finalcopy->metadata, index);
    DIDMetadata_SetDeactivated(&finalcopy->metadata, DIDMetadata_GetDeactivated(&chaincopy->metadata));

    if (DIDStore_StoreDID(store, finalcopy) == 0)
        success = true;

errorExit:
    if (finalcopy != chaincopy && finalcopy != localcopy)
        DIDDocument_Destroy(finalcopy);
    DIDDocument_Destroy(chaincopy);
    DIDDocument_Destroy(localcopy);
    DID_Destroy(did);
    return success;
}

ssize_t RootIdentity_LazyCreatePrivateKey(DIDURL *key, DIDStore *store, const char *storepass,
        uint8_t *extendedkey, size_t size)
{
    DIDDocument *doc = NULL;
    const char *id;
    uint8_t rootPrvkey[EXTENDEDKEY_BYTES];
    HDKey _derivedkey, *derivedkey = NULL;
    char publickeybase58[PUBLICKEY_BASE58_BYTES];
    PublicKey *pk;
    ssize_t len;
    int index, rc = -1;

    assert(id);
    assert(store);
    assert(storepass && *storepass);
    assert(extendedkey);
    assert(size >= EXTENDEDKEY_BYTES);

    doc = DIDStore_LoadDID(store, &key->did);
    if (!doc)
        return -1;

    id = DIDMetadata_GetRootIdentity(&doc->metadata);
    if (!id) {
        DIDError_Set(DIDERR_MALFORMED_ROOTIDENTITY, "Missing id.");
        goto errorExit;
    }

    index = DIDMetadata_GetIndex(&doc->metadata);
    if (index < 0) {
        DIDError_Set(DIDERR_MALFORMED_ROOTIDENTITY, "Missing index.");
        goto errorExit;
    }

    len = DIDStore_LoadRootIdentityPrvkey(store, storepass, id,
            rootPrvkey, sizeof(rootPrvkey));
    if (len != EXTENDEDKEY_BYTES)
        goto errorExit;

    derivedkey = get_derivedkey(rootPrvkey, len, index, &_derivedkey);
    memset(rootPrvkey, 0, sizeof(rootPrvkey));
    if (!derivedkey)
        goto errorExit;

    if (b58_encode(publickeybase58, sizeof(publickeybase58),
            derivedkey->publickey, PUBLICKEY_BYTES) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Encode extended public key failed.");
        goto errorExit;
    }

    pk = DIDDocument_GetPublicKey(doc, key);
    if (!pk)
        goto errorExit;

    if (strcmp(pk->publicKeyBase58, publickeybase58)) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Meta data mismatch with DID.");
        goto errorExit;
    }

    len = HDKey_SerializePrv(derivedkey, extendedkey, size);
    if (len < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Serialize extended private key failed.");
        goto errorExit;
    }

    if (DIDStore_StorePrivateKey(store, storepass, &key->did, key,
            extendedkey, len) < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Meta data mismatch with DID.");
        goto errorExit;
    }

    rc = len;

errorExit:
    HDKey_Wipe(derivedkey);
    DIDDocument_Destroy(doc);
    return rc;
}

