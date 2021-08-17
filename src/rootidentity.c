/*
 * Copyright (c) 2019 - 2021 Elastos Foundation
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

static RootIdentity *create_rootidentity(const char *mnemonic, HDKey *hdkey)
{
    RootIdentity *rootidentity = NULL;
    HDKey _derivedkey, *predeviedkey = NULL;

    assert(hdkey);

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
    if (md5_hex((char*)rootidentity->id, sizeof(rootidentity->id), rootidentity->preDerivedPublicKey, EXTENDEDKEY_BYTES) < 0) {
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
        DIDError_Set(DIDERR_ALREADY_EXISTS, "Already has rootidentity.");
        return -1;
    }

    IdentityMetadata_SetStore(&rootidentity->metadata, store);
    if (DIDStore_StoreRootIdentity(store, storepass, rootidentity) < 0)
        return -1;

    return 0;
}

RootIdentity *RootIdentity_Create(const char *mnemonic, const char *passphrase,
        bool overwrite, DIDStore *store, const char *storepass)
{
    RootIdentity *rootidentity = NULL;
    HDKey _hdkey, *hdkey = NULL;
    const char *language;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!mnemonic || !*mnemonic, "No mnemonic string.", NULL);
    CHECK_ARG(!store, "No store argument.", NULL);
    CHECK_PASSWORD(storepass, NULL);
    CHECK_ARG(strlen(mnemonic) + 1 > ELA_MAX_MNEMONIC_LEN, "Mnemonic is too long.", NULL);

    if (!passphrase)
        passphrase = "";

    language = Mnemonic_GetLanguage(mnemonic);
    if (!language) {
        DIDError_Set(DIDERR_MNEMONIC, "Mnemonic must be from specified languages.");
        return NULL;
    }

    hdkey = HDKey_FromMnemonic(mnemonic, passphrase, language, &_hdkey);
    free((void*)language);
    if (!hdkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Initial private identity failed.");
        return NULL;
    }

    rootidentity = create_rootidentity(mnemonic, hdkey);
    if (!rootidentity || store_rootidentity(rootidentity, store, storepass, overwrite) < 0)
        goto errorExit;

    HDKey_Wipe(hdkey);
    RootIdentity_Wipe(rootidentity);
    return rootidentity;

errorExit:
    HDKey_Wipe(hdkey);
    RootIdentity_Destroy(rootidentity);
    return NULL;

    DIDERROR_FINALIZE();
}

RootIdentity *RootIdentity_CreateFromRootKey(const char *extendedkey,
        bool overwrite, DIDStore *store, const char *storepass)
{
    RootIdentity *rootidentity = NULL;
    HDKey _hdkey, *hdkey = NULL;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!extendedkey || !*extendedkey, "No extendedkey string.", NULL);
    CHECK_ARG(!store, "No store argument.", NULL);
    CHECK_PASSWORD(storepass, NULL);

    hdkey = HDKey_FromExtendedKeyBase58(extendedkey, strlen(extendedkey) + 1, &_hdkey);
    if (!hdkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Initial private identity failed.");
        return NULL;
    }

    rootidentity = create_rootidentity(NULL, hdkey);
    if (!rootidentity || store_rootidentity(rootidentity, store, storepass, overwrite) < 0)
        goto errorExit;

    HDKey_Wipe(hdkey);
    RootIdentity_Wipe(rootidentity);
    return rootidentity;

errorExit:
    HDKey_Wipe(hdkey);
    RootIdentity_Destroy(rootidentity);
    return NULL;

    DIDERROR_FINALIZE();
}

const char *RootIdentity_CreateId(const char *mnemonic, const char *passphrase)
{
    RootIdentity *rootidentity = NULL;
    HDKey _hdkey, *hdkey = NULL;
    const char *language, *id = NULL;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!mnemonic || !*mnemonic, "No mnemonic string.", NULL);

    if (!passphrase)
        passphrase = "";

    language = Mnemonic_GetLanguage(mnemonic);
    if (!language) {
        DIDError_Set(DIDERR_MNEMONIC, "Mnemonic must be from specified languages.");
        return NULL;
    }

    hdkey = HDKey_FromMnemonic(mnemonic, passphrase, language, &_hdkey);
    free((void*)language);
    if (!hdkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Initial private identity failed.");
        return NULL;
    }

    rootidentity = create_rootidentity(mnemonic, hdkey);
    HDKey_Wipe(hdkey);
    if (rootidentity)
        id = strdup(rootidentity->id);

    RootIdentity_Destroy(rootidentity);
    return id;

    DIDERROR_FINALIZE();
}

const char *RootIdentity_CreateIdFromRootKey(const char *extendedkey)
{
    RootIdentity *rootidentity = NULL;
    HDKey _hdkey, *hdkey = NULL;
    const char *id = NULL;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!extendedkey || !*extendedkey, "No extendedkey string.", NULL);

    hdkey = HDKey_FromExtendedKeyBase58(extendedkey, strlen(extendedkey) + 1, &_hdkey);
    if (!hdkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Initial private identity failed.");
        return NULL;
    }

    rootidentity = create_rootidentity(NULL, hdkey);
    HDKey_Wipe(hdkey);

    if (rootidentity)
        id = strdup(rootidentity->id);

    RootIdentity_Destroy(rootidentity);
    return id;

    DIDERROR_FINALIZE();
}

void RootIdentity_Destroy(RootIdentity *rootidentity)
{
    DIDERROR_INITIALIZE();

    if (rootidentity) {
        IdentityMetadata_Free(&rootidentity->metadata);
        memset(rootidentity, 0, sizeof(RootIdentity));
        free((void*)rootidentity);
    }

    DIDERROR_FINALIZE();
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
    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity argument.", NULL);
    return rootidentity->id;

    DIDERROR_FINALIZE();
}

const char *RootIdentity_GetAlias(RootIdentity *rootidentity)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity argument.", NULL);
    return IdentityMetadata_GetAlias(&rootidentity->metadata);

    DIDERROR_FINALIZE();
}

int RootIdentity_SetAlias(RootIdentity *rootidentity, const char *alias)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity argument.", -1);
    return IdentityMetadata_SetAlias(&rootidentity->metadata, alias);

    DIDERROR_FINALIZE();
}

int RootIdentity_SetDefaultDID(RootIdentity *rootidentity, DID *did)
{
    char idstring[ELA_MAX_DID_LEN];

    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity argument.", -1);
    CHECK_ARG(!did, "No did to become default did.", -1);

    return IdentityMetadata_SetDefaultDID(&rootidentity->metadata, DID_ToString(did, idstring, sizeof(idstring)));

    DIDERROR_FINALIZE();
}

DID *RootIdentity_GetDefaultDID(RootIdentity *rootidentity)
{
    const char *idstring;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity argument.", NULL);

    idstring = IdentityMetadata_GetDefaultDID(&rootidentity->metadata);
    if (!idstring) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No default DID.");
        return NULL;
    }

    return DID_FromString(idstring);

    DIDERROR_FINALIZE();
}

static HDKey *get_derivedkey(uint8_t *extendedkey, size_t size, int index,
        HDKey *derivedkey)
{
    HDKey _identity, *identity, *dkey;

    assert(extendedkey);
    assert(size >= EXTENDEDKEY_BYTES);
    assert(index >= 0);
    assert(derivedkey);

    identity = HDKey_FromExtendedKey(extendedkey, size, &_identity);
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

    memset(derivedkey, 0, sizeof(HDKey));
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

    if (DIDURL_Init(&id, did, "primary") == -1)
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
        DIDStore *store, const char *storepass, bool overwrite)
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
    if (!derivedkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Derive private key failed.");
        return NULL;
    }

    DID_Init(&did, HDKey_GetAddress(derivedkey));

    //check did is exist or not
    document = DIDStore_LoadDID(store, &did);
    if (document) {
        HDKey_Wipe(derivedkey);
        DIDDocument_Destroy(document);
        return NULL;
    }

    document = DID_Resolve(&did, &status, true);
    if (document) {
        if (DIDDocument_IsDeactivated(document) || !overwrite) {
            if (DIDDocument_IsDeactivated(document))
                DIDError_Set(DIDERR_DID_DEACTIVATED, "DID is deactivated.");
            else
                DIDError_Set(DIDERR_ALREADY_EXISTS, "DID already exists.");

            HDKey_Wipe(derivedkey);
            DIDDocument_Destroy(document);
            return NULL;
        }
    }

    if (HDKey_SerializePrv(derivedkey, extendedkey, sizeof(extendedkey)) < 0) {
        HDKey_Wipe(derivedkey);
        return NULL;
    }

    if (DIDStore_StoreDefaultPrivateKey(store, storepass, did.idstring,
            extendedkey, sizeof(extendedkey)) < 0) {
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
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Store document(%s) failed.", DIDSTR(&document->did));
        DIDStore_DeleteDID(store, &did);
        DIDDocument_Destroy(document);
        return NULL;
    }

    DIDDocument_SetStore(document, store);
    return document;
}

DIDDocument *RootIdentity_NewDID(RootIdentity *rootidentity, const char *storepass,
        const char *alias, bool overwrite)
{
    DIDDocument *document;
    DIDStore *store;
    char didstring[ELA_MAX_DID_LEN];
    int index;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity to new did.", NULL);
    CHECK_PASSWORD(storepass, NULL);

    store = rootidentity->metadata.base.store;
    if (!store) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with rootidentity.");
        return NULL;
    }

    index = DIDStore_LoadIndex(store, rootidentity->id);
    if (index < 0)
        return NULL;

    document = rootidentity_createdid(rootidentity, index++, alias, store, storepass, overwrite);
    if (!document)
        return NULL;

    if (DIDStore_StoreIndex(store, rootidentity->id, index) == -1) {
        DIDDocument_Destroy(document);
        return NULL;
    }

    if (!IdentityMetadata_GetDefaultDID(&rootidentity->metadata))
        IdentityMetadata_SetDefaultDID(&rootidentity->metadata, DID_ToString(&document->did, didstring, sizeof(didstring)));

    return document;

    DIDERROR_FINALIZE();
}

DIDDocument *RootIdentity_NewDIDByIndex(RootIdentity *rootidentity, int index,
        const char *storepass, const char *alias, bool overwrite)
{
    DIDStore *store;
    DIDDocument *document;
    char didstring[ELA_MAX_DID_LEN];

    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity to new did.", NULL);
    CHECK_ARG(index < 0, "Invalid index.", NULL);
    CHECK_PASSWORD(storepass, NULL);

    store = rootidentity->metadata.base.store;
    if (!store) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with rootidentity.");
        return NULL;
    }

    document = rootidentity_createdid(rootidentity, index, alias, store, storepass, overwrite);
    if (!document)
        return NULL;

    if (!IdentityMetadata_GetDefaultDID(&rootidentity->metadata))
        IdentityMetadata_SetDefaultDID(&rootidentity->metadata, DID_ToString(&document->did, didstring, sizeof(didstring)));

    return document;

    DIDERROR_FINALIZE();
}

DID *RootIdentity_GetDIDByIndex(RootIdentity *rootidentity, int index)
{
    DID *did;
    DIDStore *store;
    HDKey _derivedkey, *derivedkey;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity to get did.", NULL);
    CHECK_ARG(index < 0, "Invalid index.", NULL);

    store = rootidentity->metadata.base.store;
    if (!store) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with rootidentity.");
        return NULL;
    }

    derivedkey = get_derive(rootidentity, index, store, NULL, &_derivedkey);
    if (!derivedkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Derive private key failed.");
        return NULL;
    }

    did = DID_New(HDKey_GetAddress(derivedkey));
    HDKey_Wipe(derivedkey);
    return did;

    DIDMetadata_SetRootIdentity(&did->metadata, rootidentity->id);
    DIDMetadata_SetIndex(&did->metadata, index);
    did->metadata.base.store = store;

    DIDERROR_FINALIZE();
}

int RootIdentity_SetAsDefault(RootIdentity *rootidentity)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity to set default did.", -1);

    if (!rootidentity->metadata.base.store) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with rootidentity.");
        return -1;
    }

    return DIDStore_SetDefaultRootIdentity(rootidentity->metadata.base.store, rootidentity->id);

    DIDERROR_FINALIZE();
}

static DIDDocument* diddocument_conflict_merge(DIDDocument *chaincopy, DIDDocument *localcopy)
{
    assert(chaincopy);
    assert(localcopy);

    return localcopy;
}

bool RootIdentity_Synchronize(RootIdentity *rootidentity, DIDDocument_ConflictHandle *handle)
{
    int lastindex, i = 0, blanks = 0;
    bool exists;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity to synchronize.", false);

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

        i++;
    }

    if (lastindex >= rootidentity->index)
        rootidentity->index = lastindex + 1;

    return true;

    DIDERROR_FINALIZE();
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

    DIDERROR_INITIALIZE();

    CHECK_ARG(!rootidentity, "No rootidentity to synchronize.", false);
    CHECK_ARG(index < 0, "Invalid index.", false);

    if (!handle)
        handle = diddocument_conflict_merge;

    did = RootIdentity_GetDIDByIndex(rootidentity, index);
    if (!did)
        return false;

    chaincopy = DID_Resolve(did, &status, true);
    if (!chaincopy) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Synchronize DID %s %s.", DIDSTR(did), DIDSTATUS_MSG(status));
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
    DIDMetadata_SetPublished(&finalcopy->metadata, DIDMetadata_GetPublished(&chaincopy->metadata));
    DIDMetadata_SetSignature(&finalcopy->metadata, DIDMetadata_GetSignature(&chaincopy->metadata));

    if (DIDStore_StoreDID(store, finalcopy) == 0 &&
            DIDStore_StoreLazyPrivateKey(store, DIDDocument_GetDefaultPublicKey(finalcopy)) == 0)
        success = true;

errorExit:
    if (finalcopy != chaincopy && finalcopy != localcopy)
        DIDDocument_Destroy(finalcopy);
    DIDDocument_Destroy(chaincopy);
    DIDDocument_Destroy(localcopy);
    DID_Destroy(did);
    return success;

    DIDERROR_FINALIZE();
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
    ssize_t len, rc = -1;
    int index;

    assert(key);
    assert(store);
    assert(storepass && *storepass);
    assert(extendedkey);
    assert(size >= EXTENDEDKEY_BYTES);

    doc = DIDStore_LoadDID(store, &key->did);
    if (!doc) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No owner's document.");
        return -1;
    }

    id = DIDMetadata_GetRootIdentity(&doc->metadata);
    if (!id) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Missing rootidentity id owned to key.");
        goto errorExit;
    }

    index = DIDMetadata_GetIndex(&doc->metadata);
    if (index < 0) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Missing index for owner's document.");
        goto errorExit;
    }

    len = DIDStore_LoadRootIdentityPrvkey(store, storepass, id,
            rootPrvkey, sizeof(rootPrvkey));
    if (len != EXTENDEDKEY_BYTES)
        goto errorExit;

    derivedkey = get_derivedkey(rootPrvkey, len, index, &_derivedkey);
    memset(rootPrvkey, 0, sizeof(rootPrvkey));
    if (!derivedkey) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get hdkey for owner's document failed.");
        goto errorExit;
    }

    if (b58_encode(publickeybase58, sizeof(publickeybase58),
            derivedkey->publickey, PUBLICKEY_BYTES) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Encode extended publicKey failed.");
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

    if (DIDStore_StorePrivateKey(store, storepass, key, extendedkey, len) < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Store private key failed.");
        goto errorExit;
    }

    rc = len;

errorExit:
    HDKey_Wipe(derivedkey);
    DIDDocument_Destroy(doc);
    return rc;
}

