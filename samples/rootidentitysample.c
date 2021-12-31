#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "samples.h"

static const char *STORE_PASS = "secret";

RootIdentity *createNewRootIdentity(DIDStore *store)
{
    // Create a mnemonic use default language(English).
    mnemonic = Mnemonic_Generate("english");
    if (!mnemonic)
        return NULL;

    printf("Please write down your mnemonic:\n  %s\n", mnemonic);

    // Initialize the root identity.
    return RootIdentity_Create(mnemonic, NULL, store, STORE_PASS);
}

static int get_identities(RootIdentity *rootidentity, void *context)
{
    if (!rootidentity)
        return 0;

    printf("RootIdentity: %s\n", RootIdentity_GetId(rootidentity));
    return 0;
}

void listRootIdentity(DIDStore *store)
{
    if (DIDStore_ListRootIdentities(store, get_identities, NULL) == -1)
        printf("listRootIdentity failed.\n");
}

void createDid(RootIdentity *identity)
{
    DIDDocument *doc;
    DID *did;
    char id[ELA_MAX_DID_LEN] = {0};
    int rc;

    doc = RootIdentity_NewDID(rootidentity, STORE_PASS, NULL, false);
    if (!doc) {
        printf("createDid failed.\n");
        return;
    }

    did = DIDDocument_GetSubject(doc);
    if (!did) {
        DIDDocument_Destroy(doc);
        printf("createDid failed.\n");
        return;
    }

    printf("Created DID: \n", DID_ToString(did, id, sizeof(id)));

    rc = DIDDocument_PublishDID(doc, NULL, false, STORE_PASS);
    DIDDocument_Destroy(doc);
    if (rc != 1)
        printf("createDid failed.\n");
    else
        printf("Published DID: %s\n", id);
}

void createDidByIndex(RootIdentity *identity, int index)
{
    DIDDocument *doc;
    DID *did;
    char id[ELA_MAX_DID_LEN] = {0};
    int rc;

    doc = RootIdentity_NewDIDByIndex(rootidentity, index, STORE_PASS, NULL, false);
    if (!doc) {
        printf("createDidByIndex failed.\n");
        return;
    }

    did = DIDDocument_GetSubject(doc);
    if (!did) {
        DIDDocument_Destroy(doc);
        printf("createDidByIndex failed.\n");
        return;
    }

    printf("Created DID: \n", DID_ToString(did, id, sizeof(id)));

    rc = DIDDocument_PublishDID(doc, NULL, false, STORE_PASS);
    DIDDocument_Destroy(doc);
    if (rc != 1)
        printf("createDidByIndex failed.\n");
    else
        printf("Published DID: %s\n", id);
}

void createAnotherStoreAndSyncRootIdentity()
{
    RootIdentity *id;

    const char *storePath = "/tmp/RootIdentitySample_new.store";
    deletefile(storePath);

    DIDStore *newStore = DIDStore_Open(storePath);
    if (!newStore) {
        printf("createAnotherStoreAndSyncRootIdentity failed.\n");
        return;
    }

    // Re-create the root identity with user's mnemonic.
    id = RootIdentity_Create(mnemonic, NULL, newStore, STORE_PASS);
    Mnemonic_Free(mnemonic);
    if (!id) {
        DIDStore_Close(newStore);
        printf("createAnotherStoreAndSyncRootIdentity failed.\n");
        return;
    }

    // Synchronize the existing(published) DIDs that created by this identity
    RootIdentity_Synchronize(id);
    // now the new store has the same contexts with the previous sample store

    DIDStore_Close(newStore);
}

void initRootIdentity(void)
{
    RootIdentity *identity;
    const char *mnemonic;

    if (AssistAdapter_Init("mainnet") == -1) {
        printf("initRootIdentity failed.\n");
        return;
    }

    // Location to your DIDStore
    const char* storePath = "/tmp/RootIdentitySample.store";
    store = DIDStore_Open(storePath);
    if (!store) {
        printf("initRootIdentity failed.\n");
        return;
    }

    // Create a mnemonic use default language(English).
    mnemonic = Mnemonic_Generate("english");
    if (!mnemonic) {
        DIDStore_Close(store);
        printf("initRootIdentity failed.\n");
        return;
    }
    printf("Please write down your mnemonic:\n  %s\n", mnemonic);

    // Initialize the root identity.
    identity = RootIdentity_Create(mnemonic, NULL, store, STORE_PASS);
    if (!identity) {
        DIDStore_Close(store);
        printf("initRootIdentity failed.\n");
        return;
    }

    // The new created root identities in the store
    listRootIdentity(store);

    // Create DID using next available index
    createDid(identity);

    // Create DID with specified index
    createDidByIndex(identity, 1234);

    DIDStore_Close(store);

    // you can do this on the other device restore same identity and store
    createAnotherStoreAndSyncRootIdentity(mnemonic);
    Mnemonic_Free(mnemonic);
}
