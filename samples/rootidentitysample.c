#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "samples.h"
#include "common.h"
#include "assistadapter.h"

static const char *STORE_PASS = "secret";

static int get_identities(RootIdentity *rootidentity, void *context)
{
    if (!rootidentity)
        return 0;

    printf("RootIdentity: %s\n", RootIdentity_GetId(rootidentity));
    return 0;
}

void list_rootidentity(DIDStore *store)
{
    if (DIDStore_ListRootIdentities(store, get_identities, NULL) == -1)
        printf("[error] list_rootidentity failed.\n");
}

void create_did(RootIdentity *identity)
{
    DIDDocument *doc;
    DID *did;
    char id[ELA_MAX_DID_LEN] = {0};
    int rc;

    doc = RootIdentity_NewDID(identity, STORE_PASS, NULL, false);
    if (!doc) {
        printf("[error] create_did failed.\n");
        return;
    }

    did = DIDDocument_GetSubject(doc);
    if (!did) {
        DIDDocument_Destroy(doc);
        printf("[error] create_did failed.\n");
        return;
    }

    printf("Created DID: %s\n", DID_ToString(did, id, sizeof(id)));

    rc = DIDDocument_PublishDID(doc, NULL, false, STORE_PASS);
    DIDDocument_Destroy(doc);
    if (rc != 1)
        printf("[error] create_did failed.\n");
    else
        printf("Published DID: %s\n", id);
}

void create_did_by_index(RootIdentity *identity, int index)
{
    DIDDocument *doc;
    DID *did;
    char id[ELA_MAX_DID_LEN] = {0};
    int rc;

    doc = RootIdentity_NewDIDByIndex(identity, index, STORE_PASS, NULL, false);
    if (!doc) {
        printf("[error] create_did_by_index failed.\n");
        return;
    }

    did = DIDDocument_GetSubject(doc);
    if (!did) {
        DIDDocument_Destroy(doc);
        printf("[error] create_did_by_index failed.\n");
        return;
    }

    printf("Created DID: %s\n", DID_ToString(did, id, sizeof(id)));

    rc = DIDDocument_PublishDID(doc, NULL, false, STORE_PASS);
    DIDDocument_Destroy(doc);
    if (rc != 1)
        printf("[error] create_did_by_index failed.\n");
    else
        printf("Published DID: %s\n", id);
}

void create_another_store_and_sync_rootidentity(const char *mnemonic)
{
    RootIdentity *id;

    const char *storePath = "/tmp/RootIdentitySample_new.store";
    delete_file(storePath);

    DIDStore *newStore = DIDStore_Open(storePath);
    if (!newStore) {
        printf("[error] create_another_store_and_sync_rootidentity failed.\n");
        return;
    }

    // Re-create the root identity with user's mnemonic.
    id = RootIdentity_Create(mnemonic, NULL, false, newStore, STORE_PASS);
    if (!id) {
        DIDStore_Close(newStore);
        printf("[error] create_another_store_and_sync_rootidentity failed.\n");
        return;
    }

    // Synchronize the existing(published) DIDs that created by this identity
    RootIdentity_Synchronize(id, NULL);
    // now the new store has the same contexts with the previous sample store

    DIDStore_Close(newStore);
}

void InitRootIdentity(void)
{
    RootIdentity *identity;
    const char *mnemonic;
    DIDStore *store;

    printf("-----------------------------------------\nBeginning, initialize root identity ...\n");

    if (AssistAdapter_Init("mainnet") == -1) {
        printf("[error] InitRootIdentity failed.\n");
        return;
    }

    // Location to your DIDStore
    const char* storePath = "/tmp/RootIdentitySample.store";
    store = DIDStore_Open(storePath);
    if (!store) {
        printf("[error] InitRootIdentity failed.\n");
        return;
    }

    // Create a mnemonic use default language(English).
    mnemonic = Mnemonic_Generate("english");
    if (!mnemonic) {
        DIDStore_Close(store);
        printf("[error] InitRootIdentity failed.\n");
        return;
    }
    printf("Please write down your mnemonic:\n  %s\n", mnemonic);

    // Initialize the root identity.
    identity = RootIdentity_Create(mnemonic, NULL, false, store, STORE_PASS);
    if (!identity) {
        DIDStore_Close(store);
        printf("[error] InitRootIdentity failed.\n");
        return;
    }

    // The new created root identities in the store
    list_rootidentity(store);

    // Create DID using next available index
    create_did(identity);

    // Create DID with specified index
    create_did_by_index(identity, 1234);

    // you can do this on the other device restore same identity and store
    create_another_store_and_sync_rootidentity(mnemonic);

    DIDStore_Close(store);
    Mnemonic_Free((void*)mnemonic);
    RootIdentity_Destroy(identity);
    printf("Initialize rootidentity, end.\n");
}
