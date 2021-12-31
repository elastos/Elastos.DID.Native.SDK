#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "samples.h"

static const char *passphrase = "mypassphrase";
static const char *storepass = "mypassword";
static DIDStore *store;

typedef struct List_Helper {
    DIDStore *store;
    DID did;
} List_Helper;

static void initRootIdentity()
{
    RootIdentity *identity;
    // Check the store whether contains the root private identity.
    if (DIDStore_ContainsRootIdentities(store) != 1) {
        printf("initRootIdentity failed.\n");
        return; // Already exists
    }

    // Create a mnemonic use default language(English).
    const char *mnemonic = Mnemonic_Generate("english");
    if (!mnemonic){
        printf("initRootIdentity failed.\n");
        return;
    }

    printf("Please write down your mnemonic and passwords:\n");
    printf("  Mnemonic: %s\n", mnemonic);
    printf("  Mnemonic passphrase: %s\n", passphrase);
    printf("  Store password: %s\n", storepass);

    // Initialize the root identity.
    identity = RootIdentity_Create(mnemonic, passphrase, false, store, storepass);
    Mnemonic_Free(mnemonic);
    if (!identity) {
        printf("initRootIdentity failed.\n");
        return;
    }
    RootIdentity_Destroy(identity);
}

static int get_did(DID *did, void *context)
{
    List_Helper *helper = (List_Helper*)context;

    if (!did)
        return 0;

    DIDDocument *doc = DIDStore_LoadDid(helper->store, did);
    if (!doc)
        return 0;

    const char *alias = DIDMetadata_GetAlias(&doc->metadata);
    if (alias && !strcmp(alias, "me"))
        DID_Copy(&helper->did, &doc->did);

    DIDDocument_Destroy(doc);
    return 0;
}

static int init_did()
{
    const char *id;
    RootIdentity *identity;
    DIDDocument *doc;
    int rc;

    List_Helper helper;
    helper->store = store;
    memset(&helper->did, 0, sizeof(DID));

    if (DIDStore_ListDIDs(store, 1, get_did, (void*)&helper) == -1)
        return -1;

    if (helper->did)
        return 0;    // Already create my DID.

    id = DIDStore_GetDefaultRootIdentity(entity->store);
    if (!id)
        return -1;

    identity = DIDStore_LoadRootIdentity(entity->store, id);
    free((void*)id);
    if (!identity)
        return -1;

    doc = RootIdentity_NewDID(identity, entity->storepass, "me", false);
    RootIdentity_Destroy(identity);
    if (!doc)
        return -1;

    printf("My new DID created: %s\n", &doc->did);
    rc = DIDDocument_PublishDID(doc, NULL, false, entity->storepass);
    DIDDocument_Destroy(doc);
    return rc;
}

void initDid(void)
{
    const char *storePath = "/tmp/InitializeDID.store";

    if (AssistDIDAdapter_Init("mainnet") == -1) {
        printf("initDid failed.\n");
        return;
    }

    store = DIDStore_Open(storePath);
    if (!store) {
        printf("initDid failed.\n");
        return;
    }

    initRootIdentity();
    initDid();

    DIDStore_Close(store);
}
