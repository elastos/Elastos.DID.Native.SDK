#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "samples.h"
#include "assistadapter.h"

static const char *passphrase = "mypassphrase";
static const char *storepass = "mypassword";
static DIDStore *store;

typedef struct List_Helper {
    DIDStore *store;
    DID *did;
} List_Helper;

static void init_identity()
{
    RootIdentity *identity;
    // Check the store whether contains the root private identity.
    if (DIDStore_ContainsRootIdentities(store) == 1)
        return; // Already exists

    // Create a mnemonic use default language(English).
    const char *mnemonic = Mnemonic_Generate("english");
    if (!mnemonic){
        printf("[error] initRootIdentity failed.\n");
        return;
    }

    printf("Please write down your mnemonic and passwords:\n");
    printf("  Mnemonic: %s\n", mnemonic);
    printf("  Mnemonic passphrase: %s\n", passphrase);
    printf("  Store password: %s\n", storepass);

    // Initialize the root identity.
    identity = RootIdentity_Create(mnemonic, passphrase, false, store, storepass);
    Mnemonic_Free((void*)mnemonic);
    if (!identity) {
        printf("[error] initRootIdentity failed.\n");
        return;
    }
    RootIdentity_Destroy(identity);
}

static int get_did(DID *did, void *context)
{
    List_Helper *helper = (List_Helper*)context;
    char id[ELA_MAX_DID_LEN];

    if (!did)
        return 0;

    DIDDocument *doc = DIDStore_LoadDID(helper->store, did);
    if (!doc)
        return 0;

    const char *alias = DIDMetadata_GetAlias(DIDDocument_GetMetadata(doc));
    if (alias && !strcmp(alias, "me")) {
        if (helper->did)
            DID_Destroy(helper->did);

        DID_ToString(did, id, sizeof(id));
        helper->did = DID_FromString(id);
    }

    DIDDocument_Destroy(doc);
    return 0;
}

static void init_did()
{
    const char *id;
    RootIdentity *identity;
    DIDDocument *doc;
    DID *did;
    char idstring[ELA_MAX_DID_LEN];
    int rc;

    List_Helper helper;
    helper.store = store;
    helper.did = NULL;

    if (DIDStore_ListDIDs(store, 1, get_did, (void*)&helper) == -1) {
        printf("[error] init did failed.\n");
        return;
    }

    if (helper.did) {
        DID_Destroy(helper.did);
        return;    // Already create my DID.
    }

    id = DIDStore_GetDefaultRootIdentity(store);
    if (!id) {
        printf("[error] init did failed.\n");
        return;
    }

    identity = DIDStore_LoadRootIdentity(store, id);
    free((void*)id);
    if (!identity) {
        printf("[error] init did failed.\n");
        return;
    }

    doc = RootIdentity_NewDID(identity, storepass, "me", false);
    RootIdentity_Destroy(identity);
    if (!doc) {
        printf("[error] init did failed.\n");
        return;
    }

    did = DIDDocument_GetSubject(doc);

    printf("My new DID created: %s\n", DID_ToString(did, idstring, sizeof(idstring)));
    rc = DIDDocument_PublishDID(doc, NULL, false, storepass);
    DIDDocument_Destroy(doc);
    if (rc != 1)
        printf("[error] init did failed.\n");

    return;
}

void InitalizeDid(void)
{
    const char *storePath = "/tmp/InitializeDID.store";

    printf("\n-----------------------------------------\nBeginning, initialize did ...\n");

    if (AssistAdapter_Init("mainnet") == -1) {
        printf("[error] InitalizeDid failed.\n");
        return;
    }

    store = DIDStore_Open(storePath);
    if (!store) {
        printf("[error] InitalizeDid failed.\n");
        return;
    }

    init_identity();
    init_did();

    DIDStore_Close(store);

    printf("Initialize did, end.\n");
}
