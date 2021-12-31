#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "common.h"
#include "samples.h"

static int get_did(DID *did, void *context)
{
    char id[ELA_MAX_DID_LEN] = {0};

    int *count = (int*)context;

    if (!did)
        return 0;

    printf("%s\n", DID_ToSting(did, id, sizeof(id)));
    (*count)++;
    return 0;
}

void restoreFromMnemonic(void)
{
    const char *mnemonic = "advance duty suspect finish space matter squeeze elephant twenty over stick shield";
    const char *passphrase = "secret";
    const char *storepass = "passwd";
    int count = 0;

    // Initializa the DID backend globally.
    if (AssistAdapter_Init("mainnet") == -1) {
        printf("restoreFromMnemonic failed.\n");
        return;
    }

    const char *storePath = "/tmp/RestoreFromMnemonic.store";
    delete_file(storePath);

    DIDStore *store = DIDStore_Open(storePath);
    if (!store) {
        printf("restoreFromMnemonic failed.\n");
        return;
    }

    RootIdentity *identity = RootIdentity_Create(mnemonic, passphrase,
            false, store, storepass);
    if (!identity) {
        DIDStore_close(store);
        printf("restoreFromMnemonic failed.\n");
        return;
    }

    printf("Synchronize begin....");
    RootIdentity_Synchronize(identity, NULL);
    printf("Synchronize finish.");

    if (DIDStore_ListDIDs(store, 1, get_did, (void*)&count) == -1) {
        RootIdentity_Destroy(identity);
        DIDStore_close(store);
        printf("restoreFromMnemonic failed.\n");
        return;
    }

    if (count == 0)
        printf("No dids restored.");

    DIDStore_close(store);
}
