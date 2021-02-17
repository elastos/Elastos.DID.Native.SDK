#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "spvadapter.h"
#include "testadapter.h"

static SpvDidAdapter *gSpvAdapter;
static GetPasswordCallback *gPasswordCallback;
static char *gWalletDir;
static char *gWalletId;

bool TestDIDAdapter_CreateIdTransaction(const char *payload, const char *memo)
{
    const char *password;

    if (!payload)
        return false;

    password = gPasswordCallback((const char *)gWalletDir, (const char *)gWalletId);

    printf("Waiting for wallet available");
    while (true) {
        if (SpvDidAdapter_IsAvailable(gSpvAdapter)) {
            printf(" OK\n");
            break;
        } else {
            printf(".");
            sleep(30);
        }
    }

    return SpvDidAdapter_CreateIdTransaction(gSpvAdapter, payload, memo, password);
}

int TestDIDAdapter_Init(const char *walletDir, const char *walletId,
        const char *network, GetPasswordCallback *callback)
{
    const char *password;

    if (!walletDir || !walletId || !callback)
        return -1;

    gSpvAdapter = SpvDidAdapter_Create(walletDir, walletId, network);
    if (!gSpvAdapter)
        return -1;

    gPasswordCallback = callback;
    gWalletDir = strdup(walletDir);
    gWalletId = strdup(walletId);
    return 0;
}

void TestDIDAdapter_Cleanup(void)
{
    gSpvAdapter = NULL;
    gPasswordCallback = NULL;

    if (gWalletDir) {
        free((void*)gWalletDir);
        gWalletDir = NULL;
    }

    if (gWalletId) {
        free((void*)gWalletId);
        gWalletId = NULL;
    }
}


