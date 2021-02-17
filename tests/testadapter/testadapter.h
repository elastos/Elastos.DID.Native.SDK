#ifndef __TEST_DID_ADAPTER_H__
#define __TEST_DID_ADAPTER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "ela_did.h"

typedef const char* (GetPasswordCallback)(const char *walletDir, const char *walletId);

bool TestDIDAdapter_CreateIdTransaction(const char *payload, const char *memo);

int TestDIDAdapter_Init(const char *walletDir, const char *walletId,
        const char *network, GetPasswordCallback *callback);

void TestDIDAdapter_Cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __TEST_DID_ADAPTER_H__ */