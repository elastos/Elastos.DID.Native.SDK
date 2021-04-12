#ifndef __TEST_DID_ADAPTER_H__
#define __TEST_DID_ADAPTER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "ela_did.h"

bool TestDIDAdapter_CreateIdTransaction(const char *payload, const char *memo);

#ifdef __cplusplus
}
#endif

#endif /* __TEST_DID_ADAPTER_H__ */