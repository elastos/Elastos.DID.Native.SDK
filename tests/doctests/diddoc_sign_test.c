#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <crystal.h>
#include <CUnit/Basic.h>
#include <limits.h>
#include <crystal.h>

#include "constant.h"
#include "loader.h"
#include "ela_did.h"
#include "HDkey.h"
#include "crypto.h"

#define SIGNATURE_BYTES         64

static DIDDocument *document;
static DIDURL *keyid;
static DIDStore *store;

static void test_diddoc_sign_verify(void)
{
    uint8_t data[124];
    char signature[SIGNATURE_BYTES * 2 + 16];
    int rc, i;

    for (i = 0; i < 10; i++) {
        memset(data, i, sizeof(data));

        rc = DIDDocument_Sign(document, keyid, storepass, signature, 1, data, sizeof(data));
        CU_ASSERT_NOT_EQUAL(rc, -1);

        rc = DIDDocument_Verify(document, keyid, signature, 1, data, sizeof(data));
        CU_ASSERT_NOT_EQUAL(rc, -1);

        data[0] = 0xFF;
        rc = DIDDocument_Verify(document, keyid, signature, 1, data, sizeof(data));
        CU_ASSERT_EQUAL(rc, -1);
    }
}

static void test_diddoc_digest_sign_verify(void)
{
    uint8_t digest[32];
    char signature[SIGNATURE_BYTES * 2 + 16];
    int rc, i;

    for (i = 0; i < 10; i++) {
        memset(digest, i, sizeof(digest));

        rc = DIDDocument_SignDigest(document, keyid, storepass, signature, digest, sizeof(digest));
        CU_ASSERT_NOT_EQUAL(rc, -1);

        rc = DIDDocument_VerifyDigest(document, keyid, signature, digest, sizeof(digest));
        CU_ASSERT_NOT_EQUAL(rc, -1);

        digest[0] = 0xFF;
        rc = DIDDocument_VerifyDigest(document, keyid, signature, digest, sizeof(digest));
        CU_ASSERT_EQUAL(rc, -1);
    }
}

static void test_diddoc_derive_fromidentifier(void)
{
    HDKey *hdkey, _hdkey;
    uint8_t binkey[EXTENDEDKEY_BYTES], sk[PRIVATEKEY_BYTES];

    const char *identifier = "org.elastos.did.test";

    for (int i = -100; i < 100; i++) {
        const char *strkey = DIDDocument_Derive(document, identifier, i, storepass);
        CU_ASSERT_PTR_NOT_NULL_FATAL(strkey);

        hdkey = HDKey_DeserializeBase58(&_hdkey, strkey, strlen(strkey) + 1);
        size_t size = base58_decode(binkey, sizeof(binkey), strkey);
        free((void*)strkey);
        CU_ASSERT_PTR_NOT_NULL_FATAL(hdkey);
        CU_ASSERT_EQUAL(size, EXTENDEDKEY_BYTES);

        memcpy(sk, binkey + 46, PRIVATEKEY_BYTES);
        memset(binkey, 0, sizeof(binkey));

        uint8_t *key = HDKey_GetPrivateKey(hdkey);
        for (int j = 0; j < PRIVATEKEY_BYTES; j++)
            CU_ASSERT_EQUAL(sk[j], key[j]);

        memset(sk, 0, sizeof(sk));
    }
}

static void test_diddoc_derive_compatible_withjava(void)
{
    const char *key;
    uint8_t binkey[EXTENDEDKEY_BYTES];

    const char *identifier = "org.elastos.did.test";
    const char *keybase1 = "xprvABa5HYokqCjsR5Pk9dvYLxHkYbFQtJ2rPKPjeousKdcsh87vTSFmj8KrrnQfocDYWbgXeT9c5wnBb281JxWv8X4Xm3vh5eCcRpjCuhYnY3V";   //security code: 10
    const char *keybase2 = "xprvABa5HYokqCjtBrHFbHrLFuTNowffc6YoRN6aUQdMqA5AnrrFiDF4uoxC9qH1b5a1H3WbDUWnT58tcR47TTR8V77L2vjEJTVpfwA8dVKTk3V";   //security code: 28
    const char *keybase3 = "xprvABa5HYp3WXoo6LXePBD5PxFskrNGyPhmyrxgqZzTK3Su3H2cQxNuo3sdVhB7WpJvjiEgWV9ypCcujKMSbkyrPkT54vErRAZ8XAua6124pjc";   //security code: -5
    const char *keybase4 = "xprvABa5HYp3WXomZhF8qXBSvTWooy926aiEhNZH9AEufPwAP6XT97t59P5CvyJviE9ENpGh5jF84WLhp3DHV57ZUYzucWfkHkLwrGx3izaqzEu";   //security code: -40

    key = DIDDocument_Derive(document, identifier, 10, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase1);
    free((void*)key);

    key = DIDDocument_Derive(document, identifier, 28, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase2);
    free((void*)key);

    key = DIDDocument_Derive(document, identifier, -5, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase3);
    free((void*)key);

    key = DIDDocument_Derive(document, identifier, -40, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase4);
    free((void*)key);
}

static int diddoc_sign_test_suite_init(void)
{
    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    document = TestData_LoadDoc();
    if (!document) {
        TestData_Free();
        return -1;
    }

    keyid = DIDDocument_GetDefaultPublicKey(document);
    if (!keyid) {
        TestData_Free();
        return -1;
    }

    return 0;
}

static int diddoc_sign_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    {   "test_diddoc_sign_verify",                test_diddoc_sign_verify                },
    {   "test_diddoc_digest_sign_verify",         test_diddoc_digest_sign_verify         },
    {   "test_diddoc_derive_fromidentifier",      test_diddoc_derive_fromidentifier      },
    {   "test_diddoc_derive_compatible_withjava", test_diddoc_derive_compatible_withjava },
    {   NULL,                                     NULL                                   }
};

static CU_SuiteInfo suite[] = {
    { "diddoc sign test",  diddoc_sign_test_suite_init,  diddoc_sign_test_suite_cleanup, NULL, NULL, cases },
    {    NULL,             NULL,                         NULL,                           NULL, NULL, NULL  }
};

CU_SuiteInfo* diddoc_sign_test_suite_info(void)
{
    return suite;
}