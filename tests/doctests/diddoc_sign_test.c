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
#include "did.h"
#include "diddocument.h"

static void test_diddoc_sign_verify(void)
{
    DIDDocument *document;
    DIDURL *keyid;
    uint8_t data[124], digest[32];
    char signature[MAX_SIGNATURE_LEN * 2 + 16];
    int i, j;

    DataParam params[] = {
        { 0, "document", NULL, NULL },    { 1, "user1", NULL, NULL },
        { 2, "user1", NULL, NULL }
    };

    for (j = 0; j < 3; j++) {
        document = TestData_GetDocument(params[j].did, params[j].type, params[j].version);
        CU_ASSERT_PTR_NOT_NULL(document);

        keyid = DIDDocument_GetDefaultPublicKey(document);
        CU_ASSERT_PTR_NOT_NULL(keyid);

        for (i = 0; i < 10; i++) {
            memset(data, i, sizeof(data));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_Sign(document, keyid, storepass, signature, 1, data, sizeof(data)));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_Verify(document, keyid, signature, 1, data, sizeof(data)));
            data[0] = 0xFF;
            CU_ASSERT_EQUAL(-1, DIDDocument_Verify(document, keyid, signature, 1, data, sizeof(data)));

            memset(digest, i, sizeof(digest));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignDigest(document, keyid, storepass, signature, digest, sizeof(digest)));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_VerifyDigest(document, keyid, signature, digest, sizeof(digest)));
            digest[0] = 0xFF;
            CU_ASSERT_EQUAL(-1, DIDDocument_VerifyDigest(document, keyid, signature, digest, sizeof(digest)));
        }
    }
}

static void test_ctmdoc_sign_verify(void)
{
    DIDDocument *document, *user1_doc;
    DIDURL *keyid1, keyid2, *keyid;
    uint8_t data[124], digest[32];
    char signature[MAX_SIGNATURE_LEN * 2 + 16];
    int i, j;

    user1_doc = TestData_GetDocument("user1", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(user1_doc);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, 2));

    document = TestData_GetDocument("foobar", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(document);

    keyid1 = DIDDocument_GetDefaultPublicKey(document);
    CU_ASSERT_PTR_NOT_NULL(keyid1);

    Init_DIDURL(&keyid2, &document->did, "key2");

    for (j = 0; j < 2; j++) {
        if (j == 1)
            keyid = &keyid2;

        for (i = 0; i < 10; i++) {
            memset(data, i, sizeof(data));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_Sign(document, keyid1, storepass, signature, 1, data, sizeof(data)));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_Verify(document, keyid1, signature, 1, data, sizeof(data)));
            data[0] = 0xFF;
            CU_ASSERT_EQUAL(-1, DIDDocument_Verify(document, keyid1, signature, 1, data, sizeof(data)));

            memset(digest, i, sizeof(digest));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignDigest(document, keyid, storepass, signature, digest, sizeof(digest)));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_VerifyDigest(document, keyid, signature, digest, sizeof(digest)));
            digest[0] = 0xFF;
            CU_ASSERT_EQUAL(-1, DIDDocument_VerifyDigest(document, keyid, signature, digest, sizeof(digest)));
        }
    }
}

static void test_diddoc_derive_fromidentifier(void)
{
    DIDDocument *doc;
    HDKey *hdkey, _hdkey;
    uint8_t binkey[EXTENDEDKEY_BYTES], sk[PRIVATEKEY_BYTES];
    int i;

    const char *identifier = "org.elastos.did.test";

    doc = TestData_GetDocument("user1", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(doc);

    for (i = -100; i < 100; i++) {
        //derive by identifier
        const char *strkey = DIDDocument_DeriveByIdentifier(doc, identifier, i, storepass);
        CU_ASSERT_PTR_NOT_NULL_FATAL(strkey);

        hdkey = HDKey_DeserializeBase58(&_hdkey, strkey, strlen(strkey) + 1);
        size_t size = b58_decode(binkey, sizeof(binkey), strkey);
        free((void*)strkey);
        CU_ASSERT_PTR_NOT_NULL_FATAL(hdkey);
        CU_ASSERT_EQUAL(size, EXTENDEDKEY_BYTES);

        memcpy(sk, binkey + 46, PRIVATEKEY_BYTES);
        memset(binkey, 0, sizeof(binkey));

        uint8_t *key = HDKey_GetPrivateKey(hdkey);
        for (int j = 0; j < PRIVATEKEY_BYTES; j++)
            CU_ASSERT_EQUAL(sk[j], key[j]);

        memset(sk, 0, sizeof(sk));

        //derive by index
        if (i >= 0) {
            strkey = DIDDocument_DeriveByIndex(doc, i, storepass);
            CU_ASSERT_PTR_NOT_NULL_FATAL(strkey);

            hdkey = HDKey_DeserializeBase58(&_hdkey, strkey, strlen(strkey) + 1);
            size_t size = b58_decode(binkey, sizeof(binkey), strkey);
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

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, 2));

    doc = TestData_GetDocument("foobar", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(doc);

    CU_ASSERT_PTR_NULL(DIDDocument_DeriveByIdentifier(doc, identifier, i, storepass));
    CU_ASSERT_STRING_EQUAL("Unsupport customized did to derive.", DIDError_GetMessage());
}

static void test_diddoc_derive_compatible_withjava(void)
{
    const char *key;
    DIDDocument *document;

    const char *identifier = "org.elastos.did.test";
    const char *keybase1 = "xprvABa5HYokqCjsR5Pk9dvYLxHkYbFQtJ2rPKPjeousKdcsh87vTSFmj8KrrnQfocDYWbgXeT9c5wnBb281JxWv8X4Xm3vh5eCcRpjCuhYnY3V";   //security code: 10
    const char *keybase2 = "xprvABa5HYokqCjtBrHFbHrLFuTNowffc6YoRN6aUQdMqA5AnrrFiDF4uoxC9qH1b5a1H3WbDUWnT58tcR47TTR8V77L2vjEJTVpfwA8dVKTk3V";   //security code: 28
    const char *keybase3 = "xprvABa5HYp3WXoo6LXePBD5PxFskrNGyPhmyrxgqZzTK3Su3H2cQxNuo3sdVhB7WpJvjiEgWV9ypCcujKMSbkyrPkT54vErRAZ8XAua6124pjc";   //security code: -5
    const char *keybase4 = "xprvABa5HYp3WXomZhF8qXBSvTWooy926aiEhNZH9AEufPwAP6XT97t59P5CvyJviE9ENpGh5jF84WLhp3DHV57ZUYzucWfkHkLwrGx3izaqzEu";   //security code: -40

    document = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(document);

    key = DIDDocument_DeriveByIdentifier(document, identifier, 10, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase1);
    free((void*)key);

    key = DIDDocument_DeriveByIdentifier(document, identifier, 28, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase2);
    free((void*)key);

    key = DIDDocument_DeriveByIdentifier(document, identifier, -5, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase3);
    free((void*)key);

    key = DIDDocument_DeriveByIdentifier(document, identifier, -40, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase4);
    free((void*)key);
}

static int diddoc_sign_test_suite_init(void)
{
    DIDStore *store = TestData_SetupStore(true);
    if (!store)
        return -1;

    return 0;
}

static int diddoc_sign_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    {   "test_diddoc_sign_verify",                test_diddoc_sign_verify                },
    {   "test_ctmdoc_sign_verify",                test_ctmdoc_sign_verify                },
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