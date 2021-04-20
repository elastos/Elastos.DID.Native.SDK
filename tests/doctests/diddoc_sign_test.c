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
    DIDURL *keyid1, keyid2;
    uint8_t data[124];
    char signature[MAX_SIGNATURE_LEN * 2 + 16];
    int i, j;

    user1_doc = TestData_GetDocument("user1", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(user1_doc);

    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user2", NULL, 2));
    CU_ASSERT_PTR_NOT_NULL(TestData_GetDocument("user3", NULL, 2));

    document = TestData_GetDocument("foobar", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(document);

    keyid1 = DIDDocument_GetDefaultPublicKey(user1_doc);
    CU_ASSERT_PTR_NOT_NULL(keyid1);

    DIDURL_Init(&keyid2, &document->did, "key2");

    for (j = 0; j < 2; j++) {
        for (i = 0; i < 10; i++) {
            memset(data, i, sizeof(data));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_Sign(document, keyid1, storepass, signature, 1, data, sizeof(data)));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_Verify(document, keyid1, signature, 1, data, sizeof(data)));
            data[0] = 0xFF;
            CU_ASSERT_EQUAL(-1, DIDDocument_Verify(document, keyid1, signature, 1, data, sizeof(data)));

            memset(data, i, sizeof(data));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_Sign(document, &keyid2, storepass, signature, 1, data, sizeof(data)));
            CU_ASSERT_NOT_EQUAL(-1, DIDDocument_Verify(document, &keyid2, signature, 1, data, sizeof(data)));
            data[0] = 0xFF;
            CU_ASSERT_EQUAL(-1, DIDDocument_Verify(document, &keyid2, signature, 1, data, sizeof(data)));
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

    const char *keys[10] = {
        "xprvA5h72rSp6gmMZKBVUsMoBVcWq4sR6z1Nn2PTzjG17pFrHz9vniDVX1v2TthxpbSMaNoWXxZgX3srDzJEMQ7LYvwK6zvtQmCfhSUR51S55vU",
        "xprvA5h72rSp6gmMcCdrFg6wC6gdEeiFy4YR9tsqPMqcBweuLUxD7KbBTHztJqZg8WgRSESD4gLTs78GguXKM2aX2CzxgpBdKNa11VpkDZtNUmh",
        "xprvA5h72rSp6gmMeMdinKY2rCFcnx27Fxfc6cF4Pkr6rPwEVPQ2eJLQsZMQY1STLFwCVj7qFqWRK6xBN2rbBAcULtJCqxLejndHBwDPWfQgQyq",
        "xprvA5h72rSp6gmMhnm3qS4GDkbrCmWgHNCX5ztxG9scLiCs1un3FhGVLFJRxNej5CC2Fv6TbxYvBfCdVPZX9gvQGuuT8U4ZvLZhF2wXzYJ1DMR",
        "xprvA5h72rSp6gmMmAqZcnuZ6Vr9Q4QSFZ6cHmqpJ8TRhd1MLAAiRURj9ZTAPnAWRHNdEvBNpWXB8wo3KA7PMuRHkxCFndaQ7pdKCDFJbxX7riL",
        "xprvA5h72rSp6gmMob1cUea7VsoyLBgwJYGg4kD62cPeJrz4paRY91JvG1sixsSi8yUZRBbF9bBzQD6RiHvdu3w99i8yWgQ6gr14ttLm5uYLJtW",
        "xprvA5h72rSp6gmMq7PSS826cUqJcgaixD9RePBdnv9WhUVeMv3K9cFKrtSwdpFAsvxozf1d8VcsffCT4FD37LanFB58Z7ofQuxPcCvvW5GMbcW",
        "xprvA5h72rSp6gmMsq6ZC4DvQvbHMMZ4cFcdvq7VLFuFGWaiVwPsAQRmPfJMGDhRrQkhwANc4ug95tEz4eBxusGo9TJFmaWqt3n3hzX7r29EznF",
        "xprvA5h72rSp6gmMwRq8b3kJejTEyXxkLG7mYFPPta1ouzphnZEs4ZX2kztRsywthHuDuFnsse3j7Dvrgpa9uGDfm6jPTrGXJoLY9Rykdc7rJpC",
        "xprvA5h72rSp6gmMyjiSoFiaVagDaa48iuzrUkwDCuxJ3nZXFLU2z4kEcA9tfReqeLM4QRrQ5JdzcnKjN9UGSFN2ChUN7yb7H3B46kuzgqYidPq"
    };

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
        if (i >= 0 && i <= 9) {
            const char *strkey = DIDDocument_DeriveByIndex(doc, i, storepass);
            CU_ASSERT_PTR_NOT_NULL_FATAL(strkey);
            CU_ASSERT_STRING_EQUAL(strkey, keys[i]);

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
    CU_ASSERT_STRING_EQUAL("Unsupport customized did to derive.", DIDError_GetLastErrorMessage());
}

static void test_diddoc_derive_compatible_withjava(void)
{
    const char *key;
    DIDDocument *document;

    const char *identifier = "org.elastos.did.test";
    const char *keybase1 = "xprvAKXRwZER2Fdm8rbtTUMx4BpFVVP99WYsfj23pqcSabgX7QaaV8dgHCXJUaVuywnF69SmzUrYeCxKiQEPZZ6dxs8nzNsqq5GLQs1HZVL5YRH";   //security code: 15
    const char *keybase2 = "xprvAKXRwZER2Fdn4oDevwVqB7UR7Y5BCnyRT1fjDoWmVp26Smo8Uk5fyg4qwANVN6siPM1RLovziJPMiHXtivCVdaoQwkB9mJECrMag2SjRD2r";   //security code: 36
    const char *keybase3 = "xprvAKXRwZER2FdsQ24vk3pTiSLvf2R5SiPk6xCEGJ2vXwDxtKqgrnvo3xh92QpQhz51CtpS8NsPA5CCUrMEnLMWosSu8jg2DzdKiozpxtssUcf";   //security code: 158
    const char *keybase4 = "xprvAKXRwZER2FduCMn9e4NHcYS65mRyQqZXFTkoXdDochQGhyHRsfjKxNZBrHCJFnSRAEh4kbi7i4pWMptu3dnJhykCSCKgYXBBW4X7Bop6mhK";   //security code: 199

    document = TestData_GetDocument("user1", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(document);

    key = DIDDocument_DeriveByIdentifier(document, identifier, 15, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase1);
    free((void*)key);

    key = DIDDocument_DeriveByIdentifier(document, identifier, 36, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase2);
    free((void*)key);

    key = DIDDocument_DeriveByIdentifier(document, identifier, 158, storepass);
    CU_ASSERT_STRING_EQUAL(key, keybase3);
    free((void*)key);

    key = DIDDocument_DeriveByIdentifier(document, identifier, 199, storepass);
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