#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
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

void check_with_ciphers(Cipher *cipher, Cipher *cipher2) {
    const char sourceStr1[] = "This is the string 1 for encrypting.";
    const char sourceStr2[] = "This is the string 2 for encrypting.";
    const char sourceStr3[] = "This is the string 3 for encrypting.";
    const unsigned char nonce[] = "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57";

    printf("a1\n");

    unsigned char *cipherText1, *cipherText2, *cipherText3, *clearText1, *clearText2, *clearText3, *header;
    unsigned int cipherTextLen1, cipherTextLen2, cipherTextLen3, clearTextLen1, clearTextLen2, clearTextLen3, headerLen;
    Cipher_EncryptionStream *encryptionStream;
    Cipher_DecryptionStream *decryptionStream;

    printf("a2\n");

    // message
    cipherText1 = Cipher_Encrypt(cipher, (const unsigned char *)sourceStr1, strlen(sourceStr1), nonce, &cipherTextLen1);
    CU_ASSERT_PTR_NOT_NULL(cipherText1);
    clearText1 = Cipher_Decrypt(cipher2, (const unsigned char *)cipherText1, cipherTextLen1, nonce, &clearTextLen1);
    CU_ASSERT_PTR_NOT_NULL(clearText1);

    printf("a3, cipherText1=%p, error=%s\n", cipherText1, DIDError_GetLastErrorMessage());
    printf("a3, clearText1=%p, error=%s\n", clearText1, DIDError_GetLastErrorMessage());
    printf("a3, clearText1=%s, error=%s\n", clearText1, DIDError_GetLastErrorMessage());

    CU_ASSERT_STRING_EQUAL(clearText1, sourceStr1);
    free((void*)cipherText1);
    free((void*)clearText1);

    printf("a4\n");

    // stream
    encryptionStream = Cipher_EncryptionStream_Create(cipher);
    CU_ASSERT_PTR_NOT_NULL(encryptionStream);
    header = Cipher_EncryptionStream_Header(encryptionStream, &headerLen);

    printf("a5\n");

    cipherText1 = Cipher_EncryptionStream_Push(encryptionStream, (unsigned char *)sourceStr1, strlen(sourceStr1), false, &cipherTextLen1);
    CU_ASSERT_PTR_NOT_NULL(cipherText1);
    cipherText2 = Cipher_EncryptionStream_Push(encryptionStream, (unsigned char *)sourceStr2, strlen(sourceStr2), false, &cipherTextLen2);
    CU_ASSERT_PTR_NOT_NULL(cipherText2);
    cipherText3 = Cipher_EncryptionStream_Push(encryptionStream, (unsigned char *)sourceStr3, strlen(sourceStr3), true, &cipherTextLen3);
    CU_ASSERT_PTR_NOT_NULL(cipherText3);

    printf("a6\n");

    decryptionStream = Cipher_DecryptionStream_Create(cipher2, header);
    CU_ASSERT_PTR_NOT_NULL(decryptionStream);

    printf("a7\n");

    clearText1 = Cipher_DecryptionStream_Pull(decryptionStream, cipherText1, cipherTextLen1, &clearTextLen1);
    CU_ASSERT_PTR_NOT_NULL(clearText1);
    clearText2 = Cipher_DecryptionStream_Pull(decryptionStream, cipherText2, cipherTextLen2, &clearTextLen2);
    CU_ASSERT_PTR_NOT_NULL(clearText2);
    clearText3 = Cipher_DecryptionStream_Pull(decryptionStream, cipherText3, cipherTextLen3, &clearTextLen3);
    CU_ASSERT_PTR_NOT_NULL(clearText3);

    printf("a8\n");

    CU_ASSERT_STRING_EQUAL(clearText1, sourceStr1);
    CU_ASSERT_STRING_EQUAL(clearText2, sourceStr2);
    CU_ASSERT_STRING_EQUAL(clearText3, sourceStr3);

    printf("a9\n");

    CU_ASSERT_STRING_EQUAL(clearText1, sourceStr1);
    CU_ASSERT_STRING_EQUAL(clearText2, sourceStr2);
    CU_ASSERT_STRING_EQUAL(clearText3, sourceStr3);
    CU_ASSERT_TRUE(Cipher_DecryptionStream_IsComplete(decryptionStream));
    free((void*)cipherText1); free((void*)clearText1);
    free((void*)cipherText2); free((void*)clearText2);
    free((void*)cipherText3); free((void*)clearText3);

    printf("a10\n");
}

static void test_diddoc_cipher(void)
{
    DIDDocument *doc, *doc2;
    Cipher *cipher, *cipher2;

    printf("1, start.\n");

    const char *identifier = "org.elastos.did.test";
    const char publicKey[] = "\xae\xa6\xa0\xb3\x37\x31\xbd\x2b\x64\xe0\xac\xc2\x9d\xf8\xf7\x1e\xaf\xc6\x95\xd3\xb4\x31\x1f\x6b\x28\xd2\x8e\x9c\x06\x68\x4e\x79";
    const char publicKey2[] = "\xa6\xa0\x14\x4b\x0b\xdd\x65\xb0\x34\x2e\xa1\xbf\xcc\x92\xac\xae\xf0\xea\x39\xdc\x53\xd3\x3f\x3b\x36\x68\xf2\x8b\x1a\xa8\x5e\x74";

    doc = TestData_GetDocument("user1", NULL, 2);
    CU_ASSERT_PTR_NOT_NULL(doc);
    doc2 = TestData_GetDocument("user2", NULL, 3);
    CU_ASSERT_PTR_NOT_NULL(doc);

    printf("2, %p, %p\n", doc, doc2);
    printf("2, %s\n", DIDDocument_ToJson(doc, true));
    printf("2, %s\n", DIDDocument_ToJson(doc2, true));

    cipher = DIDDocument_CreateCipher(doc, identifier, 15, storepass);
    CU_ASSERT_PTR_NOT_NULL(cipher);

    printf("3, %p\n", cipher);

    check_with_ciphers(cipher, cipher);
    DIDDocument_Cipher_Destroy(cipher);

    printf("4\n");

    cipher = DIDDocument_CreateCurve25519Cipher(doc, identifier, 15, storepass, false, publicKey2);
    CU_ASSERT_PTR_NOT_NULL(cipher);
    cipher2 = DIDDocument_CreateCurve25519Cipher(doc2, identifier, 15, storepass, true, publicKey);
    CU_ASSERT_PTR_NOT_NULL(cipher);

    printf("5\n");

    check_with_ciphers(cipher, cipher2);
    DIDDocument_Cipher_Destroy(cipher);
    DIDDocument_Cipher_Destroy(cipher2);

    printf("6, end!!!\n");
}

static int diddoc_cipher_test_suite_init(void)
{
    DIDStore *store = TestData_SetupStore(true);
    if (!store)
        return -1;

    return 0;
}

static int diddoc_cipher_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
        {   "test_diddoc_cipher",                     test_diddoc_cipher                     },
        {   NULL,                                     NULL                                   }
};

static CU_SuiteInfo suite[] = {
        { "diddoc cipher test", diddoc_cipher_test_suite_init, diddoc_cipher_test_suite_cleanup, NULL, NULL, cases },
        {    NULL,              NULL,                          NULL,                             NULL, NULL, NULL  }
};

CU_SuiteInfo* diddoc_cipher_test_suite_info(void)
{
    return suite;
}
