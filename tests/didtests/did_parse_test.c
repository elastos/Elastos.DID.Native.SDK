#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <CUnit/Basic.h>
#include "ela_did.h"
#include "did.h"

typedef struct CsvSource {
    const char *spec;
    const char *methodSpecificId;
} CsvSource;

typedef struct Check {
    const char *value;
    const char *err;
} Check;

static void test_did(void)
{
    char id[ELA_MAX_DIDURL_LEN] = {0};

    const char *specs[8] = {
        "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
        "     did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
        "    \n\t  did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
        "      did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN        ",
        "    \n \t  did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN     ",
        "\n\t     did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN \t  \n  ",
        "\t \n did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN     \n   \t",
        " \n \t\t did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN\t     \n   \t  ",
    };

    const char *didString = "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN";
    const char *methodSpecificId = "icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN";

    for (int i = 0; i < 8; i++) {
        const char *spec = specs[i];

        DID *did = DID_FromString(spec);
        CU_ASSERT_PTR_NOT_NULL(did);

        const char *method = DID_GetMethod(did);
        CU_ASSERT_PTR_NOT_NULL(method);
        CU_ASSERT_STRING_EQUAL("elastos", method);

        const char *idstring = DID_GetMethodSpecificId(did);
        CU_ASSERT_PTR_NOT_NULL(idstring);
        CU_ASSERT_STRING_EQUAL(methodSpecificId, idstring);

        *id = 0;
        CU_ASSERT_PTR_NOT_NULL(DID_ToString(did, id, sizeof(id)));
        CU_ASSERT_STRING_EQUAL(didString, id);

        DID *ref = DID_NewWithMethod("elastos", methodSpecificId);
        DID *dif = DID_NewWithMethod("elastos", "abc");

        // equals
        CU_ASSERT_EQUAL(1, DID_Equals(did, ref));
        CU_ASSERT_NOT_EQUAL(1, DID_Equals(did, dif));

        // hash code
        //expect(did.hashCode()).toBe(ref.hashCode());
        //expect(did.hashCode()).not.toBe(dif.hashCode());
        DID_Destroy(did);
        DID_Destroy(ref);
        DID_Destroy(dif);
    }
}

static void test_parsedid_with_specialchars(void)
{
    char id[ELA_MAX_DIDURL_LEN] = {0};

    CsvSource csvsources[] = {
        { "did:elastos:ic-J4_z2D.ULrHEzYSvjKNJpKyhqFDxvYV7pN", "ic-J4_z2D.ULrHEzYSvjKNJpKyhqFDxvYV7pN" },
        { "did:elastos:icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-", "icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-" },
        { "did:elastos:icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_", "icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_" },
        { "did:elastos:icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_.", "icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_." },
        { "did:elastos:icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_.-", "icJ.4z2D.ULrHE.zYSvj-KNJp_KyhqFDxvYV7pN-_.-" }
    };

    for (int i = 0; i < 5; i++) {
        CsvSource *source = &csvsources[i];
        DID * did = DID_FromString(source->spec);
        CU_ASSERT_PTR_NOT_NULL(did);

        const char *method = DID_GetMethod(did);
        CU_ASSERT_PTR_NOT_NULL(method);
        CU_ASSERT_STRING_EQUAL("elastos", method);

        const char *idstring = DID_GetMethodSpecificId(did);
        CU_ASSERT_PTR_NOT_NULL(idstring);
        CU_ASSERT_STRING_EQUAL(source->methodSpecificId, idstring);

        *id = 0;
        CU_ASSERT_PTR_NOT_NULL(DID_ToString(did, id, sizeof(id)));
        CU_ASSERT_STRING_EQUAL(source->spec, id);

        DID_Destroy(did);
    }
}

static void test_parse_wrongdid(void)
{
    Check checks[] = {
        { "did1:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid DID schema: 'did1', at: 0" },
        { "d-i_d:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid DID schema: 'd-i_d', at: 0" },
        { "d-i.d:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid DID schema: 'd-i.d', at: 0" },
        { "foo:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid DID schema: 'foo', at: 0" },
        { "foo:bar:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid DID schema: 'foo', at: 0" },
        { "did:bar:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Unknown DID method: 'bar', at: 4" },
        { "did:elastos-:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Unknown DID method: 'elastos-', at: 4" },
        { "did:e-l.a_stos-:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Unknown DID method: 'e-l.a_stos-', at: 4" },
        { "-did:elastos:icJ4z2%DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 0" },
        { ".did:elastos:icJ4z2%DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 0" },
        { "_did:elastos:icJ4z2%DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 0" },
        { "did :elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 3" },
        { "did: elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 4" },
        { "did:-elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 4" },
        { "did:_elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 4" },
        { "did:.elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 4" },
        { "did:*elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 4" },
        { "did:/elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 4" },
        { "did:ela*stos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 7" },
        { "did:elastos\t:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 11" },
        { "did:elastos: icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 12" },
        { "did:elastos:-icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 12" },
        { "did:elastos:_icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 12" },
        { "did:elastos:.icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 12" },
        { "did:elastos:icJ4z2%DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid char at: 18" },
        { "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN$", "Invalid char at: 46" },
        { ":elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Invalid DID schema: '', at: 0" },
        { "did::icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", "Unknown DID method: '', at: 4" },
        { "did:elastos:", "Missing id string at: 12" },
        { "did:elastos", "Missing id string at: 11" },
        { "did:elastos:abc: ", "Invalid char at: 15" }
    };

    for (int i = 0; i < 30; i++) {
        Check *check = &checks[i];
        DID *did = DID_FromString(check->value);
        CU_ASSERT_PTR_NULL(did);
        CU_ASSERT_STRING_EQUAL(check->err, DIDError_GetLastErrorMessage());
        DID_Destroy(did);
    }
}

static void test_parse_wrongdid2(void)
{
    DID *did = DID_FromString("   d-i.d:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN");
    CU_ASSERT_PTR_NULL(did);
    CU_ASSERT_STRING_EQUAL("Invalid DID schema: 'd-i.d', at: 3", DIDError_GetLastErrorMessage());
    DID_Destroy(did);
}

static void test_parse_empty(void)
{
    DID *did = DID_FromString(NULL);
    CU_ASSERT_PTR_NULL(did);
    DID_Destroy(did);

    did = DID_FromString("");
    CU_ASSERT_PTR_NULL(did);
    DID_Destroy(did);

    did = DID_FromString("          ");
    CU_ASSERT_PTR_NULL(did);
    CU_ASSERT_STRING_EQUAL("empty DID string", DIDError_GetLastErrorMessage());
    DID_Destroy(did);
}

static int did_test_parse_suite_init(void)
{
    return  0;
}

static int did_test_parse_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    {  "test_did",                        test_did                        },
    {  "test_parsedid_with_specialchars", test_parsedid_with_specialchars },
    {  "test_parse_wrongdid",             test_parse_wrongdid             },
    {  "test_parse_wrongdid2",            test_parse_wrongdid2            },
    {  "test_parse_empty",                test_parse_empty                },
    {   NULL,                             NULL                            }
};

static CU_SuiteInfo suite[] = {
    { "did parse test", did_test_parse_suite_init, did_test_parse_suite_cleanup, NULL, NULL, cases },
    {  NULL,            NULL,                      NULL,                         NULL, NULL, NULL  }
};

CU_SuiteInfo* did_parse_test_suite_info(void)
{
    return suite;
}