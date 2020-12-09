#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>
#include <CUnit/Basic.h>
#include <crystal.h>

#include "ela_did.h"
#include "loader.h"
#include "constant.h"
#include "did.h"
#include "diddocument.h"
#include "ticket.h"

static void test_ticket(void)
{
    DIDStore *store;
    DIDDocument *controllerdoc1, *controllerdoc2, *controllerdoc3, *customized_doc;
    DIDURL *signkey1, *signkey2, *signkey3, *key;
    TransferTicket *ticket;
    int i;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controllerdoc1 = TestData_LoadDoc();
    CU_ASSERT_PTR_NOT_NULL(controllerdoc1);
    signkey1 = DIDDocument_GetDefaultPublicKey(controllerdoc1);
    CU_ASSERT_PTR_NOT_NULL(signkey1);

    controllerdoc2 = TestData_LoadControllerDoc();
    CU_ASSERT_PTR_NOT_NULL(controllerdoc2);
    signkey2 = DIDDocument_GetDefaultPublicKey(controllerdoc2);
    CU_ASSERT_PTR_NOT_NULL(signkey2);

    controllerdoc3 = TestData_LoadIssuerDoc();
    CU_ASSERT_PTR_NOT_NULL(controllerdoc3);
    signkey3 = DIDDocument_GetDefaultPublicKey(controllerdoc3);
    CU_ASSERT_PTR_NOT_NULL(signkey3);

    customized_doc = TestData_LoadCtmDoc_MultisigThree();
    CU_ASSERT_PTR_NOT_NULL(controllerdoc2);

    ticket = DIDDocument_CreateTransferTicket(controllerdoc1,
            &customized_doc->did, &controllerdoc2->did, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_FALSE(TransferTicket_IsValid(ticket));

    CU_ASSERT_EQUAL(-1, DIDDocument_SignTransferTicket(controllerdoc1,
        ticket, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignTransferTicket(controllerdoc2,
        ticket, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignTransferTicket(controllerdoc3,
        ticket, storepass));
    CU_ASSERT_TRUE(TransferTicket_IsValid(ticket));

    CU_ASSERT_EQUAL(3, TransferTicket_GetProofCount(ticket));

    for (i = 0; i < ticket->proofs.size; i++) {
        key = TransferTicket_GetSignKey(ticket, i);
        CU_ASSERT_PTR_NOT_NULL(key);
        CU_ASSERT_TRUE(DIDURL_Equals(key, signkey1) || DIDURL_Equals(key, signkey2) ||
                DIDURL_Equals(key, signkey3));
    }

    TransferTicket_Destroy(ticket);
    TestData_Free();
}

static int ticket_test_suite_init(void)
{
    return 0;
}

static int ticket_test_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_ticket",        test_ticket      },
    { NULL,                 NULL             }
};

static CU_SuiteInfo suite[] = {
    { "ticket test",  ticket_test_suite_init, ticket_test_suite_cleanup,  NULL, NULL, cases },
    {  NULL,          NULL,                   NULL,                       NULL, NULL, NULL  }
};

CU_SuiteInfo* ticket_test_suite_info(void)
{
    return suite;
}
