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

static bool proof_equals(TicketProof *proof1, TicketProof *proof2)
{
    if (strcmp(proof1->type, proof2->type))
        return false;

    if (proof1->created != proof2->created)
        return false;

    if (!DIDURL_Equals(&proof1->verificationMethod, &proof2->verificationMethod))
        return false;

    if (strcmp(proof1->signatureValue, proof2->signatureValue))
        return false;

    return true;
}

static bool ticket_equals(TransferTicket *ticket1, TransferTicket *ticket2)
{
    int i, j;
    TicketProof *proof1;
    bool equal;

    assert(ticket1);
    assert(ticket2);

    if (!DID_Equals(&ticket1->did, &ticket2->did))
        return false;

    if (!DID_Equals(&ticket1->to, &ticket2->to))
        return false;

    if (strcmp(ticket1->txid, ticket2->txid))
        return false;

    if (ticket1->proofs.size != ticket2->proofs.size)
        return false;

    for(i = 0; i < ticket1->proofs.size; i++) {
        proof1 = &ticket1->proofs.proofs[i];
        for(j = 0; j < ticket2->proofs.size; j++) {
            equal = proof_equals(proof1, &ticket2->proofs.proofs[j]);
            if (equal)
                break;
        }
        if (!equal)
            return false;
    }

    return true;
}

static void test_ticket(void)
{
    DIDStore *store;
    DIDDocument *controller1_doc, *controller2_doc, *controller3_doc, *customized_doc;
    DIDURL *signkey1, *signkey2, *signkey3, *key;
    TransferTicket *ticket, *_ticket;
    const char *data;
    int i;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    controller1_doc = TestData_GetDocument("document", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller1_doc);
    signkey1 = DIDDocument_GetDefaultPublicKey(controller1_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey1);

    controller2_doc = TestData_GetDocument("controller", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller2_doc);
    signkey2 = DIDDocument_GetDefaultPublicKey(controller2_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey2);

    controller3_doc = TestData_GetDocument("issuer", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller3_doc);
    signkey3 = DIDDocument_GetDefaultPublicKey(controller3_doc);
    CU_ASSERT_PTR_NOT_NULL(signkey3);

    customized_doc = TestData_GetDocument("customized-multisigthree", NULL, 0);
    CU_ASSERT_PTR_NOT_NULL(controller2_doc);

    ticket = DIDDocument_CreateTransferTicket(controller1_doc,
            &customized_doc->did, &controller2_doc->did, storepass);
    CU_ASSERT_PTR_NOT_NULL(ticket);
    CU_ASSERT_EQUAL(0, TransferTicket_IsValid(ticket));

    CU_ASSERT_EQUAL(-1, DIDDocument_SignTransferTicket(controller1_doc,
        ticket, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignTransferTicket(controller2_doc,
        ticket, storepass));
    CU_ASSERT_NOT_EQUAL(-1, DIDDocument_SignTransferTicket(controller3_doc,
        ticket, storepass));
    CU_ASSERT_EQUAL(1, TransferTicket_IsValid(ticket));

    CU_ASSERT_EQUAL(3, TransferTicket_GetProofCount(ticket));
    for (i = 0; i < ticket->proofs.size; i++) {
        key = TransferTicket_GetSignKey(ticket, i);
        CU_ASSERT_PTR_NOT_NULL(key);
        CU_ASSERT_EQUAL(1,DIDURL_Equals(key, signkey1) || DIDURL_Equals(key, signkey2) ||
                DIDURL_Equals(key, signkey3));
    }

    data = TransferTicket_ToJson(ticket);
    CU_ASSERT_PTR_NOT_NULL(data);

    _ticket = TransferTicket_FromJson(data);
    free((void*)data);
    CU_ASSERT_PTR_NOT_NULL(_ticket);

    CU_ASSERT_TRUE(ticket_equals(ticket, _ticket));

    TransferTicket_Destroy(ticket);
    TransferTicket_Destroy(_ticket);
    TestData_Free();
}

static void test_multi_signature_ticket(void)
{
    TransferTicket *ticket;
    DID *owner, *receiver;
    DIDStore *store;
    DIDDocument *doc;
    int version;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    for (version = 2; version < 4; version++) {
        doc = TestData_GetDocument("foobar", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(doc);

        ticket = TestData_GetTransferTicket("foobar");
        CU_ASSERT_PTR_NOT_NULL(ticket);

        owner = TransferTicket_GetOwner(ticket);
        CU_ASSERT_PTR_NOT_NULL(owner);
        CU_ASSERT_STRING_EQUAL("foobar", DID_GetMethodSpecificId(owner));

        receiver = TransferTicket_GetRecipient(ticket);
        CU_ASSERT_PTR_NOT_NULL(receiver);
        CU_ASSERT_STRING_EQUAL("igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d", DID_GetMethodSpecificId(receiver));

        CU_ASSERT_STRING_EQUAL("8b98fa486d0ce78e1e676484f5826825", TransferTicket_GetTransactionId(ticket));
        CU_ASSERT_EQUAL(2, TransferTicket_GetProofCount(ticket));
        CU_ASSERT_EQUAL(1, TransferTicket_IsGenuine(ticket));
    }

    TestData_Free();
}

static void test_ticket2(void)
{
    TransferTicket *ticket;
    DID *owner, *receiver;
    DIDStore *store;
    DIDDocument *doc;
    int version;

    store = TestData_SetupStore(true);
    CU_ASSERT_PTR_NOT_NULL_FATAL(store);

    for (version = 2; version < 4; version++) {
        doc = TestData_GetDocument("baz", NULL, version);
        CU_ASSERT_PTR_NOT_NULL(doc);

        ticket = TestData_GetTransferTicket("baz");
        CU_ASSERT_PTR_NOT_NULL(ticket);

        owner = TransferTicket_GetOwner(ticket);
        CU_ASSERT_PTR_NOT_NULL(owner);
        CU_ASSERT_STRING_EQUAL("baz", DID_GetMethodSpecificId(owner));

        receiver = TransferTicket_GetRecipient(ticket);
        CU_ASSERT_PTR_NOT_NULL(receiver);
        CU_ASSERT_STRING_EQUAL("igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d", DID_GetMethodSpecificId(receiver));

        CU_ASSERT_STRING_EQUAL("f9b2284b4525d5382ee8d0942c42442e", TransferTicket_GetTransactionId(ticket));
        CU_ASSERT_EQUAL(1, TransferTicket_GetProofCount(ticket));
        CU_ASSERT_EQUAL(1, TransferTicket_IsGenuine(ticket));
    }

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
    { "test_ticket",                        test_ticket                 },
    { "test_multi_signature_ticket",        test_multi_signature_ticket },
    { "test_ticket2",                       test_ticket2                },
    { NULL,                                 NULL                        }
};

static CU_SuiteInfo suite[] = {
    { "ticket test",  ticket_test_suite_init, ticket_test_suite_cleanup,  NULL, NULL, cases },
    {  NULL,          NULL,                   NULL,                       NULL, NULL, NULL  }
};

CU_SuiteInfo* ticket_test_suite_info(void)
{
    return suite;
}
