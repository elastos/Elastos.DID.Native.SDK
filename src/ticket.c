/*
 * Copyright (c) 2019 - 2021 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "ela_did.h"
#include "diderror.h"
#include "crypto.h"
#include "common.h"
#include "JsonGenerator.h"
#include "diddocument.h"
#include "didmeta.h"
#include "ticket.h"

extern const char *ProofType;

static const char *ID = "id";
static const char *TO = "to";
static const char *TXID = "txid";
static const char *PROOF = "proof";
static const char *TYPE = "type";
static const char *VERIFICATION_METHOD = "verificationMethod";
static const char *CREATED = "created";
static const char *SIGNATURE = "signature";

static int proof_cmp(const void *a, const void *b)
{
    TicketProof *proofa = (TicketProof*)a;
    TicketProof *proofb = (TicketProof*)b;

    return (int)(proofa->created - proofb->created);
}

static int Proof_ToJson(JsonGenerator *gen, TicketProof *proof)
{
    char id[ELA_MAX_DIDURL_LEN];
    char _timestring[DOC_BUFFER_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(proof);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, TYPE, proof->type));
    CHECK(DIDJG_WriteStringField(gen, CREATED,
            get_time_string(_timestring, sizeof(_timestring), &proof->created)));
    CHECK(DIDJG_WriteStringField(gen, VERIFICATION_METHOD,
            DIDURL_ToString(&proof->verificationMethod, id, sizeof(id), false)));
    CHECK(DIDJG_WriteStringField(gen, SIGNATURE, proof->signatureValue));
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static int ProofArray_ToJson(JsonGenerator *gen, TransferTicket *ticket)
{
    TicketProof *proofs;
    size_t size;
    int i;

    assert(gen);
    assert(gen->buffer);
    assert(ticket);

    size = ticket->proofs.size;
    proofs = ticket->proofs.proofs;
    if (size > 1)
        CHECK(DIDJG_WriteStartArray(gen));

    qsort(proofs, size, sizeof(TicketProof), proof_cmp);

    for (i = 0; i < size; i++)
        CHECK(Proof_ToJson(gen, &proofs[i]));

    if (size > 1)
        CHECK(DIDJG_WriteEndArray(gen));

    return 0;
}

static int ticket_tojson_internal(JsonGenerator *gen, TransferTicket *ticket,
        bool forsign)
{
    char id[ELA_MAX_DIDURL_LEN];

    assert(gen);
    assert(gen->buffer);
    assert(ticket);

    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteStringField(gen, ID, DID_ToString(&ticket->did, id, sizeof(id))));
    CHECK(DIDJG_WriteStringField(gen, TO, DID_ToString(&ticket->to, id, sizeof(id))));
    CHECK(DIDJG_WriteStringField(gen, TXID, ticket->txid));

    if (!forsign) {
        CHECK(DIDJG_WriteFieldName(gen, PROOF));
        CHECK(ProofArray_ToJson(gen, ticket));
    }
    CHECK(DIDJG_WriteEndObject(gen));
    return 0;
}

static const char *ticket_tojson_forsign(TransferTicket *ticket, bool forsign)
{
    JsonGenerator g, *gen;

    assert(ticket);

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator for ticket initialize failed.");
        return NULL;
    }

    if (ticket_tojson_internal(gen, ticket, forsign) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize ticket to json failed.");
        DIDJG_Destroy(gen);
        return NULL;
    }

    return DIDJG_Finish(gen);
}

TransferTicket *TransferTicket_Construct(DID *owner, DID *to)
{
    TransferTicket *ticket = NULL;
    DIDDocument *document = NULL;
    const char *txid;
    int status, valid;

    assert(owner);
    assert(to);

    ticket = (TransferTicket*)calloc(1, sizeof(TransferTicket));
    if (!ticket) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for transfer ticket failed.");
        return NULL;
    }

    document = DID_Resolve(to, &status, false);
    if (!document) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Receiver of ticket %s %s", DIDSTR(to), DIDSTATUS_MSG(status));
        goto errorExit;
    }

    valid = DIDDocument_IsValid(document);
    DIDDocument_Destroy(document);
    if (valid != 1)
        goto errorExit;

    ticket->doc = DID_Resolve(owner, &status, false);
    if (!ticket->doc) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "Owner of ticket %s %s", DIDSTR(owner), DIDSTATUS_MSG(status));
        goto errorExit;
    }

    if (!DIDDocument_IsCustomizedDID(ticket->doc)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Ticket supports only for customized did.");
        goto errorExit;
    }

    txid = DIDMetadata_GetTxid(&ticket->doc->metadata);
    if (!txid) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No transaction id from resolving.");
        goto errorExit;
    }

    DID_Copy(&ticket->did, owner);
    DID_Copy(&ticket->to, to);
    strcpy(ticket->txid, txid);
    return ticket;

errorExit:
    TransferTicket_Destroy(ticket);
    return NULL;
}

static int ticket_addproof(TransferTicket *ticket, char *signature, DIDURL *signkey, time_t created)
{
    int i;
    size_t size;
    TicketProof *rps, *p;

    assert(ticket);
    assert(signature);
    assert(signkey);

    size = ticket->proofs.size;
    for (i = 0; i < size; i++) {
        p = &ticket->proofs.proofs[i];
        if (DID_Equals(&p->verificationMethod.did, &signkey->did)) {
            DIDError_Set(DIDERR_ALREADY_EXISTS, "Signkey already exist.");
            return -1;
        }
    }

    rps = realloc(ticket->proofs.proofs, (ticket->proofs.size + 1) * sizeof(TicketProof));
    if (!rps) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for ticket proofs failed.");
        return -1;
    }

    strcpy(rps[size].signatureValue, signature);
    strcpy(rps[size].type, ProofType);
    DIDURL_Copy(&rps[size].verificationMethod, signkey);
    rps[size].created = created;
    ticket->proofs.proofs = rps;
    ticket->proofs.size++;
    return 0;
}

int TransferTicket_Seal(TransferTicket *ticket, DIDDocument *controllerdoc,
        const char *storepass)
{
    const char *data = NULL;
    char signature[SIGNATURE_BYTES * 2 + 16];
    DIDURL *signkey;
    int rc;

    assert(ticket);
    assert(controllerdoc);
    assert(storepass && *storepass);

    rc = TransferTicket_IsQualified(ticket);
    if (rc) {
        if (rc == 1)
            DIDError_Set(DIDERR_ALREADY_SEALED, "The signer of ticket is enough.");
        return rc;
    }

    if (DIDDocument_IsCustomizedDID(controllerdoc)) {
        DIDError_Set(DIDERR_INVALID_CONTROLLER, "The signer of ticket is not customized DID.");
        return -1;
    }

    if (!DIDDocument_GetControllerDocument(ticket->doc, &controllerdoc->did)) {
        DIDError_Set(DIDERR_INVALID_CONTROLLER, "The signer of ticket isn't the one of owner.");
        return -1;
    }

    if (!DIDMetadata_AttachedStore(&controllerdoc->metadata)) {
        DIDError_Set(DIDERR_NO_ATTACHEDSTORE, "No attached store with controller document.");
        return -1;
    }

    signkey = DIDDocument_GetDefaultPublicKey(controllerdoc);
    if (!signkey) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "No default key of controllerdoc.");
        return -1;
    }

    data = ticket_tojson_forsign(ticket, true);
    if (!data)
        return -1;

    rc = DIDDocument_Sign(controllerdoc, NULL, storepass, signature,
            1, (unsigned char*)data, strlen(data));
    free((void*)data);
    if (rc < 0) {
        DIDError_Set(DIDERR_SIGN_ERROR, "Sign ticket failed.");
        return -1;
    }

    if (ticket_addproof(ticket, signature, signkey, time(NULL)) < 0)
        return -1;

    return 0;
}

void TransferTicket_Destroy(TransferTicket *ticket)
{
    DIDERROR_INITIALIZE();

    if (!ticket)
        return;

    if (ticket->doc)
        DIDDocument_Destroy(ticket->doc);
    if (ticket->proofs.proofs)
        free((void*)ticket->proofs.proofs);

    free((void*)ticket);

    DIDERROR_FINALIZE();
}

const char *TransferTicket_ToJson(TransferTicket *ticket)
{
    DIDERROR_INITIALIZE();

    return ticket_tojson_forsign(ticket, false);

    DIDERROR_FINALIZE();
}

static int Parse_Proof(TicketProof *proof, json_t *json)
{
    json_t *item;

    assert(proof);
    assert(json);

    item = json_object_get(json, TYPE);
    if (item) {
        if ((json_is_string(item) && strlen(json_string_value(item)) + 1 > MAX_TYPE_LEN) ||
                !json_is_string(item)) {
            DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Invalid proof type.");
            return -1;
        }
        strcpy(proof->type, json_string_value(item));
    }
    else
        strcpy(proof->type, ProofType);

    item = json_object_get(json, CREATED);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Missing create ticket time.");
        return -1;
    }
    if (!json_is_string(item) ||
            parse_time(&proof->created, json_string_value(item)) < 0) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Invalid create ticket time.");
        return -1;
    }

    item = json_object_get(json, VERIFICATION_METHOD);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Missing signkey.");
        return -1;
    }
    if (!json_is_string(item) ||
            DIDURL_Parse(&proof->verificationMethod, json_string_value(item), NULL) == -1) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Invalid signkey.");
        return -1;
    }

    item = json_object_get(json, SIGNATURE);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Missing signature.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Invalid signature.");
        return -1;
    }
    if (strlen(json_string_value(item)) + 1 > MAX_SIGNATURE_LEN) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Document signature is too long.");
        return -1;
    }
    strcpy(proof->signatureValue, json_string_value(item));
    return 0;
}

static int Parse_Proofs(TransferTicket *ticket, json_t *json)
{
    json_t *item;
    size_t size = 1, i;
    TicketProof *proof;

    assert(ticket);
    assert(json);

    if (json_is_array(json))
        size = json_array_size(json);

    ticket->proofs.proofs = (TicketProof*)calloc(size, sizeof(TicketProof));
    if (!ticket->proofs.proofs) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for proofs failed.");
        return -1;
    }

    ticket->proofs.size = 0;
    for (i = 0; i < size; i++) {
        if (json_is_object(json))
            item = json;
        else
            item = json_array_get(json, i);

        if (!json_is_object(item)) {
            DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Invalid proof format.");
            return -1;
        }

        proof = &ticket->proofs.proofs[ticket->proofs.size];
        if (Parse_Proof(proof, item) < 0)
            return -1;

        ticket->proofs.size++;
    }

    return 0;
}

static TransferTicket *TransferTicket_FromJson_Internal(json_t *root)
{
    TransferTicket *ticket = NULL;
    json_t *item;
    int status;

    assert(root);

    ticket = (TransferTicket*)calloc(1, sizeof(TransferTicket));
    if (!ticket) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for ticket failed.");
        return NULL;
    }

    item = json_object_get(root, ID);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Missing ticket owner.");
        goto errorExit;
    }
    if (!json_is_string(item) ||
            DID_Parse(&ticket->did, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Invalid ticket owner.");
        goto errorExit;
    }

    item = json_object_get(root, TO);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Missing ticket receiver.");
        goto errorExit;
    }
    if (!json_is_string(item) ||
            DID_Parse(&ticket->to, json_string_value(item)) == -1) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Invalid ticket receiver.");
        goto errorExit;
    }

    item = json_object_get(root, TXID);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Missing owner's last transaction id.");
        goto errorExit;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Invalid owner's last transaction id.");
        goto errorExit;
    }
    if (strlen(json_string_value(item)) >= ELA_MAX_TXID_LEN) {
        DIDError_Set(DIDERR_MALFORMED_TRANSFERTICKET, "Transaction id is too long.");
        goto errorExit;
    }
    strcpy(ticket->txid, json_string_value(item));

    item = json_object_get(root, PROOF);
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Missing ticket proof.");
        goto errorExit;
    }
    if (!json_is_object(item) && !json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_DOCUMENT, "Invalid ticket proof.");
        goto errorExit;
    }
    if (Parse_Proofs(ticket, item) == -1)
        goto errorExit;

    ticket->doc = DID_Resolve(&ticket->did, &status, false);
    if (!ticket->doc) {
        DIDError_Set(DIDERR_DID_RESOLVE_ERROR, "The ticket's owner .");
        goto errorExit;
    }

    return ticket;

errorExit:
    TransferTicket_Destroy(ticket);
    return NULL;
}

TransferTicket *TransferTicket_FromJson(const char *json)
{
    TransferTicket *ticket;
    json_t *root;
    json_error_t error;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!json, "No json string to ticket.", NULL);

    root = json_loads(json, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Deserialize ticket failed, error: %s.", error.text);
        return NULL;
    }

    ticket = TransferTicket_FromJson_Internal(root);
    json_decref(root);
    return ticket;

    DIDERROR_FINALIZE();
}

int TransferTicket_IsValid(TransferTicket *ticket)
{
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", -1);

    if (!ticket->doc) {
        DIDError_Set(DIDERR_NOT_VALID, " * TICKET %s : is invalid,\
                error: no owner's document.", DIDSTR(&ticket->did));
        return -1;
    }

    rc = DIDDocument_IsValid(ticket->doc);
    if (rc != 1) {
        DIDError_Set(DIDERR_NOT_VALID, " * TICKET %s : is invalid, \
                error: owner's lastest document is invalid.", DIDSTR(&ticket->did));
        return rc;
    }

    rc = TransferTicket_IsGenuine(ticket);
    if (rc != 1) {
        DIDError_Set(DIDERR_NOT_VALID, " * TICKET %s : is invalid, \
                error: the ticket is not genuine.", DIDSTR(&ticket->did));
        return rc;
    }

    if (strcmp(ticket->txid, DIDMetadata_GetTxid(&ticket->doc->metadata))) {
        DIDError_Set(DIDERR_NOT_VALID, "* TICKET %s : is invalid, \
                error: the ticket doesn't have the lastest transaction id.",
                DIDSTR(&ticket->did));
        return 0;
    }

    return 1;

    DIDERROR_FINALIZE();
}

int TransferTicket_IsQualified(TransferTicket *ticket)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", -1);

    assert((ticket->proofs.size == 0 && !ticket->proofs.proofs) ||
            (ticket->proofs.size > 0 && ticket->proofs.proofs));

    return ticket->proofs.size == (ticket->doc->controllers.size > 1 ? ticket->doc->multisig : 1) ? 1 : 0;

    DIDERROR_FINALIZE();
}

int TransferTicket_IsGenuine(TransferTicket *ticket)
{
    TicketProof *proof;
    DIDDocument *doc;
    DID **checksigners;
    const char *data = NULL;
    size_t size;
    int i, rc = 0, check;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", -1);

    check = DIDDocument_IsGenuine(ticket->doc);
    if (check != 1) {
        DIDError_Set(DIDERR_NOT_GENUINE, " * TICKET %s : is not genuine,\
                error: owner of ticket isn't genuine.", DIDSTR(&ticket->did));
        return check;
    }

    check = TransferTicket_IsQualified(ticket);
    if (check != 1) {
        DIDError_Set(DIDERR_NOT_GENUINE, " * TICKET %s : is not genuine,\
                error: ticket is not qualified.", DIDSTR(&ticket->did));
        return check;
    }

    data = ticket_tojson_forsign(ticket, true);
    if (!data) {
        DIDError_Set(DIDERR_NOT_GENUINE, " * TICKET %s : is not genuine,\
                error: %s.", DIDSTR(&ticket->did), DIDERRMSG);
        return -1;
    }

    size = ticket->proofs.size;
    checksigners = (DID**)alloca(size * sizeof(DID*));
    if (!checksigners) {
        DIDError_Set(DIDERR_NOT_GENUINE, " * TICKET %s : is not genuine,\
                error: malloc buffer for signers failed.", DIDSTR(&ticket->did));
        rc = -1;
        goto errorExit;
    }

    for (i = 0; i < size; i++) {
        proof = &ticket->proofs.proofs[i];
        doc = DIDDocument_GetControllerDocument(ticket->doc, &proof->verificationMethod.did);
        if (!doc) {
            DIDError_Set(DIDERR_NOT_GENUINE, " * TICKET %s : is not genuine,\
                    error: the signer isn't controller of ticket's owner.", DIDSTR(&ticket->did));
            goto errorExit;
        }

        if (Contains_DID(checksigners, i, &proof->verificationMethod.did)) {
            DIDError_Set(DIDERR_NOT_GENUINE, " * TICKET %s : is not genuine,\
                    error: there is the same controller signed ticket two times.", DIDSTR(&ticket->did));
            goto errorExit;
        }

        if (!DIDURL_Equals(DIDDocument_GetDefaultPublicKey(doc), &proof->verificationMethod)) {
            DIDError_Set(DIDERR_NOT_GENUINE, " * TICKET %s : is not genuine,\
                    error: signkey isn't controller's default key.", DIDSTR(&ticket->did));
            goto errorExit;
        }

        if (strcmp(proof->type, ProofType)) {
            DIDError_Set(DIDERR_NOT_GENUINE, " * TICKET %s : is not genuine,\
                    error: unsupported public key type.", DIDSTR(&ticket->did));
            goto errorExit;
        }

        rc = DIDDocument_IsValid(doc);
        if (rc != 1)
            goto errorExit;

        if (DIDDocument_Verify(doc, &proof->verificationMethod, proof->signatureValue,
                1, data, strlen(data)) < 0) {
            DIDError_Set(DIDERR_NOT_GENUINE, " * TICKET %s : is not genuine,\
                    error: verify ticket failed.", DIDSTR(&ticket->did));
            goto errorExit;
        }

        checksigners[i] = &proof->verificationMethod.did;
    }

    rc = 1;

errorExit:
    if (data)
       free((void*)data);

    return rc;

    DIDERROR_FINALIZE();
}

DID *TransferTicket_GetOwner(TransferTicket *ticket)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", NULL);
    return &ticket->did;

    DIDERROR_FINALIZE();
}

DID *TransferTicket_GetReceiver(TransferTicket *ticket)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", NULL);
    return &ticket->to;

    DIDERROR_FINALIZE();
}

const char *TransferTicket_GetTransactionId(TransferTicket *ticket)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", NULL);
    if (*ticket->txid)
        return ticket->txid;

    return NULL;

    DIDERROR_FINALIZE();
}

ssize_t TransferTicket_GetProofCount(TransferTicket *ticket)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", -1);
    return ticket->proofs.size;

    DIDERROR_FINALIZE();
}

const char *TransferTicket_GetProofType(TransferTicket *ticket, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", NULL);
    CHECK_ARG(index < 0, "Invalid index.", NULL);
    CHECK_ARG(index >= ticket->proofs.size, "Index is larger than the count of proofs.", NULL);

    return ticket->proofs.proofs[index].type;

    DIDERROR_FINALIZE();
}

DIDURL *TransferTicket_GetSignKey(TransferTicket *ticket, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", NULL);
    CHECK_ARG(index < 0, "Invalid index.", NULL);
    CHECK_ARG(index >= ticket->proofs.size, "Index is larger than the count of proofs.", NULL);

    return &ticket->proofs.proofs[index].verificationMethod;

    DIDERROR_FINALIZE();
}

time_t TransferTicket_GetProofCreatedTime(TransferTicket *ticket, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", 0);
    CHECK_ARG(index < 0, "Invalid index.", 0);
    CHECK_ARG(index >= ticket->proofs.size, "Index is larger than the count of proofs.", 0);

    return ticket->proofs.proofs[index].created;

    DIDERROR_FINALIZE();
}

const char *TransferTicket_GetProofSignature(TransferTicket *ticket, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!ticket, "No ticket argument.", NULL);
    CHECK_ARG(index < 0, "Invalid index.", NULL);
    CHECK_ARG(index >= ticket->proofs.size, "Index is larger than the count of proofs.", NULL);

    return ticket->proofs.proofs[index].signatureValue;

    DIDERROR_FINALIZE();
}
