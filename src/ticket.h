/*
 * Copyright (c) 2019 Elastos Foundation
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

#ifndef __TICKET_H__
#define __TICKET_H__

#include "ela_did.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TicketProof {
    char type[MAX_TYPE_LEN];
    time_t created;
    DIDURL verificationMethod;
    char signatureValue[MAX_SIGNATURE_LEN];
} TicketProof;

struct TransferTicket {
    DID did;
    DID to;
    char txid[ELA_MAX_TXID_LEN];

    struct {
        size_t size;
        TicketProof *proofs;
    } proofs;

    DIDDocument *doc;
};

TransferTicket *TransferTicket_Construct(DID *owner, DID *to);

int TransferTicket_Seal(TransferTicket *ticket, DIDDocument *controllerdoc,
        const char *storepass);

#ifdef __cplusplus
}
#endif

#endif //__TICKET_H__
