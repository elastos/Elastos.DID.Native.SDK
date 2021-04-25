/*
 * Copyright (c) 2020 Elastos Foundation
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
#include "diddocument.h"
#include "didbiography.h"

void DIDBiography_Destroy(DIDBiography *biography)
{
    DIDERROR_INITIALIZE();

    if (!biography)
        return;

    if (biography->txs.txs) {
        size_t i;
        assert(biography->txs.size > 0);

        for (i = 0; i < biography->txs.size; i++)
            DIDTransaction_Destroy(&biography->txs.txs[i]);
        free(biography->txs.txs);
    }
    free(biography);

    DIDERROR_FINALIZE();
}

DID *DIDBiography_GetOwner(DIDBiography *biography)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!biography, "No biography to get owner.", NULL);
    return &biography->did;

    DIDERROR_FINALIZE();
}

int DIDBiography_GetStatus(DIDBiography *biography)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!biography, "No biography to get status.", -1);
    return biography->status;

    DIDERROR_FINALIZE();
}

ssize_t DIDBiography_GetTransactionCount(DIDBiography *biography)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!biography, "No biography to get transaction count.", -1);
    return biography->txs.size;

    DIDERROR_FINALIZE();
}

DIDDocument *DIDBiography_GetDocumentByIndex(DIDBiography *biography, int index)
{
    DIDDocument *doc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!biography, "No biography to get document.", NULL);
    CHECK_ARG(index < 0, "Invalid index.", NULL);
    CHECK_ARG(!biography->txs.txs, "No transaction in biography.", NULL);
    CHECK_ARG((size_t)index >= biography->txs.size, "Index is larger than transaction \
            count in biography.", NULL);

    doc = (DIDDocument*)calloc(1, sizeof(DIDDocument));
    if (!doc) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for document failed.");
        return NULL;
    }

    if (DIDDocument_Copy(doc, biography->txs.txs[index].request.doc) < 0) {
        DIDDocument_Destroy(doc);
        return NULL;
    }

    return doc;

    DIDERROR_FINALIZE();
}

const char *DIDBiography_GetTransactionIdByIndex(DIDBiography *biography, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!biography, "No biography to get transaction id.", NULL);
    CHECK_ARG(index < 0, "Invalid index.", NULL);
    CHECK_ARG(!biography->txs.txs || (size_t)index >= biography->txs.size,
            "Index is larger than transaction count in biography.", NULL);

    return biography->txs.txs[index].txid;

    DIDERROR_FINALIZE();
}

time_t DIDBiography_GetPublishedByIndex(DIDBiography *biography, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!biography, "No biography to get transaction id.", 0);
    CHECK_ARG(index < 0, "Invalid index.", 0);
    CHECK_ARG(!biography->txs.txs || (size_t)index >= biography->txs.size,
            "Index is larger than transaction count in biography.", 0);

    return biography->txs.txs[index].timestamp;

    DIDERROR_FINALIZE();
}

const char *DIDBiography_GetOperationByIndex(DIDBiography *biography, int index)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!biography, "No biography to get transaction id.", NULL);
    CHECK_ARG(index < 0, "Invalid index.", NULL);
    CHECK_ARG(!biography->txs.txs || (size_t)index >= biography->txs.size,
            "Index is larger than transaction count in biography.", NULL);

    return biography->txs.txs[index].request.header.op;

    DIDERROR_FINALIZE();
}
