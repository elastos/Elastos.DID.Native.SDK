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
#include "didhistory.h"
#include "didtransactioninfo.h"
#include "didrequest.h"

void DIDHistory_Destroy(DIDHistory *history)
{
    if (!history)
        return;

    if (history->txinfos.infos) {
        size_t i;
        assert(history->txinfos.size > 0);

        for (i = 0; i < history->txinfos.size; i++)
            DIDTransactionInfo_Destroy(history->txinfos.infos[i]);
        free(history->txinfos.infos);
    }
    free(history);
}

DID *DIDHistory_GetOwner(DIDHistory *history)
{
    if (!history) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    return &history->did;
}

int DIDHistory_GetStatus(DIDHistory *history)
{
    if (!history) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return history->status;
}

ssize_t DIDHistory_GetTransactionCount(DIDHistory *history)
{
    if (!history) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    return history->txinfos.size;
}

ssize_t DIDHistory_GetTransactions(DIDHistory *history, DIDTransactionInfo **infos, size_t size)
{
    ssize_t count;

    if (!history || !infos || size == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return -1;
    }

    count = history->txinfos.size <= size ? history->txinfos.size : size;
    memcpy(infos, history->txinfos.infos, count);
    return count;
}

DIDTransactionInfo *DIDHistory_GetTransaction(DIDHistory *history, int index)
{
    if (!history || index < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (index >= history->txinfos.size) {
        DIDError_Set(DIDERR_INVALID_ARGS, "The index is larger than the total count.");
        return NULL;
    }

    return history->txinfos.infos[index];
}

