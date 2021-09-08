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

#ifndef __DID_H__
#define __DID_H__

#include "ela_did.h"
#include "didmeta.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ID_SPECIFIC_STRING          48
#define MAX_METHOD_STRING               48

struct DID {
    char method[MAX_METHOD_STRING];
    char idstring[MAX_ID_SPECIFIC_STRING];
    DIDMetadata metadata;
};

int DID_Parse(DID *did, const char *idstring);
int DID_Init (DID *did, const char *idstring);
int DID_InitByPos(DID *did, const char *idstring, int start, int limit);
DID *DID_Copy(DID *dest, DID *src);
bool DID_IsEmpty(DID *did);

bool Contains_DID(DID **dids, size_t size, DID *did);

#ifdef __cplusplus
}
#endif

#endif //__DID_H__