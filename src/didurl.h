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

#ifndef __DIDURL_H__
#define __DIDURL_H__

#include "ela_did.h"
#include "did.h"
#include "credmeta.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_FRAGMENT_LEN                    48
#define MAX_PATH_LEN                        128
#define MAX_QUERY_LEN                       128

struct  DIDURL {
    DID did;
    char path[MAX_PATH_LEN];
    char queryString[MAX_QUERY_LEN];
    char fragment[MAX_FRAGMENT_LEN];
    CredentialMetadata metadata;
};

int DIDURL_Parse(DIDURL *id, const char *idstring, DID *context);
//caller provide DIDURL object
int DIDURL_InitFromDid(DIDURL *id, DID *did, const char *fragment);
int DIDURL_InitFromString(DIDURL *id, const char *idstring, const char *fragment);
DIDURL *DIDURL_Copy(DIDURL *dest, DIDURL *src);
char *DIDURL_ToString_Internal(DIDURL *id, char *idstring, size_t len, bool compact);

#ifdef __cplusplus
}
#endif

#endif //__DIDURL_H__