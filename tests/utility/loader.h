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

#ifndef __TEST_LOADER_H__
#define __TEST_LOADER_H__

#include "ela_did.h"
#include "HDkey.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *Generater_Publickey(char *publickeybase58, size_t size);

HDKey *Generater_KeyPair(HDKey *hdkey);

////////////////////////////////////////
int TestData_Init(bool dummy);

void TestData_Deinit(void);

DIDStore *TestData_SetupStore(bool dummybackend);

DIDStore *TestData_SetupTestStore(bool dummybackend, int version);

void TestData_Free(void);

const char *TestData_GetDocumentJson(char *did, char *type, int version);

const char *TestData_GetCredentialJson(char *did, char *vc, char *type, int version);

const char *TestData_GetPresentationJson(char *did, char *vp, char *type, int version);

DIDDocument *TestData_GetDocument(char *did, char *type, int version);

Credential *TestData_GetCredential(char *did, char *vc, char *type, int version);

Presentation *TestData_GetPresentation(char *did, char *vp, char *type, int version);

RootIdentity *TestData_InitIdentity(DIDStore *store);

const char *TestData_LoadRestoreMnemonic(void);

#ifdef __cplusplus
}
#endif

#endif /* __TEST_LOADER_H__ */
