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

#ifndef __DID_ERROR_H__
#define __DID_ERROR_H__

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RETURN_(v)                                  do { \
        DIDError_Finialize();                            \
        return v;                                        \
    } while(0)

#define RETURN                                      do { \
        DIDError_Finialize();                            \
        return;                                          \
    } while(0)

#define DIDError_Set(code, msg, ...)    DIDError_SetEx(__FILE__, __LINE__, (code), (msg), ##__VA_ARGS__)

void DIDError_SetEx(const char *file, int line, int code, const char *msg, ...);

void DIDError_Initialize(void);

void DIDError_Finialize(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // __DID_ERROR_H__
