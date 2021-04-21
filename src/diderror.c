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

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>
#include <assert.h>
#include <stdio.h>

#include "ela_did.h"
#include "diderror.h"

#if defined(_WIN32) || defined(_WIN64)
#include <crystal.h>
#define __thread        __declspec(thread)
#endif

typedef struct ErrorInfo {
    char file[PATH_MAX];
    int line;
    int code;
    char message[256];
    struct ErrorInfo *next;
} ErrorInfo;

typedef struct ErrorContext {
    int depth;
    ErrorInfo *info;
} ErrorContext;

static __thread struct ErrorContext errorContext;

void DIDError_Initialize(void)
{
    ErrorInfo *info, *next;

    if (errorContext.depth == 0) {
        info = errorContext.info;
        while(info) {
            next = info->next;
            free((void*)info);
            memset(info, 0, sizeof(ErrorInfo));
            info = next;
        }
        errorContext.info = NULL;
    }

    errorContext.depth++;
}

void DIDError_Finalize(void)
{
    errorContext.depth--;
}

void DIDError_SetEx(const char *file, int line, int code, const char *msg, ...)
{
    ErrorInfo *info;

    info = (ErrorInfo*)calloc(1, sizeof(ErrorInfo));
    if (!info)
        return;

    info->code = code;
    if (msg && *msg) {
        va_list args;
        va_start(args, msg);
        vsnprintf(info->message, sizeof(info->message), msg, args);
        va_end(args);
    } else {
        *info->message = 0;
    }

    if (file && *file) {
        strncpy(info->file, file, sizeof(info->file));
        info->file[sizeof(info->file) - 1] = 0;
    } else {
        *info->file = 0;
    }

    info->line = line;
    info->next = errorContext.info;
    errorContext.info = info;
}

void DIDError_Print(FILE *out)
{
    ErrorInfo *info;

    if (!out)
        return;

    assert(errorContext.depth == 0);

    info = errorContext.info;
    while(info) {
        fprintf(out, "Error(%x): %s\n\t[%s:%d]\n", info->code, info->message, info->file, info->line);
        info = info->next;
    }
}

int DIDError_GetLastErrorCode(void)
{
    if (!errorContext.info)
        return 0;

    return errorContext.info->code;
}

const char *DIDError_GetLastErrorMessage(void)
{
    if (!errorContext.info)
        return NULL;

    return errorContext.info->message;
}

void __diderror_finalize_helper(int *p)
{
    DIDError_Finalize();
}