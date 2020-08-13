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
#include <pthread.h>

#include "ela_did.h"
#include "common.h"
#include "diderror.h"

typedef struct DIDError {
    int code;
    char file[PATH_MAX];
    int line;
    char message[256];
} DIDError;

#if defined(_WIN32) || defined(_WIN64)
#define __thread        __declspec(thread)
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
static __thread DIDError de;
#elif defined(__APPLE__)
#include <pthread.h>
static pthread_once_t key_once = PTHREAD_ONCE_INIT;
static pthread_key_t de;
static void diderror_setup_error(void)
{
    (void)pthread_key_create(&de, NULL);
}
#else
#error "Unsupported OS yet"
#endif

static void diderror_set(DIDError *error)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
    memcpy(&de, error, sizeof(DIDError));
#elif defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
    (void)pthread_once(&key_once, diderror_setup_error);
    (void)pthread_setspecific(de, (void*)error);
#pragma GCC diagnostic pop
#else
#error "Unsupported OS yet"
#endif
}

static DIDError *diderror_get(void)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
    return &de;
#elif defined(__APPLE__)
    return ((DIDError*)pthread_getspecific(de));
#else
#error "Unsupported OS yet"
#endif
}

void DIDError_SetEx(const char *file, int line, int code, const char *msg, ...)
{
    DIDError error;

    error.code = code;
    if (msg && *msg) {
        va_list args;
        va_start(args, msg);
        vsnprintf(error.message, sizeof(error.message), msg, args);
        va_end(args);
    } else {
        *error.message = 0;
    }

    if (file && *file) {
        strncpy(error.file, file, sizeof(error.file));
        error.file[sizeof(error.file) - 1] = 0;
    } else {
        *error.file = 0;
    }
    error.line = line;

    diderror_set(&error);
}

int DIDError_GetCode(void)
{
    return diderror_get()->code;
}

const char *DIDError_GetMessage(void)
{
    return diderror_get()->message;
}

const char *DIDError_GetFile(void)
{
    return diderror_get()->file;
}

int DIDError_GetLine(void)
{
    return diderror_get()->line;
}

void DIDError_Clear(void)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
    memset(&de, 0, sizeof(DIDError));
#elif defined(__APPLE__)
    (void)pthread_setspecific(de, 0);
#else
#error "Unsupported OS yet"
#endif
}

void DIDError_Print(void)
{
    DIDError *derror = diderror_get();
    if (derror->code == 0)
        printf("No error.\n");
    else
        printf("Error(%x): %s\n\t[%s:%d]\n", derror->code, derror->message, derror->file, derror->line);
}