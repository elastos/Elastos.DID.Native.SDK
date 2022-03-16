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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "ela_did.h"
#include "did.h"
#include "didmeta.h"
#include "diderror.h"
#include "didbackend.h"

static const char did_scheme[] = "did";
static const char did_method[] = "elastos";

static bool is_token(char ch, bool start)
{
    if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9'))
        return true;

    if (start)
        return false;

    return (ch  == '.' || ch == '_' || ch == '-');
}

static int scan_did_nextpart(const char *idstring, int start, int limit,
        const char *delimiter)
{
    int nextPart = limit;
    bool bTokenStart = true;

    assert(idstring);
    assert(start >= 0);
    assert(limit >= 0);

    for (int i = start; i < limit; i++) {
        char ch = *(idstring + i);
        if (ch == *delimiter) {
            nextPart = i;
            break;
        }

        if (is_token(ch, bTokenStart)) {
            bTokenStart = false;
            continue;
        }

        DIDError_Set(DIDERR_MALFORMED_DID, "Invalid char at: %d", i);
        return -1;
    }

    return nextPart;
}

static int parse_did_string(DID *did, const char *idstring, int start, int limit)
{
    int pos, nextPart;
    char check[ELA_MAX_DID_LEN] = {0};

    assert(did);
    assert(idstring);

    memset(did, 0, sizeof(DID));

    if (start < 0)
        start = 0;
    if (limit < 0)
        limit = strlen(idstring);

    // trim the leading and trailing spaces
    while (limit > start && *(idstring + limit - 1) <= ' ')
        limit--;        //eliminate trailing whitespace

    while (start < limit && *(idstring + start) <= ' ')
        start++;        // eliminate leading whitespace

    if (start == limit) {  // empty did string
        DIDError_Set(DIDERR_MALFORMED_DID, "empty DID string");
        return -1;
    }

    pos = start;

    // did
    nextPart = scan_did_nextpart(idstring, pos, limit, ":");
    if (nextPart < 0) {
        memset(did, 0, sizeof(DID));
        return -1;
    }

    strncpy(check, idstring + pos, nextPart - pos);
    if (strlen(check) != strlen(did_scheme) || strncmp(check, did_scheme, strlen(did_scheme))) {
        DIDError_Set(DIDERR_MALFORMED_DID, "Invalid DID schema: '%s', at: %d", check, pos);
        return -1;
    }

    pos = nextPart;

    // method
    if (pos + 1 >= limit || *(idstring + pos) != ':') {
        DIDError_Set(DIDERR_MALFORMED_DID, "Missing method and id string at: %d", pos);
        return -1;
    }

    nextPart = scan_did_nextpart(idstring, ++pos, limit, ":");
    if (nextPart < 0) {
        memset(did, 0, sizeof(DID));
        return -1;
    }

    strncpy(check, idstring + pos, nextPart - pos);
    check[nextPart - pos] = 0;
    if (strlen(check) != strlen(did_method) || strncmp(idstring + pos, did_method, strlen(did_method))) {
        DIDError_Set(DIDERR_MALFORMED_DID, "Unknown DID method: '%s', at: %d", check, pos);
        return -1;
    }

    strcpy(did->method, did_method);
    pos = nextPart;

    // id string
    if (pos + 1 >= limit || *(idstring + pos) != ':') {
        DIDError_Set(DIDERR_MALFORMED_DID, "Missing id string at: %d",
                (pos + 1 > limit ? pos : pos + 1));
        return -1;
    }

    nextPart = scan_did_nextpart(idstring, ++pos, limit, "\x0");
    if (nextPart < 0) {
        memset(did, 0, sizeof(DID));
        return -1;
    }

    strncpy(did->idstring, idstring + pos, nextPart - pos);
    did->idstring[nextPart - pos] = 0;
    return 0;
}

int DID_Parse(DID *did, const char *idstring)
{
    return parse_did_string(did, idstring, -1, -1);
}

int DID_Init(DID *did, const char *idstring)
{
    assert(did);
    assert(idstring && *idstring);

    if (strlen(idstring) >= sizeof(did->idstring)) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Id string is too long.");
        return -1;
    }

    memset(did, 0, sizeof(DID));

    strcpy(did->method, did_method);
    strcpy(did->idstring, idstring);
    return 0;
}

DID *DID_FromString(const char *idstring)
{
    DID *did;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!idstring || !*idstring, "No idstring argument.", NULL);

    did = (DID *)calloc(1, sizeof(DID));
    if (!did) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DID failed.");
        return NULL;
    }

    if (DID_Parse(did, idstring) < 0) {
        free(did);
        return NULL;
    }

    return did;

    DIDERROR_FINALIZE();
}

DID *DID_New(const char *method_specific_string)
{
    DID *did;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!method_specific_string || !*method_specific_string,
            "Invalid method specific string argument.", NULL);
    CHECK_ARG(strlen(method_specific_string) >= MAX_ID_SPECIFIC_STRING,
            "Method specific string is too long.", NULL);

    did = (DID *)calloc(1, sizeof(DID));
    if (!did) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DID failed.");
        return NULL;
    }

    strcpy(did->method, did_method);
    strcpy(did->idstring, method_specific_string);
    return did;

    DIDERROR_FINALIZE();
}

DID *DID_NewWithMethod(const char *method, const char *method_specific_string)
{
    DID *did;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!method || !*method,
            "Invalid method specific string argument.", NULL);
    CHECK_ARG(strlen(method) >= MAX_ID_SPECIFIC_STRING,
            "Method specific string is too long.", NULL);
    CHECK_ARG(!method_specific_string || !*method_specific_string,
            "Invalid method specific string argument.", NULL);
    CHECK_ARG(strlen(method_specific_string) >= MAX_ID_SPECIFIC_STRING,
            "Method specific string is too long.", NULL);

    did = (DID *)calloc(1, sizeof(DID));
    if (!did) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DID failed.");
        return NULL;
    }

    strcpy(did->method, method);
    strcpy(did->idstring, method_specific_string);
    return did;

    DIDERROR_FINALIZE();
}

int DID_InitByPos(DID *did, const char *idstring, int start, int limit)
{
    return parse_did_string(did, idstring, start, limit);
}

const char *DID_GetMethod(DID *did)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did argument.", NULL);
    return (const char*)did->method;

    DIDERROR_FINALIZE();
}

const char *DID_GetMethodSpecificId(DID *did)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did argument.", NULL);
    return (const char *)did->idstring;

    DIDERROR_FINALIZE();
}

char *DID_ToString(DID *did, char *idstring, size_t len)
{
    int size;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did argument.", NULL);
    CHECK_ARG(!idstring, "No idstring buffer.", NULL);
    CHECK_ARG(strlen(did->method) + strlen(did->idstring) + 4 >= len,
            "Buffer is too small.", NULL);

    if (*did->method && *did->idstring) {
        size = snprintf(idstring, len, "did:%s:%s", did->method, did->idstring);
        if (size < 0 || size > len)
            return NULL;
    } else {
        memset(idstring, 0, len);
    }

    return idstring;

    DIDERROR_FINALIZE();
}

DID *DID_Copy(DID *dest, DID *src)
{
    assert(dest);
    assert(src);

    strcpy(dest->method, src->method);
    strcpy(dest->idstring, src->idstring);
    return dest;
}

bool DID_IsEmpty(DID *did)
{
    assert(did);

    if (!*did->method && !*did->idstring)
        return true;

    return false;
}

int DID_Equals(DID *did1, DID *did2)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did1, "No did1 argument.", -1);
    CHECK_ARG(!did2, "No did2 argument.", -1);

    return (!strcmp(did1->idstring, did2->idstring) && !strcmp(did1->method, did2->method)) ? 1 : 0;

    DIDERROR_FINALIZE();
}

int DID_Compare(DID *did1, DID *did2)
{
    char idstring1[ELA_MAX_DID_LEN] = {0}, idstring2[ELA_MAX_DID_LEN] = {0};

    DIDERROR_INITIALIZE();

    CHECK_ARG(!did1, "No did1 argument.", -1);
    CHECK_ARG(!did2, "No did2 argument.", -1);

    if (!DID_ToString(did1, idstring1, sizeof(idstring1)) ||
            !DID_ToString(did2, idstring2, sizeof(idstring2)))
        return -1;

    return strcmp(idstring1, idstring2);

    DIDERROR_FINALIZE();
}

void DID_Destroy(DID *did)
{
    DIDERROR_INITIALIZE();

    if (did) {
        DIDMetadata_Free(&did->metadata);
        free(did);
    }

    DIDERROR_FINALIZE();
}

DIDBiography *DID_ResolveBiography(DID *did)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did to resolve biography.", NULL);
    return DIDBackend_ResolveDIDBiography(did);

    DIDERROR_FINALIZE();
}

DIDDocument *DID_Resolve(DID *did, int *status, bool force)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did to resolve.", NULL);
    CHECK_ARG(!status, "Please give argument to record status.", NULL);
    return DIDBackend_ResolveDID(did, status, force);

    DIDERROR_FINALIZE();
}

int DID_IsDeactivated(DID *did)
{
    int rc, status;
    DIDDocument *doc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did to check be deactivated or not.", -1);
    rc = DIDMetadata_GetDeactivated(&did->metadata);
    if (rc != 0)
        return rc;

    doc = DID_Resolve(did, &status, false);
    if (!doc && status == -1)
        return -1;

    if (status != DIDStatus_Deactivated)
        return 0;

    DIDMetadata_SetDeactivated(&did->metadata, true);
    return 1;

    DIDERROR_FINALIZE();
}

DIDMetadata *DID_GetMetadata(DID *did)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did to get metadata.", NULL);
    return &did->metadata;

    DIDERROR_FINALIZE();
}

bool Contains_DID(DID **dids, size_t size, DID *did)
{
    int i;

    assert(dids);
    assert(did);

    for (i = 0; i < size; i++) {
        if (DID_Equals(dids[i], did))
            return true;
    }

    return false;
}
