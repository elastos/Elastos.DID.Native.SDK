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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "ela_did.h"
#include "did.h"
#include "diddocument.h"
#include "didstore.h"
#include "credential.h"
#include "didmeta.h"
#include "diderror.h"
#include "didbackend.h"

static const char did_scheme[] = "did";
static const char did_method[] = "elastos";
static const char elastos_did_prefix[] = "did:elastos:";

// idstring has three informats:
// 1. did:elastos:xxxxxxx
// 2. did:elastos:xxxxxxx#xxxxx
// 3. #xxxxxxx
static int parse_id_string(char *id, char *fragment, const char *idstring, DID *base)
{
    const char *s, *e;
    size_t len;

    assert(id);
    assert(idstring && *idstring);

    // Fragment only, need base DID object
    if (*idstring == '#') {
        if (!fragment || !base) {
            DIDError_Set(DIDERR_MALFORMED_DIDURL, "DIDURL error: Fragment only, need base DID object");
            return -1;
        }

        len = strlen(++idstring);
        if (len == 0 || len >= MAX_FRAGMENT) {
            DIDError_Set(DIDERR_MALFORMED_DIDURL, "DIDURL error: the fragment is too long.");
            return -1;
        }

        strcpy(id, base->idstring);
        strcpy(fragment, idstring);
        return 0;
    }

    if (strncmp(idstring, elastos_did_prefix, sizeof(elastos_did_prefix) - 1) != 0) {
        DIDError_Set(DIDERR_MALFORMED_DID, "Unknow did spec.");
        return -1;
    }

    s = idstring + sizeof(elastos_did_prefix) - 1;
    for (e = s; *e != '#' && *e != '?' && *e != '/' && *e != '\x0'; e++);
    len = e - s;
    if (len >= MAX_ID_SPECIFIC_STRING || len == 0) {
        DIDError_Set(DIDERR_MALFORMED_DID, "The method specific identifier is too long.");
        return -1;
    }

    strncpy(id, s, len);
    id[len] = 0;

    if (!fragment)
        return 0;

    for (; *e != '#' && *e != '\x0'; e++);
    if (*e != '#') {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Unknow id string.");
        return -1;
    }

    len = strlen(++e);
    if (len == 0 || len >= MAX_FRAGMENT) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Wrong fragment length.");
        return -1;
    }

    strcpy(fragment, e);
    return 0;
}

int DID_Parse(DID *did, const char *idstring)
{
    return parse_id_string(did->idstring, NULL, idstring, NULL);
}

int DID_Init(DID *did, const char *idstring)
{
    assert(did);
    assert(idstring && *idstring);

    if (strlen(idstring) >= sizeof(did->idstring)) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Id string is too long.");
        return -1;
    }

    strcpy(did->idstring, idstring);
    memset(&did->metadata, 0, sizeof(DIDMetadata));
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

    strcpy(did->idstring, method_specific_string);
    return did;

    DIDERROR_FINALIZE();
}

const char *DID_GetMethod(DID *did)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did argument.", NULL);
    return did_method;

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
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did argument.", NULL);
    CHECK_ARG(!idstring, "No idstring argument.", NULL);
    CHECK_ARG(strlen(did->idstring) + strlen(elastos_did_prefix) >= len,
            "Buffer gived is too small.", NULL);

    strcpy(idstring, elastos_did_prefix);
    strcat(idstring, did->idstring);

    return idstring;

    DIDERROR_FINALIZE();
}

DID *DID_Copy(DID *dest, DID *src)
{
    assert(dest);
    assert(src);

    strcpy(dest->idstring, src->idstring);
    return dest;
}

bool DID_Equals(DID *did1, DID *did2)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did1, "No did1 argument.", false);
    CHECK_ARG(!did2, "No did2 argument.", false);

    return strcmp(did1->idstring, did2->idstring) == 0;

    DIDERROR_FINALIZE();
}

int DID_Compare(DID *did1, DID *did2)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did1, "No did1 argument.", false);
    CHECK_ARG(!did2, "No did2 argument.", false);

    return strcmp(did1->idstring, did2->idstring);

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
    return DIDBackend_ResolveDID(did, status, force);

    DIDERROR_FINALIZE();
}

DIDMetadata *DID_GetMetadata(DID *did)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did to get metadata.", NULL);
    return &did->metadata;

    DIDERROR_FINALIZE();
}

int DIDURL_Parse(DIDURL *id, const char *idstring, DID *base)
{
    return parse_id_string(id->did.idstring, id->fragment, idstring, base);
}

int DIDURL_Init(DIDURL *id, DID *did, const char *fragment)
{
    assert(id);
    assert(did);
    assert(fragment && *fragment);

    if (strlen(fragment) >= sizeof(id->fragment)) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "The fragment is too long.");
        return -1;
    }

    DID_Copy(&id->did, did);
    strcpy(id->fragment, fragment);
    memset(&id->metadata, 0, sizeof(CredentialMetadata));
    return 0;
}

int DIDURL_InitFromString(DIDURL *id, const char *idstring, const char *fragment)
{
    assert(id);
    assert(idstring && *idstring);
    assert(fragment && *fragment);

    if (strlen(fragment) >= sizeof(id->fragment)) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "The fragment is too long.");
        return -1;
    }

    strcpy(id->did.idstring, idstring);
    strcpy(id->fragment, fragment);
    return 0;
}

DIDURL *DIDURL_FromString(const char *idstring, DID *ref)
{
    DIDURL *id;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!idstring || !*idstring, "Invalid idstring.", NULL);

    id = (DIDURL *)calloc(1, sizeof(DIDURL));
    if (!id) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DIDURL failed.");
        return NULL;
    }

    if (DIDURL_Parse(id, idstring, ref) < 0) {
        free(id);
        return NULL;
    }

    return id;

    DIDERROR_FINALIZE();
}

DIDURL *DIDURL_New(const char *method_specific_string, const char *fragment)
{
    DIDURL *id;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!method_specific_string || !*method_specific_string,
            "Invalid method specific string argument.", NULL);
    CHECK_ARG(!fragment || !*fragment, "Invalid fragment string.", NULL);
    CHECK_ARG(strlen(method_specific_string) >= MAX_ID_SPECIFIC_STRING,
            "method specific string is too long.", NULL);
    CHECK_ARG(strlen(fragment) >= MAX_FRAGMENT, "The fragment is too long.", NULL);

    id = (DIDURL *)calloc(1, sizeof(DIDURL));
    if (!id) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DIDURL failed.");
        return NULL;
    }

    strcpy(id->did.idstring, method_specific_string);
    strcpy(id->fragment, fragment);

    return id;

    DIDERROR_FINALIZE();
}

DIDURL *DIDURL_NewByDid(DID *did, const char *fragment)
{
    DIDURL *id;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did argument.", NULL);
    CHECK_ARG(!fragment || !*fragment, "Invalid fragment string.", NULL);
    CHECK_ARG(strlen(fragment) >= MAX_FRAGMENT, "The fragment is too long.", NULL);

    id = (DIDURL*)calloc(1, sizeof(DIDURL));
    if (!id) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DIDURL failed.");
        return NULL;
    }

    if (!DID_Copy(&id->did, did)) {
        free(id);
        return NULL;
    }

    strcpy(id->fragment, fragment);
    return id;

    DIDERROR_FINALIZE();
}

DID *DIDURL_GetDid(DIDURL *id)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No didurl argument.", NULL);
    return &(id->did);

    DIDERROR_FINALIZE();
}

const char *DIDURL_GetFragment(DIDURL *id)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No didurl argument.", NULL);
    return (const char*)id->fragment;

    DIDERROR_FINALIZE();
}

char *DIDURL_ToString(DIDURL *id, char *idstring, size_t len, bool compact)
{
    size_t expect_len = 0;
    int size;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No didurl argument.", NULL);
    CHECK_ARG(!idstring, "No buffer argument.", NULL);

    expect_len += strlen(id->fragment) + 1;         /* #xxxx */
    expect_len += compact ? 0 : strlen(elastos_did_prefix) + strlen(id->did.idstring);

    if (expect_len >= len) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Buffer is too small, please give buffer which has %d length.", expect_len);
        return NULL;
    }

    if (compact) {
        size = snprintf(idstring, len, "#%s", id->fragment);
        if (size < 0 || size > (int)len) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Buffer is too small.");
            return NULL;
        }
    } else {
        size = snprintf(idstring, len, "%s%s#%s", elastos_did_prefix,
            id->did.idstring, id->fragment);
        if (size < 0 || size > (int)len) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Buffer is too small.");
            return NULL;
        }
    }

    return idstring;

    DIDERROR_FINALIZE();
}

bool DIDURL_Equals(DIDURL *id1, DIDURL *id2)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!id1, "No id1 argument.", false);
    CHECK_ARG(!id2, "No id2 argument.", false);

    return (strcmp(id1->did.idstring, id2->did.idstring) == 0 &&
            strcmp(id1->fragment, id2->fragment) == 0);

    DIDERROR_FINALIZE();
}

int DIDURL_Compare(DIDURL *id1, DIDURL *id2)
{
    char _idstring1[ELA_MAX_DIDURL_LEN], _idstring2[ELA_MAX_DIDURL_LEN];
    char *idstring1, *idstring2;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!id1, "No id1 argument.", -1);
    CHECK_ARG(!id2, "No id2 argument.", -1);

    idstring1 = DIDURL_ToString(id1, _idstring1, ELA_MAX_DIDURL_LEN, false);
    idstring2 = DIDURL_ToString(id2, _idstring2, ELA_MAX_DIDURL_LEN, false);
    if (!idstring1 || !idstring2)
        return -1;

    return strcmp(idstring1, idstring2);

    DIDERROR_FINALIZE();
}

DIDURL *DIDURL_Copy(DIDURL *dest, DIDURL *src)
{
    CHECK_ARG(!dest, "No destination id argument.", NULL);
    CHECK_ARG(!src, "No source id argument.", NULL);

    strcpy(dest->did.idstring, src->did.idstring);
    strcpy(dest->fragment, src->fragment);

    return dest;
}

void DIDURL_Destroy(DIDURL *id)
{
    DIDERROR_INITIALIZE();

    if (!id)
        return;

    CredentialMetadata_Free(&id->metadata);
    free(id);

    DIDERROR_FINALIZE();
}

CredentialMetadata *DIDURL_GetMetadata(DIDURL *id)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No destination id argument.", NULL);
    return &id->metadata;

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
