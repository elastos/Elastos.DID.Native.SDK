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
#include "credential.h"
#include "diderror.h"

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

static bool is_hexchar(char ch)
{
    return ((ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f') ||
            (ch >= '0' && ch <= '9'));
}

static int scan_didurl_nextpart(const char *url, int start, int limit,
        const char *partSeps, const char *tokenSeps)
{
    int nextPart = limit;
    bool tokenStart = true;

    assert(url);
    assert(start >= 0);
    assert(limit >= 0);

    for (int i = start; i < limit; i++) {
        char ch = *(url + i);

        if (partSeps && strchr(partSeps, ch) != NULL) {
            nextPart = i;
            break;
        }

        if (tokenSeps && strchr(tokenSeps, ch) != NULL) {
            if (tokenStart) {
                DIDError_Set(DIDERR_MALFORMED_DIDURL, "Invalid char at: %d", i);
                return -1;
            }

            tokenStart = true;
            continue;
        }

        if (is_token(ch, tokenStart)) {
            tokenStart = false;
            continue;
        }

        if (ch == '%') {
            if (i + 2 >= limit) {
                DIDError_Set(DIDERR_MALFORMED_DIDURL, "Invalid char at: %d", i);
                return -1;
            }

            char seq = *(url + (++i));
            if (!is_hexchar(seq)) {
                DIDError_Set(DIDERR_MALFORMED_DIDURL, "Invalid hex char at: %d", i);
                return -1;
            }

            seq = *(url + (++i));
            if (!is_hexchar(seq)) {
                DIDError_Set(DIDERR_MALFORMED_DIDURL, "Invalid hex char at: %d", i);
                return -1;
            }

            tokenStart = false;
            continue;
        }

        DIDError_Set(DIDERR_MALFORMED_DIDURL, "Invalid char at: %d", i);
        return -1;
    }

    return nextPart;
}

int DIDURL_Parse(DIDURL *id, const char *url, DID *context)
{
    int start, limit, nextPart, pos;

    assert(id);
    assert(url && *url);

    memset(id, 0, sizeof(DIDURL));
    if (!url) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "null DIDURL string");
        return -1;
    }

    if (context)
        DID_Copy(&id->did, context);

    start = 0;
    limit = strlen(url);

    // trim the leading and trailing spaces
    while (limit > 0 && *(url + limit - 1) <= ' ')
        limit--;        //eliminate trailing whitespace

    while (start < limit && *(url + start) <= ' ')
        start++;        // eliminate leading whitespace

    if (start == limit) { // empty url string
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "empty DIDURL string");
        return -1;
    }

    pos = start;

    // DID
    if (pos < limit && !strncmp("did:", url + pos, 4)) {
        nextPart = scan_didurl_nextpart(url, pos, limit, "/?#", ":");
        if (nextPart < 0)
            return -1;

        if (DID_InitByPos(&id->did, url, pos, nextPart) < 0) {
            DIDError_Set(DIDERR_MALFORMED_DIDURL, "Invalid did at: %d", pos);
            return -1;
        }

        pos = nextPart;
    }

    // path
    if (pos < limit && *(url + pos) == '/') {
        nextPart = scan_didurl_nextpart(url, pos + 1, limit, "?#", "/");
        if (nextPart < 0)
            return -1;

        if (nextPart - pos >= MAX_PATH_LEN) {
            DIDError_Set(DIDERR_MALFORMED_DIDURL, "Path string is too long.");
            return -1;
        }

        strncpy(id->path, url + pos, nextPart - pos);
        id->path[nextPart - pos] = 0;
        pos = nextPart;
    }

    // query
    if (pos < limit && *(url + pos) == '?') {
        nextPart = scan_didurl_nextpart(url, pos + 1, limit, "#", "&=");
        if (nextPart < 0)
            return -1;

        if (nextPart - pos > MAX_QUERY_LEN) {
            DIDError_Set(DIDERR_MALFORMED_DIDURL, "Query string is too long.");
            return -1;
        }

        strncpy(id->queryString, url + pos + 1, nextPart - pos - 1);
        id->queryString[nextPart - pos - 1] = 0;
        pos = nextPart;
    }

    // fragment
    // condition: pos == start
    //  Compatible with v1, support fragment without leading '#'
    if ((pos < limit && *(url + pos) == '#') || (pos == start)) {
        if (*(url + pos) == '#')
            pos++;

        nextPart = scan_didurl_nextpart(url, pos, limit, "", NULL);
        if (nextPart < 0)
            return -1;

        if (nextPart - pos > MAX_FRAGMENT_LEN) {
            DIDError_Set(DIDERR_MALFORMED_DIDURL, "Fragment string is too long.");
            return -1;
        }

        strncpy(id->fragment, url + pos, nextPart - pos);
        id->fragment[nextPart - pos] = 0;
    }
    return 0;
}

int DIDURL_InitFromDid(DIDURL *id, DID *did, const char *fragment)
{
    assert(id);
    assert(did);
    assert(fragment && *fragment);

    memset(id, 0, sizeof(DIDURL));
    if (strlen(fragment) >= sizeof(id->fragment)) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "The fragment is too long.");
        return -1;
    }

    DID_Copy(&id->did, did);
    strcpy(id->fragment, fragment);
    return 0;
}

int DIDURL_InitFromString(DIDURL *id, const char *idstring, const char *fragment)
{
    assert(id);
    assert(idstring && *idstring);
    assert(fragment && *fragment);

    memset(id, 0, sizeof(DIDURL));
    if (strlen(fragment) >= sizeof(id->fragment)) {
        DIDError_Set(DIDERR_MALFORMED_DIDURL, "The fragment is too long.");
        return -1;
    }

    strcpy(id->did.method, did_method);
    strcpy(id->did.idstring, idstring);
    strcpy(id->fragment, fragment);
    return 0;
}

DIDURL *DIDURL_FromString(const char *idstring, DID *context)
{
    DIDURL *id;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!idstring || !*idstring, "Invalid idstring.", NULL);

    id = (DIDURL*)calloc(1, sizeof(DIDURL));
    if (!id) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DIDURL failed.");
        return NULL;
    }

    if (DIDURL_Parse(id, idstring, context) < 0) {
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
    CHECK_ARG(strlen(fragment) >= MAX_FRAGMENT_LEN, "The fragment is too long.", NULL);

    id = (DIDURL *)calloc(1, sizeof(DIDURL));
    if (!id) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for DIDURL failed.");
        return NULL;
    }

    strcpy(id->did.method, did_method);
    strcpy(id->did.idstring, method_specific_string);
    strcpy(id->fragment, fragment);

    return id;

    DIDERROR_FINALIZE();
}

DIDURL *DIDURL_NewFromDid(DID *did, const char *fragment)
{
    DIDURL *id;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!did, "No did argument.", NULL);
    CHECK_ARG(!fragment || !*fragment, "Invalid fragment string.", NULL);
    CHECK_ARG(strlen(fragment) >= MAX_FRAGMENT_LEN, "The fragment is too long.", NULL);

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
    if (!DID_IsEmpty(&id->did))
        return &id->did;

    return NULL;

    DIDERROR_FINALIZE();
}

const char *DIDURL_GetFragment(DIDURL *id)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No didurl argument.", NULL);
    return (const char*)id->fragment;

    DIDERROR_FINALIZE();
}

const char *DIDURL_GetPath(DIDURL *id)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No didurl argument.", NULL);
    if (!*id->path)
        return NULL;

    return (const char*)id->path;

    DIDERROR_FINALIZE();
}

const char *DIDURL_GetQueryString(DIDURL *id)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No didurl argument.", NULL);
    if (!*id->queryString)
        return NULL;

    return (const char*)id->queryString;

    DIDERROR_FINALIZE();
}

int DIDURL_GetQuerySize(DIDURL *id)
{
    char query[MAX_QUERY_LEN], *token, *save = NULL;
    int count = 0;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No didurl argument.", -1);

    strcpy(query, id->queryString);

    token = strtok_r(query, "&", &save);
    while(token) {
        count++;
        token = strtok_r(NULL, "&", &save);
    }

    return count;

    DIDERROR_FINALIZE();
}

const char *DIDURL_GetQueryParameter(DIDURL *id, const char *key)
{
    char query[MAX_QUERY_LEN], *token, *pos, *save = NULL;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No didurl argument.", NULL);
    CHECK_ARG(!key || !*key, "No key argument.", NULL);

    strcpy(query, id->queryString);

    token = strtok_r(query, "&", &save);
    while(token) {
        pos = strstr(token, "=");
        if (!pos)
            pos = token + strlen(token);

        if (strlen(key) == pos - token && !strncmp(token, key, pos - token)) {
            if (pos == token + strlen(token) + 1)
                return NULL;

            return (pos == token + strlen(token)) ? NULL : strdup(pos + 1);
        }

        token = strtok_r(NULL, "&", &save);
    }

    return NULL;

    DIDERROR_FINALIZE();
}

int DIDURL_HasQueryParameter(DIDURL *id, const char *key)
{
    char query[MAX_QUERY_LEN], *token, *pos, *save = NULL;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No didurl argument.", -1);
    CHECK_ARG(!key || !*key, "No key argument.", -1);

    strcpy(query, id->queryString);

    token = strtok_r(query, "&", &save);
    while(token) {
        pos = strstr(token, "=");
        if (!pos)
            pos = token + strlen(token);

        if (strlen(key) == pos - token && !strncmp(token, key, pos - token))
            return 1;

        token = strtok_r(NULL, "&", &save);
    }

    return 0;

    DIDERROR_FINALIZE();
}

char *DIDURL_ToString_Internal(DIDURL *id, char *idstring, size_t len, bool compact)
{
    size_t expect_len = 0;
    int path_len = 0, query_len = 0, fragment_len = 0;
    char str[ELA_MAX_DID_LEN] = {0};

    memset(idstring, 0, len);

    if (!id)
        return NULL;

    path_len = strlen(id->path);
    if (*id->queryString)
        query_len = strlen(id->queryString) + 1;   //include "?"
    if (*id->fragment)
        fragment_len = strlen(id->fragment) + 1;   //inclue "#"

    expect_len += path_len + query_len + fragment_len;         /* #xxxx */
    expect_len += compact ? 0 : strlen(id->did.idstring) + strlen(id->did.method) + 5;  //5 is length of "did:" + ":"

    if (expect_len >= len) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Buffer is too small, please give buffer which has %d length.", expect_len);
        return NULL;
    }

    if (!compact) {
        DID_ToString(&id->did, str, sizeof(str));
        strcpy(idstring, str);
    }

    strcat(idstring, id->path);
    if (*id->queryString) {
        strcat(idstring, "?");
        strcat(idstring, id->queryString);
    }
    if (*id->fragment) {
        strcat(idstring, "#");
        strcat(idstring, id->fragment);
    }

    return idstring;
}

char *DIDURL_ToString(DIDURL *id, char *idstring, size_t len)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!id, "No didurl argument.", NULL);
    CHECK_ARG(!idstring, "No buffer argument.", NULL);

    return DIDURL_ToString_Internal(id, idstring, len, false);

    DIDERROR_FINALIZE();
}

int DIDURL_Equals(DIDURL *id1, DIDURL *id2)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!id1, "No id1 argument.", -1);
    CHECK_ARG(!id2, "No id2 argument.", -1);

    return !DIDURL_Compare(id1, id2);

    DIDERROR_FINALIZE();
}

int DIDURL_Compare(DIDURL *id1, DIDURL *id2)
{
    char _idstring1[ELA_MAX_DIDURL_LEN] = {0}, _idstring2[ELA_MAX_DIDURL_LEN] = {0};
    char *idstring1, *idstring2;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!id1, "No id1 argument.", -1);
    CHECK_ARG(!id2, "No id2 argument.", -1);

    idstring1 = DIDURL_ToString_Internal(id1, _idstring1, ELA_MAX_DIDURL_LEN, false);
    idstring2 = DIDURL_ToString_Internal(id2, _idstring2, ELA_MAX_DIDURL_LEN, false);
    if (!idstring1 || !idstring2)
        return -1;

    return strcmp(idstring1, idstring2);

    DIDERROR_FINALIZE();
}

DIDURL *DIDURL_Copy(DIDURL *dest, DIDURL *src)
{
    assert(dest);
    assert(src);

    DID_Copy(&dest->did, &src->did);
    strcpy(dest->path, src->path);
    strcpy(dest->queryString, src->queryString);
    strcpy(dest->fragment, src->fragment);

    return dest;
}

int DIDURL_IsQualified(DIDURL *id)
{
    CHECK_ARG(!id, "No didurl argument.", -1);

    return (!DID_IsEmpty(&id->did) && *id->fragment) ? 1 : 0;
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
