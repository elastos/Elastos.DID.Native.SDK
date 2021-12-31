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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <curl/curl.h>
#include <assert.h>
#include <jansson.h>

#include "ela_did.h"
#include "common.h"
#include "diderror.h"
#include "didresolver.h"

static const char *gEndpoint;

static int MAX_DIFF = 10;

static const char *MAINNET = "mainnet";
static const char *TESTNET = "testnet";

static const char *MAINNET_RPC_ENDPOINT = "https://assist-restapi.tuum.tech/v2";
static const char *TESTNET_RPC_ENDPOINT = "https://assist-restapi-testnet.tuum.tech/v2";
static const char *API_KEY = "IdSFtQosmCwCB9NOLltkZrFy5VqtQn8QbxBKQoHPw7zp3w0hDOyOYjgL53DO3MDH";

#define ASSIST_REQUEST "{\"did\":\"%s\",\"memo\":\"%s\", \"requestFrom\":\"DID command line utils\", \"requestFrom\": %s}"

typedef struct HttpResponseBody {
    size_t used;
    size_t sz;
    void *data;
} HttpResponseBody;

typedef struct CheckResult {
    const char *endpoint;
    int latency;
    int lastBlock;
} CheckResult;

static size_t HttpResponseBodyWriteCallback(char *ptr,
        size_t size, size_t nmemb, void *userdata)
{
    HttpResponseBody *response = (HttpResponseBody *)userdata;
    size_t length = size * nmemb;

    if (response->sz - response->used < length) {
        size_t new_sz;
        size_t last_try;
        void *new_data;

        if (response->sz + length < response->sz) {
            response->used = 0;
            return 0;
        }

        for (new_sz = response->sz ? response->sz << 1 : 512, last_try = response->sz;
            new_sz > last_try && new_sz <= response->sz + length;
            last_try = new_sz, new_sz <<= 1) ;

        if (new_sz <= last_try)
            new_sz = response->sz + length;

        new_sz += 16;

        new_data = realloc(response->data, new_sz);
        if (!new_data) {
            response->used = 0;
            return 0;
        }

        response->data = new_data;
        response->sz = new_sz;
    }

    memcpy((char *)response->data + response->used, ptr, length);
    response->used += length;

    return length;
}

typedef struct HttpRequestBody {
    size_t used;
    size_t sz;
    char *data;
} HttpRequestBody;

static size_t HttpRequestBodyReadCallback(void *dest, size_t size,
        size_t nmemb, void *userdata)
{
    HttpRequestBody *request = (HttpRequestBody *)userdata;
    size_t length = size * nmemb;
    size_t bytes_copy = request->sz - request->used;

    if (bytes_copy) {
        if(bytes_copy > length)
            bytes_copy = length;

        memcpy(dest, request->data + request->used, bytes_copy);

        request->used += bytes_copy;
        return bytes_copy;
    }

    return 0;
}

static const char *perform_request(const char *url, const char *request_content,
        const char *header)
{
    HttpRequestBody request;
    HttpResponseBody response;
    long httpcode;

    assert(url);
    assert(request_content);

    request.used = 0;
    request.sz = strlen(request_content);
    request.data = (char*)request_content;

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, HttpRequestBodyReadCallback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &request);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)request.sz);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HttpResponseBodyWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

#if defined(_WIN32) || defined(_WIN64)
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    memset(&response, 0, sizeof(response));
    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (rc != CURLE_OK) {
        curl_easy_cleanup(curl);
        if (response.data)
            free(response.data);

        return NULL;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
    curl_easy_cleanup(curl);
    if (httpcode < 200 || httpcode > 250) {
        if (response.data)
            free(response.data);
        return NULL;
    }

    ((char *)response.data)[response.used] = 0;
    return (const char *)response.data;
}

static const char *get_request(const char *url, const char *header)
{
    HttpRequestBody request;
    HttpResponseBody response;
    long httpcode;

    assert(url);

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_GET, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, HttpRequestBodyReadCallback);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HttpResponseBodyWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

#if defined(_WIN32) || defined(_WIN64)
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    memset(&response, 0, sizeof(response));
    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (rc != CURLE_OK) {
        curl_easy_cleanup(curl);
        if (response.data)
            free(response.data);

        return NULL;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
    curl_easy_cleanup(curl);
    if (httpcode < 200 || httpcode > 250) {
        if (response.data)
            free(response.data);
        return NULL;
    }

    ((char *)response.data)[response.used] = 0;
    return (const char *)response.data;
}

static int assist_request(char *request, const char *payload, const char *memo)
{
    json_t *item;
    DIDRequest didRequest;
    DID *did;
    char idstring[ELA_MAX_DID_LEN] = {0};

    assert(payload);

    item = json_loads(payload, JSON_COMPACT, &error);
    if (!item)
        return -1;

    memset(&didRequest, 0, sizeof(DIDRequest));
    if (DIDRequest_FromJson(&didRequest, item) == -1) {
        json_decref(item);
        return -1;
    }

    did = &didRequest->did;
    DID_ToString(did, idstring, sizeof(idstring));
    DIDRequest_Destroy(&didRequest);
    return sprintf(request, ASSIST_REQUEST, idstring, memo == NULL ? "" : memo, payload) == -1 ? -1 : 0;
}

static int assist_url(char *url, size_t size, int count, ...)
{
    va_list list;
    int i, totalsize = 0;

    assert(url);
    assert(size > 0);

    *url = 0;
    va_start(list, count);
    for (i = 0; i < count; i++) {
        const char *suffix = va_arg(list, const char*);
        assert(suffix);
        int len = strlen(suffix);
        totalsize = totalsize + len;
        if (totalsize > size)
            return -1;

        strncat(path, suffix, len + 1);
    }
    va_end(list);

    return 0;
}

static int parse_assist_response(const char *data, char *confirm_id)
{
    json_t *root = NULL, *item, *filed;
    json_error_t error;
    long code;
    char *message;

    assert(data);

    root = json_loads(data, CONTRACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid assist responese.");
        return -1;
    }

    item = json_object_get(root, "meta");
    if (!item || !json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'meta' of assist responese.");
        json_decref(root);
        return -1;
    }

    field = json_object_get(item, "code");
    if (!filed || !json_is_number(field)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'code' of assist responese.");
        json_decref(root);
        return -1;
    }
    code = json_integer_value(field);

    field = json_object_get(item, "message");
    if (!filed || !json_is_string(field)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'message' of assist responese.");
        json_decref(root);
        return -1;
    }
    message = json_string_value(field);

    item = json_object_get(root, "data");
    if (!item || !json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'data' of assist responese.");
        json_decref(root);
        return -1;
    }

    field = json_object_get(item, "confirmation_id");
    if (!field || json_is_string(field) || code != 200) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Asssit API error: %ld, message: %s", code, message);
        json_decref(root);
        return -1;
    }
    strcpy(confirm_id, json_string_value(field));

    field = json_object_get(item, "service_count");
    if (!field || !json_is_string(field)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'service count' of assist response.");
        json_decref(root);
        return -1;
    }

    field = json_object_get(item, "duplicate");
    if (!field || !json_is_boolean(field)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'duplicate' of assist response.");
        json_decref(root);
        return -1;
    }

    json_decref(root);
    return 0;
}

static int parse_assist_txstatus(const char *data, char *s)
{
    json_t *root = NULL, *item, *filed;
    json_error_t error;
    long code;
    char *message, *stauts;

    assert(data);

    root = json_loads(data, CONTRACT, &error);
    free((void*)data);
    if (!root) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid assist tx status.");
        return -1;
    }

    item = json_object_get(root, "meta");
    if (!item || !json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'meta' of assist tx status.");
        json_decref(root);
        return -1;
    }

    field = json_object_get(item, "code");
    if (!filed || !json_is_number(field)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'code' of assist tx status.");
        json_decref(root);
        return -1;
    }
    code = json_integer_value(field);

    field = json_object_get(item, "message");
    if (!filed || !json_is_string(field)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'message' of assist tx status.");
        json_decref(root);
        return -1;
    }
    message = json_string_value(field);

    item = json_object_get(root, "data");
    if (!item || !json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'data' of assist tx status.");
        json_decref(root);
        return -1;
    }

    field = json_object_get(item, "status");
    if (!field || !json_is_string(field) || code != 200) {
        DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Asssit API error: %ld, message: %s", code, message);
        json_decref(root);
        return -1;
    }

    status = json_string_value(field);

    if (!strcpm(status, "Quarantined") || !strcmp(status, "Error")) {
        field = json_object_get(item, "blockchainTxId");
        if (!field || !json_is_string(field)) {
            DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "Invalid 'blockchainTxId' of assist tx status.");
        } else {
            DIDError_Set(DIDERR_MALFORMED_RESOLVE_RESPONSE, "DID transaction %s is %s",
                    json_string_value(field), status);
        }

        json_decref(root);
        return -1;
    }

    strcpy(*s, status);
    json_decref(root);
    return 0;
}

bool AssistAdapter_CreateTransaction(const char *payload, const char *memo)
{
    char request[256] = {0}, url[256] = {0}, header[256] = {0}, error[256] = {0};
    char confirm_id[256] = {0}, s[256] = {0};
    const char *data;
    bool completed = false;
    int rc;

    if (!payload)
        return false;

    if (assist_request(request, payload, memo) == -1)
        return false;

    if (assist_url(url, sizeof(url), 2, gEndpoint, "/didtx/create") == -1)
        return false;

    if (sprintf(header, "Authorization:%s", API_KEY) == -1)
        return false;

    data = perform_request(url, request, header);
    if (!data)
        return false;

    rc = parse_assist_response(data, confirm_id);
    free((void*)data);
    if (rc == -1)
        return false;

    if (assist_url(url, sizeof(url), 3, gEndpoint, "/didtx/confirmation_id/", confirm_id) == -1)
        return false;

    while (completed == false) {
        data = get_request(url, header);
        if (!data)
            return false;

        rc = parse_assist_txstatus(data, s);
        free((void*)data);
        if (rc == -1)
            return false;

        if (!strcmp(s, "Pending") || !strcmp(s, "Processing")) {
            sleep(3);
            continue;
        } else if (!strcmp(s, "Completed")) {
            completed = true;
        }
    }

    return true;
}

int AssistAdapter_Init(const char *url)
{
    const char *url;
    char cachedir[PATH_MAX];
    CURLUcode rc;

    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK)
        return -1;

    sprintf(cachedir, "%s%s", getenv("HOME"), "/.cache.did.elastos");

    if (!strcmp(MAINNET, url)) {
        gEndpoint = MAINNET_RPC_ENDPOINT;
    } else {
        gEndpoint = TESTNET_RPC_ENDPOINT;
    }

    return DIDBackend_InitializeDefault(create_transaction,
            url, cachedir);
}
