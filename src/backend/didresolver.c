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

static char gURL[URL_LEN];
static int MAX_DIFF = 10;

static const char *MAINNET = "mainnet";
static const char *TESTNET = "testnet";
static const char *MAINNET_RESOLVERS[] = {
    "https://api.elastos.io/eid",
    "https://api.trinity-tech.io/eid"
};
static const char *TESTNET_RESOLVERS[] = {
    "https://api-testnet.elastos.io/eid",
    "https://api-testnet.trinity-tech.io/eid",
};

#define CHECK_NETWORK_REQUEST "{\"id\": %ld,\"jsonrpc\":\"2.0\", \"method\":\"eth_blockNumber\"}"

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

static const char *perform_request(const char *url, const char *request_content)
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
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HttpResponseBodyWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

#if defined(_WIN32) || defined(_WIN64)
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    memset(&response, 0, sizeof(response));
    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (rc != CURLE_OK) {
        DIDError_Set(DIDERR_NETWORK, "Resolve error, status: %d, message: %s", rc, curl_easy_strerror(rc));
        curl_easy_cleanup(curl);
        if (response.data)
            free(response.data);

        return NULL;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);
    curl_easy_cleanup(curl);
    if (httpcode < 200 || httpcode > 250) {
        DIDError_Set(DIDERR_NETWORK, "Http error, code: %d", httpcode);
        if (response.data)
            free(response.data);
        return NULL;
    }

    ((char *)response.data)[response.used] = 0;
    return (const char *)response.data;
}

const char *DefaultResolve_Resolve(const char *resolve_request)
{
    return perform_request(gURL, resolve_request);
}

static int check_url(const char *url)
{
    CURLUcode rc;
    CURLU *curl;

    assert(url);

    curl = curl_url();
    rc = curl_url_set(curl, CURLUPART_URL, url, 0);
    curl_url_cleanup(curl);
    if(rc != 0) {
        DIDError_Set(DIDERR_NETWORK, "Invalid url(%s).", url);
        return -1;
    }

    return 0;
}

static int check_endpoint(CheckResult *result, const char *network)
{
    time_t id, start;
    int latency, blockNumber;
    char request[256];
    const char *response = NULL;
    json_error_t error;
    json_t *root = NULL, *item;
    int rc = -1;

    assert(result);
    assert(network);

    time(&id);

    memset(result, 0, sizeof(CheckResult));

    if (sprintf(request, CHECK_NETWORK_REQUEST, (long)id) == -1) {
        DIDError_Set(DIDERR_IO_ERROR, "Generate resolve request failed.");
        return rc;
    }

    start = time(NULL);
    response = perform_request(network, request);
    if (!response)
        return rc;

    latency = (int)(time(NULL) - start);
    root = json_loads(response, JSON_COMPACT, &error);
    if (!root) {
        DIDError_Set(DIDERR_IO_ERROR, "Deserialize response data failed, error: %s.", error.text);
        goto errorExit;
    }

    item = json_object_get(root, "id");
    if (!item) {
        DIDError_Set(DIDERR_IO_ERROR, "Missing 'id'.");
        goto errorExit;
    }
    if (!json_is_integer(item)) {
        DIDError_Set(DIDERR_IO_ERROR, "Invalid 'id'.");
        goto errorExit;
    }
    if ((long)json_integer_value(item) != id) {
        DIDError_Set(DIDERR_IO_ERROR, "Invalid JSON RPC id.");
        goto errorExit;
    }

    item = json_object_get(root, "result");
    if (!item) {
        DIDError_Set(DIDERR_IO_ERROR, "Missing 'result'.");
        goto errorExit;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_IO_ERROR, "Invalid 'result'.");
        goto errorExit;
    }

    blockNumber = strtol(json_string_value(item), NULL, 0);

    result->endpoint = network;
    result->latency = latency;
    result->lastBlock = blockNumber;
    rc = 0;

errorExit:
    if (root)
        json_decref(root);
    if (response)
        free((void*)response);
    return rc;
}

static int select_endpoint(const void *a, const void *b)
{
    int diff;

    CheckResult *resulta = (CheckResult*)a;
    CheckResult *resultb = (CheckResult*)b;

    if (resulta->latency < 0 && resultb->latency < 0)
        return 0;

    if (resulta->latency < 0 || resultb->latency < 0)
        return resulta->latency < 0 ? 1 : -1;

    diff = resultb->latency - resulta->latency;
    if (abs(diff) > MAX_DIFF)
        return diff;

    if (resulta->latency == resultb->latency) {
        return diff;
    } else {
        return resulta->latency - resultb->latency;
    }
}

static bool network_available(CheckResult *result)
{
    assert(result);

    return result->latency >= 0;
}

static const char *check_network(const char **networks, size_t size)
{
    int i;
    const char *network;
    CheckResult *results;

    assert(networks);
    assert(size > 0);

    results = (CheckResult*)alloca(size * sizeof(CheckResult));
    if (!results) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for check result failed.");
        return NULL;
    }

    for (i = 0; i < size; i++) {
        network = networks[i];
        check_endpoint(&results[i], network);
    }

    qsort(results, size, sizeof(CheckResult), select_endpoint);
    if (network_available(&results[0]))
        return results[0].endpoint;
    else
        return NULL;
}

int DefaultResolve_Init(const char *_url)
{
    const char *url, **endpoints = NULL;
    CURLUcode rc;

    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        DIDError_Set(DIDERR_NETWORK, "Initialize curl failed.");
        return -1;
    }

    if (!strcmp(MAINNET, _url)) {
        url = MAINNET_RESOLVERS[0];
        endpoints = MAINNET_RESOLVERS;
    } else if (!strcmp(TESTNET, _url)) {
        url = TESTNET_RESOLVERS[0];
        endpoints = TESTNET_RESOLVERS;
    } else {
        url = _url;
    }

    rc = check_url(url);
    if(rc < 0)
        return -1;

    strcpy(gURL, url);

    if (endpoints) {
        url = check_network(endpoints, 2);
        if (url)
            strcpy(gURL, url);
    }

    return 0;
}
