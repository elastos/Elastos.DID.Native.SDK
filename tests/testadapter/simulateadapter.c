#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <curl/curl.h>

#include "ela_did.h"
#include "simulateadapter.h"

static const char *tx_url = "http://127.0.0.1:9123/idtx";
static const char *reset_url = "http://127.0.0.1:9123/reset";
static const char *shutdown_url = "http://127.0.0.1:9123/shutdown";
static const char *resolve_url = "http://127.0.0.1:9123/resolve";

typedef struct HttpResponseBody {
    size_t used;
    size_t sz;
    void *data;
} HttpResponseBody;

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

static bool SimulatedAdapter_PerformRequest(const char *requestbody, const char *url)
{
    HttpRequestBody request;
    HttpResponseBody response;
    long httpcode;

    assert(requestbody);

    request.used = 0;
    request.sz = strlen(requestbody);
    request.data = (char*)requestbody;

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, HttpRequestBodyReadCallback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &request);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)request.sz);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HttpResponseBodyWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    memset(&response, 0, sizeof(response));
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &httpcode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if ( httpcode < 200 || httpcode > 250 || rc != CURLE_OK) {
        if (response.data)
            free(response.data);

        return false;
    }

    return true;
}

static bool SimulatedAdapter_CreateIdTransaction(const char *payload, const char *memo)
{
    if (!payload)
        return false;

    return SimulatedAdapter_PerformRequest(payload, tx_url);
}

bool SimulatedAdapter_Reset(int type)
{
    char url[256] = {0};

    if (type == 0)
        sprintf(url, "%s", reset_url);
    if (type == 1)
        sprintf(url, "%s?idtxsonly", reset_url);
    if (type == 2)
        sprintf(url, "%s?vctxsonly", reset_url);

    return SimulatedAdapter_PerformRequest("", url);
}

bool SimulatedAdapter_Shutdown(void)
{
    return SimulatedAdapter_PerformRequest("", shutdown_url);
}

int SimulatedAdapter_Set(const char *cachedir)
{
    SimulatedAdapter_Reset(0);
    return DIDBackend_InitializeDefault(SimulatedAdapter_CreateIdTransaction, resolve_url, cachedir);
}

