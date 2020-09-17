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
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "ela_jwt.h"
#include "jwt.h"
#include "claims.h"
#include "diderror.h"

void JWT_Destroy(JWT *jwt)
{
    if (!jwt)
        return;

    if (jwt->header)
        json_decref(jwt->header);
    if (jwt->claims)
        json_decref(jwt->claims);

    free(jwt);
}

const char *JWT_GetHeader(JWT *jwt, const char *attr)
{
    cjose_err err;
    const char *data;

    if (!jwt || !attr) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    data = cjose_header_get(jwt->header, attr, &err);
    if (!data) {
        DIDError_Set(DIDERR_JWT, "Get header '%s' failed.", attr);
        return NULL;
    }

    return data;
}

const char *JWT_GetAlgorithm(JWT *jwt)
{
    return JWT_GetHeader(jwt, CJOSE_HDR_ALG);
}

const char *JWT_GetKeyId(JWT *jwt)
{
    return JWT_GetHeader(jwt, CJOSE_HDR_KID);
}

const char *JWT_GetClaim(JWT *jwt, const char *key)
{
    json_t *value;
    const char *data;

    if (!jwt || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    value = json_object_get(jwt->claims, key);
    if (!value) {
        DIDError_Set(DIDERR_JWT, "No claim: %s.", key);
        return NULL;
    }

    if (!json_is_string(value)) {
        DIDError_Set(DIDERR_JWT, "Claim '%s' is not string.", key);
        return NULL;
    }

    data = json_string_value(value);
    if (!data) {
        DIDError_Set(DIDERR_JWT, "Get claim '%s' string failed.", key);
        return NULL;
    }

    return data;
}

const char *JWT_GetClaimAsJson(JWT *jwt, const char *key)
{
    json_t *value;
    const char *data;

    if (!jwt || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    value = json_object_get(jwt->claims, key);
    if (!value) {
        DIDError_Set(DIDERR_JWT, "No claim: %s.", key);
        return NULL;
    }

    if (json_is_object(value)) {
        data = json_dumps(value, JSON_COMPACT);
        if (!data)
            DIDError_Set(DIDERR_JWT, "Get claim '%s' from json object failed.", key);

        return data;
    }

    if (json_is_array(value)) {
        data = json_dumps(value, JSON_COMPACT);
        if (!data)
            DIDError_Set(DIDERR_JWT, "Get claim '%s' from json array failed.", key);

        return data;
    }

    DIDError_Set(DIDERR_UNSUPPOTED, "Unsupport this claim type.");
    return NULL;
}

long JWT_GetClaimAsInteger(JWT *jwt, const char *key)
{
    json_t *value;

    if (!jwt || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return 0;
    }

    value = json_object_get(jwt->claims, key);
    if (!value) {
        DIDError_Set(DIDERR_JWT, "No claim: %s.", key);
        return 0;
    }
    if (!json_is_integer(value)) {
        DIDError_Set(DIDERR_JWT, "Claim '%s' is not integar.", key);
        return 0;
    }

    return json_integer_value(value);
}

bool JWT_GetClaimAsBoolean(JWT *jwt, const char *key)
{
    json_t *value;

    if (!jwt || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    value = json_object_get(jwt->claims, key);
    if (!value) {
        DIDError_Set(DIDERR_JWT, "No claim: %s.", key);
        return false;
    }
    if (!json_is_boolean(value)) {
        DIDError_Set(DIDERR_JWT, "Claim '%s' is not boolean.", key);
        return false;
    }

    return json_boolean_value(value);
}

const char *JWT_GetIssuer(JWT *jwt)
{
    return JWT_GetClaim(jwt, ISSUER);
}

const char *JWT_GetSubject(JWT *jwt)
{
    return JWT_GetClaim(jwt, SUBJECT);
}

const char *JWT_GetAudience(JWT *jwt)
{
    return JWT_GetClaim(jwt, AUDIENCE);
}

const char *JWT_GetId(JWT *jwt)
{
    return JWT_GetClaim(jwt, ID);
}

time_t JWT_GetExpiration(JWT *jwt)
{
    return JWT_GetClaimAsInteger(jwt, EXPIRATION);
}

time_t JWT_GetNotBefore(JWT *jwt)
{
    return JWT_GetClaimAsInteger(jwt, NOT_BEFORE);
}

time_t JWT_GetIssuedAt(JWT *jwt)
{
    return JWT_GetClaimAsInteger(jwt, ISSUER_AT);
}
