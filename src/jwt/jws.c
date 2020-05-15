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
#include "jws.h"
#include "claims.h"

void JWS_Destroy(JWS *jws)
{
    if (!jws)
        return;

    if (jws->jws)
        cjose_jws_release(jws->jws);
    if (jws->claims)
        json_decref(jws->claims);
}

const char *JWS_GetHeader(JWS *jws, const char *attr)
{
    cjose_err err;
    const char *data;

    if (!jws || !attr)
        return NULL;

    data = cjose_header_get(jws->header, attr, &err);
    if (!data)
        return NULL;

    return strdup(data);
}

const char *JWS_GetAlgorithm(JWS *jws)
{
    return JWS_GetHeader(jws, CJOSE_HDR_ALG);
}

const char *JWS_GetKeyId(JWS *jws)
{
    return JWS_GetHeader(jws, CJOSE_HDR_KID);
}

const char *JWS_GetClaim(JWS *jws, const char *key)
{
    json_t *value;
    const char *data;

    if (!jws || !key || !*key)
        return NULL;

    value = json_object_get(jws->claims, key);
    if (!value)
        return NULL;

    if (json_is_string(value)) {
        data = json_string_value(value);
        if (!data)
            return NULL;

        return strdup(data);
    }

    if (json_is_object(value) || json_is_array(value))
        return json_dumps(value, 0);

    return NULL;
}

long JWS_GetClaimAsInteger(JWS *jws, const char *key)
{
    json_t *value;

    if (!jws || !key || !*key)
        return 0;

    value = json_object_get(jws->claims, key);
    if (!value || !json_is_integer(value))
        return 0;

    return json_integer_value(value);
}

bool JWS_GetClaimAsBoolean(JWS *jws, const char *key)
{
    json_t *value;

    if (!jws || !key || !*key)
        return 0;

    value = json_object_get(jws->claims, key);
    if (!value || !json_is_boolean(value))
        return 0;

    return json_boolean_value(value);
}

const char *JWS_GetIssuer(JWS *jws)
{
    return JWS_GetClaim(jws, ISSUER);
}

const char *JWS_GetSubject(JWS *jws)
{
    return JWS_GetClaim(jws, SUBJECT);
}

const char *JWS_GetAudience(JWS *jws)
{
    return JWS_GetClaim(jws, AUDIENCE);
}

const char *JWS_GetId(JWS *jws)
{
    return JWS_GetClaim(jws, ID);
}

time_t JWS_GetExpiration(JWS *jws)
{
    return JWS_GetClaimAsInteger(jws, EXPIRATION);
}

time_t JWS_GetNotBefore(JWS *jws)
{
    return JWS_GetClaimAsInteger(jws, NOT_BEFORE);
}

time_t JWS_GetIssuedAt(JWS *jws)
{
    return JWS_GetClaimAsInteger(jws, ISSUER_AT);
}
