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
#include <jansson.h>
#include <cjose/cjose.h>

#include "ela_jwt.h"
#include "jwtbuilder.h"
#include "HDkey.h"
#include "claims.h"
#include "diderror.h"

JWTBuilder *JWTBuilder_Create(DID *issuer, DIDURL *keyid, KeySpec *keyspec)
{
    cjose_err err;
    char idstring[ELA_MAX_DIDURL_LEN];

    if (!issuer || !keyid || !keyspec) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    JWTBuilder *builder = (JWTBuilder*)calloc(1, sizeof(JWTBuilder));
    if (!builder) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Remalloc buffer for JWTBuilder failed.");
        return NULL;
    }

    DID_Copy(&builder->issuer, issuer);
    DIDURL_Copy(&builder->keyid, keyid);

    builder->header = cjose_header_new(&err);
    if (!builder->header) {
        DIDError_Set(DIDERR_JWT, "Create jwt header failed.");
        JWTBuilder_Destroy(builder);
        return NULL;
    }

    if (!cjose_header_set(builder->header, CJOSE_HDR_ALG, CJOSE_HDR_ALG_ES256, &err)) {
        DIDError_Set(DIDERR_JWT, "Set jwt algorithm failed.");
        JWTBuilder_Destroy(builder);
        return NULL;
    }

    if (!cjose_header_set(builder->header, CJOSE_HDR_KID,
            DIDURL_ToString(keyid, idstring, sizeof(idstring), false), &err)) {
        DIDError_Set(DIDERR_JWT, "Set jwt sign key failed.");
        JWTBuilder_Destroy(builder);
        return NULL;
    }

    builder->jwk = cjose_jwk_create_EC_spec((cjose_jwk_ec_keyspec*)keyspec, &err);
    if (!builder->jwk) {
        DIDError_Set(DIDERR_JWT, "Create jwk failed.");
        JWTBuilder_Destroy(builder);
        return NULL;
    }

    builder->claims = json_object();
    if (!JWTBuilder_SetIssuer(builder, DID_ToString(issuer, idstring, sizeof(idstring)))) {
        DIDError_Set(DIDERR_JWT, "Set jwt issuer failed.");
        JWTBuilder_Destroy(builder);
        return NULL;
    }

    return builder;
}

void JWTBuilder_Destroy(JWTBuilder *builder)
{
    if (!builder)
        return;

    if (builder->header)
        cjose_header_release(builder->header);
    if (builder->jwk)
        cjose_jwk_release(builder->jwk);
    if (builder->claims)
        json_decref(builder->claims);
}

bool JWTBuilder_SetHeader(JWTBuilder *builder, const char *attr, const char *value)
{
    cjose_err err;
    bool succussed;

    if (!builder || !attr || !*attr || !value) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    if (!builder->header) {
        DIDError_Set(DIDERR_JWT, "No header in jwt builder.");
        return false;
    }

    if (!strcmp(attr, CJOSE_HDR_ALG) || !strcmp(attr, CJOSE_HDR_KID)) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Cann't set algorithm or sign key!!!!");
        return false;
    }

    succussed = cjose_header_set(builder->header, attr, value, &err);
    if (!succussed)
        DIDError_Set(DIDERR_JWT, "Set header '%s' failed.", attr);

    return succussed;
}

bool JWTBuilder_SetClaim(JWTBuilder *builder, const char *key, const char *value)
{
    json_t *value_obj;
    int rc;

    if (!builder || !key || !*key || !value) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    value_obj = json_string(value);
    if (!value_obj) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Get value json failed.");
        return false;
    }

    rc = json_object_set_new(builder->claims, key, value_obj);
    if (rc == -1)
        DIDError_Set(DIDERR_JWT, "Set claim '%s' failed.", key);

    return rc == -1 ? false : true;
}

bool JWTBuilder_SetClaimWithJson(JWTBuilder *builder, const char *key, const char *json)
{
    json_t *json_obj;
    int rc;
    bool succussed;

    if (!builder || !key || !*key || !json || !*json) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    json_obj = json_loads(json, 0, NULL);
    if (!json_obj) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Load json object failed.");
        return false;
    }

    rc = json_object_set_new(builder->claims, key, json_obj);
    succussed = (rc == -1) ? false : true;
    if (!succussed)
        DIDError_Set(DIDERR_JWT, "Set json claim '%s' failed.", key);

    return succussed;
}

bool JWTBuilder_SetClaimWithIntegar(JWTBuilder *builder, const char *key, long value)
{
    json_t *value_obj;
    int rc;
    bool succussed;

    if (!builder || !key || !*key || !value) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    value_obj = json_integer(value);
    if (!value_obj) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Get value json failed.");
        return false;
    }

    rc = json_object_set_new(builder->claims, key, value_obj);
    succussed = (rc == -1) ? false : true;
    if (!succussed)
        DIDError_Set(DIDERR_JWT, "Set claim '%s' failed.", key);

    return succussed;
}

bool JWTBuilder_SetClaimWithBoolean(JWTBuilder *builder, const char *key, bool value)
{
    json_t *value_obj;
    int rc;
    bool succussed;

    if (!builder || !key || !*key) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return false;
    }

    value_obj = json_boolean(value);
    if (!value_obj) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Get value json failed.");
        return false;
    }

    rc = json_object_set_new(builder->claims, key, value_obj);
    succussed = (rc == -1) ? false : true;
    if (!succussed)
        DIDError_Set(DIDERR_JWT, "Set claim '%s' failed.", key);

    return succussed;
}

bool JWTBuilder_SetIssuer(JWTBuilder *builder, const char *issuer)
{
    return JWTBuilder_SetClaim(builder, ISSUER, issuer);
}

bool JWTBuilder_SetSubject(JWTBuilder *builder, const char *subject)
{
    return JWTBuilder_SetClaim(builder, SUBJECT, subject);
}

bool JWTBuilder_SetAudience(JWTBuilder *builder, const char *audience)
{
    return JWTBuilder_SetClaim(builder, AUDIENCE, audience);
}

bool JWTBuilder_SetExpiration(JWTBuilder *builder, time_t expire)
{
    return JWTBuilder_SetClaimWithIntegar(builder, EXPIRATION, expire);
}

bool JWTBuilder_SetNotBefore(JWTBuilder *builder, time_t nbf)
{
    return JWTBuilder_SetClaimWithIntegar(builder, NOT_BEFORE, nbf);
}

bool JWTBuilder_SetIssuedAt(JWTBuilder *builder, time_t iat)
{
    return JWTBuilder_SetClaimWithIntegar(builder, ISSUER_AT, iat);
}

bool JWTBuilder_SetId(JWTBuilder *builder, const char *jti)
{
    return JWTBuilder_SetClaim(builder, ID, jti);
}

const char *JWTBuilder_Compact(JWTBuilder *builder)
{
    cjose_jws_t *jws;
    cjose_err err;
    const char *payload, *compacted_str;
    bool exported;

    if (!builder) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    if (!builder->header || !builder->claims) {
        DIDError_Set(DIDERR_INVALID_ARGS, "No header or claims in jwt builder.");
        return NULL;
    }

    payload = json_dumps(builder->claims, 0);
    if (!payload) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Get jwt body string failed.");
        return NULL;
    }

    jws = cjose_jws_sign(builder->jwk, builder->header, (uint8_t*)payload, strlen(payload), &err);
    free((char*)payload);
    payload = NULL;
    if (!jws) {
        DIDError_Set(DIDERR_JWT, "Sign jwt body failed.");
        return NULL;
    }

    exported = cjose_jws_export(jws, &payload, &err);
    if (!exported) {
        DIDError_Set(DIDERR_JWT, "Export token failed.");
        cjose_jws_release(jws);
        return NULL;
    }

    compacted_str = strdup(payload);
    cjose_jws_release(jws);

    return compacted_str;
}