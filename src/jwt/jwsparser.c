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
#include <assert.h>
#include <cjose/cjose.h>
#include <jansson.h>

#include "ela_did.h"
#include "ela_jwt.h"
#include "crypto.h"
#include "HDkey.h"
#include "jwt.h"
#include "jwsparser.h"
#include "diderror.h"
#include "common.h"
#include "diddocument.h"

static cjose_jwk_t *get_jwk(JWSParser *parser, JWT *jwt)
{
    cjose_err err;
    DID *issuer = NULL;
    DIDDocument *doc = NULL;
    DIDURL *keyid;
    PublicKey *key;
    const char *keybase58, *iss;
    uint8_t binkey[PUBLICKEY_BYTES];
    KeySpec _spec, *spec;
    cjose_jwk_t *jwk = NULL;
    int rc = -1, status;
    bool isresolved = false;

    assert(jwt);
    assert(jwt->header);
    assert(jwt->claims);

    iss = JWT_GetIssuer(jwt);
    if (!iss)
        goto errorExit;

    issuer = DID_FromString(iss);
    if (!issuer)
        goto errorExit;

    if (parser) {
        doc = parser->doc;
        if (doc && !DID_Equals(issuer, &doc->did))
            goto errorExit;
    }

    if (!doc) {
        doc = DID_Resolve(issuer, &status, false);
        isresolved = true;
    }

    if (!JWT_GetKeyId(jwt)) {
        keyid = DIDDocument_GetDefaultPublicKey(doc);
        key = DIDDocument_GetPublicKey(doc, keyid);
    }
    else {
        keyid = DIDURL_FromString(JWT_GetKeyId(jwt), issuer);
        key = DIDDocument_GetPublicKey(doc, keyid);
        DIDURL_Destroy(keyid);
    }
    if (!key)
        goto errorExit;

    keybase58 = PublicKey_GetPublicKeyBase58(key);
    if (!keybase58)
        goto errorExit;

    base58_decode(binkey, sizeof(binkey), keybase58);

    memset(&_spec, 0, sizeof(KeySpec));
    spec = KeySpec_Fill(&_spec, binkey, NULL);
    if (!spec) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get key spec failed.");
        goto errorExit;
    }

    jwk = cjose_jwk_create_EC_spec((cjose_jwk_ec_keyspec*)spec, &err);
    if (!jwk) {
        DIDError_Set(DIDERR_JWT, "Create jwk failed.");
        goto errorExit;
    }

errorExit:
    if (issuer)
        DID_Destroy(issuer);
    if (isresolved && doc)
        DIDDocument_Destroy(doc);

    return jwk;
}

static JWT *parse_jwt(const char *token)
{
    JWT *jwt = NULL;
    char *claims, *header, *_token;
    const char *pos;
    size_t len;
    int dot;

    assert(token && *token);

    pos = strchr(token, '.');
    assert(pos);
    dot = pos - token;

    jwt = (JWT *)calloc(1, sizeof(JWT));
    if (!jwt) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Remalloc buffer for JWT failed.");
        return NULL;
    }

    //copy token
    len = strlen(token);
    _token = (char*)alloca(len);
    strncpy(_token, token, len - 1);
    _token[len - 1] = 0;

    //get claims
    len = strlen(_token) - dot - 1;
    claims = (char*)alloca(len + 1);
    len = base64_url_decode((uint8_t *)claims, _token + dot + 1);
    if (len <= 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode jwt claims failed");
        goto errorExit;
    }
    claims[len] = 0;

    jwt->claims = json_loadb(claims, len, 0, NULL);
    if (!jwt->claims) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Load jwt body failed.");
        goto errorExit;
    }

    //get header
    _token[dot] = 0;
    len = dot;
    header = (char*)alloca(len + 1);
    len = base64_url_decode((uint8_t *)header, _token);
    if (len <= 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode jwt header failed");
        goto errorExit;
    }

    jwt->header = json_loadb(header, len, 0, NULL);
    if (!jwt->header) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Load jwt header failed.");
        goto errorExit;
    }

    return jwt;

errorExit:
    if (jwt)
        JWT_Destroy(jwt);

    return NULL;
}

static JWT *parse_jws(JWSParser *parser, const char *token)
{
    JWT *jwt = NULL;
    cjose_err err;
    cjose_jwk_t *jwk = NULL;
    cjose_jws_t *jws_t = NULL;
    char *payload = NULL;
    size_t payload_len = 0;
    bool successed;
    time_t current, exp, nbf;

    assert(token && *token);

    jwt = (JWT *)calloc(1, sizeof(JWT));
    if (!jwt) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Remalloc buffer for JWT failed.");
        return NULL;
    }

    //set jwt
    jws_t = cjose_jws_import(token, strlen(token), &err);
    if (!jws_t) {
        DIDError_Set(DIDERR_JWT, "Import token to jwt failed.");
        goto errorExit;
    }

    //get header
    json_t *json = cjose_jws_get_protected(jws_t);
    if (!json) {
        DIDError_Set(DIDERR_JWT, "Get jwt protected part failed.");
        goto errorExit;
    }

    jwt->header = json_deep_copy(json);
    if (!jwt->header) {
        DIDError_Set(DIDERR_JWT, "Get jwt header failed.");
        goto errorExit;
    }

    //set claims(payload)
    successed = cjose_jws_get_plaintext(jws_t, (uint8_t**)&payload, &payload_len, &err);
    if (!successed) {
        DIDError_Set(DIDERR_JWT, "Get jwt body failed.");
        goto errorExit;
    }

    jwt->claims = json_loadb(payload, payload_len, 0, NULL);;
    if (!jwt->claims) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Load jwt body failed.");
        goto errorExit;
    }

    //get jwk, must put after getting header and claims.
    jwk = get_jwk(parser, jwt);
    if (!jwk) {
        JWT_Destroy(jwt);
        return NULL;
    }

    successed = cjose_jws_verify(jws_t, jwk, &err);
    cjose_jws_release(jws_t);
    cjose_jwk_release(jwk);
    if (!successed) {
        DIDError_Set(DIDERR_JWT, "Verify jwt failed.");
        JWT_Destroy(jwt);
        return NULL;
    }

    time(&current);
    exp = JWT_GetExpiration(jwt);
    if (exp > 0 && exp < current) {
        DIDError_Set(DIDERR_JWT, "Token is expired.");
        JWT_Destroy(jwt);
        return NULL;
    }

    nbf = JWT_GetNotBefore(jwt);
    if (nbf > 0 && nbf > current) {
        DIDError_Set(DIDERR_JWT, "Token is not in the validity period.");
        JWT_Destroy(jwt);
        return NULL;
    }

    return jwt;

errorExit:
    if (jws_t)
        cjose_jws_release(jws_t);
    if (jwt)
        JWT_Destroy(jwt);

    return NULL;
}

static int check_token(const char *token)
{
    size_t i, idx = 0;
    int dots[2] = {0, 0};
    size_t len;

    assert(token && *token);

    len = strlen(token);

    // find the indexes of the dots
    for (i = 0; i < len && idx < 2; ++i) {
        if (token[i] == '.')
            dots[idx++] = i;
    }

    if (idx != 2 || dots[0] == 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid token! Please check it.");
        return -1;
    }

    //token is jwt, return the first '.' pos
    if (dots[1] == len -1)
        return 0;

    //jws
    return 1;
}

JWT *JWTParser_Parse(const char *token)
{
    int isjwt;

    if (!token || !*token) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    isjwt = check_token(token);
    if (isjwt == -1)
        return NULL;

    if (isjwt == 1) {
        DIDError_Set(DIDERR_JWT, "Not support JWS token.");
        return NULL;
    }

    return parse_jwt(token);
}

JWT *JWSParser_Parse(JWSParser *parser, const char *token)
{
    int isjwt;

    if (!parser || !token || !*token) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    isjwt = check_token(token);
    if (isjwt == -1)
        return NULL;

    if (isjwt == 0) {
        DIDError_Set(DIDERR_JWT, "Not support JWT token.");
        return NULL;
    }

    return parse_jws(parser, token);
}

JWT *DefaultJWSParser_Parse(const char *token)
{
    int isjwt;

    if (!token || !*token) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid arguments.");
        return NULL;
    }

    isjwt = check_token(token);
    if (isjwt == -1)
        return NULL;

    if (isjwt == 0) {
        DIDError_Set(DIDERR_JWT, "Not support JWT token.");
        return NULL;
    }

    return parse_jws(NULL, token);
}

JWSParser *JWSParser_Create(DIDDocument *document)
{
    JWSParser *parser;

    parser = (JWSParser*)calloc(1, sizeof(JWSParser));
    if (!parser) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for jws parser failed.");
        return NULL;
    }

    if (document) {
        parser->doc = (DIDDocument*)calloc(1, sizeof(DIDDocument));
        if (!parser->doc) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for did document failed.");
            goto errorExit;
        }

        if (DIDDocument_Copy(parser->doc, document) < 0) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Document copy failed.");
            goto errorExit;
        }
    }
    return parser;

errorExit:
    if (parser)
       JWSParser_Destroy(parser);

    return NULL;
}

void JWSParser_Destroy(JWSParser *parser)
{
    if (parser) {
        if (parser->doc)
            DIDDocument_Destroy(parser->doc);

        free((void*)parser);
    }
}
