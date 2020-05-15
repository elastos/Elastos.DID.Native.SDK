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

#ifndef __ELA_JWT_H__
#define __ELA_JWT_H__

#include "ela_did.h"
#include "HDkey.h"

typedef struct JWTBuilder          JWTBuilder;

typedef struct JWS                 JWS;

/******************************************************************************
 * JWTBuilder.
 *****************************************************************************/

DID_API void JWTBuilder_Destroy(JWTBuilder *builder);

DID_API bool JWTBuilder_SetHeader(JWTBuilder *builder, const char *attr, const char *value);

DID_API bool JWTBuilder_SetClaim(JWTBuilder *builder, const char *key, const char *value);

DID_API bool JWTBuilder_SetClaimWithJson(JWTBuilder *builder, const char *key, const char *json);

DID_API bool JWTBuilder_SetClaimWithIntegar(JWTBuilder *builder, const char *key, long value);

DID_API bool JWTBuilder_SetClaimWithBoolean(JWTBuilder *builder, const char *key, bool value);

DID_API bool JWTBuilder_SetIssuer(JWTBuilder *builder, const char *issuer);

DID_API bool JWTBuilder_SetSubject(JWTBuilder *builder, const char *subject);

DID_API bool JWTBuilder_SetAudience(JWTBuilder *builder, const char *audience);

DID_API bool JWTBuilder_SetExpiration(JWTBuilder *builder, time_t expire);

DID_API bool JWTBuilder_SetNotBefore(JWTBuilder *builder, time_t nbf);

DID_API bool JWTBuilder_SetIssuedAt(JWTBuilder *builder, time_t iat);

DID_API bool JWTBuilder_SetId(JWTBuilder *builder, const char *jti);

DID_API const char *JWTBuilder_Compact(JWTBuilder *builder);

/******************************************************************************
 * JWTParser.
 *****************************************************************************/

DID_API JWS *JWTParser_Parse(const char *token);

/******************************************************************************
 * JWS.
 *****************************************************************************/

DID_API void JWS_Destroy(JWS *jws);

DID_API const char *JWS_GetHeader(JWS *jws, const char *attr);

DID_API const char *JWS_GetAlgorithm(JWS *jws);

DID_API const char *JWS_GetKeyId(JWS *jws);

DID_API const char *JWS_GetClaim(JWS *jws, const char *key);

DID_API long JWS_GetClaimAsInteger(JWS *jws, const char *key);

DID_API bool JWS_GetClaimAsBoolean(JWS *jws, const char *key);

DID_API const char *JWS_GetIssuer(JWS *jws);

DID_API const char *JWS_GetSubject(JWS *jws);

DID_API const char *JWS_GetAudience(JWS *jws);

DID_API const char *JWS_GetId(JWS *jws);

DID_API time_t JWS_GetExpiration(JWS *jws);

DID_API time_t JWS_GetNotBefore(JWS *jws);

DID_API time_t JWS_GetIssuedAt(JWS *jws);

#ifdef __cplusplus
}
#endif

#endif /* __ELA_JWT_H__ */
