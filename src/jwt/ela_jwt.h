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

/**
 * \~English
 * JWT is from parsing jwt token，signing the given plaintext within the given header.
 */
typedef struct JWT                 JWT;

/******************************************************************************
 * JWTBuilder.
 *****************************************************************************/

/**
 * \~English
 * Destroy the JWTBuilder.
 *
 * @param
 *      builder             [in] The handle to JWTBuilder.
 */
DID_API void JWTBuilder_Destroy(JWTBuilder *builder);

/**
 * \~English
 * Set the header of JWTBuilder.
 *
 * @param
 *      builder     [in] The handle to JWTBuilder.
 * @param
 *      attr        [in] The key to header.
 * @param
 *      value       [in] The value to header.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetHeader(JWTBuilder *builder, const char *attr, const char *value);

/**
 * \~English
 * Set the claim(body elem) of JWTBuilder.
 *
 * @param
 *      builder     [in] The handle to JWTBuilder.
 * @param
 *      key         [in] The key to claim.
 * @param
 *      value       [in] The value to claim.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetClaim(JWTBuilder *builder, const char *key, const char *value);

/**
 * \~English
 * Set the claim(body elem) of JWTBuilder with json value.
 *
 * @param
 *      builder     [in] The handle to JWTBuilder.
 * @param
 *      key         [in] The key to claim.
 * @param
 *      json        [in] The json string to claim.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetClaimWithJson(JWTBuilder *builder, const char *key, const char *json);

/**
 * \~English
 * Set the claim(body elem) of JWTBuilder with integar value.
 *
 * @param
 *      builder      [in] The handle to JWTBuilder.
 * @param
 *      key          [in] The key to claim.
 * @param
 *      value        [in] The integar value to claim.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetClaimWithIntegar(JWTBuilder *builder, const char *key, long value);

/**
 * \~English
 * Set the claim(body elem) of JWTBuilder with boolean value.
 *
 * @param
 *      builder      [in] The handle to JWTBuilder.
 * @param
 *      key          [in] The key to claim.
 * @param
 *      value        [in] The boolean value to claim.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetClaimWithBoolean(JWTBuilder *builder, const char *key, bool value);

/**
 * \~English
 * Set JWT issuer.
 *
 * @param
 *      builder         [in] The handle to JWTBuilder.
 * @param
 *      issuer          [in] The issuer value.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetIssuer(JWTBuilder *builder, const char *issuer);

/**
 * \~English
 * Set JWT subject.
 *
 * @param
 *      builder         [in] The handle to JWTBuilder.
 * @param
 *      subject          [in] The subject value.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetSubject(JWTBuilder *builder, const char *subject);

/**
 * \~English
 * Set JWT audience.
 *
 * @param
 *      builder         [in] The handle to JWTBuilder.
 * @param
 *      audience        [in] The audience value.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetAudience(JWTBuilder *builder, const char *audience);

/**
 * \~English
 * Set JWT expiration.
 *
 * @param
 *      builder         [in] The handle to JWTBuilder.
 * @param
 *      expire          [in] The expire value.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetExpiration(JWTBuilder *builder, time_t expire);

/**
 * \~English
 * Set JWT 'nbf' value.
 *
 * @param
 *      builder         [in] The handle to JWTBuilder.
 * @param
 *      nbf             [in] The 'nbf' value.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetNotBefore(JWTBuilder *builder, time_t nbf);

/**
 * \~English
 * Set JWT issued time.
 *
 * @param
 *      builder         [in] The handle to JWTBuilder.
 * @param
 *      iat             [in] The 'iat' value.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetIssuedAt(JWTBuilder *builder, time_t iat);

/**
 * \~English
 * Set JWT id.
 *
 * @param
 *      builder         [in] The handle to JWTBuilder.
 * @param
 *      jti             [in] The Id value.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
DID_API bool JWTBuilder_SetId(JWTBuilder *builder, const char *jti);

/**
 * \~English
 * Sign the jwtbuilder header and body.
 *
 * @param
 *      builder             [in] The handle to JWTBuilder.
 * @param
 *      keyid               [in] The sign key.
 * @param
 *      storepass           [in] The password for DIDStore.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
DID_API int JWTBuilder_Sign(JWTBuilder *builder, DIDURL *keyid, const char *storepass);

/**
 * \~English
 * Get token from compacting JWTBuilder.
 *
 * @param
 *      builder         [in] The handle to JWTBuilder.
 * @return
 *      If no error occurs, return token string. Otherwise, return NULL.
 *      Free the return value after using it.
 */
DID_API const char *JWTBuilder_Compact(JWTBuilder *builder);

/**
 * \~English
 * Reset header and body of JWTbuilder except 'alg', 'kid' and 'iss'.
 *
 * @param
 *      builder         [in] The handle to JWTBuilder.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
DID_API int JWTBuilder_Reset(JWTBuilder *builder);

/******************************************************************************
 * JWTParser/JWSParser.
 *****************************************************************************/
/**
 * \~English
 * Default parser for JWT only.
 *
 * @param
 *      token            [in] The token string.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
DID_API JWT *JWTParser_Parse(const char *token);
/**
 * \~English
 * Default parser for JWS only.
 *
 * @param
 *      token            [in] The token string.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
DID_API JWT *DefaultJWSParser_Parse(const char *token);
/**
 * \~English
 * Parse jwt token.
 *
 * @param
 *      parser           [in] The handle to JWTParser.
 * @param
 *      token            [in] The token string.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
DID_API JWT *JWSParser_Parse(JWSParser *parser, const char *token);
/**
 * \~English
 * Destroy the JWTParser.
 *
 * @param
 *      parser             [in] The handle to JWTParser.
 */
DID_API void JWSParser_Destroy(JWSParser *parser);

/******************************************************************************
 * JWT.
 *****************************************************************************/

/**
 * \~English
 * Destroy the JWT.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 */
DID_API void JWT_Destroy(JWT *jwt);

/**
 * \~English
 * Get header value by header key.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @param
 *      attr            [in] The key to header.
 * @return
 *      If no error occurs, return value string. Otherwise, return NULL.
 */
DID_API const char *JWT_GetHeader(JWT *jwt, const char *attr);

/**
 * \~English
 * Get algorithm string.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @return
 *      If no error occurs, return algorithm string. Otherwise, return NULL.
 */
DID_API const char *JWT_GetAlgorithm(JWT *jwt);

/**
 * \~English
 * Get sign key.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @return
 *      If no error occurs, return key string. Otherwise, return NULL.
 */
DID_API const char *JWT_GetKeyId(JWT *jwt);

/**
 * \~English
 * Get claim from JWT.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @param
 *      key             [in] The key to claim.
 * @return
 *      If no error occurs, return value string. Otherwise, return NULL.
 */
DID_API const char *JWT_GetClaim(JWT *jwt, const char *key);

/**
 * \~English
 * Get claim from JWT.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @param
 *      key             [in] The key to claim.
 * @return
 *      If no error occurs, return value json string. Otherwise, return NULL.
 *      Free the return value after using it.
 */
DID_API const char *JWT_GetClaimAsJson(JWT *jwt, const char *key);

/**
 * \~English
 * Get integar value of claim by key value.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @param
 *      key             [in] The key to claim.
 * @return
 *      If no error occurs, return integar value. Otherwise, return 0.
 */
DID_API long JWT_GetClaimAsInteger(JWT *jwt, const char *key);

/**
 * \~English
 * Get boolean value of claim by key value.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @param
 *      key             [in] The key to claim.
 * @return
 *      If no error occurs, return boolean value. Otherwise, return false.
 */
DID_API bool JWT_GetClaimAsBoolean(JWT *jwt, const char *key);

/**
 * \~English
 * Get jwt issuer.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @return
 *      If no error occurs, return issuer string. Otherwise, return NULL.
 */
DID_API const char *JWT_GetIssuer(JWT *jwt);

/**
 * \~English
 * Get jwt subject.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @return
 *      If no error occurs, return subject string. Otherwise, return NULL.
 */
DID_API const char *JWT_GetSubject(JWT *jwt);

/**
 * \~English
 * Get jwt audience.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @return
 *      If no error occurs, return audience string. Otherwise, return NULL.
 */
DID_API const char *JWT_GetAudience(JWT *jwt);

/**
 * \~English
 * Get jwt id.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @return
 *      If no error occurs, return id string. Otherwise, return NULL.
 */
DID_API const char *JWT_GetId(JWT *jwt);

/**
 * \~English
 * Get jwt expire time.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @return
 *      If no error occurs, return expire time. Otherwise, return 0.
 */
DID_API time_t JWT_GetExpiration(JWT *jwt);

/**
 * \~English
 * Get jwt not before time.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @return
 *      If no error occurs, return not before time. Otherwise, return 0.
 */
DID_API time_t JWT_GetNotBefore(JWT *jwt);

/**
 * \~English
 * Get jwt issued time.
 *
 * @param
 *      jwt             [in] The handle to JWT.
 * @return
 *      If no error occurs, return issued time. Otherwise, return 0.
 */
DID_API time_t JWT_GetIssuedAt(JWT *jwt);

#ifdef __cplusplus
}
#endif

#endif /* __ELA_JWT_H__ */
