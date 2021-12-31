#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>

#include "ela_did.h"
#include "samples.h"

static void get_time(time_t *date, int n)
{
    struct tm *tm = NULL;

    *date = time(NULL);
    tm = gmtime(date);
    tm->tm_month += n;
    *date = mktime(tm);
}

void presentationInJWT()
{
    University *university = NULL;
    Student *student = NULL;
    Credential *vc = NULL;
    const char *data = NULL;
    Presentation *vp = NULL;
    time_t iat, nbf, exp;
    struct tm *tm = NULL;
    DIDDocument *doc = NULL;
    char id[ELA_MAX_DID_LEN] = {0};
    bool success;
    JWTBuilder *builder = NULL;
    JWT *jwt = NULL;

    // Initializa the DID backend globally
    if (AssistAdapter_Init("mainnet") == -1) {
        printf("presentationInJWT failed.\n");
        return;
    }

    university = University_Init("Elastos");
    if(!university) {
        printf("presentationInJWT failed.\n");
        return;
    }

    student = Student_Init("John Smith", "Male", "johnsmith@example.org");
    if(!student) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    //create diploma vc
    vc = University_IssuerDiplomaFor(university, student);
    if(!vc) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    data = Credential_ToJson(vc, true);
    if(!data) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    printf("The diploma credential:\n");
    printf("  %s\n", data);
    free((void*)data);
    printf("  Genuine: %s\n", Credential_IsGenuine(vc) == 1 ? "true" : "false");
    printf("  Expired: %s\n", Credential_IsExpired(vc) == 1 ? "true" : "false");
    printf("  Valid: %s\n", Credential_IsValid(vc) == 1 ? "true" : "false");

    if(Student_AddCredential(vc) == -1) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    //create selfclaimed vc
    vc = Student_CreateSelfProclaimedCredential(student);
    if (!vc) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    data = Credential_ToJson(vc, true);
    if(!data) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    printf("The profile credential:\n");
    printf("  %s\n", data);
    free((void*)data);
    printf("  Genuine: %s\n", Credential_IsGenuine(vc) == 1 ? "true" : "false");
    printf("  Expired: %s\n", Credential_IsExpired(vc) == 1 ? "true" : "false");
    printf("  Valid: %s\n", Credential_IsValid(vc) == 1 ? "true" : "false");

    if(Student_AddCredential(vc) == -1) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    //create presentation
    vc = NULL;
    vp = Student_CreatePresentation(student, "test", "873172f58701a9ee686f0630204fee59");
    if (!vp) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    data = Presentation_ToJson(vp, true);
    if (!data) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    printf("The verifiable presentation:\n");
    printf("  %s\n", data);
    printf("  Genuine: %s\n", Presentation_IsGenuine(vp) == 1 ? "true" : "false");
    printf("  Valid: %s\n", Presentation_IsValid(vp) == 1 ? "true" : "false");
    Presentation_Destroy(vp);
    vp = NULL;

    iat = time(NULL);
    nbf = iat;
    exp = iat;
    tm = gmtime(&exp);
    tm->tm_month += 3;
    exp = timegm(tm);

    // Create JWT token with presentation.
    doc = Student_GetDocument(student);
    if (!doc) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    builder = DIDDocument_GetJwtBuilder(doc);
    if (!builder) {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    success = JWTBuilder_SetSubject(builder, "JwtTest") &&
            JWTBuilder_SetId(builder, "test00000000") &&
            JWTBuilder_SetAudience(builder, DID_ToString(University_GetDid(university), id, sizeof(id))) &&
            JWTBuilder_SetIssuedAt(builder, iat) &&
            JWTBuilder_SetExpiration(builder, exp) &&
            JWTBuilder_SetNotBefore(builder, nbf) &&
            JWTBuilder_SetClaim(builder, "presentation", data);
    free((void*)data);
    if (!success) {
        JWTBuilder_Destroy(builder);
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    if (JWTBuilder_Sign(builder, NULL, storepass) == -1) {
        JWTBuilder_Destroy(builder);
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    const char *token = JWTBuilder_Compact(builder);
    JWTBuilder_Destroy(builder);
    if (!token)  {
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    printf("JWT Token:\n  %s\n", token);

    // Verify the token automatically
    jwt = DefaultJWSParser_Parse(token);
    if (!jwt) {
        free((void*)token);
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    // Get claims from the token
    const char *preJson = JWT_GetClaimAsJson(jwt, "presentation");
    JWT_Destroy(jwt);
    if (!preJson) {
        free((void*)token);
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    vp = Presentation_FromJson(preJson);
    free((void*)preJson);
    if (!vp) {
        free((void*)token);
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    data = Presentation_ToJson(vp);
    if (!data) {
        free((void*)token);
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    printf("Presentation from JWT:\n");
    printf("  %s\n", data);
    free((void*)data);
    printf("  Genuine: %s\n", Presentation_IsGenuine(vp) == 1 ? "true" : "false");
    printf("  Valid: %s\n", Presentation_IsValid(vp) == 1 ? "true" : "false");

    // Verify the token based on a DID
    // This will success, because the JWT was signed by the student
    JWSParser *jsp = DIDDocument_GetJwsParser(doc);
    DIDDocument_Destroy(doc);
    if (!jsp) {
        free((void*)token);
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    jwt = JWSParser_Parse(jsp, token);
    JWSParser_Destroy(jsp);
    if (!jwt) {
        free((void*)token);
        printf("presentationInJWT failed.\n");
        goto exit;
    }
    JWT_Destroy(jwt);

    doc = University_GetDocument(university);
    if (!doc) {
        free((void*)token);
        printf("presentationInJWT failed.\n");
        goto exit;
    }

    // This will failed, because the JWT was signed by the student not by the university
    jwt = JWSParser_Parse(jsp, token);
    free((void*)token);
    JWSParser_Destroy(jsp);
    if (jwt) {
        JWT_Destroy(jwt);
        printf("presentationInJWT failed.\n");
    }

exit:
    if(university)
        University_Deinit(university);
    if(student)
        Student_Deinit(student);
    if(vc)
        Credential_Destroy(vc);
    if(vp)
        Presentation_Destroy(vp);
    if (doc)
        DIDDocument_Destroy(doc);
    return;
}
