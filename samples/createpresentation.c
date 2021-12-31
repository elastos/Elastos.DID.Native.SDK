#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "entity.h"
#include "samples.h"

void createPresentation(void)
{
    University *university = NULL;
    Student *student = NULL;
    Credential *vc = NULL;
    const char *data = NULL;
    Presentation *vp = NULL;

    if (AssistAdapter_Init("mainnet") == -1) {
        printf("createPresentation failed.\n");
        return;
    }

    university = University_Init("Elastos");
    if(!university) {
        printf("createPresentation failed.\n");
        return;
    }

    student = Student_Init("John Smith", "Male", "johnsmith@example.org");
    if(!student) {
        printf("createPresentation failed.\n");
        goto exit;
    }

    vc = University_IssuerDiplomaFor(university, student);
    if(!vc) {
        printf("createPresentation failed.\n");
        goto exit;
    }

    data = Credential_ToJson(vc, true);
    if(!data) {
        printf("createPresentation failed.\n");
        goto exit;
    }

    printf("The diploma credential:\n");
    printf("  %s\n", data);
    free((void*)data);
    printf("  Genuine: %s\n", Credential_IsGenuine(vc) == 1 ? "true" : "false");
    printf("  Expired: %s\n", Credential_IsExpired(vc) == 1 ? "true" : "false");
    printf("  Valid: %s\n", Credential_IsValid(vc) == 1 ? "true" : "false");

    if(Student_AddCredential(vc) == -1) {
        printf("createPresentation failed.\n");
        goto exit;
    }

    vc = Student_CreateSelfProclaimedCredential(student);
    if (!vc) {
        printf("createPresentation failed.\n");
        goto exit;
    }

    data = Credential_ToJson(vc, true);
    if(!data) {
        printf("createPresentation failed.\n");
        goto exit;
    }

    printf("The profile credential:\n");
    printf("  %s\n", data);
    free((void*)data);
    printf("  Genuine: %s\n", Credential_IsGenuine(vc) == 1 ? "true" : "false");
    printf("  Expired: %s\n", Credential_IsExpired(vc) == 1 ? "true" : "false");
    printf("  Valid: %s\n", Credential_IsValid(vc) == 1 ? "true" : "false");

    if(Student_AddCredential(vc) == -1) {
        printf("createPresentation failed.\n");
        goto exit;
    }

    vc = NULL;
    vp = Student_CreatePresentation(student, "test", "873172f58701a9ee686f0630204fee59");
    if (!vp) {
        printf("createPresentation failed.\n");
        goto exit;
    }

    data = Presentation_ToJson(vp, true);
    if (!data) {
        printf("createPresentation failed.\n");
        goto exit;
    }

    printf("The verifiable presentation:\n");
    printf("  %s\n", data);
    free((void*)data);
    printf("  Genuine: %s\n", Presentation_IsGenuine(vp) == 1 ? "true" : "false");
    printf("  Valid: %s\n", Presentation_IsValid(vp) == 1 ? "true" : "false");

exit:
    if(university)
        University_Deinit(university);
    if(student)
        Student_Deinit(student);
    if(vc)
        Credential_Destroy(vc);
    if(vp)
        Presentation_Destroy(vp);

    return;
}