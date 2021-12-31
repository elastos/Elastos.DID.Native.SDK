#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "entity.h"
#include "samples.h"

void issueCredential()
{
    University *university = NULL;
    Student *student = NULL;
    Credential *vc = NULL;
    const char *data;

    // Initializa the DID backend globally.
    if (AssistAdapter_Init("mainnet") == -1) {
        printf("issueCredential failed.\n");
        return;
    }

    university = University_Init("Elastos");
    if(!university) {
        printf("issueCredential failed.\n");
        return;
    }

    student = Student_Init("John Smith", "Male", "johnsmith@example.org");
    if(!student) {
        printf("issueCredential failed.\n");
        goto exit;
    }

    vc = University_IssuerDiplomaFor(university, student);
    if(!vc) {
        printf("issueCredential failed.\n");
        goto exit;
    }

    data = Credential_ToJson(vc, true);
    if(!data) {
        printf("issueCredential failed.\n");
        goto exit;
    }

    printf("The diploma credential:\n");
    printf("  %s\n", data);
    free((void*)data);
    printf("  Genuine: %s\n", Credential_IsGenuine(vc) == 1 ? "true" : "false");
    printf("  Expired: %s\n", Credential_IsExpired(vc) == 1 ? "true" : "false");
    printf("  Valid: %s\n", Credential_IsValid(vc) == 1 ? "true" : "false");

exit:
    if(university)
        University_Deinit(university);
    if(student)
        Student_Deinit(student);
    if(vc)
        Credential_Destroy(vc);
    return;
}
