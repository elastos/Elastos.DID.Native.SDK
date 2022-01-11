#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "entity.h"
#include "samples.h"
#include "assistadapter.h"

void IssueCredential()
{
    University *university = NULL;
    Student *student = NULL;
    Credential *vc = NULL;
    const char *data;

    printf("-----------------------------------------\nBeginning, issue credential ...\n");

    // Initializa the DID backend globally.
    if (AssistAdapter_Init("mainnet") == -1) {
        printf("[error] IssueCredential failed.\n");
        return;
    }

    university = University_Init("Elastos");
    if(!university) {
        printf("[error] IssueCredential failed.\n");
        return;
    }

    student = Student_Init("John Smith", "Male", "johnsmith@example.org");
    if(!student) {
        printf("[error] IssueCredential failed.\n");
        goto exit;
    }

    vc = University_IssuerDiplomaFor(university, student);
    if(!vc) {
        printf("[error] IssueCredential failed.\n");
        goto exit;
    }

    data = Credential_ToJson(vc, true);
    if(!data) {
        printf("[error] IssueCredential failed.\n");
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

    printf("Issue credential, end.\n");
    return;
}
