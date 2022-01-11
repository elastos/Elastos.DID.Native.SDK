#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "samples.h"

static void create_from_string(void)
{
    const char *urlString = "did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2#test";
    DIDURL *url = DIDURL_FromString(urlString, NULL);
    if (!url) {
        printf("[error] create_from_string failed.\n");
        return;
    }

    DIDURL_Destroy(url);
}

static void create_from_parts()
{
    char urlstr[ELA_MAX_DIDURL_LEN] = {0};

    DID *did = DID_New("did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2");
    if (!did) {
        printf("[error] create_from_parts failed.\n");
        return;
    }

    // create a url from a DID object and a relative url
    DIDURL *url = DIDURL_FromString("/vcs/abc?opt=false&value=1#test", did);
    if (!url) {
        printf("[error] create_from_parts failed.\n");
        DID_Destroy(did);
        return;
    }

    // output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2/vcs/abc?opt=false&value=1#test
    printf("%s\n", DIDURL_ToString(url, urlstr, sizeof(urlstr)));

    // output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2
    printf("%s\n", DID_ToString(DIDURL_GetDid(url), urlstr, sizeof(urlstr)));
    // output: /vcs/abc
    printf("%s\n", DIDURL_GetPath(url));
    // output: opt=false&value=1
    printf("%s\n", DIDURL_GetQueryString(url));
    // output: test
    printf("%s\n", DIDURL_GetFragment(url));

    DID_Destroy(did);
    DIDURL_Destroy(url);
}

void InitalizeDidurl(void)
{
    printf("-----------------------------------------\nBeginning, initalize didurl ...\n");
    create_from_string();
    create_from_parts();
    printf("Initalize didurl, end.\n");

}
