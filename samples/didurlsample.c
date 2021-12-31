#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "samples.h"

static void createFromString(void)
{
    const char *urlString = "did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2#test";
    DIDURL *url = DIDURL_FromString(urlString);
    if (!url) {
        printf("createFromString failed.\n");
        return;
    }

    DIDURL_Destroy(url);
}

static void createFromParts()
{
    char urlstr[ELA_MAX_DIDURL_LEN] = {0};

    DID *did = DID_New("did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2");
    if (!did) {
        printf("createFromParts failed.\n", );
        return;
    }

    // create a url from a DID object and a relative url
    DIDURL *url = DIDURL_FromString("/vcs/abc?opt=false&value=1#test", did);
    if (!url) {
        printf("createFromParts failed.\n", );
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

void initDidurl(void)
{
    createFromString();
    createFromParts();

}
