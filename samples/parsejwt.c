#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>
#include <CUnit/Basic.h>
#include <time.h>
#include <crystal.h>

#include "ela_did.h"
#include "ela_jwt.h"
#include "samples.h"

void parseJWT()
{
    JWT *jwt;

    // Initializa the DID backend globally.
    if (AssistAdapter_Init("mainnet") == -1) {
        printf("parseJWT failed.\n");
        return;
    }

    const char *token = "eyJhbGciOiAiRVMyNTYiLCAiY3R5cCI6ICJqc29uIiwgImxpYnJhcnkiOiAiRWxhc3RvcyBESUQiLCAidHlwIjogIkpXVCIsICJ2ZXJzaW9uIjogIjEuMCIsICJraWQiOiAiZGlkOmVsYXN0b3M6aVdGQVVZaFRhMzVjMWZQZTNpQ0p2aWhaSHg2cXV1bW55bSNrZXkyIn0.eyJpc3MiOiJkaWQ6ZWxhc3RvczppV0ZBVVloVGEzNWMxZlBlM2lDSnZpaFpIeDZxdXVtbnltIiwic3ViIjoiSnd0VGVzdCIsImp0aSI6IjAiLCJhdWQiOiJUZXN0IGNhc2VzIiwiaWF0IjoxNjM4MTY3NjM5LCJleHAiOjE3MDEyMTA4MzksIm5iZiI6MTYwNjYwMjgzOSwiZm9vIjoiYmFyIiwib2JqZWN0Ijp7ImhlbGxvIjoid29ybGQiLCJ0ZXN0IjoidHJ1ZSJ9LCJmaW5pc2hlZCI6ZmFsc2V9.h0hLrePTLkekxDTv6fqg6NqlDTEcatcIa-LMZD0GEXMWnX3dmzv6XRmfwEX8u_dCFGjFQlUUlYhEgmvtt2cscA";
    ParseJWT.printJwt(token);

    jwt = DefaultJWSParser_Parse(token);
    if (!jwt)  {
        printf("parseJWT failed.\n");
        return;
    }

    JWT_Destroy(jwt);
}