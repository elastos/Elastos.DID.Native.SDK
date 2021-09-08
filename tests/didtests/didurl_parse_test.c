#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <CUnit/Basic.h>
#include "ela_did.h"
#include "didurl.h"
#include "constant.h"

typedef struct Provider {
    const char *spec;
    uint8_t part;
} Provider;

typedef struct Check {
    const char *value;
    const char *err;
} Check;


static const char *TEST_DID = "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN";
static const char *TEST_PATH = "/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource";
static const char *TEST_QUERY = "?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A";
static const char *TEST_FRAGMENT = "#testfragment";

static Provider provideDIDURLs[] = {
    { "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN", 0x01 },
    { "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource", 0x01 | 0x02 },
    { "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A", 0x01 | 0x04 },
    { "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#testfragment", 0x01 | 0x08 },
    { "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource#testfragment", 0x01 | 0x02 | 0x08 },
    { "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A#testfragment", 0x01 | 0x04 | 0x08 },
    { "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A", 0x01 | 0x02 | 0x04 },
    { "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A#testfragment", 0x01 | 0x02 | 0x04 | 0x08 },

    { "/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource", 0x02 },
    { "?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A", 0x04 },
    { "#testfragment", 0x08 },
    { "/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource#testfragment", 0x02 | 0x08 },
    { "?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A#testfragment", 0x04 | 0x08 },
    { "/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A", 0x02 | 0x04 },
    { "/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A#testfragment", 0x02 | 0x04 | 0x08 },

    { "  \n \t did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN\t    \n", 0x01 },
    { "\t   \ndid:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource  \n \t", 0x01 | 0x02 },
    { "   did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A\n", 0x01 | 0x04 },
    { "\ndid:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#testfragment      ", 0x01 | 0x08 },
    { "\tdid:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource#testfragment  \n", 0x01 | 0x02 | 0x08 },
    { " did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A#testfragment\t", 0x01 | 0x04 | 0x08 },
    { "   did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A", 0x01 | 0x02 | 0x04 },
    { "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A#testfragment    ", 0x01 | 0x02 | 0x04 | 0x08 },

    { "  \t/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource ", 0x02 },
    { " \n \t ?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A   \n", 0x04 },
    { "   #testfragment\t", 0x08 },
    { " /path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource#testfragment    ", 0x02 | 0x08 },
    { "   ?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A#testfragment", 0x04 | 0x08 },
    { "/path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A  \n \t  ", 0x02 | 0x04 },
    { "   /path/to/the/test-%E6%B5%8B%E8%AF%95-2020/resource?qkey=qvalue&qkeyonly&hello=%E4%BD%A0%E5%A5%BD&test=true&a=%E5%95%8A#testfragment \n\t\t\n  ", 0x02 | 0x04 | 0x08 }
};

static int trim(const char *str, char *string, size_t size)
{
    int start = 0;
    int limit = strlen(str);

    // trim the leading and trailing spaces
    while (limit > 0 && *(str + limit - 1) <= ' ')
        limit--;        //eliminate trailing whitespace

    while (start < limit && *(str + start) <= ' ')
        start++;        // eliminate leading whitespace

    if (limit - start >= size)
        return -1;

    strncpy(string, str, limit - start);
    string[limit-start] = 0;
    return 0;
};

static void test_didurl(void)
{
    char refURLString[512] = {0}, difURLString[512] = {0};
    char id[ELA_MAX_DIDURL_LEN] = {0};
    DIDURL *url, *refURL, *difURL;
    DID *did, *test_did;
    const char *queryString, *value, *fragment;
    int pos;

    for (int i = 0; i < 30; i++) {
        Provider *provider = &provideDIDURLs[i];

        url = DIDURL_FromString(provider->spec, NULL);
        CU_ASSERT_PTR_NOT_NULL(url);

        *refURLString = 0;
        // getDid()
        if ((provider->part & 0x01) == 0x01) {
            did = DIDURL_GetDid(url);
            CU_ASSERT_PTR_NOT_NULL(did);

            test_did = DID_FromString(TEST_DID);
            CU_ASSERT_PTR_NOT_NULL(test_did);
            CU_ASSERT_EQUAL(1, DID_Equals(did, test_did));
            DID_Destroy(test_did);

            *id = 0;
            CU_ASSERT_PTR_NOT_NULL(DID_ToString(did, id, sizeof(id)));
            CU_ASSERT_STRING_EQUAL(TEST_DID, id);

            strcat(refURLString, TEST_DID);
        } else {
            CU_ASSERT_PTR_NULL(DIDURL_GetDid(url));
        }

        // getPath()
        if ((provider->part & 0x02) == 0x02) {
            const char *path = DIDURL_GetPath(url);
            CU_ASSERT_PTR_NOT_NULL(path);
            CU_ASSERT_STRING_EQUAL(TEST_PATH, path);

            strcat(refURLString, TEST_PATH);
        } else {
            CU_ASSERT_PTR_NULL(DIDURL_GetPath(url));
        }

        // getQuery(), getQueryString(), getQueryParameter(), hasQueryParameter()
        if ((provider->part & 0x04) == 0x04) {
            queryString = DIDURL_GetQueryString(url);
            CU_ASSERT_PTR_NOT_NULL(queryString);
            CU_ASSERT_STRING_EQUAL(TEST_QUERY + 1, queryString);
            CU_ASSERT_EQUAL(5, DIDURL_GetQuerySize(url));

            value = DIDURL_GetQueryParameter(url, "qkey");
            CU_ASSERT_PTR_NOT_NULL(value);
            CU_ASSERT_STRING_EQUAL("qvalue", value);
            free((void*)value);

            value = DIDURL_GetQueryParameter(url, "test");
            CU_ASSERT_PTR_NOT_NULL(value);
            CU_ASSERT_STRING_EQUAL("true", value);
            free((void*)value);

            value = DIDURL_GetQueryParameter(url, "qkeyonly");
            CU_ASSERT_PTR_NULL(value);

            //expect(decodeURIComponent(url.getQueryParameter("hello"))).toEqual("你好");
            //expect(decodeURIComponent(url.getQueryParameter("a"))).toEqual("啊");
            CU_ASSERT_EQUAL(1, DIDURL_HasQueryParameter(url, "qkeyonly"));
            CU_ASSERT_EQUAL(1, DIDURL_HasQueryParameter(url, "qkey"));
            CU_ASSERT_EQUAL(1, DIDURL_HasQueryParameter(url, "test"));
            CU_ASSERT_EQUAL(1, DIDURL_HasQueryParameter(url, "hello"));
            CU_ASSERT_EQUAL(1, DIDURL_HasQueryParameter(url, "a"));
            CU_ASSERT_EQUAL(0, DIDURL_HasQueryParameter(url, "notexist"));

            strcat(refURLString, TEST_QUERY);
        } else {
            CU_ASSERT_PTR_NULL(DIDURL_GetQueryString(url));
            CU_ASSERT_EQUAL(0, DIDURL_GetQuerySize(url));

            CU_ASSERT_PTR_NULL(DIDURL_GetQueryParameter(url, "qkey"));
            CU_ASSERT_EQUAL(0, DIDURL_HasQueryParameter(url, "qkey"));
        }

        // getFragment()
        if ((provider->part & 0x08) == 0x08) {
            fragment = DIDURL_GetFragment(url);
            CU_ASSERT_PTR_NOT_NULL(fragment);
            CU_ASSERT_STRING_EQUAL(TEST_FRAGMENT + 1, fragment);
            strcat(refURLString, TEST_FRAGMENT);
        } else {
            CU_ASSERT_PTR_NOT_NULL(DIDURL_GetFragment(url));
        }

        refURL = DIDURL_FromString(refURLString, NULL);
        CU_ASSERT_PTR_NOT_NULL(refURL);

        // toString()
        *id = 0;
        CU_ASSERT_PTR_NOT_NULL(DIDURL_ToString(url, id, sizeof(id)));
        CU_ASSERT_STRING_EQUAL(refURLString, id);

        // equals()
        CU_ASSERT_EQUAL(1, DIDURL_Equals(url, refURL));

        *id = 0;
        CU_ASSERT_PTR_NOT_NULL(DIDURL_ToString(url, id, sizeof(id)));
        CU_ASSERT_STRING_EQUAL(refURLString, id);

        strcpy(difURLString, refURLString);
        strcat(difURLString, "_abc");

        difURL = DIDURL_FromString(difURLString, NULL);
        CU_ASSERT_PTR_NOT_NULL(difURL);

        CU_ASSERT_EQUAL(0, DIDURL_Equals(url, difURL));
        *id = 0;
        CU_ASSERT_PTR_NOT_NULL(DIDURL_ToString(url, id, sizeof(id)));
        CU_ASSERT_STRING_NOT_EQUAL(difURLString, id);

        // hashCode()
        //expect(url.hashCode()).toBe(refURL.hashCode());
        //expect(url.hashCode()).not.toBe(difURL.hashCode());

        DIDURL_Destroy(difURL);
        DIDURL_Destroy(url);
        DIDURL_Destroy(refURL);
    }
}

static void test_didurl_withcontext(void)
{
    char refURLString[512] = {0}, id1[ELA_MAX_DIDURL_LEN], id2[ELA_MAX_DIDURL_LEN];
    char id3[ELA_MAX_DIDURL_LEN] = {0}, difURLString[512] = {0};
    DID *context, *test_did, *did;
    DIDURL *url, *refURL, *difURL;
    const char *path, *queryString, *value, *fragment;

    context = DID_FromString("did:elastos:foobar");
    CU_ASSERT_PTR_NOT_NULL(context);

    for (int i = 0; i < 30; i++) {
        Provider *provider = &provideDIDURLs[i];

        url = DIDURL_FromString(provider->spec, context);
        CU_ASSERT_PTR_NOT_NULL(url);

        *refURLString = 0;
        // getDid()
        did = DIDURL_GetDid(url);
        CU_ASSERT_PTR_NOT_NULL(did);
        *id1 = 0;
        CU_ASSERT_PTR_NOT_NULL(DID_ToString(did, id1, sizeof(id1)));

        if ((provider->part & 0x01) == 0x01) {
            test_did = DID_FromString(TEST_DID);
            CU_ASSERT_PTR_NOT_NULL(test_did);
            CU_ASSERT_EQUAL(1, DID_Equals(did, test_did));
            DID_Destroy(test_did);

            CU_ASSERT_STRING_EQUAL(TEST_DID, id1);

            strcat(refURLString, TEST_DID);
        } else {
            CU_ASSERT_EQUAL(1, DID_Equals(did, context));

            *id2 = 0;
            CU_ASSERT_PTR_NOT_NULL(DID_ToString(context, id2, sizeof(id2)));
            CU_ASSERT_STRING_EQUAL(id1, id2)

            strcat(refURLString, id2);
        }

        // getPath()
        if ((provider->part & 0x02) == 0x02) {
            path = DIDURL_GetPath(url);
            CU_ASSERT_PTR_NOT_NULL(path);
            CU_ASSERT_STRING_EQUAL(TEST_PATH, path);

            strcat(refURLString, TEST_PATH);
        } else {
            CU_ASSERT_PTR_NULL(DIDURL_GetPath(url))
        }

        // getQuery(), getQueryString(), getQueryParameter(), hasQueryParameter()
        if ((provider->part & 0x04) == 0x04) {
            queryString = DIDURL_GetQueryString(url);
            CU_ASSERT_PTR_NOT_NULL(queryString);
            CU_ASSERT_STRING_EQUAL(TEST_QUERY + 1, queryString);
            CU_ASSERT_EQUAL(5, DIDURL_GetQuerySize(url));

            value = DIDURL_GetQueryParameter(url, "qkey");
            CU_ASSERT_PTR_NOT_NULL(value);
            CU_ASSERT_STRING_EQUAL("qvalue", value);
            free((void*)value);

            value = DIDURL_GetQueryParameter(url, "test");
            CU_ASSERT_PTR_NOT_NULL(value);
            CU_ASSERT_STRING_EQUAL("true", value);
            free((void*)value);

            //expect(decodeURIComponent(url.getQueryParameter("hello"))).toEqual("你好");
            //expect(decodeURIComponent(url.getQueryParameter("a"))).toEqual("啊");

            value = DIDURL_GetQueryParameter(url, "qkeyonly");
            CU_ASSERT_PTR_NULL(value);

            CU_ASSERT_EQUAL(1, DIDURL_HasQueryParameter(url, "qkeyonly"));
            CU_ASSERT_EQUAL(1, DIDURL_HasQueryParameter(url, "qkey"));
            CU_ASSERT_EQUAL(1, DIDURL_HasQueryParameter(url, "test"));
            CU_ASSERT_EQUAL(1, DIDURL_HasQueryParameter(url, "hello"));
            CU_ASSERT_EQUAL(1, DIDURL_HasQueryParameter(url, "a"));
            CU_ASSERT_EQUAL(0, DIDURL_HasQueryParameter(url, "notexist"));

            strcat(refURLString, TEST_QUERY);
        } else {
            CU_ASSERT_PTR_NULL(DIDURL_GetQueryString(url));
            CU_ASSERT_EQUAL(0, DIDURL_GetQuerySize(url));

            CU_ASSERT_PTR_NULL(DIDURL_GetQueryParameter(url, "qkey"));
            CU_ASSERT_EQUAL(0, DIDURL_HasQueryParameter(url, "qkey"));
        }

        // getFragment()
        if ((provider->part & 0x08) == 0x08) {
            fragment = DIDURL_GetFragment(url);
            CU_ASSERT_PTR_NOT_NULL(fragment);
            CU_ASSERT_STRING_EQUAL(TEST_FRAGMENT + 1, fragment);
            strcat(refURLString, TEST_FRAGMENT);
        } else {
            CU_ASSERT_PTR_NOT_NULL(DIDURL_GetFragment(url));
        }

        refURL = DIDURL_FromString(refURLString, NULL);
        CU_ASSERT_PTR_NOT_NULL(refURL);

        // toString()
        *id1 = 0;
        CU_ASSERT_PTR_NOT_NULL(DIDURL_ToString(url, id1, sizeof(id1)));
        CU_ASSERT_STRING_EQUAL(refURLString, id1);

        // equals()
        CU_ASSERT_EQUAL(1, DIDURL_Equals(url, refURL));

        *id1 = 0;
        CU_ASSERT_PTR_NOT_NULL(DIDURL_ToString(url, id1, sizeof(id1)));
        CU_ASSERT_STRING_EQUAL(refURLString, id1);

        strcpy(difURLString, refURLString);
        strcat(difURLString, "_abc");

        difURL = DIDURL_FromString(difURLString, NULL);
        CU_ASSERT_PTR_NOT_NULL(difURL);

        CU_ASSERT_EQUAL(0, DIDURL_Equals(url, difURL));
        *id1 = 0;
        CU_ASSERT_PTR_NOT_NULL(DIDURL_ToString(url, id1, sizeof(id1)));
        CU_ASSERT_STRING_NOT_EQUAL(difURLString, id1);

        // hashCode()
        //expect(url.hashCode()).toBe(refURL.hashCode());
        //expect(url.hashCode()).not.toBe(difURL.hashCode());
        DIDURL_Destroy(difURL);
        DIDURL_Destroy(url);
        DIDURL_Destroy(refURL);
    }
}

static void test_compatible_with_plainfragment(void)
{
    char testURL[ELA_MAX_DIDURL_LEN], id[ELA_MAX_DIDURL_LEN];
    DIDURL *url1, *url2, *url;
    const char *fragment;
    DID *test_did;

    strcpy(testURL, TEST_DID);
    strcat(testURL, "#test");

    url1 = DIDURL_FromString(testURL, NULL);
    CU_ASSERT_PTR_NOT_NULL(url1);

    *id = 0;
    CU_ASSERT_PTR_NOT_NULL(DIDURL_ToString(url1, id, sizeof(id)));
    CU_ASSERT_STRING_EQUAL(testURL, id);

    fragment = DIDURL_GetFragment(url1);
    CU_ASSERT_PTR_NOT_NULL(fragment);
    CU_ASSERT_STRING_EQUAL("test", fragment);

    test_did = DID_FromString(TEST_DID);
    CU_ASSERT_PTR_NOT_NULL(test_did);

    url2 = DIDURL_FromString("#test", test_did);
    CU_ASSERT_PTR_NOT_NULL(url2);

    *id = 0;
    CU_ASSERT_PTR_NOT_NULL(DIDURL_ToString(url2, id, sizeof(id)));
    CU_ASSERT_STRING_EQUAL(testURL, id);

    fragment = DIDURL_GetFragment(url2);
    CU_ASSERT_PTR_NOT_NULL(fragment);
    CU_ASSERT_STRING_EQUAL("test", fragment);

    CU_ASSERT_EQUAL(1, DIDURL_Equals(url1, url2));
    DIDURL_Destroy(url1);
    DIDURL_Destroy(url2);

    url1 = DIDURL_FromString("test", NULL);
    CU_ASSERT_PTR_NOT_NULL(url1);

    *id = 0;
    CU_ASSERT_PTR_NOT_NULL(DIDURL_ToString(url1, id, sizeof(id)));
    CU_ASSERT_STRING_EQUAL(id, "#test");

    DIDURL_Destroy(url1);
    DID_Destroy(test_did);
}

static void test_parseurl_with_specialchars(void)
{
    char urlString[256], id[ELA_MAX_DIDURL_LEN];

    const char *specs[] = {
        "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld",
        "did:elastos:foobar/p.a_t-h/to-/resource_?te_st=tr_ue&ke.y=va_lue&na_me=foobar#helloworld_",
        "did:elastos:foobar/path_/to./resource_?test-=true.&ke.y_=va_lue.&name_=foobar.#helloworld_-.",
        "did:elastos:foobar/pa...th/to.../resource_-_?test-__.=true...&ke...y_---=va_lue.&name_=foo...bar.#helloworld_-.",
        "did:elastos:foobar/path/to/resou___rce?test=tr----ue&key=va----lue&name=foobar#hello....---world__",
    };

    for (int i = 0; i < 5; i++) {
        const char *spec = specs[i];

        DIDURL *url = DIDURL_FromString(spec, NULL);
        CU_ASSERT_PTR_NOT_NULL(url);

        DID *did = DID_NewWithMethod("elastos", "foobar");
        CU_ASSERT_PTR_NOT_NULL(did);

        CU_ASSERT_PTR_NOT_NULL(DIDURL_GetDid(url));
        CU_ASSERT_EQUAL(1, DID_Equals(DIDURL_GetDid(url), did));

        CU_ASSERT_NOT_EQUAL(-1, trim(spec, urlString, sizeof(urlString)));

        CU_ASSERT_PTR_NOT_NULL(DIDURL_ToString(url, id, sizeof(id)));
        CU_ASSERT_STRING_EQUAL(id, urlString);

        DIDURL_Destroy(url);
        DID_Destroy(did);
    }
}

static void test_parse_wrongurl(void)
{
    Check checks[] = {
        { "did1:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 4" },
        { "did:unknown:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld", "Invalid did at: 0" },
        { "did:elastos:foobar:/path/to/resource?test=true&key=value&name=foobar#helloworld", "Invalid did at: 0" },
        { "did:elastos:foobar/-path/to/resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 19" },
        { "did:elastos:foobar/._path/to/resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 19" },
        { "did:elastos:foobar/-._path/to/resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 19" },
        { "did:elastos:foobar/path/-to/resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 24" },
        { "did:elastos:foobar/path/.to/resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 24" },
        { "did:elastos:foobar/path/_to/resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 24" },
        { "did:elastos:foobar/path/*to/resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 24" },
        { "did:elastos:foobar/path/$to/resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 24" },
        { "did:elastos:foobar/path./$to/resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 25" },
        { "did:elastos:foobar/path/%to/resource?test=true&key=value&name=foobar#helloworld", "Invalid hex char at: 25" },
        { "did:elastos:foobar/path/to//resource?test=true&key=value&name=foobar#helloworld", "Invalid char at: 27" },
        { "did:elastos:foobar/path/to/resource?test=true&&&key=value&name=foobar#helloworld", "Invalid char at: 46" },
        { "did:elastos:foobar/path/to/resource?test=true&_key=value&name=foobar#helloworld", "Invalid char at: 46" },
        { "did:elastos:foobar/path/to/resource?test=true&*key=value&name=foobar#helloworld", "Invalid char at: 46" },
        { "did:elastos:foobar/path/to/resource?test=true&-key=value&name=foobar#helloworld", "Invalid char at: 46" },
        { "did:elastos:foobar/path/to/resource?test=true.&-key=value&name=foobar#helloworld", "Invalid char at: 47" },
        { "did:elastos:foobar/path/to/resource%20?test=true.&-key=value&name=foobar#helloworld", "Invalid char at: 50" },
        { "did:elastos:foobar/path/to/resource?test=true&key=value&name==foobar#helloworld", "Invalid char at: 61" },
        { "did:elastos:foobar/path/to/resource?test=true&key=value&name%=foobar#helloworld", "Invalid hex char at: 61" },
        { "did:elastos:foobar/path/to/resource?test=true&key=va--lue&name%=foobar#helloworld", "Invalid hex char at: 63" },
        { "did:elastos:foobar/path/to/resource?test=t.rue&ke.y=val_ue&nam-e=^foobar#helloworld", "Invalid char at: 65" },
        { "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar*#helloworld", "Invalid char at: 67" },
        { "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar?#helloworld", "Invalid char at: 67" },
        { "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar##helloworld", "Invalid char at: 68" },
        { "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld*", "Invalid char at: 78" },
        { "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld&", "Invalid char at: 78" },
        { "did:elastos:foobar/path/to/resource?test=true&key=value&name=foobar#helloworld%", "Invalid char at: 78" },
    };

    for (int i = 0; i < 30; i++) {
        CU_ASSERT_PTR_NULL(DIDURL_FromString(checks[i].value, NULL));
        CU_ASSERT_STRING_EQUAL(checks[i].err, DIDError_GetLastErrorMessage());
    }

}

static void test_parsewrongurl_with_padding(void)
{
    CU_ASSERT_PTR_NULL(DID_FromString("       \t did:elastos:foobar/-path/to/resource?test=true&key=value&name=foobar#helloworld"));
}

static void test_parse_empty(void)
{
    CU_ASSERT_PTR_NULL(DIDURL_FromString(NULL, NULL));
    CU_ASSERT_PTR_NULL(DIDURL_FromString("", NULL));
    CU_ASSERT_PTR_NULL(DIDURL_FromString("           ", NULL));
}

static int didurl_test_parse_suite_init(void)
{
    return 0;
}

static int didurl_test_parse_suite_cleanup(void)
{
    return 0;
}

static CU_TestInfo cases[] = {
    {  "test_didurl",                        test_didurl                        },
    {  "test_didurl_withcontext",            test_didurl_withcontext            },
    {  "test_compatible_with_plainfragment", test_compatible_with_plainfragment },
    {  "test_parseurl_with_specialchars",    test_parseurl_with_specialchars    },
    {  "test_parse_wrongurl",                test_parse_wrongurl                },
    {  "test_parsewrongurl_with_padding",    test_parsewrongurl_with_padding    },
    {  "test_parse_empty",                   test_parse_empty                   },
    {   NULL,                                   NULL                            }
};

static CU_SuiteInfo suite[] = {
    { "didurl parse test", didurl_test_parse_suite_init, didurl_test_parse_suite_cleanup, NULL, NULL, cases },
    {  NULL,               NULL,                         NULL,                            NULL, NULL, NULL  }
};

CU_SuiteInfo* didurl_parse_test_suite_info(void)
{
    return suite;
}
