#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>
#include <CUnit/Basic.h>
#include <crystal.h>

#include "ela_did.h"
#include "loader.h"
#include "constant.h"
#include "credential.h"
#include "diddocument.h"

static DIDDocument *issuerdoc;
static DIDDocument *doc;
static DID *issuerid;
static DID *did;
static DIDStore *store;

static bool has_type(const char **types, size_t size, const char *type)
{
    int i;

    if (!types || size <= 0 || !type || !*type)
        return false;

    for (i = 0; i < size; i++) {
        if (!strcmp(types[i], type))
            return true;
    }

    return false;
}

static void test_issuer_issuevc(void)
{
    Credential *vc;
    DID *vcdid;
    DIDURL *credid;
    time_t expires;
    bool isEquals;
    ssize_t size;
    int rc;
    const char* provalue;
    Issuer *issuer;

    expires = DIDDocument_GetExpires(doc);

    issuer = Issuer_Create(issuerid, NULL, store);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);

    credid = DIDURL_NewByDid(did, "kyccredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "PhoneCredential"};
    Property props[7];
    props[0].key = "name";
    props[0].value = "John";
    props[1].key = "gender";
    props[1].value = "Male";
    props[2].key = "nation";
    props[2].value = "Singapore";
    props[3].key = "language";
    props[3].value = "English";
    props[4].key = "email";
    props[4].value = "john@example.com";
    props[5].key = "twitter";
    props[5].value = "@john";
    props[6].key = "phone";
    props[6].value = "132780456";

    vc = Issuer_CreateCredential(issuer, did, credid, types, 2, props, 7,
            expires, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));

    vcdid = DIDURL_GetDid(Credential_GetId(vc));
    isEquals = DID_Equals(vcdid, did);
    CU_ASSERT_TRUE(isEquals);
    isEquals = DID_Equals(Credential_GetOwner(vc), did);
    CU_ASSERT_TRUE(isEquals);
    isEquals = DID_Equals(Credential_GetIssuer(vc), issuerid);
    CU_ASSERT_TRUE(isEquals);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "PhoneCredential"));

    CU_ASSERT_EQUAL(Credential_GetPropertyCount(vc), 7);
    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "John");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "gender");
    CU_ASSERT_STRING_EQUAL(provalue, "Male");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "twitter");
    CU_ASSERT_STRING_EQUAL(provalue, "@john");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "phone");
    CU_ASSERT_STRING_EQUAL(provalue, "132780456");
    free((void*)provalue);

    DIDURL_Destroy(credid);
    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

static void test_issuer_issueselfvc(void)
{
    Credential *vc;
    DID *vcdid;
    DIDURL *credid;
    time_t expires;
    bool isEquals;
    ssize_t size;
    const char* provalue;
    Issuer *issuer;

    expires = DIDDocument_GetExpires(issuerdoc);

    issuer = Issuer_Create(issuerid, NULL, store);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);

    credid = DIDURL_NewByDid(issuerid, "mycredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "PhoneCredential",
            "SelfProclaimedCredential"};
    Property props[7];
    props[0].key = "name";
    props[0].value = "John";
    props[1].key = "gender";
    props[1].value = "Male";
    props[2].key = "nation";
    props[2].value = "Singapore";
    props[3].key = "language";
    props[3].value = "English";
    props[4].key = "email";
    props[4].value = "john@example.com";
    props[5].key = "twitter";
    props[5].value = "@john";
    props[6].key = "phone";
    props[6].value = "132780456";

    vc = Issuer_CreateCredential(issuer, issuerid, credid, types, 3,
            props, 7, expires, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));

    vcdid = DIDURL_GetDid(Credential_GetId(vc));
    isEquals = DID_Equals(vcdid, issuerid);
    CU_ASSERT_TRUE(isEquals);
    isEquals = DID_Equals(Credential_GetOwner(vc), issuerid);
    CU_ASSERT_TRUE(isEquals);
    isEquals = DID_Equals(Credential_GetIssuer(vc), issuerid);
    CU_ASSERT_TRUE(isEquals);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 3);
    const char *tmptypes[3];
    size = Credential_GetTypes(vc, tmptypes, 3);
    CU_ASSERT_EQUAL(size, 3);
    CU_ASSERT_TRUE(has_type(tmptypes, 3, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 3, "PhoneCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 3, "SelfProclaimedCredential"));

    CU_ASSERT_EQUAL(Credential_GetPropertyCount(vc), 7);
    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "John");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "gender");
    CU_ASSERT_STRING_EQUAL(provalue, "Male");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "twitter");
    CU_ASSERT_STRING_EQUAL(provalue, "@john");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "phone");
    CU_ASSERT_STRING_EQUAL(provalue, "132780456");
    free((void*)provalue);

    DIDURL_Destroy(credid);
    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

static void test_issuer_issuerbystring(void)
{
    Credential *vc;
    DIDURL *credid;
    DID *vcdid;
    time_t expires;
    bool isEquals;
    ssize_t size;
    const char *provalue;
    Issuer *issuer;

    expires = DIDDocument_GetExpires(issuerdoc);

    issuer = Issuer_Create(issuerid, NULL, store);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);

    credid = DIDURL_NewByDid(issuerid, "mycredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential",
            "SelfProclaimedCredential"};

    const char *propdata = "{\"name\":\"Jay Holtslander\",\"alternateName\":\"Jason Holtslander\",\"booleanValue\":true,\"numberValue\":1234,\"doubleValue\":9.5,\"nationality\":\"Canadian\",\"birthPlace\":{\"type\":\"Place\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"}},\"affiliation\":[{\"type\":\"Organization\",\"name\":\"Futurpreneur\",\"sameAs\":[\"https://twitter.com/futurpreneur\",\"https://www.facebook.com/futurpreneur/\",\"https://www.linkedin.com/company-beta/100369/\",\"https://www.youtube.com/user/CYBF\"]}],\"alumniOf\":[{\"type\":\"CollegeOrUniversity\",\"name\":\"Vancouver Film School\",\"sameAs\":\"https://en.wikipedia.org/wiki/Vancouver_Film_School\",\"year\":2000},{\"type\":\"CollegeOrUniversity\",\"name\":\"CodeCore Bootcamp\"}],\"gender\":\"Male\",\"Description\":\"Technologist\",\"disambiguatingDescription\":\"Co-founder of CodeCore Bootcamp\",\"jobTitle\":\"Technical Director\",\"worksFor\":[{\"type\":\"Organization\",\"name\":\"Skunkworks Creative Group Inc.\",\"sameAs\":[\"https://twitter.com/skunkworks_ca\",\"https://www.facebook.com/skunkworks.ca\",\"https://www.linkedin.com/company/skunkworks-creative-group-inc-\",\"https://plus.google.com/+SkunkworksCa\"]}],\"url\":\"https://jay.holtslander.ca\",\"image\":\"https://s.gravatar.com/avatar/961997eb7fd5c22b3e12fb3c8ca14e11?s=512&r=g\",\"address\":{\"type\":\"PostalAddress\",\"addressLocality\":\"Vancouver\",\"addressRegion\":\"BC\",\"addressCountry\":\"Canada\"},\"sameAs\":[\"https://twitter.com/j_holtslander\",\"https://pinterest.com/j_holtslander\",\"https://instagram.com/j_holtslander\",\"https://www.facebook.com/jay.holtslander\",\"https://ca.linkedin.com/in/holtslander/en\",\"https://plus.google.com/+JayHoltslander\",\"https://www.youtube.com/user/jasonh1234\",\"https://github.com/JayHoltslander\",\"https://profiles.wordpress.org/jasonh1234\",\"https://angel.co/j_holtslander\",\"https://www.foursquare.com/user/184843\",\"https://jholtslander.yelp.ca\",\"https://codepen.io/j_holtslander/\",\"https://stackoverflow.com/users/751570/jay\",\"https://dribbble.com/j_holtslander\",\"http://jasonh1234.deviantart.com/\",\"https://www.behance.net/j_holtslander\",\"https://www.flickr.com/people/jasonh1234/\",\"https://medium.com/@j_holtslander\"]}";

    vc = Issuer_CreateCredentialByString(issuer, issuerid, credid, types, 2,
            propdata, expires, storepass);
    DIDURL_Destroy(credid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));

    vcdid = DIDURL_GetDid(Credential_GetId(vc));
    isEquals = DID_Equals(vcdid, issuerid);
    CU_ASSERT_TRUE(isEquals);
    isEquals = DID_Equals(Credential_GetOwner(vc), issuerid);
    CU_ASSERT_TRUE(isEquals);
    isEquals = DID_Equals(Credential_GetIssuer(vc), issuerid);
    CU_ASSERT_TRUE(isEquals);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "SelfProclaimedCredential"));
    CU_ASSERT_FALSE(has_type(tmptypes, 2, "PhoneCredential"));

    provalue = Credential_GetProperty(vc, "Description");
    CU_ASSERT_STRING_EQUAL(provalue, "Technologist");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "alternateName");
    CU_ASSERT_STRING_EQUAL(provalue, "Jason Holtslander");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "numberValue");
    CU_ASSERT_STRING_EQUAL(provalue, "1234");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "doubleValue");
    CU_ASSERT_STRING_EQUAL(provalue, "9.5");
    free((void*)provalue);

    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

static void test_issuer_issuerbystring_with_ctrl_chars(void)
{
    Credential *vc;
    DIDURL *credid;
    DID *vcdid;
    time_t expires;
    bool isEquals;
    ssize_t size;
    const char *provalue;
    Issuer *issuer;

    expires = DIDDocument_GetExpires(issuerdoc);

    credid = DIDURL_NewByDid(issuerid, "mycredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    issuer = Issuer_Create(issuerid, NULL, store);
    CU_ASSERT_PTR_NOT_NULL_FATAL(issuer);

    const char *types[] = {"BasicProfileCredential",
            "SelfProclaimedCredential"};

    const char *propdata = "{\"editTime\":\"1602998098\",\"customInfos\":\"\",\"didName\":\"cr03-did\",\"email\":\"\",\"nickname\":\"macdev\",\"gender\":\"\",\"did\":\"did:elastos:imnP8SJsFJfFb5mUrc6qLe9qyf18KAGH1X\",\"introduction\":\"Hello I\'m \\\"MacDev\\\"\\nThis is the \\\"MacDev\\\"\\nWhat\'s the matter?\"}";

    vc = Issuer_CreateCredentialByString(issuer, issuerid, credid, types, 2,
            propdata, expires, storepass);
    DIDURL_Destroy(credid);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));

    vcdid = DIDURL_GetDid(Credential_GetId(vc));
    isEquals = DID_Equals(vcdid, issuerid);
    CU_ASSERT_TRUE(isEquals);
    isEquals = DID_Equals(Credential_GetOwner(vc), issuerid);
    CU_ASSERT_TRUE(isEquals);
    isEquals = DID_Equals(Credential_GetIssuer(vc), issuerid);
    CU_ASSERT_TRUE(isEquals);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "SelfProclaimedCredential"));
    CU_ASSERT_FALSE(has_type(tmptypes, 2, "PhoneCredential"));

    provalue = Credential_GetProperty(vc, "editTime");
    CU_ASSERT_STRING_EQUAL(provalue, "1602998098");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "didName");
    CU_ASSERT_STRING_EQUAL(provalue, "cr03-did");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nickname");
    CU_ASSERT_STRING_EQUAL(provalue, "macdev");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "introduction");
    CU_ASSERT_STRING_EQUAL(provalue, "Hello I'm \"MacDev\"\nThis is the \"MacDev\"\nWhat's the matter?");
    free((void*)provalue);

    provalue = Credential_GetProperties(vc);
    CU_ASSERT_PTR_NOT_NULL(provalue);
    CU_ASSERT_EQUAL(strlen(propdata), strlen(provalue));
    Credential_Destroy(vc);
}

static void test_cidissuer_issue_kycvc(void)
{
    DIDDocument *customizeddoc;
    Issuer *issuer;
    DIDURL *credid;
    time_t expires;
    DID *subject;
    Credential *vc;
    ssize_t size;
    const char* provalue;

    expires = DIDDocument_GetExpires(doc);

    customizeddoc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL(customizeddoc);

    subject = DIDDocument_GetSubject(customizeddoc);
    CU_ASSERT_PTR_NOT_NULL(subject);

    issuer = Issuer_Create(subject, NULL, store);
    CU_ASSERT_PTR_NOT_NULL(issuer);

    credid = DIDURL_NewByDid(did, "testcredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "InternetAccountCredential"};
    Property props[6];
    props[0].key = "name";
    props[0].value = "John";
    props[1].key = "gender";
    props[1].value = "Male";
    props[2].key = "nation";
    props[2].value = "Singapore";
    props[3].key = "language";
    props[3].value = "English";
    props[4].key = "email";
    props[4].value = "john@example.com";
    props[5].key = "twitter";
    props[5].value = "@john";

    vc = Issuer_CreateCredential(issuer, did, credid, types, 2,
            props, 6, expires, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(credid, Credential_GetId(vc)));
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));
    DIDURL_Destroy(credid);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "InternetAccountCredential"));
    CU_ASSERT_FALSE(has_type(tmptypes, 2, "SelfProclaimedCredential"));

    CU_ASSERT_TRUE(DID_Equals(subject, Credential_GetIssuer(vc)));

    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "John");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "gender");
    CU_ASSERT_STRING_EQUAL(provalue, "Male");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "twitter");
    CU_ASSERT_STRING_EQUAL(provalue, "@john");
    free((void*)provalue);

    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

static void test_issuer_issue_cidvc(void)
{
    DIDDocument *customizeddoc;
    Issuer *issuer;
    DIDURL *credid;
    time_t expires;
    DID *subject;
    Credential *vc;
    ssize_t size;
    const char* provalue;

    expires = DIDDocument_GetExpires(issuerdoc);

    customizeddoc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL(customizeddoc);

    subject = DIDDocument_GetSubject(customizeddoc);
    CU_ASSERT_PTR_NOT_NULL(subject);

    issuer = Issuer_Create(issuerid, NULL, store);
    CU_ASSERT_PTR_NOT_NULL(issuer);

    credid = DIDURL_NewByDid(subject, "testcredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "InternetAccountCredential"};
    Property props[6];
    props[0].key = "name";
    props[0].value = "John";
    props[1].key = "gender";
    props[1].value = "Male";
    props[2].key = "nation";
    props[2].value = "Singapore";
    props[3].key = "language";
    props[3].value = "English";
    props[4].key = "email";
    props[4].value = "john@example.com";
    props[5].key = "twitter";
    props[5].value = "@john";

    vc = Issuer_CreateCredential(issuer, subject, credid, types, 2,
            props, 6, expires, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(credid, Credential_GetId(vc)));
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));
    DIDURL_Destroy(credid);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "InternetAccountCredential"));
    CU_ASSERT_FALSE(has_type(tmptypes, 2, "SelfProclaimedCredential"));

    CU_ASSERT_TRUE(DID_Equals(issuerid, Credential_GetIssuer(vc)));

    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "John");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "gender");
    CU_ASSERT_STRING_EQUAL(provalue, "Male");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "twitter");
    CU_ASSERT_STRING_EQUAL(provalue, "@john");
    free((void*)provalue);

    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

static void test_cidissuer_issue_selfvc(void)
{
    DIDDocument *customizeddoc;
    Issuer *issuer;
    DIDURL *credid;
    time_t expires;
    DID *subject;
    Credential *vc;
    ssize_t size;
    const char* provalue;

    customizeddoc = TestData_LoadCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL(customizeddoc);
    expires = DIDDocument_GetExpires(customizeddoc);

    subject = DIDDocument_GetSubject(customizeddoc);
    CU_ASSERT_PTR_NOT_NULL(subject);

    issuer = Issuer_Create(subject, NULL, store);
    CU_ASSERT_PTR_NOT_NULL(issuer);

    credid = DIDURL_NewByDid(subject, "testcredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfProclaimedCredential"};
    Property props[4];
    props[0].key = "name";
    props[0].value = "Testing Issuer";
    props[1].key = "nation";
    props[1].value = "Singapore";
    props[2].key = "language";
    props[2].value = "English";
    props[3].key = "email";
    props[3].value = "john@example.com";

    vc = Issuer_CreateCredential(issuer, subject, credid, types, 2,
            props, 4, expires, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(credid, Credential_GetId(vc)));
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));
    DIDURL_Destroy(credid);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "SelfProclaimedCredential"));
    CU_ASSERT_FALSE(has_type(tmptypes, 2, "InternetAccountCredential"));

    CU_ASSERT_TRUE(DID_Equals(subject, Credential_GetIssuer(vc)));

    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "Testing Issuer");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);

    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

//------------------------------------------------------------------
static void test_issuer_issue_multicidvc(void)
{
    DIDDocument *customizeddoc;
    Issuer *issuer;
    DIDURL *credid, *signkey;
    time_t expires;
    DID *subject;
    Credential *vc;
    ssize_t size;
    const char* provalue;

    expires = DIDDocument_GetExpires(issuerdoc);

    customizeddoc = TestData_LoadMultiCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL(customizeddoc);

    subject = DIDDocument_GetSubject(customizeddoc);
    CU_ASSERT_PTR_NOT_NULL(subject);

    issuer = Issuer_Create(issuerid, NULL, store);
    CU_ASSERT_PTR_NOT_NULL(issuer);

    credid = DIDURL_NewByDid(subject, "testcredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "InternetAccountCredential"};
    Property props[6];
    props[0].key = "name";
    props[0].value = "John";
    props[1].key = "gender";
    props[1].value = "Male";
    props[2].key = "nation";
    props[2].value = "Singapore";
    props[3].key = "language";
    props[3].value = "English";
    props[4].key = "email";
    props[4].value = "john@example.com";
    props[5].key = "twitter";
    props[5].value = "@john";

    vc = Issuer_CreateCredential(issuer, subject, credid, types, 2,
            props, 6, expires, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(credid, Credential_GetId(vc)));
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));
    DIDURL_Destroy(credid);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "InternetAccountCredential"));
    CU_ASSERT_FALSE(has_type(tmptypes, 2, "SelfProclaimedCredential"));

    CU_ASSERT_TRUE(DID_Equals(issuerid, Credential_GetIssuer(vc)));

    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "John");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "gender");
    CU_ASSERT_STRING_EQUAL(provalue, "Male");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "twitter");
    CU_ASSERT_STRING_EQUAL(provalue, "@john");
    free((void*)provalue);

    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

static void test_multicidissuer_issue_kycvc(void)
{
    DIDDocument *customizeddoc;
    Issuer *issuer;
    DIDURL *credid, *signkey;
    time_t expires;
    DID *subject;
    Credential *vc;
    ssize_t size;
    const char* provalue;

    expires = DIDDocument_GetExpires(doc);

    customizeddoc = TestData_LoadMultiCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL(customizeddoc);

    subject = DIDDocument_GetSubject(customizeddoc);
    CU_ASSERT_PTR_NOT_NULL(subject);

    signkey = DIDURL_NewByDid(&customizeddoc->controllers.docs[0]->did, "key2");
    CU_ASSERT_PTR_NOT_NULL(signkey);

    issuer = Issuer_Create(subject, signkey, store);
    CU_ASSERT_PTR_NOT_NULL(issuer);
    DIDURL_Destroy(signkey);

    credid = DIDURL_NewByDid(did, "testcredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "InternetAccountCredential"};
    Property props[6];
    props[0].key = "name";
    props[0].value = "John";
    props[1].key = "gender";
    props[1].value = "Male";
    props[2].key = "nation";
    props[2].value = "Singapore";
    props[3].key = "language";
    props[3].value = "English";
    props[4].key = "email";
    props[4].value = "john@example.com";
    props[5].key = "twitter";
    props[5].value = "@john";

    vc = Issuer_CreateCredential(issuer, did, credid, types, 2,
            props, 6, expires, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(credid, Credential_GetId(vc)));
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));
    DIDURL_Destroy(credid);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "InternetAccountCredential"));
    CU_ASSERT_FALSE(has_type(tmptypes, 2, "SelfProclaimedCredential"));

    CU_ASSERT_TRUE(DID_Equals(subject, Credential_GetIssuer(vc)));

    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "John");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "gender");
    CU_ASSERT_STRING_EQUAL(provalue, "Male");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "twitter");
    CU_ASSERT_STRING_EQUAL(provalue, "@john");
    free((void*)provalue);

    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

static void test_multicidissuer_issue_kycvc2(void)
{
    DIDDocument *customizeddoc;
    Issuer *issuer;
    DIDURL *credid, *signkey;
    time_t expires;
    DID *subject;
    Credential *vc;
    ssize_t size;
    const char* provalue;

    expires = DIDDocument_GetExpires(doc);

    customizeddoc = TestData_LoadMultiCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL(customizeddoc);

    subject = DIDDocument_GetSubject(customizeddoc);
    CU_ASSERT_PTR_NOT_NULL(subject);

    signkey = DIDURL_NewByDid(subject, "k1");
    CU_ASSERT_PTR_NOT_NULL(signkey);

    issuer = Issuer_Create(subject, signkey, store);
    CU_ASSERT_PTR_NOT_NULL(issuer);
    DIDURL_Destroy(signkey);

    credid = DIDURL_NewByDid(issuerid, "testcredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "InternetAccountCredential"};
    Property props[6];
    props[0].key = "name";
    props[0].value = "John";
    props[1].key = "gender";
    props[1].value = "Male";
    props[2].key = "nation";
    props[2].value = "Singapore";
    props[3].key = "language";
    props[3].value = "English";
    props[4].key = "email";
    props[4].value = "john@example.com";
    props[5].key = "twitter";
    props[5].value = "@john";

    vc = Issuer_CreateCredential(issuer, issuerid, credid, types, 2,
            props, 6, expires, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(credid, Credential_GetId(vc)));
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));
    DIDURL_Destroy(credid);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "InternetAccountCredential"));
    CU_ASSERT_FALSE(has_type(tmptypes, 2, "SelfProclaimedCredential"));

    CU_ASSERT_TRUE(DID_Equals(subject, Credential_GetIssuer(vc)));

    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "John");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "gender");
    CU_ASSERT_STRING_EQUAL(provalue, "Male");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "twitter");
    CU_ASSERT_STRING_EQUAL(provalue, "@john");
    free((void*)provalue);

    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

static void test_multicidissuer_issue_selfvc(void)
{
    DIDDocument *customizeddoc;
    Issuer *issuer;
    DIDURL *credid, *signkey;
    time_t expires;
    DID *subject;
    Credential *vc;
    ssize_t size;
    const char* provalue;

    customizeddoc = TestData_LoadMultiCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL(customizeddoc);
    expires = DIDDocument_GetExpires(customizeddoc);

    subject = DIDDocument_GetSubject(customizeddoc);
    CU_ASSERT_PTR_NOT_NULL(subject);

    signkey = DIDURL_NewByDid(&customizeddoc->controllers.docs[1]->did, "pk1");
    CU_ASSERT_PTR_NOT_NULL(signkey);

    issuer = Issuer_Create(subject, signkey, store);
    CU_ASSERT_PTR_NOT_NULL(issuer);

    credid = DIDURL_NewByDid(subject, "testcredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfProclaimedCredential"};
    Property props[4];
    props[0].key = "name";
    props[0].value = "Testing Issuer";
    props[1].key = "nation";
    props[1].value = "Singapore";
    props[2].key = "language";
    props[2].value = "English";
    props[3].key = "email";
    props[3].value = "john@example.com";

    vc = Issuer_CreateCredential(issuer, subject, credid, types, 2,
            props, 4, expires, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(credid, Credential_GetId(vc)));
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));
    DIDURL_Destroy(credid);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "SelfProclaimedCredential"));
    CU_ASSERT_FALSE(has_type(tmptypes, 2, "InternetAccountCredential"));

    CU_ASSERT_TRUE(DID_Equals(subject, Credential_GetIssuer(vc)));

    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "Testing Issuer");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);

    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

static void test_multicidissuer_issue_selfvc2(void)
{
    DIDDocument *customizeddoc;
    Issuer *issuer;
    DIDURL *credid, *signkey;
    time_t expires;
    DID *subject;
    Credential *vc;
    ssize_t size;
    const char* provalue;

    customizeddoc = TestData_LoadMultiCustomizedDoc();
    CU_ASSERT_PTR_NOT_NULL(customizeddoc);
    expires = DIDDocument_GetExpires(customizeddoc);

    subject = DIDDocument_GetSubject(customizeddoc);
    CU_ASSERT_PTR_NOT_NULL(subject);

    signkey = DIDURL_NewByDid(subject, "k1");
    CU_ASSERT_PTR_NOT_NULL(signkey);

    issuer = Issuer_Create(subject, signkey, store);
    CU_ASSERT_PTR_NOT_NULL(issuer);

    credid = DIDURL_NewByDid(subject, "testcredential");
    CU_ASSERT_PTR_NOT_NULL(credid);

    const char *types[] = {"BasicProfileCredential", "SelfProclaimedCredential"};
    Property props[4];
    props[0].key = "name";
    props[0].value = "Testing Issuer";
    props[1].key = "nation";
    props[1].value = "Singapore";
    props[2].key = "language";
    props[2].value = "English";
    props[3].key = "email";
    props[3].value = "john@example.com";

    vc = Issuer_CreateCredential(issuer, subject, credid, types, 2,
            props, 4, expires, storepass);
    CU_ASSERT_PTR_NOT_NULL_FATAL(vc);
    CU_ASSERT_TRUE_FATAL(DIDURL_Equals(credid, Credential_GetId(vc)));
    CU_ASSERT_FALSE(Credential_IsExpired(vc));
    CU_ASSERT_TRUE(Credential_IsGenuine(vc));
    CU_ASSERT_TRUE(Credential_IsValid(vc));
    DIDURL_Destroy(credid);

    CU_ASSERT_EQUAL(Credential_GetTypeCount(vc), 2);
    const char *tmptypes[2];
    size = Credential_GetTypes(vc, tmptypes, 2);
    CU_ASSERT_EQUAL(size, 2);
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "BasicProfileCredential"));
    CU_ASSERT_TRUE(has_type(tmptypes, 2, "SelfProclaimedCredential"));
    CU_ASSERT_FALSE(has_type(tmptypes, 2, "InternetAccountCredential"));

    CU_ASSERT_TRUE(DID_Equals(subject, Credential_GetIssuer(vc)));

    provalue = Credential_GetProperty(vc, "name");
    CU_ASSERT_STRING_EQUAL(provalue, "Testing Issuer");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "nation");
    CU_ASSERT_STRING_EQUAL(provalue, "Singapore");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "language");
    CU_ASSERT_STRING_EQUAL(provalue, "English");
    free((void*)provalue);
    provalue = Credential_GetProperty(vc, "email");
    CU_ASSERT_STRING_EQUAL(provalue, "john@example.com");
    free((void*)provalue);

    Credential_Destroy(vc);
    Issuer_Destroy(issuer);
}

static int issuer_issuevc_test_suite_init(void)
{
    DIDURL *signkey;
    int rc;

    store = TestData_SetupStore(true);
    if (!store)
        return -1;

    issuerdoc = TestData_LoadIssuerDoc();
    if (!issuerdoc) {
        TestData_Free();
        return -1;
    }

    issuerid = DIDDocument_GetSubject(issuerdoc);
    if (!issuerid) {
        TestData_Free();
        return -1;
    }

    doc = TestData_LoadDoc();
    if (!doc) {
        TestData_Free();
        return -1;
    }

    did = DIDDocument_GetSubject(doc);
    if (!did) {
        TestData_Free();
        return -1;
    }

    return 0;
}

static int issuer_issuevc_test_suite_cleanup(void)
{
    TestData_Free();
    return 0;
}

static CU_TestInfo cases[] = {
    { "test_issuer_issuevc",                   test_issuer_issuevc       },
    { "test_issuer_issueselfvc",               test_issuer_issueselfvc   },
    { "test_issuer_issuerbystring",            test_issuer_issuerbystring},
    { "test_issuer_issuerbystring_with_ctrl_chars", test_issuer_issuerbystring_with_ctrl_chars },
    { "test_issuer_issue_cidvc",               test_issuer_issue_cidvc         },
    { "test_cidissuer_issue_kycvc",            test_cidissuer_issue_kycvc      },
    { "test_cidissuer_issue_selfvc",           test_cidissuer_issue_selfvc     },
    //----------------------------------------------------------------------
    { "test_issuer_issue_multicidvc",          test_issuer_issue_multicidvc    },
    { "test_multicidissuer_issue_kycvc",       test_multicidissuer_issue_kycvc },
    { "test_multicidissuer_issue_kycvc2",      test_multicidissuer_issue_kycvc2},
    { "test_multicidissuer_issue_selfvc",      test_multicidissuer_issue_selfvc},
    { "test_multicidissuer_issue_selfvc2",     test_multicidissuer_issue_selfvc2},
    { NULL,                                    NULL                             }
};

static CU_SuiteInfo suite[] = {
    { "issuer issue credential test", issuer_issuevc_test_suite_init, issuer_issuevc_test_suite_cleanup, NULL, NULL, cases },
    {  NULL,                          NULL,                          NULL,                               NULL, NULL, NULL  }
};


CU_SuiteInfo* issuer_issuevc_test_suite_info(void)
{
    return suite;
}
