#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_GLOB_H
#include <glob.h>
#endif
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

#include "ela_did.h"
#include "dummyadapter.h"
#include "constant.h"
#include "loader.h"
#include "crypto.h"
#include "HDkey.h"
#include "did.h"
#include "diddocument.h"
#include "credential.h"
#include "credmeta.h"

#if defined(_WIN32) || defined(_WIN64)
    #include <crystal.h>
#else
    #include "testadapter.h"
#endif

#define HARDENED                       0x80000000

typedef struct TestData {
    DIDStore *store;
    RootIdentity *rootidentity;

    DIDDocument *issuerdoc;
    const char *issuerJson;
    const char *issuerCompactJson;
    const char *issuerNormalizedJson;

    DIDDocument *doc;
    const char *docJson;
    const char *docCompactJson;
    const char *docNormalizedJson;

    DIDDocument *controllerdoc;
    DIDDocument *user1doc;
    DIDDocument *user2doc;
    DIDDocument *user3doc;
    DIDDocument *issuerIddoc;

    DIDDocument *emptyctmdoc;
    DIDDocument *ctmdoc;

    DIDDocument *emptyctmdoc_multisigone;
    DIDDocument *ctmdoc_multisigone;

    DIDDocument *emptyctmdoc_multisigtwo;
    DIDDocument *ctmdoc_multisigtwo;

    DIDDocument *emptyctmdoc_multisigthree;
    DIDDocument *ctmdoc_multisigthree;

    Credential *profileVc;
    const char *profileVcCompactJson;
    const char *profileVcNormalizedJson;

    Credential *emailVc;
    const char *emailVcCompactJson;
    const char *emailVcNormalizedJson;

    Credential *passportVc;
    const char *passportVcCompactJson;
    const char *passportVcNormalizedJson;

    Credential *twitterVc;
    const char *twitterVcCompactJson;
    const char *twitterVcNormalizedJson;

    Credential *Vc;
    const char *VcCompactJson;
    const char *VcNormalizedJson;

    Presentation *vp;
    const char *vpNormalizedJson;

    const char *restoreMnemonic;
} TestData;

typedef struct Dir_Copy_Helper {
    const char *srcpath;
    const char *dstpath;
} Dir_Copy_Helper;

TestData testdata;

char *get_wallet_path(char* path, const char* dir)
{
    if (!path || !dir)
        return NULL;

    sprintf(path, "%s%s%s", getenv("HOME"), PATH_STEP, dir);
    return path;
}

const char *get_store_path(char* path, const char *dir)
{
    if (!path || !dir)
        return NULL;

    if(!getcwd(path, PATH_MAX)) {
        printf("\nCan't get current dir.");
        return NULL;
    }

    strcat(path, PATH_STEP);
    strcat(path, dir);
    return path;
}

char *get_path(char *path, const char *file, int version)
{
    size_t len;

    assert(file);
    assert(*file);

    switch (version) {
        case 0:
            len = snprintf(path, PATH_MAX, "..%setc%sdid%sresources%stestdata%s%s",
                PATH_STEP, PATH_STEP, PATH_STEP, PATH_STEP, PATH_STEP, file);
            break;
        case 1:
            len = snprintf(path, PATH_MAX, "..%setc%sdid%sresources%sv1%stestdata%s%s",
                PATH_STEP, PATH_STEP, PATH_STEP, PATH_STEP, PATH_STEP, PATH_STEP, file);
            break;
        case 2:
            len = snprintf(path, PATH_MAX, "..%setc%sdid%sresources%sv2%stestdata%s%s",
                PATH_STEP, PATH_STEP, PATH_STEP, PATH_STEP, PATH_STEP, PATH_STEP, file);
            break;
        default:
            return NULL;
    }

    if (len < 0 || len > PATH_MAX)
        return NULL;

    return path;
}

static const char *load_testdata_file(const char *file, int version)
{
    char _path[PATH_MAX];
    char *readstring = NULL, *path;

    assert(file && *file);

    path = get_path(_path, file, version);
    if (!path)
        return NULL;

    return load_file(path);
}

static const char *getpassword(const char *walletDir, const char *walletId)
{
    return walletpass;
}

char *get_file_path(char *path, size_t size, int count, ...)
{
    va_list list;
    int i, totalsize = 0;

    if (!path || size <= 0 || count <= 0)
        return NULL;

    *path = 0;
    va_start(list, count);
    for (i = 0; i < count; i++) {
        const char *suffix = va_arg(list, const char*);
        assert(suffix);
        int len = strlen(suffix);
        totalsize = totalsize + len;
        if (totalsize > size)
            return NULL;

        strncat(path, suffix, len + 1);
    }
    va_end(list);

    return path;
}

static int copy_metadata(const char *dst, const char *src)
{
    int fd1, fd2;
    char symbol[1];
    int rc = -1;

    assert(dst);
    assert(src);

    fd1 = open(src, O_RDONLY);
    if (fd1 == -1)
        return -1;

    fd2 = open(dst, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd2 == -1) {
        close(fd1);
        return -1;
    }

    while (read(fd1, symbol, sizeof(symbol)) == 1) {
        if(write(fd2, symbol, sizeof(symbol)) < 1)
            goto errorExit;
    }

    rc = 0;

errorExit:
    close(fd2);
    close(fd1);

    return rc;
}

static int dir_copy(const char *dst, const char *src);

static int dir_copy_helper(const char *path, void *context)
{
    char srcpath[PATH_MAX];
    char dstpath[PATH_MAX];

    Dir_Copy_Helper *dh = (Dir_Copy_Helper*)context;

    if (!path)
        return 0;

    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
        return 0;

    sprintf(srcpath, "%s%s%s", dh->srcpath, PATH_SEP, path);
    sprintf(dstpath, "%s%s%s", dh->dstpath, PATH_SEP, path);

    return dir_copy(dstpath, srcpath);
}

static int dir_copy(const char *dst, const char *src)
{
    Dir_Copy_Helper dh;
    const char *string;
    char path[PATH_MAX];
    int rc = -1;

    assert(dst && *dst);
    assert(src && *src);

    if (test_path(src) < 0)
        return -1;

    //src is directory.
    if (test_path(src) == S_IFDIR) {
        if (test_path(dst) < 0) {
            rc = mkdirs(dst, S_IRWXU);
            if (rc < 0)
                return -1;
        }

        dh.srcpath = src;
        dh.dstpath = dst;

        if (list_dir(src, "*", dir_copy_helper, (void*)&dh) == -1)
            return -1;
        return 0;
    }

    //src is file
    string = load_file(src);
    if (!string || !*string) {
        if (last_strstr(src, ".meta"))
            rc = copy_metadata(dst, src);

        if (string)
            free((void*)string);

        return rc;
    }

    rc = store_file(dst, string);
    free((void*)string);
    return rc;
}

static Credential *store_credential(const char *file, const char *alias, bool version)
{
    Credential *cred;
    const char *data;

    data = load_testdata_file(file, version);
    if (!data)
        return NULL;

    cred = Credential_FromJson(data, NULL);
    free((void*)data);
    if (!cred)
        return NULL;

    CredentialMetadata *metadata = Credential_GetMetadata(cred);
    if (!metadata) {
        Credential_Destroy(cred);
        return NULL;
    }

    if (CredentialMetadata_SetAlias(metadata, alias) < 0) {
        Credential_Destroy(cred);
        return NULL;
    }

    if (DIDStore_StoreCredential(testdata.store, cred) == -1) {
        Credential_Destroy(cred);
        return NULL;
    }

    return cred;
}

static DIDDocument *store_document(const char *file, const char *alias, int version)
{
    DIDDocument *doc;
    const char *string;
    DID did;
    int rc;

    string = load_testdata_file(file, version);
    if (!string)
        return NULL;

    doc = DIDDocument_FromJson(string);
    free((void*)string);
    if (!doc)
        return NULL;

    strcpy(did.idstring, doc->did.idstring);
    DIDMetadata *metadata = DIDDocument_GetMetadata(doc);
    if (!metadata) {
        DIDDocument_Destroy(doc);
        return NULL;
    }

    if (DIDMetadata_SetAlias(metadata, alias) < 0) {
        DIDDocument_Destroy(doc);
        return NULL;
    }

    rc = DIDStore_StoreDID(testdata.store, doc);
    DIDDocument_Destroy(doc);
    if (rc < 0)
        return NULL;

    return DIDStore_LoadDID(testdata.store, &did);
}

bool file_exist(const char *path)
{
    return test_path(path) == S_IFREG;
}

bool dir_exist(const char* path)
{
    return test_path(path) == S_IFDIR;
}

static int import_privatekey(DIDURL *id, const char *storepass, const char *file, int version)
{
    const char *skbase;
    uint8_t extendedkey[EXTENDEDKEY_BYTES];
    ssize_t size;
    HDKey _hdkey, *hdkey;

    if (!id || !file || !*file)
        return -1;

    skbase = load_testdata_file(file, version);
    if (!skbase || !*skbase)
        return -1;

    size = b58_decode(extendedkey, sizeof(extendedkey), skbase);
    free((void*)skbase);
    if (version != 0) {
        if (size != EXTENDEDKEY_BYTES)
            return -1;
    }

    if (DIDStore_StorePrivateKey(testdata.store, storepass, DIDURL_GetDid(id),
            id, extendedkey, size) == -1)
        return -1;

    return 0;
}

/////////////////////////////////////
int TestData_Init(bool dummy)
{
    char _dir[PATH_MAX];
    char *walletDir;
    int rc = 0;

    walletDir = get_wallet_path(_dir, walletdir);
    if (!dummy && !dir_exist(walletDir)) {
        printf("Wallet Dir doesn't exist: %s\n", walletDir);
        return -1;
    }

#if !defined(_WIN32) && !defined(_WIN64)
    if (!dummy)
        rc = TestDIDAdapter_Init(walletDir, walletId, network, getpassword);
#endif

    return rc;
}

void TestData_Deinit(void)
{
#if !defined(_WIN32) && !defined(_WIN64)
    TestDIDAdapter_Cleanup();
#endif
    DummyAdapter_Cleanup();
}

static DIDStore *setup_store(bool dummybackend, const char *root)
{
    char cachedir[PATH_MAX];

    assert(root);

    sprintf(cachedir, "%s%s%s", getenv("HOME"), PATH_STEP, ".cache.did.elastos");
    testdata.store = DIDStore_Open(root);

#if defined(_WIN32) ||  defined(_WIN64)
    dummybackend = true;
#else
    if (!dummybackend)
        DIDBackend_InitializeDefault(TestDIDAdapter_CreateIdTransaction, resolver, cachedir);
#endif

    if (dummybackend) {
        DummyAdapter_Cleanup();
        DummyAdapter_Set(cachedir);
    }

    return testdata.store;
}

DIDStore *TestData_SetupStore(bool dummybackend)
{
    char _path[PATH_MAX];
    const char*root;

    root = get_store_path(_path, "DIDStore");
    delete_file(root);
    return setup_store(dummybackend, root);
}

//only for v2
DIDStore *TestData_SetupTestStore(bool dummybackend)
{
    char _path[PATH_MAX];
    const char *path;

    path = get_file_path(_path, PATH_MAX, 11, "..", PATH_STEP, "etc", PATH_STEP,
        "did", PATH_STEP, "resources", PATH_STEP, "v2", PATH_STEP, "teststore");
    if (!path)
        return NULL;

    return setup_store(dummybackend, path);
}

//only for v1
DIDStore *TestData_SetupV1TestStore(bool dummybackend)
{
    char _path[PATH_MAX], _newpath[PATH_MAX];
    const char *path, *newpath;

    path = get_file_path(_path, PATH_MAX, 11, "..", PATH_STEP, "etc", PATH_STEP,
        "did", PATH_STEP, "resources", PATH_STEP, "v1", PATH_STEP, "teststore");
    if (!path)
        return NULL;

    newpath = get_file_path(_newpath, PATH_MAX, 11, "..", PATH_STEP, "etc", PATH_STEP,
        "did", PATH_STEP, "resources", PATH_STEP, "v1-backup", PATH_STEP, "teststore");
    if (!newpath)
        return NULL;

    delete_file(newpath);
    dir_copy(newpath, path);
    return setup_store(dummybackend, newpath);
}

RootIdentity *TestData_InitIdentity(DIDStore *store)
{
    const char *mnemonic;
    int rc;

    mnemonic = Mnemonic_Generate(language);
    testdata.rootidentity = RootIdentity_Create(mnemonic, passphrase, language, true, store, storepass);
    Mnemonic_Free((void*)mnemonic);

    return testdata.rootidentity;
}

const char *TestData_LoadIssuerJson(void)
{
    if (!testdata.issuerJson)
        testdata.issuerJson = load_testdata_file("issuer.json", 0);

    return testdata.issuerJson;
}

const char *TestData_LoadIssuerCompJson(void)
{
    if (!testdata.issuerCompactJson)
        testdata.issuerCompactJson = load_testdata_file("issuer.compact.json", 0);

    return testdata.issuerCompactJson;
}

const char *TestData_LoadIssuerNormJson(void)
{
    if (!testdata.issuerNormalizedJson)
        testdata.issuerNormalizedJson = load_testdata_file("issuer.normalized.json", 0);

    return testdata.issuerNormalizedJson;
}

const char *TestData_LoadDocJson(void)
{
    if (!testdata.docJson)
        testdata.docJson = load_testdata_file("document.json", 0);

    return testdata.docJson;
}

const char *TestData_LoadDocCompJson(void)
{
    if (!testdata.docCompactJson)
        testdata.docCompactJson = load_testdata_file("document.compact.json", 0);

    return testdata.docCompactJson;
}

const char *TestData_LoadDocNormJson(void)
{
    if (!testdata.docNormalizedJson)
        testdata.docNormalizedJson = load_testdata_file("document.normalized.json", 0);

    return testdata.docNormalizedJson;
}

Credential *TestData_LoadProfileVc(void)
{
    if (!testdata.profileVc)
        testdata.profileVc = store_credential("vc-profile.json", "profile vc", 0);

    return testdata.profileVc;
}

const char *TestData_LoadProfileVcCompJson(void)
{
    if (!testdata.profileVcCompactJson)
        testdata.profileVcCompactJson = load_testdata_file("vc-profile.compact.json", 0);

    return testdata.profileVcCompactJson;
}

const char *TestData_LoadProfileVcNormJson(void)
{
    if (!testdata.profileVcNormalizedJson)
        testdata.profileVcNormalizedJson = load_testdata_file("vc-profile.normalized.json", 0);

    return testdata.profileVcNormalizedJson;
}

Credential *TestData_LoadEmailVc(void)
{
    if (!testdata.emailVc)
        testdata.emailVc = store_credential("vc-email.json", "email vc", 0);

    return testdata.emailVc;
}

const char *TestData_LoadEmailVcCompJson(void)
{
    if (!testdata.emailVcCompactJson)
        testdata.emailVcCompactJson = load_testdata_file("vc-email.compact.json", 0);

    return testdata.emailVcCompactJson;
}

const char *TestData_LoadEmailVcNormJson(void)
{
    if (!testdata.emailVcNormalizedJson)
        testdata.emailVcNormalizedJson = load_testdata_file("vc-email.normalized.json", 0);

    return testdata.emailVcNormalizedJson;
}

Credential *TestData_LoadPassportVc(void)
{
    if (!testdata.passportVc)
        testdata.passportVc = store_credential("vc-passport.json", "passport vc", 0);

    return testdata.passportVc;
}

const char *TestData_LoadPassportVcCompJson(void)
{
    if (!testdata.passportVcCompactJson)
        testdata.passportVcCompactJson = load_testdata_file("vc-passport.compact.json", 0);

    return testdata.passportVcCompactJson;
}

const char *TestData_LoadPassportVcNormJson(void)
{
    if (!testdata.passportVcNormalizedJson)
        testdata.passportVcNormalizedJson = load_testdata_file("vc-passport.normalized.json", 0);

    return testdata.passportVcNormalizedJson;
}

Credential *TestData_LoadTwitterVc(void)
{
    if (!testdata.twitterVc)
        testdata.twitterVc = store_credential("vc-twitter.json", "twitter vc", 0);

    return testdata.twitterVc;
}

const char *TestData_LoadTwitterVcCompJson(void)
{
    if (!testdata.twitterVcCompactJson)
        testdata.twitterVcCompactJson = load_testdata_file("vc-twitter.compact.json", 0);

    return testdata.twitterVcCompactJson;
}

const char *TestData_LoadTwitterVcNormJson(void)
{
    if (!testdata.twitterVcNormalizedJson)
        testdata.twitterVcNormalizedJson = load_testdata_file("vc-twitter.normalized.json", 0);

    return testdata.twitterVcNormalizedJson;
}

Credential *TestData_LoadVc(void)
{
    if (!testdata.Vc)
        testdata.Vc = store_credential("vc-json.json", "test vc", 0);

    return testdata.Vc;
}

const char *TestData_LoadVcCompJson(void)
{
    if (!testdata.VcCompactJson)
        testdata.VcCompactJson = load_testdata_file("vc-json.compact.json", 0);

    return testdata.VcCompactJson;
}

const char *TestData_LoadVcNormJson(void)
{
    if (!testdata.VcNormalizedJson)
        testdata.VcNormalizedJson = load_testdata_file("vc-json.normalized.json", 0);

    return testdata.VcNormalizedJson;
}

Presentation *TestData_LoadVp(void)
{
    if (!testdata.vp) {
        const char *data = load_testdata_file("vp.json", 0);
        if (!data)
            return NULL;

        testdata.vp = Presentation_FromJson(data);
        free((void*)data);
    }
    return testdata.vp;
}

const char *TestData_LoadVpNormJson(void)
{
    if (!testdata.vpNormalizedJson)
        testdata.vpNormalizedJson = load_testdata_file("vp.normalized.json", 0);

    return testdata.vpNormalizedJson;
}

DIDDocument *TestData_LoadDoc(void)
{
    DIDURL *id;
    DID *subject;
    int rc, status;
    DIDDocument *doc;

    if (!testdata.doc)
       testdata.doc = store_document("document.json", "doc test", 0);

    subject = DIDDocument_GetSubject(testdata.doc);
    id = DIDURL_NewByDid(subject, "key2");
    rc = import_privatekey(id, storepass, "document.key2.sk", 0);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    id = DIDURL_NewByDid(subject, "key3");
    rc = import_privatekey(id, storepass, "document.key3.sk", 0);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    id = DIDURL_NewByDid(subject, "primary");
    rc = import_privatekey(id, storepass, "document.primary.sk", 0);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.doc, NULL, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.doc;
}

DIDDocument *TestData_LoadControllerDoc(void)
{
    DIDURL *id;
    DID *subject;
    int rc, status;
    DIDDocument *doc;

    if (!testdata.controllerdoc)
       testdata.controllerdoc = store_document("controller.json", "controller test", 0);

    subject = DIDDocument_GetSubject(testdata.controllerdoc);
    id = DIDURL_NewByDid(subject, "pk1");
    rc = import_privatekey(id, storepass, "controller.pk1.sk", 0);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    id = DIDURL_NewByDid(subject, "primary");
    rc = import_privatekey(id, storepass, "controller.primary.sk", 0);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.controllerdoc, NULL, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.controllerdoc;
}

DIDDocument *TestData_LoadIssuerDoc(void)
{
    DIDURL *id;
    DID *subject;
    int rc, status;
    DIDDocument *doc;

    if (!testdata.issuerdoc)
        testdata.issuerdoc = store_document("issuer.json", "issuer test", 0);

    subject = DIDDocument_GetSubject(testdata.issuerdoc);
    id = DIDURL_NewByDid(subject, "primary");
    rc = import_privatekey(id, storepass, "issuer.primary.sk", 0);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.issuerdoc, NULL, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.issuerdoc;
}

DIDDocument *TestData_LoadUser1Doc(void)
{
    DIDURL *id;
    DID *subject;
    int rc, status;
    DIDDocument *doc;

    if (!testdata.user1doc)
        testdata.user1doc = store_document("user1.id.json", "User1", 2);

    subject = DIDDocument_GetSubject(testdata.user1doc);
    id = DIDURL_NewByDid(subject, "key2");
    rc = import_privatekey(id, storepass, "user1.id.key2.sk", 2);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    id = DIDURL_NewByDid(subject, "key3");
    rc = import_privatekey(id, storepass, "user1.id.key3.sk", 2);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    id = DIDURL_NewByDid(subject, "primary");
    rc = import_privatekey(id, storepass, "user1.id.primary.sk", 2);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.user1doc, NULL, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.user1doc;
}

DIDDocument *TestData_LoadUser2Doc(void)
{
    DIDURL *id;
    DID *subject;
    int rc, status;
    DIDDocument *doc;

    if (!testdata.user2doc)
        testdata.user2doc = store_document("user2.id.json", "User2", 2);

    subject = DIDDocument_GetSubject(testdata.user2doc);
    id = DIDURL_NewByDid(subject, "primary");
    rc = import_privatekey(id, storepass, "user2.id.primary.sk", 2);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.user2doc, NULL, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.user2doc;
}

DIDDocument *TestData_LoadUser3Doc(void)
{
    DIDURL *id;
    DID *subject;
    int rc, status;
    DIDDocument *doc;

    if (!testdata.user3doc)
        testdata.user3doc = store_document("user3.id.json", "User3", 2);

    subject = DIDDocument_GetSubject(testdata.user3doc);
    id = DIDURL_NewByDid(subject, "primary");
    rc = import_privatekey(id, storepass, "user3.id.primary.sk", 2);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.user3doc, NULL, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.user3doc;
}

DIDDocument *TestData_LoadIssuerIdDoc(void)
{
    DIDURL *id;
    DID *subject;
    int rc, status;
    DIDDocument *doc;

    if (!testdata.issuerIddoc)
        testdata.issuerIddoc = store_document("issuer.id.json", "Issuer", 2);

    subject = DIDDocument_GetSubject(testdata.issuerIddoc);
    id = DIDURL_NewByDid(subject, "primary");
    rc = import_privatekey(id, storepass, "issuer.id.primary.sk", 2);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.issuerIddoc, NULL, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.issuerIddoc;
}

DIDDocument *TestData_LoadEmptyCtmDoc(void)
{
    DIDDocument *doc;
    DID *subject;
    int status;

    TestData_LoadIssuerDoc();
    TestData_LoadDoc();

    if (!testdata.emptyctmdoc)
        testdata.emptyctmdoc = store_document("customized-did-empty.json", "empty customized doc", 0);

    subject = DIDDocument_GetSubject(testdata.emptyctmdoc);
    if (!subject)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.emptyctmdoc, NULL, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.emptyctmdoc;
}

DIDDocument *TestData_LoadCtmDoc(void)
{
    DIDDocument *doc;
    DID *subject;
    DIDURL *id;
    int rc, status;

    TestData_LoadIssuerDoc();
    TestData_LoadDoc();

    if (!testdata.ctmdoc)
        testdata.ctmdoc = store_document("customized-did.json", "customized doc", 0);

    subject = DIDDocument_GetSubject(testdata.ctmdoc);
    if (!subject)
        return NULL;

    id = DIDURL_NewByDid(subject, "k1");
    rc = import_privatekey(id, storepass, "customized.k1.sk", 0);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    id = DIDURL_NewByDid(subject, "k2");
    rc = import_privatekey(id, storepass, "customized.k2.sk", 0);
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.ctmdoc, NULL, false, storepass))
        return NULL;

    DIDDocument_Destroy(doc);

    return testdata.ctmdoc;
}

static int import_ctmdid_privatekey(DID *did, const char *storepass)
{
    DIDURL *id;
    int rc;

    assert(did);

    id = DIDURL_NewByDid(did, "k1");
    rc = import_privatekey(id, storepass, "customized.k1.sk", 0);
    DIDURL_Destroy(id);
    if (rc)
        return -1;

    id = DIDURL_NewByDid(did, "k2");
    rc = import_privatekey(id, storepass, "customized.k2.sk", 0);
    DIDURL_Destroy(id);
    if (rc)
        return -1;

    return 0;
}

//1:3
DIDDocument *TestData_LoadEmptyCtmDoc_MultisigOne(void)
{
    DIDDocument *doc, *controller_doc;
    DID *subject;
    DIDURL *signkey;
    int status;

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.emptyctmdoc_multisigone)
        testdata.emptyctmdoc_multisigone = store_document("customized-multisigone-empty.json", "empty ctmdoc_1:3", 0);

    subject = DIDDocument_GetSubject(testdata.emptyctmdoc_multisigone);
    if (!subject)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.emptyctmdoc_multisigone, signkey, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.emptyctmdoc_multisigone;
}

//1:3
DIDDocument *TestData_LoadCtmDoc_MultisigOne(void)
{
    DIDDocument *doc, *controller_doc;
    DID *subject;
    DIDURL *signkey;
    int status;

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.ctmdoc_multisigone)
        testdata.ctmdoc_multisigone = store_document("customized-multisigone.json", "ctmdoc_1:3", 0);

    subject = DIDDocument_GetSubject(testdata.ctmdoc_multisigone);
    if (!subject)
        return NULL;

    if (import_ctmdid_privatekey(subject, storepass) < 0)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.ctmdoc_multisigone, signkey, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.ctmdoc_multisigone;
}

//2:3
DIDDocument *TestData_LoadEmptyCtmDoc_MultisigTwo(void)
{
    DIDDocument *doc, *controller_doc;
    DID *subject;
    DIDURL *signkey;
    int status;

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.emptyctmdoc_multisigtwo)
        testdata.emptyctmdoc_multisigtwo = store_document("customized-multisigtwo-empty.json", "empty ctmdoc_2:3", 0);

    subject = DIDDocument_GetSubject(testdata.emptyctmdoc_multisigtwo);
    if (!subject)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.emptyctmdoc_multisigtwo, signkey, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.emptyctmdoc_multisigtwo;
}

//2:3
DIDDocument *TestData_LoadCtmDoc_MultisigTwo(void)
{
    DIDDocument *doc, *controller_doc;
    DID *subject;
    DIDURL *signkey;
    int status;

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.ctmdoc_multisigtwo)
        testdata.ctmdoc_multisigtwo = store_document("customized-multisigtwo.json", "ctmdoc_2:3", 0);

    subject = DIDDocument_GetSubject(testdata.ctmdoc_multisigtwo);
    if (!subject)
        return NULL;

    if (import_ctmdid_privatekey(subject, storepass) < 0)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.ctmdoc_multisigtwo, signkey, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.ctmdoc_multisigtwo;
}

//3:3
DIDDocument *TestData_LoadEmptyCtmDoc_MultisigThree(void)
{
    DIDDocument *doc, *controller_doc;
    DID *subject;
    DIDURL *signkey;
    int status;

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.emptyctmdoc_multisigthree)
        testdata.emptyctmdoc_multisigthree = store_document("customized-multisigthree-empty.json", "empty ctmdoc_3:3", 0);

    subject = DIDDocument_GetSubject(testdata.emptyctmdoc_multisigthree);
    if (!subject)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.emptyctmdoc_multisigthree, signkey, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.emptyctmdoc_multisigthree;
}

//3:3
DIDDocument *TestData_LoadCtmDoc_MultisigThree(void)
{
    DIDDocument *doc, *controller_doc;
    DID *subject;
    DIDURL *signkey;
    int status;

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.ctmdoc_multisigthree)
        testdata.ctmdoc_multisigthree = store_document("customized-multisigthree.json", "ctmdoc_3:3", 0);

    subject = DIDDocument_GetSubject(testdata.ctmdoc_multisigthree);
    if (!subject)
        return NULL;

    if (import_ctmdid_privatekey(subject, storepass) < 0)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, &status, true);
    if (!doc && !DIDDocument_PublishDID(testdata.ctmdoc_multisigthree, signkey, false, storepass))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.ctmdoc_multisigthree;
}

const char *TestData_LoadRestoreMnemonic(void)
{
    if (!testdata.restoreMnemonic)
        testdata.restoreMnemonic = load_testdata_file("mnemonic.restore", 0);

    return testdata.restoreMnemonic;
}

void TestData_Free(void)
{
    DIDStore_Close(testdata.store);

    if (testdata.rootidentity)
        RootIdentity_Destroy(testdata.rootidentity);

    if (testdata.issuerdoc)
        DIDDocument_Destroy(testdata.issuerdoc);
    if (testdata.issuerJson)
        free((void*)testdata.issuerJson);
    if (testdata.issuerCompactJson)
        free((void*)testdata.issuerCompactJson);
    if (testdata.issuerNormalizedJson)
        free((void*)testdata.issuerNormalizedJson);

    if (testdata.doc)
        DIDDocument_Destroy(testdata.doc);
    if (testdata.docJson)
        free((void*)testdata.docJson);
    if (testdata.docCompactJson)
        free((void*)testdata.docCompactJson);
    if (testdata.docNormalizedJson)
        free((void*)testdata.docNormalizedJson);

    if (testdata.controllerdoc)
        DIDDocument_Destroy(testdata.controllerdoc);
    if (testdata.user1doc)
        DIDDocument_Destroy(testdata.user1doc);
    if (testdata.user2doc)
        DIDDocument_Destroy(testdata.user2doc);
    if (testdata.user3doc)
        DIDDocument_Destroy(testdata.user3doc);
    if (testdata.issuerIddoc)
        DIDDocument_Destroy(testdata.issuerIddoc);

    if (testdata.emptyctmdoc)
        DIDDocument_Destroy(testdata.emptyctmdoc);
    if (testdata.ctmdoc)
        DIDDocument_Destroy(testdata.ctmdoc);

    if (testdata.emptyctmdoc_multisigone)
        DIDDocument_Destroy(testdata.emptyctmdoc_multisigone);
    if (testdata.ctmdoc_multisigone)
        DIDDocument_Destroy(testdata.ctmdoc_multisigone);

    if (testdata.emptyctmdoc_multisigtwo)
        DIDDocument_Destroy(testdata.emptyctmdoc_multisigtwo);
    if (testdata.ctmdoc_multisigtwo)
        DIDDocument_Destroy(testdata.ctmdoc_multisigtwo);

    if (testdata.emptyctmdoc_multisigthree)
        DIDDocument_Destroy(testdata.emptyctmdoc_multisigthree);
    if (testdata.ctmdoc_multisigthree)
        DIDDocument_Destroy(testdata.ctmdoc_multisigthree);

    if (testdata.profileVc)
        Credential_Destroy(testdata.profileVc);
    if (testdata.profileVcCompactJson)
        free((void*)testdata.profileVcCompactJson);
    if (testdata.profileVcNormalizedJson)
        free((void*)testdata.profileVcNormalizedJson);

    if (testdata.emailVc)
        Credential_Destroy(testdata.emailVc);
    if (testdata.emailVcCompactJson)
        free((void*)testdata.emailVcCompactJson);
    if (testdata.emailVcNormalizedJson)
        free((void*)testdata.emailVcNormalizedJson);

    if (testdata.passportVc)
        Credential_Destroy(testdata.passportVc);
    if (testdata.passportVcCompactJson)
        free((void*)testdata.passportVcCompactJson);
    if (testdata.passportVcNormalizedJson)
        free((void*)testdata.passportVcNormalizedJson);

    if (testdata.twitterVc)
        Credential_Destroy(testdata.twitterVc);
    if (testdata.twitterVcCompactJson)
        free((void*)testdata.twitterVcCompactJson);
    if (testdata.twitterVcNormalizedJson)
        free((void*)testdata.twitterVcNormalizedJson);

    if (testdata.Vc)
        Credential_Destroy(testdata.Vc);
    if (testdata.VcCompactJson)
        free((void*)testdata.VcCompactJson);
    if (testdata.VcNormalizedJson)
        free((void*)testdata.VcNormalizedJson);

    if (testdata.vp)
        Presentation_Destroy(testdata.vp);
    if (testdata.vpNormalizedJson)
        free((void*)testdata.vpNormalizedJson);

    if (testdata.restoreMnemonic)
        free((void*)testdata.restoreMnemonic);

    memset(&testdata, 0, sizeof(testdata));
}

/////////////////////////////////////////
const char *Generater_Publickey(char *publickeybase58, size_t size)
{
    const char *mnemonic;
    HDKey hk, *privateIdentity;
    HDKey _derivedkey, *derivedkey;

    if (size < PUBLICKEY_BASE58_BYTES)
        return NULL;

    mnemonic = Mnemonic_Generate(language);
    if (!mnemonic || !*mnemonic)
        return NULL;

    privateIdentity = HDKey_FromMnemonic(mnemonic, "", language, &hk);
    Mnemonic_Free((void*)mnemonic);
    if (!privateIdentity)
        return NULL;

    derivedkey = HDKey_GetDerivedKey(privateIdentity, &_derivedkey, 5, 44 | HARDENED,
            0 | HARDENED, 0 | HARDENED, 0, 0);
    if (!derivedkey)
        return NULL;

    return HDKey_GetPublicKeyBase58(derivedkey, publickeybase58, size);
}

HDKey *Generater_KeyPair(HDKey *hdkey)
{
    const char *mnemonic;
    HDKey hk, *privateIdentity;

    mnemonic = Mnemonic_Generate(language);
    if (!mnemonic || !*mnemonic)
        return NULL;

    privateIdentity = HDKey_FromMnemonic(mnemonic, "", language, &hk);
    Mnemonic_Free((void*)mnemonic);
    if (!privateIdentity)
        return NULL;

    return HDKey_GetDerivedKey(privateIdentity, hdkey, 5, 44 | HARDENED,
           0 | HARDENED, 0 | HARDENED, 0, 0);
}

