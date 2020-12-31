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
    #include "testadapter/didtest_adapter.h"
#endif

#define HARDENED                       0x80000000

typedef struct TestData {
    DIDStore *store;

    DIDDocument *issuerdoc;
    char *issuerJson;
    char *issuerCompactJson;
    char *issuerNormalizedJson;

    DIDDocument *doc;
    char *docJson;
    char *docCompactJson;
    char *docNormalizedJson;

    DIDDocument *controllerdoc;

    DIDDocument *emptyctmdoc;
    DIDDocument *ctmdoc;

    DIDDocument *emptyctmdoc_multisigone;
    DIDDocument *ctmdoc_multisigone;

    DIDDocument *emptyctmdoc_multisigtwo;
    DIDDocument *ctmdoc_multisigtwo;

    DIDDocument *emptyctmdoc_multisigthree;
    DIDDocument *ctmdoc_multisigthree;

    Credential *profileVc;
    char *profileVcCompactJson;
    char *profileVcNormalizedJson;

    Credential *emailVc;
    char *emailVcCompactJson;
    char *emailVcNormalizedJson;

    Credential *passportVc;
    char *passportVcCompactJson;
    char *passportVcNormalizedJson;

    Credential *twitterVc;
    char *twitterVcCompactJson;
    char *twitterVcNormalizedJson;

    Credential *Vc;
    char *VcCompactJson;
    char *VcNormalizedJson;

    Presentation *vp;
    char *vpNormalizedJson;

    char *restoreMnemonic;
} TestData;

TestData testdata;

static DIDAdapter *adapter;
static DummyAdapter *dummyadapter;

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

char *get_path(char *path, const char *file)
{
    size_t len;

    assert(file);
    assert(*file);

    len = snprintf(path, PATH_MAX, "..%setc%sdid%sresources%stestdata%s%s",
        PATH_STEP, PATH_STEP, PATH_STEP, PATH_STEP, PATH_STEP, file);
        if (len < 0 || len > PATH_MAX)
            return NULL;

    return path;
}

char *load_path(const char *file)
{
    char *readstring = NULL;
    size_t reclen, bufferlen;
    struct stat st;
    int fd;

    assert(file && *file);

    fd = open(file, O_RDONLY);
    if (fd == -1)
        return NULL;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }

    bufferlen = st.st_size;
    readstring = calloc(1, bufferlen + 1);
    if (!readstring)
        return NULL;

    reclen = read(fd, readstring, bufferlen);
    if(reclen == 0 || reclen == -1)
        return NULL;

    close(fd);
    return readstring;
}

int store_file(const char *path, const char *string)
{
    int fd;
    size_t len, size;

    if (!path || !*path || !string)
        return -1;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1)
        return -1;

    len = strlen(string);
    size = write(fd, string, len);
    if (size < len) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static char *load_testdata_file(const char *file)
{
    char _path[PATH_MAX];
    char *readstring = NULL, *path;

    assert(file && *file);

    path = get_path(_path, file);
    if (!path)
        return NULL;

    return load_path(path);
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

static int list_directory(const char *path, const char *pattern,
        int (*callback)(const char *name, void *context), void *context)
{
    char full_pattern[PATH_MAX];
    size_t len;

    assert(path);
    assert(pattern);

    len = snprintf(full_pattern, sizeof(full_pattern), "%s%s%s", path, PATH_STEP, pattern);
    if (len == sizeof(full_pattern))
        full_pattern[len-1] = 0;

#if defined(_WIN32) || defined(_WIN64)
    struct _finddata_t c_file;
    intptr_t hFile;

    if ((hFile = _findfirst(full_pattern, &c_file )) == -1L)
        return -1;

    do {
        if(callback(c_file.name, context) < 0)
            break;
    } while (_findnext(hFile, &c_file) == 0);

    _findclose(hFile);
#else
    glob_t gl;
    size_t pos = strlen(path) + 1;

    memset(&gl, 0, sizeof(gl));

    glob(full_pattern, GLOB_DOOFFS, NULL, &gl);

    for (int i = 0; i < gl.gl_pathc; i++) {
        char *fn = gl.gl_pathv[i] + pos;
        if(callback(fn, context) < 0)
            break;
    }

    globfree(&gl);
#endif

    return 0;
}

static int test_paths(const char *path)
{
    struct stat s;

    assert(path);

    if (stat(path, &s) < 0)
        return -1;

    if (s.st_mode & S_IFDIR)
        return S_IFDIR;
    else if (s.st_mode & S_IFREG)
        return S_IFREG;
    else
        return -1;
}

void delete_file(const char *path);

static int delete_file_helper(const char *path, void *context)
{
    char fullpath[PATH_MAX];
    int len;

    if (!path)
        return 0;

    if (strcmp(path, ".") != 0 && strcmp(path, "..") != 0) {
        len = snprintf(fullpath, sizeof(fullpath), "%s%s%s", (char *)context, PATH_STEP, path);
        if (len < 0 || len > PATH_MAX)
            return -1;

        delete_file(fullpath);
    }

    return 0;
}

void delete_file(const char *path)
{
    int rc;

    if (!path)
        return;

    rc = test_paths(path);
    if (rc < 0)
        return;
    else if (rc == S_IFDIR) {
        list_directory(path, ".*", delete_file_helper, (void *)path);

        if (list_directory(path, "*", delete_file_helper, (void *)path) == 0)
            rmdir(path);
    } else
        remove(path);
}

static Credential *store_credential(const char *file, const char *alias)
{
    Credential *cred;
    const char *data;

    data = load_testdata_file(file);
    if (!data)
        return NULL;

    cred = Credential_FromJson(data, NULL);
    free((void*)data);
    if (!cred)
        return NULL;

    CredentialMetaData *metadata = Credential_GetMetaData(cred);
    if (!metadata) {
        Credential_Destroy(cred);
        return NULL;
    }

    if (CredentialMetaData_SetAlias(metadata, alias) < 0) {
        Credential_Destroy(cred);
        return NULL;
    }

    if (DIDStore_StoreCredential(testdata.store, cred) == -1) {
        Credential_Destroy(cred);
        return NULL;
    }

    return cred;
}

static DIDDocument *store_document(const char *file, const char *alias)
{
    DIDDocument *doc;
    const char *string;
    DID did;
    int rc;

    string = load_testdata_file(file);
    if (!string)
        return NULL;

    doc = DIDDocument_FromJson(string);
    free((void*)string);
    if (!doc)
        return NULL;

    strcpy(did.idstring, doc->did.idstring);
    DIDMetaData *metadata = DIDDocument_GetMetaData(doc);
    if (!metadata) {
        DIDDocument_Destroy(doc);
        return NULL;
    }

    if (DIDMetaData_SetAlias(metadata, alias) < 0) {
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
    return test_paths(path) == S_IFREG;
}

bool dir_exist(const char* path)
{
    return test_paths(path) == S_IFDIR;
}

static int import_privatekey(DIDURL *id, const char *storepass, const char *file)
{
    char *skbase;
    uint8_t privatekey[EXTENDEDKEY_BYTES];
    HDKey _hdkey, *hdkey;

    if (!id || !file || !*file)
        return -1;

    skbase = load_testdata_file(file);
    if (!skbase || !*skbase)
        return -1;

    if (base58_decode(privatekey, sizeof(privatekey), skbase) == EXTENDEDKEY_BYTES) {
        hdkey = HDKey_FromExtendedKeyBase58(skbase, strlen(skbase), &_hdkey);
        if (!hdkey) {
            free(skbase);
            return -1;
        }

        memcpy(privatekey, HDKey_GetPrivateKey(hdkey), PRIVATEKEY_BYTES);
    }

    free(skbase);
    if (DIDStore_StorePrivateKey(testdata.store, storepass, DIDURL_GetDid(id),
            id, privatekey, PRIVATEKEY_BYTES) == -1)
        return -1;

    return 0;
}

DID *DID_Copy(DID *dest, DID *src)
{
    if (!dest || !src) {
        return NULL;
    }

    strcpy(dest->idstring, src->idstring);
    return dest;
}

DIDURL *DIDURL_Copy(DIDURL *dest, DIDURL *src)
{
    if (!dest || !src ) {
        return NULL;
    }

    strcpy(dest->did.idstring, src->did.idstring);
    strcpy(dest->fragment, src->fragment);

    return dest;
}

/////////////////////////////////////
int TestData_Init(bool dummy)
{
    char _dir[PATH_MAX];
    char *walletDir;

    walletDir = get_wallet_path(_dir, walletdir);
    if (!dummy && !dir_exist(walletDir)) {
        printf("Wallet Dir doesn't exist: %s\n", walletDir);
        return -1;
    }

#if defined(_WIN32) || defined(_WIN64)
    adapter = NULL;
#else
    adapter = dummy ? NULL : TestDIDAdapter_Create(walletDir, walletId, network, getpassword);
#endif

    dummyadapter = DummyAdapter_Create();
    return 0;
}

void TestData_Deinit(void)
{
#if !defined(_WIN32) && !defined(_WIN64)
    TestDIDAdapter_Destroy(adapter);
#endif
    DummyAdapter_Destroy();
}

DIDAdapter *TestData_GetAdapter(bool dummybackend)
{
    if (dummybackend)
        return &dummyadapter->adapter;

    return adapter;
}

static DIDStore *setup_store(bool dummybackend, const char *root)
{
    char cachedir[PATH_MAX];

    assert(root);

    sprintf(cachedir, "%s%s%s", getenv("HOME"), PATH_STEP, ".cache.did.elastos");
    if (dummybackend) {
        dummyadapter->reset(dummyadapter);
        testdata.store = DIDStore_Open(root, &dummyadapter->adapter);
        DIDBackend_Initialize(&dummyadapter->resolver, cachedir);
    } else {
        testdata.store = DIDStore_Open(root, adapter);
        DIDBackend_InitializeDefault(resolver, cachedir);
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

DIDStore *TestData_SetupTestStore(bool dummybackend)
{
    char _path[PATH_MAX];
    const char *path;

    path = get_file_path(_path, PATH_MAX, 9, "..", PATH_STEP, "etc", PATH_STEP,
        "did", PATH_STEP, "resources", PATH_STEP, "teststore");
    if (!path)
        return NULL;

    return setup_store(dummybackend, path);
}

int TestData_InitIdentity(DIDStore *store)
{
    const char *mnemonic;
    int rc;

    mnemonic = Mnemonic_Generate(language);
    rc = DIDStore_InitPrivateIdentity(store, storepass, mnemonic, passphase, language, false);
    Mnemonic_Free((void*)mnemonic);

    return rc;
}

const char *TestData_LoadIssuerJson(void)
{
    if (!testdata.issuerJson)
        testdata.issuerJson = load_testdata_file("issuer.json");

    return testdata.issuerJson;
}

const char *TestData_LoadIssuerCompJson(void)
{
    if (!testdata.issuerCompactJson)
        testdata.issuerCompactJson = load_testdata_file("issuer.compact.json");

    return testdata.issuerCompactJson;
}

const char *TestData_LoadIssuerNormJson(void)
{
    if (!testdata.issuerNormalizedJson)
        testdata.issuerNormalizedJson = load_testdata_file("issuer.normalized.json");

    return testdata.issuerNormalizedJson;
}

const char *TestData_LoadDocJson(void)
{
    if (!testdata.docJson)
        testdata.docJson = load_testdata_file("document.json");

    return testdata.docJson;
}

const char *TestData_LoadDocCompJson(void)
{
    if (!testdata.docCompactJson)
        testdata.docCompactJson = load_testdata_file("document.compact.json");

    return testdata.docCompactJson;
}

const char *TestData_LoadDocNormJson(void)
{
    if (!testdata.docNormalizedJson)
        testdata.docNormalizedJson = load_testdata_file("document.normalized.json");

    return testdata.docNormalizedJson;
}

Credential *TestData_LoadProfileVc(void)
{
    if (!testdata.profileVc)
        testdata.profileVc = store_credential("vc-profile.json", "profile vc");

    return testdata.profileVc;
}

const char *TestData_LoadProfileVcCompJson(void)
{
    if (!testdata.profileVcCompactJson)
        testdata.profileVcCompactJson = load_testdata_file("vc-profile.compact.json");

    return testdata.profileVcCompactJson;
}

const char *TestData_LoadProfileVcNormJson(void)
{
    if (!testdata.profileVcNormalizedJson)
        testdata.profileVcNormalizedJson = load_testdata_file("vc-profile.normalized.json");

    return testdata.profileVcNormalizedJson;
}

Credential *TestData_LoadEmailVc(void)
{
    if (!testdata.emailVc)
        testdata.emailVc = store_credential("vc-email.json", "email vc");

    return testdata.emailVc;
}

const char *TestData_LoadEmailVcCompJson(void)
{
    if (!testdata.emailVcCompactJson)
        testdata.emailVcCompactJson = load_testdata_file("vc-email.compact.json");

    return testdata.emailVcCompactJson;
}

const char *TestData_LoadEmailVcNormJson(void)
{
    if (!testdata.emailVcNormalizedJson)
        testdata.emailVcNormalizedJson = load_testdata_file("vc-email.normalized.json");

    return testdata.emailVcNormalizedJson;
}

Credential *TestData_LoadPassportVc(void)
{
    if (!testdata.passportVc)
        testdata.passportVc = store_credential("vc-passport.json", "passport vc");

    return testdata.passportVc;
}

const char *TestData_LoadPassportVcCompJson(void)
{
    if (!testdata.passportVcCompactJson)
        testdata.passportVcCompactJson = load_testdata_file("vc-passport.compact.json");

    return testdata.passportVcCompactJson;
}

const char *TestData_LoadPassportVcNormJson(void)
{
    if (!testdata.passportVcNormalizedJson)
        testdata.passportVcNormalizedJson = load_testdata_file("vc-passport.normalized.json");

    return testdata.passportVcNormalizedJson;
}

Credential *TestData_LoadTwitterVc(void)
{
    if (!testdata.twitterVc)
        testdata.twitterVc = store_credential("vc-twitter.json", "twitter vc");

    return testdata.twitterVc;
}

const char *TestData_LoadTwitterVcCompJson(void)
{
    if (!testdata.twitterVcCompactJson)
        testdata.twitterVcCompactJson = load_testdata_file("vc-twitter.compact.json");

    return testdata.twitterVcCompactJson;
}

const char *TestData_LoadTwitterVcNormJson(void)
{
    if (!testdata.twitterVcNormalizedJson)
        testdata.twitterVcNormalizedJson = load_testdata_file("vc-twitter.normalized.json");

    return testdata.twitterVcNormalizedJson;
}

Credential *TestData_LoadVc(void)
{
    if (!testdata.Vc)
        testdata.Vc = store_credential("vc-json.json", "test vc");

    return testdata.Vc;
}

const char *TestData_LoadVcCompJson(void)
{
    if (!testdata.VcCompactJson)
        testdata.VcCompactJson = load_testdata_file("vc-json.compact.json");

    return testdata.VcCompactJson;
}

const char *TestData_LoadVcNormJson(void)
{
    if (!testdata.VcNormalizedJson)
        testdata.VcNormalizedJson = load_testdata_file("vc-json.normalized.json");

    return testdata.VcNormalizedJson;
}

Presentation *TestData_LoadVp(void)
{
    if (!testdata.vp) {
        const char *data = load_testdata_file("vp.json");
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
        testdata.vpNormalizedJson = load_testdata_file("vp.normalized.json");

    return testdata.vpNormalizedJson;
}

DIDDocument *TestData_LoadDoc(void)
{
    DIDURL *id;
    DID *subject;
    int rc;
    DIDDocument *doc;

    if (!testdata.doc)
       testdata.doc = store_document("document.json", "doc test");

    subject = DIDDocument_GetSubject(testdata.doc);
    id = DIDURL_NewByDid(subject, "key2");
    rc = import_privatekey(id, storepass, "document.key2.sk");
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    id = DIDURL_NewByDid(subject, "key3");
    rc = import_privatekey(id, storepass, "document.key3.sk");
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    id = DIDURL_NewByDid(subject, "primary");
    rc = import_privatekey(id, storepass, "document.primary.sk");
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, NULL, false))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.doc;
}

DIDDocument *TestData_LoadControllerDoc(void)
{
    DIDURL *id;
    DID *subject;
    int rc;
    DIDDocument *doc;

    if (!testdata.controllerdoc)
       testdata.controllerdoc = store_document("controller.json", "controller test");

    subject = DIDDocument_GetSubject(testdata.controllerdoc);
    id = DIDURL_NewByDid(subject, "pk1");
    rc = import_privatekey(id, storepass, "controller.pk1.sk");
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    id = DIDURL_NewByDid(subject, "primary");
    rc = import_privatekey(id, storepass, "controller.primary.sk");
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, NULL, false))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.controllerdoc;
}

DIDDocument *TestData_LoadIssuerDoc(void)
{
    DIDURL *id;
    DID *subject;
    int rc;
    DIDDocument *doc;

    if (!testdata.issuerdoc)
        testdata.issuerdoc = store_document("issuer.json", "issuer test");

    subject = DIDDocument_GetSubject(testdata.issuerdoc);
    id = DIDURL_NewByDid(subject, "primary");
    rc = import_privatekey(id, storepass, "issuer.primary.sk");
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, NULL, false))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.issuerdoc;
}

DIDDocument *TestData_LoadEmptyCtmDoc(void)
{
    DIDDocument *doc;
    DID *subject;

    TestData_LoadIssuerDoc();
    TestData_LoadDoc();

    if (!testdata.emptyctmdoc)
        testdata.emptyctmdoc = store_document("customized-did-empty.json", "empty customized doc");

    subject = DIDDocument_GetSubject(testdata.emptyctmdoc);
    if (!subject)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, NULL, false))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.emptyctmdoc;
}

DIDDocument *TestData_LoadCtmDoc(void)
{
    DIDDocument *doc;
    DID *subject;
    DIDURL *id;
    int rc;

    TestData_LoadIssuerDoc();
    TestData_LoadDoc();

    if (!testdata.ctmdoc)
        testdata.ctmdoc = store_document("customized-did.json", "customized doc");

    subject = DIDDocument_GetSubject(testdata.ctmdoc);
    if (!subject)
        return NULL;

    id = DIDURL_NewByDid(subject, "k1");
    rc = import_privatekey(id, storepass, "customized.k1.sk");
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    id = DIDURL_NewByDid(subject, "k2");
    rc = import_privatekey(id, storepass, "customized.k2.sk");
    DIDURL_Destroy(id);
    if (rc)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, NULL, false))
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
    rc = import_privatekey(id, storepass, "customized.k1.sk");
    DIDURL_Destroy(id);
    if (rc)
        return -1;

    id = DIDURL_NewByDid(did, "k2");
    rc = import_privatekey(id, storepass, "customized.k2.sk");
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

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.emptyctmdoc_multisigone)
        testdata.emptyctmdoc_multisigone = store_document("customized-multisigone-empty.json", "empty ctmdoc_1:3");

    subject = DIDDocument_GetSubject(testdata.emptyctmdoc_multisigone);
    if (!subject)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, signkey, false))
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

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.ctmdoc_multisigone)
        testdata.ctmdoc_multisigone = store_document("customized-multisigone.json", "ctmdoc_1:3");

    subject = DIDDocument_GetSubject(testdata.ctmdoc_multisigone);
    if (!subject)
        return NULL;

    if (import_ctmdid_privatekey(subject, storepass) < 0)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, signkey, false))
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

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.emptyctmdoc_multisigtwo)
        testdata.emptyctmdoc_multisigtwo = store_document("customized-multisigtwo-empty.json", "empty ctmdoc_2:3");

    subject = DIDDocument_GetSubject(testdata.emptyctmdoc_multisigtwo);
    if (!subject)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, signkey, false))
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

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.ctmdoc_multisigtwo)
        testdata.ctmdoc_multisigtwo = store_document("customized-multisigtwo.json", "ctmdoc_2:3");

    subject = DIDDocument_GetSubject(testdata.ctmdoc_multisigtwo);
    if (!subject)
        return NULL;

    if (import_ctmdid_privatekey(subject, storepass) < 0)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, signkey, false))
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

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.emptyctmdoc_multisigthree)
        testdata.emptyctmdoc_multisigthree = store_document("customized-multisigthree-empty.json", "empty ctmdoc_3:3");

    subject = DIDDocument_GetSubject(testdata.emptyctmdoc_multisigthree);
    if (!subject)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, signkey, false))
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

    TestData_LoadIssuerDoc();
    TestData_LoadControllerDoc();
    controller_doc = TestData_LoadDoc();
    if (!controller_doc)
        return NULL;

    if (!testdata.ctmdoc_multisigthree)
        testdata.ctmdoc_multisigthree = store_document("customized-multisigthree.json", "ctmdoc_3:3");

    subject = DIDDocument_GetSubject(testdata.ctmdoc_multisigthree);
    if (!subject)
        return NULL;

    if (import_ctmdid_privatekey(subject, storepass) < 0)
        return NULL;

    signkey = DIDDocument_GetDefaultPublicKey(controller_doc);
    if (!signkey)
        return NULL;

    doc = DID_Resolve(subject, true);
    if (!doc && !DIDStore_PublishDID(testdata.store, storepass, subject, signkey, false))
        return NULL;
    DIDDocument_Destroy(doc);

    return testdata.ctmdoc_multisigthree;
}

const char *TestData_LoadRestoreMnemonic(void)
{
    if (!testdata.restoreMnemonic)
        testdata.restoreMnemonic = load_testdata_file("mnemonic.restore");

    return testdata.restoreMnemonic;
}

void TestData_Free(void)
{
    DIDStore_Close(testdata.store);

    if (testdata.issuerdoc)
        DIDDocument_Destroy(testdata.issuerdoc);
    if (testdata.issuerJson)
        free(testdata.issuerJson);
    if (testdata.issuerCompactJson)
        free(testdata.issuerCompactJson);
    if (testdata.issuerNormalizedJson)
        free(testdata.issuerNormalizedJson);

    if (testdata.doc)
        DIDDocument_Destroy(testdata.doc);
    if (testdata.docJson)
        free(testdata.docJson);
    if (testdata.docCompactJson)
        free(testdata.docCompactJson);
    if (testdata.docNormalizedJson)
        free(testdata.docNormalizedJson);

    if (testdata.controllerdoc)
        DIDDocument_Destroy(testdata.controllerdoc);

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
        free(testdata.profileVcCompactJson);
    if (testdata.profileVcNormalizedJson)
        free(testdata.profileVcNormalizedJson);

    if (testdata.emailVc)
        Credential_Destroy(testdata.emailVc);
    if (testdata.emailVcCompactJson)
        free(testdata.emailVcCompactJson);
    if (testdata.emailVcNormalizedJson)
        free(testdata.emailVcNormalizedJson);

    if (testdata.passportVc)
        Credential_Destroy(testdata.passportVc);
    if (testdata.passportVcCompactJson)
        free(testdata.passportVcCompactJson);
    if (testdata.passportVcNormalizedJson)
        free(testdata.passportVcNormalizedJson);

    if (testdata.twitterVc)
        Credential_Destroy(testdata.twitterVc);
    if (testdata.twitterVcCompactJson)
        free(testdata.twitterVcCompactJson);
    if (testdata.twitterVcNormalizedJson)
        free(testdata.twitterVcNormalizedJson);

    if (testdata.Vc)
        Credential_Destroy(testdata.Vc);
    if (testdata.VcCompactJson)
        free(testdata.VcCompactJson);
    if (testdata.VcNormalizedJson)
        free(testdata.VcNormalizedJson);

    if (testdata.vp)
        Presentation_Destroy(testdata.vp);
    if (testdata.vpNormalizedJson)
        free(testdata.vpNormalizedJson);

    if (testdata.restoreMnemonic)
        free(testdata.restoreMnemonic);

    memset(&testdata, 0, sizeof(testdata));
}

/////////////////////////////////////////
const char *Generater_Publickey(char *publickeybase58, size_t size)
{
    const char *mnemonic;
    HDKey hk, *privateIdentity;
    HDKey _derivedkey, *derivedkey;

    if (size < MAX_PUBLICKEY_BASE58)
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

