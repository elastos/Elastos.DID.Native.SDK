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
#include "testadapter.h"

#if defined(_WIN32) || defined(_WIN64)
    #include <crystal.h>
#else
    #include "simulateadapter.h"
#endif

#define HARDENED                       0x80000000

const char *VERSION[3] = {"v1-backup", "v1", "v2"};

typedef struct TestData {
    char dkey[128];
    void *dvalue;
} TestData;

typedef struct CompatibleData {
    DIDStore *store;
    RootIdentity *rootidentity;

    TestData testdata[512];
    int dsize;
} CompatibleData;

typedef struct Dir_Copy_Helper {
    const char *srcpath;
    const char *dstpath;
} Dir_Copy_Helper;

CompatibleData compatibledata;
static int gDummyType;

char *get_store_path(char* path, const char *dir)
{
    assert(path);
    assert(dir);

    if(!getcwd(path, PATH_MAX)) {
        printf("\nCan't get current dir.");
        return NULL;
    }

    strcat(path, PATH_STEP);
    strcat(path, dir);
    return path;
}

static char *get_testdata_path(char *path, char *file, int version)
{
    size_t len;

    assert(path);

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

bool file_exist(const char *path)
{
    return test_path(path) == S_IFREG;
}

bool dir_exist(const char* path)
{
    return test_path(path) == S_IFDIR;
}

static char *get_did_path(char *path, char *did, char *type, int version)
{
    char file[128];

    assert(path);
    assert(did);

    strcpy(file, did);
    if (version != 0)
        strcat(file, ".id");

    if (type) {
        strcat(file, ".");
        strcat(file, type);
    }
    strcat(file, ".json");

    get_testdata_path(path, file, version);
    return path;
}

static char *get_credential_path(char *path, char *did, char *vc, char *type, int version)
{
    char file[120];

    assert(path);

    if (version != 0) {
        strcpy(file, did);
        strcat(file, ".vc");
        strcat(file, ".");
        strcat(file, vc);
    } else {
        strcpy(file, vc);
    }

    if (type) {
        strcat(file, ".");
        strcat(file, type);
    }

    strcat(file, ".json");

    get_testdata_path(path, file, version);
    return path;
}

static char *get_presentation_path(char *path, char *did, char *vp, char *type, int version)
{
    char file[120];

    assert(path);

    if (version == 0) {
        strcpy(file, vp);
    } else {
        strcpy(file, did);
        strcat(file, ".vp.");
        strcat(file, vp);
    }

    if (type) {
        strcat(file, ".");
        strcat(file, type);
    }

    strcat(file, ".json");

    get_testdata_path(path, file, version);
    return path;
}

static char *get_ticket_path(char *path, char *did)
{
    char file[120];

    assert(path);
    assert(did);

    strcpy(file, did);
    strcat(file, ".tt.json");

    get_testdata_path(path, file, 2);
    return path;
}

static char *get_privatekey_path(char *path, const char *did, const char *fragment, int version)
{
    char file[120];

    assert(path);
    assert(did);
    assert(fragment);

    strcpy(file, did);
    if (version != 0)
        strcat(file, ".id.");
    else
        strcat(file, ".");
    strcat(file, fragment);
    strcat(file, ".sk");

    get_testdata_path(path, file, version);
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

static int import_privatekey(DIDURL *id, const char *storepass, const char *file, int version)
{
    const char *skbase;
    uint8_t extendedkey[EXTENDEDKEY_BYTES];
    ssize_t size;

    assert(id);
    assert(storepass && *storepass);
    assert(file);

    skbase = load_file(file);
    if (!skbase || !*skbase)
        return -1;

    size = b58_decode(extendedkey, sizeof(extendedkey), skbase);
    free((void*)skbase);
    if (version != 0) {
        if (size != EXTENDEDKEY_BYTES)
            return -1;
    }

    if (DIDStore_StorePrivateKey(compatibledata.store, storepass, id, extendedkey, size) == -1)
        return -1;

    return 0;
}

static void *get_testdata(char *dkey)
{
    int i;
    TestData *data;

    assert(dkey && *dkey);

    if (strncmp(dkey, "res:", 4))
        return NULL;

    for(i = 0; i < compatibledata.dsize; i++) {
        data = &compatibledata.testdata[i];
        if (!strcmp(data->dkey, dkey))
            return data->dvalue;
    }

    return NULL;
}

static int set_testdata(char *dkey, void *dvalue)
{
    assert(dkey);
    assert(dvalue);

    if (strncmp(dkey, "res:", 4))
        return -1;

    strcpy(compatibledata.testdata[compatibledata.dsize].dkey, dkey);
    compatibledata.testdata[compatibledata.dsize++].dvalue = dvalue;
    return 0;
}

static void did_basekey(char *basekey, char *did, char *type, int version, bool json)
{
    char _version[10];

    assert(basekey);
    assert(did);

    sprintf(_version, "%d", version);

    strcpy(basekey, "res:");
    if (json)
        strcat(basekey, "json:");
    strcat(basekey, "did");
    strcat(basekey, _version);
    strcat(basekey, ":");
    strcat(basekey, did);
    if (type) {
        strcat(basekey, ":");
        strcat(basekey, type);
    }
}

static void credential_basekey(char *basekey, char *did, char *vc, char *type, int version, bool json)
{
    char _version[10];

    assert(basekey);
    assert(vc);

    sprintf(_version, "%d", version);

    strcpy(basekey, "res:");
    if (json)
        strcat(basekey, "json:");
    strcat(basekey, "vc");
    strcat(basekey, _version);
    strcat(basekey, ":");
    if (did) {
       strcat(basekey, did);
       strcat(basekey, ":");
    }
    strcat(basekey, vc);
    if (type) {
        strcat(basekey, ":");
        strcat(basekey, type);
    }
}

static void presentation_basekey(char *basekey, char *did, char *vp, char *type, int version, bool json)
{
    char _version[10];

    assert(basekey);
    assert(vp);

    sprintf(_version, "%d", version);

    strcpy(basekey, "res:");
    if (json)
        strcat(basekey, "json:");
    strcat(basekey, "vp");
    strcat(basekey, _version);
    strcat(basekey, ":");
    if (did) {
        strcat(basekey, did);
        strcat(basekey, ":");
    }
    strcat(basekey, vp);
    if (type) {
        strcat(basekey, ":");
        strcat(basekey, type);
    }
}

void ticket_basekey(char *basekey, char *did, bool json)
{
    assert(basekey);
    assert(did);

    strcpy(basekey, "res:");
    if (json)
        strcat(basekey, "json:");
    strcat(basekey, "tt:");
    strcat(basekey, did);
}

const char *TestData_GetDocumentJson(char *did, char *type, int version)
{
    char path[PATH_MAX * 2], basekey[120] = {0};
    const char *data;
    void *dvalue;

    assert(did);

    did_basekey(basekey, did, type, version, true);
    dvalue = get_testdata(basekey);
    if (dvalue)
        return (const char*)dvalue;

    get_did_path(path, did, type, version);
    data = load_file(path);
    if (!data)
        return NULL;

    if (set_testdata(basekey, (void*)data) < 0) {
        free((void*)data);
        return NULL;
    }

    return data;
}

DIDDocument *TestData_GetDocument(char *did, char *type, int version)
{
    char path[PATH_MAX * 2], basekey[120] = {0};
    const char *keys[5] = {0};
    const char *data, *subject;
    char *idstring;
    DIDDocument *doc = NULL, *signerdoc = NULL;
    void *dvalue;
    DIDURL *signkey = NULL, *id;
    int rc, i, size = 0;

    assert(did);

    did_basekey(basekey, did, type, version, false);
    dvalue = get_testdata(basekey);
    if (dvalue)
        return (DIDDocument*)dvalue;

    data = TestData_GetDocumentJson(did, type, version);
    if (!data)
        return NULL;

    doc = DIDDocument_FromJson(data);
    if (!doc)
        return NULL;

    subject = doc->did.idstring;

    if (!type) {
        if (DIDStore_StoreDID(compatibledata.store, doc) < 0)
            goto errorExit;

        if (!DIDDocument_IsCustomizedDID(doc)) {
            keys[size++] = "primary";
            idstring = did;
        }

        if (!strcmp(did, "user1") || !strcmp(did, "foobar") || !strcmp(did, "document")) {
            keys[size++] = "key2";
            keys[size++] = "key3";
            idstring = did;
        }

        if (!strcmp(did, "controller")) {
            keys[size++] = "pk1";
            idstring = did;
        }

        if (!strncmp(did, "customized", 10)) {
            keys[size++] = "k1";
            keys[size++] = "k2";
            idstring = "customized";
        }

        for (i = 0; i < size; i++) {
            id = DIDURL_New(subject, keys[i]);
            get_privatekey_path(path, idstring, keys[i], version);
            rc = import_privatekey(id, storepass, path, version);
            DIDURL_Destroy(id);
            if (rc < 0)
                goto errorExit;
        }

        if (DIDDocument_IsCustomizedDID(doc)) {
            if (version == 0) {
                signerdoc = TestData_GetDocument("document", NULL, 0);
            } else {
                if (!strcmp("example", subject))
                    signerdoc = TestData_GetDocument("issuer", NULL, version);
                else
                    signerdoc = TestData_GetDocument("user1", NULL, version);
            }

            if (!signerdoc)
                goto errorExit;

            signkey = DIDDocument_GetDefaultPublicKey(signerdoc);
        }

        if (!DIDDocument_PublishDID(doc, signkey, false, storepass))
            goto errorExit;
    }

    if (set_testdata(basekey, (void*)doc) < 0)
        goto errorExit;

    return doc;

errorExit:
    DIDDocument_Destroy(doc);
    return NULL;
}

const char *TestData_GetCredentialJson(char *did, char *vc, char *type, int version)
{
    char path[PATH_MAX * 2], basekey[120] = {0};
    const char *data;
    void *dvalue;

    assert(vc);

    credential_basekey(basekey, did, vc, type, version, true);
    dvalue = get_testdata(basekey);
    if (dvalue)
        return (const char*)dvalue;

    get_credential_path(path, did, vc, type, version);
    data = load_file(path);
    if (!data)
        return NULL;

    if (set_testdata(basekey, (void*)data) < 0) {
        free((void*)data);
        return NULL;
    }

    return data;
}

Credential *TestData_GetCredential(char *did, char *vc, char *type, int version)
{
    char basekey[120] = {0};
    Credential *credential;
    const char *data;
    void *dvalue;

    assert(vc);

    credential_basekey(basekey, did, vc, type, version, false);
    dvalue = get_testdata(basekey);
    if (dvalue)
        return (Credential*)dvalue;

    data = TestData_GetCredentialJson(did, vc, type, version);
    if (!data)
        return NULL;

    credential = Credential_FromJson(data, NULL);
    if (!credential)
        return NULL;

    if (!type) {
        if (DIDStore_StoreCredential(compatibledata.store, credential) < 0) {
            Credential_Destroy(credential);
            return NULL;
        }
    }

    if (set_testdata(basekey, (void*)credential) < 0) {
        Credential_Destroy(credential);
        return NULL;
    }

    return credential;
}

const char *TestData_GetPresentationJson(char *did, char *vp, char *type, int version)
{
    char path[PATH_MAX * 2], basekey[120] = {0};
    const char *data;
    void *dvalue;

    assert(vp);

    presentation_basekey(basekey, did, vp, type, version, true);
    dvalue = get_testdata(basekey);
    if (dvalue)
        return (const char*)dvalue;

    get_presentation_path(path, did, vp, type, version);
    data = load_file(path);
    if (!data)
        return NULL;

    if (set_testdata(basekey, (void*)data) < 0) {
        free((void*)data);
        return NULL;
    }

    return data;
}

const char *TestData_GetTransferTicketJson(char *did)
{
    char path[PATH_MAX * 2], basekey[120] = {0};
    const char *data;
    void *dvalue;

    assert(did);

    ticket_basekey(basekey, did, true);
    dvalue = get_testdata(basekey);
    if (dvalue)
        return (const char*)dvalue;

    get_ticket_path(path, did);
    data = load_file(path);
    if (!data)
        return NULL;

    if (set_testdata(basekey, (void*)data) < 0) {
        free((void*)data);
        return NULL;
    }

    return data;
}

Presentation *TestData_GetPresentation(char *did, char *vp, char *type, int version)
{
    char basekey[120] = {0};
    Presentation *presentation;
    const char *data;
    void *dvalue;

    assert(vp);

    presentation_basekey(basekey, did, vp, type, version, false);
    dvalue = get_testdata(basekey);
    if (dvalue)
        return (Presentation*)dvalue;

    data = TestData_GetPresentationJson(did, vp, type, version);
    if (!data)
        return NULL;

    presentation = Presentation_FromJson(data);
    if (!presentation)
        return NULL;

    if (set_testdata(basekey, (void*)presentation) < 0) {
        Presentation_Destroy(presentation);
        return NULL;
    }

    return presentation;
}

TransferTicket *TestData_GetTransferTicket(char *did)
{
    char basekey[120] = {0};
    TransferTicket *ticket;
    const char *data;
    void *dvalue;

    assert(did);

    ticket_basekey(basekey, did, false);
    dvalue = get_testdata(basekey);
    if (dvalue)
        return (TransferTicket*)dvalue;

    data = TestData_GetTransferTicketJson(did);
    if (!data)
        return NULL;

    ticket = TransferTicket_FromJson(data);
    if (!ticket)
        return NULL;

    if (set_testdata(basekey, (void*)ticket) < 0) {
        TransferTicket_Destroy(ticket);
        return NULL;
    }

    return ticket;
}


/////////////////////////////////////
void TestData_Init(int dummy)
{
    gDummyType = dummy;
}

void TestData_Deinit(void)
{
#if !defined(_WIN32) && !defined(_WIN64)
    if (gDummyType == 2)
        SimulatedAdapter_Shutdown();
#endif

    DummyAdapter_Cleanup(0);
}

static DIDStore *setup_store(bool dummybackend, const char *root)
{
    char cachedir[PATH_MAX];

    assert(root);

    sprintf(cachedir, "%s%s%s", getenv("HOME"), PATH_STEP, ".cache.did.elastos");
    compatibledata.store = DIDStore_Open(root);

    if (!dummybackend) {
        if (DIDBackend_InitializeDefault(TestDIDAdapter_CreateIdTransaction, resolver, cachedir) < 0)
            return NULL;
    } else {
#if !defined(_WIN32) && !defined(_WIN64)
        if (gDummyType == 2)
            SimulatedAdapter_Set(cachedir);
        else
#endif
            DummyAdapter_Set(cachedir);
    }

    return compatibledata.store;
}

DIDStore *TestData_SetupStore(bool dummybackend)
{
    char _path[PATH_MAX];
    char *root;

    root = get_store_path(_path, "DIDStore");
    delete_file(root);
    return setup_store(dummybackend, root);
}

DIDStore *TestData_SetupTestStore(bool dummybackend, int version)
{
    char _path[PATH_MAX], _newpath[PATH_MAX];
    char *path, *newpath;

    path = get_file_path(_path, PATH_MAX, 11, "..", PATH_STEP, "etc", PATH_STEP,
        "did", PATH_STEP, "resources", PATH_STEP, VERSION[version], PATH_STEP, "teststore");
    if (!path)
        return NULL;

    if (version == 1) {
        newpath = get_file_path(_newpath, PATH_MAX, 11, "..", PATH_STEP, "etc", PATH_STEP,
            "did", PATH_STEP, "resources", PATH_STEP, VERSION[0], PATH_STEP, "teststore");
        if (!newpath)
            return NULL;

        delete_file(newpath);
        dir_copy(newpath, path);
        path = newpath;
    }

    return setup_store(dummybackend, path);
}

DIDStore *TestData_GetStore(void)
{
    if (compatibledata.store)
        return compatibledata.store;

    compatibledata.store = TestData_SetupStore(true);
    return compatibledata.store;
}

RootIdentity *TestData_InitIdentity(DIDStore *store)
{
    const char *mnemonic;

    mnemonic = Mnemonic_Generate(language);
    compatibledata.rootidentity = RootIdentity_Create(mnemonic, passphrase, true, store, storepass);
    Mnemonic_Free((void*)mnemonic);

    return compatibledata.rootidentity;
}

void TestData_Cleanup(void)
{
    int i;
    TestData *testdata;
    char *dkey;
    void *dvalue;

    for (i = 0; i < compatibledata.dsize; i++) {
        testdata = &compatibledata.testdata[i];
        dkey = testdata->dkey;
        dvalue = testdata->dvalue;
        if (!strncmp(dkey, "res:did", 7)) {
            DIDDocument_Destroy((DIDDocument*)dvalue);
        } else if (!strncmp(dkey, "res:vc", 6)) {
            Credential_Destroy((Credential*)dvalue);
        } else if (!strncmp(dkey, "res:vp", 6)) {
            Presentation_Destroy((Presentation*)dvalue);
        } else if (!strncmp(dkey, "res:tt", 6)) {
            TransferTicket_Destroy((TransferTicket*)dvalue);
        } else {
            free(dvalue);
        }
    }

    compatibledata.dsize = 0;
}

void TestData_Reset(int type)
{
#if !defined(_WIN32) && !defined(_WIN64)
    if (gDummyType == 2)
        SimulatedAdapter_Reset(type);
#endif

    DummyAdapter_Cleanup(type);
}

void TestData_Free(void)
{
    DIDStore_Close(compatibledata.store);

    if (compatibledata.rootidentity)
        RootIdentity_Destroy(compatibledata.rootidentity);

#if !defined(_WIN32) && !defined(_WIN64)
    if (gDummyType == 2)
        SimulatedAdapter_Reset(0);
#endif

    TestData_Cleanup();
    memset(&compatibledata, 0, sizeof(compatibledata));
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

