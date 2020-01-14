/*
 * Copyright (c) 2019 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_GLOB_H
#include <glob.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
#include <fnmatch.h>
#include <pthread.h>
#include <openssl/opensslv.h>
#include <cjson/cJSON.h>

#include "ela_did.h"
#include "didstore.h"
#include "common.h"
#include "credential.h"
#include "diddocument.h"
#include "crypto.h"
#include "HDkey.h"
#include "didbackend.h"
#include "credential.h"
#include "didmeta.h"
#include "credmeta.h"

DIDStore *storeInstance = NULL;

static const char *META_FILE = ".meta";
static char MAGIC[] = { 0x00, 0x0D, 0x01, 0x0D };
static char VERSION[] = { 0x00, 0x00, 0x00, 0x01 };

static const char *PATH_SEP = "/";
static const char *PRIVATE_DIR = "private";
static const char *HDKEY_FILE = "key";
static const char *INDEX_FILE = "index";
static const char *MNEMONIC_FILE = "mnemonic";

static const char *DID_DIR = "ids";
static const char *DOCUMENT_FILE = "document";
static const char *CREDENTIALS_DIR = "credentials";
static const char *CREDENTIAL_FILE = "credential";
static const char *PRIVATEKEYS_DIR = "privatekeys";

extern const char *ProofType;

typedef struct DID_List_Helper {
    DIDStore *store;
    DIDStore_GetDIDCallback *cb;
    void *context;
} DID_List_Helper;

typedef struct Cred_List_Helper {
    DIDStore *store;
    DIDStore_GetCredCallback *cb;
    void *context;
    DID did;
    const char *type;
} Cred_List_Helper;

static int test_path(const char *path)
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

static int list_dir(const char *path, const char *pattern,
        int (*callback)(const char *name, void *context), void *context)
{
    char full_pattern[PATH_MAX];
    size_t len;
    int rc = 0;

    assert(path);
    assert(pattern);

    len = snprintf(full_pattern, sizeof(full_pattern), "%s/%s", path, pattern);
    if (len == sizeof(full_pattern))
        full_pattern[len-1] = 0;

#if defined(_WIN32) || defined(_WIN64)
    struct _finddata_t c_file;
    intptr_t hFile;

    if ((hFile = _findfirst(full_pattern, &c_file )) == -1L)
        return -1;

    do {
        rc = callback(c_file.name, context);
        if(rc < 0) {
            break;
        }
    } while (_findnext(hFile, &c_file) == 0);

    _findclose(hFile);
#else
    glob_t gl;
    size_t pos = strlen(path) + 1;

    memset(&gl, 0, sizeof(gl));
    glob(full_pattern, GLOB_DOOFFS, NULL, &gl);
    for (int i = 0; i < gl.gl_pathc; i++) {
        char *fn = gl.gl_pathv[i] + pos;
        rc = callback(fn, context);
        if(rc < 0)
            break;
    }

    globfree(&gl);
#endif

    if (!rc)
        callback(NULL, context);

    return rc;
}

static void delete_file(const char *path);

static int delete_file_helper(const char *path, void *context)
{
    char fullpath[PATH_MAX];
    int len;

    if (!path)
        return 0;

    if (strcmp(path, ".") != 0 && strcmp(path, "..") != 0) {
        len = snprintf(fullpath, sizeof(fullpath), "%s/%s", (char *)context, path);
        if (len < 0 || len > PATH_MAX)
            return -1;

        delete_file(fullpath);
    }

    return 0;
}

static void delete_file(const char *path)
{
    int rc;

    assert(path);

    rc = test_path(path);
    if (rc < 0)
        return;

    if (rc == S_IFDIR) {
        list_dir(path, ".*", delete_file_helper, (void *)path);

        if (list_dir(path, "*", delete_file_helper, (void *)path) == 0)
            rmdir(path);
    } else {
        remove(path);
    }
}

static int get_dirv(char *path, bool create, int count, va_list components)
{
    struct stat st;
    int rc;

    assert(path);
    assert(count > 0);

    *path = 0;
    for (int i = 0; i < count; i++) {
        const char *component = va_arg(components, const char *);
        assert(component != NULL);
        strcat(path, component);

        rc = stat(path, &st);
        if (!create && rc < 0)
            return -1;

        if (create) {
            if (rc < 0) {
                if (errno != ENOENT || (errno == ENOENT && mkdir(path, S_IRWXU) < 0))
                    return -1;
            } else {
                if (!S_ISDIR(st.st_mode)) {
                    if (remove(path) < 0)
                        return -1;

                    if (mkdir(path, S_IRWXU) < 0)
                        return -1;
                }
            }
        }

        if (i < (count - 1))
            strcat(path, PATH_SEP);
    }

    return 0;
}

static int get_dir(char* path, bool create, int count, ...)
{
    va_list components;
    int rc;

    assert(path);
    assert(count > 0);

    va_start(components, count);
    rc = get_dirv(path, create, count, components);
    va_end(components);

    return rc;
}

static int get_file(char *path, bool create, int count, ...)
{
    const char *filename;
    va_list components;
    int rc;

    assert(path);
    assert(count > 0);

    va_start(components, count);
    rc = get_dirv(path, create, count - 1, components);
    if (rc < 0)
        return -1;

    filename = va_arg(components, const char *);
    strcat(path, PATH_SEP);
    strcat(path, filename);

    va_end(components);
    return 0;
}

static int store_file(const char *path, const char *string)
{
    int fd;
    size_t len, size;

    assert(path);
    assert(string);

    fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
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

static const char *load_file(const char *path)
{
    int fd;
    size_t size;
    struct stat st;
    const char *data;

    if (!path)
        return NULL;

    fd = open(path, O_RDONLY);
    if (fd == -1)
        return NULL;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }

    size = st.st_size;
    data = (const char*)calloc(1, size + 1);
    if (!data) {
        close(fd);
        return NULL;
    }

    if (read(fd, (char*)data, size) != size) {
        free((char*)data);
        close(fd);
        return NULL;
    }

    close(fd);
    return data;
}

static int is_empty_helper(const char *path, void *context)
{
    if (!path) {
        *(int *)context = 0;
        return 0;
    }

    *(int *)context = 1;
    return -1;
}

static bool is_empty(const char *path)
{
    int flag = 0;

    assert(path);

    if (list_dir(path, "*", is_empty_helper, &flag) < 0 && flag)
        return false;

    return true;
}

static int store_didmeta(DIDStore *store, DIDMeta *meta, DID *did)
{
    char path[PATH_MAX];
    const char *data;
    int rc;

    assert(store);
    assert(meta);
    assert(did);

    if (DIDMeta_IsEmpty(meta))
        return 0;

    if (get_file(path, 1, 4, store->root, DID_DIR, did->idstring, META_FILE) == -1)
        return -1;

    if (test_path(path) == S_IFDIR) {
        delete_file(path);
        return -1;
    }

    data = DIDMeta_ToJson(meta);
    if (!data) {
        delete_file(path);
        return -1;
    }

    rc = store_file(path, data);
    free((char*)data);
    return rc;
}

static int load_didmeta(DIDStore *store, DIDMeta *meta, const char *did)
{
    const char *data;
    char path[PATH_MAX];
    int rc;

    assert(store);
    assert(meta);
    assert(did);

    memset(meta, 0, sizeof(DIDMeta));
    if (get_file(path, 0, 4, store->root, DID_DIR, did, META_FILE) == -1)
        return 0;

    rc = test_path(path);
    if (rc < 0)
        return 0;

    if (rc == S_IFDIR) {
        delete_file(path);
        return -1;
    }

    data = load_file(path);
    if (!data)
        return -1;

    rc = DIDMeta_FromJson(meta, data);
    free((char*)data);
    return rc;
}

int didstore_loaddidmeta(DIDStore *store, DIDMeta *meta, DID *did)
{
    bool iscontain;

    if (!store || !meta || !did)
        return -1;

    iscontain = DIDStore_ContainsDID(store, did);
    if (!iscontain)
        return -1;

    return load_didmeta(store, meta, did->idstring);
}

int didstore_storedidmeta(DIDStore *store, DIDMeta *meta, DID *did)
{
    bool iscontain;

    if (!store || !did || !meta)
        return -1;

    iscontain = DIDStore_ContainsDID(store, did);
    if (!iscontain)
        return -1;

    return store_didmeta(store, meta, did);
}

static int store_credmeta(DIDStore *store, CredentialMeta *meta, DIDURL *id)
{
    char path[PATH_MAX];
    const char *data;
    int rc;

    assert(store);
    assert(meta);
    assert(id);

    if (CredentialMeta_IsEmpty(meta))
        return 0;

    data = CredentialMeta_ToJson(meta);
    if (!data)
        return -1;

    if (get_file(path, 1, 6, store->root, DID_DIR, id->did.idstring,
            CREDENTIALS_DIR, id->fragment, META_FILE) == -1) {
        free((char*)data);
        return -1;
    }

    if (test_path(path) == S_IFDIR) {
        free((char*)data);
        goto errorExit;
    }

    rc = store_file(path, data);
    free((char*)data);
    if (!rc)
        return 0;

errorExit:
    delete_file(path);

    if (get_dir(path, 0, 5, store->root, DID_DIR, id->did.idstring,
            CREDENTIALS_DIR, id->fragment) == 0) {
        if (is_empty(path))
            delete_file(path);
    }

    if (get_dir(path, 0, 4, store->root, DID_DIR, id->did.idstring, CREDENTIALS_DIR) == 0) {
        if (is_empty(path))
            delete_file(path);
    }

    return -1;
}

static int load_credmeta(DIDStore *store, CredentialMeta *meta, const char *did,
        const char *fragment)
{
    const char *data;
    char path[PATH_MAX];
    int rc;

    assert(store);
    assert(meta);
    assert(did);
    assert(fragment);

    memset(meta, 0, sizeof(CredentialMeta));
    if (get_file(path, 0, 6, store->root, DID_DIR, did, CREDENTIALS_DIR,
            fragment, META_FILE) == -1)
        return 0;

    rc = test_path(path);
    if (rc < 0)
        return 0;

    if (rc == S_IFDIR) {
        delete_file(path);
        return -1;
    }

    data = load_file(path);
    if (!data)
        return -1;

    rc = CredentialMeta_FromJson(meta, data);
    free((char*)data);
    return rc;
}

int didstore_storecredmeta(DIDStore *store, CredentialMeta *meta, DIDURL *id)
{
    bool iscontain;

    if (!store || !meta || !id)
        return -1;

    iscontain = DIDStore_ContainsCredential(store, DIDURL_GetDid(id), id);
    if (!iscontain)
        return -1;

    return store_credmeta(store, meta, id);
}

int didstore_loadcredmeta(DIDStore *store, CredentialMeta *meta, DIDURL *id)
{
    bool iscontain;

    if (!store || !meta || !id)
        return -1;

    iscontain = DIDStore_ContainsCredential(store, DIDURL_GetDid(id), id);
    if (!iscontain)
        return -1;

    return load_credmeta(store, meta, id->did.idstring, id->fragment);
}

static int create_store(DIDStore *store)
{
    int fd;
    size_t size;
    char path[PATH_MAX];

    assert(store);

    if (get_file(path, 1, 2, store->root, META_FILE) == -1)
        return -1;

    fd = open(path, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1)
        return -1;

    size = write(fd, MAGIC, sizeof(MAGIC));
    if (size < sizeof(MAGIC)) {
        close(fd);
        return -1;
    }

    size = write(fd, VERSION, sizeof(VERSION));
    if (size < sizeof(VERSION)) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int check_store(DIDStore *store)
{
    int fd;
    char symbol[1];
    int i, flag = 0;
    size_t size;
    char path[PATH_MAX];

    assert(store);

    if (test_path(store->root) != S_IFDIR)
        return -1;

    if (get_file(path, 0, 2, store->root, META_FILE) == -1)
        return -1;

    fd = open(path, O_RDONLY);
    if (fd == -1)
        return -1;

    while (read(fd, symbol, sizeof(char)) == 1) {
        for (i = 0; i < sizeof(MAGIC); i++) {
            if (symbol[0] == MAGIC[i])
                flag = 1;
        }
        if (!flag) {
            close(fd);
            return -1;
        }
    }
    flag = 0;
    while (read(fd, symbol, sizeof(char)) == 1) {
        for (i = 0; i < sizeof(VERSION); i++) {
            if (symbol[0] == VERSION[i])
                flag = 1;
        }
        if (!flag) {
            close(fd);
            return -1;
        }
    }

    close(fd);
    return 0;
}

static int store_seed(DIDStore *store, uint8_t *seed, size_t size, const char *storepass)
{
    unsigned char base64[512];
    char path[PATH_MAX];

    assert(store);
    assert(seed);
    assert(storepass);
    assert(*storepass);

    if (encrypt_to_base64((char *)base64, storepass, seed, size) == -1)
        return -1;

    if (get_file(path, 1, 3, store->root, PRIVATE_DIR, HDKEY_FILE) == -1)
        return -1;

    if (store_file(path, (const char *)base64) == -1)
        return -1;

    return 0;
}

static ssize_t load_seed(DIDStore *store, uint8_t *seed, size_t size, const char *storepass)
{
    const char *encrpted_seed;
    char path[PATH_MAX];
    ssize_t len;

    assert(store);
    assert(seed);
    assert(storepass);
    assert(*storepass);
    assert(size > SEED_BYTES);

    if (get_file(path, 0, 3, store->root, PRIVATE_DIR, HDKEY_FILE) == -1)
        return -1;

    encrpted_seed = load_file(path);
    if (!encrpted_seed)
        return -1;

    len = decrypt_from_base64(seed, storepass, encrpted_seed);
    free((char*)encrpted_seed);

    return len;
}

static int store_mnemonic(DIDStore *store, const char *storepass, const char *mnemonic)
{
    unsigned char base64[512];
    char path[PATH_MAX];

    assert(store);
    assert(mnemonic);
    assert(*mnemonic);

    if (encrypt_to_base64((char *)base64, storepass, mnemonic, strlen(mnemonic)) == -1)
        return -1;

    if (get_file(path, 1, 3, store->root, PRIVATE_DIR, MNEMONIC_FILE) == -1)
        return -1;

    if (store_file(path, (const char *)base64) == -1)
        return -1;

    return 0;
}

static ssize_t load_mnemonic(DIDStore *store, const char *storepass,
        char *mnemonic, size_t size)
{
    const char *encrpted_mnemonic;
    char path[PATH_MAX];
    ssize_t len;

    assert(store);
    assert(mnemonic);
    assert(size >= ELA_MAX_MNEMONIC_LEN);

    if (get_file(path, 0, 3, store->root, PRIVATE_DIR, MNEMONIC_FILE) == -1)
        return -1;

    encrpted_mnemonic = load_file(path);
    if (!encrpted_mnemonic)
        return -1;

    len = decrypt_from_base64(mnemonic, storepass, encrpted_mnemonic);
    free((char*)encrpted_mnemonic);

    return len;
}

static int get_last_index(DIDStore *store)
{
    int index;
    char path[PATH_MAX];
    const char *index_string;

    assert(store);

    if (get_file(path, 0, 3, store->root, PRIVATE_DIR, INDEX_FILE) == -1)
        return -1;

    index_string = load_file(path);
    if (!index_string)
        index = 0;
    else {
        index = atoi(index_string);
        free((char*)index_string);
    }

    return index;
}

static int store_index(DIDStore *store, int index)
{
    char path[PATH_MAX];
    char string[32];
    int len;

    assert(store);
    assert(index >= 0);

    len = snprintf(string, sizeof(string), "%d", index);
    if (len < 0 || len > sizeof(string))
        return -1;

    if (get_file(path, 1, 3, store->root, PRIVATE_DIR, INDEX_FILE) == -1)
        return -1;

    if (store_file(path, string) == -1)
        return -1;

    return 0;
}

static int list_did_helper(const char *path, void *context)
{
    DID_List_Helper *dh = (DID_List_Helper*)context;
    char didpath[PATH_MAX];
    DID did;
    int rc;

    if (!path)
        return dh->cb(NULL, dh->context);

    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
        return 0;

    if (strlen(path) >= sizeof(did.idstring)) {
        if (get_dir(didpath, 0, 3, dh->store->root, DID_DIR, path) == 0) {
            delete_file(didpath);
            return 0;
        }
    }

    strcpy(did.idstring, path);
    return dh->cb(&did, dh->context);
}

static bool has_type(DID *did, const char *path, const char *type)
{
    const char *data;
    Credential *credential;
    int i;

    assert(did);
    assert(path);
    assert(type);

    data = load_file(path);
    if (!data)
        return false;

    credential = Credential_FromJson(data, did);
    free((char*)data);
    if (!credential)
        return false;

    for (i = 0; i < credential->type.size; i++) {
        const char *new_type = credential->type.types[i];
        if (!new_type)
            continue;
        if (strcmp(new_type, type) == 0) {
            Credential_Destroy(credential);
            return true;
        }
    }

    Credential_Destroy(credential);
    return false;
}

static int select_credential_helper(const char *path, void *context)
{
    Cred_List_Helper *ch = (Cred_List_Helper*)context;
    const char* data;
    Credential *credential;
    char credpath[PATH_MAX];
    DIDURL id;

    if (!path)
        return ch->cb(NULL, ch->context);

    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
        return -1;

    if (get_file(credpath, 0, 6, ch->store->root, DID_DIR, ch->did.idstring,
            CREDENTIALS_DIR, path, CREDENTIAL_FILE) == -1)
        return -1;

    data = load_file(path);
    if (!data)
        return -1;

    credential = Credential_FromJson(data, &(ch->did));
    free((char*)data);
    if (!credential)
        return -1;

    for (int j = 0; j < credential->type.size; j++) {
        const char *new_type = credential->type.types[j];
        if (!new_type)
            continue;
        if (strcmp(new_type, ch->type) == 0) {
            strcpy(id.did.idstring, ch->did.idstring);
            strcpy(id.fragment, path);
            Credential_Destroy(credential);
            return ch->cb(&id, ch->context);
        }
    }
    Credential_Destroy(credential);
    return 0;
}

static int list_credential_helper(const char *path, void *context)
{
    Cred_List_Helper *ch = (Cred_List_Helper*)context;
    char credpath[PATH_MAX];
    DIDURL id;
    int rc;

    if (!path)
        return ch->cb(NULL, ch->context);

    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
        return 0;

    if (strlen(path) >= sizeof(id.fragment)) {
        if (get_dir(credpath, 0, 5, ch->store->root, DID_DIR, ch->did.idstring,
                CREDENTIALS_DIR, path) == 0) {
            delete_file(credpath);
            return 0;
        }
    }

    strcpy(id.did.idstring, ch->did.idstring);
    strcpy(id.fragment, path);
    return ch->cb(&id, ch->context);
}

static DIDDocument *create_document(DID *did, const char *key,
        const char *storepass, const char *alias)
{
    DIDDocument *document;
    DIDURL id;
    DID controller;
    int rc;
    DIDDocumentBuilder *builder;

    assert(did);
    assert(key);
    assert(*key);
    assert(storepass);
    assert(*storepass);

    builder = DID_CreateBuilder(did);
    if (!builder)
        return NULL;

    strcpy((char*)id.did.idstring, did->idstring);
    strcpy((char*)id.fragment, "primary");

    if (DIDDocumentBuilder_AddPublicKey(builder, &id, did, key) == -1) {
        DIDDocumentBuilder_Destroy(builder);
        return NULL;
    }

    if (DIDDocumentBuilder_AddAuthenticationKey(builder, &id, key) == -1) {
        DIDDocumentBuilder_Destroy(builder);
        return NULL;
    }

    if (DIDDocumentBuilder_SetExpires(builder, 0) == -1) {
        DIDDocumentBuilder_Destroy(builder);
        return NULL;
    }

    document = DIDDocumentBuilder_Seal(builder, storepass);
    if (!document) {
        DIDDocumentBuilder_Destroy(builder);
        return NULL;
    }

    if (DIDMeta_Init(&document->meta, alias, NULL, false, 0) == -1) {
        DIDDocument_Destroy(document);
        return NULL;
    }

    return document;
}

static int store_credential(DIDStore *store, Credential *credential)
{
    const char *data;
    char path[PATH_MAX];
    DIDURL *id;
    int rc;

    assert(store);
    assert(credential);

    id = Credential_GetId(credential);
    if (!id)
        return -1;

    data = Credential_ToJson(credential, 1, 0);
    if (!data)
        return -1;

    if (get_file(path, 1, 6, store->root, DID_DIR, id->did.idstring,
            CREDENTIALS_DIR, id->fragment, CREDENTIAL_FILE) == -1) {
        free((char*)data);
        return -1;
    }

    rc = store_file(path, data);
    free((char*)data);
    if (!rc)
        return 0;

    delete_file(path);

    if (get_dir(path, 0, 5, store->root, DID_DIR, id->did.idstring,
            CREDENTIALS_DIR, id->fragment) == 0) {
        if (is_empty(path))
            delete_file(path);
    }

    if (get_dir(path, 0, 4, store->root, DID_DIR, id->did.idstring, CREDENTIALS_DIR) == 0) {
        if (is_empty(path))
            delete_file(path);
    }
    return -1;
}

/////////////////////////////////////////////////////////////////////////
DIDStore* DIDStore_Initialize(const char *root, DIDAdapter *adapter)
{
    char path[PATH_MAX];

    if (!root || !*root || strlen(root) >= PATH_MAX|| !adapter)
        return NULL;

    DIDStore_Deinitialize();

    storeInstance = (DIDStore *)calloc(1, sizeof(DIDStore));
    if (!storeInstance)
        return NULL;

    strcpy(storeInstance->root, root);
    storeInstance->backend.adapter = adapter;

    if (get_dir(path, 0, 1, root) == 0 && !check_store(storeInstance))
        return storeInstance;

    if (get_dir(path, 1, 1, root) == 0 && !create_store(storeInstance))
        return storeInstance;

    free(storeInstance);
    return NULL;
}

DIDStore* DIDStore_GetInstance(void)
{
    if (!storeInstance)
        return NULL;

    return storeInstance;
}

void DIDStore_Deinitialize()
{
    if (!storeInstance)
        return;

    free(storeInstance);
    storeInstance = NULL;
}

int DIDStore_ExportMnemonic(DIDStore *store, const char *storepass,
        char *mnemonic, size_t size)
{
    if (!store || !mnemonic || size <= 0)
        return -1;

    return load_mnemonic(store, storepass, mnemonic, size);
}

int DIDStore_StoreDID(DIDStore *store, DIDDocument *document, const char *alias)
{
    char path[PATH_MAX];
    const char *data, *root;
    DIDMeta meta;
    ssize_t count;
    int rc;

    if (!store || !document)
        return -1;

    if (load_didmeta(store, &meta, document->did.idstring) == -1 ||
            DIDMeta_SetAlias(&document->meta, alias) == -1 ||
            DIDMeta_Merge(&meta, &document->meta) == -1)
        return -1;

    memcpy(&document->meta, &meta, sizeof(DIDMeta));
	data = DIDDocument_ToJson(document, 0, 0);
	if (!data)
		return -1;

    rc = get_file(path, 1, 4, store->root, DID_DIR, document->did.idstring, DOCUMENT_FILE);
    if (rc < 0) {
        free((char*)data);
        return -1;
    }

    rc = store_file(path, data);
    free((char*)data);
    if (rc)
        goto errorExit;

    if (store_didmeta(store, &document->meta, &document->did) == -1)
        goto errorExit;

    count = DIDDocument_GetCredentialCount(document);
    for (int i = 0; i < count; i++) {
        Credential *cred = document->credentials.credentials[i];
        store_credential(store, cred);
    }

    return 0;

errorExit:
    delete_file(path);

    //check ids directory is empty or not
    if (get_dir(path, 0, 3, store->root, DID_DIR, document->did.idstring) == 0) {
        if (is_empty(path))
            delete_file(path);
    }

    return -1;
}

DIDDocument *DIDStore_LoadDID(DIDStore *store, DID *did)
{
    DIDDocument *document;
    char path[PATH_MAX];
    const char *data;
    int rc;

    if (!store || !did)
        return NULL;

    if (get_file(path, 0, 4, store->root, DID_DIR, did->idstring, DOCUMENT_FILE) == -1)
        return NULL;

    rc = test_path(path);
    if (rc < 0)
        return NULL;

    if (rc == S_IFDIR) {
        delete_file(path);
        return NULL;
    }

    data = load_file(path);
    if (!data)
        return NULL;

    document = DIDDocument_FromJson(data);
    free((char*)data);
    if (!document)
        return NULL;

    if (load_didmeta(store, &document->meta, document->did.idstring) == -1) {
        DIDDocument_Destroy(document);
        return NULL;
    }

    return document;
}

bool DIDStore_ContainsDID(DIDStore *store, DID *did)
{
    char path[PATH_MAX];
    int rc;

    if (!store || !did)
        return false;

    if (get_dir(path, 0, 3, store->root, DID_DIR, did->idstring) == -1)
        return false;

    rc = test_path(path);
    if (rc < 0)
        return false;

    if (rc == S_IFREG || is_empty(path)) {
        delete_file(path);
        return false;
    }

    return true;
}

void DIDStore_DeleteDID(DIDStore *store, DID *did)
{
    char path[PATH_MAX];
    int rc;

    if (!store || !did)
        return;

    if (get_dir(path, 0, 3, store->root, DID_DIR, did->idstring) == -1)
        return;

    if (test_path(path) > 0)
        delete_file(path);
}

int DIDStore_ListDID(DIDStore *store, DIDStore_GetDIDCallback *callback,
        void *context)
{
    char path[PATH_MAX];
    DID_List_Helper dh;
    int rc;

    if (!store || !callback)
        return -1;

    if (get_dir(path, 0, 2, store->root, DID_DIR) == -1)
        return -1;

    rc = test_path(path);
    if (rc < 0)
        return -1;

    if (rc != S_IFDIR)
        return -1;

    dh.store = store;
    dh.cb = callback;
    dh.context = context;

    if (list_dir(path, "*", list_did_helper, (void*)&dh) == -1)
        return -1;

    return 0;
}

int DIDStore_StoreCredential(DIDStore *store, Credential *credential, const char *alias)
{
    CredentialMeta meta;
    DIDURL *id;

    if (!store || !credential)
        return -1;

    id = Credential_GetId(credential);
    if (!id)
        return -1;

    if (load_credmeta(store, &meta, id->did.idstring, id->fragment) == -1 ||
            CredentialMeta_SetAlias(&credential->meta, alias) == -1 ||
            CredentialMeta_Merge(&meta, &credential->meta) == -1)
        return -1;

    memcpy(&credential->meta, &meta, sizeof(CredentialMeta));
    if (store_credential(store, credential) == -1 ||
            store_credmeta(store, &credential->meta, id) == -1)
        return -1;

    return 0;
}

Credential *DIDStore_LoadCredential(DIDStore *store, DID *did, DIDURL *id)
{
    const char *data;
    char path[PATH_MAX];
    Credential *credential;
    int rc;

    if (!store || !did ||!id)
        return NULL;

    if (get_file(path, 0, 6, store->root, DID_DIR, did->idstring,
            CREDENTIALS_DIR, id->fragment, CREDENTIAL_FILE) == -1)
        return NULL;

    rc = test_path(path);
    if (rc < 0)
        return NULL;

    if (rc == S_IFDIR) {
        delete_file(path);
        return NULL;
    }

    data = load_file(path);
    if (!data)
        return NULL;

    credential = Credential_FromJson(data, did);
    free((char*)data);
    return credential;
}

bool DIDStore_ContainsCredentials(DIDStore *store, DID *did)
{
    char path[PATH_MAX];
    int rc;

    if (!store || !did)
        return false;

    if (get_dir(path, 0, 4, store->root, DID_DIR, did->idstring, CREDENTIALS_DIR) == -1)
        return -1;

    rc = test_path(path);
    if (rc < 0)
        return false;

    if (rc == S_IFREG) {
        delete_file(path);
        return false;
    }

    return !is_empty(path);
}

bool DIDStore_ContainsCredential(DIDStore *store, DID *did, DIDURL *id)
{
    char path[PATH_MAX];
    int rc;

    if (!store || !did || !id)
        return false;

    if (get_dir(path, 0, 5, store->root, DID_DIR, did->idstring,
            CREDENTIALS_DIR, id->fragment) == -1)
        return false;

    rc = test_path(path);
    if (rc < 0)
        return false;

    if (rc == S_IFREG) {
        delete_file(path);
        return false;
    }

    return true;
}

void DIDStore_DeleteCredential(DIDStore *store, DID *did, DIDURL *id)
{
    char path[PATH_MAX];

    if (!store || !did || !id)
        return;

    if (get_dir(path, 0, 5, store->root, DID_DIR, did->idstring,
            CREDENTIALS_DIR, id->fragment) == -1)
        return;

    if (!is_empty(path))
        delete_file(path);

    if (get_dir(path, 0, 4, store->root, DID_DIR, did->idstring, CREDENTIALS_DIR) == 0) {
        if (is_empty(path))
            delete_file(path);
    }
}

int DIDStore_ListCredentials(DIDStore *store, DID *did,
        DIDStore_GetCredCallback *callback, void *context)
{
    ssize_t size = 0;
    char path[PATH_MAX];
    Cred_List_Helper ch;
    int rc;

    if (!store || !did || !callback)
        return -1;

    if (get_dir(path, 0, 4, store->root, DID_DIR, did->idstring, CREDENTIALS_DIR) == -1)
        return -1;

    rc = test_path(path);
    if (rc < 0)
        return -1;

    if (rc == S_IFREG) {
        delete_file(path);
        return -1;
    }

    ch.store = store;
    ch.cb = callback;
    ch.context = context;
    strcpy((char*)ch.did.idstring, did->idstring);
    ch.type = NULL;

    if (list_dir(path, "*", list_credential_helper, (void*)&ch) == -1)
        return -1;

    return 0;
}

int DIDStore_SelectCredentials(DIDStore *store, DID *did, DIDURL *id,
        const char *type, DIDStore_GetCredCallback *callback, void *context)
{
    char path[PATH_MAX];
    Cred_List_Helper ch;
    int rc;

    if (!store || !did || (!id && !type) || !callback)
        return -1;

    if (id) {
        if (get_file(path, 0, 6, store->root, DID_DIR, did->idstring,
                CREDENTIALS_DIR, id->fragment, CREDENTIAL_FILE) == -1)
            return -1;

        if (test_path(path) > 0) {
            if ((type && has_type(did, path, type) == true) || !type)
                return callback(id, context);
            return -1;
        }
        return -1;
    }

    if (get_dir(path, 0, 4, store->root, DID_DIR, did->idstring, CREDENTIALS_DIR) == -1)
        return -1;

    rc = test_path(path);
    if (rc < 0)
        return -1;

    if (rc == S_IFREG) {
        delete_file(path);
        return -1;
    }

    ch.store = store;
    ch.cb = callback;
    ch.context = context;
    strcpy((char*)ch.did.idstring, did->idstring);
    ch.type = type;

    if (list_dir(path, "*.*", select_credential_helper, (void*)&ch) == -1)
        return -1;

    return 0;
}

bool DIDSotre_ContainsPrivateKeys(DIDStore *store, DID *did)
{
    char path[PATH_MAX];

    if (!store || !did)
        return false;

    if (get_dir(path, 0, 4, store->root, DID_DIR, did->idstring, PRIVATEKEYS_DIR) == -1)
        return -1;

    return is_empty(path);
}

bool DIDStore_ContainsPrivateKey(DIDStore *store, DID *did, DIDURL *id)
{
    char path[PATH_MAX];

    int rc;

    if (!store || !did || !id)
        return false;

    if (get_file(path, 0, 5, store->root, DID_DIR, did->idstring,
            PRIVATEKEYS_DIR, id->fragment) == -1)
        return false;

    rc = test_path(path);
    if (rc < 0)
        return false;

    if (rc == S_IFDIR) {
        delete_file(path);
        return false;
    }

    return true;
}

int DIDStore_StorePrivateKey(DIDStore *store, DID *did, DIDURL *id,
        const char *privatekey)
{
    char path[PATH_MAX];
    const char *fragment;

    if (!store || !did || !id || !privatekey)
        return -1;

    if (!DID_Equals(DIDURL_GetDid(id), did))
        return -1;

    fragment = DIDURL_GetFragment(id);
    if (get_file(path, 1, 5, store->root, DID_DIR, did->idstring,
            PRIVATEKEYS_DIR, fragment) == -1)
        return -1;

    if (!store_file(path, privatekey))
        return 0;

    delete_file(path);
    if (get_dir(path, 0, 4, store->root, DID_DIR, did->idstring, PRIVATEKEYS_DIR) == 0) {
        if (is_empty(path))
            delete_file(path);
    }

    return -1;
}

void DIDStore_DeletePrivateKey(DIDStore *store, DID *did, DIDURL *id)
{
    char path[PATH_MAX];

    if (!store || !did || !id)
        return;

    if (get_file(path, 0, 6, store->root, DID_DIR, did->idstring,
            PRIVATEKEYS_DIR, id->fragment) == -1)
        return;

    if (test_path(path) > 0)
        delete_file(path);

    return;
}

static int refresh_did_fromchain(DIDStore *store, const char *storepass,
        uint8_t *seed, DID *did, uint8_t *publickey, size_t size)
{
    int index, last_index;
    int rc;
    DIDDocument *document;
    uint8_t last_publickey[PUBLICKEY_BYTES];
    uint8_t privatekey[PRIVATEKEY_BYTES];
    char last_idstring[MAX_ID_SPECIFIC_STRING];
    unsigned char privatekeybase64[PRIVATEKEY_BYTES * 2];
    MasterPublicKey _mk, *masterkey;
    DID last_did;

    if (publickey)
        assert(size >= PUBLICKEY_BYTES);

    assert(store);
    assert(storepass);
    assert(*storepass);
    assert(seed);

    masterkey = HDkey_GetMasterPublicKey(seed, 0, &_mk);
    if (!masterkey)
        return -1;

    index = get_last_index(store);
    last_index = index;

    while (last_index - index <= 1) {
        if (!HDkey_GetSubPublicKey(masterkey, 0, last_index, last_publickey))
            return -1;

        if (!HDkey_GetIdString(last_publickey, last_idstring, sizeof(last_idstring)))
            return -1;

        strcpy((char*)last_did.idstring, last_idstring);
        if (did && publickey && last_index == index) {
            strcpy(did->idstring, last_idstring);
            memcpy(publickey, last_publickey, size);
        }

        document = DIDStore_ResolveDID(store, &last_did, true);
        if (!document)
            last_index++;
        else {
            rc = DIDStore_StoreDID(store, document, NULL);
            if (rc < 0)
                return -1;

            DIDURL id;
            DID_Copy(&id.did, &last_did);
            strcpy(id.fragment, "primary");
            if (!HDkey_GetSubPrivateKey(seed, 0, 0, last_index, privatekey) ||
                encrypt_to_base64((char *)privatekeybase64, storepass, privatekey, sizeof(privatekey)) == -1 ||
                DIDStore_StorePrivateKey(store, &last_did, &id, (const char *)privatekeybase64) == -1) {
                DIDStore_DeleteDID(store, &last_did);
                //TODO: check need destroy document
                return -1;
            }

            index = ++last_index;
        }
    }

    return index;
}

bool DIDStore_ContainsPrivateIdentity(DIDStore *store)
{
    const char *seed;
    char path[PATH_MAX];
    struct stat st;

    if (!store)
        return false;

    if (get_file(path, 0, 3, store->root, PRIVATE_DIR, HDKEY_FILE) == -1)
        return false;

    if (lstat(path, &st) < 0)
        return false;

    return st.st_size > 0;
}

int DIDStore_InitPrivateIdentity(DIDStore *store, const char *mnemonic,
        const char *passphrase, const char *storepass, const int language, bool force)
{
    int index;
    uint8_t seed[SEED_BYTES];
    const char *encrpted_seed;
    char path[PATH_MAX];

    if (!store || !mnemonic || !storepass || !*storepass)
        return -1;

    if (!passphrase)
        passphrase = "";

    //check if DIDStore has existed private identity
    if (get_file(path, 0, 3, store->root, PRIVATE_DIR, HDKEY_FILE) == 0) {
        encrpted_seed = load_file(path);
        if (encrpted_seed && strlen(encrpted_seed) > 0 && !force) {
            free((char*)encrpted_seed);
            return -1;
        }
        free((char*)encrpted_seed);
    }

    if (!HDkey_GetSeedFromMnemonic(mnemonic, passphrase, language, seed) ||
        store_seed(store, seed, sizeof(seed), storepass) == -1)
        return -1;

    memset(seed, 0, sizeof(seed));

    index = refresh_did_fromchain(store, storepass, seed, NULL, NULL, 0);
    if (index < 0)
        return -1;

    if (store_mnemonic(store, storepass, mnemonic) == -1)
        return -1;

    return store_index(store, index);
}

DIDDocument *DIDStore_NewDID(DIDStore *store, const char *storepass, const char *alias)
{
    int index;
    unsigned char privatekeybase64[MAX_PRIVATEKEY_BASE64];
    uint8_t publickey[PUBLICKEY_BYTES];
    uint8_t privatekey[PRIVATEKEY_BYTES];
    char publickeybase58[MAX_PUBLICKEY_BASE58];
    uint8_t seed[SEED_BYTES * 2];
    ssize_t len;
    DID did;
    DIDDocument *document;

    if (!store || !storepass || !*storepass)
        return NULL;

    len = load_seed(store, seed, sizeof(seed), storepass);
    if (len < 0)
        return NULL;

    index = refresh_did_fromchain(store, storepass, seed, &did, publickey, sizeof(publickey));
    if (index < 0) {
        memset(seed, 0, sizeof(seed));
        return NULL;
    }

    DIDURL id;
    DID_Copy(&id.did, &did);
    strcpy(id.fragment, "primary");
    if (!HDkey_GetSubPrivateKey(seed, 0, 0, index, privatekey) ||
        encrypt_to_base64((char *)privatekeybase64, storepass, privatekey, sizeof(privatekey)) == -1 ||
        DIDStore_StorePrivateKey(store, &did, &id, (const char *)privatekeybase64) == -1) {
        memset(seed, 0, sizeof(seed));
        return NULL;
    }

    base58_encode(publickeybase58, publickey, sizeof(publickey));
    document = create_document(&did, publickeybase58, storepass, alias);
    if (!document) {
        memset(seed, 0, sizeof(seed));
        DIDStore_DeleteDID(store, &did);
        return NULL;
    }

    if (DIDStore_StoreDID(store, document, alias) == -1) {
        memset(seed, 0, sizeof(seed));
        DIDStore_DeleteDID(store, &did);
        DIDDocument_Destroy(document);
        return NULL;
    }

    memset(seed, 0, sizeof(seed));
    memset(privatekey, 0, sizeof(privatekey));

    return document;
}

int DIDStore_Signv(DIDStore *store, DID *did, DIDURL *key, const char *storepass,
        char *sig, int count, va_list inputs)
{
    const char *privatekey;
    unsigned char binkey[PRIVATEKEY_BYTES];
    char path[PATH_MAX];
    int rc;

    if (!store || !did || !key || !storepass || !*storepass || !sig || count <= 0)
        return -1;

    if (get_file(path, 0, 5, store->root, DID_DIR, did->idstring, PRIVATEKEYS_DIR, key->fragment) == -1)
        return -1;

    privatekey = load_file(path);
    if (!privatekey)
        return -1;

    rc = decrypt_from_base64(binkey, storepass, privatekey);
    free((char*)privatekey);
    if (rc == -1)
        return -1;

    if (ecdsa_sign_base64v(sig, binkey, count, inputs) <= 0)
        return -1;

    memset(binkey, 0, sizeof(binkey));
    return 0;
}

int DIDStore_Sign(DIDStore *store, DID *did, DIDURL *key, const char *storepass,
        char *sig, int count, ...)
{
    int rc;
    va_list inputs;

    if (!store || !did || !key || !storepass || !*storepass || !sig || count <= 0)
        return -1;

    va_start(inputs, count);
    rc = DIDStore_Signv(store, did, key, storepass, sig, count, inputs);
    va_end(inputs);

    return rc;
}

DIDDocument *DIDStore_ResolveDID(DIDStore *store, DID *did, bool force)
{
    DIDDocument *doc;
    const char *json;
    char alias[ELA_MAX_ALIAS_LEN];

    if (!store || !did)
        return NULL;

    doc = DIDStore_LoadDID(store, did);
    if (!doc || DIDDocument_GetAlias(doc, alias, sizeof(alias)) == -1)
        *alias = 0;

    doc = DIDBackend_Resolve(&store->backend, did);
    if (doc && DIDStore_StoreDID(store, doc, alias) == -1) {
        DIDDocument_Destroy(doc);
        return NULL;
    }

    if (!doc && !force)
        doc = DIDStore_LoadDID(store, did);

    return doc;
}

const char *DIDStore_PublishDID(DIDStore *store, DID *did, DIDURL *signKey,
        const char *storepass)
{
    char alias[ELA_MAX_ALIAS_LEN];
    char txid[ELA_MAX_TXID_LEN], resolvetxid[ELA_MAX_TXID_LEN];
    DIDDocument *doc, *resolvedoc;

    if (!store || !did || !storepass || !*storepass)
        return NULL;

    doc = DIDStore_LoadDID(store, did);
    if (!doc || DIDDocument_IsDeactivated(doc))
        return NULL;

    if (!signKey)
        signKey = DIDDocument_GetDefaultPublicKey(doc);

    resolvedoc = DIDStore_ResolveDID(store, did, true);
    if (!resolvedoc)
        return DIDBackend_Create(&store->backend, doc, signKey, storepass);

    if (DIDDocument_IsDeactivated(resolvedoc)) {
        if (DIDDocument_GetAlias(doc, alias, sizeof(alias)) == -1)
            *alias = 0;
        DIDStore_StoreDID(store, resolvedoc, alias);
        return NULL;
    }

    if (DIDDocument_GetTxid(doc, txid, sizeof(txid)) == -1
            || DIDDocument_GetTxid(resolvedoc, resolvetxid, sizeof(resolvetxid)) == -1)
        return NULL;

    if (strcmp(txid, resolvetxid))
        return NULL;

    return DIDBackend_Update(&store->backend, doc, signKey, storepass);
}

const char *DIDStore_DeactivateDID(DIDStore *store, DID *did, DIDURL *signKey,
        const char *storepass)
{
    if (!store || !did || !signKey || !storepass || !*storepass)
        return NULL;

    if (!signKey) {
        DIDDocument *doc = DIDStore_ResolveDID(store, did, false);
        if (!doc)
            return NULL;

        signKey = DIDDocument_GetDefaultPublicKey(doc);
        DIDDocument_Destroy(doc);
        if (!signKey)
            return NULL;
    }

    return DIDBackend_Deactivate(&store->backend, did, signKey, storepass);
}