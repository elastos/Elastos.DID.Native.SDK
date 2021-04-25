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
#include <fcntl.h>
#include <assert.h>
#include <sys/stat.h>
#include <openssl/opensslv.h>
#include <jansson.h>
#include <zip.h>

#include "ela_did.h"
#include "diderror.h"
#include "crypto.h"
#include "HDkey.h"
#include "common.h"
#include "didstore.h"
#include "credential.h"
#include "diddocument.h"
#include "didbackend.h"
#include "credential.h"
#include "didmeta.h"
#include "credmeta.h"
#include "identitymeta.h"
#include "storemeta.h"
#include "resolvercache.h"
#include "didrequest.h"
#include "ticket.h"
#include "rootidentity.h"

static char MAGIC[] = { 0x00, 0x0D, 0x01, 0x0D };
static char VERSION[] = { 0x00, 0x00, 0x00, 0x02 };

static const char *DIDSTORE_TYPE = "did:elastos:store";
static const char *DIDSTORE_VERSION = "3";

static const char *META_FILE = ".metadata";
static const char *DATA_DIR = "data";
static const char *ROOTS_DIR = "roots";
static const char *MNEMONIC_FILE = "mnemonic";
static const char *PRIVATE_FILE = "private";
static const char *PUBLIC_FILE = "public";
static const char *INDEX_FILE = "index";

static const char *IDS_DIR = "ids";
static const char *DOCUMENT_FILE = "document";
static const char *CREDENTIALS_DIR = "credentials";
static const char *CREDENTIAL_FILE = "credential";
static const char *PRIVATEKEYS_DIR = "privatekeys";

static const char *DATA_JOURNAL = "data.journal";
static const char *POST_PASSWORD = "postChangePassword";
static const char *POST_UPGRADE = "postUpgrade";
static const char *DID_EXPORT = "did.elastos.export/2.0";

const char *renames[2] = {"credentials", "privatekeys"};

extern const char *ProofType;

typedef struct DID_List_Helper {
    DIDStore *store;
    DIDStore_DIDsCallback *cb;
    void *context;
    int filter;
} DID_List_Helper;

typedef struct Cred_List_Helper {
    DIDStore *store;
    DIDStore_CredentialsCallback *cb;
    void *context;
    DID did;
    const char *type;
} Cred_List_Helper;

typedef struct RootIdentity_List_Helper {
    DIDStore *store;
    DIDStore_RootIdentitiesCallback *cb;
    void *context;
} RootIdentity_List_Helper;

typedef struct Dir_Copy_Helper {
    const char *srcpath;
    const char *dstpath;
    const char *oldpassword;
    const char *newpassword;
} Dir_Copy_Helper;

typedef struct Cred_Export_Helper {
    DIDStore *store;
    JsonGenerator *gen;
    Sha256_Digest *digest;
} Cred_Export_Helper;

typedef struct Prvkey_Export {
    DIDURL keyid;
    char key[512];
} Prvkey_Export;

typedef struct DID_Export {
    DIDStore *store;
    const char *storepass;
    const char *password;
    const char *tmpdir;
    zip_t *zip;
} DID_Export;

typedef struct RootIdentity_Export {
    DIDStore *store;
    const char *storepass;
    const char *password;
    const char *tmpdir;
    zip_t *zip;
} RootIdentity_Export;

typedef struct DefaultRootIdentity_Helper {
    char id[MAX_ID_LEN];
    int count;
} DefaultRootIdentity_Helper;
//checked
int DIDStore_StoreDIDMetadata(DIDStore *store, DIDMetadata *metadata, DID *did)
{
    char path[PATH_MAX];
    const char *data;
    int rc;

    assert(store);
    assert(metadata);
    assert(did);

    if (get_file(path, 1, 5, store->root, DATA_DIR, IDS_DIR, did->idstring, META_FILE) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create file for did(%s) metadata file failed.", DIDSTR(did));
        return -1;
    }

    if (test_path(path) == S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Did(%s) metadata should be a file.", DIDSTR(did));
        delete_file(path);
        return -1;
    }

    data = DIDMetadata_ToJson(metadata);
    if (!data) {
        delete_file(path);
        return 0;
    }

    rc = store_file(path, data);
    free((void*)data);
    if (rc)
        DIDError_Set(DIDERR_IO_ERROR, "Store did(%s) metadata failed.", DIDSTR(did));

    return rc;
}
//checked
static int DIDStore_LoadDIDMetadata(DIDStore *store, DIDMetadata *metadata, DID *did)
{
    const char *data;
    char path[PATH_MAX];
    DIDDocument *doc;
    int rc, status;

    assert(store);
    assert(metadata);
    assert(did);

    memset(metadata, 0, sizeof(DIDMetadata));
    if (get_file(path, 0, 5, store->root, DATA_DIR, IDS_DIR, did->idstring, META_FILE) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Did(%s) metadata don't exist.", DIDSTR(did));
        return 0;
    }

    rc = test_path(path);
    if (rc < 0)
        return 0;

    if (rc == S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Did(%s) metadata should be a file.", DIDSTR(did));
        delete_file(path);
        return -1;
    }

    data = load_file(path);
    if (!data) {
        DIDError_Set(DIDERR_IO_ERROR, "Load did(%s) metadata failed.", DIDSTR(did));
        return -1;
    }

    rc = DIDMetadata_FromJson(metadata, data);
    free((void*)data);
    if (rc < 0) {
        delete_file(path);
        doc = DID_Resolve(did, &status, false);
        if (!doc) {
            memset(metadata, 0, sizeof(DIDMetadata));
            DIDMetadata_SetStore(metadata, store);
            DID_ToString(did, metadata->did, sizeof(metadata->did));
            DIDMetadata_SetDeactivated(metadata, false);
        } else {
            DIDMetadata_SetStore(&doc->metadata, store);
            DID_ToString(did, doc->metadata.did, sizeof(doc->metadata.did));
            DIDMetadata_Store(&doc->metadata);
            DIDDocument_Destroy(doc);
        }
    }

    return 0;
}
//checked
int DIDStore_StoreCredMetadata(DIDStore *store, CredentialMetadata *metadata, DIDURL *id)
{
    char path[PATH_MAX], filename[128];
    const char *data;
    int rc;

    assert(store);
    assert(metadata);
    assert(id);

    if (!metadata->base.data)
        return 0;

    data = CredentialMetadata_ToJson(metadata);
    if (!data)
        return -1;

    sprintf(filename, "%s%s", "#", id->fragment);
    if (get_file(path, 1, 7, store->root, DATA_DIR, IDS_DIR, id->did.idstring,
            CREDENTIALS_DIR, filename, META_FILE) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create file for credential metadata failed.");
        free((void*)data);
        return -1;
    }

    if (test_path(path) == S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Credential metadata should be a file.");
        free((void*)data);
        goto errorExit;
    }

    rc = store_file(path, data);
    free((void*)data);
    if (!rc)
        return 0;

errorExit:
    delete_file(path);

    if (get_dir(path, 0, 6, store->root, DATA_DIR, IDS_DIR, id->did.idstring,
            CREDENTIALS_DIR, filename) == 0) {
        if (is_empty(path))
            delete_file(path);
    }

    if (get_dir(path, 0, 5, store->root, DATA_DIR, IDS_DIR, id->did.idstring, CREDENTIALS_DIR) == 0) {
        if (is_empty(path))
            delete_file(path);
    }

    DIDError_Set(DIDERR_IO_ERROR, "Store credential metadata failed.");
    return -1;
}
//checked
static int DIDStore_LoadCredMetadata(DIDStore *store, CredentialMetadata *metadata, DIDURL *id)
{
    const char *data;
    char path[PATH_MAX], filename[128];
    int rc;

    assert(store);
    assert(metadata);
    assert(id);

    memset(metadata, 0, sizeof(CredentialMetadata));

    sprintf(filename, "%s%s", "#", id->fragment);
    CredentialMetadata_SetStore(metadata, store);
    if (get_file(path, 0, 7, store->root, DATA_DIR, IDS_DIR, &id->did.idstring, CREDENTIALS_DIR,
            filename, META_FILE) == -1)
        return 0;

    rc = test_path(path);
    if (rc < 0)
        return 0;

    if (rc == S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Credential(%s) metadata should be file.", DIDURLSTR(id));
        delete_file(path);
        return -1;
    }

    data = load_file(path);
    if (!data) {
        DIDError_Set(DIDERR_IO_ERROR, "Load credential(%s) metadata error.", DIDURLSTR(id));
        return -1;
    }

    rc = CredentialMetadata_FromJson(metadata, data);
    free((void*)data);
    CredentialMetadata_SetStore(metadata, store);
    DIDURL_ToString(id, metadata->id, sizeof(metadata->id), false);
    if (rc < 0) {
        //compatible with the oldest version
        delete_file(path);
        memset(metadata, 0, sizeof(CredentialMetadata));
    }

    return 0;
}
//checked
static int store_identitymetadata(DIDStore *store, const char *id, IdentityMetadata *metadata)
{
    char path[PATH_MAX];
    const char *data;
    int rc;

    assert(store);
    assert(metadata);
    assert(id);

    if (!metadata->base.data)
        return 0;

    data = IdentityMetadata_ToJson(metadata);
    if (!data)
        return -1;

    if (get_file(path, 1, 5, store->root, DATA_DIR, ROOTS_DIR, id, META_FILE) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create file for root identity metadata data failed.");
        free((void*)data);
        return -1;
    }

    if (test_path(path) == S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Root identity metadata data should be a file.");
        free((void*)data);
        goto errorExit;
    }

    rc = store_file(path, data);
    free((void*)data);
    if (!rc)
        return 0;

errorExit:
    delete_file(path);

    if (get_dir(path, 0, 4, store->root, DATA_DIR, ROOTS_DIR, id) == 0) {
        if (is_empty(path))
            delete_file(path);
    }

    DIDError_Set(DIDERR_IO_ERROR, "Store rootidentity metadata failed.");
    return -1;
}
//checked
static int load_identitymetadata(DIDStore *store, const char *id, IdentityMetadata *metadata)
{
    const char *data;
    char path[PATH_MAX];
    int rc;

    assert(store);
    assert(id);
    assert(metadata);

    memset(metadata, 0, sizeof(IdentityMetadata));

    IdentityMetadata_SetStore(metadata, store);
    if (get_file(path, 0, 5, store->root, DATA_DIR, ROOTS_DIR, id, META_FILE) == -1)
        return 0;

    rc = test_path(path);
    if (rc < 0)
        return 0;

    if (rc == S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Root identity metadata should be file.");
        delete_file(path);
        return -1;
    }

    data = load_file(path);
    if (!data) {
        DIDError_Set(DIDERR_IO_ERROR, "Load identity metadata error.");
        return -1;
    }

    rc = IdentityMetadata_FromJson(metadata, data);
    free((void*)data);
    return rc;
}
//checked
static int calc_fingerprint(char *fingerprint, size_t size, const char *storepass)
{
    unsigned char *cipher;
    uint8_t buffer[16];
    char data[10];
    size_t len;
    int i;

    assert(fingerprint);
    assert(size >= 64);
    assert(storepass);

    memset(fingerprint, 0, size);

    md5(buffer, sizeof(buffer), (unsigned char*)storepass, strlen(storepass));
    cipher = (unsigned char *)alloca(sizeof(buffer) * 4);
    len = aes256_encrypt(cipher, storepass, buffer, sizeof(buffer));
    if (len < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt storepass failed.");
        return -1;
    }

    md5(buffer, sizeof(buffer), cipher, len);

    for(i = 0; i < sizeof(buffer); i++) {
        sprintf(data, "%02x", buffer[i]);
        strcat(fingerprint, data);
    }

    return 0;
}
//checked
static int store_storemetadata(DIDStore *store, const char *datadir, StoreMetadata *metadata)
{
    char path[PATH_MAX];
    const char *data;
    int rc;

    assert(store);
    assert(metadata);

    if (!datadir)
        datadir = DATA_DIR;

    if (get_file(path, 1, 3, store->root, datadir, META_FILE) < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create store metadata file failed.");
        return -1;
    }

    data = StoreMetadata_ToJson(metadata);
    if (!data)
        return -1;

    rc = store_file(path, data);
    free((void*)data);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "Store store metadata failed.");
        delete_file(path);
        return -1;
    }

    StoreMetadata_SetStore(metadata, store);
    return 0;
}
//checked
static int load_storemetadata(DIDStore *store, StoreMetadata *metadata)
{
    char path[PATH_MAX];
    const char *data;
    int rc;

    assert(store);
    assert(metadata);

    memset(metadata, 0, sizeof(StoreMetadata));
    if (get_file(path, 0, 3, store->root, DATA_DIR, META_FILE) == -1)
        return 0;

    rc = test_path(path);
    if (rc < 0)
        return 0;

    if (rc == S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Store metadata should be file.");
        delete_file(path);
        return -1;
    }

    data = load_file(path);
    if (!data) {
        DIDError_Set(DIDERR_IO_ERROR, "Load store metadata failed.");
        return -1;
    }

    rc = StoreMetadata_FromJson(metadata, data);
    free((void*)data);
    if (rc < 0)
        return -1;

    StoreMetadata_SetStore(metadata, store);
    return 0;
}
//checked
static int create_store(DIDStore *store)
{
    char path[PATH_MAX];

    assert(store);

    if (get_file(path, 1, 3, store->root, DATA_DIR, META_FILE) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create store metadata file failed.");
        return -1;
    }

    memset(&store->metadata, 0, sizeof(store->metadata));
    if (StoreMetadata_SetType(&store->metadata, DIDSTORE_TYPE) < 0 ||
           StoreMetadata_SetVersion(&store->metadata, DIDSTORE_VERSION) < 0 ||
           store_storemetadata(store, NULL,&store->metadata) < 0)
        return -1;

    return 0;
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow="
#endif
//checked
static int post_changepassword(DIDStore *store)
{
    char post_file[PATH_MAX], buffer[DOC_BUFFER_LEN];
    char data_dir[PATH_MAX], data_journal_dir[PATH_MAX], data_deprecated_dir[PATH_MAX];

    assert(store);

    sprintf(post_file, "%s%s%s", store->root, PATH_SEP, POST_PASSWORD);
    if (test_path(post_file) == S_IFREG) {
        if (get_dir(data_journal_dir, 0, 2, store->root, DATA_JOURNAL) == 0) {
            if (get_dir(data_dir, 0, 2, store->root, DATA_DIR) == 0) {
                sprintf(buffer, "%s_%ld", DATA_DIR, (long)time(NULL));
                get_dir(data_deprecated_dir, 0, 2, store->root, buffer);
                if (rename(data_dir, data_deprecated_dir) < 0)
                    return -1;
            }
            if (rename(data_journal_dir, data_dir) < 0) {
                DIDError_Set(DIDERR_DIDSTORE_ERROR, "Rename 'data_journal' to 'data' failed.");
                return -1;
            }
        }
        delete_file(post_file);
    } else {
        if (get_dir(data_journal_dir, 0, 2, store->root, DATA_JOURNAL) == 0)
            delete_file(data_journal_dir);
    }

    return 0;
}
//checked
static int post_upgrade(DIDStore *store)
{
    char post_file[PATH_MAX], path[PATH_MAX * 2];
    char data_dir[PATH_MAX], data_journal_dir[PATH_MAX], data_deprecated_dir[PATH_MAX];
    const char *data;

    assert(store);

    sprintf(post_file, "%s%s%s", store->root, PATH_SEP, POST_UPGRADE);
    if (test_path(post_file) == S_IFREG) {
        if (get_dir(data_journal_dir, 0, 2, store->root, DATA_JOURNAL) == 0) {
            sprintf(data_dir, "%s%s%s", store->root, PATH_SEP, DATA_DIR);
            rename(data_journal_dir, data_dir);
        }

        data = load_file(post_file);
        if (!data) {
            DIDError_Set(DIDERR_IO_ERROR, "Upgrade file is wrong.");
            return -1;
        }

        if (!*data) {
            sprintf(data_deprecated_dir, "%s%s%s_%ld", store->root, PATH_SEP, DATA_DIR, (long)time(NULL));
            store_file(post_file, data_deprecated_dir);
        } else {
            sprintf(data_deprecated_dir, "%s%s%s", store->root, PATH_SEP, data);
        }
        free((void*)data);

        if (test_path(data_deprecated_dir) != S_IFDIR)
            delete_file(data_deprecated_dir);

        if (test_path(data_deprecated_dir) == -1)
            mkdirs(data_deprecated_dir, S_IRWXU);

        if (get_dir(data_dir, 0, 2, store->root, PRIVATE_FILE) == 0) {
            sprintf(path, "%s%s%s", data_deprecated_dir, PATH_SEP, PRIVATE_FILE);
            rename(data_dir, path);
        }
        if (get_dir(data_dir, 0, 2, store->root, IDS_DIR) == 0) {
            sprintf(path, "%s%s%s", data_deprecated_dir, PATH_SEP, IDS_DIR);
            rename(data_dir, path);
        }
        if (get_file(data_dir, 0, 2, store->root, ".meta") == 0) {
            sprintf(path, "%s%s%s", data_deprecated_dir, PATH_SEP, ".meta");
            rename(data_dir, path);
        }

        delete_file(post_file);
    } else {
        if (get_dir(data_journal_dir, 0, 2, store->root, DATA_JOURNAL) == 0)
            delete_file(data_journal_dir);
    }

    return 0;
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
//checked
static bool check_old_store(DIDStore *store)
{
    int fd;
    char symbol[1];
    int i, flag = 0;
    char path[PATH_MAX];
    bool check = false;

    assert(store);

    if (test_path(store->root) != S_IFDIR)
        return false;

    if (get_file(path, 0, 2, store->root, ".meta") == -1)
        return false;

    fd = open(path, O_RDONLY);
    if (fd == -1)
        return false;

    while (read(fd, symbol, sizeof(char)) == 1) {
        for (i = 0; i < sizeof(MAGIC); i++) {
            if (symbol[0] == MAGIC[i])
                flag = 1;
        }
        if (!flag)
            goto errorExit;
    }
    flag = 0;
    while (read(fd, symbol, sizeof(char)) == 1) {
        for (i = 0; i < sizeof(VERSION); i++) {
            if (symbol[0] == VERSION[i])
                flag = 1;
        }
        if (!flag)
            goto errorExit;
    }

    check = true;

errorExit:
    close(fd);
    return check;
}
//checked
static const char* upgradeMetadataV2(const char *path)
{
    const char *data = NULL;
    Metadata newmetadata, oldmetadata;
    int rc;

    assert(path);

    data = load_file(path);
    if (!data) {
        DIDError_Set(DIDERR_IO_ERROR, "Load metadata file (%s) failed.", path);
        return NULL;
    }

    memset(&newmetadata, 0, sizeof(Metadata));
    memset(&oldmetadata, 0, sizeof(Metadata));

    rc = Metadata_FromJson(&oldmetadata, data);
    free((void*)data);
    data = NULL;
    if (rc < 0)
        goto errorExit;

    if (Metadata_Upgrade(&newmetadata, &oldmetadata) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Upgrade metadata failed.");
        goto errorExit;
    }

    data = Metadata_ToJson(&newmetadata);

errorExit:
    Metadata_Free(&newmetadata);
    Metadata_Free(&oldmetadata);

    return data;
}
//checked
int dids_upgrade(const char *dst, const char *src);

static int dids_upgrade_helper(const char *path, void *context)
{
    char srcpath[PATH_MAX], dstpath[PATH_MAX];
    char *pos;
    int i, len;

    Dir_Copy_Helper *dh = (Dir_Copy_Helper*)context;

    if (!path)
        return 0;

    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
        return 0;

    len = snprintf(srcpath, PATH_MAX, "%s%s%s", dh->srcpath, PATH_SEP, path);
    if (len < 0 || len > PATH_MAX)
        return -1;

    if (!strcmp(".meta", path))
        path = META_FILE;

    for (i = 0; i < 2; i++) {
        pos = last_strstr(dh->srcpath, renames[i]);
        if (pos && !strcmp(pos, renames[i])) {
            len = snprintf(dstpath, PATH_MAX, "%s%s%s%s", dh->dstpath, PATH_SEP, "#", path);
            if (len < 0 || len > PATH_MAX)
                return -1;
            break;
        }

        if (i == 1) {
            len = snprintf(dstpath, PATH_MAX, "%s%s%s", dh->dstpath, PATH_SEP, path);
            if (len < 0 || len > PATH_MAX)
                return -1;
        }
    }

    return dids_upgrade(dstpath, srcpath);
}
//checked
int dids_upgrade(const char *dst, const char *src)
{
    Dir_Copy_Helper dh;
    const char *data;
    int rc;

    assert(dst && *dst);
    assert(src && *src);

    if (test_path(src) < 0)
        return -1;

    //src is directory.
    if (test_path(src) == S_IFDIR) {
        if (test_path(dst) < 0) {
            rc = mkdirs(dst, S_IRWXU);
            if (rc < 0) {
                DIDError_Set(DIDERR_IO_ERROR, "Create upgrade ids folder (%s) failed", dst);
                return -1;
            }
        }

        dh.srcpath = src;
        dh.dstpath = dst;
        dh.oldpassword = NULL;
        dh.newpassword = NULL;

        if (list_dir(src, "*", dids_upgrade_helper, (void*)&dh) == -1) {
            DIDError_Set(DIDERR_DIDSTORE_ERROR, "Copy directory failed.");
            return -1;
        }

        return 0;
    }

    //src is file
    if (last_strstr(src, ".meta")) {
        data = upgradeMetadataV2(src);
        if (!data)
            return 0;
    } else {
        data = load_file(src);
        if (!data || !*data) {
            if (data)
                free((void*)data);

            DIDError_Set(DIDERR_IO_ERROR, "Load %s failed.", src);
            return -1;
        }
    }

    rc = store_file(dst, data);
    free((void*)data);
    if (rc < 0)
        DIDError_Set(DIDERR_IO_ERROR, "Store %s failed.", dst);

    return rc;
}
//checked
static const char *get_rootfile(DIDStore *store, const char *filename)
{
    char path[PATH_MAX];
    const char *data;

    assert(store);
    assert(filename);

    if (get_file(path, 0, 3, store->root, "private", filename) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No root file.");
        return NULL;
    }

    if (test_path(path) != S_IFREG) {
        DIDError_Set(DIDERR_IO_ERROR, "Root file isn't the file.");
        return NULL;
    }

    data = load_file(path);
    if (!data) {
        DIDError_Set(DIDERR_IO_ERROR, "Load root file (%s) failed.", path);
        return NULL;
    }

    return data;
}
//checked
static int store_pubkey_file(DIDStore *store, const char *datadir, const char *id, const char *keybase58)
{
    char path[PATH_MAX];

    assert(store);
    assert(id);
    assert(keybase58);

    if (!datadir)
        datadir = DATA_DIR;

    if (get_file(path, 1, 5, store->root, datadir, ROOTS_DIR, id, PUBLIC_FILE) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create file for publicKey of rootidentity (%s) failed.", id);
        return -1;
    }

    if (store_file(path, keybase58) == -1) {
        DIDError_Set(DIDERR_IO_ERROR, "Store publicKey of rootidentity (%s) failed.", id);
        delete_file(path);
        return -1;
    }
    return 0;
}
//checked
static int store_prvkey_file(DIDStore *store, const char *datadir, const char *id, const char *rootPrivateKey)
{
    char path[PATH_MAX];

    assert(store);
    assert(id);
    assert(rootPrivateKey);

    if (!datadir)
        datadir = DATA_DIR;

    if (get_file(path, 1, 5, store->root, datadir, ROOTS_DIR, id, PRIVATE_FILE) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create file for privatekey of rootidentity (%s) failed.", id);
        return -1;
    }

    if (store_file(path, rootPrivateKey) < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "Store privatekey of rootidentity (%s) failed.", id);
        delete_file(path);
        return -1;
    }

    return 0;
}
//checked
static int store_mnemonic_file(DIDStore *store, const char *datadir, const char *id, const char *base64)
{
    char path[PATH_MAX];

    assert(store);
    assert(id);
    assert(base64);

    if (!datadir)
        datadir = DATA_DIR;

    if (get_file(path, 1, 5, store->root, datadir, ROOTS_DIR, id, MNEMONIC_FILE) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create file for mnemonic of rootidentity (%s) failed.", id);
        return -1;
    }

    if (store_file(path, base64) == -1) {
        DIDError_Set(DIDERR_IO_ERROR, "Store mnemonic of rootidentity (%s) failed.", id);
        delete_file(path);
        return -1;
    }

    return 0;
}
//checked
static int store_index_string(DIDStore *store, const char *datadir, const char *id, const char *index)
{
    char path[PATH_MAX];

    assert(store);
    assert(id);
    assert(index && *index);

    if (!datadir)
        datadir = DATA_DIR;

    if (get_file(path, 1, 5, store->root, datadir, ROOTS_DIR, id, INDEX_FILE) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create file for index of rootidentity (%s) failed.", id);
        return -1;
    }

    if (store_file(path, index) == -1) {
        DIDError_Set(DIDERR_IO_ERROR, "Store index of rootidentity (%s) failed.", id);
        delete_file(path);
        return -1;
    }
    return 0;
}
//checked
static const char *load_index_string(DIDStore *store, const char *id)
{
    char path[PATH_MAX];
    const char *string;

    assert(store);
    assert(id);

    if (get_file(path, 0, 5, store->root, DATA_DIR, ROOTS_DIR, id, INDEX_FILE) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Index file of rootidentity (%s) is not exist.", id);
        return NULL;
    }

    string = load_file(path);
    if (!string)
        DIDError_Set(DIDERR_IO_ERROR, "Load index of rootidentity (%s) failed.", id);

    return string;

}
//checked
static int upgradeFromV2(DIDStore *store)
{
    char path[PATH_MAX], v2path[PATH_MAX * 2], id[MAX_ID_LEN] = {0};
    uint8_t extendedkey[EXTENDEDKEY_BYTES];
    StoreMetadata metadata;
    const char *data;
    time_t current = 0;
    size_t len;
    int rc;

    assert(store);

    if (!check_old_store(store)) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Invalid DID store.");
        return -1;
    }

    //upgrade to data journal directory
    if (get_dir(v2path, 0, 2, store->root, DATA_JOURNAL) == 0)
        delete_file(v2path);

    if (get_dir(path, 0, 2, store->root, "private") == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Get rootidentity directory (old store) failed.");
        return -1;
    }

    if (get_dir(v2path, 1, 2, store->root, DATA_JOURNAL) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create data journal directory failed.");
        return -1;
    }

    if (test_path(path) != S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Invalid rootidentity folder.");
        goto errorExit;
    }

    //private/key.pub
    data = get_rootfile(store, "key.pub");
    if (!data) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Get root prederived public key failed.");
        goto errorExit;
    }

    len = b58_decode(extendedkey, EXTENDEDKEY_BYTES, data);
    if (len < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode extended public key failed.");
        free((void*)data);
        goto errorExit;
    }

    if (md5_hex(id, sizeof(id), extendedkey, EXTENDEDKEY_BYTES) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get id from public key failed.");
        free((void*)data);
        goto errorExit;
    }

    rc = store_pubkey_file(store, DATA_JOURNAL, id, data);
    free((void*)data);
    if (rc < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Store root publicKey in the data journal directory failed.");
        goto errorExit;
    }

    //private/key
    data = get_rootfile(store, "key");
    if (!data) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Get root prederived publicKey failed.");
        goto errorExit;
    }
    rc = store_prvkey_file(store, DATA_JOURNAL, id, data);
    free((void*)data);
    if (rc < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Store root privatekey in the data journal directory failed.");
        goto errorExit;
    }

    //private/mnemonic
    data = get_rootfile(store, MNEMONIC_FILE);
    if (!data) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Load mnemonic string failed.");
        goto errorExit;
    }
    rc = store_mnemonic_file(store, DATA_JOURNAL, id, data);
    free((void*)data);
    if (rc < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Store nmemonic in the data journal directory failed.");
        goto errorExit;
    }

    //private/index
    data = get_rootfile(store, INDEX_FILE);
    if (!data) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Load index string failed.");
        goto errorExit;
    }
    rc = store_index_string(store, DATA_JOURNAL, id, data);
    free((void*)data);
    if (rc < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Store index failed.");
        goto errorExit;
    }

    //ids
    if (get_dir(path, 0, 2, store->root, IDS_DIR) == 0) {
        if (get_dir(v2path, 1, 3, store->root, DATA_JOURNAL, IDS_DIR) < 0) {
            DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create ids folder failed.");
            goto errorExit;
        }
        if (dids_upgrade(v2path, path) < 0) {
            DIDError_Set(DIDERR_DIDSTORE_ERROR, "Upgrade ids folder failed.");
            goto errorExit;
        }
    }

    if (StoreMetadata_Init(&metadata, DIDSTORE_TYPE, DIDSTORE_VERSION, NULL, id) < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Upgrade store metadata failed.");
        goto errorExit;
    }

    rc = store_storemetadata(store, DATA_JOURNAL, &metadata);
    StoreMetadata_Free(&metadata);
    if (rc < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Store store metadata failed.");
        goto errorExit;
    }

    //create tag file to indicate copying successfully.
    if (get_file(path, 1, 2, store->root, POST_UPGRADE) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create 'upgrade' file failed.");
        goto errorExit;
    }

    if (store_file(path, "") < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "Store 'upgrade' file failed.");
        goto errorExit;
    }

    if (post_upgrade(store) < 0) {
        delete_file(path);
        goto errorExit;
    }

    return 0;

errorExit:
    if (get_dir(v2path, 0, 2, store->root, DATA_JOURNAL) == 0)
        delete_file(path);
    return -1;
}
//checked
static void post_operations(DIDStore *store)
{
    post_upgrade(store);
    post_changepassword(store);
}
//checked
static int check_store(DIDStore *store)
{
    char path[PATH_MAX], metapath[PATH_MAX];
    int rc = -1;

    assert(store);

    if (test_path(store->root) != S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "The wrong root directory.");
        return -1;
    }

    post_operations(store);

    //data does not already exist.
    if (get_dir(path, 0, 2, store->root, DATA_DIR) == -1) {
        if (get_file(metapath, 0, 2, store->root, ".meta") == -1 || test_path(metapath) != S_IFREG) {
            DIDError_Set(DIDERR_DIDSTORE_ERROR, "Invalid DID store.");
            return -1;
        }

        upgradeFromV2(store);
    } else {
        if (test_path(path) != S_IFDIR) {
            DIDError_Set(DIDERR_IO_ERROR, "Invalid DID store, missing data directory.");
            return -1;
        }
    }

    if (load_storemetadata(store, &store->metadata) < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Invalid DIDStore metadata.");
        return -1;
    }

    if (strcmp(DIDSTORE_TYPE, StoreMetadata_GetType(&store->metadata))) {
        DIDError_Set(DIDERR_UNKNOWN, "Unknown DIDStore type");
        return -1;
    }

    if (strcmp(DIDSTORE_VERSION, StoreMetadata_GetVersion(&store->metadata))) {
        DIDError_Set(DIDERR_UNSUPPORTED, "Unsupported DIDStore version");
        return -1;
    }

    return 0;
}
//checked
static bool check_password(DIDStore *store, const char *storepass)
{
    char fingerprint[64] = {0};
    const char *_fingerprint;

    if (calc_fingerprint(fingerprint, sizeof(fingerprint), storepass) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get fingerprint failed.");
        return false;
    }

    _fingerprint = StoreMetadata_GetFingerPrint(&store->metadata);
    if (_fingerprint) {
        if (strcmp(fingerprint, _fingerprint)) {
            DIDError_Set(DIDERR_DIDSTORE_ERROR, "DIDStore password mismatch with the first one.");
            return false;
        }
    } else {
        if (StoreMetadata_SetFingerPrint(&store->metadata, fingerprint) < 0 ||
                store_storemetadata(store, NULL, &store->metadata) < 0)
            return false;
    }

    return true;
}
//checked
static ssize_t didstore_encrypt_to_base64(DIDStore *store, const char *storepass,
        char *base64, const uint8_t *input, size_t len)
{
    ssize_t length;

    assert(store);
    assert(storepass && *storepass);
    assert(base64);
    assert(input);

    if (!check_password(store, storepass)) {
        DIDError_Set(DIDERR_WRONG_PASSWORD, "Wrong storepass.");
        return -1;
    }

    length = encrypt_to_b64(base64, storepass, input, len);
    if (!length) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt data failed.");
        return -1;
    }

    return length;
}
//checked
static ssize_t didstore_decrypt_from_base64(DIDStore *store, const char *storepass,
       uint8_t *plain, const char *base64)
{
    ssize_t length;

    assert(store);
    assert(storepass && *storepass);
    assert(plain);
    assert(base64);

    length = decrypt_from_b64(plain, storepass, base64);
    if (length < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decrypt data failed.");
        return -1;
    }

    if (!check_password(store, storepass)) {
        DIDError_Set(DIDERR_WRONG_PASSWORD, "Wrong storepass.");
        return -1;
    }

    return length;
}
//checked
static const char *load_prvkey_file(DIDStore *store, const char *id)
{
    const char *string;
    char path[PATH_MAX];

    assert(store);
    assert(id);

    if (get_file(path, 0, 5, store->root, DATA_DIR, ROOTS_DIR, id, PRIVATE_FILE) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Private key of rootidentity (%s) doesn't already exist.", id);
        return NULL;
    }

    string = load_file(path);
    if (!string) {
        DIDError_Set(DIDERR_IO_ERROR, "Load privatekey of rootidentity (%s) failed.", id);
        return NULL;
    }

    return string;
}
//checked
static int store_extendedprvkey(DIDStore *store, const char *storepass,
        const char *id, uint8_t *extendedkey, size_t size)
{
    char base64[512] = {0};

    assert(store);
    assert(id);
    assert(extendedkey && size > 0);
    assert(storepass && *storepass);

    if (didstore_encrypt_to_base64(store, storepass, base64, extendedkey, size) == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt privatekey of rootidentity (%s) failed.", id);
        return -1;
    }

    return store_prvkey_file(store, NULL, id, base64);
}
//checked
ssize_t DIDStore_LoadRootIdentityPrvkey(DIDStore *store, const char *storepass,
        const char *id, uint8_t *extendedkey, size_t size)
{
    const char *string;
    ssize_t len;

    assert(store);
    assert(storepass && *storepass);
    assert(id);
    assert(extendedkey && size >= EXTENDEDKEY_BYTES);

    string = load_prvkey_file(store, id);
    if (!string)
        return -1;

    len = didstore_decrypt_from_base64(store, storepass, extendedkey, string);
    free((void*)string);
    if (len < 0)
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decrypt privatekey of rootidentity (%s) failed.", id);

    return len;
}
//checked
static const char *load_pubkey_file(DIDStore *store, const char *id)
{
    const char *string;
    char path[PATH_MAX];

    assert(store);
    assert(id);

    if (get_file(path, 0, 5, store->root, DATA_DIR, ROOTS_DIR, id, PUBLIC_FILE) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "PublicKey of rootidentity (%s) don't exist.", id);
        return NULL;
    }

    string = load_file(path);
    if (!string) {
        DIDError_Set(DIDERR_IO_ERROR, "Load publicKey of rootidentity (%s) failed.");
        return NULL;
    }

    return string;
}
//checked
static int store_extendedpubkey(DIDStore *store, const char *id, uint8_t *extendedkey, size_t size)
{
    char publickeybase58[EXTENDEDKEY_BASE58_BYTES];

    assert(store);
    assert(id);
    assert(extendedkey && size > 0);

    if (b58_encode(publickeybase58, sizeof(publickeybase58), extendedkey, size) == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode publicKey of rootidentity (%s) failed.", id);
        return -1;
    }

    return store_pubkey_file(store, NULL, id, publickeybase58);
}
//checked
static ssize_t load_extendedpubkey(DIDStore *store, const char *id, uint8_t *extendedkey, size_t size)
{
    const char *string;
    ssize_t len;

    assert(store);
    assert(id);
    assert(extendedkey && size >= EXTENDEDKEY_BYTES);

    string = load_pubkey_file(store, id);
    if (!string)
        return -1;

    len = b58_decode(extendedkey, size, string);
    free((void*)string);
    if (len < 0)
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decode publicKey of rootidentity (%s) failed.", id);

    return len;
}
//checked
static int store_mnemonic(DIDStore *store, const char *storepass, const char *id,
        const uint8_t *mnemonic, size_t size)
{
    char base64[512] = {0};

    assert(store);
    assert(storepass && *storepass);
    assert(id);
    assert(mnemonic);
    assert(size > 0);

    if (didstore_encrypt_to_base64(store, storepass, base64, mnemonic, size) == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt mnemonic failed.");
        return -1;
    }

    return store_mnemonic_file(store, NULL, id, base64);
}
//checked
static ssize_t load_mnemonic(DIDStore *store, const char *storepass, const char *id,
        char *mnemonic, size_t size)
{
    const char *encrpted_mnemonic;
    char path[PATH_MAX];
    ssize_t len;

    assert(store);
    assert(storepass && *storepass);
    assert(id);
    assert(mnemonic);
    assert(size >= ELA_MAX_MNEMONIC_LEN);

    *mnemonic = 0;
    if (get_file(path, 0, 5, store->root, DATA_DIR, ROOTS_DIR, id, MNEMONIC_FILE) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Mnemonic file of rootidentity (%s) don't exist.", id);
        return 0;
    }

    encrpted_mnemonic = load_file(path);
    if (!encrpted_mnemonic) {
        DIDError_Set(DIDERR_IO_ERROR, "Load encrypted mnemonic string failed.");
        return -1;
    }

    len = didstore_decrypt_from_base64(store, storepass, (uint8_t*)mnemonic, encrpted_mnemonic);
    free((void*)encrpted_mnemonic);
    if (len < 0)
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decrypt mnemonic failed.");

    mnemonic[len++] = 0;

    return len;
}
//checked
static int list_did_helper(const char *path, void *context)
{
    DID_List_Helper *dh = (DID_List_Helper*)context;
    char didpath[PATH_MAX];
    DID did;
    int rc = 0, len;

    if (!path)
        return dh->cb(NULL, dh->context);

    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
        return 0;

    len = snprintf(didpath, sizeof(didpath), "%s%s%s%s%s%s%s", dh->store->root, PATH_SEP,
            DATA_DIR,  PATH_SEP, IDS_DIR, PATH_SEP, path);
    if (len < 0 || len > sizeof(didpath)) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Get did (%s) path failed.", path);
        return -1;
    }

    if (test_path(didpath) == S_IFREG || strlen(path) >= sizeof(did.idstring)) {
        delete_file(didpath);
        return 0;
    }

    strcpy(did.idstring, path);
    DIDStore_LoadDIDMetadata(dh->store, &did.metadata, &did);

    if (dh->filter == 0 || (dh->filter == 1 && DIDSotre_ContainsPrivateKeys(dh->store, &did)) ||
            (dh->filter == 2 && !DIDSotre_ContainsPrivateKeys(dh->store, &did)))
            rc = dh->cb(&did, dh->context);

    DIDMetadata_Free(&did.metadata);
    return rc;
}

static int list_rootidentity_helper(const char *path, void *context)
{
    RootIdentity_List_Helper *rh = (RootIdentity_List_Helper*)context;
    char identitypath[PATH_MAX];
    RootIdentity *rootidentity;
    size_t len;
    int rc;

    if (!path)
        return rh->cb(NULL, rh->context);

    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
        return 0;

    len = snprintf(identitypath, sizeof(identitypath), "%s%s%s%s%s%s%s", rh->store->root, PATH_SEP,
            DATA_DIR,  PATH_SEP, ROOTS_DIR, PATH_SEP, path);
    if (len < 0 || len > sizeof(identitypath)) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Get rootidentity (%s) path failed.", path);
        return -1;
    }

    if (test_path(identitypath) == S_IFREG || strlen(path) >= MAX_ID_LEN) {
        delete_file(identitypath);
        return 0;
    }

    rootidentity = DIDStore_LoadRootIdentity(rh->store, path);
    if (rootidentity)
        rc = rh->cb(rootidentity, rh->context);

    RootIdentity_Destroy(rootidentity);
    return rc;
}
//checked
static bool has_type(DID *did, const char *path, const char *type)
{
    const char *data;
    Credential *credential;
    size_t i;

    assert(did);
    assert(path);
    assert(type);

    data = load_file(path);
    if (!data) {
        DIDError_Set(DIDERR_IO_ERROR, "Load '%s' failed.", path);
        return false;
    }

    credential = Credential_FromJson(data, did);
    free((void*)data);
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
//checked
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
        return 0;

    if (get_file(credpath, 0, 7, ch->store->root, DATA_DIR, IDS_DIR, ch->did.idstring,
            CREDENTIALS_DIR, path, CREDENTIAL_FILE) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Credential (%s) file doesn't exist.");
        return -1;
    }

    data = load_file(path);
    if (!data) {
        DIDError_Set(DIDERR_IO_ERROR, "Load credential file (%s) failed.", path);
        return -1;
    }

    credential = Credential_FromJson(data, &(ch->did));
    free((void*)data);
    if (!credential)
        return -1;

    for (size_t j = 0; j < credential->type.size; j++) {
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
//checked
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
        if (get_dir(credpath, 0, 6, ch->store->root, DATA_DIR, IDS_DIR, ch->did.idstring,
                CREDENTIALS_DIR, path) == 0) {
            delete_file(credpath);
            return 0;
        }
    }

    strcpy(id.did.idstring, ch->did.idstring);
    strcpy(id.fragment, path + 1);
    DIDStore_LoadCredMetadata(ch->store, &id.metadata, &id);
    rc = ch->cb(&id, ch->context);
    CredentialMetadata_Free(&id.metadata);
    return rc;
}
//checked
static int store_credential(DIDStore *store, Credential *credential)
{
    const char *data;
    char path[PATH_MAX], filename[128];
    DIDURL *id;
    int rc;

    assert(store);
    assert(credential);

    id = Credential_GetId(credential);
    if (!id)
        return -1;

    data = Credential_ToJson(credential, true);
    if (!data)
        return -1;

    sprintf(filename, "%s%s", "#", id->fragment);
    if (get_file(path, 1, 7, store->root, DATA_DIR, IDS_DIR, id->did.idstring,
            CREDENTIALS_DIR, filename, CREDENTIAL_FILE) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create credential (%s) file failed.", DIDURLSTR(&credential->id));
        free((void*)data);
        return -1;
    }

    rc = store_file(path, data);
    free((void*)data);
    if (!rc)
        return 0;

    delete_file(path);

    if (get_dir(path, 0, 6, store->root, DATA_DIR, IDS_DIR, id->did.idstring,
            CREDENTIALS_DIR, filename) == 0) {
        if (is_empty(path))
            delete_file(path);
    }

    if (get_dir(path, 0, 5, store->root, DATA_DIR, IDS_DIR, id->did.idstring, CREDENTIALS_DIR) == 0) {
        if (is_empty(path))
            delete_file(path);
    }

    DIDError_Set(DIDERR_IO_ERROR, "Store credential failed.");
    return -1;
}

/////////////////////////////////////////////////////////////////////////
//checked
DIDStore* DIDStore_Open(const char *root)
{
    char path[PATH_MAX];
    DIDStore *store;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!root || !*root, "Invalid root path for DIDStore.", NULL);
    CHECK_ARG(strlen(root) >= PATH_MAX, "DIDStore root is too long.", NULL);

    store = (DIDStore *)calloc(1, sizeof(DIDStore));
    if (!store) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for didstore failed.");
        return NULL;
    }

    strcpy(store->root, root);

    if (get_dir(path, 0, 1, root) == 0) {
        if ((!is_empty(path) && !check_store(store)) ||
               (is_empty(path) && !create_store(store)))
            return store;

        goto errorExit;
    }

    if (mkdirs(path, S_IRWXU) == 0 && !create_store(store))
        return store;

errorExit:
    DIDError_Set(DIDERR_DIDSTORE_ERROR, "Open DIDStore failed.");
    DIDStore_Close(store);
    return NULL;

    DIDERROR_FINALIZE();
}
//checked
void DIDStore_Close(DIDStore *store)
{
    DIDERROR_INITIALIZE();

    if (store) {
        StoreMetadata_Free(&store->metadata);
        free(store);
    }

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_StoreDID(DIDStore *store, DIDDocument *document)
{
    char path[PATH_MAX];
    const char *data;
    DIDMetadata metadata;
    ssize_t count;
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to store document.", -1);
    CHECK_ARG(!document, "No document argument to be stored.", -1);

    if (DIDStore_LoadDIDMetadata(store, &metadata, &document->did) == -1)
        return -1;

    rc = DIDMetadata_Merge(&document->metadata, &metadata);
    DIDMetadata_Free(&metadata);
    if (rc < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Merge did metadata failed.");
        return -1;
    }

    DIDMetadata_SetStore(&document->metadata, store);
    DID_ToString(&document->did, document->metadata.did, sizeof(document->metadata.did));
    memcpy(&document->did.metadata, &document->metadata, sizeof(DIDMetadata));
	data = DIDDocument_ToJson(document, true);
	if (!data)
		return -1;

    rc = get_file(path, 1, 5, store->root, DATA_DIR, IDS_DIR, document->did.idstring, DOCUMENT_FILE);
    if (rc < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create file for document (%s) failed.", DIDSTR(&document->did));
        free((void*)data);
        return -1;
    }

    rc = store_file(path, data);
    free((void*)data);
    if (rc) {
        DIDError_Set(DIDERR_IO_ERROR, "Store document (%s) failed.", DIDSTR(&document->did));
        goto errorExit;
    }

    if (DIDStore_StoreDIDMetadata(store, &document->metadata, &document->did) == -1)
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
    if (get_dir(path, 0, 4, store->root, DATA_DIR, IDS_DIR, document->did.idstring) == 0) {
        if (is_empty(path))
            delete_file(path);
    }
    return -1;

    DIDERROR_FINALIZE();
}
//checked
const char *load_didfile(DIDStore *store, DID *did)
{
    char path[PATH_MAX];
    const char *data;
    int rc;

    assert(store);
    assert(did);

    if (get_file(path, 0, 5, store->root, DATA_DIR, IDS_DIR, did->idstring, DOCUMENT_FILE) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "The file for document(%s) doesn't exist.", DIDSTR(did));
        return NULL;
    }

    rc = test_path(path);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "File(%s) error.", path);
        return NULL;
    }

    if (rc == S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "File(%s) error.", path);
        delete_file(path);
        return NULL;
    }

    data = load_file(path);
    if (!data) {
        DIDError_Set(DIDERR_IO_ERROR, "Load did(%s) file error.", DIDSTR(did));
        return NULL;
    }

    return data;
}
//checked
DIDDocument *DIDStore_LoadDID(DIDStore *store, DID *did)
{
    DIDDocument *document;
    const char *data;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to load did.", NULL);
    CHECK_ARG(!did, "No did argument to be loaded.", NULL);

    data = load_didfile(store, did);
    if (!data) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Load document(%s) file error.", DIDSTR(did));
        return NULL;
    }

    document = DIDDocument_FromJson(data);
    free((void*)data);
    if (!document)
        return NULL;

    if (DIDStore_LoadDIDMetadata(store, &document->metadata, &document->did) == -1) {
        DIDDocument_Destroy(document);
        return NULL;
    }

    DIDMetadata_SetStore(&document->metadata, store);
    memcpy(&document->did.metadata, &document->metadata, sizeof(DIDMetadata));

    return document;

    DIDERROR_FINALIZE();
}
//checked
bool DIDStore_ContainsDID(DIDStore *store, DID *did)
{
    char path[PATH_MAX];
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to check did existence.", false);
    CHECK_ARG(!did, "No did argument to be checked existence.", false);

    if (get_dir(path, 0, 4, store->root, DATA_DIR, IDS_DIR, did->idstring) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No did [%s] directory in store.", DIDSTR(did));
        return false;
    }

    rc = test_path(path);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "Invalid did [%s] directory in store.", DIDSTR(did));
        return false;
    }

    if (rc == S_IFREG || is_empty(path)) {
        DIDError_Set(DIDERR_IO_ERROR, "Invalid did [%s] directory in store.", DIDSTR(did));
        delete_file(path);
        return false;
    }

    return true;

    DIDERROR_FINALIZE();
}
//checked
bool DIDStore_DeleteDID(DIDStore *store, DID *did)
{
    char path[PATH_MAX];

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to delete did.", false);
    CHECK_ARG(!did, "No did argument to be deleted.", false);

    if (get_dir(path, 0, 4, store->root, DATA_DIR, IDS_DIR, did->idstring) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Did(%s) doesn't exist.", DIDSTR(did));
        return false;
    }

    if (test_path(path) > 0) {
        delete_file(path);
        return true;
    } else {
        DIDError_Set(DIDERR_IO_ERROR, "Did(%s) file error.", DIDSTR(did));
        return false;
    }

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_ListDIDs(DIDStore *store, ELA_DID_FILTER filter,
        DIDStore_DIDsCallback *callback, void *context)
{
    char path[PATH_MAX];
    DID_List_Helper dh;
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to list dids.", -1);
    CHECK_ARG(!callback, "No callback argument.", -1);

    if (get_dir(path, 0, 3, store->root, DATA_DIR, IDS_DIR) == -1)
        return 0;

    rc = test_path(path);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "The 'ids' directory error.");
        return -1;
    }

    if (rc != S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "The 'ids' directory should be directory.");
        return -1;
    }

    dh.store = store;
    dh.cb = callback;
    dh.context = context;
    dh.filter = filter;

    if (list_dir(path, "*", list_did_helper, (void*)&dh) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "List dids failed.");
        return -1;
    }

    return 0;

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_StoreCredential(DIDStore *store, Credential *credential)
{
    CredentialMetadata metadata;
    DIDURL *id;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to store credential.", -1);
    CHECK_ARG(!credential, "No credential argument to be stored.", -1);

    id = Credential_GetId(credential);
    if (!id)
        return -1;

    if (DIDStore_LoadCredMetadata(store, &metadata, id) == -1)
        return -1;

    if (CredentialMetadata_Merge(&credential->metadata, &metadata) < 0)
        return -1;

    CredentialMetadata_SetStore(&credential->metadata, store);
    DIDURL_ToString(&credential->id, credential->metadata.id, sizeof(credential->metadata.id), false);
    memcpy(&credential->id.metadata, &credential->metadata, sizeof(CredentialMetadata));
    CredentialMetadata_Free(&metadata);

    if (store_credential(store, credential) == -1 ||
            DIDStore_StoreCredMetadata(store, &credential->metadata, id) == -1)
        return -1;

    return 0;

    DIDERROR_FINALIZE();
}
//checked
Credential *DIDStore_LoadCredential(DIDStore *store, DID *did, DIDURL *id)
{
    const char *data;
    char path[PATH_MAX], filename[128];
    Credential *credential;
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to load credential", NULL);
    CHECK_ARG(!did, "No owner of credential.", NULL);
    CHECK_ARG(!id, "No credential argument to be loaded.", NULL);

    sprintf(filename, "#%s", id->fragment);
    if (get_file(path, 0, 7, store->root, DATA_DIR, IDS_DIR, did->idstring,
            CREDENTIALS_DIR, filename, CREDENTIAL_FILE) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "The credential(%s) file doesn't exist.", DIDURLSTR(id));
        return NULL;
    }

    rc = test_path(path);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "The credential(%s) file error.", DIDURLSTR(id));
        return NULL;
    }

    if (rc == S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "The credential(%s) file should be a file.", DIDURLSTR(id));
        delete_file(path);
        return NULL;
    }

    data = load_file(path);
    if (!data) {
        DIDError_Set(DIDERR_IO_ERROR, "Load credential(%s) file failed.", DIDURLSTR(id));
        return NULL;
    }

    credential = Credential_FromJson(data, did);
    free((void*)data);
    if (!credential)
        return NULL;

    if (DIDStore_LoadCredMetadata(store, &credential->metadata, id) == -1) {
        Credential_Destroy(credential);
        return NULL;
    }

    memcpy(&credential->id.metadata, &credential->metadata, sizeof(CredentialMetadata));
    return credential;

    DIDERROR_FINALIZE();
}
//checked
bool DIDStore_ContainsCredentials(DIDStore *store, DID *did)
{
    char path[PATH_MAX];
    int rc;
    bool empty;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to check credentials' existence.", false);
    CHECK_ARG(!did, "No owner of credentials to be checked.", false);

    if (get_dir(path, 0, 5, store->root, DATA_DIR, IDS_DIR, did->idstring, CREDENTIALS_DIR) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "The credential directory of did(%s) doesn't not exist.", DIDSTR(did));
        return -1;
    }

    rc = test_path(path);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "The credential directory of did(%s) error.", DIDSTR(did));
        return false;
    }

    if (rc == S_IFREG) {
        DIDError_Set(DIDERR_IO_ERROR, "The credential directory of did(%s) should be directory.", DIDSTR(did));
        delete_file(path);
        return false;
    }

    empty = is_empty(path);
    if (empty)
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "The credential directory of did(%s) is empty.", DIDSTR(did));

    return !empty;

    DIDERROR_FINALIZE();
}
//checked
bool DIDStore_ContainsCredential(DIDStore *store, DID *did, DIDURL *id)
{
    char path[PATH_MAX], filename[128];
    int rc;

    CHECK_ARG(!store, "No didstore to check credential's existence.", false);
    CHECK_ARG(!did, "No owner of credential.", false);
    CHECK_ARG(!id, "No id of credential to be checked existence.", false);

    sprintf(filename, "#%s", id->fragment);
    if (get_dir(path, 0, 6, store->root, DATA_DIR, IDS_DIR, did->idstring,
            CREDENTIALS_DIR, filename) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Credential[%s] doesn't exist in didstore.", DIDURLSTR(id));
        return false;
    }

    rc = test_path(path);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "Credential[%s] directory error.", DIDURLSTR(id));
        return false;
    }

    if (rc == S_IFREG) {
        DIDError_Set(DIDERR_IO_ERROR, "Credential[%s] directory should be directory.", DIDURLSTR(id));
        delete_file(path);
        return false;
    }

    return true;
}
//checked
bool DIDStore_DeleteCredential(DIDStore *store, DID *did, DIDURL *id)
{
    char path[PATH_MAX], filename[128];

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to delete credential.", false);
    CHECK_ARG(!did, "No owner of credential.", false);
    CHECK_ARG(!id, "No id of credential to be deleted.", false);

    sprintf(filename, "#%s", id->fragment);
    if (get_dir(path, 0, 6, store->root, DATA_DIR, IDS_DIR, did->idstring,
            CREDENTIALS_DIR, filename) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Credential[%s] doesn't exist in didstore.", DIDURLSTR(id));
        return false;
    }

    if (is_empty(path)) {
        DIDError_Set(DIDERR_IO_ERROR, "Credential[%s] directory is empty.", DIDURLSTR(id));
        return false;
    }

    delete_file(path);
    if (get_dir(path, 0, 5, store->root, DATA_DIR, IDS_DIR, did->idstring, CREDENTIALS_DIR) == 0) {
        if (is_empty(path))
            delete_file(path);
    }
    return true;

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_ListCredentials(DIDStore *store, DID *did,
        DIDStore_CredentialsCallback *callback, void *context)
{
    ssize_t size = 0;
    char path[PATH_MAX];
    Cred_List_Helper ch;
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to list credentials.", -1);
    CHECK_ARG(!did, "No owner of credential.", -1);
    CHECK_ARG(!callback, "No callback argument.", -1);

    if (get_dir(path, 0, 5, store->root, DATA_DIR, IDS_DIR, did->idstring, CREDENTIALS_DIR) == -1)
        return 0;

    rc = test_path(path);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "The did(%s) directory stored credentials error.", DIDSTR(did));
        return -1;
    }

    if (rc == S_IFREG) {
        DIDError_Set(DIDERR_IO_ERROR, "The did(%s) directory stored credentials should be directory.", DIDSTR(did));
        delete_file(path);
        return -1;
    }

    ch.store = store;
    ch.cb = callback;
    ch.context = context;
    strcpy((char*)ch.did.idstring, did->idstring);
    ch.type = NULL;

    if (list_dir(path, "*", list_credential_helper, (void*)&ch) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "List credentials failed.");
        return -1;
    }

    return 0;

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_SelectCredentials(DIDStore *store, DID *did, DIDURL *id,
        const char *type, DIDStore_CredentialsCallback *callback, void *context)
{
    char path[PATH_MAX], filename[128];
    Cred_List_Helper ch;
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to select credentials.", -1);
    CHECK_ARG(!did, "No owner of credential.", -1);
    CHECK_ARG(!callback, "No callback argument.", -1);
    CHECK_ARG(!id && !type, "No feature to select credential.", -1);

    if (id) {
        sprintf(filename, "#%s", id->fragment);
        if (get_file(path, 0, 7, store->root, DATA_DIR, IDS_DIR, did->idstring,
                CREDENTIALS_DIR, filename, CREDENTIAL_FILE) == -1) {
            DIDError_Set(DIDERR_NOT_EXISTS, "Credentials don't exist.");
            return -1;
        }

        if (test_path(path) > 0) {
            if ((type && has_type(did, path, type) == true) || !type) {
                if (callback(id, context) < 0) {
                    DIDError_Set(DIDERR_DIDSTORE_ERROR, "Select credentials' callback error.");
                }

                return 0;
            }

            DIDError_Set(DIDERR_DIDSTORE_ERROR, "No credential is match with type.");
            return -1;
        }

        DIDError_Set(DIDERR_UNKNOWN, "Unknown error.");
        return -1;
    }

    if (get_dir(path, 0, 5, store->root, DATA_DIR, IDS_DIR, did->idstring, CREDENTIALS_DIR) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No credentials.");
        return -1;
    }

    rc = test_path(path);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "The directory[%s] stored credentials error.", path);
        return -1;
    }

    if (rc == S_IFREG) {
        DIDError_Set(DIDERR_IO_ERROR, "The directory[%s] stored credentials should be directory.", path);
        delete_file(path);
        return -1;
    }

    ch.store = store;
    ch.cb = callback;
    ch.context = context;
    strcpy((char*)ch.did.idstring, did->idstring);
    ch.type = type;

    if (list_dir(path, "*.*", select_credential_helper, (void*)&ch) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Select credentials failed.");
        return -1;
    }

    return 0;

    DIDERROR_FINALIZE();
}
//checked
bool DIDSotre_ContainsPrivateKeys(DIDStore *store, DID *did)
{
    char path[PATH_MAX];
    bool empty;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to check privatekeys' existence.", false);
    CHECK_ARG(!did, "No owner of privatekeys.", false);

    if (get_dir(path, 0, 5, store->root, DATA_DIR, IDS_DIR, did->idstring, PRIVATEKEYS_DIR) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "The did(%s) directory stored privatekeys doesn't exist.", DIDSTR(did));
        return false;
    }

    empty = is_empty(path);
    if (empty)
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "The did(%s) directory stored privatekeys is empty.", DIDSTR(did));

    return !empty;

    DIDERROR_FINALIZE();
}
//checked
bool DIDStore_ContainsPrivateKey(DIDStore *store, DID *did, DIDURL *id)
{
    char path[PATH_MAX], filename[128];
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to check privatekey's existence.", false);
    CHECK_ARG(!did, "No owner of privatekey.", false);
    CHECK_ARG(!id, "No privatekey id.", false);

    sprintf(filename, "#%s", id->fragment);
    if (get_file(path, 0, 6, store->root, DATA_DIR, IDS_DIR, did->idstring,
            PRIVATEKEYS_DIR, filename) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "The privatekey(%s) file doesn't exist.", DIDURLSTR(id));
        return false;
    }

    rc = test_path(path);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "Privatekey(%s) file error.", DIDURLSTR(id));
        return false;
    }

    if (rc == S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Privatekey(%s) file should be file.", DIDURLSTR(id));
        delete_file(path);
        return false;
    }

    return true;

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_StorePrivateKey_Internal(DIDStore *store, DIDURL *id, const char *prvkey)
{
    char path[PATH_MAX], filename[128];

    assert(store);
    assert(id);
    assert(prvkey && *prvkey);

    sprintf(filename, "#%s", id->fragment);
    if (get_file(path, 1, 6, store->root, DATA_DIR, IDS_DIR, id->did.idstring,
            PRIVATEKEYS_DIR, filename) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create privatekey(%s) file failed.", DIDURLSTR(id));
        return -1;
    }

    if (!store_file(path, prvkey))
        return 0;

    DIDError_Set(DIDERR_IO_ERROR, "Store privatekey(%s) failed.", DIDURLSTR(id));
    delete_file(path);
    return -1;
}
//checked
int DIDStore_StorePrivateKey(DIDStore *store, const char *storepass, DIDURL *id,
        const uint8_t *privatekey, size_t size)
{
    char base64[MAX_PRIVATEKEY_BASE64];

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to store privatekey.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!id, "No privatekey id.", -1);
    CHECK_ARG(!privatekey || size == 0, "Invalid privatekey.", -1);

    if (didstore_encrypt_to_base64(store, storepass, base64, privatekey, size) == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt privatekey(%s) failed.", DIDURLSTR(id));
        return -1;
    }

    return DIDStore_StorePrivateKey_Internal(store, id, base64);

    DIDERROR_FINALIZE();
}
//checked
void DIDStore_DeletePrivateKey(DIDStore *store, DIDURL *id)
{
    char path[PATH_MAX], filename[128];

    DIDERROR_INITIALIZE();

    if (!store || !id)
        return;

    sprintf(filename, "%s%s", "#", id->fragment);
    if (get_file(path, 0, 6, store->root, DATA_DIR, IDS_DIR, &id->did,
            PRIVATEKEYS_DIR, filename) == -1)
        return;

    if (test_path(path) > 0)
        delete_file(path);

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_StoreDefaultPrivateKey(DIDStore *store, const char *storepass,
        const char *idstring, uint8_t *privatekey, size_t size)
{
    DIDURL id;

    assert(store);
    assert(storepass && *storepass);
    assert(idstring && *idstring);
    assert(privatekey);

    if (DIDURL_InitFromString(&id, idstring, "primary") < 0)
        return -1;

    if (DIDStore_StorePrivateKey(store, storepass, &id, privatekey, size) == -1)
        return -1;

    return 0;
}
//checked
bool DIDStore_ContainsRootIdentity(DIDStore *store, const char *id)
{
    char path[PATH_MAX];

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to check rootidentity.", false);
    CHECK_ARG(!id, "No rootidentity id argument.", false);

    if (get_dir(path, 0, 4, store->root, DATA_DIR, ROOTS_DIR, id) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Rootidentity(%s) directory doesn't exist.", id);
        return false;
    }

    return true;

    DIDERROR_FINALIZE();
}
//checked
bool DIDStore_ContainsRootIdentities(DIDStore *store)
{
    char path[PATH_MAX];

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No didstore to check rootidentities.", false);

    if (get_dir(path, 0, 3, store->root, DATA_DIR, ROOTS_DIR) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "'roots' directory doesn't exist.");
        return false;
    }

    return !is_empty(path);

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_StoreRootIdentityWithElem(DIDStore *store, const char *storepass, const char *id,
        const char *mnemonic, uint8_t *rootPrivatekey, size_t rootsize,
        uint8_t *preDerivedPublicKey, size_t keysize, int index)
{
    assert(store);
    assert(storepass && *storepass);
    assert(id);

    if (mnemonic && *mnemonic && store_mnemonic(store, storepass, id,
            (unsigned char*)mnemonic, strlen(mnemonic)) < 0)
        return -1;

    if (rootPrivatekey && rootsize == EXTENDEDKEY_BYTES && store_extendedprvkey(store,
            storepass, id, rootPrivatekey, rootsize) < 0)
        return -1;

    if (preDerivedPublicKey && keysize == EXTENDEDKEY_BYTES && store_extendedpubkey(store,
            id, preDerivedPublicKey, keysize) < 0)
        return -1;

    if (index >= 0 && DIDStore_StoreIndex(store, id, index) < 0)
        return -1;

    return 0;
}
//checked
int DIDStore_StoreRootIdentity(DIDStore *store, const char *storepass, RootIdentity *rootidentity)
{
    CHECK_ARG(!store, "No store to store rootidentity.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!rootidentity, "No rootidentity to be stored.", -1);

    if (DIDStore_StoreRootIdentityWithElem(store, storepass, rootidentity->id,
            rootidentity->mnemonic, rootidentity->rootPrivateKey, sizeof(rootidentity->rootPrivateKey),
            rootidentity->preDerivedPublicKey, sizeof(rootidentity->preDerivedPublicKey),
            rootidentity->index) < 0)
        return -1;

    if (!StoreMetadata_GetDefaultRootIdentity(&store->metadata)) {
        if (StoreMetadata_SetDefaultRootIdentity(&store->metadata, rootidentity->id) < 0 ||
                store_storemetadata(store, NULL, &store->metadata) < 0) {
            return -1;
        }
    }

    return 0;
}
//checked
RootIdentity *DIDStore_LoadRootIdentity(DIDStore *store, const char *id)
{
    RootIdentity *rootidentity = NULL;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to load rootidentity.", NULL);
    CHECK_ARG(!id, "No rootidentity id.", NULL);
    CHECK_ARG(strlen(id) + 1 > MAX_ID_LEN, "Rootidentity id string is too long.", NULL);

    rootidentity = (RootIdentity*)calloc(1, sizeof(RootIdentity));
    if (!rootidentity) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for rootIdentity failed.");
        return NULL;
    }

    if (load_extendedpubkey(store, id, rootidentity->preDerivedPublicKey, EXTENDEDKEY_BYTES) < 0)
        goto errorExit;

    rootidentity->index = DIDStore_LoadIndex(store, id);
    if (rootidentity->index < 0)
        goto errorExit;

    strcpy((char*)rootidentity->id, id);
    load_identitymetadata(store, id, &rootidentity->metadata);
    return rootidentity;

errorExit:
    RootIdentity_Destroy(rootidentity);
    return NULL;

    DIDERROR_FINALIZE();
}
//checked
bool DIDStore_DeleteRootIdentity(DIDStore *store, const char *id)
{
    char path[PATH_MAX];
    const char *defaultid;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to delete rootidentity.", false);
    CHECK_ARG(!id, "No rootidentity id.", false);

    if (get_dir(path, 0, 4, store->root, DATA_DIR, ROOTS_DIR, id) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "The rootidentity(%s) doesn't exist.", id);
        return false;
    }

    delete_file(path);

    defaultid = DIDStore_GetDefaultRootIdentity(store);
    if (defaultid) {
        if (!strcmp(defaultid, id))
            DIDStore_SetDefaultRootIdentity(store, NULL);

        free((void*)defaultid);
    }
    return true;

    DIDERROR_FINALIZE();
}
//checked
ssize_t DIDStore_ListRootIdentities(DIDStore *store,
        DIDStore_RootIdentitiesCallback *callback, void *context)
{
    char path[PATH_MAX];
    RootIdentity_List_Helper rh;
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to list rootidentities.", -1);
    CHECK_ARG(!callback, "No callback argument.", -1);

    if (get_dir(path, 0, 3, store->root, DATA_DIR, ROOTS_DIR) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "The 'roots' directory doesn't exist.");
        return -1;
    }

    rc = test_path(path);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "The 'roots' directory error.");
        return -1;
    }

    if (rc != S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "The 'roots' directory should be directory.");
        return -1;
    }

    rh.store = store;
    rh.cb = callback;
    rh.context = context;

    if (list_dir(path, "*", list_rootidentity_helper, (void*)&rh) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "List rootidentities failed.");
        return -1;
    }

    return 0;

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_SetDefaultRootIdentity(DIDStore *store, const char *id)
{
    assert(store);

    if (id && !DIDStore_ContainsRootIdentity(store, id)) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No rootidentity(%s).", id);
        return -1;
    }

    if (StoreMetadata_SetDefaultRootIdentity(&store->metadata, id) < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Set default rootidentity failed.");
        return -1;
    }

    if (store_storemetadata(store, NULL, &store->metadata) < 0)
        return -1;

    return 0;
}
//checked
static int get_identity(RootIdentity *identity, void *context)
{
    DefaultRootIdentity_Helper *helper = (DefaultRootIdentity_Helper*)context;

    if (!identity)
        return 0;

    if (!*helper->id)
        strcpy(helper->id, identity->id);

    helper->count++;
    return 0;
}
//checked
const char *DIDStore_GetDefaultRootIdentity(DIDStore *store)
{
    DefaultRootIdentity_Helper helper;
    const char *id, *_id = NULL;
    int count = 0;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to get default rootidentitiy.", NULL);

    id = StoreMetadata_GetDefaultRootIdentity(&store->metadata);
    if (id && DIDStore_ContainsRootIdentity(store, id))
        return strdup(id);

    *helper.id = 0;
    helper.count = 0;

    if (DIDStore_ListRootIdentities(store, get_identity, (void*)&helper) < 0)
        return NULL;

    if (helper.count == 0) {
        DIDError_Set(DIDERR_NOT_EXISTS, "There is no rootidentities.");
        return NULL;
    }
    if (helper.count > 1) {
        DIDError_Set(DIDERR_NOT_EXISTS,
                "There is no default rootidentity, but one more rootidentities in didstore.Please specify one.");
        return NULL;
    }

    return strdup(helper.id);

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_ExportRootIdentityMnemonic(DIDStore *store, const char *storepass,
        const char *id, char *mnemonic, size_t size)
{
    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to export mnemonic.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!id, "No rootidentity id.", -1);
    CHECK_ARG(!mnemonic || size == 0, "Invalid buffer for mnemonic.", -1);

    return load_mnemonic(store, storepass, id, mnemonic, size);

    DIDERROR_FINALIZE();
}

bool DIDStore_ContainsRootIdentityMnemonic(DIDStore *store, const char *id)
{
    char path[PATH_MAX];
    struct stat st;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to check mnemonic.", -1);
    CHECK_ARG(!id, "No rootidentity id.", false);

    if (get_file(path, 0, 5, store->root, DATA_DIR, ROOTS_DIR, id, MNEMONIC_FILE) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Mnemonic file of rootidentity(%s) doesn't exist.", id);
        return -1;
    }

    if (stat(path, &st) < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "Mnemonic file of rootidentity(%s) error.", id);
        return false;
    }

    if (st.st_size <= 0) {
        DIDError_Set(DIDERR_IO_ERROR, "No mnemonic content of rootidentity(%s).", id);
        return false;
    }

    return true;

    DIDERROR_FINALIZE();
}
//checked
int DIDStore_LoadIndex(DIDStore *store, const char *id)
{
    const char *string;
    int index;

    assert(store);
    assert(id);

    string = load_index_string(store, id);
    if (!string) {
        DIDError_Set(DIDERR_IO_ERROR, "Load index failed.");
        return -1;
    }

    index = atoi(string);
    free((void*)string);
    return index;
}
//checked
int DIDStore_StoreIndex(DIDStore *store, const char *id, int index)
{
    char string[32];
    int len;

    assert(store);
    assert(index >= 0);

    len = snprintf(string, sizeof(string), "%d", index);
    if (len < 0 || len > sizeof(string)) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Get index string failed.");
        return -1;
    }
    return store_index_string(store, NULL, id, string);
}
//checked
ssize_t DIDStore_LoadPrivateKey(DIDStore *store, const char *storepass,
        DID *did, DIDURL *key, uint8_t *privatekey, size_t size)
{
    uint8_t extendedkey[EXTENDEDKEY_BYTES];
    HDKey _identity, *identity;
    ssize_t len;

    assert(store);
    assert(did);
    assert(key);
    assert(privatekey);
    assert(size >= PRIVATEKEY_BYTES);

    len = DIDStore_LoadPrivateKey_Internal(store, storepass, did, key, extendedkey, sizeof(extendedkey));
    if (len < 0)
        return -1;

    //To remove later! only for test case.
    if (len == PRIVATEKEY_BYTES) {
        memcpy(privatekey, extendedkey, PRIVATEKEY_BYTES);
        return len;
    }

    identity = HDKey_FromExtendedKey(extendedkey, sizeof(extendedkey), &_identity);
    memset(extendedkey, 0, sizeof(extendedkey));
    if (!identity) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get HDKey failed.");
        return -1;
    }

    memcpy(privatekey, HDKey_GetPrivateKey(identity), PRIVATEKEY_BYTES);
    return PRIVATEKEY_BYTES;
}
//checked
ssize_t DIDStore_LoadPrivateKey_Internal(DIDStore *store, const char *storepass, DID *did,
        DIDURL *key, uint8_t *extendedkey, size_t size)
{
    ssize_t len;
    const char *privatekey_str = NULL;
    char path[PATH_MAX], filename[128];
    bool success = false;
    int rc = -1;

    assert(store);
    assert(storepass && *storepass);
    assert(did);
    assert(key);
    assert(extendedkey);
    assert(size >= EXTENDEDKEY_BYTES);

    sprintf(filename, "%s%s", "#", key->fragment);
    rc = get_file(path, 0, 6, store->root, DATA_DIR, IDS_DIR, did->idstring, PRIVATEKEYS_DIR, filename);
    if (rc == 0) {
        privatekey_str = load_file(path);
        if (!privatekey_str) {
            rc = -1;
        }
    }

    if (rc == -1)
        return RootIdentity_LazyCreatePrivateKey(key, store, storepass, extendedkey, size);

    len = didstore_decrypt_from_base64(store, storepass, extendedkey, privatekey_str);
    free((void*)privatekey_str);
    if (len == -1)
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decrypt private key failed.");

    return len;
}
//checked
int DIDStore_Sign(DIDStore *store, const char *storepass, DID *did,
        DIDURL *key, char *sig, uint8_t *digest, size_t size)
{
    uint8_t binkey[PRIVATEKEY_BYTES];

    assert(store);
    assert(storepass && *storepass);
    assert(did);
    assert(key);
    assert(sig);
    assert(digest && size == SHA256_BYTES);

    if (DIDStore_LoadPrivateKey(store, storepass, did, key, binkey, sizeof(binkey)) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "No private key to sign in the store.");
        return -1;
    }

    if (ecdsa_sign_base64(sig, binkey, digest, size) == -1) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "ECDSA sign failed.");
        return -1;
    }

    memset(binkey, 0, sizeof(binkey));
    return 0;
}

static bool need_reencrypt(const char *path)
{
    char file[PATH_MAX];
    char *token, *pos;
    bool isPrivates = false;
    int i = -1;

    assert(path && *path);

    pos = strstr(path, DATA_DIR);
    if (!pos)
        return false;

    strcpy(file, pos);

    token = strtok((char*)file, PATH_SEP);
    while(token) {
        if (i <= 2)
            i++;
        if (i == 3) {
            if (!strcmp(token, PRIVATE_FILE) || !strcmp(token, MNEMONIC_FILE))
                return true;
            i++;
        }
        if (i == 4 && !strcmp(token, PRIVATEKEYS_DIR)) {
            isPrivates = true;
            i++;
        }
        if (i == 5 && isPrivates)
            return true;

        token = strtok(NULL, PATH_SEP);
    }

    return false;
}

static int dir_copy(const char *dst, const char *src, const char *newpw, const char *oldpw);

static int dir_copy_helper(const char *path, void *context)
{
    char srcpath[PATH_MAX], dstpath[PATH_MAX];
    int len;

    Dir_Copy_Helper *dh = (Dir_Copy_Helper*)context;

    if (!path)
        return 0;

    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0)
        return 0;

    len = snprintf(srcpath, PATH_MAX, "%s%s%s", dh->srcpath, PATH_SEP, path);
    if (len < 0 || len > PATH_MAX)
        return -1;

    len = snprintf(dstpath, PATH_MAX, "%s%s%s", dh->dstpath, PATH_SEP, path);
    if (len < 0 || len > PATH_MAX)
        return -1;

    return dir_copy(dstpath, srcpath, dh->newpassword, dh->oldpassword);
}
//checked
static int dir_copy(const char *dst, const char *src, const char *newpw, const char *oldpw)
{
    int rc;
    Dir_Copy_Helper dh;
    const char *string;
    ssize_t size;
    uint8_t plain[256];
    unsigned char data[512];

    assert(dst && *dst);
    assert(src && *src);

    if (test_path(src) < 0)
        return -1;

    //src is directory.
    if (test_path(src) == S_IFDIR) {
        if (test_path(dst) < 0) {
            rc = mkdirs(dst, S_IRWXU);
            if (rc < 0) {
                DIDError_Set(DIDERR_IO_ERROR, "Create cache directory (%s) failed", dst);
                return -1;
            }
        }

        dh.srcpath = src;
        dh.dstpath = dst;
        dh.oldpassword = oldpw;
        dh.newpassword = newpw;

        if (list_dir(src, "*", dir_copy_helper, (void*)&dh) == -1) {
            DIDError_Set(DIDERR_DIDSTORE_ERROR, "Copy directory failed.");
            return -1;
        }

        return 0;
    }

    //src is file
    string = load_file(src);
    if (!string || !*string) {
        DIDError_Set(DIDERR_IO_ERROR, "Load %s failed.", src);
        return -1;
    }

    //src is not encrypted file.
    if (!need_reencrypt(src)) {
        rc = store_file(dst, string);
        free((void*)string);
        if (rc < 0)
            DIDError_Set(DIDERR_IO_ERROR, "Store %s failed.", dst);

        return rc;
    }

    //src is encrypted file.
    size = decrypt_from_b64(plain, oldpw, string);
    free((void*)string);
    if (size < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decrypt %s failed.", src);
        return -1;
    }

    size = encrypt_to_b64((char*)data, newpw, plain, size);
    memset(plain, 0, sizeof(plain));
    if (size < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt %s with new password failed.", src);
        return -1;
    }

    rc = store_file(dst, (char*)data);
    if (rc < 0)
        DIDError_Set(DIDERR_IO_ERROR, "Store %s failed.", dst);

    return rc;
}
//checked
static int change_password(DIDStore *store, const char *newpw, const char *oldpw)
{
    char data_dir[PATH_MAX] = {0}, data_journal_dir[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};

    assert(store);
    assert(newpw && *newpw);
    assert(oldpw && *oldpw);

    if (get_dir(data_dir, 0, 2, store->root, DATA_DIR) == -1) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Data directory doesn't exist.");
        return -1;
    }
    if (test_path(data_dir) != S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Data directory is not a directory.");
        return -1;
    }

    if (get_dir(data_journal_dir, 1, 2, store->root, DATA_JOURNAL) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create data journal directory failed.");
        return -1;
    }
    if (test_path(data_journal_dir) != S_IFDIR) {
        DIDError_Set(DIDERR_IO_ERROR, "Data journal is not a directory.");
        return -1;
    }

    if (dir_copy(data_journal_dir, data_dir, newpw, oldpw) == -1) {
        delete_file(data_journal_dir);
        return -1;
    }

    //create tag file to indicate copying dir successfully.
    if (get_file(path, 1, 2, store->root, POST_PASSWORD) == -1) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Create 'post_password' file failed.");
        delete_file(data_journal_dir);
        return -1;
    }

    return store_file(path, "");
}
//checked
int DIDStore_ChangePassword(DIDStore *store, const char *newpw, const char *oldpw)
{
    char fingerprint[64] = {0};

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to change password.", -1);
    CHECK_ARG(!oldpw || !*oldpw, "Please specify valid old password.", -1);
    CHECK_ARG(!newpw || !*newpw, "Please specify valid new password.", -1);

    if (!check_password(store, oldpw)) {
        DIDError_Set(DIDERR_WRONG_PASSWORD, "Old password isn't current DIDStore's password.");
        return -1;
    }

    if (change_password(store, newpw, oldpw) == -1)
        return -1;

    if (calc_fingerprint(fingerprint, sizeof(fingerprint), newpw) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Calculate new fingerprint failed.");
        return -1;
    }

    if (post_changepassword(store) < 0)
        return -1;

    if (StoreMetadata_SetFingerPrint(&store->metadata, fingerprint) < 0 ||
            store_storemetadata(store, NULL, &store->metadata) < 0)
        return -1;

    return 0;

    DIDERROR_FINALIZE();
}

//--------export and import store
static int write_credentials(DIDURL *id, void *context)
{
    Cred_Export_Helper *ch = (Cred_Export_Helper*)context;

    Credential *cred = NULL;
    const char *vc_string = NULL, *meta_string = NULL;
    DID *creddid;
    int rc = -1;

    if (!id)
        return 0;

    creddid = DIDURL_GetDid(id);
    if (!creddid)
        return -1;

    cred = DIDStore_LoadCredential(ch->store, creddid, id);
    if (!cred)
        return -1;

    CHECK_TO_MSG_ERROREXIT(DIDJG_WriteStartObject(ch->gen),
            DIDERR_OUT_OF_MEMORY, "Start 'credential' object failed.");
    CHECK_TO_MSG_ERROREXIT(DIDJG_WriteFieldName(ch->gen, "content"),
            DIDERR_OUT_OF_MEMORY, "Write 'vc' failed.");
    CHECK_TO_MSG_ERROREXIT(Credential_ToJson_Internal(ch->gen, cred, creddid, true, false),
            DIDERR_OUT_OF_MEMORY, "Write credential failed.");
    if (cred->metadata.base.data) {
        CHECK_TO_MSG_ERROREXIT(DIDJG_WriteFieldName(ch->gen, "metadata"),
                DIDERR_OUT_OF_MEMORY, "Write 'metadata' failed.");
        CHECK_TO_MSG_ERROREXIT(CredentialMetadata_ToJson_Internal(&cred->metadata, ch->gen),
                DIDERR_OUT_OF_MEMORY, "Write credential metadata failed.");
    }
    CHECK_TO_MSG_ERROREXIT(DIDJG_WriteEndObject(ch->gen),
            DIDERR_OUT_OF_MEMORY, "End 'credential' object failed.");
    vc_string = Credential_ToJson(cred, true);
    if (!vc_string)
        goto errorExit;

    if (sha256_digest_update(ch->digest, 1, vc_string, strlen(vc_string)) < 0)
        goto errorExit;

    rc = 0;
    meta_string = CredentialMetadata_ToJson(&cred->metadata);
    if (meta_string) {
        rc = sha256_digest_update(ch->digest, 1, meta_string, strlen(meta_string));
        if (rc < 0)
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Metadata(%s) to update digest failed.");
    }

errorExit:
    if (cred)
        Credential_Destroy(cred);
    if (vc_string)
        free((void*)vc_string);
    if (meta_string)
        free((void*)meta_string);

    return rc;
}
//checked
static int export_type(JsonGenerator *gen, Sha256_Digest *digest)
{
    assert(gen);
    assert(digest);

    CHECK_TO_MSG(DIDJG_WriteStringField(gen, "type", DID_EXPORT),
            DIDERR_OUT_OF_MEMORY, "Write 'type' failed.");
    CHECK_TO_MSG(sha256_digest_update(digest, 1, DID_EXPORT, strlen(DID_EXPORT)),
            DIDERR_CRYPTO_ERROR, "Sha256 'type' failed.");

    return 0;
}
//checked
static int export_id(JsonGenerator *gen, DID *did, Sha256_Digest *digest)
{
    char idstring[ELA_MAX_DID_LEN];
    const char *value;

    assert(gen);
    assert(did);
    assert(digest);

    value = DID_ToString(did, idstring, sizeof(idstring));
    if (!value)
        return -1;

    CHECK_TO_MSG(DIDJG_WriteStringField(gen, "id", value),
            DIDERR_OUT_OF_MEMORY, "Write 'id' failed.");
    CHECK_TO_MSG(sha256_digest_update(digest, 1, value, strlen(value)),
            DIDERR_CRYPTO_ERROR, "Sha256 'id' failed.");

    return 0;
}

static int export_created(JsonGenerator *gen, Sha256_Digest *digest)
{
    char timestring[DOC_BUFFER_LEN];
    const char *value;
    time_t created = 0;

    assert(gen);
    assert(digest);

    value = get_time_string(timestring, sizeof(timestring), &created);
    if(!value) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Get current time failed.");
        return -1;
    }

    CHECK_TO_MSG(DIDJG_WriteStringField(gen, "created", value),
            DIDERR_OUT_OF_MEMORY, "Write 'created' failed.");
    CHECK_TO_MSG(sha256_digest_update(digest, 1, value, strlen(value)),
            DIDERR_CRYPTO_ERROR, "Sha256 'created' failed.");

    return 0;
}

static int export_document(JsonGenerator *gen, DIDDocument *doc, Sha256_Digest *digest)
{
    const char *docstring, *metadata;
    int rc;

    assert(gen);
    assert(doc);

    CHECK(DIDJG_WriteFieldName(gen, "document"));
    CHECK(DIDJG_WriteStartObject(gen));
    CHECK(DIDJG_WriteFieldName(gen, "content"));
    CHECK(DIDDocument_ToJson_Internal(gen, doc, true, false));
    CHECK(DIDJG_WriteFieldName(gen, "metadata"));
    CHECK(DIDMetadata_ToJson_Internal(&doc->metadata, gen));
    CHECK(DIDJG_WriteEndObject(gen));

    docstring = DIDDocument_ToJson(doc, true);
    if (!docstring)
        return -1;

    metadata = DIDMetadata_ToJson(&doc->metadata);
    if (!metadata) {
        free((void*)docstring);
        return -1;
    }

    rc = sha256_digest_update(digest, 2, docstring, strlen(docstring), metadata, strlen(metadata));
    free((void*)docstring);
    free((void*)metadata);
    if (rc < 0)
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Update sha256 digest failed.");

    return rc;
}
//checked
static int export_creds(JsonGenerator *gen, DIDStore *store, DID *did, Sha256_Digest *digest)
{
    Cred_Export_Helper ch;

    assert(gen);
    assert(store);
    assert(did);

    if (DIDStore_ContainsCredentials(store, did)) {
        CHECK_TO_MSG(DIDJG_WriteFieldName(gen, "credential"),
                DIDERR_OUT_OF_MEMORY, "Write 'document' failed.");
        CHECK_TO_MSG(DIDJG_WriteStartArray(gen),
                DIDERR_OUT_OF_MEMORY, "Start credential array failed.");

        ch.store = store;
        ch.gen = gen;
        ch.digest = digest;
        CHECK(DIDStore_ListCredentials(store, did, write_credentials, (void*)&ch));
        CHECK_TO_MSG(DIDJG_WriteEndArray(gen),
                DIDERR_OUT_OF_MEMORY, "End credential array failed.");
    }

    return 0;
}
//checked
static int export_privatekey(JsonGenerator *gen, DIDStore *store, const char *storepass,
        const char *password, DIDDocument *doc, Sha256_Digest *digest)
{
    ssize_t size;
    int rc, i;
    DID *did;
    DIDURL *keyid;
    char _idstring[ELA_MAX_DIDURL_LEN], *idstring;

    assert(gen);
    assert(store);
    assert(digest);

    did = &doc->did;
    //todo: check customized did size == 0
    if (DIDSotre_ContainsPrivateKeys(store, did)) {
        size = doc->publickeys.size;
        if (size == 0)
            //return -1;
            return 0;

        PublicKey **pks = doc->publickeys.pks;
        if (!pks)
            //return -1;
            return 0;

        CHECK_TO_MSG(DIDJG_WriteFieldName(gen, "privatekey"),
                DIDERR_OUT_OF_MEMORY, "Write 'privatekey' failed.");
        CHECK_TO_MSG(DIDJG_WriteStartArray(gen),
                DIDERR_OUT_OF_MEMORY, "Start 'privatekey' array failed.");

        for (i = 0; i < size; i++) {
            char base64[512];
            uint8_t extendedkey[EXTENDEDKEY_BYTES];
            keyid = &pks[i]->id;
            if (DIDStore_ContainsPrivateKey(store, did, keyid)) {
                if (DIDStore_LoadPrivateKey_Internal(store, storepass, did, keyid, extendedkey, sizeof(extendedkey)) == -1)
                    return -1;

                rc = encrypt_to_b64(base64, password, extendedkey, sizeof(extendedkey));
                memset(extendedkey, 0, sizeof(extendedkey));
                if (rc < 0) {
                    DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt password failed.");
                    return -1;
                }

                CHECK_TO_MSG(DIDJG_WriteStartObject(gen),
                        DIDERR_OUT_OF_MEMORY, "Start 'privatekey' failed.");
                idstring = DIDURL_ToString(keyid, _idstring, sizeof(_idstring), false);
                CHECK_TO_MSG(DIDJG_WriteStringField(gen, "id", idstring),
                        DIDERR_OUT_OF_MEMORY, "Write 'id' failed.");
                CHECK_TO_MSG(DIDJG_WriteStringField(gen, "privatekey", (char*)base64),
                        DIDERR_OUT_OF_MEMORY, "Write 'key' failed.");
                CHECK_TO_MSG(DIDJG_WriteEndObject(gen),
                        DIDERR_OUT_OF_MEMORY, "End 'privatekey' failed.");

                CHECK_TO_MSG(sha256_digest_update(digest, 2, idstring, strlen(idstring), base64, strlen(base64)),
                        DIDERR_CRYPTO_ERROR, "Update digest with privatekey failed.");
            }
        }

        CHECK_TO_MSG(DIDJG_WriteEndArray(gen),
                DIDERR_OUT_OF_MEMORY, "End 'privatekey' array failed.");
    }

    return 0;
}
//checked
static int export_init(JsonGenerator *gen, const char *password, Sha256_Digest *digest)
{
    assert(gen);
    assert(digest);

    CHECK_TO_MSG(sha256_digest_init(digest),
            DIDERR_CRYPTO_ERROR, "Init sha256 digest failed.");
    CHECK_TO_MSG(sha256_digest_update(digest, 1, password, strlen(password)),
            DIDERR_CRYPTO_ERROR, "Sha256 password failed.");
    CHECK_TO_MSG(DIDJG_WriteStartObject(gen),
            DIDERR_OUT_OF_MEMORY, "Write object failed.");

    return 0;
}
//checked
static int export_final(JsonGenerator *gen, Sha256_Digest *digest)
{
    char base64[512];
    uint8_t final_digest[SHA256_BYTES];
    ssize_t size;

    assert(gen);
    assert(digest);

    size = sha256_digest_final(digest, final_digest);
    if (size < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Final sha256 digest failed.");
        return -1;
    }

    CHECK_TO_MSG(b64_url_encode(base64, final_digest, size),
            DIDERR_CRYPTO_ERROR, "Final sha256 digest failed.");
    CHECK_TO_MSG(DIDJG_WriteStringField(gen, "fingerprint", base64),
            DIDERR_OUT_OF_MEMORY, "Write 'fingerprint' failed.");
    CHECK_TO_MSG(DIDJG_WriteEndObject(gen),
            DIDERR_OUT_OF_MEMORY, "End export object failed.");

    return 0;
}
//checked
static int exportdid_internal(JsonGenerator *gen, DIDStore *store, const char * storepass,
        DID *did, const char *password)
{
    Sha256_Digest digest;
    DIDDocument *doc;
    int rc = -1;

    assert(gen);
    assert(did);

    doc = DIDStore_LoadDID(store, did);
    if (!doc) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Export DID failed, not exist.");
        return rc;
    }

    if (export_init(gen, password, &digest) < 0 ||
            export_type(gen, &digest) < 0 ||
            export_id(gen, did, &digest) < 0 ||
            export_document(gen, doc, &digest) < 0 ||
            export_creds(gen, store, did, &digest) < 0 ||
            export_privatekey(gen, store, storepass, password, doc, &digest) < 0 ||
            export_created(gen, &digest) < 0 ||
            export_final(gen, &digest) < 0)
        goto errorExit;

    rc = 0;

errorExit:
    sha256_digest_cleanup(&digest);

    if (doc)
        DIDDocument_Destroy(doc);

    return rc;
}
//checked
static int check_file(const char *file)
{
    char *path;

    assert(file && *file);

    if (test_path(file) > 0)
        delete_file(file);

    path = alloca(strlen(file) + 1);
    strcpy(path, file);

    char *pos = last_strstr(path, PATH_SEP);
    if (!pos) {
        DIDError_Set(DIDERR_IO_ERROR, "Invalid file[%s] path.", file);
        return -1;
    }

    *pos = 0;
    if (mkdirs(path, S_IRWXU) == -1) {
        DIDError_Set(DIDERR_IO_ERROR, "Create the directory failed.");
        return -1;
    }
    strncpy(path, PATH_SEP, strlen(PATH_SEP));
    return 0;
}

int DIDStore_ExportDID(DIDStore *store, const char *storepass, DID *did,
        const char *file, const char *password)
{
    JsonGenerator g, *gen;
    const char *data;
    int rc;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to export did.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!did, "Please specify did to be exported.", -1);
    CHECK_ARG(!file || !*file, "Please provide file to export did.", -1);
    CHECK_ARG(!password || !*password, "Invalid password.", -1);

    //check file
    if (check_file(file) < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid file[%s].", file);
        return -1;
    }

    //generate did export string
    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator for exporting did initialize failed.");
        return -1;;
    }

    if (exportdid_internal(gen, store, storepass, did, password) < 0) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Serialize exporting did to json failed.");
        DIDJG_Destroy(gen);
        return -1;
    }

    data = DIDJG_Finish(gen);
    rc = store_file(file, data);
    free((void*)data);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "write exporting did string into file failed.");
        return -1;
    }

    return 0;

    DIDERROR_FINALIZE();
}
//checked
static int import_type(json_t *json, Sha256_Digest *digest)
{
    json_t *item;

    assert(json);
    assert(digest);

    item = json_object_get(json, "type");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing export did type.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid export did type.");
        return -1;
    }

    if (strcmp(json_string_value(item), DID_EXPORT)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid export data, unknown type.");
        return -1;
    }

    CHECK_TO_MSG(sha256_digest_update(digest, 1, json_string_value(item), strlen(json_string_value(item))),
            DIDERR_CRYPTO_ERROR, "Sha256 'type' failed.");

    return 0;
}

static DID *import_id(json_t *json, Sha256_Digest *digest)
{
    json_t *item;

    assert(json);
    assert(digest);

    item = json_object_get(json, "id");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing export did.");
        return NULL;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid export did.");
        return NULL;
    }

    if (sha256_digest_update(digest, 1, json_string_value(item), strlen(json_string_value(item))) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Sha256 'id' failed.");
        return NULL;
    }

    return DID_FromString(json_string_value(item));
}

static int import_created(json_t *json, Sha256_Digest *digest)
{
    json_t *item;

    assert(json);
    assert(digest);

    item = json_object_get(json, "created");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing created time.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid created time.");
        return -1;
    }

    if (sha256_digest_update(digest, 1, json_string_value(item), strlen(json_string_value(item))) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Sha256 'created' failed.");
        return -1;
    }

    return 0;
}

static DIDDocument *import_document(json_t *json, DID *did, Sha256_Digest *digest)
{
    json_t *item, *field;
    DIDDocument *doc = NULL;
    const char *docstring = NULL, *metastring = NULL;
    int rc;

    assert(json);
    assert(did);
    assert(digest);

    item = json_object_get(json, "document");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing created time.");
        return NULL;
    }
    if (!json_is_object(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'document'.");
        return NULL;
    }

    field = json_object_get(item, "content");
    if (!field) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing document 'content'.");
        return NULL;
    }
    if (!json_is_object(field)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid document 'content'.");
        return NULL;
    }

    doc = DIDDocument_FromJson_Internal(field);
    if (!doc)
        return NULL;

    if (!DID_Equals(&doc->did, did) || !DIDDocument_IsGenuine(doc)) {
        DIDError_Set(DIDERR_NOT_GENUINE, "Invalid DID document in the export data.");
        goto errorExit;
    }

    docstring = DIDDocument_ToJson(doc, true);
    if (!docstring)
        goto errorExit;

    field = json_object_get(item, "metadata");
    if (!field) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'metadata'.");
        goto errorExit;
    }
    if (!json_is_object(field)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'metadata'.");
        goto errorExit;
    }

    if (DIDMetadata_FromJson_Internal(&doc->metadata, field) < 0)
        goto errorExit;

    memcpy(&doc->did.metadata, &doc->metadata, sizeof(DIDMetadata));
    metastring = DIDMetadata_ToJson(&doc->metadata);
    if (!metastring)
        goto errorExit;

    rc = sha256_digest_update(digest, 2, docstring, strlen(docstring), metastring, strlen(metastring));
    free((void*)docstring);
    free((void*)metastring);
    if (rc < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Sha256 'document' failed.");
        DIDDocument_Destroy(doc);
        return NULL;
    }

    return doc;

errorExit:
    if (doc)
        DIDDocument_Destroy(doc);
    if (docstring)
        free((void*)docstring);
    if (metastring)
        free((void*)metastring);

    return NULL;
}

static int import_creds_count(json_t *json)
{
    json_t *item;

    assert(json);

    item = json_object_get(json, "credential");
    if (!item)
        return 0;

    if (!json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid credential.");
        return -1;
    }

    return json_array_size(item);
}

static ssize_t import_creds(json_t *json, DID *did, Credential **creds, size_t size,
        Sha256_Digest *digest)
{
    json_t *item, *field, *child_field;
    const char *metastring, *credstring;
    int count;
    int i, rc;

    assert(json);
    assert(creds);
    assert(size > 0);

    item = json_object_get(json, "credential");
    if (!item)
        return 0;

    if (!json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Unknown 'credential'.");
        return -1;
    }

    count = json_array_size(item);
    if (count == 0 || count > (int)size) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'credential'.");
        return -1;
    }

    for (i = 0; i < count; i++) {
        field = json_array_get(item, i);
        child_field = json_object_get(field, "content");
        if (!child_field) {
            DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing credential 'content'.");
            goto errorExit;
        }
        if (!json_is_object(child_field)) {
            DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid credential 'content'.");
            goto errorExit;
        }

        Credential *cred = Parse_Credential(child_field, did);
        if (!cred)
            goto errorExit;

        creds[i] = cred;
        credstring = Credential_ToJson(cred, true);
        if (!credstring)
            goto errorExit;

        rc = sha256_digest_update(digest, 1, credstring, strlen(credstring));
        free((void*)credstring);
        if (rc < 0)
            goto errorExit;

        child_field = json_object_get(field, "metadata");
        if (child_field) {
            if (!json_is_object(child_field)) {
                DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'metadata'.");
                goto errorExit;
            }
            if (CredentialMetadata_FromJson_Internal(&cred->metadata, child_field) < 0)
                goto errorExit;

            metastring = CredentialMetadata_ToJson(&cred->metadata);
            if (!metastring)
                goto errorExit;

            rc = sha256_digest_update(digest, 1, metastring, strlen(metastring));
            free((void*)metastring);
            if (rc < 0) {
                DIDError_Set(DIDERR_CRYPTO_ERROR, "Update sha256 digest failed.");
                goto errorExit;
            }
        }
    }

    return i;

errorExit:
    if (i > 0) {
        for (int j = 0; j < i + 1; j++)
            Credential_Destroy(creds[j]);
    }

    return -1;
}

static ssize_t import_privatekey_count(json_t *json)
{
    json_t *item;

    assert(json);

    item = json_object_get(json, "privatekey");
    if (!item)
        return 0;

    if (!json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'privatekey'.");
        return -1;
    }

    return json_array_size(item);
}

static ssize_t import_privatekey(json_t *json, const char *storepass, const char *password,
       DID *did, Prvkey_Export *prvs, size_t size, Sha256_Digest *digest)
{
    json_t *item, *field, *id_field, *key_field;
    size_t count, keysize, i;
    uint8_t binkey[EXTENDEDKEY_BYTES];
    char privatekey[512];

    assert(json);
    assert(storepass && *storepass);
    assert(password && *password);
    assert(did);
    assert(prvs);
    assert(size > 0);
    assert(digest);

    item = json_object_get(json, "privatekey");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'privatekey'.");
        return -1;
    }
    if (!json_is_array(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'privatekey' array.");
        return -1;
    }

    count = json_array_size(item);
    if (count == 0) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'privatekey' array.");
        return -1;
    }
    if (count > size) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Please give larger buffer for private keys.");
        return -1;
    }

    for (i = 0; i < count; i++) {
        field = json_array_get(item, i);
        if (!field) {
            DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'privatekey' item.");
            return -1;
        }
        if (!json_is_object(field)) {
            DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'privatekey'.");
            return -1;
        }
        id_field = json_object_get(field, "id");
        if (!id_field) {
            DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'id' in 'privatekey' failed.");
            return -1;
        }
        if (!json_is_string(id_field)) {
            DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'id' in 'privatekey' failed.");
            return -1;
        }

        DIDURL *id = DIDURL_FromString(json_string_value(id_field), did);
        if (!id)
            return -1;

        DIDURL_Copy(&prvs[i].keyid, id);
        DIDURL_Destroy(id);

        key_field = json_object_get(field, "privatekey");
        if (!key_field) {
            DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'key' in 'privatekey'.");
            return -1;
        }
        if (!json_is_string(key_field)) {
            DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'key' in 'privatekey'.");
            return -1;
        }

        keysize = decrypt_from_b64(binkey, password, json_string_value(key_field));
        if (keysize < 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Decrypt privatekey failed.");
            return -1;
        }

        keysize = encrypt_to_b64(privatekey, storepass, binkey, keysize);
        memset(binkey, 0, sizeof(binkey));
        if (keysize < 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt privatekey failed.");
            return -1;
        }
        memcpy(prvs[i].key, privatekey, keysize);

        if (sha256_digest_update(digest, 2, json_string_value(id_field), strlen(json_string_value(id_field)),
                    json_string_value(key_field), strlen(json_string_value(key_field))) < 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Sha256 'key' in 'privatekey' failed.");
            return -1;
        }
    }
    return (ssize_t)i;
}

static int import_fingerprint(json_t *json, Sha256_Digest *digest)
{
    json_t *item;
    uint8_t final_digest[SHA256_BYTES];
    char base64[512];
    ssize_t size;

    assert(json);
    assert(digest);

    item = json_object_get(json, "fingerprint");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'fingerprint'.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'fingerprint'.");
        return -1;
    }

    size = sha256_digest_final(digest, final_digest);
    if (size < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Final sha256 digest failed.");
        return -1;
    }

    if (b64_url_encode(base64, final_digest, size) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt digest failed.");
        return -1;
    }
    if (strcmp(base64, json_string_value(item))) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid export data, the fingerprint mismatch.");
        return -1;
    }

    return 0;
}

static int import_init(const char *password, Sha256_Digest *digest)
{
    CHECK_TO_MSG(sha256_digest_init(digest),
            DIDERR_CRYPTO_ERROR, "Init sha256 digest failed.");
    CHECK_TO_MSG(sha256_digest_update(digest, 1, password, strlen(password)),
            DIDERR_CRYPTO_ERROR, "Sha256 password failed.");
    return 0;
}

int DIDStore_ImportDID(DIDStore *store, const char *storepass,
        const char *file, const char *password)
{
    const char *string = NULL;
    json_t *root = NULL;
    json_error_t error;
    Sha256_Digest digest;
    DID *did = NULL;
    DIDDocument *doc = NULL;
    Credential **creds = NULL;
    Prvkey_Export *prvs;
    int rc = -1;
    size_t i;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to import did.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!file || !*file, "Please provide file to import did.", -1);
    CHECK_ARG(!password || !*password, "Please specify password to import.", -1);

    if (test_path(file) != S_IFREG) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid file to import did error.");
        return -1;
    }

    string = load_file(file);
    if (!string) {
        DIDError_Set(DIDERR_IO_ERROR, "Load file [%s] failed.", file);
        return -1;
    }

    root = json_loads(string, JSON_COMPACT, &error);
    free((void*)string);
    if (!root) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Deserialize export file failed, error: %s.", error.text);
        return -1;
    }

    if (import_init(password, &digest) < 0)
        goto errorExit;

    //type
    if (import_type(root, &digest) < 0)
        goto errorExit;

    //id
    did = import_id(root, &digest);
    if (!did)
        goto errorExit;

    //document
    doc = import_document(root, did, &digest);
    if (!doc)
        goto errorExit;

    //credential
    size_t cred_size = import_creds_count(root);
    if (cred_size < 0)
        goto errorExit;
    if (cred_size > 0) {
        creds = (Credential**)alloca(cred_size * sizeof(Credential*));
        cred_size = import_creds(root, did, creds, cred_size, &digest);
        if (cred_size < 0)
            goto errorExit;
    }

    //privatekey
    size_t prv_size = import_privatekey_count(root);
    if (prv_size < 0)
        goto errorExit;
    if (prv_size > 0) {
        prvs = (Prvkey_Export*)alloca(prv_size * sizeof(Prvkey_Export));
        memset(prvs, 0, prv_size * sizeof(Prvkey_Export));
        prv_size = import_privatekey(root, storepass, password, did, prvs, prv_size, &digest);
        if (prv_size < 0)
            goto errorExit;
    }

    //created
    if (import_created(root, &digest) < 0)
        goto errorExit;

    //fingerprint
    if (import_fingerprint(root, &digest) < 0)
        goto errorExit;

    //save all files
    if (DIDStore_StoreDID(store, doc) < 0) {
        DIDError_Set(DIDERR_DIDSTORE_ERROR, "Store document(%s) failed.", DIDSTR(&doc->did));
        goto errorExit;
    }

    for (i = 0; i < cred_size; i++) {
        if (DIDStore_StoreCredential(store, creds[i]) < 0) {
            DIDError_Set(DIDERR_DIDSTORE_ERROR, "Store credential(%s) failed.", DIDURLSTR(&creds[i]->id));
            goto errorExit;
        }
    }

    for (i = 0; i < prv_size; i++) {
        if (DIDStore_StorePrivateKey_Internal(store, &prvs[i].keyid, prvs[i].key) < 0)
            goto errorExit;
    }

    rc = 0;

errorExit:
    if (rc == -1)
        sha256_digest_cleanup(&digest);
    if (root)
        json_decref(root);
    if (did)
        DID_Destroy(did);
    if (doc)
        DIDDocument_Destroy(doc);
    if (creds) {
        for (i = 0; i < cred_size; i++)
            Credential_Destroy(creds[i]);
    }

    return rc;

    DIDERROR_FINALIZE();
}

static int export_mnemonic(JsonGenerator *gen, DIDStore *store, const char *storepass,
        const char *id, const char *password, Sha256_Digest *digest)
{
    char mnemonic[ELA_MAX_MNEMONIC_LEN], encryptedmnemonic[512];
    ssize_t size;

    assert(gen);
    assert(store);
    assert(storepass && *storepass);
    assert(id);
    assert(password && *password);
    assert(digest);

    size = load_mnemonic(store, storepass, id, mnemonic, sizeof(mnemonic));
    if (size < 0)
        return -1;

    if (size > 0) {
        size = encrypt_to_b64(encryptedmnemonic, password, (uint8_t*)mnemonic, size - 1);
        memset(mnemonic, 0, sizeof(mnemonic));
        if (size < 0) {
            DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt password failed.");
            return -1;
        }

        CHECK_TO_MSG(DIDJG_WriteStringField(gen, "mnemonic", encryptedmnemonic),
                DIDERR_OUT_OF_MEMORY, "Write 'mnemonic' failed.");
        CHECK_TO_MSG(sha256_digest_update(digest, 1, encryptedmnemonic, strlen(encryptedmnemonic)),
               DIDERR_CRYPTO_ERROR, "Sha256 'mnemonic' failed.");
    }

    return 0;
}
//checked
static int export_prvkey(JsonGenerator *gen, DIDStore *store, const char *storepass,
        const char *id, const char *password, Sha256_Digest *digest)
{
    uint8_t extendedkey[EXTENDEDKEY_BYTES];
    char encryptedKey[512];
    ssize_t size;

    assert(gen);
    assert(store);
    assert(storepass && *storepass);
    assert(id);
    assert(password && *password);
    assert(digest);

    size = DIDStore_LoadRootIdentityPrvkey(store, storepass, id, extendedkey, sizeof(extendedkey));
    if (size < 0)
        return -1;

    size = encrypt_to_b64(encryptedKey, password, extendedkey, size);
    memset(extendedkey, 0, sizeof(extendedkey));
    if (size < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Encrypt extended privatekey of rootidentity failed.");
        return -1;
    }

    CHECK_TO_MSG(DIDJG_WriteStringField(gen, "privatekey", encryptedKey),
        DIDERR_OUT_OF_MEMORY, "Write 'key' failed.");
    CHECK_TO_MSG(sha256_digest_update(digest, 1, encryptedKey, strlen(encryptedKey)),
        DIDERR_CRYPTO_ERROR, "Sha256 'key' failed.");

    return 0;
}
//checked
static int export_pubkey(JsonGenerator *gen, DIDStore *store, const char *id, Sha256_Digest *digest)
{
    const char *pubKey = NULL;
    int rc = -1;

    assert(gen);
    assert(store);
    assert(id);
    assert(digest);

    pubKey = load_pubkey_file(store, id);
    if (!pubKey)
        return -1;

    CHECK_TO_MSG_ERROREXIT(DIDJG_WriteStringField(gen, "publickey", pubKey),
            DIDERR_OUT_OF_MEMORY, "Write 'publickey' failed.");
    CHECK_TO_MSG_ERROREXIT(sha256_digest_update(digest, 1, pubKey, strlen(pubKey)),
            DIDERR_CRYPTO_ERROR, "Sha256 'publickey' failed.");

    rc = 0;

errorExit:
    if (pubKey)
        free((void*)pubKey);

    return rc;
}

static int export_index(JsonGenerator *gen, DIDStore *store, const char *id, Sha256_Digest *digest)
{
    const char *index;
    int rc = -1;

    assert(gen);
    assert(store);
    assert(id);
    assert(digest);

    index = load_index_string(store, id);
    if (!index)
        return -1;

    CHECK_TO_MSG_ERROREXIT(DIDJG_WriteStringField(gen, "index", index),
            DIDERR_OUT_OF_MEMORY, "Write 'index' failed.");
    CHECK_TO_MSG_ERROREXIT(sha256_digest_update(digest, 1, index, strlen(index)),
            DIDERR_CRYPTO_ERROR, "Sha256 'index' failed.");
    rc = 0;

errorExit:
    free((void*)index);
    return rc;
}
//checked
static int export_defaultId(JsonGenerator *gen, DIDStore *store, const char *id, Sha256_Digest *digest)
{
    const char *defaultid;
    bool isDefault = false;

    assert(gen);
    assert(digest);

    defaultid = DIDStore_GetDefaultRootIdentity(store);
    if (defaultid) {
        if (!strcmp(id, defaultid))
           isDefault = true;
        free((void*)defaultid);
    }

    defaultid = isDefault ? "true" : "false";

    CHECK_TO_MSG(DIDJG_WriteFieldName(gen, "default"),
            DIDERR_OUT_OF_MEMORY, "Write 'default' failed.");
    CHECK_TO_MSG(DIDJG_WriteBoolean(gen, isDefault),
            DIDERR_OUT_OF_MEMORY, "Write 'default' failed.");
    CHECK_TO_MSG(sha256_digest_update(digest, 1, defaultid, strlen(defaultid)),
            DIDERR_CRYPTO_ERROR, "Sha256 'default' failed.");

    return 0;
}
//checked
int DIDStore_ExportRootIdentity(DIDStore *store, const char *storepass,
        const char *id, const char *file, const char *password)
{
    Sha256_Digest digest;
    const char *pubKey = NULL, *data;
    int rc = -1;
    JsonGenerator g, *gen;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to export rootidentity.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!id, "No rootidentity id argument.", -1);
    CHECK_ARG(!file || !*file, "Please provide file to export rootidentity.", -1);
    CHECK_ARG(!password || !*password, "Invalid password.", -1);

    if (check_file(file) < 0) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid file to export rootidentity.");
        return -1;
    }

    gen = DIDJG_Initialize(&g);
    if (!gen) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Json generator for exporting rootidentity initialize failed.");
        goto errorExit;
    }

    if (export_init(gen, password, &digest) < 0 || export_type(gen, &digest) < 0)
        goto errorExit;

    //private extended key
    if (export_mnemonic(gen, store, storepass, id, password, &digest) < 0 ||
            export_prvkey(gen, store, storepass, id, password, &digest) < 0 ||
            export_pubkey(gen, store, id, &digest) < 0 ||
            export_index(gen, store, id, &digest) < 0 ||
            export_defaultId(gen, store, id, &digest) < 0 ||
            export_created(gen, &digest) < 0)
        return -1;

    if (export_final(gen, &digest) < 0)
        goto errorExit;

    data = DIDJG_Finish(gen);
    rc = store_file(file, data);
    free((void*)data);
    if (rc < 0) {
        DIDError_Set(DIDERR_IO_ERROR, "Write exporting did string into file failed.");
        goto errorExit;
    }

    rc = 0;

errorExit:
    if (pubKey)
       free((void*)pubKey);

    return rc;

    DIDERROR_FINALIZE();
}
//checked
static int import_rootidentity_id(json_t *json, DIDStore *store, char *id, size_t size)
{
    json_t *item;
    const char *string;

    assert(json);
    assert(store);
    assert(id);
    assert(size > 0);

    item = json_object_get(json, "publickey");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'publickey'.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'publickey'.");
        return -1;
    }

    string = json_string_value(item);
    if (!string) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "No 'publickey' value.");
        return -1;
    }

    if (md5_hexfrombase58(id, size, string) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Get root identity's id failed.");
        return -1;
    }

    CHECK(store_pubkey_file(store, NULL, id, json_string_value(item)));
    return 0;
}
//checked
static int import_pubkey(DIDStore *store, const char *id, Sha256_Digest *digest)
{
    const char *string;
    int rc = -1;

    assert(store);
    assert(id);
    assert(digest);

    string = load_pubkey_file(store, id);
    if (!string)
        return -1;

    CHECK_TO_MSG_ERROREXIT(sha256_digest_update(digest, 1, string, strlen(string)),
            DIDERR_CRYPTO_ERROR, "Sha256 'publickey' failed.");
    rc = 0;

errorExit:
    free((void*)string);
    return rc;
}
//checked
static int import_prvkey(json_t *json, DIDStore *store, const char *storepass,
        const char *id, Sha256_Digest *digest, const char *password)
{
    json_t *item;
    uint8_t extendedkey[EXTENDEDKEY_BYTES];
    ssize_t size;

    assert(json);
    assert(store);
    assert(storepass && *storepass);
    assert(id);
    assert(digest);
    assert(password);

    item = json_object_get(json, "privatekey");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'privatekey'.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'privatekey'.");
        return -1;
    }
    memset(extendedkey, 0, sizeof(extendedkey));
    size = decrypt_from_b64(extendedkey, password, json_string_value(item));
    if (size < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decrypt 'privatekey' failed.");
        return -1;
    }

    CHECK(store_extendedprvkey(store, storepass, id, extendedkey, size));
    memset(extendedkey, 0, sizeof(extendedkey));
    CHECK_TO_MSG(sha256_digest_update(digest, 1, json_string_value(item), strlen(json_string_value(item))),
            DIDERR_CRYPTO_ERROR, "Sha256 'privatekey' failed.");
    return 0;
}
//checked
static int import_mnemonic(json_t *json, DIDStore *store, const char *storepass,
       const char *id, Sha256_Digest *digest, const char *password)
{
    json_t *item;
    uint8_t mnemonic[ELA_MAX_MNEMONIC_LEN];
    ssize_t size;

    assert(json);
    assert(store);
    assert(storepass && *storepass);
    assert(id);
    assert(digest);
    assert(password);

    item = json_object_get(json, "mnemonic");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'mnemonic'.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'mnemonic'.");
        return -1;
    }

    size = decrypt_from_b64(mnemonic, password, json_string_value(item));
    if (size < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Decrypt mnemonic failed.");
        return -1;
    }

    CHECK(store_mnemonic(store, storepass, id, mnemonic, size));
    CHECK_TO_MSG(sha256_digest_update(digest, 1, json_string_value(item), strlen(json_string_value(item))),
            DIDERR_CRYPTO_ERROR, "Sha256 'mnemonic' failed.");
    return 0;
}
//checked
static int import_index(json_t *json, DIDStore *store, const char *id, Sha256_Digest *digest)
{
    json_t *item;

    assert(json);
    assert(store);
    assert(id);
    assert(digest);

    item = json_object_get(json, "index");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'index'.");
        return -1;
    }
    if (!json_is_string(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'index'.");
        return -1;
    }
    CHECK(store_index_string(store, NULL, id, json_string_value(item)));
    CHECK_TO_MSG(sha256_digest_update(digest, 1, json_string_value(item), strlen(json_string_value(item))),
            DIDERR_CRYPTO_ERROR, "Sha256 'index' failed.");
    return 0;
}
//checked
static int import_defaultId(json_t *json, DIDStore *store, const char *id,
        bool *isDefault, Sha256_Digest *digest)
{
    json_t *item;
    const char *data;

    assert(json);
    assert(store);
    assert(id);
    assert(digest);

    item = json_object_get(json, "default");
    if (!item) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Missing 'default'.");
        return -1;
    }
    if (!json_is_boolean(item)) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Invalid 'default'.");
        return -1;
    }

    *isDefault = json_is_true(item) ? true : false;
    data = *isDefault ? "true" : "false";
    CHECK_TO_MSG(sha256_digest_update(digest, 1, data, strlen(data)),
            DIDERR_CRYPTO_ERROR, "Sha256 'default' failed.");
    return 0;
}
//checked
int DIDStore_ImportRootIdentity(DIDStore *store, const char *storepass,
        const char *file, const char *password)
{
    json_t *root = NULL;
    json_error_t error;
    const char *string = NULL;
    char fingerprint[64] = {0};
    char id[MAX_ID_LEN] = {0}, path[PATH_MAX];
    Sha256_Digest digest;
    bool isDefault, toDelete = true;
    int rc = -1;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to import rootidentity.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!file || !*file, "Please provide file to import rootidentity.", -1);
    CHECK_ARG(!password || !*password, "Invalid password.", -1);

    if (test_path(file) != S_IFREG) {
        DIDError_Set(DIDERR_INVALID_ARGS, "Invalid file to import rootidentity.");
        return -1;
    }

    string = load_file(file);
    if (!string) {
        DIDError_Set(DIDERR_IO_ERROR, "Load file[%s] failed.", file);
        return -1;
    }

    root = json_loads(string, JSON_COMPACT, &error);
    free((void*)string);
    if (!root) {
        DIDError_Set(DIDERR_OUT_OF_MEMORY, "Deserialize rootidentity failed, error: %s.", error.text);
        return -1;
    }

    if (import_init(password, &digest) < 0 || import_type(root, &digest) < 0)
        goto errorExit;

    if (import_rootidentity_id(root, store, id, sizeof(id)) < 0)
        goto errorExit;

    if (import_mnemonic(root, store, storepass, id, &digest, password) < 0 ||
            import_prvkey(root, store, storepass, id, &digest, password) < 0 ||
            import_pubkey(store, id, &digest) < 0 ||
            import_index(root, store, id, &digest) < 0 ||
            import_defaultId(root, store, id, &isDefault, &digest) < 0 ||
            import_created(root, &digest) < 0)
        goto errorExit;

    if (import_fingerprint(root, &digest) < 0)
        goto errorExit;

    if (calc_fingerprint(fingerprint, sizeof(fingerprint), storepass) < 0) {
        DIDError_Set(DIDERR_CRYPTO_ERROR, "Calculate fingerprint failed.");
        goto errorExit;
    }

    if (StoreMetadata_SetFingerPrint(&store->metadata, fingerprint) < 0)
        goto errorExit;

    if (isDefault && StoreMetadata_SetDefaultRootIdentity(&store->metadata, id) < 0)
        goto errorExit;

    if (store_storemetadata(store, NULL, &store->metadata) < 0)
        goto errorExit;

    toDelete = false;
    rc = 0;

errorExit:
    if (root)
       json_decref(root);
    if (*id && toDelete) {
        get_dir(path, 0, 4, store->root, DATA_DIR, ROOTS_DIR, id);
        delete_file(path);
    }
    return rc;

    DIDERROR_FINALIZE();
}

static zip_t *create_zip(const char *file)
{
    int err;
    zip_t *zip;

    assert(file && *file);

    if ((zip = zip_open(file, ZIP_CREATE | ZIP_TRUNCATE, &err)) == NULL) {
        zip_error_t error;
        zip_error_init_with_code(&error, err);
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Can't open zip archive '%s': %s", file, zip_error_strerror(&error));
        zip_error_fini(&error);
    }

    return zip;
}
//checked
static int did_to_zip(DID *did, void *context)
{
    DID_Export *export = (DID_Export*)context;
    char tmpfile[PATH_MAX];

    if (!did)
        return 0;

    sprintf(tmpfile, "%s%s%s.json", export->tmpdir, PATH_SEP, did->idstring);
    delete_file(tmpfile);
    if (DIDStore_ExportDID(export->store, export->storepass, did, tmpfile, export->password) < 0)
       return -1;

    zip_source_t *did_source = zip_source_file(export->zip, tmpfile, 0, 0);

    if (!did_source) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Get source file failed.");
        return -1;
    }

    if (zip_file_add(export->zip, did->idstring, did_source, 0) < 0) {
        zip_source_free(did_source);
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Add source file failed.");
        return -1;
    }

    return 0;
}
//checked
static int exportdid_to_zip(DIDStore *store, const char *storepass, zip_t *zip,
        const char *password, const char *tmpdir)
{
    DID_Export export;

    assert(store);
    assert(storepass && *storepass);
    assert(zip);
    assert(password && *password);

    export.store = store;
    export.storepass = storepass;
    export.password = password;
    export.zip = zip;
    export.tmpdir = tmpdir;

    return DIDStore_ListDIDs(store, 0, did_to_zip, (void*)&export);
}

static int rootidentity_to_zip(RootIdentity *rootidentity, void *context)
{
    RootIdentity_Export *export = (RootIdentity_Export*)context;

    char tmpfile[PATH_MAX], path[PATH_MAX];
    zip_source_t *prv_source;

    if (!rootidentity)
        return 0;

    sprintf(tmpfile, "%s%s%s.json", export->tmpdir, PATH_SEP, rootidentity->id);
    delete_file(tmpfile);
    if (DIDStore_ExportRootIdentity(export->store, export->storepass, rootidentity->id, tmpfile, export->password) < 0)
        return -1;

    prv_source = zip_source_file(export->zip, tmpfile, 0, 0);
    if (!prv_source) {
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Get source file failed.");
        return -1;
    }

    sprintf(path, "rootIdentity-%s", rootidentity->id);
    if (zip_file_add(export->zip, path, prv_source, 0) < 0) {
        zip_source_free(prv_source);
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Add source file failed.");
        return -1;
    }

    return 0;
}

static int exportidentity_to_zip(DIDStore *store, const char *storepass, zip_t *zip,
        const char *password, const char *tmpdir)
{
    RootIdentity_Export export;

    assert(store);
    assert(storepass && *storepass);
    assert(zip);
    assert(password && *password);

    export.store = store;
    export.storepass = storepass;
    export.password = password;
    export.zip = zip;
    export.tmpdir = tmpdir;

    return DIDStore_ListRootIdentities(store, rootidentity_to_zip, (void*)&export);
}

int DIDStore_ExportStore(DIDStore *store, const char *storepass,
        const char *zipfile, const char *password)
{
    zip_t *zip = NULL;
    char tmpdir[PATH_MAX];
    int rc = -1;

    DIDERROR_INITIALIZE();

    CHECK_ARG(!store, "No store to export store.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!zipfile || !*zipfile, "Please provide zipfile to export.", -1);
    CHECK_ARG(!password || !*password, "Invalid password.", -1);

    zip = create_zip(zipfile);
    if (!zip) {
        DIDError_Set(DIDERR_IO_ERROR, "Create zip file failed.");
        return -1;
    }

    //create temp dir
#if defined(_WIN32) || defined(_WIN64)
    const char *tmp = getenv("TEMP");
    if (!tmp) {
        DIDError_Set(DIDERR_NOT_EXISTS, "Temp file doesn't exist.");
        return -1;
    }
#else
    const char *tmp = getenv("TMPDIR");
    if (!tmp) {
        if (access("/tmp", 0) == 0) {
            tmp = "/tmp";
        } else {
            DIDError_Set(DIDERR_NOT_EXISTS, "Temp file doesn't exist.");
            return -1;
        }
    }
#endif

    snprintf(tmpdir, sizeof(tmpdir), "%s%sdidexport", tmp, PATH_SEP);
    mkdirs(tmpdir, S_IRWXU);

    if (exportidentity_to_zip(store, storepass, zip, password, tmpdir) < 0 ||
            exportdid_to_zip(store, storepass, zip, password, tmpdir) < 0 )
        goto errorExit;

    rc = 0;

errorExit:
    if (zip)
        zip_close(zip);

    delete_file(tmpdir);
    return rc;

    DIDERROR_FINALIZE();
}

static zip_t *open_zip(const char *file)
{
    int err;
    zip_t *zip;

    assert(file && *file);

    if ((zip = zip_open(file, ZIP_RDONLY, &err)) == NULL) {
        zip_error_t error;
        zip_error_init_with_code(&error, err);
        DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Can't open zip archive '%s': %s", file, zip_error_strerror(&error));
        zip_error_fini(&error);
    }

    return zip;
}

int DIDStore_ImportStore(DIDStore *store, const char *storepass, const char *zipfile,
        const char *password)
{
    zip_t *zip = NULL;
    zip_int64_t count, i;
    zip_stat_t stat;
    int rc = -1;

    DIDERROR_INITIALIZE();

#if defined(_WIN32) || defined(_WIN64)
    char filename[] = "\\tmp\\storeexport.json";
#else
    char filename[] = "/tmp/storeexport.json";
#endif

    CHECK_ARG(!store, "No store to import store.", -1);
    CHECK_PASSWORD(storepass, -1);
    CHECK_ARG(!zipfile || !*zipfile, "Please provide zipfile to import.", -1);
    CHECK_ARG(!password || !*password, "Invalid password.", -1);

    zip = open_zip(zipfile);
    if (!zip)
        return -1;

    count = zip_get_num_entries(zip, ZIP_FL_UNCHANGED);
    if (count == 0)
        goto errorExit;

    for (i = 0; i < count; i++) {
        zip_int64_t readed;
        int code;
        zip_stat_init(&stat);
        if (zip_stat_index(zip, i, ZIP_FL_UNCHANGED, &stat) < 0) {
            DIDError_Set(DIDERR_IO_ERROR, "Obtain information about index %d file.", i);
            goto errorExit;
        }

        zip_file_t *zip_file = zip_fopen_index(zip, i, ZIP_FL_UNCHANGED);
        if (!zip_file) {
            DIDError_Set(DIDERR_IO_ERROR, "Open index %d file.", i);
            goto errorExit;
        }

        char *buffer = (char*)malloc(stat.size + 1);
        if (!buffer) {
            DIDError_Set(DIDERR_OUT_OF_MEMORY, "Malloc buffer for index %d file failed.", i);
            zip_fclose(zip_file);
            goto errorExit;
        }

        readed = zip_fread(zip_file, buffer, stat.size);
        zip_fclose(zip_file);
        if (readed < 0) {
            DIDError_Set(DIDERR_IO_ERROR, "Read index %d file failed.", i);
            goto errorExit;
        }
        buffer[stat.size] = 0;

        delete_file(filename);
        if (check_file(filename) < 0) {
            DIDError_Set(DIDERR_IO_ERROR, "Invalid file[%s].", filename);
            goto errorExit;
        }

        code = store_file(filename, buffer);
        free(buffer);
        if (code < 0) {
            DIDError_Set(DIDERR_IO_ERROR, "Store '%s' file failed.", filename);
            delete_file(filename);
            goto errorExit;
        }

        if (!strncmp(stat.name, "rootIdentity-", strlen("rootIdentity-"))) {
            code = DIDStore_ImportRootIdentity(store, storepass, filename, password);
            delete_file(filename);
            if (code < 0) {
                DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Import rootidentity(%s) failed.", filename);
                goto errorExit;
            }
        } else {
            DID * did = DID_New(stat.name);
            if (!did)
                goto errorExit;

            code = DIDStore_ImportDID(store, storepass, filename, password);
            delete_file(filename);
            DID_Destroy(did);
            if (code < 0) {
                DIDError_Set(DIDERR_MALFORMED_EXPORTDID, "Import did(%s) failed.", filename);
                goto errorExit;
            }
        }
    }
    rc = 0;

errorExit:
    if (zip)
        zip_close(zip);

    return rc;

    DIDERROR_FINALIZE();
}
