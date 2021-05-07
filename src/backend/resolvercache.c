/*
 * Copyright (c) 2019 - 2021 Elastos Foundation
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

#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <assert.h>

#include "ela_did.h"
#include "diderror.h"
#include "common.h"
#include "did.h"
#include "resolvercache.h"
#include "credentialbiography.h"

static char rootpath[PATH_MAX] = {0};

int ResolverCache_SetCacheDir(const char *root)
{
    int rc;

    assert(root && *root);

    if (strlen(root) >= sizeof(rootpath))
        return -1;

    rc = mkdirs(root, S_IRWXU);
    strcpy(rootpath, root);
    return rc;
}

const char *ResolverCache_GetCacheDir(void)
{
    if (!*rootpath)
        return NULL;

    return rootpath;
}

int ResolverCache_Reset(void)
{
    if (!*rootpath)
        return 0;

    delete_file(rootpath);
    return 0;
}

int ResolverCache_LoadDID(ResolveResult *result, DID *did, long ttl)
{
    char path[PATH_MAX];
    const char *data;
    struct stat s;
    time_t curtime;
    json_t *root;
    json_error_t error;
    int rc;

    assert(result);
    assert(did);
    assert(ttl >= 0);

    if (get_file(path, 0, 2, rootpath, did->idstring) == -1)
        return -1;

    //check the last modify time
    if (stat(path, &s) < 0)
        return -1;

    time(&curtime);
    if (curtime - s.st_mtime > ttl)
        return -1;

    data = load_file(path);
    if (!data)
        return -1;

    root = json_loads(data, JSON_COMPACT, &error);
    free((void*)data);
    if (!root)
        return -1;

    rc = ResolveResult_FromJson(result, root, false);
    json_decref(root);
    return rc;
}

int ResolveCache_StoreDID(ResolveResult *result, DID *did)
{
    char path[PATH_MAX];
    const char *data;
    int rc;

    assert(result);
    assert(did);

    if (get_file(path, 1, 2, rootpath, did->idstring) == -1)
        return -1;

    data = ResolveResult_ToJson(result);
    if (!data)
        return -1;

    rc = store_file(path, data);
    free((void*)data);
    return rc;
}

void ResolveCache_InvalidateDID(DID *did)
{
    char path[PATH_MAX];

    assert(did);

    if (get_file(path, 0, 2, rootpath, did->idstring) == 0)
        delete_file(path);
}

CredentialBiography *ResolverCache_LoadCredential(DIDURL *id, DID *issuer, long ttl)
{
    CredentialBiography *biography;
    CredentialTransaction *tx;
    char path[PATH_MAX], buffer[ELA_MAX_DIDURL_LEN];
    DID *signer;
    const char *data;
    struct stat s;
    time_t curtime;
    json_t *root;
    json_error_t error;
    int size;

    assert(id);
    assert(ttl >= 0);

    size = snprintf(buffer, ELA_MAX_DIDURL_LEN, "%s_%s", id->did.idstring, id->fragment);
    if (size < 0 || size > sizeof(buffer))
        return NULL;

    if (get_file(path, 0, 2, rootpath, buffer) == -1)
        return NULL;

    //check the lasted modify time
    if (stat(path, &s) < 0)
        return NULL;

    time(&curtime);
    if (curtime - s.st_mtime > ttl)
        return NULL;

    data = load_file(path);
    if (!data)
        return NULL;

    root = json_loads(data, JSON_COMPACT, &error);
    free((void*)data);
    if (!root)
        return NULL;

    biography = CredentialBiography_FromJson(root);
    if (!biography)
        goto errorExit;

    for (size = 0; size < biography->txs.size; size++) {
        tx = &biography->txs.txs[size];
        if (!strcmp("revoke", tx->request.header.op)) {
            signer = &tx->request.proof.verificationMethod.did;
            if (!DID_Equals(&id->did, signer) && (issuer && !DID_Equals(issuer, signer))) {
                CredentialBiography_Destroy(biography);
                biography = NULL;
                goto errorExit;
            }
        }
    }

errorExit:
    json_decref(root);
    return biography;
}

int ResolveCache_StoreCredential(CredentialBiography *biography, DIDURL *id)
{
    char path[PATH_MAX], buffer[ELA_MAX_DIDURL_LEN];
    const char *data;
    int rc, size;

    assert(biography);
    assert(id);

    size = snprintf(buffer, ELA_MAX_DIDURL_LEN, "%s_%s", id->did.idstring, id->fragment);
    if (size < 0 || size > sizeof(buffer))
        return -1;

    if (get_file(path, 1, 2, rootpath, buffer) == -1)
        return -1;

    data = Credentialbiography_ToJson(biography);
    if (!data)
        return -1;

    rc = store_file(path, data);
    free((void*)data);
    return rc;
}

void ResolveCache_InvalidateCredential(DIDURL *id)
{
    char path[PATH_MAX];

    assert(id);

    if (get_file(path, 0, 3, rootpath, id->did.idstring, id->fragment) == 0)
        delete_file(path);
}
