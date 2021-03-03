#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <limits.h>
#include <assert.h>

#include "ela_did.h"
#include "constant.h"
#include "did.h"

const char *get_store_path(char* path, const char *dir)
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

const char *get_file_path(char *path, size_t size, int count, ...)
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

char *get_did_path(char *path, char *did, char *type, int version)
{
    char file[128];

    assert(path);
    assert(did);

    strcpy(file, did);
    if (version != 0)
        strcat(file, ".id.");
    if (type)
        strcat(file, type);
    strcat(file, ".json");

    get_testdata_path(path, file, version);
    return path;
}

char *get_credential_path(char *path, char *did, char *vc, char *type, int version)
{
    char file[120];

    assert(path);

    if (version == 0) {
        strcpy(file, vc);
    } else {
        strcpy(file, did);
        strcat(file, ".vc");
    }

    if (type) {
        strcat(file, ".");
        strcat(file, type);
    }

    strcat(file, ".json");

    get_testdata_path(path, file, version);
    return path;
}

char *get_presentation_path(char *path, char *root, char *did, char *vp, char *type, int version)
{
    char file[120];

    assert(path);

    if (version == 0) {
        strcpy(file, vp);
    } else {
        strcpy(file, did);
        strcat(file, ".vp");
    }

    if (type) {
        strcat(file, ".");
        strcat(file, type);
    }

    strcat(file, ".json");

    get_testdata_path(path, file, version);
    return path;
}

char *get_ticket_path(char *path, char *did)
{
    char file[120];

    assert(path);
    assert(did);

    strcpy(file, did);
    strcat(file, ".tt.json");

    get_testdata_path(path, file, 2);
    return path;
}

char *get_privatekey_path(char *path, DIDURL *id, int version)
{
    char file[120];

    assert(path);
    assert(id);

    strcpy(file, id->did.idstring);
    if (version != 0)
        strcat(file, ".id.");
    strcat(file, id->fragment);
    strcat(file, ".sk");

    get_testdata_path(path, file, version);
    return path;
}



