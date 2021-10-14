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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_GLOB_H
#include <glob.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_DIRECT_H
#include <io.h>
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <limits.h>
#include <sys/stat.h>

#if defined(_WIN32) || defined(_WIN64)
#include <crystal.h>
#endif

#include "common.h"
#include "did.h"
#include "HDkey.h"
#include "crypto.h"
#include "JsonHelper.h"

#define DID_MAX_LEN      512

const char *get_time_string(char *timestring, size_t len, time_t *p_time)
{
    time_t t;
    struct tm tm;

    if (len < DOC_BUFFER_LEN || !p_time)
        return NULL;

    if (*p_time == 0)
        time(&t);
    else
        t = *p_time;

    gmtime_r(&t, &tm);
    strftime(timestring, 80, "%Y-%m-%dT%H:%M:%SZ", &tm);

    return timestring;
}

int parse_time(time_t *time, const char *string)
{
    struct tm tm;
    char buffer[DOC_BUFFER_LEN];
    char *pos;

    if (!time || !string)
        return -1;

    pos = strchr(string, '.');
    if (pos) {
        size_t len = pos - string;
        if (len > 20)
            return -1;

        strncpy(buffer, string, len);
        buffer[len] = 'Z';
        buffer[len + 1] = 0;
        string = buffer;
    }

    if (!strptime(string, "%Y-%m-%dT%H:%M:%SZ", &tm))
        return -1;

    *time = timegm(&tm);
    return 0;
}

int test_path(const char *path)
{
    struct stat s;

    if (!path || !*path)
        return -1;

    if (stat(path, &s) < 0)
        return -1;

    if (s.st_mode & S_IFDIR)
        return S_IFDIR;
    else if (s.st_mode & S_IFREG)
        return S_IFREG;
    else
        return -1;
}

int list_dir(const char *path, const char *pattern,
        int (*callback)(const char *name, void *context), void *context)
{
    char full_pattern[PATH_MAX];
    size_t len;
    int rc = 0;

    if (!path || !*path || !pattern || !callback)
        return -1;

#if defined(_WIN32) || defined(_WIN64)
    len = snprintf(full_pattern, sizeof(full_pattern), "%s\\%s", path, pattern);
    if (len == sizeof(full_pattern))
        full_pattern[len-1] = 0;

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
    len = snprintf(full_pattern, sizeof(full_pattern), "%s/{.*,%s}", path, pattern);
    if (len == sizeof(full_pattern))
        full_pattern[len-1] = 0;

    glob_t gl;
    size_t pos = strlen(path) + 1;

    memset(&gl, 0, sizeof(gl));
    glob(full_pattern, GLOB_DOOFFS | GLOB_BRACE, NULL, &gl);

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

void delete_file(const char *path);

static int delete_file_helper(const char *path, void *context)
{
    char fullpath[PATH_MAX];
    int len;

    if (!path)
        return 0;

    if (strcmp(path, ".") != 0 && strcmp(path, "..") != 0) {
        len = snprintf(fullpath, sizeof(fullpath), "%s%s%s", (char *)context, PATH_SEP, path);
        if (len < 0 || len > PATH_MAX)
            return -1;

        delete_file(fullpath);
    }

    return 0;
}

void delete_file(const char *path)
{
    int rc;

    if (!path || !*path)
        return;

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
    int rc, i;

    assert(path);
    assert(count > 0);

    *path = 0;
    for (i = 0; i < count; i++) {
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

int get_dir(char* path, bool create, int count, ...)
{
    va_list components;
    int rc;

    if (!path || count <= 0)
        return -1;

    va_start(components, count);
    rc = get_dirv(path, create, count, components);
    va_end(components);

    return rc;
}

int get_file(char *path, bool create, int count, ...)
{
    const char *filename;
    va_list components;
    int rc, i;

    if (!path || count <= 0)
        return -1;

    va_start(components, count);
    rc = get_dirv(path, create, count - 1, components);
    if (rc < 0)
        return -1;

    va_end(components);
    va_start(components, count);
    for (i = 0; i < count - 1; i++)
        va_arg(components, const char *);

    filename = va_arg(components, const char *);
    strcat(path, PATH_SEP);
    strcat(path, filename);

    va_end(components);
    return 0;
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

const char *load_file(const char *path)
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
        free((void*)data);
        close(fd);
        return NULL;
    }

    close(fd);
    return data;
}

static int is_empty_helper(const char *path, void *context)
{
    if (!path || !strcmp(path, ".") || !strcmp(path, "..")) {
        *(int *)context = 0;
        return 0;
    }

    *(int *)context = 1;
    return -1;
}

bool is_empty(const char *path)
{
    int flag = 0;

    if (!path || !*path)
        return false;

    if (list_dir(path, "*", is_empty_helper, &flag) < 0 && flag)
        return false;

    return true;
}

static int mkdir_internal(const char *path, mode_t mode)
{
    struct stat st;
    int rc = 0;

    if (stat(path, &st) != 0) {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            rc = -1;
    } else if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        rc = -1;
    }

    return rc;
}

int mkdirs(const char *path, mode_t mode)
{
    int rc = 0;
    char *pp;
    char *sp;
    char copypath[PATH_MAX];

    strncpy(copypath, path, sizeof(copypath));
    copypath[sizeof(copypath) - 1] = 0;

    pp = copypath;
    while(rc == 0 && (sp = strstr(pp, PATH_SEP)) != 0) {
        if (sp != pp) {
            /* Neither root nor double slash in path */
            *sp = '\0';
            rc = mkdir_internal(copypath, mode);
            strncpy(sp, PATH_SEP, strlen(PATH_SEP));
        }
        pp = sp + strlen(PATH_SEP);
    }

    if (rc == 0)
        rc = mkdir_internal(path, mode);

    return rc;
}

int md5_hex(char *id, size_t size, uint8_t *data, size_t datasize)
{
    uint8_t md[16];
    char step[10];
    size_t len = 0;
    int i;

    assert(id);
    assert(size > 0);
    assert(data);
    assert(datasize > 0);

    md5(md, sizeof(md), data, datasize);
    for (i = 0; i < sizeof(md); i++) {
        sprintf(step, "%02x", md[i]);
        if (len + strlen(step) + 1 > datasize)
            return -1;
        strcat(id, step);
    }

    return 0;
}

int md5_hexfrombase58(char *id, size_t size, const char *base58)
{
    uint8_t binkey[EXTENDEDKEY_BYTES];
    ssize_t len;

    assert(id);
    assert(size > 0);
    assert(base58);

    len = b58_decode(binkey, sizeof(binkey), base58);
    if (len != EXTENDEDKEY_BYTES)
        return -1;

    return md5_hex(id, size, binkey, len);
}

char *last_strstr(const char *haystack, const char *needle)
{
    assert(haystack && needle);

    if (*needle == '\0')
        return (char *)haystack;

    char *result = NULL;
    for (;;) {
        char *p = strstr(haystack, needle);
        if (p == NULL)
            break;
        result = p;
        haystack = p + strlen(needle);
    }

    return result;
}

const char *json_astext(json_t *item)
{
    const char *value;
    char buffer[64];

    assert(item);

    if (json_is_object(item) || json_is_array(item)) {
        value = (char*)JsonHelper_ToString(item);
        if (!value)
            DIDError_Set(DIDERR_MALFORMED_CREDENTIAL, "Serialize credential subject to json failed.");

        return value;
    }

    if (json_is_string(item)) {
        value = json_string_value(item);
    } else if (json_is_false(item)) {
        value = "false";
    } else if (json_is_true(item)) {
        value = "true";
    } else if (json_is_null(item)) {
        value = "null";
    } else if (json_is_integer(item)) {
        snprintf(buffer, sizeof(buffer), "%" JSON_INTEGER_FORMAT, json_integer_value(item));
        value = buffer;
    } else if (json_is_real(item)) {
        snprintf(buffer, sizeof(buffer), "%g", json_real_value(item));
        value = buffer;
    } else {
        value = "";
    }

    return strdup(value);
}

