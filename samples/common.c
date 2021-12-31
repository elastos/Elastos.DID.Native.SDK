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

#include "common.h"

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

