/*
 * Copyright (c) 2020 Elastos Foundation
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

#ifndef __WINHELPER_H__
#define __WINHELPER_H__

#include <string.h>
#include <time.h>
#include <stdint.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <direct.h>
#include <sys/utime.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t              mode_t;

#define PATH_MAX              256
#define S_ISREG(m)            (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)            (((m) & S_IFMT) == S_IFDIR)

#define S_IRWXU               _S_IREAD | _S_IWRITE
#define S_IRUSR               _S_IREAD
#define S_IWUSR               _S_IWRITE

#define alloca                _alloca
#define utimbuf               _utimbuf
#define utime                 _utime
#define timegm                _mkgmtime
#define rmdir                 _rmdir
#define getcwd                _getcwd
#define strptime              _strptime
#define mkdir(dir, mode)      _mkdir(dir)
#define gmtime_r(a, b)        gmtime_s(b, a)

char *_strptime(const char *buf, const char *fmt, struct tm *tm);

#ifdef __cplusplus
}
#endif

#endif //__WINHELPER_H__