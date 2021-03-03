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

#ifndef __TEST_UTILITY_H__
#define __TEST_UTILITY_H__

#include "ela_did.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *get_store_path(char* path, const char *dir);

const char *get_file_path(char *path, size_t size, int count, ...);

bool file_exist(const char *path);

bool dir_exist(const char *path);

const char *get_did_path(char *path, char *did, char *type, int version);

const char *get_credential_path(char *path, char *did, char *vc, char *type, int version);

const char *get_presentation_path(char *path, char *did, char *vp, char *type, int version);

const char *get_privatekey_path(char *path, DIDURL *id, int version);

const char *get_ticket_path(char *path, char *did);

#ifdef __cplusplus
}
#endif

#endif /* __TEST_UTILITY_H__ */
