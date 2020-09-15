#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
   #include <crystal.h>
#endif

#include "ela_did.h"

static char *MAINTYPE = "MainNet";
static char *TESTTYPE = "TestNet";
static char *MAINNET = "http://api.elastos.io:20606";
static char *TESTNET = "http://api.elastos.io:21606";

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>

static int sys_coredump_set(bool enable) {
    const struct rlimit rlim = {
        enable ? RLIM_INFINITY : 0,
        enable ? RLIM_INFINITY : 0
    };

    return setrlimit(RLIMIT_CORE, &rlim);
}
#endif

static void usage(void)
{
    fprintf(stdout, "DID Validater\n");
    fprintf(stdout, "Usage agent [OPTION]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  -n, --network=type      The net type to check DID.\n");
    fprintf(stdout, "  -c, --credential=path   The path of file stored credential.\n");
    fprintf(stdout, "  -d, --document=path     The path of file stored document.\n");
    fprintf(stdout, "\n");
}

//free the returned value
static char *load_file(const char *file)
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

int main(int argc, char *argv[])
{
    char *vc_path = NULL, *doc_path = NULL, *url = MAINNET, *nettype = MAINTYPE;
    char cachedir[PATH_MAX];

    int opt;
    int idx;
    struct option options[] = {
        { "network",        optional_argument,   NULL, 'n' },
        { "credential",     optional_argument,   NULL, 'c' },
        { "document",       optional_argument,   NULL, 'd' },
        { "help",           no_argument,         NULL, 'h' },
        { NULL,             0,                   NULL,  0  }
    };

#ifdef HAVE_SYS_RESOURCE_H
    sys_coredump_set(true);
#endif

    while ((opt = getopt_long(argc, argv, "n:c:d:h?", options, &idx)) != -1) {
        switch (opt) {
        case 'n':
            nettype = optarg;
            break;

        case 'c':
            vc_path = optarg;
            break;

        case 'd':
            doc_path = optarg;
            break;

        case 'h':
        case '?':
        default:
            usage();
            exit(-1);
        }
    }

    if (!vc_path && !doc_path) {
        fprintf(stderr, "No document or credential to validated.\n");
        return 0;
    }

    if (!strcmp(nettype, TESTTYPE))
        url = TESTNET;

    sprintf(cachedir, "%s%s", getenv("HOME"), "/.cache.did.elastos");
    if (DIDBackend_InitializeDefault(url, cachedir) < 0) {
        fprintf(stderr, "Initial resolver failed. Error: %s\n", DIDError_GetMessage());
        goto cleanup;
    }

    if (vc_path) {
        const char *data = load_file(vc_path);
        if (!data) {
            fprintf(stderr, "No content in file [%s]\n", vc_path);
            goto cleanup;
        }

        Credential *vc = Credential_FromJson(data, NULL);
        free((void*)data);
        if (!vc) {
            fprintf(stderr, "File content is wrong to credential. Error: %s\n", DIDError_GetMessage());
            goto cleanup;
        }

        bool validate = Credential_IsValid(vc);
        Credential_Destroy(vc);
        if (!validate) {
            fprintf(stdout, "The credential is invalid. Error: %s\n", DIDError_GetMessage());
            goto cleanup;
        } else {
            fprintf(stdout, "The credential is valid. \n");
            goto cleanup;
        }
    }

    if (doc_path) {
        const char *data = load_file(doc_path);
        if (!data) {
            fprintf(stderr, "No content in file [%s]\n", doc_path);
            goto cleanup;
        }

        DIDDocument *doc = DIDDocument_FromJson(data);
        free((void*)data);
        if (!doc) {
            fprintf(stderr, "File content is wrong to document. Error: %s\n", DIDError_GetMessage());
            goto cleanup;
        }

        bool validate = DIDDocument_IsValid(doc);
        DIDDocument_Destroy(doc);
        if (!validate) {
            fprintf(stdout, "The document is invalid. Error: %s\n", DIDError_GetMessage());
            goto cleanup;
        } else {
            fprintf(stdout, "The document is valid. \n");
            goto cleanup;
        }
    }

cleanup:
    return 0;
}

