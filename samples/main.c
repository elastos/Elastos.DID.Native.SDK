#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#include <signal.h>
#include <crystal.h>

#include "ela_did.h"
#include "samples.h"

#if defined(_WIN32) || defined(_WIN64)
#define getpid                _getpid
#endif

static int which = 9;

typedef void (*Func)(void);

Func funcs[] = { NULL,
                 InitalizeDid,
                 InitalizeDidurl,
                 IssueCredential,
                 CreatePresentation,
                 ParseJWT,
                 PresentationInJWT,
                 RestoreFromMnemonic,
                 InitRootIdentity };

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

void signal_handler(int signum)
{
    exit(-1);
}

static void usage(void)
{
    fprintf(stdout, "DID CLI agent\n");
    fprintf(stdout, "Usage agent [OPTION]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "  --initdid            Initailize DID\n");
    fprintf(stdout, "  --didurl             DIDURL sample\n");
    fprintf(stdout, "  --issue              Issue credential\n");
    fprintf(stdout, "  --createvp           Create presentation\n");
    fprintf(stdout, "  --parsejwt           Parse JWT\n");
    fprintf(stdout, "  --vpinjwt            Presentation in JWT\n");
    fprintf(stdout, "  --restore            Restore from mnemonic\n");
    fprintf(stdout, "  --rootidentity       Rootidentity sample\n");
    fprintf(stdout, "  --all                Run all samples\n");
    fprintf(stdout, "  --debug              Wait for debugger to attach\n");
    fprintf(stdout, "\n");
}

int main(int argc, char *argv[])
{
    int wait_for_attach = 0;

    int opt;
    int idx;
    struct option options[] = {
        { "initdid",       no_argument,  NULL,  1  },
        { "didurl",        no_argument,  NULL,  2  },
        { "issue",         no_argument,  NULL,  3  },
        { "createvp",      no_argument,  NULL,  4  },
        { "parsejwt",      no_argument,  NULL,  5  },
        { "vpinjwt",       no_argument,  NULL,  6  },
        { "restore",       no_argument,  NULL,  7  },
        { "rootidentity",  no_argument,  NULL,  8  },
        { "all",           no_argument,  NULL,  9  },
        { "debug",         no_argument,  NULL, 'd' },
        { "help",          no_argument,  NULL, 'h' },
        { NULL,            0,            NULL,  0  }
    };

#ifdef HAVE_SYS_RESOURCE_H
    sys_coredump_set(true);
#endif

    while ((opt = getopt_long(argc, argv, "d:h?", options, &idx)) != -1) {
        switch (opt) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
            which = opt;
            break;

        case 'd':
            wait_for_attach = 1;
            break;

        case 'h':
        case '?':
        default:
            usage();
            exit(-1);
        }
    }

    if (wait_for_attach) {
        printf("Wait for debugger attaching, process id is: %d.\n", getpid());
#ifndef _MSC_VER
        printf("After debugger attached, press any key to continue......");
        getchar();
        printf("Attached, press any key to continue......");
        getchar();
#else
        DebugBreak();
#endif
    }

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
#ifdef HAVE_SIGKILL
    signal(SIGKILL, signal_handler);
#endif
#ifdef HAVE_SIGHUP
    signal(SIGHUP, signal_handler);
#endif

    if (which < 1 || which > 9) {
        printf("error case");
        return 0;
    }

    if (which != 9) {
        funcs[which]();
    } else {
        for (int i = 1; i < 9; i++)
            funcs[i]();
    }

    return 0;
}

