#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>
#include <crystal.h>
#include <sys/stat.h>
#include <stdarg.h>

#include "constant.h"

const char *walletdir = ".elawallet";
//const char *walletdir = "Projects/did/Elastos.DID.Native.cy/.elawallet";
const char *walletId = "cywallet";
const char *network = "TestNet";
const char *resolver = "http://api.elastos.io:21606";
const char *walletpass = "12345678";

//const char *storepass = "123456";
const char *storepass = "passwd";
const char *passphrase = "";
const char *default_type = "ECDSAsecp256r1";
const char *service_type = "CarrierAddress";

const char *mnemonic = "cloth always junk crash fun exist stumble shift over benefit fun toe";
const char *language = "english";

const char *testdid_string = "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym";
const char *testid_string = "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym#default";
const char *method_specific_string = "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym";
const char *fragment = "default";
const char *compact_idstring = "#default";

#if defined(_WIN32) || defined(_WIN64)
    const char *PATH_STEP = "\\";
#else
    const char *PATH_STEP = "/";
#endif

const char *DATA_DIR = "data";
const char *ROOTS_DIR = "roots";
const char *INDEX_FILE = "index";
const char *MNEMONIC_FILE = "mnemonic";
const char *PRIVATE_FILE = "private";
const char *PUBLIC_FILE = "public";
const char *HDKEY_FILE = "key";
const char *HDPUBKEY_FILE = "key.pub";

const char *IDS_DIR = "ids";
const char *DOCUMENT_FILE = "document";
const char *CREDENTIALS_DIR = "credentials";
const char *CREDENTIAL_FILE = "credential";
const char *PRIVATEKEYS_DIR = "privatekeys";
const char *META_FILE = ".metadata";