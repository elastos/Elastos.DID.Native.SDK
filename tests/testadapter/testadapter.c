#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "common.h"
#include "testadapter.h"

#define DATA_OP "payload = \'%s\'\n"

static const char *header_data = \
"Web3 = require(\"web3\");\n\
web3 = new Web3(\"http://52.80.107.251:1111\");\n\
contract = new web3.eth.Contract([\n\
{\n\
    \"inputs\": [\n\
        {\n\
            \"internalType\": \"string\",\n\
            \"name\": \"data\",\n\
            \"type\": \"string\"\n\
        }\n\
    ],\n\
    \"name\": \"publishDidTransaction\",\n\
    \"outputs\": [],\n\
    \"stateMutability\": \"nonpayable\",\n\
    \"type\": \"function\"\n\
}, {\n\
        \"inputs\": [],\n\
        \"stateMutability\": \"nonpayable\",\n\
        \"type\": \"constructor\"\n\
}, {\n\
        \"inputs\": [],\n\
        \"name\": \"leftGas\",\n\
        \"outputs\": [\n\
            {\n\
                \"internalType\": \"uint256\",\n\
                \"name\": \"\",\n\
                \"type\": \"uint256\"\n\
            }\n\
        ],\n\
        \"stateMutability\": \"view\",\n\
        \"type\": \"function\"\n\
    }\n\
]);\n\
contract.options.address = \"0x8b2324fd40a74843711C9B48BC968A5FAEdd4Ef0\";\n\
acc = web3.eth.accounts.decrypt({\"address\":\"53781e106a2e3378083bdcede1874e5c2a7225f8\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"bc53c1fcd6e31a6392ddc1777157ae961e636c202ed60fb5dda77244c5c4b6ff\",\"cipherparams\":{\"iv\":\"c5d1a7d86d0685aa4542d58c27ae7eb4\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":262144,\"p\":1,\"r\":8,\"salt\":\"409429444dabb5664ba1314c93f0e1d7a1e994a307e7b43d3f6cc95850fbfa9f\"},\"mac\":\"4c37821c90d35118182c2d4a51356186482662bb945f0fcd33d3836749fe59c0\"},\"id\":\"39e7770e-4bc6-42f3-aa6a-c0ae7756b607\",\"version\":3}, \"123\");\n";

static const char *tail_data = \
"cdata = contract.methods.publishDidTransaction(payload).encodeABI();\n\
tx = {data: cdata, to: contract.options.address, from: acc.address, gas: 3000000, gasPrice: \"1000000000000\"};\n\
acc.signTransaction(tx).then((res)=>{\n\
    //console.log(\"coming\");\n\
    stx = res;\n\
    //console.log(stx.rawTransaction);\n\
    web3.eth.sendSignedTransaction(stx.rawTransaction)/*.then(console.log)*/\n\
});";

static char *get_current_path(char* path)
{
    assert(path);

    if(!getcwd(path, PATH_MAX)) {
        printf("\nCan't get current dir.");
        return NULL;
    }

    return path;
}

static const char *generate_ethdata(const char *payload)
{
    size_t len;
    char *write, *buffer;

    assert(payload);
    buffer = (char*)alloca(strlen(payload) + 100);
    if (!buffer)
        return NULL;

    sprintf(buffer, DATA_OP, payload);

    len = strlen(header_data) + strlen(payload) + strlen(tail_data) + 100;
    write = (char *)calloc(1, len);
    if (!write)
        return NULL;

    strcpy(write, header_data);
    strcat(write, buffer);
    strcat(write, tail_data);
    return write;
}

bool TestDIDAdapter_CreateIdTransaction(const char *payload, const char *memo)
{
    const char *data;
    char path[512], *_path, buffer[512];
    int rc;

    if (!payload)
        return false;

    _path = get_current_path(path);
    if (!_path)
        return false;

    snprintf(buffer, sizeof(buffer), "%s/ethdata.js", _path);
    data = generate_ethdata(payload);
    if (!data)
        return false;

    rc = store_file(buffer, data);
    free((void*)data);
    if (rc < 0)
        return false;

#if defined(_WIN32) || defined(_WIN64)
    snprintf(buffer, sizeof(buffer), "set PATH=%s/../../deps/nodejs/external/src/nodejs;%%windir%%;%%windir%%/SYSTEM32 && node ethdata.js", _path);
#else
    snprintf(buffer, sizeof(buffer), "export PATH=$PATH:%s/../../deps/nodejs/external/src/nodejs/bin && node ethdata.js", _path);
#endif
    system(buffer);
    return true;
}


