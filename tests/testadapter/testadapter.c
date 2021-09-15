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
web3 = new Web3(\"https://api-testnet.elastos.io/eid\");\n\
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
contract.options.address = \"0xF654c3cBBB60D7F4ac7cDA325d51E62f47ACD436\";\n\
acc = web3.eth.accounts.decrypt({\"address\":\"2291bb3d2b5d55217262bf1552ab9b95bfe5b72d\",\"id\":\"ffcd8c94-80ef-4410-b743-d2f72ecdc80e\",\"version\":3,\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"38d49204366be1e7f51464c20f33e51d8138b72411cf055bbd1bd3d9e03624a2\",\"cipherparams\":{\"iv\":\"a5108e26cacaf50842f9b8ebf7047bdf\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":262144,\"p\":1,\"r\":8,\"salt\":\"75a558ca5f7eda86237b11c514f96e348bdb94b554b15c55e5cd1dc6c79a577d\"},\"mac\":\"75e5b2371464435015f1d153bce23097774bdef78c67694a89b25434c2fa0ba2\"}}, \"password\");\n";

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


