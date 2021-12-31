#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"

typedef struct Entity {
    const char *passphrase = "mypassphrase";
    const char *storepass = "mypassword";

    char name[256];
    DIDStore *store;
    DID did;
} Entity;

typedef struct University {
    Entity *base;
    Issuer *issuer;
} University;

typedef struct Student {
    Entity *base;

    char gender[256];
    char email[256];

    struct {
        size_t size;
        Credential **creds;
    } credentials;
} Student;

Entity *Entity_Init(const char *name);
void Entity_Deinit(Entity *entity);
DID *Entity_GetDid(Entity *entity);

University *University_Init(const char *name);
void University_Deinit(University *university);
Credential *University_IssuerDiplomaFor(University *university, Student *student);
DID *University_GetDid(University *university);
DIDDocument *University_GetDocument(University *university);


Student *Student_Init(const char *name, const char *gender, const char *email);
void Student_Deinit(Student *student);
Credential *Student_CreateSelfProclaimedCredential(Student *student);
int Student_AddCredential(Student *student, Credential *credential);
Presentation *Student_CreatePresentation(Student *student, const char *realm, const char *nonce);
DIDDocument *Student_GetDocument(Student *student);


