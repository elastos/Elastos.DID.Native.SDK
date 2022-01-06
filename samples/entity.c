#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>
#include <assert.h>

#include "ela_did.h"
#include "entity.h"

#define DIPLOMA_SUBJECT "{\"name\":\"%s\",\"degree\":\"bachelor\", \"institute\":\"Computer Science\", \"university\":\"%s\"}"

/******************************************************************************
 * Entity
 *****************************************************************************/
static int init_rootIdentity(Entity *entity)
{
    const char *mnemonic;
    RootIdentity *identity;
    char path[PATH_MAX] = {0};
    size_t size;

    assert(entity);

    size = snprintf(path, sizeof(path), "/tmp/%s.store", entity->name);
    if (size < 0 || size > sizeof(path))
        return -1;

    entity->store = DIDStore_Open(path);
    if (!entity->store)
        return -1;

    // Check the store whether contains the root private identity.
    if (DIDStore_ContainsRootIdentities(entity->store))
        return 0; // Already exists

    // Create a mnemonic use default language(English).
    mnemonic = Mnemonic_Generate("english");
    if (!mnemonic)
        return -1;

    printf("%s Please write down your mnemonic and passwords", entity->name);
    printf("  Mnemonic: %s\n", mnemonic);
    printf("  Mnemonic passphrase: %s\n", entity->passphrase);
    printf("  Store password: %s\n", entity->storepass);

    // Initialize the root identity.
    identity = RootIdentity_Create(mnemonic, entity->passphrase,
            true, entity->store, entity->storepass);
    Mnemonic_Free((void*)mnemonic);
    if (!identity)
        return -1;

    RootIdentity_Destroy(identity);
    return 0;
}

static int get_did(DID *did, void *context)
{
    Entity *entity = (Entity*)context;
    char id[ELA_MAX_DID_LEN];

    if (!did)
        return 0;

    DIDDocument *doc = DIDStore_LoadDID(entity->store, did);
    if (!doc)
        return 0;

    const char *alias = DIDMetadata_GetAlias(DIDDocument_GetMetadata(doc));
    if (alias && !strcmp(alias, "me")) {
        DID_ToString(did, id, sizeof(id));
        entity->did = DID_FromString(id);
    }

    DIDDocument_Destroy(doc);
    return 0;
}

static int init_did(Entity *entity)
{
    const char *id;
    RootIdentity *identity;
    DIDDocument *doc;
    DID *did;
    char idstring[ELA_MAX_DID_LEN];
    int rc, status;

    assert(entity);
    assert(entity->store);

    if (DIDStore_ListDIDs(entity->store, 1, get_did, (void*)entity) == -1)
        return -1;

    if (entity->did) {
        doc = DID_Resolve(entity->did, &status, true);
        if (doc) {
            DIDDocument_Destroy(doc);
            return 0;    // Already create my DID.
        }
    } else {
        id = DIDStore_GetDefaultRootIdentity(entity->store);
        if (!id)
            return -1;

        identity = DIDStore_LoadRootIdentity(entity->store, id);
        free((void*)id);
        if (!identity)
            return -1;

        doc = RootIdentity_NewDID(identity, entity->storepass, "me", false);
        RootIdentity_Destroy(identity);
        if (!doc)
            return -1;

        DID_ToString(DIDDocument_GetSubject(doc), idstring, sizeof(idstring));
        entity->did = DID_FromString(idstring);
        printf("My new DID created: %s\n", idstring);
    }

    rc = DIDDocument_PublishDID(doc, NULL, false, entity->storepass);
    DIDDocument_Destroy(doc);
    if (rc != 1) {
        DIDStore_DeleteDID(entity->store, entity->did);
        DID_Destroy(entity->did);
        entity->did = NULL;
    }

    return rc;
}

Entity *Entity_Init(const char *name)
{
    Entity *entity = NULL;

    if (!name)
        return NULL;

    entity = (Entity*)calloc(1, sizeof(Entity));
    if (!entity)
        return NULL;

    strcpy(entity->name, name);
    strcpy(entity->passphrase, "mypassphrase");
    strcpy(entity->storepass, "mypassword");

    if (init_rootIdentity(entity) == -1 || init_did(entity) == -1) {
        Entity_Deinit(entity);
        return NULL;
    }

    return entity;
}

void Entity_Deinit(Entity *entity)
{
    if (!entity)
        return;

    if (entity->store)
        DIDStore_Close(entity->store);
    if (entity->did)
        DID_Destroy(entity->did);
    free((void*)entity);
}

DID *Entity_GetDid(Entity *entity)
{
    if (!entity)
        return NULL;

    return entity->did;
}

DIDDocument *Entity_GetDocument(Entity *entity)
{
    if (!entity)
        return NULL;

    return DIDStore_LoadDID(entity->store, entity->did);
}

/******************************************************************************
 * University
 *****************************************************************************/
University *University_Init(const char *name)
{
    University *university;

    if (!name)
        return NULL;

    university = (University*)calloc(1, sizeof(University));
    if (!university)
        return NULL;

    university->base = Entity_Init(name);
    if (!university->base) {
        University_Deinit(university);
        return NULL;
    }

    university->issuer = Issuer_Create(university->base->did, NULL, university->base->store);
    if (!university->issuer) {
        University_Deinit(university);
        return NULL;
    }

    return university;
}

void University_Deinit(University *university)
{
    if (!university)
        return;

    Entity_Deinit(university->base);
    Issuer_Destroy(university->issuer);
    free((void*)university);
}

Credential *University_IssuerDiplomaFor(University *university, Student *student)
{
    char subject[256] = {0};
    DIDURL *id;
    Credential *vc;
    time_t max_expires;
    struct tm *tm = NULL;

    if (!university || !student)
        return NULL;

    if (sprintf(subject, DIPLOMA_SUBJECT, student->base->name, university->base->name) == -1)
        return NULL;

    id = DIDURL_NewFromDid(student->base->did, "diploma");
    if (!id)
        return NULL;

    const char *types[] = {"https://ttech.io/credentials/diploma/v1#DiplomaCredential"};

    max_expires = time(NULL);
    tm = gmtime(&max_expires);
    tm->tm_year += 5;
    max_expires = timegm(tm);

    vc = Issuer_CreateCredentialByString(university->issuer, student->base->did, id,
            types, 1, subject, max_expires, university->base->storepass);
    DIDURL_Destroy(id);
    return vc;
}

DID *University_GetDid(University *university)
{
    if (!university)
        return NULL;

    return Entity_GetDid(university->base);
}

DIDDocument *University_GetDocument(University *university)
{
    if (!university)
        return NULL;

    return Entity_GetDocument(university->base);
}

/******************************************************************************
 * Student
 *****************************************************************************/
Student *Student_Init(const char *name, const char *gender, const char *email)
{
    Student *student;

    if (!name || !gender || !email)
        return NULL;

    student = (Student*)calloc(1, sizeof(Student));
    if (!student)
        return NULL;

    student->base = Entity_Init(name);
    if (!student->base) {
        Student_Deinit(student);
        return NULL;
    }

    strcpy(student->gender, gender);
    strcpy(student->email, email);
    return student;
}

void Student_Deinit(Student *student)
{
    if (!student)
        return;

    Entity_Deinit(student->base);
    for (int i = 0; i < student->credentials.size; i++) {
        if (student->credentials.creds[i])
            Credential_Destroy(student->credentials.creds[i]);
    }

    free((void*)student);
}

Credential *Student_CreateSelfProclaimedCredential(Student *student)
{
    DIDURL *id;
    Credential *vc;
    time_t max_expires;
    struct tm *tm = NULL;
    Issuer *issuer;

    if (!student)
        return NULL;

    Property props[3];
    props[0].key = "name";
    props[0].value = student->base->name;
    props[1].key = "gender";
    props[1].value = student->gender;
    props[2].key = "email";
    props[2].value = student->email;

    max_expires = time(NULL);
    tm = gmtime(&max_expires);
    tm->tm_year += 1;
    max_expires = timegm(tm);

    const char *types[] = {
                "https://elastos.org/credentials/v1#SelfProclaimedCredential",
                "https://elastos.org/credentials/profile/v1#ProfileCredential",
                "https://elastos.org/credentials/email/v1#EmailCredential" };

    issuer = Issuer_Create(student->base->did, NULL, student->base->store);
    if (!issuer)
        return NULL;

    id = DIDURL_NewFromDid(student->base->did, "profile");
    if (!id) {
        Issuer_Destroy(issuer);
        return NULL;
    }

    vc = Issuer_CreateCredential(issuer, student->base->did, id,
            types, 3, props, 3, max_expires, student->base->storepass);
    DIDURL_Destroy(id);
    Issuer_Destroy(issuer);
    return vc;
}

int Student_AddCredential(Student *student, Credential *credential)
{
    Credential **vcs;

    vcs = (Credential **)realloc(student->credentials.creds, (student->credentials.size + 1) * sizeof(Credential*));
    if (!vcs)
        return -1;

    vcs[student->credentials.size++] = credential;
    student->credentials.creds = vcs;
    return 0;
}

Presentation *Student_CreatePresentation(Student *student, const char *realm, const char *nonce)
{
    Presentation *vp;
    DIDURL *id;

    if (!student || !realm || !nonce)
        return NULL;

    id = DIDURL_NewFromDid(student->base->did, student->base->name);
    if (!id)
        return NULL;

    vp = Presentation_CreateByCredentials(id, student->base->did,
            NULL, 0, nonce, realm, student->credentials.creds, student->credentials.size,
            NULL, student->base->store, student->base->storepass);
    DIDURL_Destroy(id);
    return vp;
}

DIDDocument *Student_GetDocument(Student *student)
{
    if (!student)
        return NULL;

    return Entity_GetDocument(student->base);
}







