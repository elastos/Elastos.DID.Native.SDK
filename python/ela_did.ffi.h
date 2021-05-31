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

typedef long time_t;
typedef struct va_list va_list;

/**
 * \~English
 * DID string max length. eg, did:elastos:ixxxxxxxxxx
 */
#define ELA_MAX_DID_LEN                 128
/**
 * \~English
 * DIDURL string max length. eg, did:elastos:ixxxxxxxxxx#xxxxxx
 */
#define ELA_MAX_DIDURL_LEN              256
/**
 * \~English
 * DIDDocument and Credential alias max length.
 */
#define ELA_MAX_ALIAS_LEN               64
/**
 * \~English
 * DID transaction id max length.
 */
#define ELA_MAX_TXID_LEN                128
/**
 * \~English
 * Mnemonic max length.
 */
#define ELA_MAX_MNEMONIC_LEN            256
/**
 * \~English
 * Signature max length.
 */
#define MAX_SIGNATURE_LEN               128
/**
 * \~English
 * Type max length.
 */
#define MAX_TYPE_LEN                    64

/**
 * \~English
 * Indicate the DID type to list.
 */
typedef enum {
    /**
     * \~English
     * List all dids.
     */
    DIDFilter_All = 0,
    /**
     * \~English
     * List dids that contain private key.
     */
    DIDFilter_HasPrivateKey = 1,
    /**
     * \~English
     * List dids without private key contained.
     */
    DIDFilter_WithoutPrivateKey = 2
} ELA_DID_FILTER;

/**
 * \~English
 * Indicate the DID status on the chain. '1' remains for expired status.
 */
typedef enum
{
    /**
     * \~English
     * DID is valid on chain.
     */
    DIDStatus_Valid = 0,
    /**
     * \~English
     * DID is deactivated on the chain.
     */
    DIDStatus_Deactivated = 2,
    /**
     * \~English
     * DID is not on the chain.
     */
    DIDStatus_NotFound = 3,
    /**
     * \~English
     * DID is not on the chain.
     */
    DIDStatus_Error = -1
} DIDStatus;

/**
 * \~English
 * Indicate the credential status on the chain.
 */
typedef enum
{
    /**
     * \~English
     * Credential is valid on chain.
     */
    CredentialStatus_Valid = 0,
    /**
     * \~English
     * Credential is revoked on chain.
     */
    CredentialStatus_Revoked = 2,
    /**
     * \~English
     * Credential isn't on the chain.
     */
    CredentialStatus_NotFound = 3,
    /**
     * \~English
     * Credential is not on the chain.
     */
    CredentialStatus_Error = -1
} CredentialStatus;

/**
 * \~English
 * The value of the credential Subject property is defined as
 * a set of objects that contain one or more properties that are
 * each related to a subject of the credential.
 */
typedef struct Property {
    /**
     * \~English
     * Property key.
     */
    char *key;
    /**
     * \~English
     * Property value.
     */
    char *value;
} Property;

/**
 * \~English
 * DID is a globally unique identifier that does not require
 * a centralized registration authority.
 * It includes method specific string. (elastos:id:ixxxxxxxxxx).
 */
typedef struct DID                     DID;
/**
 * \~English
 * DID URL defines by the did-url rule, refers to a URL that begins with a DID
 * followed by one or more additional components. A DID URL always
 * identifies the resource to be located.
 * DIDURL includes DID and Url fragment by user defined.
 */
typedef struct DIDURL                   DIDURL;
/**
 * \~English
 * Root Identity records mnemonic, extended private key, extended public key and
 * index for the private identity.
 */
typedef struct RootIdentity             RootIdentity;
/**
 * \~English
 * Identity Metadata records alias string for Root identity and default DID derived
 * from Root Identity.
 **/
typedef struct IdentityMetadata         IdentityMetadata;
/**
 * \~English
 * Public keys are used for digital signatures, encryption and
 * other cryptographic operations, which are the basis for purposes such as
 * authentication or establishing secure communication with service endpoints.
 */
typedef struct PublicKey                PublicKey;
/**
 * \~English
 * Credential is a set of one or more claims made by the same entity.
 * Credentials might also include an identifier and metadata to
 * describe properties of the credential.
 */
typedef struct Credential               Credential;
/**
 * \~English
 * A service endpoint may represent any type of service the subject
 * wishes to advertise, including decentralized identity management services
 * for further discovery, authentication, authorization, or interaction.
 */
typedef struct Service                  Service;
/**
 * \~English
 * A Presentation can be targeted to a specific verifier by using a Linked Data
 * Proof that includes a nonce and realm.
 * This also helps prevent a verifier from reusing a verifiable presentation as
 * their own.
 */
typedef struct Presentation             Presentation;
/**
 * \~English
 * A DID resolves to document. This is the concrete serialization of
 * the data model, according to a particular syntax.
 * DIDDocument is a set of data that describes the subject of a DID,
 * including public key, authentication(optional), authorization(optional),
 * credential and services. One document must be have only subject,
 * and at least one public key.
 */
typedef struct DIDDocument              DIDDocument;
/**
 * \~English
 * A DIDDocument Builder to modify DIDDocument elems.
 */
typedef struct DIDDocumentBuilder       DIDDocumentBuilder;
/**
 * \~English
 DIDMetadata is store for other information about DID except DIDDocument information.
 */
typedef struct DIDMetadata              DIDMetadata;
/**
 * \~English
 * CredentialMetadata stores information about Credential except information in Credential.
 */
typedef struct CredentialMetadata       CredentialMetadata;
/**
 * \~English
 DIDBiography stores all did transactions from chain.
 */
typedef struct DIDBiography             DIDBiography;
/**
 * \~English
 CredentialBiography stores valid transactions from chain, at most has two transaction.
 */
typedef struct CredentialBiography      CredentialBiography;
/**
 * \~English
 * Transfer ticket.
 *
 * When customized DID owner(s) transfer the DID ownership to the others,
 * they need create and sign a transfer ticket, if the DID document is mulisig
 * document, the ticket should also multi-signed according the DID document.
 *
 * The new owner(s) can use this ticket create a transfer transaction, get
 * the subject DID's ownership..
 */
typedef struct TransferTicket          TransferTicket;
/**
 * \~English
 * A issuer is the did to issue credential. Issuer includes issuer's did and
 * issuer's sign key.
 */
typedef struct Issuer                   Issuer;
/**
 * \~English
 * DIDStore is local store for specified DID.
 */
typedef struct DIDStore                 DIDStore;
/**
 * \~English
 * JWTBuilder records the content about jwt.
 */
typedef struct JWTBuilder           JWTBuilder;
/**
 * \~English
 * JWSParser holds the DIDDocument to parse jws.
 */
typedef struct JWSParser            JWSParser;
/**
 * \~English
 * DID list callbacks, which is realized by user.
 * @param
 *      did               [in] A handle to DID.
 * @param
 *      context           [in] The application defined context data.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
typedef int DIDStore_DIDsCallback(DID *did, void *context);
extern "Python" int ListDIDsCallback(DID *did, void *context);

/**
 * \~English
 * Credential list callbacks, which is realized by user.
 * @param
 *      id                [in] A handle to DIDURL.
 * @param
 *      context           [in] The application defined context data.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
typedef int DIDStore_CredentialsCallback(DIDURL *id, void *context);
extern "Python" int ListCredentialsCallback(DIDURL *id, void *context);
/**
 * \~English
 * Root Identity list callbacks, which is realized by user.
 * @param
 *      rootidentity      [in] A handle to RootIdentity.
 * @param
 *      context           [in] The application defined context data.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
typedef int DIDStore_RootIdentitiesCallback(RootIdentity *rootidentity, void *context);
extern "Python" int ListRootIdentitiesCallback(RootIdentity *rootidentity, void *context);
/**
 * \~English
 * The function indicate how to resolve the confict, if the local document is different
 * with the one resolved from chain.
 * @param
 *      chaincopy           [in] The document from DIDStore.
 * @param
 *      localcopy           [in] The document from chain.
 * @return
 *      If no error occurs, return merged document. Otherwise, return NULL.
 */
typedef DIDDocument* DIDDocument_ConflictHandle(DIDDocument *chaincopy, DIDDocument *localcopy);
extern "Python" DIDDocument* DocumentMergeCallback(DIDDocument *chaincopy, DIDDocument *localcopy);
/**
 * \~English
 * The function indicate how to get local did document, if this did is not published to chain.
 * @param
 *      did                 [in] The DID string.
 * @return
 *      If no error occurs, return the handle to DIDDocument. Otherwise, return NULL.
 */
typedef DIDDocument* DIDLocalResovleHandle(DID *did);
extern "Python" DIDDocument* MyDIDLocalResovleHandle(DID *did);
/**
 * \~English
 * The function that create id transaction to chain（publish did, declare credential or revoke credential).
 * @param
 *      payload              [in] The content of id transaction.
 * @param
 *      memo                 [in] Memo string.
 * @return
 *      If no error occurs, return true. Otherwise, return false.
 */
typedef bool CreateIdTransaction_Callback(const char *payload, const char *memo);
extern "Python" bool MyCreateIdTransaction(const char *payload, const char *memo);
/**
 * \~English
 * The function that resolve id data from chain.
 * @param
 *      request              [in] The rpc request to resolve.
 * @return
 *      If no error occurs, return resolved data.
 *      Otherwise, return NULL.
 */
typedef const char* Resolve_Callback(const char *request);
extern "Python" const char* MyResolve(const char *request);

/******************************************************************************
 * DID
 *****************************************************************************/
/**
 * \~English
 * Get DID from string.
 *
 * @param
 *      idstring     [in] A pointer to string including id information.
 *                        idstring support:   did:elastos:ixxxxxxx
 * @return
 *      If no error occurs, return the pointer of DID.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DID *DID_FromString(const char *idstring);

/**
 * \~English
 * Create a new DID according to method specific string.
 *
 * @param
 *      method_specific_string    [in] A pointer to specific string.
 *                                     The method-specific-id value should be
 *                                     globally unique by itself.
 * @return
 *      If no error occurs, return the pointer of DID.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DID *DID_New(const char *method_specific_string);

/**
 * \~English
 * Get method of DID.
 *
 * @param
 *      did                 [in] A handle to DID.
 * @return
 *      If no error occurs, return method string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *DID_GetMethod(DID *did);

/**
 * \~English
 * Get method specific string of DID.
 *
 * @param
 *      did                  [in] A handle to DID.
 * @return
 *      If no error occurs, return string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *DID_GetMethodSpecificId(DID *did);

/**
 * \~English
 * Get id string from DID.
 *
 * @param
 *      did                  [in] A handle to DID.
 * @param
 *      idstring             [out] The buffer that will receive the id string.
 *                                 The buffer size should at least (ELA_MAX_DID_LEN) bytes.
 * @param
 *      len                  [in] The buffer size of idstring.
 * @return
 *      The id string pointer, or NULL if buffer is too small.
 */
/* DID_API */ char *DID_ToString(DID *did, char *idstring, size_t len);

/**
 * \~English
 * Compare two DID is same or not.
 *
 * @param
 *      did1                  [in] One DID to be compared.
 * @param
 *      did2                  [in] The other DID to be compared.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, two dids are not same;
 *      return value = 1, two dids are same.
 */
/* DID_API */ int DID_Equals(DID *did1, DID *did2);

/**
 * \~English
 * Compare two DIDs with their did string.
 *
 * @param
 *      did1                   [in] One DID to be compared.
 * @param
 *      did2                   [in] The other DID to be compared.
 * @return
 *      return value = -1, if error occurs;
 *      return value < 0(exclude -1), it indicates did1 is less than did2;
 *      return value = 0, it indicates did1 is equal to did2;
 *      return value > 0, it indicates did1 is greater than did2.
 */
/* DID_API */ int DID_Compare(DID *did1, DID *did2);

/**
 * \~English
 * Destroy DID.
 *
 * @param
 *      did                   [in] A handle to DID to be destroied.
 */
/* DID_API */ void DID_Destroy(DID *did);

/**
 * \~English
 * Get the newest DID Document from chain.
 *
 * @param
 *      did                      [in] The handle of DID.
 * @param
 *      status                   [in] The status of DID.
 * @param
 *      force                    [in] Indicate if load document from cache or not.
 *                               force = true, document gets only from chain.
 *                               force = false, document can get from cache,
 *                               if no document is in the cache, resolve it from chain.
 * @return
 *      If no error occurs, return the handle to DID Document.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDDocument *DID_Resolve(DID *did, DIDStatus *status, bool force);

/**
 * \~English
 * Get all DID Documents from chain.
 *
 * @param
 *      did                      [in] The handle of DID.
 * @return
 *      when no error occurs, it returns the handle to DIDBiography instance.
 *      otherwise, it returns NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDBiography *DID_ResolveBiography(DID *did);

/**
 * \~English
 * Get DID metadata from did.
 *
 * @param
 *      did                      [in] The handle of DID.
 * @return
 *      If no error occurs, return the handle to metadata.
 *      Otherwise, return -1.
 */
/* DID_API */ DIDMetadata *DID_GetMetadata(DID *did);

/**
 * \~English
 * Get alias for did.
 *
 * @param
 *      metadata                        [in] The handle of DIDMetadata.
 * @return
 *      If no error occurs, return alias string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *DIDMetadata_GetAlias(DIDMetadata *metadata);

/**
 * \~English
 * Get did status, deactived or not.
 *
 * @param
 *      metadata                        [in] The handle of DIDMetadata.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, did isn't deacativated;
 *      return value = 1, did is deacativated.
 */
/* DID_API */ int DIDMetadata_GetDeactivated(DIDMetadata *metadata);

/**
 * \~English
 * Get the time of transaction id for did.
 *
 * @param
 *      metadata                        [in] The handle of DIDMetadata.
 * @return
 *      If no error occurs, return time stamp.
 *      Otherwise, return 0.
 */
/* DID_API */ time_t DIDMetadata_GetPublished(DIDMetadata *metadata);

/**
 * \~English
 * Set alias for did.
 *
 * @param
 *      metadata                        [in] The handle of DIDMetadata.
 * @param
 *      alias                           [in] The ailas string.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
/* DID_API */ int DIDMetadata_SetAlias(DIDMetadata *metadata, const char *alias);

/**
 * \~English
 * Set 'string' extra elemfor did.
 *
 * @param
 *      metadata                        [in] The handle of DIDMetadata.
 * @param
 *      key                             [in] The key string.
 * @param
 *      value                           [in] The value string.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
/* DID_API */ int DIDMetadata_SetExtra(DIDMetadata *metadata, const char* key, const char *value);

/**
 * \~English
 * Set 'boolean' extra elem for did.
 *
 * @param
 *      metadata                        [in] The handle of DIDMetadata.
 * @param
 *      key                             [in] The key string.
 * @param
 *      value                           [in] The boolean value.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
/* DID_API */ int DIDMetadata_SetExtraWithBoolean(DIDMetadata *metadata, const char *key, bool value);

/**
 * \~English
 * Set 'double' extra elem for did.
 *
 * @param
 *      metadata                        [in] The handle of DIDMetadata.
 * @param
 *      key                             [in] The key string.
 * @param
 *      value                           [in] The double value.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
/* DID_API */ int DIDMetadata_SetExtraWithDouble(DIDMetadata *metadata, const char *key, double value);

/**
 * \~English
 * Get 'string' extra elem from DID.
 *
 * @param
 *      metadata                       [in] The handle of CredentialMetadata.
 * @param
 *      key                            [in] The key string.
 * @return
 *      If no error occurs, return the elem string. Otherwise, return NULL.
 */
/* DID_API */ const char *DIDMetadata_GetExtra(DIDMetadata *metadata, const char *key);

/**
 * \~English
 * Get 'boolean' extra elem from DID.
 *
 * @param
 *      metadata                       [in] The handle of CredentialMetadata.
 * @param
 *      key                            [in] The key string.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, it equals to 'false';
 *      return value = 1, it equals to 'true'.
 */
/* DID_API */ int DIDMetadata_GetExtraAsBoolean(DIDMetadata *metadata, const char *key);

/**
 * \~English
 * Get 'double' extra elem from DID.
 *
 * @param
 *      metadata                       [in] The handle of CredentialMetadata.
 * @param
 *      key                            [in] The key string.
 * @return
 *      'double' elem value.
 */
/* DID_API */ double DIDMetadata_GetExtraAsDouble(DIDMetadata *metadata, const char *key);

/******************************************************************************
 * DIDURL
 *****************************************************************************/
/**
 * \~English
 * Get DID URL from string.
 *
 * @param
 *      idstring     [in] A pointer to string including id information.
 *                   idstring support: 1. "did:elastos:xxxxxxx#xxxxx"
 *                                     2. "#xxxxxxx"
 * @param
 *      ref          [in] A pointer to DID.
 * @return
 *      If no error occurs, return the handle to DID URL.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDURL *DIDURL_FromString(const char *idstring, DID *ref);

/**
 * \~English
 * Create a new DID URL according to specific string and fragment.
 *
 * @param
 *      method_specific_string    [in] A pointer to specific string.
 *                                     The method-specific-id value should be
 *                                     globally unique by itself.
 * @param
 *      fragment                  [in] The portion of a DID URL.
 * @return
 *      If no error occurs, return the handle to DID URL.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDURL *DIDURL_New(const char *method_specific_string, const char *fragment);

/**
 * \~English
 * Create a new DID URL according to DID and fragment.
 *
 * @param
 *      did                       [in] A pointer to DID.
 * @param
 *      fragment                  [in] The portion of a DID URL.
 * @return
 *      If no error occurs, return the handle to DID URL.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDURL *DIDURL_NewByDid(DID *did, const char *fragment);

/**
 * \~English
 * Get DID from DID URL.
 *
 * @param
 *      id               [in] A handle to DID URL.
 * @return
 *      If no error occurs, return the handle to DID.
 *      Otherwise, return NULL.
 */
/* DID_API */ DID *DIDURL_GetDid(DIDURL *id);

/**
 * \~English
 * Get fragment from DID URL.
 *
 * @param
 *      id               [in] A handle to DID URL.
 * @return
 *      If no error occurs, return fragment string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *DIDURL_GetFragment(DIDURL *id);

/**
 * \~English
 * Get id string from DID URL.
 *
 * @param
 *      id               [in] A handle to DID URL.
 * @param
 *      idstring         [out] The buffer that will receive the id string.
 *                             The buffer size should at least (ELA_MAX_DID_LEN) bytes.
 * @param
 *      len              [in] The buffer size of idstring.
 * @param
 *      compact          [in] Id string is compact or not.
 *                       true represents compact, flase represents not compact.
 * @return
 *      If no error occurs, return id string. Otherwise, return NULL.
 */
/* DID_API */ char *DIDURL_ToString(DIDURL *id, char *idstring, size_t len, bool compact);

/**
 * \~English
 * Compare two DID URL is same or not.
 *
 * @param
 *      id1                  [in] One DID URL to be compared.
 * @param
 *      id2                  [in] The other DID URL to be compared.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, two ids aren't same;
 *      return value = 1, two ids are same.
 */
/* DID_API */ int DIDURL_Equals(DIDURL *id1, DIDURL *id2);

/**
 * \~English
 * Compare two DIDURLs with their whole string.
 *
 * @param
 *      id1                   [in] One DID URL to be compared.
 * @param
 *      id2                   [in] The other DID URL to be compared.
 * @return
 *      return value = -1, if error occurs;
 *      return value < 0(exclude -1), it indicates id1 is less than id2;
 *      return value = 0, it indicates id1 is equal to id2;
 *      return value > 0, it indicates id1 is greater than id2.
 */
/* DID_API */ int DIDURL_Compare(DIDURL *id1, DIDURL *id2);

/**
 * \~English
 * Destroy DID URL.
 *
 * @param
 *      id                  [in] A handle to DID URL to be destroied.
 */
/* DID_API */ void DIDURL_Destroy(DIDURL *id);

/**
 * \~English
 * Get CredentialMetadata from Credential.
 *
 * @param
 *      id                       [in] The handle of DIDURL.
 * @return
 *      If no error occurs, return the handle to CredentialMetadata. Otherwise, return NULL.
 */
/* DID_API */ CredentialMetadata *DIDURL_GetMetadata(DIDURL *id);

/**
 * \~English
 * Set alias for Credential.
 *
 * @param
 *      metadata                       [in] The handle of CredentialMetadata.
 * @param
 *      alias                          [in] The alias string.
 * @return
 *      If no error occurs, return the 0. Otherwise, return -1.
 */
/* DID_API */ int CredentialMetadata_SetAlias(CredentialMetadata *metadata, const char *alias);

/**
 * \~English
 * Set 'string' extra elem for Credential.
 *
 * @param
 *      metadata                       [in] The handle of CredentialMetadata.
 * @param
 *      key                            [in] The key string.
 * @param
 *      value                          [in] The value string.
 * @return
 *      If no error occurs, return the 0. Otherwise, return -1.
 */
/* DID_API */ int CredentialMetadata_SetExtra(CredentialMetadata *metadata,
        const char* key, const char *value);

/**
 * \~English
 * Set 'boolean' extra elem for Credential.
 *
 * @param
 *      metadata                       [in] The handle of CredentialMetadata.
 * @param
 *      key                            [in] The key string.
 * @param
 *      value                          [in] The boolean value.
 * @return
 *      If no error occurs, return the 0. Otherwise, return -1.
 */
/* DID_API */ int CredentialMetadata_SetExtraWithBoolean(CredentialMetadata *metadata,
        const char *key, bool value);

/**
 * \~English
 * Set 'double' extra elem for Credential.
 *
 * @param
 *      metadata                       [in] The handle of CredentialMetadata.
 * @param
 *      key                            [in] The key string.
 * @param
 *      value                          [in] The double value.
 * @return
 *      If no error occurs, return the 0. Otherwise, return -1.
 */
/* DID_API */ int CredentialMetadata_SetExtraWithDouble(CredentialMetadata *metadata,
        const char *key, double value);
/**
 * \~English
 * Get alias from credential by meta data.
 *
 * @param
 *      metadata                     [in] The handle of CredentialMetadata.
 * @return
 *      If no error occurs, return alias string. Otherwise, return NULL.
 */
/* DID_API */ const char *CredentialMetadata_GetAlias(CredentialMetadata *metadata);

/**
 * \~English
 * Get alias from credential by meta data.
 *
 * @param
 *      metadata                     [in] The handle of CredentialMetadata.
 * @return
 *      If no error occurs, return published time. Otherwise, return 0.
 */
/* DID_API */ time_t CredentialMetadata_GetPublished(CredentialMetadata *metadata);

/**
 * \~English
 * Get revoked status from credential by meta data.
 *
 * @param
 *      metadata                     [in] The handle of CredentialMetadata.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, credential isn't revoked;
 *      return value = 1, credential is revoked.
 */
/* DID_API */ int CredentialMetadata_GetRevoke(CredentialMetadata *metadata);

/**
 * \~English
 * Get transaction id from credential by meta data.
 *
 * @param
 *      metadata                     [in] The handle of CredentialMetadata.
 * @return
 *      If credential is revoked, return true. Otherwise, return false.
 */
/* DID_API */ const char *CredentialMetadata_GetTxid(CredentialMetadata *metadata);

/**
 * \~English
 * Get 'string' extra elem from Credential.
 *
 * @param
 *      metadata                       [in] The handle of CredentialMetadata.
 * @param
 *      key                            [in] The key string.
 * @return
 *      If no error occurs, return the elem string. Otherwise, return NULL.
 */
/* DID_API */ const char *CredentialMetadata_GetExtra(CredentialMetadata *metadata,
        const char *key);

/**
 * \~English
 * Get 'boolean' extra elem from Credential.
 *
 * @param
 *      metadata                       [in] The handle of CredentialMetadata.
 * @param
 *      key                            [in] The key string.
 * @return
 *      'boolean' elem value.
 */
/* DID_API */ bool CredentialMetadata_GetExtraAsBoolean(CredentialMetadata *metadata,
        const char *key);

/**
 * \~English
 * Get 'double' extra elem from Credential.
 *
 * @param
 *      metadata                       [in] The handle of CredentialMetadata.
 * @param
 *      key                            [in] The key string.
 * @return
 *      'double' elem value.
 */
/* DID_API */ double CredentialMetadata_GetExtraAsDouble(CredentialMetadata *metadata,
        const char *key);

/******************************************************************************
 * DIDBiography
 *****************************************************************************/

/**
 * \~English
 * Get owner of DID resolved biography.
 *
 * @param
 *      biography                       [in] The handle to DIDBiography.
 * @return
 *      If no error occurs, return the handle to DID. Destroy DID after finishing use.
 *      Otherwise, return NULL.
 */
/* DID_API */ DID *DIDBiography_GetOwner(DIDBiography *biography);

/**
 * \~English
 * Get DID status of DID.
 *
 * @param
 *      biography                       [in] The handle to DIDBiography.
 * @return
*      If no error occurs, return DID status. Otherwise, return -1.
 */
/* DID_API */ int DIDBiography_GetStatus(DIDBiography *biography);

/**
 * \~English
 * Get DID transaction count.
 *
 * @param
 *      biography                       [in] The handle to DIDBiography.
 * @return
*      If no error occurs, return count. Otherwise, return -1.
 */
/* DID_API */ ssize_t DIDBiography_GetTransactionCount(DIDBiography *biography);

/**
 * \~English
 * Get DID Document from 'index' transaction.
 *
 * @param
 *      biography                     [in] The handle to DIDBiography.
 * @param
 *      index                         [in] The index of transaction.
 * @return
 *      If no error occurs, return the handle to DID Document.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDDocument *DIDBiography_GetDocumentByIndex(DIDBiography *biography, int index);

/**
 * \~English
 * Get transaction id from 'index' transaction.
 *
 * @param
 *      biography                     [in] The handle to DIDBiography.
 * @param
 *      index                         [in] The index of transaction.
 * @return
 *      If no error occurs, return transaction.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *DIDBiography_GetTransactionIdByIndex(DIDBiography *biography, int index);

/**
 * \~English
 * Get published time from 'index' transaction.
 *
 * @param
 *      biography                     [in] The handle to DIDBiography.
 * @param
 *      index                         [in] The index of transaction.
 * @return
*      If no error occurs, return published time. Otherwise, return 0.
 */
/* DID_API */ time_t DIDBiography_GetPublishedByIndex(DIDBiography *biography, int index);

/**
 * \~English
 * Get operation of 'index' transaction. Operation: 'created', 'update' and 'deactivated'.
 *
 * @param
 *      biography                     [in] The handle to DIDBiography.
 * @param
 *      index                         [in] The index of transaction.
 * @return
 *       If no error occurs, return operation string.
 *       Otherwise, return -1.
 */
/* DID_API */ const char *DIDBiography_GetOperationByIndex(DIDBiography *biography, int index);
/**
 * \~English
 * Destroy DIDBiography.
 *
 * @param
 *      biography               [in] A handle to DIDBiography.
 */
/* DID_API */ void DIDBiography_Destroy(DIDBiography *biography);

/******************************************************************************
 * CredentialBiography
 *****************************************************************************/

/**
 * \~English
 * Get id of credential biography.
 *
 * @param
 *      biography                   [in] The handle to CredentialBiography.
 * @return
 *      If no error occurs, return the handle to DIDURL. Destroy the returned value
 *      after finishing use. Otherwise, return NULL.
 */
/* DID_API */ DIDURL *CredentialBiography_GetId(CredentialBiography *biography);

/**
 * \~English
 * Get owner of credential biography.
 *
 * @param
 *      biography                   [in] The handle to CredentialBiography.
 * @return
 *      If no error occurs, return the handle to DID. Destroy the returned value
 *      after finishing use. Otherwise, return NULL.
 */
/* DID_API */ DID *CredentialBiography_GetOwner(CredentialBiography *biography);

/**
 * \~English
 * Get credential status on chain.
 *
 * @param
 *      biography                   [in] The handle to CredentialBiography.
 * @return
*      If no error occurs, return credential status. Otherwise, return -1.
 */
/* DID_API */ int CredentialBiography_GetStatus(CredentialBiography *biography);

/**
 * \~English
 * Get Credential transaction count.
 *
 * @param
 *      biography                    [in] The handle to CredentialBiography.
 * @return
*      If no error occurs, return count. Otherwise, return -1.
 */
/* DID_API */ ssize_t CredentialBiography_GetTransactionCount(CredentialBiography *biography);

/**
 * \~English
 * Get Credential from 'index' transaction.
 *
 * @param
 *      biography                     [in] The handle to CredentialBiography.
 * @param
 *      index                         [in] The index of transaction.
 * @return
 *      If no error occurs, return the handle to Credential. Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ Credential *CredentialBiography_GetCredentialByIndex(CredentialBiography *biography, int index);

/**
 * \~English
 * Get transaction id from 'index' transaction.
 *
 * @param
 *      biography                     [in] The handle to CredentialBiography.
 * @param
 *      index                         [in] The index of transaction.
 * @return
 *      If no error occurs, return transaction id string. Otherwise, return NULL.
 */
/* DID_API */ const char *CredentialBiography_GetTransactionIdByIndex(CredentialBiography *biography, int index);

/**
 * \~English
 * Get published time from 'index' transaction.
 *
 * @param
 *      biography                     [in] The handle to CredentialBiography.
 * @param
 *      index                         [in] The index of transaction.
 * @return
*      If no error occurs, return published time. Otherwise, return 0.
 */
/* DID_API */ time_t CredentialBiography_GetPublishedByIndex(CredentialBiography *biography, int index);

/**
 * \~English
 * Get operation of 'index' transaction. Operation: 'declare' and 'revoke'.
 *
 * @param
 *      biography                     [in] The handle to CredentialBiography.
 * @param
 *      index                         [in] The index of transaction.
 * @return
 *       If no error occurs, return operation string.
 *       Otherwise, return NULL.
 */
/* DID_API */ const char *CredentialBiography_GetOperationByIndex(CredentialBiography *biography, int index);

/**
 * \~English
 * Get signkey of 'index' transaction.
 *
 * @param
 *      biography                     [in] The handle to CredentialBiography.
 * @param
 *      index                         [in] The index of transaction.
 * @return
 *       If no error occurs, return the handle to DIDURL. Otherwise, return NULL.
 */
/* DID_API */ DIDURL *CredentialBiography_GetTransactionSignkeyByIndex(CredentialBiography *biography, int index);

/**
 * \~English
 * Destroy CredentialBiography.
 *
 * @param
 *      biography               [in] A handle to CredentialBiography.
 */
/* DID_API */ void CredentialBiography_Destroy(CredentialBiography *biography);

/******************************************************************************
 * RootIdentity
 *****************************************************************************/
/**
 * \~English
 * Initial root identity by mnemonic.
 *
 * @param
 *      mnemonic          [in] Mnemonic for generate key.
 * @param
 *      passphrase        [in] The password to generate private identity.
 * @param
 *      language          [in] The language for DID.
 *                        support language string: "chinese_simplified",
 *                        "chinese_traditional", "czech", "english", "french",
 *                        "italian", "japanese", "korean", "spanish".
 * @param
 *      overwrite         [in] If private identity exist, remove or remain it.
 *                        If force is true, then will choose to create a new identity
 *                        even if the private identity already exists and
 *                        the new private key will replace the original one in DIDStore.
 *                        If force is false, then will choose to remain the old
 *                        private key if the private identity exists, and return error code.
 * @param
 *      store             [in] The handle to DIDStore.
 * @param
 *      storepass         [in] The password for DIDStore.
 * @return
 *      the handle to RootIdentity, otherwise, return NULL.
 */
/* DID_API */ RootIdentity *RootIdentity_Create(const char *mnemonic, const char *passphrase,
        bool overwrite, DIDStore *store, const char *storepass);

/**
 * \~English
 * Initial root identity by extened private key.
 *
 * @param
 *      extendedprvkey     [in] Extendedkey string.
 * @param
 *      overwrite         [in] If private identity exist, remove or remain it.
 *                        If force is true, then will choose to create a new identity
 *                        even if the private identity already exists and
 *                        the new private key will replace the original one in DIDStore.
 *                        If force is false, then will choose to remain the old
 *                        private key if the private identity exists, and return error code.
 * @param
 *      store             [in] The handle to DIDStore.
 * @param
 *      storepass         [in] The password for DIDStore.
 * @return
 *      the handle to RootIdentity, otherwise, return NULL.
 */
/* DID_API */ RootIdentity *RootIdentity_CreateFromRootKey(const char *extendedprvkey,
        bool overwrite, DIDStore *store, const char *storepass);

/**
 * \~English
 * Create root identity id string by mnemonic.
 *
 * @param
 *      mnemonic          [in] Mnemonic for generate key.
 * @param
 *      passphrase        [in] The password to generate private identity.
 * @return
 *      the RootIdentity id string, otherwise, return NULL.
 *      Notice that user need to free the returned value that it's memory.
 */
/* DID_API */ const char *RootIdentity_CreateId(const char *mnemonic, const char *passphrase);

/**
 * \~English
 * Create root identity id string by extened private key.
 *
 * @param
 *      extendedprvkey     [in] Extendedkey string.
 * @return
 *      the RootIdentity id string, otherwise, return NULL.
 *      Notice that user need to free the returned value that it's memory.
 */
/* DID_API */ const char *RootIdentity_CreateIdFromRootKey(const char *extendedprvkey);

/**
 * \~English
 * Destroy RootIdentity.
 *
 * @param
 *      rootidentity               [in] A handle to RootIdentity.
 */
/* DID_API */ void RootIdentity_Destroy(RootIdentity *rootidentity);

/**
 * \~English
 * Set default rootidentity.
 *
 * @param
 *      rootidentity             [in] A handle to RootIdentity.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int RootIdentity_SetAsDefault(RootIdentity *rootidentity);

/**
 * \~English
 * Get RootIdentity's id (id is on behalf of RootIdentity).
 *
 * @param
 *      rootidentity               [in] A handle to RootIdentity.
 * @return
 *      the id string, otherwise, return NULL.
 */
/* DID_API */ const char *RootIdentity_GetId(RootIdentity *rootidentity);

/**
 * \~English
 * Get RootIdentity's alias.
 *
 * @param
 *      rootidentity               [in] A handle to RootIdentity.
 * @return
 *      the alias string, otherwise, return NULL.
 */
/* DID_API */ const char *RootIdentity_GetAlias(RootIdentity *rootidentity);

/**
 * \~English
 * Set RootIdentity's alias.
 *
 * @param
 *      rootidentity        [in] A handle to RootIdentity.
 * @param
 *      alias               [in] The alias string.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int RootIdentity_SetAlias(RootIdentity *rootidentity, const char *alias);

/**
 * \~English
 * Set default DID derived from RootIdentity.
 *
 * @param
 *      rootidentity        [in] A handle to RootIdentity.
 * @param
 *      did                 [in] A handle to default DID.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int RootIdentity_SetDefaultDID(RootIdentity *rootidentity, DID *did);

/**
 * \~English
 * Get default DID derived from RootIdentity.
 *
 * @param
 *      rootidentity        [in] A handle to RootIdentity.
 * @return
 *      the handle to DID on success, NULL if an error occurred.
 *      Notice that user need to free the returned value that it's memory.
 */
/* DID_API */ DID *RootIdentity_GetDefaultDID(RootIdentity *rootidentity);

/**
 * \~English
 * Create new DID Document.
 *
 * @param
 *      rootidentity              [in] THe handle to RootIdentity.
 * @param
 *      storepass                 [in] Password for DIDStore.
 * @param
 *      alias                     [in] The nickname of DID.
 *                                     ‘alias' supports NULL.
 * @return
 *      If no error occurs, return the handle to DID Document.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDDocument *RootIdentity_NewDID(RootIdentity *rootidentity,
        const char *storepass, const char *alias);

/**
 * \~English
 * Create new DID Document by specified index.
 *
 * @param
 *      rootidentity              [in] The handle to RootIdentity.
 * @param
 *      index                     [in] Index number.
 * @param
 *      storepass                 [in] Password for DIDStore.
 * @param
 *      alias                     [in] The nickname of DID.
 *                                     ‘alias' supports NULL.
 * @return
 *      If no error occurs, return the handle to DID Document.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDDocument *RootIdentity_NewDIDByIndex(RootIdentity *rootidentity, int index,
        const char *storepass, const char *alias);

/**
 * \~English
 * Only get DID object by index, not create document and so on.
 *
 * @param
 *      rootidentity              [in] The handle to RootIdentity.
 * @param
 *      index                     [int] The index of DerivedKey from HDKey.
 * @return
 *      If no error occurs, return DID object. Free DID after use it.
 *      Otherwise, return NULL.
 */
/* DID_API */ DID *RootIdentity_GetDIDByIndex(RootIdentity *rootidentity, int index);

/**
 * \~English
 * Synchronize all DID from RootIdentity.
 *
 * @param
 *      rootidentity           [in] The handle to RootIdentity.
 * @param
 *      handle                 [in] The method to merge document.
 *                              handle == NULL, use default method supported by sdk.
 * @return
 *      true on success, false if an error occurred.
 */
/* DID_API */ bool RootIdentity_Synchronize(RootIdentity *rootidentity, DIDDocument_ConflictHandle *handle);

/**
 * \~English
 * Synchronize the specified DID from RootIdentity.
 *
 * @param
 *      rootidentity           [in] The handle to RootIdentity.
 * @param
 *      index                  [in] The index number.
 * @param
 *      handle                 [in] The method to merge document.
 *                              handle == NULL, use default method supported by sdk.
 * @return
 *      true on success, false if an error occurred.
 */
/* DID_API */ bool RootIdentity_SynchronizeByIndex(RootIdentity *rootidentity, int index,
        DIDDocument_ConflictHandle *handle);

/******************************************************************************
 * DIDDocument
 *****************************************************************************/
/**
 * \~English
 * Get DID Document from json context.
 *
 * @param
 *      json               [in] Context of did conforming to json informat.
 * @return
 *      If no error occurs, return the handle to DID Document.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDDocument *DIDDocument_FromJson(const char* json);

/**
 * \~English
 * Get json non-formatted context from DID Document.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      normalized           [in] Json context is normalized or not.
 *                           true represents normalized, false represents not compact.
 * @return
 *      If no error occurs, return json context. Otherwise, return NULL.
 *      Notice that user need to free the returned value that it's memory.
 */
/* DID_API */ const char *DIDDocument_ToJson(DIDDocument *document, bool normalized);


/**
 * \~English
 * Get json formatted context from DID Document.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      normalized           [in] Json context is normalized or not.
 *                           true represents normalized, false represents not compact.
 * @return
 *      If no error occurs, return json context. Otherwise, return NULL.
 *      Notice that user need to free the returned value that it's memory.
 */
/* DID_API */ const char *DIDDocument_ToString(DIDDocument *document, bool normalized);
/**
 * \~English
 * Destroy DID Document.
 *
 * @param
 *      document             [in] A handle to DID Document to be destroied.
 */
/* DID_API */ void DIDDocument_Destroy(DIDDocument *document);

/**
 * \~English
  * Check that document is owned to customized DID or not.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, did isn't customized one;
 *      return value = 1, did is customized one.
*/
/* DID_API */ int DIDDocument_IsCustomizedDID(DIDDocument *document);
/**
 * \~English
 * Check that document is deactivated or not.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, did isn't deactivated;
 *      return value = 1, did is deactivated.
*/
/* DID_API */ int DIDDocument_IsDeactivated(DIDDocument *document);

/**
 * \~English
 * Check that document is genuine or not.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, did isn't genuine;
 *      return value = 1, did is genuine.
*/
/* DID_API */ int DIDDocument_IsGenuine(DIDDocument *document);

/**
 * \~English
 * Check that document is expired or not.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, did isn't expired;
 *      return value = 1, did is expired.
*/
/* DID_API */ int DIDDocument_IsExpired(DIDDocument *document);

/**
 * \~English
 * Check that document is valid or not.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, diddocument isn't valid;
 *      return value = 1, diddocument is valid;
*/
/* DID_API */ int DIDDocument_IsValid(DIDDocument *document);

/**
 * \~English
 * Check that document is qualified or not.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, did isn't qualified;
 *      return value = 1, did is qualified.
*/
/* DID_API */ int DIDDocument_IsQualified(DIDDocument *document);

/**
 * \~English
 * Get DID subject to DID Document. The DID Subject is the entity of
 * the DID Document. A DID Document must have exactly one DID subject.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      If no error occurs, return a handle to DID.
 *      Otherwise, return NULL.
 */
/* DID_API */ DID* DIDDocument_GetSubject(DIDDocument *document);

/**
 * \~English
 * Get DIDDocument Builder to modify document.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      controllerdoc        [in] A handle to controlle's Document.
 *                           If DID is normal DID or customiezed DID has only one controller,
 *                           controllerdoc can be null.
 * @return
 *      If no error occurs, return a handle to DIDDocumentBuilder.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDDocumentBuilder* DIDDocument_Edit(DIDDocument *document, DIDDocument *controllerdoc);

/**
 * \~English
 * Destroy DIDDocument Builder.
 *
 * @param
 *      builder             [in] A handle to DIDDocument Builder.
 */
/* DID_API */ void DIDDocumentBuilder_Destroy(DIDDocumentBuilder *builder);

/**
 * \~English
 * Finish modiy document.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      storepass            [in] The password for DIDStore.
 * @return
 *      If no error occurs, return a handle to DIDDocument.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDDocument *DIDDocumentBuilder_Seal(DIDDocumentBuilder *builder,
            const char *storepass);

/**
 * \~English
 * Add controller for DIDDocument.
 *
 * @param
 *      builder               [in] A handle to DIDDocument Builder.
 * @param
 *      controller            [in] The controller for DIDDocument.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_AddController(DIDDocumentBuilder *builder, DID *controller);

/**
 * \~English
 * Remove controller from DIDDocument.
 *
 * @param
 *      builder               [in] A handle to DIDDocument Builder.
 * @param
 *      controller            [in] The controller for DIDDocument.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_RemoveController(DIDDocumentBuilder *builder, DID *controller);

/**
 * \~English
 * Add public key to DID Document.
 * Each public key has an identifier (id) of its own, a type, and a controller,
 * as well as other properties publicKeyBase58 depend on which depend on
 * what type of key it is.
 *
 * @param
 *      builder               [in] A handle to DIDDocument Builder.
 * @param
 *      keyid                 [in] An identifier of public key.
 * @param
 *      controller            [in] A controller property, identifies
 *                              the controller of the corresponding private key.
 * @param
 *      key                  [in] Key propertie depend on key type.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_AddPublicKey(DIDDocumentBuilder *builder,
        DIDURL *keyid, DID *controller, const char *key);

/**
 * \~English
 * Remove specified public key from DID Document.
 *
 * @param
 *      builder               [in] A handle to DIDDocument Builder.
 * @param
 *      keyid                 [in] An identifier of public key.
 * @param
 *      force                 [in] True, must to remove key; false, if key
 *                                 is authentication or authorization key, not to remove.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_RemovePublicKey(DIDDocumentBuilder *builder,
        DIDURL *keyid, bool force);

/**
 * \~English
 * Add public key to Authenticate.
 * Authentication is the mechanism by which the controller(s) of a DID can
 * cryptographically prove that they are associated with that DID.
 * A DID Document must include an authentication property.
 *
 * @param
 *      builder               [in] A handle to DIDDocument Builder.
 * @param
 *      keyid                 [in] An identifier of public key.
 * @param
 *      key                   [in] Key property depend on key type.
 *                             If 'keyid' is from pk array, 'key' can be null.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_AddAuthenticationKey(DIDDocumentBuilder *builder,
        DIDURL *keyid, const char *key);

/**
 * \~English
 * Remove authentication key from Authenticate.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      keyid                [in] An identifier of public key.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_RemoveAuthenticationKey(DIDDocumentBuilder *builder,
        DIDURL *keyid);

/**
 * \~English
 * Add public key to authorizate.
 * Authorization is the mechanism used to state
 * how operations may be performed on behalf of the DID subject.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      keyid                [in] An identifier of authorization key.
 * @param
 *      controller           [in] A controller property, identifies
 *                              the controller of the corresponding private key.
 *                              If 'keyid' is from pk array, 'controller' can be null.
 * @param
 *      key                  [in] Key property depend on key type.
 *                              If 'keyid' is from pk array, 'key' can be null.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_AddAuthorizationKey(DIDDocumentBuilder *builder,
        DIDURL *keyid, DID *controller, const char *key);

/**
 * \~English
 * Add Authorization key to Authentication array according to DID.
 * Authentication is the mechanism by which the controller(s) of a DID can
 * cryptographically prove that they are associated with that DID.
 * A DID Document must include an authentication property.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      keyid                [in] An identifier of public key.
 * @param
 *      controller           [in] A controller property, identifies
 *                              the controller of the corresponding private key.
 * @param
 *      authorkeyid          [in] An identifier of authorization key.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_AuthorizeDid(DIDDocumentBuilder *builder,
        DIDURL *keyid, DID *controller, DIDURL *authorkeyid);

/**
 * \~English
 * Remove authorization key from authorizate.
 *
 * @param
 *      builder               [in] A handle to DIDDocument Builder.
 * @param
 *      keyid                 [in] An identifier of authorization key.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_RemoveAuthorizationKey(DIDDocumentBuilder *builder,
        DIDURL *keyid);


/**
 * \~English
 * Add one credential to credential array.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      credential           [in] The handle to Credential.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_AddCredential(DIDDocumentBuilder *builder,
        Credential *credential);

/**
 * \~English
 * Remove specified credential from credential array.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      credid               [in] An identifier of Credential.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_RemoveCredential(DIDDocumentBuilder *builder,
        DIDURL *credid);

/**
 * \~English
 * Directly, add self claimed information(credential).
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      credid               [in] The handle to DIDURL.
 * @param
 *      types                [in] The array of credential types.
 *                                Support types == NULL，api add 'SelfProclaimedCredential' type.
 * @param
 *      typesize             [in] The size of credential types.
 * @param
 *      properties           [in] The array of credential subject property.
 * @param
 *      propsize             [in] The size of credential subject property.
 * @param
 *      expires              [in] The time to credential be expired.
 *                               Support expires == 0, api add document expires time.
 * @param
 *      signkey              [in] The key to sign.
 *                                eg, if signkey is NULL, it uses the default key.
 * @param
 *      storepass            [in] Password for DIDStores.
 * @return
 *      If no error occurs, return 0.
 *      Otherwise, return -1.
 */
/* DID_API */ int DIDDocumentBuilder_AddSelfProclaimedCredential(DIDDocumentBuilder *builder,
        DIDURL *credid, const char **types, size_t typesize,
        Property *properties, int propsize, time_t expires, DIDURL *signkey, const char *storepass);

/**
 * \~English
 * Directly, renew self proclaimed credentials signed by controller. Use signkey to sign
 * the new credential.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      controller           [in] The old credential signed by controller.
 * @param
 *      signkey              [in] The key to sign.
 *                                eg, if signkey is NULL, it uses the default key.
 * @param
 *      storepass            [in] Password for DIDStores.
 * @return
 *      If no error occurs, return 0. Otherwise, return -1.
 */
/* DID_API */ int DIDDocumentBuilder_RenewSelfProclaimedCredential(DIDDocumentBuilder *builder,
        DID *controller, DIDURL *signkey, const char *storepass);

/**
 * \~English
 * Directly, remove self proclaimed credetial signed by controller.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      controller           [in] The old credential signed by controller.
 * @return
 *      If no error occurs, return 0. sOtherwise, return -1.
 */
/* DID_API */ int DIDDocumentBuilder_RemoveSelfProclaimedCredential(DIDDocumentBuilder *builder,
        DID *controller);

/**
 * \~English
 * Add one Service to services array.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      serviceid            [in] The identifier of Service.
 * @param
 *      type                 [in] The type of Service.
 * @param
 *      endpoint             [in] ServiceEndpoint property is a valid URI.
 * @param
 *      properties           [in] The extra property by user provided, it can NULL.
 * @param
 *      size                 [in] The size of properties.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_AddService(DIDDocumentBuilder *builder,
        DIDURL *serviceid, const char *type, const char *endpoint,
        Property *properties, int size);

/**
 * \~English
 * Add one Service to services array.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      serviceid            [in] The identifier of Service.
 * @param
 *      type                 [in] The type of Service.
 * @param
 *      endpoint             [in] ServiceEndpoint property is a valid URI.
 * @param
 *      properties           [in] The extra properties string by user provided, it can NULL.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/*DID_API*/ int DIDDocumentBuilder_AddServiceByString(DIDDocumentBuilder *builder,
        DIDURL *serviceid, const char *type, const char *endpoint,
        const char *properties);

/**
 * \~English
 * Remove specified Service to services array.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      serviceid            [in] The identifier of Service.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_RemoveService(DIDDocumentBuilder *builder,
        DIDURL *serviceid);

/**
 * \~English
 * Remove proof signed by controller.
 *
 * @param
 *      builder              [in] A handle to DIDDocument Builder.
 * @param
 *      controller           [in] Remove the proof signed by controller.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_RemoveProof(DIDDocumentBuilder *builder,
        DID *controller);

/**
 * \~English
 * Set expire time about DID Document.
 *
 * @param
 *      builder             [in] A handle to DIDDocument Builder.
 * @param
 *      expires             [in] time to expire.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_SetExpires(DIDDocumentBuilder *builder, time_t expires);

/**
 * \~English
 * Set multisig for customized did.
 *
 * @param
 *      builder             [in] A handle to DIDDocument Builder.
 * @param
 *      multisig            [in] The multisig number.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocumentBuilder_SetMultisig(DIDDocumentBuilder *builder, int multisig);

/**
 * \~English
 * Get multisig for customized did.
 *
 * @param
 *      document             [in] A handle to DIDDocument.
 * @return
 *      return 0 if DID is normal DID or customized did has one controller;
 *      return multisig number if customized did has multiple controller;
 *      return -1 if an error occurred.
 */
/* DID_API */ int DIDDocument_GetMultisig(DIDDocument *document);
/**
 * \~English
 * Get the count of controllers. The customized DID Document has controller, so the controller
 * is optional.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      size of controllers on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetControllerCount(DIDDocument *document);

/**
 * \~English
 * Get the array of controllers. A DID Document MAY include a controller property.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      controllers          [out] The buffer that will receive the controllers.
 * @param
 *      size                 [in] The buffer size of controllers.
 * @return
 *      size of controllers on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetControllers(DIDDocument *document,
        DID **controllers, size_t size);

/**
 * \~English
 * Indicate that document contains controller or not.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      controller           [in] The controller to be removed.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, document doesn't contain controller;
 *      return value = 1, document contains controller.
 */
/* DID_API */ int DIDDocument_ContainsController(DIDDocument *document, DID *controller);

/**
 * \~English
 * Get the count of public keys. A DID Document must include a publicKey property.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      size of public keys on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetPublicKeyCount(DIDDocument *document);

/**
 * \~English
 * Get the array of public keys. A DID Document MAY include a publicKey property.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      pks                  [out] The buffer that will receive the public keys.
 * @param
 *      size                 [in] The buffer size of pks.
 * @return
 *      size of public keys on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetPublicKeys(DIDDocument *document,
        PublicKey **pks, size_t size);

/**
 * \~English
 * Get public key according to identifier of public key.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      keyid                [in] An identifier of public key.
 * @return
 *      If no error occurs, return the handle to public key.
 *      Otherwise, return NULL
 */
/* DID_API */ PublicKey *DIDDocument_GetPublicKey(DIDDocument *document, DIDURL *keyid);

/**
 * \~English
 * Get public key conforming to type or identifier.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      type                 [in] The type of public key to be selected.
 * @param
 *      keyid                [in] An identifier of public key to be selected.
 * @param
 *      pks                  [out] The buffer that will receive the public keys.
 * @param
 *      size                 [in] The buffer size of pks.
 * @return
 *      size of public keys selected on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_SelectPublicKeys(DIDDocument *document, const char *type,
        DIDURL *keyid, PublicKey **pks, size_t size);

/**
 * \~English
 * Get primary public key, which is for creating method specific string.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      If no error occurs, return the handle to identifier.
 *      Otherwise, return NULL
 */
/* DID_API */ DIDURL *DIDDocument_GetDefaultPublicKey(DIDDocument *document);

/**
 * \~English
 * Get the count of authentication keys.
 * A DID Document must include a authentication property.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      size of authentication keys on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetAuthenticationCount(DIDDocument *document);

/**
 * \~English
 * Get the array of authentication keys.
 * A DID Document must include a authentication property.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      pks                  [out] The buffer that will receive
 *                                 the authentication keys.
 * @param
 *      size                 [in] The buffer size of pks.
 * @return
 *      size of authentication keys on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetAuthenticationKeys(DIDDocument *document,
        PublicKey **pks, size_t size);

/**
 * \~English
 * Get authentication key according to identifier of authentication key.
 * A DID Document must include a authentication property.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      keyid                [in] An identifier of authentication key.
 * @return
 *       If no error occurs, return the handle to public key.
 *       Otherwise, return NULL
 */
/* DID_API */ PublicKey *DIDDocument_GetAuthenticationKey(DIDDocument *document, DIDURL *keyid);

/**
 * \~English
 * Get authentication key conforming to type or identifier of key.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      type                 [in] The type of authentication key to be selected.
 * @param
 *      keyid                [in] An identifier of authentication key to be selected.
 * @param
 *      pks                  [out] The buffer that will receive the authentication keys.
 * @param
 *      size                 [in] The buffer size of pks.
 * @return
 *      size of authentication key selected, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_SelectAuthenticationKeys(DIDDocument *document, const char *type,
        DIDURL *keyid, PublicKey **pks, size_t size);


/**
 * \~English
 * Check key if authentiacation key or not.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      keyid                [in] An identifier of authentication key.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, signkey isn't authentication key;
 *      return value = 1, signkey is authentication key.

 */
/* DID_API */ int DIDDocument_IsAuthenticationKey(DIDDocument *document, DIDURL *keyid);

/**
 * \~English
 * Check key if authorization key or not.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      keyid                [in] An identifier of authorization key.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, signkey isn't authorization key;
 *      return value = 1, signkey is authorization key.
 */
/* DID_API */ int DIDDocument_IsAuthorizationKey(DIDDocument *document, DIDURL *keyid);

/**
 * \~English
 * Get the count of authorization keys.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      size of authorization keys on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetAuthorizationCount(DIDDocument *document);

/**
 * \~English
 * Get the array of authorization keys.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      pks                  [out] The buffer that will receive
 *                                 the authorization keys.
 * @param
 *      size                 [in] The buffer size of pks.
 * @return
 *      size of authorization keys on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetAuthorizationKeys(DIDDocument *document,
        PublicKey **pks, size_t size);

/**
 * \~English
 * Get authorization key according to identifier of key.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      keyid                [in] An identifier of authorization key.
 * @return
 *       If no error occurs, return the handle to public key.
 *       Otherwise, return NULL
 */
/* DID_API */ PublicKey *DIDDocument_GetAuthorizationKey(DIDDocument *document, DIDURL *keyid);

/**
 * \~English
 * Get authorization key conforming to type or identifier of key.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      type                 [in] The type of authorization key to be selected.
 * @param
 *      keyid                [in] An identifier of authorization key to be selected.
 * @param
 *      pks                  [out] The buffer that will receive the authorization keys.
 * @param
 *      size                 [in] The buffer size of pks.
 * @return
 *      size of authorization key selected, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_SelectAuthorizationKeys(DIDDocument *document, const char *type,
        DIDURL *keyid, PublicKey **pks, size_t size);


/**
 * \~English
 * Get the count of credentials.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      size of credentials on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetCredentialCount(DIDDocument *document);

/**
 * \~English
 * Get the array of credentials.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      creds                [out] The buffer that will receive credentials.
 * @param
 *      size                 [in] The buffer size of creds.
 * @return
 *      size of credentials on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetCredentials(DIDDocument *document,
        Credential **creds, size_t size);

/**
 * \~English
 * Get credential according to identifier of credential.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      credid               [in] An identifier of Credential.
 * @return
 *       If no error occurs, return the handle to Credential.
 *       Otherwise, return NULL
 */
/* DID_API */ Credential *DIDDocument_GetCredential(DIDDocument *document, DIDURL *credid);

/**
 * \~English
 * Get Credential conforming to type or identifier of key.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      type                 [in] The type of Credential.
 * @param
 *      credid               [in] An identifier of Credential to be selected.
 * @param
 *      creds                [out] The buffer that will receive credentials.
 * @param
 *      size                 [in] The buffer size of creds.
 * @return
 *      size of credentials selected, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_SelectCredentials(DIDDocument *document, const char *type,
        DIDURL *credid, Credential **creds, size_t size);


/**
 * \~English
 * Get the count of services.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      size of services on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetServiceCount(DIDDocument *document);

/**
 * \~English
 * Get the array of services.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      services             [out] The buffer that will receive services.
 * @param
 *      size                 [in] The buffer size of services.
 * @return
 *      size of services on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetServices(DIDDocument *document, Service **services,
        size_t size);

/**
 * \~English
 * Get Service according to identifier of Service.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      serviceid            [in] An identifier of Service.
 * @return
 *       If no error occurs, return the handle to Service.
 *       Otherwise, return NULL
 */
/* DID_API */ Service *DIDDocument_GetService(DIDDocument *document, DIDURL *serviceid);

/**
 * \~English
 * Get Service conforming to type or identifier of key.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @param
 *      type                 [in] The type of Service.
 * @param
 *      serviceid            [in] An identifier of Service to be selected.
 * @param
 *      services             [out] The buffer that will receive services.
 * @param
 *      size                 [in] The buffer size of services.
 * @return
 *      size of services selected, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_SelectServices(DIDDocument *document, const char *type,
        DIDURL *serviceid, Service **services, size_t size);

/**
 * \~English
 * Get expire time about DID Document.
 *
 * @param
 *      document             [in] A handle to DID Document.
 * @return
 *      expire time on success, 0 if failed.
 */
/* DID_API */ time_t DIDDocument_GetExpires(DIDDocument *document);

/**
 * \~English
 * Create a new DID Document and store in the DID Store by customized string.
 *
 * @param
 *      document                  [in] The controller document.
 *                                the first signer for customized did.
 * @param
 *      customizeddid              [in] The nickname of DID.
 *                                     'customizeddid' supports NULL.
 * @param
 *      controllers               [out] The controllers for customized DID.
 * @param
 *      size                      [in] The count of controllers.
 * @param
 *      multisig                  [in] Multisig number.
 * @param
 *      force                     [in] Force mode.
 * @param
 *      storepass                 [in] Password for DIDStore stored controller's document.
 * tip: if the count of controllers is one, 'controller' supports NULL. Otherwise,
 * the error occures.
 * @return
 *      If no error occurs, return the handle to customized DID Document.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDDocument *DIDDocument_NewCustomizedDID(DIDDocument *document,
        const char *customizeddid, DID **controllers, size_t size, int multisig,
        bool force, const char *storepass);

/**
 * \~English
 * Sign data by DID.
 *
 * @param
 *      document                 [in] The handle to DID Document.
 * @param
 *      keyid                    [in] Public key to sign.
 *                                   If key = NULL, sdk will get default key from
 *                                   DID Document.
 * @param
 *      storepass                [in] The password for DIDStore.
 * @param
 *      sig                      [out] The buffer will receive signature data.
 * @param
 *      count                    [in] The size of data list.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocument_Sign(DIDDocument *document, DIDURL *keyid, const char *storepass,
        char *sig, int count, ...);

/**
 * \~English
 * Sign digest by DID.
 *
 * @param
 *      document                 [in] The handle to DID Document.
 * @param
 *      keyid                    [in] Public key to sign.
 *                               If keyid is null, then will sign with
 *                               the default key of this DID document.
 * @param
 *      storepass                [in] The password for DIDStore.
 * @param
 *      sig                      [out] The buffer will receive signature data.
 * @param
 *      digest                   [in] The digest to sign.
  * @param
 *      size                     [in] The length of digest array.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocument_SignDigest(DIDDocument *document, DIDURL *keyid,
        const char *storepass, char *sig, uint8_t *digest, size_t size);

/**
 * \~English
 * verify data.
 *
 * @param
 *      document                [in] The handle to DID Document.
 * @param
 *      keyid                   [in] Public key to sign.
 *                                   If key = NULL, sdk will get default key from
 *                                   DID Document.
 * @param
 *      sig                     [in] Signature data.
 * @param
 *      count                   [in] The size of data list.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocument_Verify(DIDDocument *document, DIDURL *keyid, char *sig,
        int count, ...);
/**
 * \~English
 * verify digest.
 *
 * @param
 *      document                [in] The handle to DID Document.
 * @param
 *      keyid                   [in] Public key to sign.
 *                                   If key = NULL, sdk will get default key from
 *                                   DID Document.
 * @param
 *      sig                     [in] Signature data.
 * @param
 *      digest                   [in] The digest to sign.
  * @param
 *      size                     [in] The length of digest array.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocument_VerifyDigest(DIDDocument *document, DIDURL *keyid,
        char *sig, uint8_t *digest, size_t size);

/**
 * \~English
 * Get DIDMetadata from DID.
 *
 * @param
 *      document                 [in] The handle to DIDDocument.
 * @return
 *      If no error occurs, return the handle to DIDMetadata.
 *      Otherwise, return NULL.
 */
/* DID_API */ DIDMetadata *DIDDocument_GetMetadata(DIDDocument *document);

/**
 * \~English
 * Get the signer count.
 *
 * @param
 *      document                    [in] The handle to DIDDocument.
 * @return
 *      Return  on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t DIDDocument_GetProofCount(DIDDocument *document);

/**
 * \~English
 * Get the type property of embedded proof.
 *
 * @param
 *      document                 [in] A handle to DID Document.
 * @param
 *      index                    [in] Index number.
 * @return
 *      If no error occurs, return type string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *DIDDocument_GetProofType(DIDDocument *document, int index);

/**
 * \~English
 * Get verification method identifier of DIDDocument.
 * The verification Method property specifies the public key
 * that can be used to verify the digital signature.
 *
 * @param
 *      document                 [in] A handle to DID Document.
 * @param
 *      index                    [in] Index number.
 * @return
 *      If no error occurs, return the handle to identifier of public key.
 *      Otherwise, return NULL.
 */
/* DID_API */ DIDURL *DIDDocument_GetProofCreater(DIDDocument *document, int index);

/**
 * \~English
 * Get time of create DIDDocument proof.
 *
 * @param
 *      document                 [in] A handle to DID Document.
 * @param
 *      index                    [in] Index number.
 * @return
 *      If no error occurs, return 0.
 *      Otherwise, return time.
 */
/* DID_API */ time_t DIDDocument_GetProofCreatedTime(DIDDocument *document, int index);

/**
 * \~English
 * Get signature of DIDDocument.
 * A signature that can be later used to verify the authenticity and
 * integrity of a linked data document.
 *
 * @param
 *      document                 [in] A handle to DID Document.
 * @param
 *      index                    [in] Index number.
 * @return
 *      If no error occurs, return signature string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *DIDDocument_GetProofSignature(DIDDocument *document, int index);

/**
 * \~English
 * Get JWTBuilder from document.
 *
 * @param
 *      document                 [in] A handle to DID Document.
 *                                ps：document must attatch DIDstore.
 * @return
 *      If no error occurs, return the handle to JWTBuilder.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ JWTBuilder *DIDDocument_GetJwtBuilder(DIDDocument *document);
/**
 * \~English
 * Get JWSParser from document.
 *
 * @param
 *      document                 [in] A handle to DID Document.
 *                                    Support document is NULL.
 * @return
 *      If no error occurs, return the handle to JWSParser.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/*DID_API*/ JWSParser *DIDDocument_GetJwsParser(DIDDocument *document);

/**
 * \~English
 * Derive the default key of document by identifier and securityCode.
 *
 * @param
 *      document                 [in] A handle to primitive DID Document.
 *                                ps：document must attatch DIDstore.
 * @param
 *      identifier                [in] Application secified identifier.
 * @param
 *      securityCode              [in] User specified security code.
 * @param
 *      storepass                 [in] The password for DIDStore.
 * @return
 *      If no error occurs, return serialize HDKey string. Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/*DID_API*/ const char *DIDDocument_DeriveByIdentifier(DIDDocument *document, const char *identifier,
        int securityCode, const char *storepass);

/**
 * \~English
 * Derive the default key of document by index.
 *
 * @param
 *      document                  [in] A handle to primitive DID Document.
 *                                ps：document must attatch DIDstore.
 * @param
 *      index                     [in] The index.
 * @param
 *      storepass                 [in] The password for DIDStore.
 * @return
 *      If no error occurs, return serialize HDKey string. Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/*DID_API*/ const char *DIDDocument_DeriveByIndex(DIDDocument *document, int index,
        const char *storepass);

/**
 * \~English
 * Get document by multiple signature.
 *
 * @param
 *      controllerdoc            [in] The handle to controller's document.
 * @param
 *      document                 [in] The document string to be signed.
 * @param
 *      storepass                [in] The password for DIDStore.
 * @return
 *      the handle to new document if no error occurred and user should be destory the returned value.
 */
/* DID_API */ DIDDocument *DIDDocument_SignDIDDocument(DIDDocument* controllerdoc,
        const char *document, const char *storepass);

/**
 * \~English
 * Merge the several document.
 *
 * @param
 *      count                    [in] The count of idrequest string.
 * @return
 *      document string if no error occurred and user should be free the returned value.
 */
/* DID_API */ const char *DIDDocument_MergeDIDDocuments(int count, ...);

/**
 * \~English
 * Controller create transfer ticket by document.
 *
 * @param
 *      controllerdoc           [in] The handle to controller's Document.
 * @param
 *      owner                   [in] The owner of transfer ticket.
 * @param
 *      to                      [in] The DID who received this ticket.
 * @param
 *      storepass               [in] The password for DIDStore.
 * @return
 *      the handle to ticket if no error occurred and user should be destroy the returned value.
 */
/* DID_API */ TransferTicket *DIDDocument_CreateTransferTicket(DIDDocument *controllerdoc,
        DID *owner, DID *to, const char *storepass);

/**
 * \~English
 * Realize multi-signature for transfer ticket.
 *
 * @param
 *      controllerdoc           [in] The handle to controller's document.
 * @param
 *      ticket                  [in] The handle of transfer ticket.
 * @param
 *      storepass               [in] The password for DIDStore.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDDocument_SignTransferTicket(DIDDocument *controllerdoc,
        TransferTicket *ticket, const char *storepass);

/**
 * \~English
 * Creates a DID and its associated DID Document to chain.
 *
 * @param
 *      document                 [in] The handle to DIDDocument.
 * @param
 *      signkey                  [in] The public key to sign.
 * @param
 *      force                    [in] Force document into chain.
 * @param
 *      storepass                [in] The password for DIDStore.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, publish did failed;
 *      return value = 1, publish did successfully.
 */
/* DID_API */ int DIDDocument_PublishDID(DIDDocument *document, DIDURL *signkey, bool force,
        const char *storepass);

/**
 * \~English
 * Transfer DID if customized DID had add or remove controller.
 *
 * @param
 *      document                 [in] The handle to DIDDocument.
 * @param
 *      ticket                   [in] The handle to Transfer ticket.
 * @param
 *      signkey                  [in] The public key to sign.
 * @param
 *      storepass                [in] The password for DIDStore.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, transfer did failed;
 *      return value = 1, transfer did successfully.
 */
/* DID_API */ int DIDDocument_TransferDID(DIDDocument *document, TransferTicket *ticket,
        DIDURL *signkey, const char *storepass);

/**
 * \~English
 * Deactivate DID by owner.
 *
 * @param
 *      document                 [in] The handle to DIDDocument.
 * @param
 *      signkey                  [in] The public key to sign.
 * @param
 *      storepass                [in] Password for DIDStore.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, deactivate did failed;
 *      return value = 1, deactivate did successfully.
 */
/* DID_API */ int DIDDocument_DeactivateDID(DIDDocument *document, DIDURL *signkey,
        const char *storepass);

/**
 * \~English
 * Deactivate DID by authorizor.
 *
 * @param
 *      document                 [in] The authorizor's DIDDocument.
 * @param
 *      target                   [in] The DID to be deactivated.
 * @param
 *      signkey                  [in] The public key of authorizor to sign.
 * @param
 *      storepass                [in] Password for DIDStore.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, deactivate did failed;
 *      return value = 1, deactivate did successfully.
 */
/* DID_API */ int DIDDocument_DeactivateDIDByAuthorizor(DIDDocument *document, DID *target,
        DIDURL *signkey, const char *storepass);


/**
 * \~English
 * Get identifier of public key.
 *
 * @param
 *      publickey             [in] A handle to public key.
 * @return
 *      If no error occurs, return the identifier of public key.
 *      Otherwise, return NULL.
 */

/* DID_API */ DIDURL *PublicKey_GetId(PublicKey *publickey);

/**
 * \~English
 * Get DID controller of public key.
 *
 * @param
 *      publickey             [in] A handle to public key.
 * @return
 *      If no error occurs, return the handle to DID controller.
 *      Otherwise, return NULL.
 */
/* DID_API */ DID *PublicKey_GetController(PublicKey *publickey);

/**
 * \~English
 * Get key property of public key.
 *
 * @param
 *      publickey             [in] A handle to public key.
 * @return
 *      If no error occurs, return key property string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *PublicKey_GetPublicKeyBase58(PublicKey *publickey);

/**
 * \~English
 * Get type of public key.
 *
 * @param
 *      publickey             [in] A handle to public key.
 * @return
 *      If no error occurs, return key type string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *PublicKey_GetType(PublicKey *publickey);

/**
 * \~English
 * Publickey is authentication key or not.
 *
 * @param
 *      publickey             [in] A handle to public key.
 * @return
 *      return value = -1, no publickey;
 *      return value = 0, key is authentication key;
 *      return value = 1, key isn't authentication key.
 */
/* DID_API */ int PublicKey_IsAuthenticationKey(PublicKey *publickey);

/**
 * \~English
 * Publickey is authorization key or not.
 *
 * @param
 *      publickey             [in] A handle to public key.
 * @return
 *      return value = -1, no publickey;
 *      return value = 0, key is authorization key;
 *      return value = 1, key isn't authorization key.
 */
/* DID_API */ int PublicKey_IsAuthorizationKey(PublicKey *publickey);

/**
 * \~English
 * Get identifier of Service.
 *
 * @param
 *      service             [in] A handle to Service.
 * @return
 *      If no error occurs, return identifier of service.
 *      Otherwise, return NULL.
 */
/* DID_API */ DIDURL *Service_GetId(Service *service);

/**
 * \~English
 * Get service end point.
 *
 * @param
 *      service             [in] A handle to Service.
 * @return
 *      If no error occurs, return service point string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *Service_GetEndpoint(Service *service);

/**
 * \~English
 * Get type of service.
 *
 * @param
 *      service             [in] A handle to Service.
 * @return
 *      If no error occurs, return service type string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *Service_GetType(Service *service);

/**
 * \~English
 * Get size of extra properties in Service.
 *
 * @param
 *      service                 [in] A handle to Service.
 * @return
 *      size of subject porperties on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t Service_GetPropertyCount(Service *service);

/**
 * \~English
 * Get array of extra properties in Service.
 *
 * @param
 *      service                 [in] A handle to Service.
 * @return
 *      size of extra porperties on success, -1 if an error occurred.
 *      Notice that user need to free the returned value it's memory.
 */
/* DID_API */ const char *Service_GetProperties(Service *service);

/**
 * \~English
 * Get specific property value in string with the given key of property.
 *
 * @param
 *      service              [in] A handle to Service.
 * @param
 *      name                 [in] The key of property.
 * @return
 *      If no error occurs, return property value string, otherwise return NULL.
 *      Notice that user need to free the returned value it's memory.
 */
/* DID_API */ const char *Service_GetProperty(Service *service, const char *name);

/******************************************************************************
 * Credential
 *****************************************************************************/
/**
 * \~English
 * Get json non-formatted context from Credential.
 *
 * @param
 *      cred                 [in] A handle to Credential.
 * @param
 *      normalized           [in] Json context is normalized or not.
 *                           true represents normalized, false represents not.
 * @return
 *      If no error occurs, return json context. Otherwise, return NULL.
 *      Notice that user need to free the returned value that it's memory.
 */
/* DID_API */ const char *Credential_ToJson(Credential *credential , bool normalized);

/**
 * \~English
 * Get json formatted context from Credential.
 *
 * @param
 *      credential           [in] A handle to Credential.
 * @param
 *      normalized           [in] Json context is normalized or not.
 *                           true represents normalized, false represents not.
 * @return
 *      If no error occurs, return json context. Otherwise, return NULL.
 *      Notice that user need to free the returned value that it's memory.
 */
/* DID_API */ const char *Credential_ToString(Credential *credential , bool normalized);

/**
 * \~English
 * Get one DID's Credential from json context.
 *
 * @param
 *      json                 [in] Json context about credential.
 * @param
 *      owner                [in] A handle to credential owner's DID.
 * @return
 *      If no error occurs, return the handle to Credential.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ Credential *Credential_FromJson(const char *json, DID *owner);

/**
 * \~English
 * Destroy Credential.
 *
 * @param
 *      credential            [in] A handle to Credential.
 */
/* DID_API */ void Credential_Destroy(Credential *credential);

/**
 * \~English
 * Check Credential is self claimed or not.
 *
 * @param
 *      credential             [in] A handle to Credential.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, did isn't selfproclaimed;
 *      return value = 1, did is selfproclaimed.
 */
/* DID_API */ int Credential_IsSelfProclaimed(Credential *credential);

/**
 * \~English
 * Get id property from Credential.
 *
 * @param
 *      credential             [in] A handle to Credential.
 * @return
 *      If no error occurs, return id property of credential.
 *      Otherwise, return NULL.
 */
/* DID_API */ DIDURL *Credential_GetId(Credential *credential);

/**
 * \~English
 * Get who this credential is belong to.
 *
 * @param
 *      credential              [in] A handle to Credential.
 * @return
 *      If no error occurs, return owner DID.
 *      Otherwise, return NULL.
 */
/* DID_API */ DID *Credential_GetOwner(Credential *credential);

/**
 * \~English
 * Get count of Credential types.
 *
 * @param
 *      credential              [in] A handle to Credential.
 * @return
 *      size of Credential types on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t Credential_GetTypeCount(Credential *credential);

/**
 * \~English
 * Get array of Credential types.
 *
 * @param
 *      credential           [in] A handle to Credential.
 * @param
 *      types                [out] The buffer that will receive credential types.
  * @param
 *      size                 [in] The buffer size of credential types.
 * @return
 *      size of Credential types on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t Credential_GetTypes(Credential *credential, const char **types, size_t size);

/**
 * \~English
 * Get DID issuer of Credential.
 *
 * @param
 *      credential           [in] A handle to Credential.
 * @return
 *      If no error occurs, return the handle to DID issuer.
 *      Otherwise, return NULL.
 */
/* DID_API */ DID *Credential_GetIssuer(Credential *credential);

/**
 * \~English
 * Get date of issuing credential.
 *
 * @param
 *      credential            [in] A handle to Credential.
 * @return
 *      If no error occurs, return the date.
 *      Otherwise, return 0.
 */
/* DID_API */ time_t Credential_GetIssuanceDate(Credential *credential);

/**
 * \~English
 * Get the date of credential expired.
 *
 * @param
 *      credential             [in] A handle to Credential.
 * @return
 *      If no error occurs, return the time.
 *      Otherwise, return 0.
 */
/* DID_API */ time_t Credential_GetExpirationDate(Credential *credential);

/**
 * \~English
 * Get size of subject properties in Credential.
 * A credential must have a credential Subject property. The value of
 * the credential Subject property is defined as a set of objects that
 * contain one or more properties that are each related to a subject
 * of the credential. Each object must contain an id.
 *
 * @param
 *      credential             [in] A handle to Credential.
 * @return
 *      size of subject porperties on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t Credential_GetPropertyCount(Credential *credential);

/**
 * \~English
 * Get array of subject properties in Credential.
 *
 * @param
 *      credential              [in] A handle to Credential.
 * @return
 *      size of subject porperties on success, -1 if an error occurred.
 *      Notice that user need to free the returned value it's memory.
 */
/* DID_API */ const char *Credential_GetProperties(Credential *credential);

/**
 * \~English
 * Get specific subject property value in string with the given key of property.
 *
 * @param
 *      credential           [in] A handle to Credential.
 * @param
 *      name                 [in] The key of property.
 * @return
 *      If no error occurs, return property value string, otherwise return NULL.
 *      Notice that user need to free the returned value it's memory.
 */
/* DID_API */ const char *Credential_GetProperty(Credential *credential, const char *name);

/**
 * \~English
 * Get created time of credential.
 *
 * @param
 *      credential            [in] A handle to Credential.
 * @return
 *      If no error occurs, return created time. otherwise, return 0.
 */
/* DID_API */ time_t Credential_GetProofCreatedTime(Credential *credential);

/**
 * \~English
 * Get verification method identifier of Credential.
 * The verification method property specifies the public key
 * that can be used to verify the digital signature.
 *
 * @param
 *      credential              [in] A handle to Credential.
 * @return
 *      If no error occurs, return the handle to identifier of public key.
 *      Otherwise, return NULL.
 */
/* DID_API */ DIDURL *Credential_GetProofMethod(Credential *credential);

/**
 * \~English
 * Get the type property of embedded proof.
 *
 * @param
 *      credential            [in] A handle to Credential.
 * @return
 *      If no error occurs, return type string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *Credential_GetProofType(Credential *credential);

/**
 * \~English
 * Get signature of Credential.
 * A signature that can be later used to verify the authenticity and
 * integrity of a linked data document.
 *
 * @param
 *      credential            [in] A handle to Credential.
 * @return
 *      If no error occurs, return signature string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *Credential_GetProofSignture(Credential *credential);

/**
 * \~English
 * Credential is expired or not.
 * Issuance always occurs before any other actions involving a credential.
 *
 * @param
 *      credential             [in] The Credential handle.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, credentil isn't expired;
 *      return value = 1, credentil is expired.
 */
/* DID_API */ int Credential_IsExpired(Credential *credential);

/**
 * \~English
 * Credential is genuine or not.
 * Issuance always occurs before any other actions involving a credential.
 *
 * @param
 *      credential              [in] The Credential handle.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, credentil isn't genuine;
 *      return value = 1, credentil is genuine.
 */
/* DID_API */ int Credential_IsGenuine(Credential *credential);

/**
 * \~English
 * Credential is expired or not.
 * Issuance always occurs before any other actions involving a credential.
 *
 * @param
 *      credential             [in] The Credential handle.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, credentil isn't valid;
 *      return value = 1, credentil is valid.
 */
/* DID_API */ int Credential_IsValid(Credential *credential);

/**
 * \~English
 * Declare a credential to chain.
 *
 * @param
 *      credential               [in] The handle to Credential.
 * @param
 *      signkey                  [in] The public key to sign.
 * @param
 *      storepass                [in] The password for DIDStore.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, declare credential failed;
 *      return value = 1, declare credential successfully.
 */
/* DID_API */ int Credential_Declare(Credential *credential, DIDURL *signkey, const char *storepass);

/**
 * \~English
 * Revoke credential to chain.
 *
 * @param
 *      credential               [in] The handle to Credential.
 * @param
 *      signkey                  [in] The public key to sign.
 *                               signkey can be owner's public key or issuer's public key.
 * @param
 *      storepass                [in] The password for DIDStore.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, revoke credential failed;
 *      return value = 1, revoke credential successfully.
 */
/* DID_API */ int Credential_Revoke(Credential *credential, DIDURL *signkey, const char *storepass);

/**
 * \~English
 * Revoke credential to chain.
 *
 * @param
 *      id                       [in] The id of Credential.
  * @param
 *      document                 [in] The document of DID to revoke credential.
 * @param
 *      signkey                  [in] The public key of document.
 * @param
 *      storepass                [in] The password for DIDStore.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, revoke credential failed;
 *      return value = 1, revoke credential successfully.
 */
/* DID_API */ int Credential_RevokeById(DIDURL *id, DIDDocument *document, DIDURL *signkey,
        const char *storepass);
/**
 * \~English
 * Get the lastest credential from the chain.
 *
 * @param
 *      id                     [in] The id of credential to resolve.
 * @param
 *      status                 [in] The status of credential.
 * @param
 *      force                  [in] Indicate if load document from cache or not.
 *                               force = true, document gets only from chain.
 *                               force = false, document can get from cache,
 *                               if no document is in the cache, resolve it from chain.
 * @return
 *      If no error occurs, return the handle to Credential.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ Credential *Credential_Resolve(DIDURL *id, int *status, bool force);

/**
 * \~English
 * Check if the credential is revoked by the specified DID.
 *
 * @param
 *      id                     [in] The id of credential to resolve.
 * @param
 *      issuer                 [in] The DID to issue this credential.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, credential isn't revoked by issuer;
 *      return value = 1, credential is revoked by issuer.
 */
/* DID_API */ int Credential_ResolveRevocation(DIDURL *id, DID *issuer);

/**
 * \~English
 * Resolve all Credential transactions.
 *
 * @param
 *      id                     [in] The id of credential to resolve.
 * @param
 *      issuer                 [in] The DID to issue this credential.
 * @return
 *      If the credential has valid transactions, return the handle to CredentialBiography.
 *      Otherwise, return NULL.
 */
/* DID_API */ CredentialBiography *Credential_ResolveBiography(DIDURL *id, DID *issuer);

/**
 * \~English
 * Indicate the credential was ever declared in the chain. Whatever the current status of
 * credetial is.
 *
 * @param
 *      id                     [in] The id of credential to resolve.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, credential isn't declared;
 *      return value = 1, credential is declared.
 */
/* DID_API */ int Credential_WasDeclared(DIDURL *id);

/**
 * \~English
 * Indicate the credential is revoked or not.
 *
 * @param
 *      credential             [in] The handle of credential.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, credential isn't revoked;
 *      return value = 1, credential is revoked.
 */
/* DID_API */ int Credential_IsRevoked(Credential *credential);

/**
 * \~English
 * Get credentials owned by did.
 *
 * @param
 *      did                      [in] The handle of DID.
 * @param
 *      buffer                   [out] The buffer to store credentials' id.
 * @param
 *      size                     [in] The size of buffer.
 * @param
 *      skip                     [in] The index of beginning credential.
 * @param
 *      limit                    [in] The size of credentials to listed.
 *                               If limit == 0, and the count of credentials is more than
 *                               128, return 128. You can reset 'skip' to get other credentials.
 *                               If limit > 512, and the count of credentials is more than
 *                               512, return 512. You can reset 'skip' to get other credentials.
 * @return
 *      If no error occurs, return the size of credentials. Remember: destory every 'DIDURL'
 *      object in buffer. Otherwise, return -1.
 */
/* DID_API */ ssize_t Credential_List(DID *did, DIDURL **buffer, size_t size, int skip, int limit);

/**
 * \~English
 * Get credential alias.
 *
 * @param
 *      credential             [in] The handle to Credential.
 * @return
 *      If no error occurs, return alias string.
 *      Otherwise, return NULL.
 */
/* DID_API */ CredentialMetadata *Credential_GetMetadata(Credential *cred);

/******************************************************************************
 * Issuer
 *****************************************************************************/
/**
 * \~English
 * Create a issuer to issue Credential.
 *
 * @param
 *      did                      [in] Issuer's did.
 * @param
 *      signkey                  [in] Issuer's key to sign credential.
 * @param
 *      store                    [in] The handle to DIDStore.
 * @return
 *      If no error occurs, return the handle to Issuer. Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ Issuer *Issuer_Create(DID *did, DIDURL *signkey, DIDStore *store);

/**
 * \~English
 * Destroy a issuer.
 *
 * @param
 *      issuer                    [in] the handle of Issuer..
 */
/* DID_API */ void Issuer_Destroy(Issuer *issuer);

/**
 * \~English
 * An issuer issues a verifiable credential to a holder with subject object.
 *
 * @param
 *      issuer               [in] An issuer issues this credential.
 * @param
 *      owner                [in] A handle to DID.
 *                               The holder of this Credential.
 * @param
 *      credid               [in] The handle to DIDURL.
 * @param
 *      types                [in] The array of credential types.
 * @param
 *      typesize             [in] The size of credential types.
 * @param
 *      subject              [in] The array of credential subject property.
 * @param
 *      size                 [in] The size of credential subject property.
 * @param
 *      expires              [in] The time to credential be expired.
 * @param
 *      storepass            [in] The password for DIDStore.
 * @return
 *      If no error occurs, return the handle to Credential issued.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ Credential *Issuer_CreateCredential(Issuer *issuer, DID *owner, DIDURL *credid,
        const char **types, size_t typesize, Property *subject, int size,
        time_t expires, const char *storepass);

/**
 * \~English
 * An issuer issues a verifiable credential to a holder with subject string.
 *
 * @param
 *      issuer               [in] An issuer issues this credential.
 * @param
 *      owner                [in] A handle to DID.
 *                               The holder of this Credential.
 * @param
 *      credid               [in] The handle to DIDURL.
 * @param
 *      types                [in] The array of credential types.
 * @param
 *      typesize             [in] The size of credential types.
 * @param
 *      subject              [in] The array of credential subject property.
 * @param
 *      expires              [in] The time to credential be expired.
 * @param
 *      storepass            [in] The password for DIDStore.
 * @return
 *      If no error occurs, return the handle to Credential issued.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ Credential *Issuer_CreateCredentialByString(Issuer *issuer, DID *owner,
        DIDURL *credid, const char **types, size_t typesize, const char *subject,
        time_t expires, const char *storepass);

/**
 * \~English
 * Get the DID of this issuer
 *
 * @param
 *      issuer                  [in] The handle to Issuer.
 * @return
 *      If no error occurs, return the handle to DID of this issuer.
 *      Otherwise, return NULL.
 */
/* DID_API */ DID *Issuer_GetSigner(Issuer *issuer);

/**
 * \~English
 * Get the DID of this issuer
 *
 * @param
 *      issuer                  [in] The handle to Issuer.
 * @return
 *      If no error occurs, return the handle to key.
 *      Otherwise, return NULL.
 */
/* DID_API */ DIDURL *Issuer_GetSignKey(Issuer *issuer);

/******************************************************************************
 * DIDStore
 *****************************************************************************/
/**
 * \~English
 * Initialize or check the DIDStore.
 *
 * @param
 *      root                 [in] The path of DIDStore's root.
 * @return
 *      If no error occurs, return the handle to DID Store. Otherwise, return NULL.
 */
/* DID_API */ DIDStore* DIDStore_Open(const char *root);

/**
 * \~English
 * Deinitialize DIDStore.
 *
 * @param
 *      store                 [in] The handle to DIDStore.
 */
/* DID_API */ void DIDStore_Close(DIDStore *store);
/**
 * \~English
 * Check if it has the specified root identity or not.
 *
 * @param
 *      store                 [in] The handle to DIDStore.
  * @param
 *      id                    [in] The specified root identity's id.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, didstore doestn't contain rootidentiy;
 *      return value = 1, didstore contains rootidentiy.
 */
/* DID_API */ int DIDStore_ContainsRootIdentity(DIDStore *store, const char *id);

/**
 * \~English
 * Check if it has root identity or not.
 *
 * @param
 *      store                 [in] The handle to DIDStore.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, there isn't rootidentity in didstore;
 *      return value = 1, there is rootidentity in didstore.
 */
/* DID_API */ int DIDStore_ContainsRootIdentities(DIDStore *store);

/**
 * \~English
 * Load the specified RootIdentity.
 *
 * @param
 *      store                 [in] The handle to DIDStore.
 * @param
 *      id                    [in] The id string.
 * @return
 *      the handle to RootIdentity if success, NULL if failed.
 */
/* DID_API */ RootIdentity *DIDStore_LoadRootIdentity(DIDStore *store, const char *id);

/**
 * \~English
 * Delete the specified RootIdentity.
 *
 * @param
 *      store                 [in] The handle to DIDStore.
 * @param
 *      id                    [in] The id string.
 * @return
 *      ture if delete rootidentity is successfully, false if failed.
 */
/* DID_API */ bool DIDStore_DeleteRootIdentity(DIDStore *store, const char *id);

/**
 * \~English
 * Check if contain specific RootIdentity's mnemonic or not.
 *
 * @param
 *      store                 [in] The handle to DIDStore.
 * @param
 *      id                    [in] The id string.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, there isn't rootidentity's mnemonic in didstore;
 *      return value = 1, there is rootidentity's mnemonic in didstore.
 */
/* DID_API */ int DIDStore_ContainsRootIdentityMnemonic(DIDStore *store, const char *id);

/**
 * \~English
 * List all root identities in DIDStore.
 *
 * @param
 *      store                 [in] The handle to DIDStore.
 * @param
 *      callback              [in] A pointer to DIDStore_RootIdentitiesCallback function.
 * @param
 *      context               [in] The application defined context data.
 * @return
 *      the count of root identities if success, -1 if an error occurred
 */
/* DID_API */ ssize_t DIDStore_ListRootIdentities(DIDStore *store,
        DIDStore_RootIdentitiesCallback *callback, void *context);

/**
 * \~English
 * Get default rootidentity from DIDStore.
 *
 * @param
 *      store                [in] The handle to DIDStore.
 * @return
 *      root identity's id string on success, NULL if an error occurred.
 *      Notice that user need to free the returned value.
 */
/* DID_API */ const char *DIDStore_GetDefaultRootIdentity(DIDStore *store);

/**
 * \~English
 * Export mnemonic of the specific root identity.
 *
 * @param
 *      store              [in] THe handle to DIDStore.
 * @param
 *      storepass          [in] The password of DIDStore.
 * @param
 *      id                 [in] The string for root identity.
 * @param
 *      mnemonic           [out] The buffer that will receive the mnemonic.
 *                               The buffer size should at least
 *                               (ELA_MAX_MNEMONIC_LEN + 1) bytes.
 * @param
 *      size               [in] The buffter size.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_ExportRootIdentityMnemonic(DIDStore *store, const char *storepass,
        const char *id, char *mnemonic, size_t size);

/**
 * \~English
 * Store DID Document in DID Store.
 *
 * @param
 *      store                     [in] The handle to DIDStore.
 * @param
 *      document                  [in] The handle to DID Document.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_StoreDID(DIDStore *store, DIDDocument *document);

/**
 * \~English
 * Load DID Document from DID Store.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      did                     [in] The handle to DID.
 * @return
 *      If no error occurs, return the handle to DID Document.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ DIDDocument *DIDStore_LoadDID(DIDStore *store, DID *did);

/**
 * \~English
 * Check if contain specific DID or not.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      did                     [in] The handle to DID.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, did isn't in didstore;
 *      return value = 1, did is in didstore.
 */
/* DID_API */ int DIDStore_ContainsDID(DIDStore *store, DID *did);

/**
 * \~English
 * Delete specific DID.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      did                     [in] The handle to DID.
 * @return
 *      true on success, false if an error occurred.
 */
/* DID_API */ bool DIDStore_DeleteDID(DIDStore *store, DID *did);

/**
 * \~English
 * List DIDs in DID Store.
 *
 * @param
 *      store       [in] The handle to DIDStore.
 * @param
 *      filer       [in] DID filer. 0: all did; 1: did has privatekeys;
 *                                  2: did has no privatekeys.
 * @param
 *      callback    [in] a pointer to DIDStore_DIDsCallback function.
 * @param
 *      context     [in] the application defined context data.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_ListDIDs(DIDStore *store, ELA_DID_FILTER filer,
        DIDStore_DIDsCallback *callback, void *context);

/**
 * \~English
 * Store Credential in DID Store.
 *
 * @param
 *      store                    [in] The handle to DIDStore.
 * @param
 *      credential               [in] The handle to Credential.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_StoreCredential(DIDStore *store, Credential *credential);

/**
 * \~English
 * Load Credential from DID Store.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      did                     [in] The handle to DID.
 * @param
 *      credid                   [in] The identifier of credential.
 * @return
 *      If no error occurs, return the handle to Credential.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ Credential *DIDStore_LoadCredential(DIDStore *store, DID *did, DIDURL *credid);

/**
 * \~English
 * Check if contain any credential of specific DID.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      did                     [in] The handle to DID.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, there isn't credential in didstore;
 *      return value = 1, there is credential in didstore.
 */
/* DID_API */ int DIDStore_ContainsCredentials(DIDStore *store, DID *did);

/**
 * \~English
 * Check if contain specific credential of specific DID.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      did                     [in] The handle to DID.
 * @param
 *      credid                  [in] The identifier of credential.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, credential isn't in didstore;
 *      return value = 1, credential is in didstore.
 */
/* DID_API */ int DIDStore_ContainsCredential(DIDStore *store, DID *did, DIDURL *credid);

/**
 * \~English
 * Delete specific credential.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      did                     [in] The handle to DID.
 * @param
 *      id                      [in] The identifier of credential.
 * @return
 *      true on success, false if an error occurred.
 */
/* DID_API */ bool DIDStore_DeleteCredential(DIDStore *store, DID *did, DIDURL *id);

/**
 * \~English
 * List credentials of specific DID.
 *
 * @param
 *      store       [in] The handle to DIDStore.
 * @param
 *      did         [in] The handle to DID.
 * @param
 *      callback    [in] A pointer to DIDStore_CredentialsCallback function.
 * @param
 *      context     [in] The application defined context data.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_ListCredentials(DIDStore *store, DID *did,
        DIDStore_CredentialsCallback *callback, void *context);

/**
 * \~English
 * Get credential conforming to identifier or type property.
 *
 * @param
 *      store       [in] The handle to DIDStore.
 * @param
 *      did         [in] The handle to DID.
 * @param
 *      credid      [in] The identifier of credential.
 * @param
 *      type        [in] The type of Credential to be selected.
 * @param
 *      callback    [in] a pointer to DIDStore_CredentialsCallback function.
 * @param
 *      context     [in] the application defined context data.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_SelectCredentials(DIDStore *store, DID *did, DIDURL *credid,
        const char *type, DIDStore_CredentialsCallback *callback, void *context);

/**
 * \~English
 * Check if contain any private key of specific DID.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      did                     [in] The handle to DID.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, there isn't private key in didstore;
 *      return value = 1, did is deacativated.
 */
/* DID_API */ int DIDSotre_ContainsPrivateKeys(DIDStore *store, DID *did);

/**
 * \~English
 * Check if contain specific private key of specific DID.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      did                     [in] The handle to DID.
 * @param
 *      keyid                   [in] The identifier of public key.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, there isn't private key in didstore;
 *      return value = 1, there is private key in didstore.
 */
/* DID_API */ int DIDStore_ContainsPrivateKey(DIDStore *store, DID *did, DIDURL *keyid);

/**
 * \~English
 * Store private key.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      storepass               [in] Password for DIDStore.
 * @param
 *      id                      [in] The handle to public key identifier.
 * @param
 *      privatekey              [in] Private key string.
 * @param
 *      size                    [in] The bytes of Private key.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_StorePrivateKey(DIDStore *store, const char *storepass,
        DIDURL *id, const uint8_t *privatekey, size_t size);

/**
 * \~English
 * Delete private key.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      keyid                    [in] The identifier of public key.
 */
/* DID_API */ void DIDStore_DeletePrivateKey(DIDStore *store, DIDURL *keyid);

/**
 * \~English
 * Change the store password from old one to new one.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      new                     [in] New store password for DIDStore.
 * @param
 *      old                     [in] Old store password for DIDStore.
 * @return
 *      0 on success, -1 if an error occurred. Caller should free the returned value.
 */
/* DID_API */ int DIDStore_ChangePassword(DIDStore *store, const char *newpw, const char *oldpw);

/**
 * \~English
 * Export DID information into file with json format. The json content include document,
 * credentials, private keys and metadata.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      storepass               [in] Password for DIDStore.
 * @param
 *      did                     [in] The handle to DID.
 * @param
 *      file                    [in] Export file.
 * @param
 *      password                [in] Password to encrypt.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_ExportDID(DIDStore *store, const char *storepass, DID *did,
        const char *file, const char *password);

/**
 * \~English
 * Import DID information by file.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      storepass               [in] Password for DIDStore.
 * @param
 *      file                    [in] Export file.
 * @param
 *      password                [in] Password to encrypt.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_ImportDID(DIDStore *store, const char *storepass,
        const char *file, const char *password);

/**
 * \~English
 * Export private identity information into file with json format.
 * The json content include mnemonic(encrypted), extended private key(encrypted),
 * extended public key(if has it, dont't encrypted) and index.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      storepass               [in] Password for DIDStore.
 * @param
 *      id                      [in] RootIdentity's id string.
 * @param
 *      file                    [in] Export file.
 * @param
 *      password                [in] Password to encrypt.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_ExportRootIdentity(DIDStore *store, const char *storepass,
        const char *id, const char *file, const char *password);
/**
 * \~English
 * Import private identity by file.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      storepass               [in] Password for DIDStore.
 * @param
 *      file                    [in] Export file.
 * @param
 *      password                [in] Password to encrypt.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_ImportRootIdentity(DIDStore *store, const char *storepass,
        const char *file, const char *password);

/**
 * \~English
 * Export whole store information into zip file.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      storepass               [in] Password for DIDStore.
 * @param
 *      zipfile                 [in] Zip file to export.
 * @param
 *      password                [in] Password to encrypt.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_ExportStore(DIDStore *store, const char *storepass,
        const char *zipfile, const char *password);

/**
 * \~English
 * Import zip file into new DIDStore.
 *
 * @param
 *      store                   [in] The handle to DIDStore.
 * @param
 *      storepass               [in] Password for DIDStore.
 * @param
 *      zipfile                 [in] zip file to import.
 * @param
 *      password                [in] Password to encrypt.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDStore_ImportStore(DIDStore *store, const char *storepass,
        const char *zipfile, const char *password);

/******************************************************************************
 * Mnemonic
 *****************************************************************************/
/**
 * \~English
 * Gernerate a random mnemonic.
 *
 * @param
 *      language               [in] The language for DID.
 *                             support language string: "chinese_simplified",
 *                             "chinese_traditional", "czech", "english", "french",
 *                             "italian", "japanese", "korean", "spanish".
 * @return
 *      mnemonic string. Use Mnemonic_free after finish using mnemonic string.
 */
/* DID_API */ const char *Mnemonic_Generate(const char *language);

/**
 * \~English
 * Free mnemonic buffer.
 *
 * @param
 *      mnemonic               [in] mnemonic buffter.
 */
/* DID_API */ void Mnemonic_Free(void *mnemonic);

/**
 * \~English
 * Check mnemonic.
 *
 * @param
 *      mnemonic               [in] mnemonic buffter.
 * @param
 *      language               [in] The language for DID.
 *                             Support languages' string: "english", "french", "spanish",
 *                             "chinese_simplified", "chinese_traditional",
 *                             "japanese", "czech", "italian", "korean".
 * @return
 *      true, if mnemonic is valid. or else, return false.
 */
/* DID_API */ bool Mnemonic_IsValid(const char *mnemonic, const char *language);

/**
 * \~English
 * Get the language name from a mnemonic string and check mnemoic validity.
 *
 * @param
 *      mnemonic               [in] mnemonic string
 *                             Only Support mnenomic from languages as follow:
 *                             "english", "french", "spanish",
 *                             "chinese_simplified", "chinese_traditional",
 *                             "japanese", "czech", "italian", "korean".
 * @return
 *      return language name string. Member release the returned value.
 *      return NULL, if mnemonic isn't from specified languages or mnemonic isn't valid.
 */
/* DID_API */ const char *Mnemonic_GetLanguage(const char *mnemonic);

/******************************************************************************
 * Presentation
 *****************************************************************************/
/**
 * \~English
 * Create a presentation including some credentials.
 *
 * @param
 *      id                       [in] The Id of Presentation.
 * @param
 *      holder                   [in] The handle to holder.
 * @param
 *      types                    [in] The type array.
 * @param
 *      size                     [in] The size of types.
 * @param
 *      nonce                    [in] Indicate the usage of Presentation.
  * @param
 *      realm                    [in] Indicate where the Presentation is use.
 * @param
 *      signkey                  [in] The key id to sign.
 * @param
 *      store                    [in] The handle to DIDStore.
 * @param
 *      storepass                [in] The password of DIDStore.
 * @param
 *      count                    [in] The count of Credentials.
 * @return
 *      If no error occurs, return the handle to Presentataion.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ Presentation *Presentation_Create(DIDURL *id, DID *holder,
        const char **types, size_t size, const char *nonce, const char *realm,
        DIDURL *signkey, DIDStore *store, const char *storepass, int count, ...);

/**
 * \~English
 * Create a presentation including some credentials.
 *
 * @param
 *      id                       [in] The Id of Presentation.
 * @param
 *      holder                   [in] The handle to holder.
 * @param
 *      types                    [in] The type array.
 * @param
 *      size                     [in] The size of types.
 * @param
 *      nonce                    [in] Indicate the usage of Presentation.
 * @param
 *      realm                    [in] Indicate where the Presentation is use.
 * @param
 *      creds                    [in] The credential array.
 * @param
 *      count                    [in] The count of Credentials.
 * @param
 *      signkey                  [in] The key id to sign.
 * @param
 *      store                    [in] The handle to DIDStore.
 * @param
 *      storepass                [in] The password of DIDStore.
 * @return
 *      If no error occurs, return the handle to Presentataion.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/*DID_API*/ Presentation *Presentation_CreateByCredentials(DIDURL *id, DID *holder,
        const char **types, size_t size, const char *nonce, const char *realm,
        Credential **creds, size_t count, DIDURL *signkey, DIDStore *store,
        const char *storepass);

/**
 * \~English
 * Destroy Presentation.
 *
 * @param
 *      presentation         [in] The handle to Presentation.
 */
/* DID_API */ void Presentation_Destroy(Presentation *presentation);

/**
 * \~English
 * Get json context from Presentation.
 *
 * @param
 *      presentation         [in] A handle to Presentation.
 * @param
 *      normalized           [in] Json context is normalized or not.
 *                           true represents normalized, false represents not normalized.
 * @return
 *      If no error occurs, return json context. Otherwise, return NULL.
 *      Notice that user need to free the returned value that it's memory.
 */
/* DID_API */ const char* Presentation_ToJson(Presentation *presentation, bool normalized);

/**
 * \~English
 * Get Presentation from json context.
 *
 * @param
 *      json                 [in] Json context about Presentation.
 * @return
 *      If no error occurs, return the handle to Presentation.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ Presentation *Presentation_FromJson(const char *json);

/**
 * \~English
 * Get id of Presentation.
 *
 * @param
 *      presentation         [in] The handle to Presentation.
 * @return
 *      If no error occurs, return the id.
 *      Otherwise, return NULL.
 */
/* DID_API */ DIDURL *Presentation_GetId(Presentation *presentation);

/**
 * \~English
 * Get the holder(owner) of Presentation.
 *
 * @param
 *      presentation         [in] The handle to Presentation.
 * @return
 *      If no error occurs, return the handle to DID.
 *      Otherwise, return NULL.
 */
/* DID_API */ DID *Presentation_GetHolder(Presentation *presentation);

/**
 * \~English
 * Get Credential count in Presentation.
 *
 * @param
 *      presentation          [in] The handle to Presentation.
 * @return
 *      If no error occurs, return the count of Credential.
 *      Otherwise, return -1.
 */
/* DID_API */ ssize_t Presentation_GetCredentialCount(Presentation *presentation);

/**
 * \~English
 * Get Credential list for signing the Presentation.
 *
 * @param
 *      presentation          [in] The handle to Presentation.
 * @param
 *      creds                 [out] The buffer that will receive the public keys.
  * @param
 *      size                  [in] The count of Credentials.
 * @return
 *      If no error occurs, return the count of Credential.
 *      Otherwise, return -1.
 */
/* DID_API */ ssize_t Presentation_GetCredentials(Presentation *presentation,
        Credential **creds, size_t size);

/**
 * \~English
 * Get Credential list for signing the Presentation.
 *
 * @param
 *      presentation          [in] The handle to Presentation.
 * @param
 *      credid                [in] The Credential Id.
 * @return
 *      If no error occurs, return the handle to Credential.
 *      Otherwise, return NULL.
 */
/* DID_API */ Credential *Presentation_GetCredential(Presentation *presentation, DIDURL *credid);

/**
 * \~English
 * Get count of Presentation types.
 *
 * @param
 *      presentation         [in] A handle to Presentation.
 * @return
 *      size of Presentation types on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t Presentation_GetTypeCount(Presentation *presentation);

/**
 * \~English
 * Get array of Presentation types.
 *
 * @param
 *      presentation         [in] A handle to Presentation.
 * @param
 *      types                [out] The buffer that will receive presentation types.
  * @param
 *      size                 [in] The buffer size of presentation types.
 * @return
 *      size of Presentation types on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t Presentation_GetTypes(Presentation *presentation, const char **types, size_t size);

/**
 * \~English
 * Get time created Presentation.
 *
 * @param
 *      presentation         [in] The handle to Presentation.
 * @return
 *      If no error occurs, return the time created Presentation.
 *      Otherwise, return 0.
 */
/* DID_API */ time_t Presentation_GetCreatedTime(Presentation *presentation);

/**
 * \~English
 * Get key to sign Presentation.
 *
 * @param
 *      presentation           [in] The handle to Presentation.
 * @return
 *      If no error occurs, return the handle to signkey.
 *      Otherwise, return NULL.
 */
/* DID_API */ DIDURL *Presentation_GetVerificationMethod(Presentation *presentation);

/**
 * \~English
 * Get Presentation nonce.
 *
 * @param
 *      presentation            [in] The handle to Presentation.
 * @return
 *      If no error occurs, return the Presentaton nonce string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *Presentation_GetNonce(Presentation *presentation);

/**
 * \~English
 * Get Presentation realm.
 *
 * @param
 *      presentation             [in] The handle to Presentation.
 * @return
 *      If no error occurs, return the Presentaton realm string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *Presentation_GetRealm(Presentation *presentation);

/**
 * \~English
 * Presentation is genuine or not.
 *
 * @param
 *      presentation              [in] The Presentation handle.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, presentation isn't genuine;
 *      return value = 1, presentation is genuine.
 */
/* DID_API */ int Presentation_IsGenuine(Presentation *presentation);

/**
 * \~English
 * Presentation is valid or not.
 *
 * @param
 *      presentation              [in] The Presentation handle.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, presentation isn't valid;
 *      return value = 1, presentation is valid.
 */
/* DID_API */ int Presentation_IsValid(Presentation *presentation);

/******************************************************************************
 * TransferTicket
 *****************************************************************************/
/**
 * \~English
 * Destroy TransferTicket.
 *
 * @param
 *      ticket                      [in] The handle to TransferTicket.
 */
/* DID_API */ void TransferTicket_Destroy(TransferTicket *ticket);

/**
 * \~English
 * Get json non-formatted context from Transfer Ticket.
 *
 * @param
 *      ticket               [in] A handle to Transfer Ticket.
 * @return
 *      If no error occurs, return json context. Otherwise, return NULL.
 *      Notice that user need to free the returned value that it's memory.
 */
/* DID_API */ const char *TransferTicket_ToJson(TransferTicket *ticket);

/**
 * \~English
 * Get Transfer Ticket from json context.
 *
 * @param
 *      json               [in] Context of did conforming to json informat.
 * @return
 *      If no error occurs, return the handle to Transfer Ticket.
 *      Otherwise, return NULL.
 *      Notice that user need to release the handle of returned instance to destroy it's memory.
 */
/* DID_API */ TransferTicket *TransferTicket_FromJson(const char *json);

/**
 * \~English
 * Check that transfer ticket is valid or not.
 *
 * @param
 *      ticket             [in] A handle to Transfer Ticket.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, transfer ticket isn't valid;
 *      return value = 1, transfer ticket is valid.
*/
/* DID_API */ int TransferTicket_IsValid(TransferTicket *ticket);

/**
 * \~English
 * Check that ticket is qualified or not.
 *
 * @param
 *      ticket             [in] A handle to TransferTicket.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, ticket isn't qualified;
 *      return value = 1, ticket is qualified.
*/
/* DID_API */ int TransferTicket_IsQualified(TransferTicket *ticket);

/**
 * \~English
 * Check that transfer ticket is genuine or not.
 *
 * @param
 *      ticket              [in] A handle to TransferTicket.
 * @return
 *      return value = -1, if error occurs;
 *      return value = 0, ticket isn't genuine;
 *      return value = 1, ticket is genuine.
*/
/* DID_API */ int TransferTicket_IsGenuine(TransferTicket *ticket);

/**
 * \~English
 * Get the transfer ticket's signer count.
 *
 * @param
 *      ticket                    [in] The handle to TransferTicket.
 * @return
 *      Return  on success, -1 if an error occurred.
 */
/* DID_API */ ssize_t TransferTicket_GetProofCount(TransferTicket *ticket);

/**
 * \~English
 * Get the type property of embedded proof.
 *
 * @param
 *      ticket                   [in] A handle to TransferTicket.
 * @param
 *      index                    [in] Index number.
 * @return
 *      If no error occurs, return type string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *TransferTicket_GetProofType(TransferTicket *ticket, int index);

/**
 * \~English
 * Get verification method identifier of TransferTicket.
 * The verification Method property specifies the public key
 * that can be used to verify the digital signature.
 *
 * @param
 *      ticket                 [in] A handle to TransferTicket.
 * @param
 *      index                    [in] Index number.
 * @return
 *      If no error occurs, return the handle to identifier of public key.
 *      Otherwise, return NULL.
 */
/* DID_API */ DIDURL *TransferTicket_GetSignKey(TransferTicket *ticket, int index);

/**
 * \~English
 * Get time of create TransferTicket proof.
 *
 * @param
 *      ticket                   [in] A handle to TransferTicket.
 * @param
 *      index                    [in] Index number.
 * @return
 *      If no error occurs, return 0.
 *      Otherwise, return time.
 */
/* DID_API */ time_t TransferTicket_GetProofCreatedTime(TransferTicket *ticket, int index);

/**
 * \~English
 * Get signature of TransferTicket.
 * A signature that can be later used to verify the authenticity and
 * integrity of a linked data ticket.
 *
 * @param
 *      ticket                  [in] A handle to DID Document.
 * @param
 *      index                    [in] Index number.
 * @return
 *      If no error occurs, return signature string.
 *      Otherwise, return NULL.
 */
/* DID_API */ const char *TransferTicket_GetProofSignature(TransferTicket *ticket, int index);

/******************************************************************************
 * DIDBackend
 *****************************************************************************/
/**
 * \~English
 * Initialize DIDBackend by url.
 *
 * @param
 *      createtransaction  [in] The method to create id transaction.
 * @param
 *      url                [in] The URL string.
 * @param
 *      cachedir           [in] The directory for cache.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDBackend_InitializeDefault(CreateIdTransaction_Callback *createtransaction,
        const char *url, const char *cachedir);

/**
 * \~English
 * Initialize DIDBackend.
 *
 * @param
 *      createtransaction  [in] The method to create id transaction.
 * @param
 *      resolve           [in] The method to resolve.
 * @param
 *      cachedir          [in] The directory for cache.
 * @return
 *      0 on success, -1 if an error occurred.
 */
/* DID_API */ int DIDBackend_Initialize(CreateIdTransaction_Callback *createtransaction,
        Resolve_Callback *resolve, const char *cachedir);

/**
 * \~English
 * Set ttl for resolve cache.
 *
 * @param
 *      ttl            [in] The time for cache.
 */
/* DID_API */ void DIDBackend_SetTTL(long ttl);

/**
 * \~English
 * User set DID Local Resolve handle in order to give which did document to verify.
 * If handle != NULL, set DID Local Resolve Handle; If handle == NULL, clear this handle.
 *
 * @param
 *      handle            [in] The pointer to DIDLocalResovleHandle function.
 */
/* DID_API */ void DIDBackend_SetLocalResolveHandle(DIDLocalResovleHandle *handle);

/******************************************************************************
 * Error handling
 *****************************************************************************/

#define DIDSUCCESS                                  0
/**
 * \~English
 * Argument(s) is(are) invalid.
 */
#define DIDERR_INVALID_ARGS                         0x8D000001
/**
 * \~English
 * Runs out of memory.
 */
#define DIDERR_OUT_OF_MEMORY                        0x8D000002
/**
 * \~English
 * IO error.
 */
#define DIDERR_IO_ERROR                             0x8D000003
/**
 * \~English
 * DID object/Credential/RootIdentity already exists.
 * The key already sign document, so it already exists in doc's proof.
 */
#define DIDERR_ALREADY_EXISTS                       0x8D000004
/**
 * \~English
 * DID object doesn't already exists.
 */
#define DIDERR_NOT_EXISTS                           0x8D000005
/**
 * \~English
 * Unsupported error.
 */
#define DIDERR_UNSUPPORTED                           0x8D000006
/**
 * \~English
 * DID is malformed.
 */
#define DIDERR_MALFORMED_DID                        0x8D000007
/**
 * \~English
 * DIDURL is malformed.
 */
#define DIDERR_MALFORMED_DIDURL                     0x8D000008
/**
 * \~English
 * DIDDocument is malformed.
 */
#define DIDERR_MALFORMED_DOCUMENT                   0x8D000009
/**
 * \~English
 * Credential is malformed.
 */
#define DIDERR_MALFORMED_CREDENTIAL                 0x8D00000A
/**
 * \~English
 * Presentation is malformed.
 */
#define DIDERR_MALFORMED_PRESENTATION               0x8D00000B
/**
 * \~English
 * Transfer ticket error.
 */
#define DIDERR_MALFORMED_TRANSFERTICKET             0x8D00000C
/**
 * \~English
 * DID is not founded in chain.
 */
#define DIDERR_DID_NOTFOUNDED                       0x8D00000D
/**
 * \~English
 * DID is the customized did which is expected be not a customized did.
 * DID is not the customized did which is expected be a customized did.
 */
#define DIDERR_NOT_EXPECTEDDID                      0x8D00000E
/**
 * \~English
 * DID/Credential is expired.
 */
#define DIDERR_EXPIRED                              0x8D00000F
/**
 * \~English
 * DID is deactivated.
 */
#define DIDERR_DID_DEACTIVATED                      0x8D000010
/**
 * \~English
 * Credential is revoked.
 */
#define DIDERR_CREDENTIAL_REVOKED                   0x8D000011
/**
 * \~English
 * DID/Credential is not genuine.
 */
#define DIDERR_NOT_GENUINE                          0x8D000012
/**
 * \~English
 * DID/Credential/Presentation is sealed.
 */
#define DIDERR_ALREADY_SEALED                       0x8D000013
/**
 * \~English
 * Controller error.
 */
#define DIDERR_INVALID_CONTROLLER                   0x8D000014
/**
 * \~English
 * key is invalid.
 */
#define DIDERR_INVALID_KEY                          0x8D000015
/**
 * \~English
 * Error from DIDStore.
 */
#define DIDERR_DIDSTORE_ERROR                       0x8D000016
/**
 * \~English
 * DID object doesn't attach DIDStore.
 */
#define DIDERR_NO_ATTACHEDSTORE                     0x8D000017
/**
 * \~English
 * Wrong password for DIDStore.
 */
#define DIDERR_WRONG_PASSWORD                       0x8D000018
/**
 * \~English
 * Export DID error.
 */
#define DIDERR_MALFORMED_EXPORTDID                  0x8D000019
/**
 * \~English
 * Publish a DID document which is not up to date.
 */
#define DIDERR_NOT_UPTODATE                         0x8D00001A
/**
 * \~English
 * IDChainRequest is malformed.
 */
#define DIDERR_MALFORMED_IDCHAINREQUEST             0x8D00001B
/**
 * \~English
 * IDChainTransaction is malformed.
 */
#define DIDERR_MALFORMED_IDCHAINTRANSACTION         0x8D00001C
/**
 * \~English
 * Resolve request is malformed.
 */
#define DIDERR_MALFORMED_RESOLVE_REQUEST            0x8D00001D
/**
 * \~English
 * Resolve response is malformed.
 */
#define DIDERR_MALFORMED_RESOLVE_RESPONSE           0x8D00001E
/**
 * \~English
 * Resolve result is malformed.
 */
#define DIDERR_MALFORMED_RESOLVE_RESULT             0x8D00001F
/**
 * \~English
 * Network error.
 */
#define DIDERR_NETWORK                              0x8D000020
/**
 * \~English
 * DID resolve error.
 */
#define DIDERR_DID_RESOLVE_ERROR                    0x8D000021
/**
 * \~English
 * Publish did error.
 */
#define DIDERR_DID_TRANSACTION_ERROR                0x8D000022
/**
 * \~English
 * Crypto failed.
 */
#define DIDERR_CRYPTO_ERROR                         0x8D000023
/**
 * \~English
 * Mnemonic error.
 */
#define DIDERR_MNEMONIC                             0x8D000024
/**
 * \~English
 * Illegal use error.
 */
#define DIDERR_ILLEGALUSAGE                         0x8D000025
/**
 * \~English
 * Sign data failed.
 */
#define DIDERR_SIGN_ERROR                           0x8D000026
/**
 * \~English
 * Verify data failed.
 */
#define DIDERR_VERIFY_ERROR                         0x8D000027
/**
 * \~English
 * Metadata error.
 */
#define DIDERR_METADATA_ERROR                       0x8D000028
/**
 * \~English
 * JWT error.
 */
#define DIDERR_JWT                                  0x8D000029
/**
 * \~English
 * Unknown error.
 */
#define DIDERR_UNKNOWN                              0x8D0000FF
/**
 * \~English
 * Print the whole information of last-error code.
 */
/*DID_API*/ void DIDError_Print(FILE *out);

/**
 * \~English
 * Get the last-error code.
 */
/*DID_API*/ int DIDError_GetLastErrorCode(void);
/**
 * \~English
 * Get the last-error message.
 */
/*DID_API*/ const char *DIDError_GetLastErrorMessage(void);
