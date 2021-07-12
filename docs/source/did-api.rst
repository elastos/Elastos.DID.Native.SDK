Elastos DID core APIs
=========================

Constants
---------

ELA_MAX_DID_LEN
###############

.. doxygendefine:: ELA_MAX_DID_LEN
   :project: DIDAPI

ELA_MAX_DIDURL_LEN
##################

.. doxygendefine:: ELA_MAX_DIDURL_LEN
   :project: DIDAPI

ELA_MAX_ALIAS_LEN
#################

.. doxygendefine:: ELA_MAX_ALIAS_LEN
   :project: DIDAPI

ELA_MAX_TXID_LEN
#################

.. doxygendefine:: ELA_MAX_TXID_LEN
   :project: DIDAPI

ELA_MAX_MNEMONIC_LEN
####################

.. doxygendefine:: ELA_MAX_MNEMONIC_LEN
   :project: DIDAPI

Data types
----------

ELA_DID_FILTER
###############

.. doxygenenum:: ELA_DID_FILTER
   :project: DIDAPI

Property
########

.. doxygenstruct:: Property
   :project: DIDAPI
   :members:

DID
###

.. doxygentypedef:: DID
   :project: DIDAPI

DIDURL
######

.. doxygentypedef:: DIDURL
   :project: DIDAPI

PublicKey
#########

.. doxygentypedef:: PublicKey
   :project: DIDAPI

Credential
##########

.. doxygentypedef:: Credential
   :project: DIDAPI

Service
#######

.. doxygentypedef:: Service
   :project: DIDAPI

Presentation
############

.. doxygentypedef:: Presentation
   :project: DIDAPI


DIDDocument
###########

.. doxygentypedef:: DIDDocument
   :project: DIDAPI

DIDDocumentBuilder
##################

.. doxygentypedef:: DIDDocumentBuilder
   :project: DIDAPI

DIDMetadata
############

.. doxygentypedef:: DIDMetadata
   :project: DIDAPI


CredentialMetadata
###################

.. doxygentypedef:: CredentialMetadata
   :project: DIDAPI

DIDBiography
############

.. doxygentypedef:: DIDBiography
   :project: DIDAPI

CredentialBiography
###################

.. doxygentypedef:: CredentialBiography
   :project: DIDAPI

Issuer
######

.. doxygentypedef:: Issuer
   :project: DIDAPI

TransferTicket
##############

.. doxygentypedef:: TransferTicket
   :project: DIDAPI

DIDStore
########

.. doxygentypedef:: DIDStore
   :project: DIDAPI

JWTBuilder
##########

.. doxygentypedef:: JWTBuilder
   :project: DIDAPI

JWSParser
##########

.. doxygentypedef:: JWSParser
   :project: DIDAPI

DIDStore_DIDsCallback
#####################

.. doxygentypedef:: DIDStore_DIDsCallback
   :project: DIDAPI

DIDDocument_ConflictHandle
###########################

.. doxygentypedef:: DIDDocument_ConflictHandle
   :project: DIDAPI

DIDLocalResovleHandle
######################

.. doxygentypedef:: DIDLocalResovleHandle
   :project: DIDAPI

CreateIdTransaction_Callback
#############################

.. doxygentypedef:: CreateIdTransaction_Callback
   :project: DIDAPI

Resolve_Callback
#################

.. doxygentypedef:: Resolve_Callback
   :project: DIDAPI

Functions
---------

DID Functions
#############

DID_New
~~~~~~~

.. doxygenfunction:: DID_New
   :project: DIDAPI

DID_FromString
~~~~~~~~~~~~~~

.. doxygenfunction:: DID_FromString
   :project: DIDAPI

DID_GetMethod
~~~~~~~~~~~~~

.. doxygenfunction:: DID_GetMethod
   :project: DIDAPI

DID_GetMethodSpecificId
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DID_GetMethodSpecificId
   :project: DIDAPI

DID_ToString
~~~~~~~~~~~~

.. doxygenfunction:: DID_ToString
   :project: DIDAPI

DID_Compare
~~~~~~~~~~~

.. doxygenfunction:: DID_Compare
   :project: DIDAPI

DID_Resolve
~~~~~~~~~~~~

.. doxygenfunction:: DID_Resolve
   :project: DIDAPI

DID_ResolveBiography
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DID_ResolveBiography
   :project: DIDAPI

DID_GetMetadata
~~~~~~~~~~~~~~~

.. doxygenfunction:: DID_GetMetadata
   :project: DIDAPI

DIDMetadata Functions
#####################

DIDMetadata_GetAlias
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDMetadata_GetAlias
   :project: DIDAPI

DIDMetadata_GetDeactivated
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDMetadata_GetDeactivated
   :project: DIDAPI

DIDMetadata_GetPublished
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDMetadata_GetPublished
   :project: DIDAPI

DIDMetadata_SetAlias
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDMetadata_SetAlias
   :project: DIDAPI

DIDMetadata_SetExtra
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDMetadata_SetExtra
   :project: DIDAPI

DIDMetadata_SetExtraWithBoolean
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDMetadata_SetExtraWithBoolean
   :project: DIDAPI

DIDMetadata_SetExtraWithDouble
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDMetadata_SetExtraWithDouble
   :project: DIDAPI

DIDMetadata_GetExtra
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDMetadata_GetExtra
   :project: DIDAPI

DIDMetadata_GetExtraAsBoolean
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDMetadata_GetExtraAsBoolean
   :project: DIDAPI

DIDMetadata_GetExtraAsDouble
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDMetadata_GetExtraAsDouble
   :project: DIDAPI

DIDURL Functions
################

DIDURL_FromString
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDURL_FromString
   :project: DIDAPI

DIDURL_NewByDid
~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDURL_NewByDid
   :project: DIDAPI

DIDURL_GetDid
~~~~~~~~~~~~~~

.. doxygenfunction:: DIDURL_GetDid
   :project: DIDAPI

DIDURL_GetFragment
~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDURL_GetFragment
   :project: DIDAPI

DIDURL_ToString
~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDURL_ToString
   :project: DIDAPI

DIDURL_Equals
~~~~~~~~~~~~~

.. doxygenfunction:: DIDURL_Equals
   :project: DIDAPI

DIDURL_Compare
~~~~~~~~~~~~~~

.. doxygenfunction:: DIDURL_Compare
   :project: DIDAPI

DIDURL_Destroy
~~~~~~~~~~~~~~

.. doxygenfunction:: DIDURL_Destroy
   :project: DIDAPI

DIDURL_GetMetadata
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDURL_GetMetadata
   :project: DIDAPI

DIDBiography Functions
######################

DIDBiography_GetOwner
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBiography_GetOwner
   :project: DIDAPI

DIDBiography_GetStatus
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBiography_GetStatus
   :project: DIDAPI

DIDBiography_GetTransactionCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBiography_GetTransactionCount
   :project: DIDAPI

DIDBiography_GetDocumentByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBiography_GetDocumentByIndex
   :project: DIDAPI

DIDBiography_GetTransactionIdByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBiography_GetTransactionIdByIndex
   :project: DIDAPI

DIDBiography_GetPublishedByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBiography_GetPublishedByIndex
   :project: DIDAPI

DIDBiography_GetOperationByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBiography_GetOperationByIndex
   :project: DIDAPI

DIDBiography_Destroy
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBiography_Destroy
   :project: DIDAPI

CredentialBiography Functions
#############################

CredentialBiography_GetId
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialBiography_GetId
   :project: DIDAPI

CredentialBiography_GetOwner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialBiography_GetOwner
   :project: DIDAPI

CredentialBiography_GetStatus
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialBiography_GetStatus
   :project: DIDAPI

CredentialBiography_GetTransactionCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialBiography_GetTransactionCount
   :project: DIDAPI

CredentialBiography_GetCredentialByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialBiography_GetCredentialByIndex
   :project: DIDAPI

CredentialBiography_GetTransactionIdByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialBiography_GetTransactionIdByIndex
   :project: DIDAPI

CredentialBiography_GetPublishedByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialBiography_GetPublishedByIndex
   :project: DIDAPI

CredentialBiography_GetTransactionSignkeyByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialBiography_GetTransactionSignkeyByIndex
   :project: DIDAPI

CredentialBiography_GetOperationByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialBiography_GetOperationByIndex
   :project: DIDAPI

CredentialBiography_Destroy
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialBiography_Destroy
   :project: DIDAPI

CredentialMetadata Functions
##############################

CredentialMetadata_SetAlias
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialMetadata_SetAlias
   :project: DIDAPI

CredentialMetadata_SetExtra
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialMetadata_SetExtra
   :project: DIDAPI

CredentialMetadata_SetExtraWithBoolean
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialMetadata_SetExtraWithBoolean
   :project: DIDAPI

CredentialMetadata_SetExtraWithDouble
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialMetadata_SetExtraWithDouble
   :project: DIDAPI

CredentialMetadata_GetAlias
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialMetadata_GetAlias
   :project: DIDAPI

CredentialMetadata_GetExtra
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialMetadata_GetExtra
   :project: DIDAPI

CredentialMetadata_GetExtraAsBoolean
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialMetadata_GetExtraAsBoolean
   :project: DIDAPI

CredentialMetadata_GetExtraAsDouble
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: CredentialMetadata_GetExtraAsDouble
   :project: DIDAPI

RootIdentity Functions
########################

RootIdentity_Create
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_Create
   :project: DIDAPI

RootIdentity_CreateFromRootKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_CreateFromRootKey
   :project: DIDAPI

RootIdentity_CreateId
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_CreateId
   :project: DIDAPI

RootIdentity_CreateIdFromRootKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_CreateIdFromRootKey
   :project: DIDAPI

RootIdentity_Destroy
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_Destroy
   :project: DIDAPI

RootIdentity_GetId
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_GetId
   :project: DIDAPI

RootIdentity_GetAlias
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_GetAlias
   :project: DIDAPI

RootIdentity_SetAlias
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_SetAlias
   :project: DIDAPI

RootIdentity_SetAsDefault
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_SetAsDefault
   :project: DIDAPI

RootIdentity_SetDefaultDID
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_SetDefaultDID
   :project: DIDAPI

RootIdentity_GetDefaultDID
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_GetDefaultDID
   :project: DIDAPI

RootIdentity_NewDID
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_NewDID
   :project: DIDAPI

RootIdentity_NewDIDByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_NewDIDByIndex
   :project: DIDAPI

RootIdentity_GetDIDByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_GetDIDByIndex
   :project: DIDAPI

RootIdentity_Synchronize
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_Synchronize
   :project: DIDAPI

RootIdentity_SynchronizeByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: RootIdentity_SynchronizeByIndex
   :project: DIDAPI

DIDDocument Functions
#####################

DIDDocument_FromJson
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_FromJson
   :project: DIDAPI

DIDDocument_ToJson
~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_ToJson
   :project: DIDAPI

DIDDocument_Destroy
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_Destroy
   :project: DIDAPI

DIDDocument_IsDeactivated
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_IsDeactivated
   :project: DIDAPI

DIDDocument_IsGenuine
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_IsGenuine
   :project: DIDAPI

DIDDocument_IsExpired
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_IsExpired
   :project: DIDAPI

DIDDocument_IsValid
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_IsValid
   :project: DIDAPI

DIDDocument_IsQualified
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_IsQualified
   :project: DIDAPI

DIDDocument_GetSubject
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetSubject
   :project: DIDAPI

DIDDocument_Edit
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_Edit
   :project: DIDAPI

DIDDocumentBuilder_Destroy
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_Destroy
   :project: DIDAPI

DIDDocumentBuilder_Seal
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_Seal
   :project: DIDAPI

DIDDocumentBuilder_AddController
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_AddController
   :project: DIDAPI

DIDDocumentBuilder_RemoveController
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_RemoveController
   :project: DIDAPI

DIDDocumentBuilder_AddPublicKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_AddPublicKey
   :project: DIDAPI

DIDDocumentBuilder_RemovePublicKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_RemovePublicKey
   :project: DIDAPI

DIDDocumentBuilder_AddAuthenticationKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_AddAuthenticationKey
   :project: DIDAPI

DIDDocumentBuilder_RemoveAuthenticationKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_RemoveAuthenticationKey
   :project: DIDAPI

DIDDocumentBuilder_AddAuthorizationKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_AddAuthorizationKey
   :project: DIDAPI

DIDDocumentBuilder_AuthorizeDid
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_AuthorizeDid
   :project: DIDAPI

DIDDocumentBuilder_AddCredential
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_AddCredential
   :project: DIDAPI

DIDDocumentBuilder_RemoveCredential
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_RemoveCredential
   :project: DIDAPI

DIDDocumentBuilder_AddSelfProclaimedCredential
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_AddSelfProclaimedCredential
   :project: DIDAPI

DIDDocumentBuilder_RenewSelfProclaimedCredential
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_RenewSelfProclaimedCredential
   :project: DIDAPI

DIDDocumentBuilder_RemoveSelfProclaimedCredential
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_RemoveSelfProclaimedCredential
   :project: DIDAPI

DIDDocumentBuilder_AddService
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_AddService
   :project: DIDAPI

DIDDocumentBuilder_RemoveService
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_RemoveService
   :project: DIDAPI

DIDDocumentBuilder_RemoveProof
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_RemoveProof
   :project: DIDAPI

DIDDocumentBuilder_SetExpires
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_SetExpires
   :project: DIDAPI

DIDDocumentBuilder_SetMultisig
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocumentBuilder_SetMultisig
   :project: DIDAPI

DIDDocument_GetMultisig
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetMultisig
   :project: DIDAPI

DIDDocument_GetControllerCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetControllerCount
   :project: DIDAPI

DIDDocument_GetControllers
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetControllers
   :project: DIDAPI

DIDDocument_ContainsController
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_ContainsController
   :project: DIDAPI

DIDDocument_GetPublicKeyCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetPublicKeyCount
   :project: DIDAPI

DIDDocument_GetPublicKeys
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetPublicKeys
   :project: DIDAPI

DIDDocument_GetPublicKey
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetPublicKey
   :project: DIDAPI

DIDDocument_SelectPublicKeys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_SelectPublicKeys
   :project: DIDAPI

DIDDocument_GetDefaultPublicKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetDefaultPublicKey
   :project: DIDAPI

DIDDocument_GetAuthenticationCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetAuthenticationCount
   :project: DIDAPI

DIDDocument_GetAuthenticationKeys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetAuthenticationKeys
   :project: DIDAPI

DIDDocument_GetAuthenticationKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetAuthenticationKey
   :project: DIDAPI

DIDDocument_SelectAuthenticationKeys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_SelectAuthenticationKeys
   :project: DIDAPI

DIDDocument_IsAuthenticationKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_IsAuthenticationKey
   :project: DIDAPI

DIDDocument_IsAuthorizationKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_IsAuthorizationKey
   :project: DIDAPI

DIDDocument_GetAuthorizationCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetAuthorizationCount
   :project: DIDAPI

DIDDocument_GetAuthorizationKeys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetAuthorizationKeys
   :project: DIDAPI

DIDDocument_GetAuthorizationKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetAuthorizationKey
   :project: DIDAPI

DIDDocument_SelectAuthorizationKeys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_SelectAuthorizationKeys
   :project: DIDAPI

DIDDocument_GetCredentialCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetCredentialCount
   :project: DIDAPI

DIDDocument_GetCredentials
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetCredentials
   :project: DIDAPI

DIDDocument_GetCredential
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetCredential
   :project: DIDAPI

DIDDocument_GetServices
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetServices
   :project: DIDAPI

DIDDocument_SelectServices
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_SelectServices
   :project: DIDAPI

DIDDocument_Sign
~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_Sign
   :project: DIDAPI

DIDDocument_SignDigest
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_SignDigest
   :project: DIDAPI

DIDDocument_Verify
~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_Verify
   :project: DIDAPI

DIDDocument_VerifyDigest
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_VerifyDigest
   :project: DIDAPI

DIDDocument_GetMetadata
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetMetadata
   :project: DIDAPI

DIDDocument_GetProofCount
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetProofCount
   :project: DIDAPI

DIDDocument_GetProofType
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetProofType
   :project: DIDAPI

DIDDocument_GetProofCreater
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetProofCreater
   :project: DIDAPI

DIDDocument_GetProofCreatedTime
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetProofCreatedTime
   :project: DIDAPI

DIDDocument_GetProofSignature
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetProofSignature
   :project: DIDAPI

DIDDocument_GetJwtBuilder
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetJwtBuilder
   :project: DIDAPI

DIDDocument_GetJwsParser
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_GetJwsParser
   :project: DIDAPI

DIDDocument_DeriveByIdentifier
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_DeriveByIdentifier
   :project: DIDAPI

DIDDocument_DeriveByIndex
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_DeriveByIndex
   :project: DIDAPI

DIDDocument_SignDIDDocument
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_SignDIDDocument
   :project: DIDAPI

DIDDocument_MergeDIDDocuments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_MergeDIDDocuments
   :project: DIDAPI

DIDDocument_CreateTransferTicket
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_CreateTransferTicket
   :project: DIDAPI

DIDDocument_SignTransferTicket
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_SignTransferTicket
   :project: DIDAPI

DIDDocument_PublishDID
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_PublishDID
   :project: DIDAPI

DIDDocument_TransferDID
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_TransferDID
   :project: DIDAPI

DIDDocument_DeactivateDID
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_DeactivateDID
   :project: DIDAPI

DIDDocument_DeactivateDIDByAuthorizor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDDocument_DeactivateDIDByAuthorizor
   :project: DIDAPI

PublicKey_GetId
~~~~~~~~~~~~~~~

.. doxygenfunction:: PublicKey_GetId
   :project: DIDAPI

PublicKey_GetController
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: PublicKey_GetController
   :project: DIDAPI

PublicKey_GetPublicKeyBase58
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: PublicKey_GetPublicKeyBase58
   :project: DIDAPI

PublicKey_GetType
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: PublicKey_GetType
   :project: DIDAPI

PublicKey_IsAuthenticationKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: PublicKey_IsAuthenticationKey
   :project: DIDAPI

PublicKey_IsAuthorizationKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: PublicKey_IsAuthorizationKey
   :project: DIDAPI

Service_GetEndpoint
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Service_GetEndpoint
   :project: DIDAPI

Service_GetType
~~~~~~~~~~~~~~~~

.. doxygenfunction:: Service_GetType
   :project: DIDAPI

Credential Functions
####################

Credential_ToJson
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_ToJson
   :project: DIDAPI

Credential_FromJson
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_FromJson
   :project: DIDAPI

Credential_Destroy
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_Destroy
   :project: DIDAPI

Credential_GetId
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetId
   :project: DIDAPI

Credential_GetOwner
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetOwner
   :project: DIDAPI

Credential_GetTypeCount
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetTypeCount
   :project: DIDAPI

Credential_GetTypes
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetTypes
   :project: DIDAPI

Credential_GetIssuer
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetIssuer
   :project: DIDAPI

Credential_GetIssuanceDate
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetIssuanceDate
   :project: DIDAPI

Credential_GetExpirationDate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetExpirationDate
   :project: DIDAPI

Credential_GetPropertyCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetPropertyCount
   :project: DIDAPI

Credential_GetProperties
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetProperties
   :project: DIDAPI

Credential_GetProperty
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetProperty
   :project: DIDAPI

Credential_GetProofType
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetProofType
   :project: DIDAPI

Credential_IsExpired
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_IsExpired
   :project: DIDAPI

Credential_IsGenuine
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_IsGenuine
   :project: DIDAPI

Credential_IsValid
~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_IsValid
   :project: DIDAPI

Credential_GetMetadata
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_GetMetadata
   :project: DIDAPI

Credential_Resolve
~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_Resolve
   :project: DIDAPI

Credential_ResolveRevocation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_ResolveRevocation
   :project: DIDAPI

Credential_ResolveBiography
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_ResolveBiography
   :project: DIDAPI

Credential_WasDeclared
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_WasDeclared
   :project: DIDAPI

Credential_IsRevoked
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_IsRevoked
   :project: DIDAPI

Credential_List
~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_List
   :project: DIDAPI

Credential_Declare
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_Declare
   :project: DIDAPI

Credential_Revoke
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_Revoke
   :project: DIDAPI

Credential_RevokeById
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Credential_RevokeById
   :project: DIDAPI

Issuer Functions
################

Issuer_Create
~~~~~~~~~~~~~

.. doxygenfunction:: Issuer_Create
   :project: DIDAPI

Issuer_Destroy
~~~~~~~~~~~~~~

.. doxygenfunction:: Issuer_Destroy
   :project: DIDAPI

Issuer_CreateCredential
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Issuer_CreateCredential
   :project: DIDAPI

Issuer_CreateCredentialByString
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Issuer_CreateCredentialByString
   :project: DIDAPI

Issuer_GetSigner
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Issuer_GetSigner
   :project: DIDAPI

Issuer_GetSignKey
~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Issuer_GetSignKey
   :project: DIDAPI

DIDStore Functions
##################

DIDStore_Open
~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_Open
   :project: DIDAPI

DIDStore_Close
~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_Close
   :project: DIDAPI

DIDStore_StoreDID
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_StoreDID
   :project: DIDAPI

DIDStore_LoadDID
~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_LoadDID
   :project: DIDAPI

DIDStore_ContainsDID
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_ContainsDID
   :project: DIDAPI

DIDStore_ListDIDs
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_ListDIDs
   :project: DIDAPI

DIDStore_StoreCredential
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_StoreCredential
   :project: DIDAPI

DIDStore_LoadCredential
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_LoadCredential
   :project: DIDAPI

DIDStore_ContainsCredentials
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_ContainsCredentials
   :project: DIDAPI

DIDStore_DeleteCredential
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_DeleteCredential
   :project: DIDAPI

DIDStore_ListCredentials
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_ListCredentials
   :project: DIDAPI

DIDStore_SelectCredentials
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_SelectCredentials
   :project: DIDAPI

DIDSotre_ContainsPrivateKeys
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDSotre_ContainsPrivateKeys
   :project: DIDAPI

DIDStore_ContainsPrivateKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_ContainsPrivateKey
   :project: DIDAPI

DIDStore_StorePrivateKey
~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_StorePrivateKey
   :project: DIDAPI

DIDStore_DeletePrivateKey
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDStore_DeletePrivateKey
   :project: DIDAPI

Mnemonic Functions
##################

Mnemonic_Generate
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Mnemonic_Generate
   :project: DIDAPI

Mnemonic_Free
~~~~~~~~~~~~~

.. doxygenfunction:: Mnemonic_Free
   :project: DIDAPI

Mnemonic_IsValid
~~~~~~~~~~~~~~~~

.. doxygenfunction:: Mnemonic_IsValid
   :project: DIDAPI


Presentation Functions
######################

Presentation_Create
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_Create
   :project: DIDAPI

Presentation_Destroy
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_Destroy
   :project: DIDAPI

Presentation_ToJson
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_ToJson
   :project: DIDAPI

Presentation_FromJson
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_FromJson
   :project: DIDAPI

Presentation_GetHolder
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_GetHolder
   :project: DIDAPI

Presentation_GetCredentialCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_GetCredentialCount
   :project: DIDAPI

Presentation_GetCredentials
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_GetCredentials
   :project: DIDAPI

Presentation_GetCredential
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_GetCredential
   :project: DIDAPI

Presentation_GetTypes
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_GetTypes
   :project: DIDAPI

Presentation_GetCreatedTime
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_GetCreatedTime
   :project: DIDAPI

Presentation_GetVerificationMethod
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_GetVerificationMethod
   :project: DIDAPI

Presentation_GetNonce
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_GetNonce
   :project: DIDAPI

Presentation_IsGenuine
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_IsGenuine
   :project: DIDAPI

Presentation_IsValid
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: Presentation_IsValid
   :project: DIDAPI

Issuer Functions
################

TransferTicket_Destroy
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_Destroy
   :project: DIDAPI

TransferTicket_ToJson
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_ToJson
   :project: DIDAPI

TransferTicket_FromJson
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_FromJson
   :project: DIDAPI

TransferTicket_IsValid
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_IsValid
   :project: DIDAPI

TransferTicket_IsQualified
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_IsQualified
   :project: DIDAPI

TransferTicket_IsGenuine
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_IsGenuine
   :project: DIDAPI

TransferTicket_GetProofCount
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_GetProofCount
   :project: DIDAPI

TransferTicket_GetProofType
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_GetProofType
   :project: DIDAPI

TransferTicket_GetSignKey
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_GetSignKey
   :project: DIDAPI

TransferTicket_GetProofCreatedTime
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_GetProofCreatedTime
   :project: DIDAPI

TransferTicket_GetProofSignature
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: TransferTicket_GetProofSignature
   :project: DIDAPI

DIDBackend Functions
####################

DIDBackend_InitializeDefault
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBackend_InitializeDefault
   :project: DIDAPI

DIDBackend_Initialize
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBackend_Initialize
   :project: DIDAPI

DIDBackend_IsInitialized
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBackend_IsInitialized
   :project: DIDAPI

DIDBackend_SetTTL
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBackend_SetTTL
   :project: DIDAPI

DIDBackend_SetLocalResolveHandle
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DIDBackend_SetLocalResolveHandle
   :project: DIDAPI