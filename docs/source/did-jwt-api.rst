Elastos DID Jwt APIs
============================

Data types
----------

JWT
####

.. doxygentypedef:: JWT
   :project: DIDAPI

Functions
---------

JWtBuilder Functions
########################

JWTBuilder_Destroy
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_Destroy
   :project: DIDAPI

JWTBuilder_SetHeader
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_SetHeader
   :project: DIDAPI

JWTBuilder_SetClaim
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_SetClaim
   :project: DIDAPI

JWTBuilder_SetClaimWithJson
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_SetClaimWithJson
   :project: DIDAPI

JWTBuilder_SetClaimWithBoolean
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_SetClaimWithBoolean
   :project: DIDAPI

JWTBuilder_SetIssuer
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_SetIssuer
   :project: DIDAPI

JWTBuilder_SetSubject
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_SetSubject
   :project: DIDAPI

JWTBuilder_SetAudience
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_SetAudience
   :project: DIDAPI

JWTBuilder_SetNotBefore
~~~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_SetNotBefore
   :project: DIDAPI

JWTBuilder_SetIssuedAt
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_SetIssuedAt
   :project: DIDAPI

JWTBuilder_SetId
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_SetId
   :project: DIDAPI

JWTBuilder_Sign
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_Sign
   :project: DIDAPI

JWTBuilder_Compact
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_Compact
   :project: DIDAPI

JWTBuilder_Reset
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTBuilder_Reset
   :project: DIDAPI


JWSParser Functions
###################

JWTParser_Parse
~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWTParser_Parse
   :project: DIDAPI

DefaultJWSParser_Parse
~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: DefaultJWSParser_Parse
   :project: DIDAPI

JWSParser_Parse
~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWSParser_Parse
   :project: DIDAPI

JWSParser_Destroy
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWSParser_Destroy
   :project: DIDAPI

JWT Functions
##############

JWT_Destroy
~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_Destroy
   :project: DIDAPI

JWT_GetHeader
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetHeader
   :project: DIDAPI


JWT_GetAlgorithm
~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetAlgorithm
   :project: DIDAPI

JWT_GetKeyId
~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetKeyId
   :project: DIDAPI

JWT_GetClaim
~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetClaim
   :project: DIDAPI

JWT_GetClaimAsJson
~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetClaimAsJson
   :project: DIDAPI

JWT_GetClaimAsInteger
~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetClaimAsInteger
   :project: DIDAPI

JWT_GetClaimAsBoolean
~~~~~~~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetClaimAsBoolean
   :project: DIDAPI

JWT_GetIssuer
~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetIssuer
   :project: DIDAPI

JWT_GetAudience
~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetAudience
   :project: DIDAPI

JWT_GetId
~~~~~~~~~~

.. doxygenfunction:: JWT_GetId
   :project: DIDAPI

JWT_GetExpiration
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetExpiration
   :project: DIDAPI

JWT_GetNotBefore
~~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetNotBefore
   :project: DIDAPI

JWT_GetIssuedAt
~~~~~~~~~~~~~~~~

.. doxygenfunction:: JWT_GetIssuedAt
   :project: DIDAPI