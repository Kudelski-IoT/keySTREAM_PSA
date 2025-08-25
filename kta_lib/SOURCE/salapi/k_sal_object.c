/**********************************************************************************
*************************keySTREAM Trusted Agent ("KTA")***************************

* (c) 2023-2025 Nagravision Sàrl

* Subject to your compliance with these terms, you may use the Nagravision Sàrl and
* any derivatives exclusively with Nagravision's products. It is your responsibility
* to comply with third party license terms applicable to your use of third party
* software (including open source software) that mayaccompany Nagravision Software.

* Redistribution of this Nagravision Software in source or binary form is allowed
* and must include the above terms of use and the following disclaimer with the
* distribution and accompanying materials.

* THIS SOFTWARE IS SUPPLIED BY NAGRAVISION "AS IS". NO WARRANTIES, WHETHER EXPRESS,
* IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED WARRANTIES OF
* NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A PARTICULAR PURPOSE. IN NO
* EVENT WILL NAGRAVISION BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE, INCIDENTAL
* OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND WHATSOEVER RELATED TO
* THE SOFTWARE, HOWEVER CAUSED, EVEN IF NAGRAVISION HAS BEEN ADVISED OF THE
* POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW,
* NAGRAVISION'S TOTAL LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS
* SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY
* TO NAGRAVISION FOR THIS SOFTWARE.
***********************************************************************************/
/** \brief  SAL object for Generic PSA.
 *
 *  \author Kudelski IoT
 *
 *  \date 2023/06/12
 *
 *  \file k_sal_object.c
 ******************************************************************************/

#include "k_sal_object.h"
/* -------------------------------------------------------------------------- */
/* IMPORTS                                                                    */
/* -------------------------------------------------------------------------- */
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "psa/crypto.h"
#include "psa/internal_trusted_storage.h"
#include "psa/initial_attestation.h"

#include "log_api.h"

/* -------------------------------------------------------------------------- */
/* LOCAL CONSTANTS, TYPES, ENUM                                               */
/* -------------------------------------------------------------------------- */
#define M_UNUSED(xArg)            (void)(xArg)
/* Macro for public key size */
#define C_SAL_OBJ_PUBLIC_KEY_SIZE                    (65U)
/* Macro to association info length */
#define C_SAL_OBJ_ASSOC_INFO_SIZE                    (19U)
/* Macro to max length of the buffer containing the key attributes */
#define C_SAL_OBJ_MAX_ATTRIBUTE_SIZE                 (20U)
/* Macro to max attestation token size */
#define C_SAL_OBJ_ATTEST_CERT_MAX_LENGTH             (512U)
/* Macro to the offset of association info */
#define C_SAL_OBJ_ASSOC_INFO_OFFSET_VALUE            (4U)
/* Macro to max association info buffer size */
#define C_SAL_OBJ_ASSOC_INFO_MAX_BUFFER_SIZE         (520U)

/* -------------------------------------------------------------------------- */
/* LOCAL VARIABLES                                                            */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* LOCAL FUNCTIONS - PROTOTYPE                                                */
/* -------------------------------------------------------------------------- */
static void lDataSerializer(uint8_t* xpDataBuffer, uint32_t xInData, uint8_t xOffset);

/* -------------------------------------------------------------------------- */
/* PUBLIC VARIABLES                                                           */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* PUBLIC FUNCTIONS - IMPLEMENTATION                                          */
/* -------------------------------------------------------------------------- */
/******************************************************************************/
/** \implements salObjectKeyGen
 *
 ******************************************************************************/
K_SAL_API TKStatus salObjectKeyGen
(
  uint32_t       xPsaKeyId,
  const uint8_t* xpPsaKeyAttributes,
  size_t         xPsaKeyAttributesLen,
  uint8_t*       xpPublicKey,
  size_t*        xpPublicKeyLen,
  uint8_t*       xpPlatformStatus
)
{
  TKStatus              status                               = E_K_STATUS_ERROR;
  psa_status_t          lpsaStatus                           = PSA_ERROR_GENERIC_ERROR;
  psa_key_id_t          keyId                                = {0};
  uint8_t               aPublicKey[C_SAL_OBJ_PUBLIC_KEY_SIZE] = {0};
  size_t                publicKeyLen = C_SAL_OBJ_PUBLIC_KEY_SIZE;
  size_t                sizeOut = 0;
  psa_key_attributes_t  keyAttr;
  uint16_t              type             = 0;
  uint16_t              bits             = 0;
  uint32_t              lifetime         = 0;
  uint32_t              id               = 0;
  uint32_t              usage            = 0;
  uint32_t              alg              = 0;

  devLog("start");

  for (;;)
  {
    if ((0U == xPsaKeyId)                                      ||
        (NULL == xpPsaKeyAttributes)                           ||
        (C_SAL_OBJ_MAX_ATTRIBUTE_SIZE != xPsaKeyAttributesLen) ||
        (NULL == xpPublicKey)                                  ||
        (NULL == xpPlatformStatus)                                  ||
        (NULL == xpPublicKeyLen)                               ||
        (C_SAL_OBJ_ATTEST_CERT_MAX_LENGTH != *xpPublicKeyLen)
       )
    {
      devLogErr("ERROR - Parameter validation failed...!");
      status = E_K_STATUS_PARAMETER;
      break;
    } // if

    type     = (xpPsaKeyAttributes[0] << 8) | xpPsaKeyAttributes[1];
    bits     = (xpPsaKeyAttributes[2] << 8) | xpPsaKeyAttributes[3];
    lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_PERSISTENT,
                                                              PSA_KEY_LOCATION_LOCAL_STORAGE);
    alg      = (xpPsaKeyAttributes[16] << 24) | (xpPsaKeyAttributes[17] << 16) |
               (xpPsaKeyAttributes[18] << 8) | xpPsaKeyAttributes[19];
    id       = (xpPsaKeyAttributes[8] << 24) | (xpPsaKeyAttributes[9] << 16) |
               (xpPsaKeyAttributes[10] << 8) | xpPsaKeyAttributes[11];
    usage    = (xpPsaKeyAttributes[12] << 24) | (xpPsaKeyAttributes[13] << 16) |
               (xpPsaKeyAttributes[14] << 8)  | xpPsaKeyAttributes[15];

    keyAttr = psa_key_attributes_init();
    psa_set_key_type(&keyAttr, type);
    psa_set_key_bits(&keyAttr, bits);
    psa_set_key_usage_flags(&keyAttr, usage);
    psa_set_key_algorithm(&keyAttr, alg);
    psa_set_key_id(&keyAttr, id);
    psa_set_key_lifetime(&keyAttr, lifetime);
    psa_destroy_key(id);
    // Generate a random persistent wrapped key
    lpsaStatus = psa_generate_key(&keyAttr, &keyId);

    if ((PSA_SUCCESS != lpsaStatus) && (PSA_ERROR_ALREADY_EXISTS != lpsaStatus))
    {
      devLogErr("ERROR - psa_generate_key failed[%d]", lpsaStatus);
      break;
    } // if

    if (keyId != xPsaKeyId)
    {
      devLogErr("ERROR -  psa_generate_key failed[%d], ID not matched", lpsaStatus);
      break;
    } // if

    // Export a public key from a persistent private wrapped key
    lpsaStatus = psa_export_public_key(xPsaKeyId, aPublicKey, publicKeyLen, &publicKeyLen);

    if ((PSA_SUCCESS != lpsaStatus) && (PSA_ERROR_ALREADY_EXISTS != lpsaStatus))
    {
      devLogErr("ERROR - psa_export_public_key failed[%d]", lpsaStatus);
      break;
    } // if

    lpsaStatus = psa_initial_attest_get_token_size(C_SAL_OBJ_PUBLIC_KEY_SIZE - 1U, xpPublicKeyLen);

    if (PSA_SUCCESS != lpsaStatus)
    {
      devLogErr("\r\nERROR - psa_initial_attest_get_token_size failed[%d]\r\n", lpsaStatus);
      break;
    } // if

    // Generate "Initial Attestation Token"
    // Pre-Requesite to psa_initial_attest_get_token:
    // Integrator responsible for following steps
    // 1. Generate keypair for attestation
    // 2. Store private key trusted storage.
    // 3. Use private key from storage when psa_initial_attest_get_token callled
    //    to generate attestation token
    lpsaStatus = psa_initial_attest_get_token(&aPublicKey[1],
                                              C_SAL_OBJ_PUBLIC_KEY_SIZE - 1U,
                                              xpPublicKey,
                                              *xpPublicKeyLen,
                                              &sizeOut);

    if (PSA_SUCCESS != lpsaStatus)
    {
      devLogErr("\r\nERROR - psa_initial_attest_get_token failed[%d]\r\n", lpsaStatus);
      break;
    } // if

    *xpPublicKeyLen = sizeOut;
    status = E_K_STATUS_OK;
    break;
  } // for (;;)

  xpPlatformStatus[0] = ((lpsaStatus >> 24) & 0xFF);
  xpPlatformStatus[1] = ((lpsaStatus >> 16) & 0xFF);
  xpPlatformStatus[2] = ((lpsaStatus >> 8) & 0xFF);
  xpPlatformStatus[3] = (lpsaStatus & 0xFF);

  devLogKStatus(status, "end");
  return status;
} //salObjectKeyGen

/******************************************************************************/
/** \implements salObjectSet
 *
 ******************************************************************************/
K_SAL_API TKStatus salObjectSet
(
  TKSalObjectType   xObjectType,
  uint32_t          xIdentifier,
  const uint8_t*    xpDataAttributes,
  size_t            xDataAttributesLen,
  object_t*       xpObject,
  uint8_t*        xpPlatformStatus
)
{
  TKStatus status = E_K_STATUS_ERROR;
  psa_status_t  psaStatus = PSA_ERROR_GENERIC_ERROR;
  uint32_t createFlags =  0U;

  devLog("start");

  for (;;)
  {
    if (
      ((E_K_SAL_OBJECT_TYPE_DATA != xObjectType) &&
       (E_K_SAL_OBJECT_TYPE_CERTFICATE != xObjectType))  ||
      (0U == xIdentifier)                           ||
      (NULL == xpObject)                          ||
      (NULL == xpPlatformStatus)
    )
    {
      devLogErr("Parameter validation failed...!");
      status = E_K_STATUS_PARAMETER;
      break;
    } // if

    /**For KTA there is no requirement to set (psa_storage_create_flags_t)
     * attribute from keySTREAM**/
    if ((xDataAttributesLen != 0U) && (xpDataAttributes != NULL))
    {
      createFlags  = (xpDataAttributes[4] << 24) | (xpDataAttributes[5] << 16) |
                     (xpDataAttributes[6] << 8) | xpDataAttributes[7];
    } // if

    psaStatus = psa_its_set(xIdentifier,
                            (size_t) xpObject->dataLen,
                            (void*) xpObject->data,
                            createFlags);

    if (PSA_SUCCESS != psaStatus)
    {
      devLogErr("PSA write failed[%d]\n", psaStatus);
      break;
    } // if

    status = E_K_STATUS_OK;
    break;
  } // for (;;)

  xpPlatformStatus[0] = ((psaStatus >> 24) & 0xFF);
  xpPlatformStatus[1] = ((psaStatus >> 16) & 0xFF);
  xpPlatformStatus[2] = ((psaStatus >> 8) & 0xFF);
  xpPlatformStatus[3] = (psaStatus & 0xFF);

  devLogKStatus(status, "end");
  return status;
} //salObjectSet

/******************************************************************************/
/** \implements salObjectKeySet
 *
 ******************************************************************************/
K_SAL_API TKStatus salObjectKeySet
(
  uint32_t        xKeyId,
  const uint8_t*  xpKeyAttributes,
  size_t          xKeyAttributesLen,
  const uint8_t*  xpKey,
  size_t          xKeyLen,
  uint8_t*        xpPlatformStatus
)
{
  M_UNUSED(xKeyId);
  M_UNUSED(xpKeyAttributes);
  M_UNUSED(xKeyAttributesLen);
  M_UNUSED(xpKey);
  M_UNUSED(xKeyLen);
  M_UNUSED(xpPlatformStatus);
  return E_K_STATUS_OK;
} //salObjectKeySet

/******************************************************************************/
/** \implements salObjectGet
 *
 ******************************************************************************/
K_SAL_API TKStatus salObjectGet
(
  TKSalObjectType        xObjectType,
  uint32_t               xObjectId,
  object_t*              xpObject,
  uint8_t*               xpPlatformStatus
)
{
  psa_status_t  retStatus = !PSA_SUCCESS;
  TKStatus    status = E_K_STATUS_ERROR;    // Status from sal layer

  devLog("start");

  for (;;)
  {
    if ((xObjectType >= E_K_SAL_OBJECT_TYPE_MAX_NUM) ||
        (0U == xObjectId)                            ||
        (NULL == xpObject)                       ||
        (NULL == xpPlatformStatus)
       )
    {
      devLogErr("Parameter validation failed...!");
      status = E_K_STATUS_PARAMETER;
      break;
    } // if

    retStatus = psa_its_get(xObjectId, 0, (size_t) xpObject->dataLen, (void*)xpObject->data, (size_t*) xpObject->dataLen);

    if (PSA_SUCCESS != retStatus)
    {
      devLogErr("PSA read failed[%d]\n", retStatus);
      break;
    } // if

    status = E_K_STATUS_OK;
    break;
  } // for (;;)

  xpPlatformStatus[0] = ((retStatus >> 24) & 0xFF);
  xpPlatformStatus[1] = ((retStatus >> 16) & 0xFF);
  xpPlatformStatus[2] = ((retStatus >> 8) & 0xFF);
  xpPlatformStatus[3] = (retStatus & 0xFF);

  devLogKStatus(status, "end");
  return status;
} //salObjectGet

/******************************************************************************/
/** \implements salObjectDelete
*
******************************************************************************/
K_SAL_API TKStatus salObjectDelete
(
  TKSalObjectType xObjectType,
  uint32_t        xObjectId,
  uint8_t*        xpPlatformStatus
)
{
  psa_status_t  retStatus = !PSA_SUCCESS;
  TKStatus    status = E_K_STATUS_ERROR;    // Status from sal layer

  devLog("start");

  for (;;)
  {
    if ((xObjectType >= E_K_SAL_OBJECT_TYPE_MAX_NUM) ||
        (0U == xObjectId))
    {
      devLogErr("Parameter validation failed...!");
      status = E_K_STATUS_PARAMETER;
      break;
    } // if

    retStatus = psa_its_remove(xObjectId);

    if (PSA_SUCCESS != retStatus)
    {
      devLogErr("PSA remove failed[%d]\n", retStatus);
      break;
    } // if

    status = E_K_STATUS_OK;
    break;
  } // for (;;)

  xpPlatformStatus[0] = ((retStatus >> 24) & 0xFF);
  xpPlatformStatus[1] = ((retStatus >> 16) & 0xFF);
  xpPlatformStatus[2] = ((retStatus >> 8) & 0xFF);
  xpPlatformStatus[3] = (retStatus & 0xFF);

  devLogKStatus(status, "end");
  return status;
} // salObjectDelete

/******************************************************************************/
/** \implements salObjectKeyDelete
 *
 ******************************************************************************/
K_SAL_API TKStatus salObjectKeyDelete
(
  uint32_t               xKeyId,
  uint8_t*               xpPlatformStatus
)
{
  psa_status_t  retStatus = !PSA_SUCCESS;
  TKStatus      status = E_K_STATUS_ERROR;    // Status from sal layer

  devLog("start");

  for (;;)
  {
    if ((0U == xKeyId)  || (NULL == xpPlatformStatus))
    {
      devLogErr("Parameter validation failed...!");
      status = E_K_STATUS_PARAMETER;
      break;
    } // if

    retStatus = psa_destroy_key(xKeyId);

    if (PSA_SUCCESS != retStatus)
    {
      devLogErr("PSA key destroy failed[%d]\n", retStatus);
      break;
    } // if

    status = E_K_STATUS_OK;
    break;
  } // for (;;)

  xpPlatformStatus[0] = ((retStatus >> 24) & 0xFF);
  xpPlatformStatus[1] = ((retStatus >> 16) & 0xFF);
  xpPlatformStatus[2] = ((retStatus >> 8) & 0xFF);
  xpPlatformStatus[3] = (retStatus & 0xFF);

  devLogKStatus(status, "end");
  return status;
} //salObjectKeyDelete

/******************************************************************************/
/** \implements salObjectSetWithAssociation
 *
 ******************************************************************************/
K_SAL_API TKStatus salObjectSetWithAssociation
(
  uint32_t                 xObjectType,
  uint32_t                 xObjectWithAssociationId,
  const uint8_t*           xpDataAttributes,
  size_t                   xDataAttributesLen,
  const uint8_t*           xpData,
  size_t                   xDataLen,
  TKSalObjAssociationInfo* xpAssociationInfo,
  uint8_t*                 xpPlatformStatus
)
{
  TKStatus     status       = E_K_STATUS_ERROR;
  psa_status_t pstatus      = !PSA_SUCCESS;
  uint8_t      aObjDataWithAssociation[C_SAL_OBJ_ASSOC_INFO_MAX_BUFFER_SIZE] = {0};
  uint8_t      dataOffset   = 0;
  size_t       totalDataLen = 0;

  devLog("start");

  for (;;)
  {
    if ((3U < xObjectType)              ||
        (0U == xObjectWithAssociationId)  ||
        ((0U != xDataAttributesLen) && (NULL == xpDataAttributes))  ||
        (NULL == xpData)              ||
        (0U == xDataLen)              ||
        (NULL == xpAssociationInfo)       ||
        (NULL == xpPlatformStatus))
    {
      devLogErr("ERROR - Parameter validation failed...!");
      status = E_K_STATUS_PARAMETER;
      break;
    } // if

    lDataSerializer(aObjDataWithAssociation,
                    xpAssociationInfo->associatedKeyId, dataOffset);
    dataOffset += C_SAL_OBJ_ASSOC_INFO_OFFSET_VALUE;//4
    lDataSerializer(aObjDataWithAssociation,
                    xpAssociationInfo->associatedKeyIdDeprecated, dataOffset);
    dataOffset += C_SAL_OBJ_ASSOC_INFO_OFFSET_VALUE;//8
    lDataSerializer(aObjDataWithAssociation,
                    xpAssociationInfo->associatedObjectId, dataOffset);
    dataOffset += C_SAL_OBJ_ASSOC_INFO_OFFSET_VALUE;//12
    lDataSerializer(aObjDataWithAssociation,
                    xpAssociationInfo->associatedObjectIdDeprecated, dataOffset);
    dataOffset += C_SAL_OBJ_ASSOC_INFO_OFFSET_VALUE;//16
    aObjDataWithAssociation[dataOffset] = (xpAssociationInfo->associatedObjectType & 0xFFU);
    dataOffset++;
    aObjDataWithAssociation[dataOffset] = ((xDataLen >> 8) & 0xFFU);
    dataOffset++;
    aObjDataWithAssociation[dataOffset] = (xDataLen & 0xFFU);

    (void)memcpy(&aObjDataWithAssociation[C_SAL_OBJ_ASSOC_INFO_SIZE], xpData, xDataLen);
    /* Concatinating both association info length + Input data length */
    totalDataLen = xDataLen + C_SAL_OBJ_ASSOC_INFO_SIZE;

    pstatus = psa_its_set(xObjectWithAssociationId, totalDataLen, aObjDataWithAssociation, 0);

    if (PSA_SUCCESS != pstatus)
    {
      devLogErr("ERROR - PSA write failed[%d]\n", pstatus);
      status = E_K_STATUS_ERROR;
      break;
    } // if

    pstatus = PSA_SUCCESS;
    status = E_K_STATUS_OK;
    break;
  } // for (;;)

  xpPlatformStatus[0] = ((pstatus >> 24) & 0xFF);
  xpPlatformStatus[1] = ((pstatus >> 16) & 0xFF);
  xpPlatformStatus[2] = ((pstatus >> 8) & 0xFF);
  xpPlatformStatus[3] = (pstatus & 0xFF);

  devLogKStatus(status, "end");
  return status;
} //salObjectSetWithAssociation


/******************************************************************************/
/** \implements salObjectGetWithAssociation
 *
 ******************************************************************************/
K_SAL_API TKStatus salObjectGetWithAssociation
(
  uint32_t                 xObjectWithAssociationId,
  const uint8_t*           xpData,
  size_t*                  xpDataLen,
  TKSalObjAssociationInfo* xpAssociationInfo,
  uint8_t*                 xpPlatformStatus
)
{
  TKStatus status = E_K_STATUS_ERROR;
  psa_status_t pstatus = !PSA_SUCCESS;
  uint8_t aObjDataWithAssociation[C_SAL_OBJ_ASSOC_INFO_MAX_BUFFER_SIZE] = {0};

  devLog("start");

  for (;;)
  {
    if ((0U == xObjectWithAssociationId) ||
        (NULL == xpData)             ||
        (NULL == xpDataLen)           ||
        (0U == *xpDataLen)            ||
        (NULL == xpAssociationInfo)       ||
        (NULL == xpPlatformStatus))
    {
      devLogErr("ERROR - Parameter validation failed...!");
      status = E_K_STATUS_PARAMETER;
      break;
    } // if

    pstatus = psa_its_get(xObjectWithAssociationId,
                          0,
                          *xpDataLen,
                          (void*)aObjDataWithAssociation,
                          xpDataLen);

    if (PSA_SUCCESS != pstatus)
    {
      devLogErr("ERROR - PSA read failed[%d]\n", pstatus);
      status = E_K_STATUS_ERROR;
      break;
    } // if

    xpAssociationInfo->associatedKeyId =
      (aObjDataWithAssociation[0] << 24) | (aObjDataWithAssociation[1] << 16) |
      (aObjDataWithAssociation[2] << 8) | aObjDataWithAssociation[3];
    xpAssociationInfo->associatedKeyIdDeprecated =
      (aObjDataWithAssociation[4] << 24) | (aObjDataWithAssociation[5] << 16) |
      (aObjDataWithAssociation[6] << 8) | aObjDataWithAssociation[7];
    xpAssociationInfo->associatedObjectId =
      (aObjDataWithAssociation[8] << 24) | (aObjDataWithAssociation[9] << 16) |
      (aObjDataWithAssociation[10] << 8) | aObjDataWithAssociation[11];
    xpAssociationInfo->associatedObjectIdDeprecated =
      (aObjDataWithAssociation[12] << 24) | (aObjDataWithAssociation[13] << 16) |
      (aObjDataWithAssociation[14] << 8) | aObjDataWithAssociation[15];

    xpAssociationInfo->associatedObjectType = aObjDataWithAssociation[16];

    *xpDataLen  = (aObjDataWithAssociation[17] << 8) | aObjDataWithAssociation[18];

    (void)memcpy(xpData, &aObjDataWithAssociation[C_SAL_OBJ_ASSOC_INFO_SIZE], *xpDataLen);
    pstatus = PSA_SUCCESS;
    status = E_K_STATUS_OK;
    break;
  } // for

  xpPlatformStatus[0] = ((pstatus >> 24) & 0xFF);
  xpPlatformStatus[1] = ((pstatus >> 16) & 0xFF);
  xpPlatformStatus[2] = ((pstatus >> 8) & 0xFF);
  xpPlatformStatus[3] = (pstatus & 0xFF);

  devLogKStatus(status, "end");
  return status;
} //salObjectGetWithAssociation

/******************************************************************************/
/** \implements salGetChallenge
 *
 ******************************************************************************/
K_SAL_API TKStatus salGetChallenge
(
  uint8_t* xpChallengeKey,
  uint8_t* xpPlatformStatus
)
{
  M_UNUSED(xpChallengeKey);
  M_UNUSED(xpPlatformStatus);
  return E_K_STATUS_OK;
} //salGetChallenge

/* -------------------------------------------------------------------------- */
/* LOCAL FUNCTIONS - IMPLEMENTATION                                                */
/* -------------------------------------------------------------------------- */
/**
 * @brief
 *    API to serialize the data
 *
 * @param[in, out]  dataBuffer
 *                  Serialize data buffer.
 * @param[in]       InData
 *                  Data to serialize.
 * @param[in]       offset
 *                  Offset from where data to be written.
 *
 */
static void lDataSerializer(uint8_t* xpDataBuffer, uint32_t xInData, uint8_t xOffset)
{
  if (NULL == xpDataBuffer)
  {
    devLogErr("ERROR - Data buffer is not valid...!");
  } // if

  xpDataBuffer[xOffset]   = ((xInData >> 24U) & 0xFFu);
  xpDataBuffer[xOffset + 1U] = ((xInData >> 16U) & 0xFFu);
  xpDataBuffer[xOffset + 2U] = ((xInData >> 8U) & 0xFFu);
  xpDataBuffer[xOffset + 3U] = (xInData & 0xFFu);
} //lDataSerializer

/* -------------------------------------------------------------------------- */
/* END OF FILE                                                                */
/* -------------------------------------------------------------------------- */
