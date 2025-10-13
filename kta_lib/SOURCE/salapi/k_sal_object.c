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
  /* Adding a temporary attestation  token */
  uint8_t               aTokenBuffer[] = {0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x59, 0x01, 0x90, 0xa8, 0x3a, 0x00, 0x01, 0x24, 0xff, 0x58, 0x40, 0x82, 0x47, 0x1e, 0xa1, 0x43, 0x5f, 0x57, 0xe1, 0xac, 0x99, 0x5b, 0x11, 0xe1, 0x02, 0x98, 0x61, 0x54, 0xbb, 0xd2, 0xfa, 0xb6, 0x72, 0x61, 0xec, 0x6f, 0x7a, 0xc7, 0xce, 0x7b, 0x8a, 0x8a, 0xa8, 0x3d, 0x19, 0x98, 0xa4, 0x4d, 0x07, 0x55, 0xf8, 0x52, 0x28, 0x53, 0xad, 0x29, 0x2b, 0x8b, 0x33, 0xda, 0x1c, 0x53, 0x50, 0xee, 0xb6, 0x36, 0x31, 0x70, 0xfe, 0x11, 0x32, 0x96, 0xbb, 0x34, 0xa6, 0x3a, 0x00, 0x01, 0x24, 0xfb, 0x58, 0x20, 0x0a, 0x87, 0x38, 0x17, 0x4e, 0x55, 0xa0, 0xab, 0xc8, 0xd7, 0xa6, 0x89, 0x88, 0xfe, 0x32, 0xaa, 0x7b, 0x4c, 0xc8, 0xcf, 0xde, 0xa7, 0xdf, 0x6c, 0x83, 0xb5, 0x28, 0x69, 0x54, 0x2c, 0xaa, 0x8d, 0x3a, 0x00, 0x01, 0x25, 0x00, 0x58, 0x21, 0x01, 0x27, 0x8f, 0xe3, 0xe2, 0xea, 0xe5, 0x66, 0xc5, 0xd5, 0x6a, 0x03, 0x9f, 0x00, 0xbb, 0x54, 0xff, 0x1d, 0xef, 0xff, 0x24, 0xa0, 0xf0, 0xf2, 0xb2, 0x86, 0xb1, 0x76, 0x8f, 0x4d, 0x23, 0x3e, 0x6b, 0x3a, 0x00, 0x01, 0x24, 0xfa, 0x54, 0xfa, 0x95, 0x0f, 0x61, 0x08, 0x1d, 0x4e, 0x6f, 0xd8, 0x5b, 0x0f, 0x3f, 0xc8, 0x53, 0x28, 0x1e, 0x8d, 0x61, 0x39, 0x02, 0x3a, 0x00, 0x01, 0x24, 0xf8, 0x20, 0x3a, 0x00, 0x01, 0x24, 0xf9, 0x19, 0x30, 0x00, 0x3a, 0x00, 0x01, 0x24, 0xfd, 0x82, 0xa5, 0x01, 0x63, 0x53, 0x50, 0x45, 0x04, 0x65, 0x30, 0x2e, 0x32, 0x2e, 0x32, 0x05, 0x58, 0x20, 0xb1, 0xcc, 0xbe, 0x5a, 0x67, 0xcb, 0x28, 0x20, 0x33, 0x1d, 0x28, 0xe6, 0xd9, 0xa9, 0x50, 0xfe, 0x54, 0xd6, 0x1a, 0x68, 0x5c, 0x5a, 0xde, 0x86, 0xd6, 0xb9, 0x57, 0x58, 0xf8, 0x52, 0xfe, 0x41, 0x06, 0x66, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x02, 0x58, 0x20, 0xbd, 0xd6, 0x3d, 0x84, 0xf7, 0x93, 0xaf, 0x69, 0x86, 0x32, 0x37, 0x16, 0x14, 0x71, 0x33, 0x33, 0xe9, 0x2d, 0x20, 0x9e, 0x9d, 0x10, 0x78, 0x07, 0xdc, 0xce, 0x1a, 0x44, 0x12, 0x6d, 0x34, 0x7b, 0xa5, 0x01, 0x64, 0x41, 0x52, 0x6f, 0x54, 0x04, 0x65, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x05, 0x58, 0x20, 0x0e, 0x1d, 0xad, 0xfa, 0x96, 0x1f, 0xa0, 0x17, 0x78, 0x7b, 0xb5, 0x6c, 0x2a, 0xb9, 0xb3, 0xbf, 0xf9, 0xc8, 0x56, 0x99, 0x7e, 0xa6, 0x16, 0x97, 0x0f, 0xfd, 0xb9, 0xe1, 0xf8, 0x87, 0x33, 0xf3, 0x06, 0x66, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x02, 0x58, 0x20, 0x03, 0xb3, 0x63, 0x3a, 0x40, 0xb3, 0x28, 0x77, 0x42, 0xb9, 0x8a, 0x66, 0x64, 0x2d, 0x05, 0xdc, 0x1a, 0xdd, 0x9e, 0x3f, 0xd2, 0x19, 0x47, 0x9d, 0x2b, 0x47, 0x52, 0x72, 0x3e, 0x54, 0x9c, 0x20, 0x3a, 0x00, 0x01, 0x24, 0xfc, 0x6e, 0x30, 0x34, 0x30, 0x38, 0x30, 0x34, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x58, 0x40, 0x23, 0x77, 0x08, 0x87, 0xdd, 0x04, 0x88, 0xc8, 0x02, 0x4f, 0x4b, 0xd8, 0x99, 0x07, 0x25, 0xb3, 0xeb, 0x51, 0x41, 0x05, 0x0a, 0x45, 0xb3, 0x93, 0x44, 0xa3, 0x80, 0xe1, 0xb4, 0xb0, 0x7a, 0xbc, 0xba, 0x06, 0x5c, 0xc2, 0x17, 0x8a, 0xe6, 0x33, 0x00, 0x0b, 0x24, 0x82, 0x38, 0x77, 0x8c, 0x8f, 0x77, 0xc5, 0xd2, 0xdd, 0xa0, 0x84, 0xb2, 0x0c, 0xc7, 0xfd, 0x94, 0x34, 0xe7, 0xe6, 0x49, 0x9d};
  size_t                publicKeyLen = C_SAL_OBJ_PUBLIC_KEY_SIZE;
  size_t                sizeOut = sizeof(aTokenBuffer);
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

    /* replace public key in temporary token don't copy offset 0 as it is just to indicate it is a publuc key*/
    memcpy(&aTokenBuffer[18], &aPublicKey[1], 64);
   #if 0
    lpsaStatus = psa_initial_attest_get_token_size(C_SAL_OBJ_PUBLIC_KEY_SIZE - 1U, xpPublicKeyLen);

    if (PSA_SUCCESS != lpsaStatus)
    {
      devLogErr("\r\nERROR - psa_initial_attest_get_token_size failed[%d]\r\n", lpsaStatus);
      break;
    } // if
   #endif 
    // Generate "Initial Attestation Token"
    // Pre-Requesite to psa_initial_attest_get_token:
    // Integrator responsible for following steps
    // 1. Generate keypair for attestation
    // 2. Store private key trusted storage.
    // 3. Use private key from storage when psa_initial_attest_get_token callled
    //    to generate attestation token
    #if 0
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
    #endif
	
    memcpy(xpPublicKey, &aTokenBuffer, sizeOut);
	
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

    retStatus = psa_its_get(xObjectId, 0, (size_t) xpObject->dataLen, (void*)xpObject->data, &(xpObject->dataLen));

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
