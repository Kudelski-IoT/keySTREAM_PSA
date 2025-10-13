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
/** \brief  SAL crypto for Generic PSA.
 *
 *  \author Kudelski IoT
 *
 *  \date 2023/06/12
 *
 *  \file k_sal_crypto.c
 ******************************************************************************/

/**
 * @brief SAL crypto for Generic PSA.
 */

#include "k_sal_crypto.h"
/* -------------------------------------------------------------------------- */
/* IMPORTS                                                                    */
/* -------------------------------------------------------------------------- */
#include "psa/crypto_sizes.h"
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_values.h"
#include "k_defs.h"
#include "k_sal.h"
#include "KTALog.h"
#include "k_sal_object.h"
#include "k_sal_rot.h"
#include "psa/initial_attestation.h"

#include <string.h>
#include <stdio.h>

/* -------------------------------------------------------------------------- */
/* LOCAL CONSTANTS, TYPES, ENUM                                               */
/* -------------------------------------------------------------------------- */
#define KEY_DUMP 1

/** @brief L1 field key id. */
#define C_SAL_CRYPTO_PSA_L1_FIELD_KEY_ID        (0x01000100u)

/** @brief Attestation Certificate Maximum Length. */
#define C_SAL_CRYPTO_ATTEST_CERT_MAX_LENGTH     (512u)

/** @brief Max key length. */
#define C_SAL_CRYPTO_MAX_KEY_LENGTH             (512u)

/** @brief Shared secret bit mask. */
#define C_SAL_CRYPTO_SHARED_SECRET_BITMASK      (0x80000000u)

/** @brief Public Key Length. */
#define C_SAL_CRYPTO_PSA_PUBLIC_KEY_MAX_SIZE    (65u)

/** @brief Public Key Length. */
#define C_SAL_CRYPTO_PUBLIC_KEY_SIZE            (64u)

/** @brief X509 CERT ID. */
#define C_SAL_CRYPTO_X509_CERT_ID               (0x000080A0u)

/** @brief Get the value of bit at 31. */
#define M_SAL_CRYPTO_GET_BIT31(x_shared_secret)  \
  ((x_shared_secret & C_SAL_CRYPTO_SHARED_SECRET_BITMASK) == C_SAL_CRYPTO_SHARED_SECRET_BITMASK)

/** @brief Other data size for digest calculation. */
#define C_SAL_CRYPTO_OTHER_DATA_SIZE            (3u)

/** @brief Shared secret key length. */
#define C_SHARED_SECRET_KEY_LEN                 (32u)

/** @brief Mac length in act req. */
#define C_MAX_ACT_MAC_LENGTH                    (32u)

/** @brief Max PSA key bits. */
#define C_MAX_PSA_KEY_BITS                      (256u)

/** @brief PSA key bits. */
#define C_PSA_KEY_BITS                          (128u)

/** @brief Max signature/message size. */
#define C_MAX_SIG_MSG_SIZE                      (64u)

/** @brief Max Secret size. */
#define C_MAX_SECRET_SIZE                       (16u)

/** @brief Attestation TAG. */
#define C_ATTESTATION_TAG                       (0xF9u)

/** @brief Birth certificate TAG. */
#define C_BIRTH_CERT_TAG                        (0xF3u)


/** @brief Sal ID Map Object. */
typedef struct
{
  uint32_t virutalObjId;
  /* Data slot to key ID. */
  union
  {
    uint8_t aSessionObjId[C_SAL_CRYPTO_MAX_KEY_LENGTH];
  } data;
  /* Session obj ID buffer. */
} TKSalObjectIdMap;

/** @brief Cipher Operation types. */
typedef enum
{
  E_K_SAL_ENCRYPT = 1,
  /* Encryption operation. */
  E_K_SAL_DECRYPT,
  /* Decryption operation. */
  E_K_INVALID_OPS
  /* Invalid operation. */
} TKCipherOps;

/* -------------------------------------------------------------------------- */
/* LOCAL VARIABLES                                                            */
/* -------------------------------------------------------------------------- */

/** @brief Macro to enable debug logs. */
static const char* gpModuleName = "SALCRYPTO";

/** @brief Sal object ID map table. */
static TKSalObjectIdMap gaSalObjectIdMapTable[] =
{
  {C_K_KTA__CHIP_SK_ID, {{[0] = 0x01}}},
  {C_K_KTA__VOLATILE_ID, {{0}}},
  {C_K_KTA__VOLATILE_2_ID, {{0}}},
  {C_K_KTA__VOLATILE_3_ID, {{0}}},
  {C_K_KTA__L1_FIELD_KEY_ID, {{0}}}
};

/* Shared secret key. */
static uint8_t      gaSharedSecret[C_SHARED_SECRET_KEY_LEN] = {0};

/* Psa return status. */
static psa_status_t gPsaStatus;
/* -------------------------------------------------------------------------- */
/* LOCAL FUNCTIONS - PROTOTYPE                                                */
/* -------------------------------------------------------------------------- */

/**
 * @brief
 *   Set the value using the ID.
 *
 * @param[in] xObjectId
 *   Input key: identifier.
 * @param[in] xpValue
 *   Key data buffer. Should not be NULL.
 * @param[in] xValueLen
 *   Length of the buffer xpValue.
 *
 * @return
 * - E_K_STATUS_OK in case of success.
 * - E_K_STATUS_ERROR for other errors.
 */
static TKStatus lSetValueById
(
  uint32_t  xObjectId,
  uint8_t*  xpValue,
  size_t    xValueLen
);

/**
 * @brief
 *   Get the value using the ID
 *
 * @param[in] xObjectId
 *   Input key: identifier.
 * @param[out] xpValue
 *   Buffer to load the key data. Should not be NULL.
 * @param[in] xValueLen
 *   Length of the buffer xpValue.
 *
 * @return
 * - E_K_STATUS_OK in case of success.
 * - E_K_STATUS_ERROR for other errors.
 */
static TKStatus lGetValueById
(
  uint32_t  xObjectId,
  uint8_t*  xpValue,
  size_t    xValueLen
);

/**
 * @brief
 *   Generic function to encrypt/decrypt  data based on AES-128 CBC.
 *   The key is always located inside the
 *   secure platform and addressed by an identifier.
 * @param[in] xOps
 *   Input  operation type.
 * @param[in] xKeyId
 *   Input key: identifier.
 * @param[in] xpInputData
 *   Plain input data: pointer to buffer; Should not be NULL.
 * @param[in] xInputDataLen
 *   Length of xpInputData.
 * @param[out] xpOutputData
 *   Encrypted output data: pointer to buffer. Should not be NULL.
 * @param[in,out] xpOutputDataLen
 *   [in]  Length of xpOutputData buffer.
 *   [out] Length of filled output data.
 *   Should not be NULL.
 *
 * @return
 * - E_K_STATUS_OK in case of success.
 * - E_K_STATUS_PARAMETER for wrong input parameter(s).
 * - E_K_STATUS_ERROR for other errors.
 */
static TKStatus lDoCipherOps
(
  TKCipherOps     xOps,
  uint32_t        xKeyId,
  const uint8_t*  xpInputData,
  size_t          xInputDataLen,
  uint8_t*        xpOutputData,
  size_t*         xpOutputDataLen
);

/**
 * @brief
 *   Destory the psa key based on the object Id.
 *
 * @param[in] xObjectId
 *   Object key ID.
 */
static psa_status_t lPsaDestoryKey
(
  uint32_t  xObjectId
);

/**
 * @brief
 *   Convert little endien to big endien.
 *
 * @param[in,out] xpChipUid
 *   Address of buffer chip_uid.
 *   [in]  ChipUid in little endien format.
 *   [out] ChipUid in big endien format.
 *   Should not be NULL.
 * @param[in] xChipUidLen
 *   [in]  Length of xpChipUid buffer.
 *   [out] Length of filled output data.
 */
static void lConvertToBigEndien
(
  uint8_t*  xpChipUid,
  size_t    xChipUidLen
);

#ifdef KEY_DUMP
/**
 * @implements lPrintKey
 *
 **/
static void lPrintKey
(
  psa_key_id_t  xKeyId,
  size_t    data_size
);
#endif // KEY_DUMP

/* -------------------------------------------------------------------------- */
/* PUBLIC VARIABLES                                                           */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* PUBLIC FUNCTIONS - IMPLEMENTATION                                          */
/* -------------------------------------------------------------------------- */

/**
 * @brief  implement salRotGetChipCertificate
 *
 */
K_SAL_API TKStatus salRotGetChipCertificate
(
  uint8_t*  xpChipCert,
  size_t*   xpChipCertLen
)
{
  psa_key_id_t          psaChipKeyPairKeyId = 0;
  psa_key_attributes_t  keyAttr;
  uint8_t               aPublicKey[C_SAL_CRYPTO_PSA_PUBLIC_KEY_MAX_SIZE] = {0};
  size_t                publicKeyLen = sizeof(aPublicKey);
  //uint8_t             aTokenBuffer[C_SAL_CRYPTO_ATTEST_CERT_MAX_LENGTH] = {0};
   size_t                tokenBufferSize = C_SAL_CRYPTO_ATTEST_CERT_MAX_LENGTH;
  TKStatus              status = E_K_STATUS_ERROR;

  uint8_t               platformStatus[4] = {0};
  size_t                certDatasize = 0;
  object_t              certParams;
  // -------------------------------------------------------------------------
  // attestationToken and f3Cert are hardcoded for the F3 certificate
  // -------------------------------------------------------------------------
  uint8_t               aTokenBuffer[] = { 0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x59, 0x01, 0x90, 0xa8, 0x3a, 0x00, 0x01, 0x24, 0xff, 0x58, 0x40, 0x5b, 0x62, 0x8e, 0xd6, 0x69, 0xec, 0x4d, 0x54, 0x34, 0x33, 0x0c, 0xf1, 0xed, 0xb7, 0xea, 0x6a, 0xcd, 0x89, 0x4d, 0x5b, 0xb2, 0x71, 0x85, 0xf2, 0xe9, 0xdf, 0x95, 0x6a, 0xc9, 0x08, 0xaa, 0x12, 0x6f, 0xa4, 0x7b, 0x11, 0xc6, 0x6d, 0x34, 0x6b, 0x28, 0xc5, 0x1f, 0x18, 0x4b, 0xce, 0xef, 0x76, 0x54, 0x71, 0x7a, 0x7f, 0xe9, 0x81, 0xf4, 0x0e, 0x47, 0x8b, 0xb4, 0x58, 0xc8, 0x10, 0xd6, 0x10, 0x3a, 0x00, 0x01, 0x24, 0xfb, 0x58, 0x20, 0x0a, 0x87, 0x38, 0x17, 0x4e, 0x55, 0xa0, 0xab, 0xc8, 0xd7, 0xa6, 0x89, 0x88, 0xfe, 0x32, 0xaa, 0x7b, 0x4c, 0xc8, 0xcf, 0xde, 0xa7, 0xdf, 0x6c, 0x83, 0xb5, 0x28, 0x69, 0x54, 0x2c, 0xaa, 0x8d, 0x3a, 0x00, 0x01, 0x25, 0x00, 0x58, 0x21, 0x01, 0x27, 0x8f, 0xe3, 0xe2, 0xea, 0xe5, 0x66, 0xc5, 0xd5, 0x6a, 0x03, 0x9f, 0x00, 0xbb, 0x54, 0xff, 0x1d, 0xef, 0xff, 0x24, 0xa0, 0xf0, 0xf2, 0xb2, 0x86, 0xb1, 0x76, 0x8f, 0x4d, 0x23, 0x3e, 0x6a, 0x3a, 0x00, 0x01, 0x24, 0xfa, 0x54, 0xfa, 0x95, 0x0f, 0x61, 0x08, 0x1d, 0x4e, 0x6f, 0xd8, 0x5b, 0x0f, 0x3f, 0xc8, 0x53, 0x28, 0x1e, 0x8d, 0x61, 0x39, 0x02, 0x3a, 0x00, 0x01, 0x24, 0xf8, 0x20, 0x3a, 0x00, 0x01, 0x24, 0xf9, 0x19, 0x30, 0x00, 0x3a, 0x00, 0x01, 0x24, 0xfd, 0x82, 0xa5, 0x01, 0x63, 0x53, 0x50, 0x45, 0x04, 0x65, 0x30, 0x2e, 0x32, 0x2e, 0x32, 0x05, 0x58, 0x20, 0xb1, 0xcc, 0xbe, 0x5a, 0x67, 0xcb, 0x28, 0x20, 0x33, 0x1d, 0x28, 0xe6, 0xd9, 0xa9, 0x50, 0xfe, 0x54, 0xd6, 0x1a, 0x68, 0x5c, 0x5a, 0xde, 0x86, 0xd6, 0xb9, 0x57, 0x58, 0xf8, 0x52, 0xfe, 0x41, 0x06, 0x66, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x02, 0x58, 0x20, 0xbd, 0xd6, 0x3d, 0x84, 0xf7, 0x93, 0xaf, 0x69, 0x86, 0x32, 0x37, 0x16, 0x14, 0x71, 0x33, 0x33, 0xe9, 0x2d, 0x20, 0x9e, 0x9d, 0x10, 0x78, 0x07, 0xdc, 0xce, 0x1a, 0x44, 0x12, 0x6d, 0x34, 0x7b, 0xa5, 0x01, 0x64, 0x41, 0x52, 0x6f, 0x54, 0x04, 0x65, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x05, 0x58, 0x20, 0x0e, 0x1d, 0xad, 0xfa, 0x96, 0x1f, 0xa0, 0x17, 0x78, 0x7b, 0xb5, 0x6c, 0x2a, 0xb9, 0xb3, 0xbf, 0xf9, 0xc8, 0x56, 0x99, 0x7e, 0xa6, 0x16, 0x97, 0x0f, 0xfd, 0xb9, 0xe1, 0xf8, 0x87, 0x33, 0xf3, 0x06, 0x66, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x02, 0x58, 0x20, 0x03, 0xb3, 0x63, 0x3a, 0x40, 0xb3, 0x28, 0x77, 0x42, 0xb9, 0x8a, 0x66, 0x64, 0x2d, 0x05, 0xdc, 0x1a, 0xdd, 0x9e, 0x3f, 0xd2, 0x19, 0x47, 0x9d, 0x2b, 0x47, 0x52, 0x72, 0x3e, 0x54, 0x9c, 0x20, 0x3a, 0x00, 0x01, 0x24, 0xfc, 0x6e, 0x30, 0x34, 0x30, 0x38, 0x30, 0x34, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x58, 0x40, 0x9e, 0x21, 0x90, 0x29, 0x5b, 0x29, 0x6d, 0x50, 0x68, 0xdb, 0x30, 0xf7, 0xdd, 0x84, 0x52, 0x02, 0xa3, 0x03, 0x98, 0x07, 0x2d, 0x61, 0xff, 0xe3, 0x87, 0xfe, 0x82, 0xd6, 0x15, 0xfd, 0x50, 0xbe, 0x5d, 0xbe, 0x03, 0x64, 0x84, 0xc5, 0xf0, 0x1a, 0xc7, 0xbe, 0x91, 0x17, 0xfc, 0xd0, 0xdb, 0x5f, 0x92, 0x2d, 0x70, 0xaa, 0x39, 0xe2, 0xfc, 0x05, 0xcd, 0x08, 0xf7, 0x5b, 0x68, 0xea, 0xae, 0x45 };
  uint8_t               f3Cert[] = { 0x30, 0x82, 0x01, 0x8e, 0x30, 0x82, 0x01, 0x33, 0x02, 0x14, 0x66, 0x03, 0xcf, 0x6d, 0x16, 0xbb, 0x83, 0x40, 0x9b, 0x31, 0x30, 0xd3, 0x9e, 0xa9, 0x2a, 0x20, 0x83, 0x1b, 0x11, 0xc3, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x79, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x4e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x49, 0x4e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x02, 0x49, 0x4e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x53, 0x54, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x07, 0x53, 0x54, 0x4d, 0x33, 0x32, 0x55, 0x33, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x53, 0x54, 0x5f, 0x44, 0x45, 0x4d, 0x4f, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x0b, 0x78, 0x78, 0x78, 0x40, 0x78, 0x78, 0x78, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x34, 0x32, 0x34, 0x30, 0x39, 0x31, 0x30, 0x30, 0x37, 0x5a, 0x17, 0x0d, 0x33, 0x35, 0x30, 0x34, 0x32, 0x32, 0x30, 0x39, 0x31, 0x30, 0x30, 0x37, 0x5a, 0x30, 0x19, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x53, 0x54, 0x4d, 0x33, 0x32, 0x55, 0x33, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x2d, 0x87, 0xeb, 0x2e, 0x04, 0xe7, 0xfc, 0x09, 0x74, 0x83, 0x8b, 0xe3, 0xab, 0xad, 0x3c, 0xe1, 0x90, 0x2b, 0x4f, 0x55, 0x24, 0x0c, 0xfa, 0xc2, 0xbc, 0x3f, 0xd9, 0x64, 0xf5, 0xe5, 0x28, 0x61, 0x6c, 0xb5, 0xdf, 0x9e, 0x7c, 0x3b, 0x49, 0x01, 0xd8, 0xc3, 0xb0, 0x88, 0xb3, 0xe6, 0xca, 0x04, 0x11, 0x7f, 0xee, 0x94, 0x4b, 0x27, 0xd3, 0x22, 0x7c, 0x1a, 0x83, 0x74, 0x65, 0x23, 0x93, 0x34, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xf5, 0xf1, 0xef, 0x89, 0xa6, 0xfc, 0x94, 0x7e, 0xb1, 0x08, 0x84, 0x28, 0x78, 0x78, 0xcb, 0x17, 0x86, 0x2e, 0x4e, 0x39, 0xc4, 0x00, 0x7d, 0x93, 0x7d, 0x96, 0xb6, 0x21, 0xc6, 0x27, 0x2f, 0x05, 0x02, 0x21, 0x00, 0x94, 0x10, 0x3a, 0x83, 0xcb, 0x48, 0x09, 0xf9, 0x6d, 0xa1, 0x92, 0xc7, 0x5d, 0x02, 0x91, 0x64, 0xe5, 0x60, 0x64, 0x0d, 0x07, 0x91, 0xef, 0x14, 0xb4, 0xdb, 0xb9, 0xe3, 0x3a, 0x0f, 0x28, 0x14 };
  size_t                sizeOut = sizeof(aTokenBuffer); // Assign here token size
  size_t                certSize  = sizeof(f3Cert);

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      (NULL == xpChipCert) ||
      (NULL == xpChipCertLen) ||
      (20U >= *xpChipCertLen)
    )
    {
      M_KTALOG__ERR("Invalid parameters");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    /* --- Generate random persistent wrapped "Chip Key Pair" ---. */
    /* Set up attributes for a volatile private wrapped key (SECP256R1). */
    keyAttr = psa_key_attributes_init();
    psa_set_key_type(&keyAttr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&keyAttr, C_MAX_PSA_KEY_BITS);
    psa_set_key_usage_flags(&keyAttr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&keyAttr, PSA_ALG_ECDH);

    gPsaStatus = psa_generate_key(&keyAttr, &psaChipKeyPairKeyId);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_generate_key failed[%d]", gPsaStatus);
      status = E_K_STATUS_PARAMETER;
      break;
    }

    /* Export a public key from a volatile private wrapped key. */
    gPsaStatus = psa_export_public_key(psaChipKeyPairKeyId,
                                       aPublicKey,
                                       publicKeyLen,
                                       &publicKeyLen);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_export_public_key failed[%d]", gPsaStatus);
      status = E_K_STATUS_PARAMETER;
      break;
    }
    /* replace public key in temporary token don't copu offset 0 as it is just to indicate is is a publuc key*/
    memcpy(&aTokenBuffer[18], &aPublicKey[1], 64);
#ifdef KEY_DUMP
    M_KTALOG__HEX("psa_export_public_key:", &aPublicKey[1], C_K_KTA__PUBLIC_KEY_MAX_SIZE);
#endif
    /* Update the session object handle in Volatile id. */
    if (lSetValueById(C_K_KTA__CHIP_SK_ID,
                      (uint8_t*)&psaChipKeyPairKeyId,
                      sizeof(psaChipKeyPairKeyId)) != E_K_STATUS_OK)
    {
      M_KTALOG__ERR("lSetValueById Failed");
      break;
    }
    /* Comenting it, cosnidering attestation service not yet working */
    #if 0
    gPsaStatus = psa_initial_attest_get_token_size(C_SAL_CRYPTO_PUBLIC_KEY_SIZE, &tokenBufferSize);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_initial_attest_get_token_size failed[%d]", gPsaStatus);
      break;
    }
    #endif

    // Generate "Initial Attestation Token".
    // Pre-Requesite to psa_initial_attest_get_token:
    // Integrator responsible for following steps
    // 1. Generate keypair for attestation
    // 2. Store private key trusted storage.
    // 3. Use private key from storage when psa_initial_attest_get_token callled
    //    to generate attestation token
    

	// Here we are using hardcoded attestation token for F3 certificate
    // The below code is commented looks like it is not yet implemented
    #if 0 
    gPsaStatus = psa_initial_attest_get_token(&aPublicKey[1],
                                              C_SAL_CRYPTO_PUBLIC_KEY_SIZE,
                                              aTokenBuffer,
                                              tokenBufferSize,
                                              &sizeOut);



    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_initial_attest_get_token failed[%d]", gPsaStatus);
      break;
    }
	
    #endif
	
    xpChipCert[0] = C_ATTESTATION_TAG;
    xpChipCert[1] = (sizeOut >> 8) & 0xFFU;
    xpChipCert[2] = sizeOut & 0xFFU;

    (void)memcpy(&xpChipCert[C_SAL_CRYPTO_OTHER_DATA_SIZE], aTokenBuffer, sizeOut);
    certDatasize = *xpChipCertLen;

    certParams.data = xpChipCert[3U + sizeOut + 3U];
    certParams.dataLen = certDatasize;

// Copy f3 cert
  (void)memcpy(certParams.data, f3Cert, certSize);

// This is commented because of the hardcoded f3 cert
#if 0
    status = salObjectGet(2,
                          C_SAL_CRYPTO_X509_CERT_ID,
                          &certParams,
                          &platformStatus);

#endif

  // Add birth cert tag
  xpChipCert[3U + sizeOut + 0U] = C_BIRTH_CERT_TAG;
  xpChipCert[3U + sizeOut + 1U] = certParams.dataLen >> 8;
  xpChipCert[3U + sizeOut + 2U] = certParams.dataLen;

    *xpChipCertLen = (3U + sizeOut + 3U + certParams.dataLen);

    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @brief  implement salRotKeyPairGeneration
 *
 */
K_SAL_API TKStatus salRotKeyPairGeneration
(
  uint8_t*  xpPublicKey
)
{
  psa_key_id_t          keyId = 0;
  psa_key_attributes_t  keyAttr;
  uint8_t               aPublicKey[C_SAL_CRYPTO_PSA_PUBLIC_KEY_MAX_SIZE] = {0};
  size_t                publicKeyLen = C_SAL_CRYPTO_PSA_PUBLIC_KEY_MAX_SIZE;
  TKStatus              status = E_K_STATUS_ERROR;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (NULL == xpPublicKey)
    {
      M_KTALOG__ERR("Invalid buffer");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    /* --- Generate random persistent wrapped "Chip Key Pair" ---. */
    /* set up attributes for a volatile private wrapped key (SECP256R1). */
    keyAttr = psa_key_attributes_init();
    psa_set_key_type(&keyAttr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&keyAttr, C_MAX_PSA_KEY_BITS);
    psa_set_key_usage_flags(&keyAttr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&keyAttr, PSA_ALG_ECDH);

    gPsaStatus = psa_generate_key(&keyAttr, &keyId);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_generate_key failed[%d]", gPsaStatus);
      break;
    }

    /* Export a public key from a volatile private wrapped key. */
    gPsaStatus = psa_export_public_key(keyId,
                                       aPublicKey,
                                       publicKeyLen,
                                       &publicKeyLen);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_export_public_key failed[%d]", gPsaStatus);
      break;
    }

    (void)memcpy(xpPublicKey, &aPublicKey[1], C_SAL_CRYPTO_PUBLIC_KEY_SIZE);

    /* Update the session object handle in Volatile id. */
    if (lSetValueById(C_K_KTA__VOLATILE_ID,
                      (uint8_t*)&keyId,
                      sizeof(keyId)) != E_K_STATUS_OK)
    {
      M_KTALOG__ERR("lSetValueById Failed");
      break;
    }

    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @brief  implement salRotKeyAgreement
 *
 */
K_SAL_API TKStatus salRotKeyAgreement
(
  uint32_t        xPrivateKeyId,
  const uint8_t*  xpPeerPublicKey,
  uint32_t        xSharedSecretTarget,
  uint8_t*        xpSharedSecret
)
{
  uint8_t       exposeSecret = M_SAL_CRYPTO_GET_BIT31(xSharedSecretTarget);
  psa_key_id_t  keyId = 0;
  size_t        outputLen = C_SHARED_SECRET_KEY_LEN;
  uint8_t       aPeerKey[C_SAL_CRYPTO_PSA_PUBLIC_KEY_MAX_SIZE];
  uint8_t       aSharedSecret[C_SHARED_SECRET_KEY_LEN];
  TKStatus      status = E_K_STATUS_ERROR;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      ((C_K_KTA__CHIP_SK_ID != xPrivateKeyId) && (C_K_KTA__VOLATILE_ID != xPrivateKeyId)) ||
      (NULL == xpPeerPublicKey) ||
      ((1U == exposeSecret) && (NULL == xpSharedSecret)) ||
      ((0U == exposeSecret) &&
       ((xSharedSecretTarget != C_K_KTA__VOLATILE_2_ID) || (NULL != xpSharedSecret)))
    )
    {
      M_KTALOG__ERR("Invalid paramertes");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    if (lGetValueById(xPrivateKeyId,
                      (uint8_t*)&keyId,
                      sizeof(keyId)) != E_K_STATUS_OK)
    {
      M_KTALOG__ERR("lGetValueById Failed");
      break;
    }

    aPeerKey[0] = 0x04;
    (void)memcpy(&aPeerKey[1], xpPeerPublicKey, C_K_KTA__PUBLIC_KEY_MAX_SIZE);

    psa_crypto_init();
#ifdef KEY_DUMP
    M_KTALOG__HEX("PublicKey", xpPeerPublicKey, C_K_KTA__PUBLIC_KEY_MAX_SIZE);
#endif
    gPsaStatus = psa_raw_key_agreement(PSA_ALG_ECDH,
                                       keyId,
                                       aPeerKey,
                                       C_SAL_CRYPTO_PSA_PUBLIC_KEY_MAX_SIZE,
                                       aSharedSecret,
                                       C_K_KTA__SHARED_SECRET_KEY_MAX_SIZE,
                                       &outputLen);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_raw_key_agreement failed[%d]", gPsaStatus);
      break;
    }
#ifdef KEY_DUMP
    M_KTALOG__HEX("aSharedSecret", aSharedSecret, C_K_KTA__SHARED_SECRET_KEY_MAX_SIZE);
#endif
    if (exposeSecret == 0u)
    {
      (void)memcpy(gaSharedSecret, aSharedSecret, C_K_KTA__SHARED_SECRET_KEY_MAX_SIZE);
    }
    else
    {
      (void)memcpy(xpSharedSecret, aSharedSecret, C_K_KTA__SHARED_SECRET_KEY_MAX_SIZE);

      /* Destory C_K_KTA__VOLATILE_ID and C_K_KTA__CHIP_SK_ID. */
      gPsaStatus = psa_destroy_key(keyId);

      if (PSA_SUCCESS != gPsaStatus)
      {
        M_KTALOG__ERR("psa_destroy_key failed[%d]", C_K_KTA__VOLATILE_ID);
        break;
      }

      /* Destroy the Activation Encryption/Decryption and Sign keys. */
      gPsaStatus = lPsaDestoryKey(C_K_KTA__VOLATILE_2_ID);

      if (PSA_SUCCESS != gPsaStatus)
      {
        M_KTALOG__ERR("lPsaDestoryKey failed[%d]", C_K_KTA__VOLATILE_2_ID);
        break;
      }

      gPsaStatus = lPsaDestoryKey(C_K_KTA__VOLATILE_3_ID);

      if (PSA_SUCCESS != gPsaStatus)
      {
        M_KTALOG__ERR("lPsaDestoryKey failed[%d]", C_K_KTA__VOLATILE_3_ID);
        break;
      }
    }

    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @brief  implement salRotHkdfExtractAndExpand
 *
 */
K_SAL_API TKStatus salRotHkdfExtractAndExpand
(
  uint32_t        xMode,
  const uint8_t*  xpSecret,
  const uint8_t*  xpSalt,
  const uint8_t*  xpInfo,
  size_t          xInfoLen
)
{
  struct psa_key_derivation_s  operation = PSA_KEY_DERIVATION_OPERATION_INIT;
  TKStatus                     status = E_K_STATUS_ERROR;
  psa_key_attributes_t         keyAttr;
  psa_key_lifetime_t           lifetime = 0;
  psa_key_attributes_t         inputKeyAttr = PSA_KEY_ATTRIBUTES_INIT;
  psa_key_id_t                 l1ActKey;
  psa_key_id_t                 keyId;
  uint8_t                      aSec[C_MAX_SIG_MSG_SIZE] = {0};
  size_t                       secLen = 0;
  uint8_t                      aSalt[C_MAX_SIG_MSG_SIZE] = {0};
  uint8_t                      saltLen = 0;
  uint8_t                      aInfo[C_PSA_KEY_BITS] = {0};
  psa_key_attributes_t         outputKeyAttr = PSA_KEY_ATTRIBUTES_INIT;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      ((C_K_KTA__HKDF_ACT_MODE != xMode) && (C_K_KTA__HKDF_GEN_MODE != xMode)) ||
      ((C_K_KTA__HKDF_GEN_MODE == xMode) && (NULL == xpSecret)) ||
      (NULL == xpSalt) ||
      (0U == xInfoLen) ||
      (NULL == xpInfo)
    )
    {
      M_KTALOG__ERR("Invalid paramertes");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    (void)memcpy(aInfo, xpInfo, xInfoLen);

    if (xMode == C_K_KTA__HKDF_ACT_MODE)
    {
      (void)memcpy(aSec, gaSharedSecret, 32);
      (void)memcpy(aSalt, xpSalt, C_MAX_SIG_MSG_SIZE);
      saltLen = C_MAX_SIG_MSG_SIZE;
      secLen = 32;
#ifdef KEY_DUMP
      M_KTALOG__HEX("ACT_MODE gaSharedSecret", gaSharedSecret, 32);
      M_KTALOG__HEX("ACT_MODE xpSalt", xpSalt, C_MAX_SIG_MSG_SIZE);
      M_KTALOG__HEX("ACT_MODE xpInfo", xpInfo, xInfoLen);
#endif
    }
    else
    {
      (void)memcpy(aSec, xpSecret, C_MAX_SIG_MSG_SIZE);
      (void)memcpy(aSalt, xpSalt, C_MAX_SECRET_SIZE);
      saltLen = C_MAX_SECRET_SIZE;
      secLen = C_MAX_SIG_MSG_SIZE;
#ifdef KEY_DUMP
      M_KTALOG__HEX("GEN_MODE gaSharedSecret", xpSecret, C_MAX_SIG_MSG_SIZE);
      M_KTALOG__HEX("GEN_MODE xpSalt", xpSalt, C_MAX_SECRET_SIZE);
      M_KTALOG__HEX("GEN_MODE xpInfo", xpInfo, xInfoLen);
#endif
      gPsaStatus = psa_get_key_attributes(C_SAL_CRYPTO_PSA_L1_FIELD_KEY_ID, &outputKeyAttr);

      if (gPsaStatus == PSA_SUCCESS)
      {
        /* Key identifier already exists. */
        psa_destroy_key(C_SAL_CRYPTO_PSA_L1_FIELD_KEY_ID);
      }
    }

    psa_set_key_usage_flags(&inputKeyAttr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&inputKeyAttr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_type(&inputKeyAttr, PSA_KEY_TYPE_DERIVE);
    /* Force to use HMAC-SHA256 as HMAC operation so far. */

    gPsaStatus = psa_import_key(&inputKeyAttr, aSec, secLen, &keyId);

    if (gPsaStatus != PSA_SUCCESS)
    {
      break;
    }

    gPsaStatus = psa_key_derivation_setup(&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256));

    if (gPsaStatus != PSA_SUCCESS)
    {
      break;
    }

    gPsaStatus = psa_key_derivation_input_bytes(&operation,
                                                PSA_KEY_DERIVATION_INPUT_SALT,
                                                aSalt,
                                                saltLen);

    if (gPsaStatus != PSA_SUCCESS)
    {
      break;
    }

    gPsaStatus = psa_key_derivation_input_key(&operation,
                                              PSA_KEY_DERIVATION_INPUT_SECRET,
                                              keyId);

    if (gPsaStatus != PSA_SUCCESS)
    {
      break;
    }

    gPsaStatus = psa_key_derivation_input_bytes(&operation,
                                                PSA_KEY_DERIVATION_INPUT_INFO,
                                                aInfo,
                                                xInfoLen);

    if (gPsaStatus != PSA_SUCCESS)
    {
      break;
    }

    if (xMode == C_K_KTA__HKDF_ACT_MODE)
    {
      psa_set_key_usage_flags(&outputKeyAttr,
                              PSA_KEY_USAGE_SIGN_MESSAGE);
      psa_set_key_algorithm(&outputKeyAttr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
      psa_set_key_type(&outputKeyAttr, PSA_KEY_TYPE_HMAC);
      psa_set_key_bits(&outputKeyAttr, C_MAX_PSA_KEY_BITS);

      gPsaStatus = psa_key_derivation_output_key(&outputKeyAttr,  &operation, &l1ActKey);

      if (gPsaStatus != PSA_SUCCESS)
      {
        break;
      }

#ifdef KEY_DUMP
      M_KTALOG__DEBUG("L1 ACT key");
      lPrintKey(l1ActKey, 32);
#endif      
      if (lSetValueById(C_K_KTA__VOLATILE_2_ID,
                        (uint8_t*)&l1ActKey,
                        sizeof(l1ActKey)) != E_K_STATUS_OK)
      {
        M_KTALOG__ERR("lSetValueById Failed");
        break;
      }
    }
    else
    {
      /* TO DO: To BE REMOVED WHEN SOLN IS FOUND FOR PERMANET KEY STORAGE. */
      psa_set_key_usage_flags(&outputKeyAttr,
                              PSA_KEY_USAGE_SIGN_MESSAGE);
      psa_set_key_algorithm(&outputKeyAttr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
      psa_set_key_type(&outputKeyAttr, PSA_KEY_TYPE_HMAC);
      psa_set_key_bits(&outputKeyAttr, C_MAX_PSA_KEY_BITS);
      lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_PERSISTENT,
                                                                PSA_KEY_LOCATION_LOCAL_STORAGE);
      psa_set_key_lifetime(&keyAttr, lifetime);
      psa_set_key_id(&outputKeyAttr, C_SAL_CRYPTO_PSA_L1_FIELD_KEY_ID);
      gPsaStatus = psa_key_derivation_output_key(&outputKeyAttr,  &operation,
                                                 &l1ActKey);

      if (gPsaStatus != PSA_SUCCESS)
      {
        break;
      }
#ifdef KEY_DUMP
      M_KTALOG__DEBUG("L1 field key");
      lPrintKey(l1ActKey, 32);
#endif
    }

    /* Free the key derivation operation object. */
    gPsaStatus = psa_key_derivation_abort(&operation);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_key_derivation_abort failed[%d]", gPsaStatus);
      break;
    }

    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @brief  implement salRotKeyDerivation
 *
 */
K_SAL_API TKStatus salRotKeyDerivation
(
  uint32_t        xKeyId,
  const uint8_t*  xpInputData,
  size_t          xInputDataLen,
  uint32_t        xDerivedKeyId
)
{
  TKStatus              status = E_K_STATUS_ERROR;
  psa_key_id_t          psaKeyId = 0;
  psa_key_id_t          l1ActKeyId = 0;
  psa_key_type_t        psaKeyType;
  size_t                psaKeyBits;
  psa_key_usage_t       psaKeyUsage;
  psa_algorithm_t       psaKeyAlgorithm;
  psa_key_attributes_t  keyAttr =  PSA_KEY_ATTRIBUTES_INIT;
  psa_key_id_t          keyId = 0;
  uint8_t               aActMac32[C_MAX_ACT_MAC_LENGTH] = { 0 };
  size_t                actMac32Len = C_MAX_ACT_MAC_LENGTH;
  psa_mac_operation_t  operation = PSA_MAC_OPERATION_INIT;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      ((C_K_KTA__VOLATILE_2_ID != xKeyId) && (C_K_KTA__L1_FIELD_KEY_ID != xKeyId)) ||
      (0U == xInputDataLen) ||
      (NULL == xpInputData) ||
      ((C_K_KTA__VOLATILE_2_ID != xDerivedKeyId) && (C_K_KTA__VOLATILE_3_ID != xDerivedKeyId))
    )
    {
      M_KTALOG__ERR("Invalid paramertes");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    if (xKeyId == C_K_KTA__VOLATILE_2_ID)
    {
      if (lGetValueById(C_K_KTA__VOLATILE_2_ID,
                        (uint8_t*)&l1ActKeyId,
                        sizeof(l1ActKeyId)) != E_K_STATUS_OK)
      {
        M_KTALOG__ERR("lGetValueById Failed");
        break;
      }

      psaKeyId = l1ActKeyId;
    }
    else if (xKeyId == C_K_KTA__L1_FIELD_KEY_ID)
    {
      psaKeyId = C_SAL_CRYPTO_PSA_L1_FIELD_KEY_ID;
    }
    else
    {
      M_KTALOG__ERR("Invalid keyId passed, %d", xKeyId);
      break;
    }

    psa_crypto_init();
    gPsaStatus = psa_mac_compute(psaKeyId, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                                 xpInputData, xInputDataLen,
                                 aActMac32, actMac32Len, &actMac32Len);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_mac_comput failed[%d]", gPsaStatus);
      break;
    }
#ifdef KEY_DUMP
    M_KTALOG__HEX("xpInputData", xpInputData, xInputDataLen);
    M_KTALOG__HEX("L2 key", aActMac32, actMac32Len);
#endif
    /* Translate derived_key_id and setup key attributes for the context:. */
    if (xDerivedKeyId == C_K_KTA__VOLATILE_2_ID)
    {
      psaKeyType = PSA_KEY_TYPE_HMAC;
      psaKeyBits = C_PSA_KEY_BITS;
      psaKeyUsage = PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE;
      psaKeyAlgorithm = PSA_ALG_HMAC(PSA_ALG_SHA_256);
    }
    else if (xDerivedKeyId == C_K_KTA__VOLATILE_3_ID)
    {
      psaKeyType = PSA_KEY_TYPE_AES;
      psaKeyBits = C_PSA_KEY_BITS;
      psaKeyUsage = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT;
      psaKeyAlgorithm = PSA_ALG_CBC_NO_PADDING;
    }
    else
    {
      M_KTALOG__ERR("Invalid DerivedKeyId passed, %d", xDerivedKeyId);
      break;
    }

    psa_set_key_type(&keyAttr, psaKeyType);
    psa_set_key_bits(&keyAttr, psaKeyBits);
    psa_set_key_usage_flags(&keyAttr, psaKeyUsage);
    psa_set_key_algorithm(&keyAttr, psaKeyAlgorithm);

    gPsaStatus = psa_import_key(&keyAttr, aActMac32, C_MAX_SECRET_SIZE,  &keyId);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_import_key failed[%d]", gPsaStatus);
      break;
    }

    /* Destroy unnecessary volatile keys. */
    if (lSetValueById(xDerivedKeyId,
                      (uint8_t*)&keyId,
                      sizeof(keyId)) != E_K_STATUS_OK)
    {
      M_KTALOG__ERR("lSetValueById Failed");
      break;
    }

    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @brief  implement salCryptoHmac
 *
 */
K_SAL_API TKStatus salCryptoHmac
(
  uint32_t        xKeyId,
  const uint8_t*  xpInputData,
  size_t          xInputDataLen,
  uint8_t*        xpMac
)
{
  psa_key_handle_t     keyId = 0;
  uint8_t              aMac[C_MAX_ACT_MAC_LENGTH]  = {0};
  size_t               macLength = C_MAX_ACT_MAC_LENGTH;
  psa_mac_operation_t  operation = PSA_MAC_OPERATION_INIT;
  TKStatus             status = E_K_STATUS_ERROR;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      (C_K_KTA__VOLATILE_2_ID != xKeyId) ||
      (0U == xInputDataLen) ||
      (NULL == xpInputData) ||
      (NULL == xpMac)
    )
    {
      M_KTALOG__ERR("Invalid paramertes");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    if (lGetValueById(xKeyId,
                      (uint8_t*)&keyId,
                      sizeof(keyId)) != E_K_STATUS_OK)
    {
      M_KTALOG__ERR("lGetValueById Failed");
      break;
    }

    psa_crypto_init();
#ifdef KEY_DUMP
    M_KTALOG__DEBUG("salCryptoHmac L2 key");
    lPrintKey(keyId, 16);
#endif
    gPsaStatus = psa_mac_compute(keyId, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                                 xpInputData, xInputDataLen,
                                 aMac, macLength, &macLength);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_mac_comput failed[%d]", gPsaStatus);
      break;
    }

    (void)memcpy(xpMac, aMac, C_MAX_SECRET_SIZE);
    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @brief  implement salCryptoHmacVerify
 *
 */
K_SAL_API TKStatus salCryptoHmacVerify
(
  uint32_t         xKeyId,
  const uint8_t*   xpInputData,
  size_t           xInputDataLen,
  const uint8_t*   xpMac
)
{
  psa_key_handle_t     keyId = 0;
  uint8_t              aMac[C_MAX_ACT_MAC_LENGTH] = {0};
  size_t               macLength = C_MAX_ACT_MAC_LENGTH;
  psa_mac_operation_t  operation = PSA_MAC_OPERATION_INIT;
  TKStatus             status = E_K_STATUS_ERROR;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      (C_K_KTA__VOLATILE_2_ID != xKeyId) ||
      (0U == xInputDataLen) ||
      (NULL == xpInputData) ||
      (NULL == xpMac)
    )
    {
      M_KTALOG__ERR("Invalid paramertes");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    if (lGetValueById(xKeyId,
                      (uint8_t*)&keyId,
                      sizeof(keyId)) != E_K_STATUS_OK)
    {
      M_KTALOG__ERR("lGetValueById Failed");
      break;
    }

    psa_crypto_init();
#ifdef KEY_DUMP
    M_KTALOG__DEBUG("salCryptoHmacVerify L2 key");
    lPrintKey(keyId, 16);
#endif

    gPsaStatus = psa_mac_compute(keyId, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                                 xpInputData, xInputDataLen,
                                 aMac, macLength, &macLength);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_mac_comput failed[%d]", gPsaStatus);
      break;
    }

    if (memcmp(xpMac, aMac, C_MAX_SECRET_SIZE) == 0)
    {
      status = E_K_STATUS_OK;
    }

    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @brief  implement salCryptoAesEnc
 *
 */
K_SAL_API TKStatus salCryptoAesEnc
(
  uint32_t        xKeyId,
  const uint8_t*  xpInputData,
  size_t          xInputDataLen,
  uint8_t*        xpOutputData,
  size_t*         xpOutputDataLen
)
{
  TKStatus status = E_K_STATUS_ERROR;

  M_KTALOG__START("Start");

  for (;;)
  {
    status = lDoCipherOps(E_K_SAL_ENCRYPT, xKeyId, xpInputData,
                          xInputDataLen, xpOutputData, xpOutputDataLen);
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @brief  implement salCryptoAesDec
 *
 */
K_SAL_API TKStatus salCryptoAesDec
(
  uint32_t        xKeyId,
  const uint8_t*  xpInputData,
  size_t          xInputDataLen,
  uint8_t*        xpOutputData,
  size_t*         xpOutputDataLen
)
{
  TKStatus  status = E_K_STATUS_ERROR;

  M_KTALOG__START("Start");

  for (;;)
  {
    status = lDoCipherOps(E_K_SAL_DECRYPT, xKeyId, xpInputData,
                          xInputDataLen, xpOutputData, xpOutputDataLen);
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @brief  implement salCryptoGetRandom
 *
 */
K_SAL_API TKStatus salCryptoGetRandom
(
  uint8_t*  xpRandomData,
  size_t*   xpRandomDataLen
)
{
  TKStatus status = E_K_STATUS_ERROR;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      (NULL == xpRandomData) ||
      (NULL == xpRandomDataLen) ||
      (0 == *xpRandomDataLen) ||
      (C_K_KTA__RANDOM_MAX_SIZE < *xpRandomDataLen)
    )
    {
      M_KTALOG__ERR("Invalid paramertes");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    gPsaStatus = psa_generate_random(xpRandomData, *xpRandomDataLen);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_generate_random failed[%d]", gPsaStatus);
      break;
    }

    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @brief  implement salSignHash
 *
 */
K_SAL_API TKStatus salSignHash
(
  uint32_t  xKeyId,
  uint8_t*  xpMsgTohash,
  size_t    xMsgTohashLen,
  uint8_t*  xpSignedHashOutBuff,
  uint32_t  xSignedHashOutBuffLen,
  size_t*   xpActualSignedHashOutLen
)
{
  TKStatus      status = E_K_STATUS_ERROR;
  psa_key_id_t  keyHandle;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      (0U == xKeyId) ||
      (NULL == xpMsgTohash) ||
      (NULL == xpSignedHashOutBuff) ||
      (NULL == xpActualSignedHashOutLen) ||
      (0U == xMsgTohashLen) ||
      (0U == xSignedHashOutBuffLen)
    )
    {
      M_KTALOG__ERR("Invalid parameters");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    gPsaStatus = psa_open_key(xKeyId, &keyHandle);

    if (gPsaStatus != PSA_SUCCESS)
    {
      M_KTALOG__ERR("psa_open_key failed[%d]", gPsaStatus);
      break;
    }

    gPsaStatus = psa_sign_hash(keyHandle,
                               PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                               xpMsgTohash,
                               xMsgTohashLen,
                               xpSignedHashOutBuff,
                               xSignedHashOutBuffLen,
                               xpActualSignedHashOutLen);

    if (gPsaStatus != PSA_SUCCESS)
    {
      M_KTALOG__ERR("psa_sign_hash failed! (Error: %d)", gPsaStatus);
      break;
    }

    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/* -------------------------------------------------------------------------- */
/* LOCAL FUNCTIONS - IMPLEMENTATION                                           */
/* -------------------------------------------------------------------------- */

/**
 * @implements lSetValueById
 *
 **/
static TKStatus lSetValueById
(
  uint32_t  xObjectId,
  uint8_t*  xpValue,
  size_t    xValueLen
)
{
  TKStatus  status = E_K_STATUS_ERROR;
  uint32_t  loopCount = 0;
  uint32_t  noOfItems = sizeof(gaSalObjectIdMapTable) / sizeof(gaSalObjectIdMapTable[0]);

  for (; loopCount < noOfItems; loopCount++)
  {
    if (gaSalObjectIdMapTable[loopCount].virutalObjId == xObjectId)
    {
      (void)memset(gaSalObjectIdMapTable[loopCount].data.aSessionObjId,
                   0,
                   C_SAL_CRYPTO_MAX_KEY_LENGTH);
      (void)memcpy(gaSalObjectIdMapTable[loopCount].data.aSessionObjId,
                   xpValue,
                   xValueLen);
      status = E_K_STATUS_OK;
      break;
    }
  }

  return status;
}

/**
 * @implements lGetValueById
 *
 **/
static TKStatus lGetValueById
(
  uint32_t  xObjectId,
  uint8_t*  xpValue,
  size_t    xValueLen
)
{
  TKStatus  status = E_K_STATUS_ERROR;
  uint32_t  loopCount = 0;
  uint32_t  noOfItems = sizeof(gaSalObjectIdMapTable) / sizeof(gaSalObjectIdMapTable[0]);

  for (; loopCount < noOfItems; loopCount++)
  {
    if (gaSalObjectIdMapTable[loopCount].virutalObjId == xObjectId)
    {
      (void)memcpy(xpValue,
                   gaSalObjectIdMapTable[loopCount].data.aSessionObjId,
                   xValueLen);
      status = E_K_STATUS_OK;
      break;
    }
  }

  return status;
}

/**
 * @implements lDoCipherOps
 *
 **/
static TKStatus lDoCipherOps
(
  TKCipherOps     xOps,
  uint32_t        xKeyId,
  const uint8_t*  xpInputData,
  size_t          xInputDataLen,
  uint8_t*        xpOutputData,
  size_t*         xpOutputDataLen
)
{

  psa_key_id_t                   keyId = 0;
  struct psa_cipher_operation_s  cipherOp = PSA_CIPHER_OPERATION_INIT;
  const uint8_t                  aIvBuf[] = { 0xA9, 0x32, 0x30, 0x31, 0x38, 0x4E, 0x61, 0x67,
                                              0x72, 0x61, 0x76, 0x69, 0x73, 0x69, 0x6F, 0x6E
                                            };
  size_t                         outputLength = 0;
  TKStatus                       status = E_K_STATUS_ERROR;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      (C_K_KTA__VOLATILE_3_ID != xKeyId) ||
      (0U == xInputDataLen) ||
      (NULL == xpInputData) ||
      (NULL == xpOutputDataLen) ||
      (0U == *xpOutputDataLen) ||
      (NULL == xpOutputData) ||
      (*xpOutputDataLen < xInputDataLen)
    )
    {
      status = E_K_STATUS_PARAMETER;
      break;
    }

    if (lGetValueById(xKeyId, (uint8_t*)&keyId, sizeof(keyId)) != E_K_STATUS_OK)
    {
      M_KTALOG__ERR("lGetValueById Failed");
      break;
    }

    psa_crypto_init();
#ifdef KEY_DUMP
    M_KTALOG__DEBUG("psa_cipher ENC key");
    lPrintKey(keyId, 16);
#endif

    if (xOps == E_K_SAL_ENCRYPT)
    {
      gPsaStatus = psa_cipher_encrypt_setup(&cipherOp, keyId, PSA_ALG_CBC_NO_PADDING);
    }
    else
    {
      gPsaStatus = psa_cipher_decrypt_setup(&cipherOp, keyId, PSA_ALG_CBC_NO_PADDING);
    }

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_cipher_%s_setup failed[%d]",
                    (xOps == E_K_SAL_ENCRYPT) ? "encrypt" : "decrypt", gPsaStatus);
      break;
    }

    gPsaStatus = psa_cipher_set_iv(&cipherOp, aIvBuf, sizeof(aIvBuf));

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_cipher_set_iv failed[%d]", gPsaStatus);
      break;
    }

    gPsaStatus = psa_cipher_update(&cipherOp,
                                   xpInputData,
                                   xInputDataLen,
                                   xpOutputData,
                                   *xpOutputDataLen,
                                   &outputLength);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_cipher_update failed[%d]", gPsaStatus);
      break;
    }

    gPsaStatus = psa_cipher_finish(&cipherOp,
                                   &xpOutputData[outputLength],
                                   *xpOutputDataLen - outputLength,
                                   &outputLength);

    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_cipher_finish failed[%d]", gPsaStatus);
      break;
    }

    *xpOutputDataLen = xInputDataLen;
    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}

/**
 * @implements lPsaDestoryKey
 *
 **/
static psa_status_t lPsaDestoryKey
(
  uint32_t  xObjectId
)
{
  psa_key_handle_t psaTempKeyId  = 0;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (lGetValueById(xObjectId, (uint8_t*)&psaTempKeyId, sizeof(psaTempKeyId)) != E_K_STATUS_OK)
    {
      M_KTALOG__ERR("lGetValueById Failed");
      gPsaStatus = PSA_ERROR_DOES_NOT_EXIST;
      break;
    }

    if ((uint32_t)psaTempKeyId != (uint32_t)0)
    {
      /* Destory the key. */
      gPsaStatus = psa_destroy_key(psaTempKeyId);
      /* Resetting the key value to 0. */
      psaTempKeyId = 0;
      (void)lSetValueById(xObjectId, (uint8_t*)&psaTempKeyId, sizeof(psaTempKeyId));
    }

    break;
  }

  M_KTALOG__END("End, status : %d", gPsaStatus);
  return gPsaStatus;
}

/**
 * @implements lConvertToBigEndien
 *
 **/
static void lConvertToBigEndien
(
  uint8_t*  xpChipUid,
  size_t    xChipUidLen
)
{
  uint8_t  tempData = 0;
  uint8_t  startPos = 0;
  uint8_t  endPos = (uint8_t)(xChipUidLen - 1u);

  for (; startPos < endPos; startPos++)
  {
    tempData = xpChipUid[startPos];
    xpChipUid[startPos] = xpChipUid[endPos];
    xpChipUid[endPos] = tempData;
    endPos--;
  }
}

#ifdef KEY_DUMP
/**
 * @implements lPrintKey
 *
 **/
static void lPrintKey
(
  psa_key_id_t  xKeyId,
  size_t    data_size
)
{

  uint8_t data[32];
  size_t data_length = 32;
  for(;;)
  {
    gPsaStatus = psa_export_key(xKeyId,
                            data,
                            data_size,
                            &data_length);
                            
    if (PSA_SUCCESS != gPsaStatus)
    {
      M_KTALOG__ERR("psa_export_key failed[%d]", gPsaStatus);
      break;
    }
    M_KTALOG__HEX("Key", data, data_length);
    break;
  }
}
#endif // KEY_DUMP
/* -------------------------------------------------------------------------- */
/* END OF FILE                                                                */
/* -------------------------------------------------------------------------- */
