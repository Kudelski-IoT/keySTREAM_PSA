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
/** \brief  SAL storage for Generic PSA.
 *
 *  \author Kudelski IoT
 *
 *  \date 2023/06/12
 *
 *  \file k_sal_storage.c
 ******************************************************************************/

/**
 * @brief SAL storage for Generic PSA.
 */

#include "k_sal_storage.h"
/* -------------------------------------------------------------------------- */
/* IMPORTS                                                                    */
/* -------------------------------------------------------------------------- */
#include "psa/internal_trusted_storage.h"
#include "KTALog.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* -------------------------------------------------------------------------- */
/* LOCAL CONSTANTS, TYPES, ENUM                                               */
/* -------------------------------------------------------------------------- */

/** @brief Sealed data key id. */
#define C_PSA_SEALED_DATA_KEY_ID                    (0x00000001u)

/** @brief ROT storage key id. */
#define C_PSA_ROT_PUBLIC_UID_KEY_ID                 (0x000080A2u)

/** @brief Life cycle state key id. */
#define C_PSA_LIFE_CYCLE_STATE_KEY_ID               (0x00008003u)

/** @brief L1 material data key id. */
#define C_PSA_L1_KEY_MATERIAL_DATA_KEY_ID           (0x00008004u)

/** @brief Maximum sealed data key id length. */
#define C_K_KTA_SEALED_DATA_STORAGE_ID_LENGTH       (133u)

/** @brief L1 key material data id length. */
#define C_K_KTA_L1_KEY_MATERIAL_DATA_ID_LENGTH      (17u)

/** @brief Life cycle data id length. */
#define C_K_KTA_LIFE_CYCLE_STATE_STORAGE_ID_LENGTH  (4u)

/** @brief Rot public UID storage id length. */
#define C_K_KTA_ROT_PUBLIC_UID_STORAGE_ID_LENGTH    (8u)

/* -------------------------------------------------------------------------- */
/* LOCAL VARIABLES                                                            */
/* -------------------------------------------------------------------------- */

/** @brief Macro to enable debug logs. */
static const char* gpModuleName = "SALSTORAGE";

/* -------------------------------------------------------------------------- */
/* LOCAL FUNCTIONS - PROTOTYPE                                                */
/* -------------------------------------------------------------------------- */

/**
 * @brief
 *   To validate the data id length.
 *
 * @param[in] xDataId
 *   Data Id.
 * @param[in] xLength
 *   Data Id length.
 *
 * @return
 * - E_K_STATUS_OK in case of success.
 * - E_K_STATUS_PARAMETER for wrong input values.
 * - E_K_STATUS_ERROR for other errors.
 */
static TKStatus lValidateDataLen
(
  uint32_t  xDataId,
  size_t    xLength
);

/* -------------------------------------------------------------------------- */
/* PUBLIC VARIABLES                                                           */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* PUBLIC FUNCTIONS - IMPLEMENTATION                                          */
/* -------------------------------------------------------------------------- */

/**
 * @brief  implement salStorageSetAndLockValue
 *
 */
K_SAL_API TKStatus salStorageSetAndLockValue
(
  uint32_t        xStorageDataId,
  const uint8_t*  xpData,
  size_t          xDataLen
)
{
  TKStatus      status = E_K_STATUS_ERROR;
  psa_status_t  retStatus = !PSA_SUCCESS;
  size_t        psaKeyId = C_PSA_ROT_PUBLIC_UID_KEY_ID;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      (NULL == xpData) ||
      (0U == xDataLen) ||
      (lValidateDataLen(xStorageDataId, xDataLen) != E_K_STATUS_OK)
    )
    {
      M_KTALOG__ERR("Invalid paramertes");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    if (xStorageDataId == C_K_KTA__ROT_PUBLIC_UID_STORAGE_ID)
    {
      psaKeyId = C_PSA_ROT_PUBLIC_UID_KEY_ID;
    }
    else if (xStorageDataId == C_K_KTA__SEALED_DATA_STORAGE_ID)
    {
      psaKeyId = C_PSA_SEALED_DATA_KEY_ID;
    }
    else
    {
      M_KTALOG__ERR("Invalid storage ID paased %d", xStorageDataId);
      break;
    }

    retStatus = psa_its_set(psaKeyId, xDataLen, xpData, 0);

    if (PSA_SUCCESS != E_K_STATUS_OK)
    {
      M_KTALOG__ERR("psa_write failed %d", retStatus);
      break;
    }

    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);

  return status;
}


/**
 * @brief  implement salStorageSetValue
 *
 */
K_SAL_API TKStatus salStorageSetValue
(
  uint32_t        xStorageDataId,
  const uint8_t*  xpData,
  size_t          xDataLen
)
{
  TKStatus      status = E_K_STATUS_ERROR;
  psa_status_t  retStatus = PSA_SUCCESS;
  size_t        psaKeyId = C_PSA_ROT_PUBLIC_UID_KEY_ID;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      (NULL == xpData) ||
      (0U == xDataLen) ||
      (lValidateDataLen(xStorageDataId, xDataLen) != E_K_STATUS_OK)
    )
    {
      M_KTALOG__ERR("Invalid parameters");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    /** TODO- Implementation of KTA Version Storage Operations. */
    if (xStorageDataId == C_K_KTA__L1_KEY_MATERIAL_DATA_ID)
    {
      psaKeyId = C_PSA_L1_KEY_MATERIAL_DATA_KEY_ID;
    }
    else if (xStorageDataId == C_K_KTA__VERSION_SLOT_ID)
    {
      status = E_K_STATUS_OK;
      break;
    }
    else if (xStorageDataId == C_K_KTA__LIFE_CYCLE_STATE_STORAGE_ID)
    {
      psaKeyId = C_PSA_LIFE_CYCLE_STATE_KEY_ID;
    }
    else
    {
      M_KTALOG__ERR("Invalid Id %d", xStorageDataId);
      status = E_K_STATUS_PARAMETER;
      break;
    }

    retStatus = psa_its_set(psaKeyId, xDataLen, xpData, 0);

    if (retStatus != PSA_SUCCESS)
    {
      M_KTALOG__ERR("psa_write failed %d", retStatus);
      break;
    }

    status = E_K_STATUS_OK;
    break;
  }

  M_KTALOG__END("End, status : %d", status);

  return status;
}


/**
 * @brief  implement salStorageGetValue
 *
 */
K_SAL_API TKStatus salStorageGetValue
(
  uint32_t  xStorageDataId,
  uint8_t*  xpData,
  size_t*   xpDataLen
)
{
  TKStatus      status = E_K_STATUS_OK;
  psa_status_t  retStatus = !PSA_SUCCESS;
  uint16_t      key = 0;
  size_t        len = 0;
  size_t        actualSize = 0;

  M_KTALOG__START("Start");

  for (;;)
  {
    if (
      (NULL == xpData) ||
      (NULL == xpDataLen) ||
      (0 == *xpDataLen) ||
      (lValidateDataLen(xStorageDataId, *xpDataLen) != E_K_STATUS_OK)
    )
    {
      M_KTALOG__ERR("Invalid parameters");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    /** TODO- Implementation of KTA Version Storage Operations. */
    if (xStorageDataId == C_K_KTA__VERSION_SLOT_ID)
    {
      status = E_K_STATUS_OK;
      break;
    }

    switch (xStorageDataId)
    {
      case C_K_KTA__LIFE_CYCLE_STATE_STORAGE_ID:
      {
        key = C_PSA_LIFE_CYCLE_STATE_KEY_ID;
      }
      break;

      case C_K_KTA__L1_KEY_MATERIAL_DATA_ID:
      {
        key = C_PSA_L1_KEY_MATERIAL_DATA_KEY_ID;
      }
      break;

      case C_K_KTA__ROT_PUBLIC_UID_STORAGE_ID:
      {
        key = C_PSA_ROT_PUBLIC_UID_KEY_ID;
      }
      break;

      case C_K_KTA__SEALED_DATA_STORAGE_ID:
      {
        key = C_PSA_SEALED_DATA_KEY_ID;
      }
      break;

      default:
      {
        M_KTALOG__ERR("Invalid mode %d", xStorageDataId);
        status = E_K_STATUS_PARAMETER;
      }
      break;
    }

    if (E_K_STATUS_OK == status)
    {
      retStatus = psa_its_get(key, 0, *xpDataLen, (void*)xpData, &actualSize);

      if (retStatus != PSA_SUCCESS)
      {
        M_KTALOG__ERR("lReadData failed %d", retStatus);
        status = E_K_STATUS_ERROR;
        break;
      }
    }

    break;
  }

  M_KTALOG__END("End, status : %d", status);
  return status;
}
/* -------------------------------------------------------------------------- */
/* LOCAL FUNCTIONS - IMPLEMENTATION                                           */
/* -------------------------------------------------------------------------- */

/**
 * @implements lValidateDataLen
 *
 **/
static TKStatus lValidateDataLen
(
  uint32_t  xDataId,
  size_t    xLength
)
{
  TKStatus  status = E_K_STATUS_OK;
  size_t    dataLen = 0;

  switch (xDataId)
  {
    case C_K_KTA__LIFE_CYCLE_STATE_STORAGE_ID:
    {
      dataLen = C_K_KTA_LIFE_CYCLE_STATE_STORAGE_ID_LENGTH;
    }
    break;

    case C_K_KTA__L1_KEY_MATERIAL_DATA_ID:
    {
      dataLen = C_K_KTA_L1_KEY_MATERIAL_DATA_ID_LENGTH;
    }
    break;

    case C_K_KTA__ROT_PUBLIC_UID_STORAGE_ID:
    {
      dataLen = C_K_KTA_ROT_PUBLIC_UID_STORAGE_ID_LENGTH;
    }
    break;

    case C_K_KTA__SEALED_DATA_STORAGE_ID:
    {
      dataLen = C_K_KTA_SEALED_DATA_STORAGE_ID_LENGTH;
    }
    break;

    default:
    {
      M_KTALOG__ERR("Invalid Id %d", xDataId);
      status = E_K_STATUS_PARAMETER;
    }
    break;
  }

  if (dataLen != xLength)
  {
    status = E_K_STATUS_ERROR;
    M_KTALOG__ERR("validate parameters error");
  }

  return status;
}

/* -------------------------------------------------------------------------- */
/* END OF FILE                                                                */
/* -------------------------------------------------------------------------- */
