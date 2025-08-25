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
/** \brief  SAL rot for Generic PSA.
 *
 *  \author Kudelski IoT
 *
 *  \date 2023/06/12
 *
 *  \file k_sal_rot.c
 ******************************************************************************/

/**
 * @brief SAL Rot for Generic PSA.
 */

#include  "k_sal_rot.h"
/* -------------------------------------------------------------------------- */
/* IMPORTS                                                                    */
/* -------------------------------------------------------------------------- */
#include "log_api.h"

#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* LOCAL CONSTANTS, TYPES, ENUM                                               */
/* -------------------------------------------------------------------------- */

/** @brief Device UID size. */
#define C_SAL_DEVICE_UID_SIZE                    (8u)

/* -------------------------------------------------------------------------- */
/* LOCAL VARIABLES                                                            */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* LOCAL FUNCTIONS - PROTOTYPE                                                */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* PUBLIC VARIABLES                                                           */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* PUBLIC FUNCTIONS - IMPLEMENTATION                                          */
/* -------------------------------------------------------------------------- */

/**
 * @brief
 *   Get chip UID. Chip Platform writes chip_uid which can have a chip specific format and length.
 *
 * @param[out] xpChipUid
 *   Address of buffer where the device platform will write the chip_uid.
 *   MAX = 32 Bytes(C_K_KTA_CHIPSET_UID_MAX_SIZE). Should not be NULL.
 * @param[in,out] xpChipUidLen
 *   [in] Length of xpChipUid buffer.
 *   [out] Length of filled output data.
 *   Should not be NULL.
 *
 * @return
 * - E_K_STATUS_OK in case of success.
 * - E_K_STATUS_PARAMETER for wrong input parameter(s).
 * - E_K_STATUS_ERROR for other errors.
 */
K_SAL_API TKStatus salRotGetChipUID
(
  uint8_t*  xpChipUid,
  size_t*   xpChipUidLen
)
{
  TKStatus  status = E_K_STATUS_ERROR;

  devLog("start");

  for (;;)
  {
    if ((NULL == xpChipUid) ||
        (C_SAL_DEVICE_UID_SIZE > *xpChipUidLen)
       )
    {
      devLogErr("bad param");
      status = E_K_STATUS_PARAMETER;
      break;
    }

    (void)memset(xpChipUid, '\0', *xpChipUidLen);
    *xpChipUidLen = 0;

    status = E_K_STATUS_OK;
    break;
  }

  devLogKStatus(status, "end");
  return status;
}
/* -------------------------------------------------------------------------- */
/* LOCAL FUNCTIONS - IMPLEMENTATION                                          */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* END OF FILE                                                                */
/* -------------------------------------------------------------------------- */
