/*
 * Copyright 2022 Nagravision Sàrl.
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
 
/** \brief  SAL Random
 ******************************************************************************/
#include  "k_sal_log_extended.h"
#include "k_sal_random.h"
#include "k_sal_log.h"
#include <stdlib.h>

// To enable or disable log for this module.
#define C_SAL_RANDOM_ENABLE_LOG 0

// Module name to display.
#define C_SAL_RANDOM_MODULE_NAME "RANDOM"

/* -------------------------------------------------------------------------- */
/* LOCAL MACROS                                                               */
/* -------------------------------------------------------------------------- */
/**
  * @brief Display a text if log is enabled.
  *
  * @param[in] x_pcText The text to display.
  *
  */
#if (C_SAL_RANDOM_ENABLE_LOG == 1)
  #define M_SAL_RANDOM_LOG(x_pcText)\
    (M_SAL_LOG(C_SAL_RANDOM_MODULE_NAME, x_pcText))
#else
  #define M_SAL_RANDOM_LOG(x_pcText) {}
#endif

/**
 * @brief Display a variable list of arguments if log is enabled.
 *
 * @param[in] x_pcFormat     Formatting string (like printf).
 * @param[in] x_varArgs      A variable list of parameters to display.
 *
 */
#if (C_SAL_RANDOM_ENABLE_LOG == 1)
  #define M_SAL_RANDOM_LOG_VAR(x_pcFormat, x_varArgs)\
    (M_SAL_LOG_VAR(C_SAL_RANDOM_MODULE_NAME, x_pcFormat, x_varArgs))
#else
  #define M_SAL_RANDOM_LOG_VAR(x_pcFormat, x_varArgs) {}
#endif

/**
 * @brief Display the buffer name, content and size if log is enabled.
 *
 * @param[in] x_pcBuffName  Buffer name
 * @param[in] x_pucBuff     Pointer on buffer
 * @param[in] x_u16BuffSize  Buffer size.
 *
 */
#if (C_SAL_RANDOM_ENABLE_LOG == 1)
  #define M_SAL_RANDOM_LOG_BUFF(x_pcBuffName, x_pucBuff, x_u16BuffSize)\
    (M_SAL_LOG_BUFF(C_SAL_RANDOM_MODULE_NAME, x_pcBuffName, x_pucBuff, x_u16BuffSize))
#else
  #define M_SAL_RANDOM_LOG_BUFF(x_pcBuffName, x_pucBuff, x_u16BuffSize) {}
#endif

/******************************************************************************/
/** \implements salCryptoRandomize
 *
 ******************************************************************************/
TKCommStatus salRandomGet
(
  unsigned char*  xpRandomBuffer,
  const size_t    xSize
)
{
  TKCommStatus status =  E_K_COMM_STATUS_ERROR;
  size_t i;

  M_SAL_RANDOM_LOG_VAR("Start of %s", __func__);

  for (;;)
  {
    if ((NULL == xpRandomBuffer) || (0 == xSize))
    {
      M_SAL_RANDOM_LOG("ERROR : Random buffer or size are invalid");
      status = E_K_COMM_STATUS_PARAMETER;
      break;
    }

    for (i = 0; i < xSize; i++)
    {
      xpRandomBuffer[i] = (uint8_t)(rand() + salTimeGetRelative());;
    }

    status = E_K_COMM_STATUS_OK;
    break;
  }

  M_SAL_RANDOM_LOG_VAR("End of %s", __func__);

  return status;
}
