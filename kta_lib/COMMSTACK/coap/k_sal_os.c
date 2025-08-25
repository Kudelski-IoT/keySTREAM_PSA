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
 

/** \brief    SAL OS
 ******************************************************************************/

/* -------------------------------------------------------------------------- */
/* IMPORTS                                                                    */
/* -------------------------------------------------------------------------- */
#include  "k_sal_log_extended.h"
#include  "k_sal_os.h"
#include  "k_sal_log.h"
#include  <stdlib.h>
#include  <stdio.h>
#include  <time.h>
#include  <unistd.h>

/* -------------------------------------------------------------------------- */
/* LOCAL CONSTANTS                                                            */
/* -------------------------------------------------------------------------- */

// To enable or disable log for this module.
#define C_SAL_OS_ENABLE_LOG 0

// Module name to display.
#define C_SAL_OS_MODULE_NAME "OS"

/* -------------------------------------------------------------------------- */
/* LOCAL MACROS                                                               */
/* -------------------------------------------------------------------------- */
/**
  * @brief Display a text if log is enabled.
  *
  * @param[in] x_pcText The text to display.
  *
  */
#if (C_SAL_OS_ENABLE_LOG == 1)
  #define M_SAL_OS_LOG(x_pcText)\
    (M_SAL_LOG(C_SAL_OS_MODULE_NAME, x_pcText))
#else
  #define M_SAL_OS_LOG(x_pcText) {}
#endif

/**
 * @brief Display a variable list of arguments if log is enabled.
 *
 * @param[in] x_pcFormat     Formatting string (like printf).
 * @param[in] x_varArgs      A variable list of parameters to display.
 *
 */
#if (C_SAL_OS_ENABLE_LOG == 1)
  #define M_SAL_OS_LOG_VAR(x_pcFormat, x_varArgs)\
    (M_SAL_LOG_VAR(C_SAL_OS_MODULE_NAME, x_pcFormat, x_varArgs))
#else
  #define M_SAL_OS_LOG_VAR(x_pcFormat, x_varArgs) {}
#endif

/**
 * @brief Display the buffer name, content and size if log is enabled.
 *
 * @param[in] x_pcBuffName  Buffer name
 * @param[in] x_pucBuff     Pointer on buffer
 * @param[in] x_u16BuffSize  Buffer size.
 *
 */
#if (C_SAL_OS_ENABLE_LOG == 1)
  #define M_SAL_OS_LOG_BUFF(x_pcBuffName, x_pucBuff, x_u16BuffSize)\
    (M_SAL_LOG_BUFF(C_SAL_OS_MODULE_NAME, x_pcBuffName, x_pucBuff, x_u16BuffSize))
#else
  #define M_SAL_OS_LOG_BUFF(x_pcBuffName, x_pucBuff, x_u16BuffSize) {}
#endif

/* -------------------------------------------------------------------------- */
/* PUBLIC FUNCTIONS - IMPLEMENTATION                                          */
/* -------------------------------------------------------------------------- */

/******************************************************************************/
/** \implements salTimeGetRelative
 *
 ******************************************************************************/
K_SAL_API TKSalMsTime salTimeGetRelative
(
  void
)
{
  TKSalMsTime time = 0;
  struct timespec ts;

  M_SAL_OS_LOG_VAR("Start of %s", __func__);

  for (;;)
  {
    if (0 != clock_gettime(CLOCK_MONOTONIC, &ts))
    {
      M_SAL_OS_LOG("ERROR: clock_gettime has failed");
      break;
    }

    time  = (TKSalMsTime)(ts.tv_sec * 1000);
    time += (TKSalMsTime)(ts.tv_nsec / 1000000);
    break;
  }

  M_SAL_OS_LOG_VAR("End of %s", __func__);

  return time;
}

/******************************************************************************/
/** \implements salTimeMilliSleep
 *
 ******************************************************************************/
void salTimeMilliSleep
(
  const TKSalMsTime xWaitTime
)
{
  usleep(1000 * xWaitTime);
}

/******************************************************************************/
/** \implements kta_pSalMemoryAllocate
 *
 ******************************************************************************/
void* kta_pSalMemoryAllocate
(
  const size_t   xSize
)
{
  void* pBlock = NULL;

  M_SAL_OS_LOG_VAR("Start of %s", __func__);

  for (;;)
  {
    if (0 == xSize)
    {
      M_SAL_OS_LOG("ERROR: Memory size is equal to 0");
      break;
    }

    pBlock = malloc(xSize);
    break;
  }

  M_SAL_OS_LOG_VAR("End of %s", __func__);

  return pBlock;
}

/******************************************************************************/
/** \implements pSalMemoryReallocate
 *
 ******************************************************************************/
void* pSalMemoryReallocate
(
  void*         xpBlock,
  const size_t  xNewSize
)
{
  void* pBlock = xpBlock;

  M_SAL_OS_LOG_VAR("Start of %s", __func__);

  for (;;)
  {
    /* If xpBlock is NULL and xNewSize is not NULL, we consider that
     * a new block must be allocatted. Use case of test
     * salOsTestAllocationReallocNullStd.
     */
    if ((NULL == xpBlock) && (0 != xNewSize))
    {
      pBlock = malloc(xNewSize);
      break;
    }

    if (NULL == xpBlock)
    {
      M_SAL_OS_LOG("ERROR: Invalid memory block");
      break;
    }

    if (0 == xNewSize)
    {
      M_SAL_OS_LOG("ERROR: Invalid size of memory block, equal to 0");
      salMemoryFree(xpBlock);
      pBlock = NULL;
      break;
    }

    pBlock = realloc(xpBlock, xNewSize);
    break;
  }

  M_SAL_OS_LOG_VAR("End of %s", __func__);

  return pBlock;
}

/******************************************************************************/
/** \implements salMemoryFree
 *
 ******************************************************************************/
void salMemoryFree
(
  void*   xpBlock
)
{
  M_SAL_OS_LOG_VAR("Start of %s", __func__);

  for (;;)
  {
    if (NULL == xpBlock)
    {
      M_SAL_OS_LOG("ERROR: Invalid memory block");
      break;
    }

    free(xpBlock);
    break;
  }

  M_SAL_OS_LOG_VAR("End of %s", __func__);
}
