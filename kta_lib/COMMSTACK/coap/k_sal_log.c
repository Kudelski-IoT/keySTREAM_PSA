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
 
/** \brief    SAL Log
 ******************************************************************************/

/* -------------------------------------------------------------------------- */
/* IMPORTS                                                                    */
/* -------------------------------------------------------------------------- */
#include  "k_sal_log_extended.h"
#include  "k_sal_log.h"
#include  <string.h>
#include  <stdarg.h>

/* Buffer is displayed on a 32 columns with 4bits value by columns like below
 * [0000] 01 23 45 67  89 AB CD EF  01 23 45 67  89 AB CD EF
 * [0010] 01 23 45 67  89 AB CD EF  01 23 45 67  89 AB CD EF
 * ...
 */
#define C_SAL_LOG_COL_SIZE 32

/******************************************************************************/
/** \implements salLogPrint
 ******************************************************************************/
void salLogPrint
(
  const char* xpText
)
{
  puts(xpText);
}

/**
 * @brief Print the module name and then a message formatted like for printf.
 *
 * @param[in] x_pcModuleName Module name. e.g. "I2C".
 * @param[in] x_pcFormat     Formatting string (like printf).
 * @param[in] ...            A variable list of parameters to display.
 *
 */
void salLogModPrint
(
  const char* x_pcModuleName,
  const char* x_pcFormat,
  ...
)
{
  va_list pArgs;
  char acNewFormat[1024];

  /* Add a string with the module name and a end of line.
   * e.g. "SAL I2C> ...\n". Avoid a call to sprintf for performance reason.*/
  strcpy(acNewFormat, "SAL ");
  strcat(acNewFormat, x_pcModuleName);
  strcat(acNewFormat, "> ");
  strcat(acNewFormat, x_pcFormat);
  strcat(acNewFormat, "\n");
  va_start(pArgs, x_pcFormat);
  vprintf(acNewFormat, pArgs);
  va_end(pArgs);
}

/**
 * @brief Display the buffer name, content and size for a given module.
 *
 * @param[in] x_pcModuleName Module name. e.g. "I2C".
 * @param[in] x_pcBuffName   Buffer name
 * @param[in] x_pucBuff      Pointer on buffer
 * @param[in] x_u16BuffSize  Buffer size.
 *
 */
void salLogModDisplayBuffer
(
  char* x_pcModuleName,
  char* x_pcBuffName,
  const unsigned char* x_pucBuff,
  uint16_t x_u16BuffSize
)
{
  uint16_t u16Index = 0;

  // Display buffer name.
  printf("SAL %s> %s (size=%d): ", x_pcModuleName, x_pcBuffName, x_u16BuffSize);

  if (x_u16BuffSize > C_SAL_LOG_COL_SIZE)
  {
    // More than one line to display.
    printf("\n");
  }

  // Display buffer.
  for (u16Index = 0; u16Index < x_u16BuffSize; u16Index++)
  {
    printf("%02X ", x_pucBuff[u16Index]);

    if ((u16Index % C_SAL_LOG_COL_SIZE) == (C_SAL_LOG_COL_SIZE - 1))
    {
      // Line full.
      printf("\n");
    }
  }

  if ((x_u16BuffSize % C_SAL_LOG_COL_SIZE) != 0)
  {
    // Last line not full.
    printf("\n");
  }
}
