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

/******************************************************************************/
/*                                                                            */
/*                               INCLUDE FILES                                */
/*                                                                            */
/******************************************************************************/
/** Features test macro for POSIX compliance with popen() and pclose()  */
#include <string.h>
#include <stdbool.h>
#include "k_comm_defs.h"
#include "k_sal_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

/******************************************************************************/
/*                                                                            */
/*                                 CONSTANTS                                  */
/*                                                                            */
/******************************************************************************/
// maximal number of sockets used in parallel
#define C_SAL_SOCKET_MAX_INSTANCES (4U)

// length of the IP address in string format
#define C_SAL_SOCKET_ADDR_STRING_SIZE (32U)

// POSIX error return value
#define C_SAL_SOCKET_ERROR_RET (-1)

// To enable or disable log for this module.
#define C_SAL_SOCKET_ENABLE_LOG 0

// Module name to display.
#define C_SAL_SOCKET_MODULE_NAME "SOCKET"

// Command used to discover the interfaces with UP state
#define C_SAL_SOCKET_READ_NETWORK_INFO_CMD "ip addr ls up"

// Max adaptaters available
#define C_SAL_SOCKET_MAX_NB_ADAPTER 10

/******************************************************************************/
/*                                                                            */
/*                              TYPES & STRUCTURES                            */
/*                                                                            */
/******************************************************************************/
/** SAL socket object */
struct SKSalSocket
{
  bool isUsed;             /**< true if the socket is in use */
  bool isCreated;          /**< true if the socket is created */
  int  socketId;           /**< ID of unique socket used */
  TKSalSocketType type;    /**< socket type */
};

/******************************************************************************/
/*                                                                            */
/*                                 VARIABLES                                  */
/*                                                                            */
/******************************************************************************/
/** socket class variable */
static TKSalSocket gSalSocketTable[C_SAL_SOCKET_MAX_INSTANCES] = { 0 };

/******************************************************************************/
/*                                LOCAL MACROS                                */
/******************************************************************************/
/**
  * @brief Display a text if log is enabled.
  *
  * @param[in] x_pcText The text to display.
  *
  */
#if (C_SAL_SOCKET_ENABLE_LOG == 1)
  #define M_SAL_SOCKET_LOG(x_pcText) \
    (M_SAL_LOG(C_SAL_SOCKET_MODULE_NAME, x_pcText))
#else
  #define M_SAL_SOCKET_LOG(x_pcText) {}
#endif

/**
 * @brief Display a variable list of arguments if log is enabled.
 *
 * @param[in] x_pcFormat     Formatting string (like printf).
 * @param[in] x_varArgs      A variable list of parameters to display.
 *
 */
#if (C_SAL_SOCKET_ENABLE_LOG == 1)
  #define M_SAL_SOCKET_LOG_VAR(x_pcFormat, x_varArgs)\
    (M_SAL_LOG_VAR(C_SAL_SOCKET_MODULE_NAME, x_pcFormat, x_varArgs))
#else
  #define M_SAL_SOCKET_LOG_VAR(x_pcFormat, x_varArgs) {}
#endif

/**
 * @brief Display the buffer name, content and size if log is enabled.
 *
 * @param[in] x_pcBuffName  Buffer name
 * @param[in] x_pucBuff     Pointer on buffer
 * @param[in] x_u16BuffSize  Buffer size.
 *
 */
#if (C_SAL_SOCKET_ENABLE_LOG == 1)
  #define M_SAL_SOCKET_LOG_BUFF(x_pcBuffName, x_pucBuff, x_u16BuffSize)\
    (M_SAL_LOG_BUFF(C_SAL_SOCKET_MODULE_NAME, x_pcBuffName, x_pucBuff, x_u16BuffSize))
#else
  #define M_SAL_SOCKET_LOG_BUFF(x_pcBuffName, x_pucBuff, x_u16BuffSize) {}
#endif

/******************************************************************************/
/*                                                                            */
/*                              PRIVATE FUNCTIONS                             */
/*                                                                            */
/******************************************************************************/
/**
 * @brief                Check if socket instance belongs to our sockets table and is used
 * @param[in]  xpThis    pointer to the socket to check
 * @return               true if valid
 *                       false if invalid
*/
static bool salSocketIsValidInstance
(
  const TKSalSocket* xpThis
)
{
  M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  size_t index = 0;
  bool isValid = false;

  /* iterate through our socket class variable */
  for (index = 0; index < C_SAL_SOCKET_MAX_INSTANCES; index++)
  {
    /* the socket belongs to the table */
    if (xpThis == gSalSocketTable + index)
    {
      /* test if the instance is used */
      if (true == xpThis->isUsed)
      {
        /* the socket instance is valid */
        isValid = true;
      } /* if */
      break;
    } /* if */
  } /* for */

  M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

  return isValid;
} /* salSocketIsValidInstance */

/**
 * @brief              Revert the order of bytes of a 32-bit value (0xAABBCCDD -> 0xDDCCBBAA).
 *                     Useful for IP address: the byte order for an address AA.BB.CC.DD is
 *                     defined as 0xAABBCCDD in SAL API, as 0xDDCCBBAA in socket API.
 * @param[in]  xValue  value to convert
 * @return             converted value
*/
static uint32_t salSocketRevertByteOrder
(
  const uint32_t xValue
)
{
M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  uint32_t value = 0;

  value = ((xValue & 0xFF000000) >> 24) |
          ((xValue & 0x00FF0000) >>  8) |
          ((xValue & 0x0000FF00) <<  8) |
          ((xValue & 0x000000FF) << 24);

M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

  return value;
} /* salSocketRevertByteOrder */

/**
 * @brief                          Build socket address to send to
 * @param[in]  xpIp                IP address; should not be NULL
 * @param[out] xpAddress           socket address; should not be NULL
 * @return                         E_K_COMM_STATUS_OK or the status
*/
static TKCommStatus salSocketBuildAddr
(
  const TKSocketIp* xpIp,
  struct sockaddr_in* xpAddress
)
{
  char addrIPv4Char[C_SAL_SOCKET_ADDR_STRING_SIZE] = { 0 };

  TKCommStatus status = E_K_COMM_STATUS_ERROR;
  uint32_t addrIPv4 = 0u;

  M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  for (;;)
  { /* pseudo-loop */
    if (NULL == xpIp || NULL == xpAddress)
    {
      M_SAL_SOCKET_LOG("ERROR : Invalid Ip/socket address");
      status = E_K_COMM_STATUS_PARAMETER;
      break;
    } /* if */

    switch (xpIp->protocol)
    {
    case E_K_IP_PROTOCOL_V4:
      addrIPv4 = xpIp->address.v4.address;

      /* Build the string IP address */
      sprintf
      (
          addrIPv4Char,
          "%u.%u.%u.%u",
          (addrIPv4 & 0xFF000000) >> 24,
          (addrIPv4 & 0x00FF0000) >> 16,
          (addrIPv4 & 0x0000FF00) >> 8,
          (addrIPv4 & 0x000000FF)
      );
      xpAddress->sin_family = AF_INET;
      xpAddress->sin_port  = htons(xpIp->address.v4.port);

      /* Convert IPv4 address from string to binary form */
      if (inet_pton(AF_INET, addrIPv4Char, &xpAddress->sin_addr) <= 0)
      {
        M_SAL_SOCKET_LOG("ERROR: Invalid address/ Address not supported.");
        status = E_K_COMM_STATUS_DATA;
        break;
      }
      status = E_K_COMM_STATUS_OK;
      break;

    case E_K_IP_PROTOCOL_V6:
      /* not supported */
      status = E_K_COMM_STATUS_DATA;
      break;

    default:
      status = E_K_COMM_STATUS_DATA;
      break;
    } /* switch */

    break; /* always */
  } /* pseudo-loop */

  M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

  return status;
} /* salSocketBuildAddr */

/**
 * @brief                        Create the socket if not yet done.
 * @param[in,out] xpThis             socket to use; should not be NULL
 * @param[in]  xProtocol         protocol to use
 * @return                       E_K_COMM_STATUS_OK or the error status
*/
/**
 * SUPPRESS: MISRA_DEV_KTA_002 : misra_c2012_rule_17.7_violation
 * Not using the return value of snprintf
 */
static TKCommStatus salSocketCreateIfNeeded
(
  TKSalSocket* xpThis,
  const TKIpProtocol xProtocol
)
{
  struct sockaddr_in  address;
  TKCommStatus status = E_K_COMM_STATUS_OK;
  uint8_t type = 0;
  int flags = C_SAL_SOCKET_ERROR_RET;
  int ret = C_SAL_SOCKET_ERROR_RET;

  M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  memset(&address, '0', sizeof(address));

  for (;;)
  { /* pseudo-loop */
    if (true != salSocketIsValidInstance(xpThis))
    {
      M_SAL_SOCKET_LOG("ERROR : Invalid socket instance");
      status = E_K_COMM_STATUS_DATA;
      break;
    } /* if */

    if (true == xpThis->isCreated)
    {
      break;
    } /* if */

    switch (xpThis->type)
    {
    case E_SAL_SOCKET_TYPE_UDP:
      type = SOCK_DGRAM;
      break;

    case E_SAL_SOCKET_TYPE_TCP:
      type = SOCK_STREAM;
      break;

    default:
      M_SAL_SOCKET_LOG("ERROR : Invalid socket type, should be UDP or TCP");
      status = E_K_COMM_STATUS_PARAMETER;
      break;
    } /* switch */

    if (E_K_COMM_STATUS_OK != status)
    {
      break;
    }

    switch (xProtocol)
    {
    case E_K_IP_PROTOCOL_V4:
      address.sin_family = AF_INET;
      break;

    case E_K_IP_PROTOCOL_V6:
      address.sin_family = AF_INET6;
      break;

    default:
      M_SAL_SOCKET_LOG("ERROR : Invalid protocol, should be ipv4 or ipv6");
      status = E_K_COMM_STATUS_PARAMETER;
      break;
    } /* switch */

    if (E_K_COMM_STATUS_OK != status)
    {
      break;
    }

    /* Create socket */
    xpThis->socketId = socket(address.sin_family, type, 0);

    if (C_SAL_SOCKET_ERROR_RET == xpThis->socketId)
    {
      M_SAL_SOCKET_LOG("ERROR : Iinvalid socket id");
      status = E_K_COMM_STATUS_RESOURCE;
      break;
    } /* if */

    /* Get flags of the file descriptor */
    flags = fcntl(xpThis->socketId, F_GETFL, 0);
    if (C_SAL_SOCKET_ERROR_RET == flags)
    {
      M_SAL_SOCKET_LOG("ERROR: Failed to get fd flags.");
      status = E_K_COMM_STATUS_ERROR;
      break;
    }

    /* nonblocking socket */
    ret = fcntl(xpThis->socketId, F_SETFL, flags | O_NONBLOCK);
    if (C_SAL_SOCKET_ERROR_RET == ret)
    {
      M_SAL_SOCKET_LOG("ERROR: Failed to set the O_NONBLOCK flag.");
      status = E_K_COMM_STATUS_ERROR;
      break;
    }

    xpThis->isCreated = true;
    status = E_K_COMM_STATUS_OK;
    break; /* always */
  } /* pseudo-loop */

  M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

  return status;
} /* salSocketCreateIfNeeded */

/**
 * @brief   Return Network information.
 *
 * This function reads the output of shell command "ip addr ls up" to build
 * a list of IP adapter connected (string="UP") with their
 * respective MTUs. If at least one adapter is connected, this function
 * returns *x_pbConnected = true and the smallest mtu size found
 * (string="mtu").
 * Otherwise, it returns *x_pbConnected = false and *x_pusMtu = 0.
 *
 * @param[out] x_pbConnected  An IP adapter is connected.
 * @param[out] x_pusMtu       Parameter "Maximum Transmission Unit" to use.
 * @return                    E_K_COMM_STATUS_OK or an error status.
*/
static TKCommStatus salSocketGetNetworkInfo
(
  bool* x_pbConnected,
  uint32_t* x_pu32Mtu
)
{
  FILE* pfShell = NULL;
  TKCommStatus eStatus = E_K_COMM_STATUS_OK;
  int iResult = 0;
  int iNumber = 0;
  char* pcLine = NULL;
  char* pcFound = NULL;
  unsigned char ucAdapterIndex = 0;
  uint32_t u32MinMtuValue = 0xFFFFFFFF;
  bool abAdapterConnected[C_SAL_SOCKET_MAX_NB_ADAPTER] = {false};
  uint32_t au32MtuValue[C_SAL_SOCKET_MAX_NB_ADAPTER] = {0};
  char acLine[200];
  char acToken[10];
  char* endptr;

  M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  // Initialize param to return
  *x_pbConnected = false;
  *x_pu32Mtu = 0;

  /* Build the list of adapter connected with their MTU values. */
  for (;;) // Dummy loop
  {
    // Execute the command and get the output.
    pfShell = popen(C_SAL_SOCKET_READ_NETWORK_INFO_CMD, "r");
    if (NULL == pfShell)
    {
        M_SAL_SOCKET_LOG_VAR("ERROR: popen(%s) command.", C_SAL_SOCKET_READ_NETWORK_INFO_CMD);
        eStatus = E_K_COMM_STATUS_ERROR;
        break;
    }

    // Read the command output.
    do
    {
      // Read a line
      pcLine = fgets(acLine, sizeof(acLine), pfShell);
      if (NULL == pcLine)
      {
        break;
      }
      // Search for the string "mtu" (same line).
      strcpy(acToken, "mtu");
      pcFound = strstr(acLine, acToken);
      if (NULL != pcFound)
      {
        abAdapterConnected[ucAdapterIndex] = true;
        // Move to the next token string after "mtu" and convert the mtu value
        pcFound += strlen(acToken);
        iNumber = strtol(pcFound, &endptr, 10);
        if (iNumber > 0)
        {
          au32MtuValue[ucAdapterIndex] = (uint32_t)iNumber;
          ucAdapterIndex++;
        }
      }
    } while (1);

    if (E_K_COMM_STATUS_OK != eStatus)
    {
      M_SAL_SOCKET_LOG("ERROR: No MTU has been found");
      // Exit also dummy loop in case of error.
      break;
    }

    /* Close the shell. In case of success, pclose() returns the status of the process.*/
    iResult = pclose(pfShell);
    if (-1 == iResult)
    {
        M_SAL_SOCKET_LOG_VAR("ERROR: pclose(%s) comnand.", C_SAL_SOCKET_READ_NETWORK_INFO_CMD);
        eStatus = E_K_COMM_STATUS_ERROR;
        break;
    }
    /*****************************************************************
    * Parse the list of adapter to compute *x_pbConnected and
    * *x_pu32Mtu.
    *****************************************************************/
    for (ucAdapterIndex = 0; ucAdapterIndex < C_SAL_SOCKET_MAX_NB_ADAPTER; ucAdapterIndex++)
    {
      if (true == abAdapterConnected[ucAdapterIndex])
      {
        // At least one adapter is connected.
        *x_pbConnected = true;

        // Compute min MTU
        if (au32MtuValue[ucAdapterIndex] < u32MinMtuValue)
        {
          u32MinMtuValue = au32MtuValue[ucAdapterIndex];
        }
      }
    } // for (ucAdapterIndex=0;

    if (true == *x_pbConnected)
    {
      *x_pu32Mtu = u32MinMtuValue;
    }

    // End of dummy loop
    break;
  } // for(;;)

  M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

  return eStatus;
} /*salSocketGetNetworkInfo*/

/******************************************************************************/
/*                                                                            */
/*                               PUBLIC FUNCTIONS                             */
/*                                                                            */
/******************************************************************************/
/*
 *  @brief    Create a socket instance to exchange data.
 */
/**
 * SUPPRESS: MISRA_DEV_KTA_002 : misra_c2012_rule_17.7_violation
 * Not using the return value of snprintf
 */
TKCommStatus salSocketCreate
(
  const TKSalSocketType xType,
  TKSalSocket** xppThis
)
{
  TKSalSocket* pThis = NULL;
  size_t index = 0;
  TKCommStatus status = E_K_COMM_STATUS_ERROR;

  M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  for (;;)
  { /* pseudo-loop */
    if (NULL == xppThis)
    {
      M_SAL_SOCKET_LOG("ERROR : Created socket is NULL");
      status = E_K_COMM_STATUS_PARAMETER;
      break;
    } /* if */

    if ((E_SAL_SOCKET_TYPE_UDP != xType) && (E_SAL_SOCKET_TYPE_TCP != xType))
    {
      M_SAL_SOCKET_LOG_VAR("ERROR: Invalid type %d.", xType);
      status = E_K_COMM_STATUS_DATA;
      break;
    } /* if */

    /* look for a free instance */
    for (index = 0; index < C_SAL_SOCKET_MAX_INSTANCES; index++)
    {
      if (false == gSalSocketTable[index].isUsed)
      {
        pThis = gSalSocketTable + index;
        break;
      } /* if */
    } /* for */

    if (NULL == pThis)
    {
      M_SAL_SOCKET_LOG_VAR("ERROR: No available instance (max %d).", C_SAL_SOCKET_MAX_INSTANCES);
      status = E_K_COMM_STATUS_MISSING;
      break;
    } /* if */

    memset(pThis, 0, sizeof(TKSalSocket));
    pThis->isCreated = false;
    pThis->type = xType;
    pThis->isUsed = true;
    *xppThis = pThis;
    status = E_K_COMM_STATUS_OK;
    break;
  } /* pseudo-loop */

  M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

  return status;
} /* salSocketCreate */

/*
 *  @brief    Send bytes through a socket.
 */
TKCommStatus salSocketSendTo
(
  TKSalSocket*          xpThis,
  const unsigned char*  xpBuffer,
  const size_t          xBufferLength,
  const TKSocketIp *xpIp
)
{
  struct sockaddr_in address;
  ssize_t size = 0;
  TKCommStatus status = E_K_COMM_STATUS_ERROR;
  uint32_t mtuValue = 0;
  bool bConnected = false;

  M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  memset(&address, '0', sizeof(address));

  for (;;)
  { /* pseudo-loop */
    if (
        (NULL == xpThis)        ||
        (NULL == xpBuffer)      ||
        (0    == xBufferLength) ||
        (NULL == xpIp)
       )
    {
      M_SAL_SOCKET_LOG("ERROR: Socket or Buffer or BufferLength or Socket IP are invalid");
      status = E_K_COMM_STATUS_PARAMETER;
      break;
    } /* if */

    if (
        (xpIp->protocol != E_K_IP_PROTOCOL_V4) &&
        (xpIp->protocol != E_K_IP_PROTOCOL_V6)
       )
    {
       M_SAL_SOCKET_LOG("ERROR: Invalid Socket type, should be ipv4 or ipv6");
      status = E_K_COMM_STATUS_PARAMETER;
      break;
    }

    if (true != salSocketIsValidInstance(xpThis))
    {
      M_SAL_SOCKET_LOG("ERROR: Invalid socket instance");
      status = E_K_COMM_STATUS_DATA;
      break;
    } /* if */

    status = salSocketCreateIfNeeded(xpThis, xpIp->protocol);
    if (E_K_COMM_STATUS_OK != status)
    {
       M_SAL_SOCKET_LOG("ERROR: Socket creation has failed");
      break;
    } /* if */

    if (E_K_COMM_STATUS_OK != salSocketBuildAddr(xpIp, &address))
    {
      M_SAL_SOCKET_LOG_VAR("ERROR: Bad IP protocol %d.", xpIp->protocol);
      break;
    } /* if */
#ifndef ENABLE_PC_SOCKETS
    // Check IP adapter info.
    status = salSocketGetNetworkInfo(&bConnected, &mtuValue);
    if (E_K_COMM_STATUS_OK != status)
    {
      M_SAL_SOCKET_LOG("ERROR: Retrieving network information has failed");
      break;
    }
    if (false == bConnected)
    {
      M_SAL_SOCKET_LOG("ERROR: No IP connection.");
      status = E_K_COMM_STATUS_NETWORK;
      break;
    }
#endif /* ENABLE_PC_SOCKETS */
    // Write data to socket.
    M_SAL_SOCKET_LOG("Write data to socket.");
    M_SAL_SOCKET_LOG_BUFF("xpBuffer", xpBuffer, xBufferLength);

    size = sendto(xpThis->socketId,
                  (const void *)xpBuffer,
                  xBufferLength,
                  0 /* flags */,
                  (struct sockaddr*)&address,
                  sizeof(address));

    if (C_SAL_SOCKET_ERROR_RET == size)
    {
      /* With some architectures or kernel, the socket might return an 101 error
      We don't really care about this error if UDP is used */
      if (E_SAL_SOCKET_TYPE_UDP == xpThis->type)
      {
        status = E_K_COMM_STATUS_OK;
        break;
      }
      M_SAL_SOCKET_LOG_VAR("ERROR: Network is unreachable, errno=%d.", errno);
      status = E_K_COMM_STATUS_ERROR;
      break;
    }

    if (size < (ssize_t)xBufferLength)
    {
      M_SAL_SOCKET_LOG("ERROR: Whole buffer has not been sent.");
      status = E_K_COMM_STATUS_TIMEOUT;
      break;
    }

    status = E_K_COMM_STATUS_OK;
    break;
  } /* pseudo-loop */

  M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

  return status;
} /* salSocketSendTo */

/*
 *  @brief    Receive bytes through a socket.
 */
/**
 * SUPPRESS: MISRA_DEV_KTA_002 : misra_c2012_rule_17.7_violation
 * Not using the return value of snprintf
 */
TKCommStatus salSocketReceiveFrom
(
  TKSalSocket* xpThis,
  unsigned char* xpBuffer,
  size_t* xpBufferLength,
  TKSocketIp* xpIp
)
{
  struct sockaddr_in address;
  uint32_t addressReverted = 0;
  uint16_t portReverted = 0;
  socklen_t addrSize = 0;
  ssize_t size = 0;
  TKCommStatus status = E_K_COMM_STATUS_ERROR;
  uint32_t mtuValue = 0;
  bool bConnected = false;

  M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  for (;;)
  { /* pseudo-loop */
    if (
        (NULL == xpThis)         ||
        (NULL == xpBuffer)       ||
        (NULL == xpBufferLength)
       )
    {
      M_SAL_SOCKET_LOG("ERROR: Socket or Buffer or BufferLength are invalid");
      status = E_K_COMM_STATUS_PARAMETER;
      break;
    } /* if */

    if (true != salSocketIsValidInstance(xpThis))
    {
      M_SAL_SOCKET_LOG("ERROR: Invalid socket instance");
      status = E_K_COMM_STATUS_DATA;
      break;
    } /* if */

    if (0 == *xpBufferLength)
    {
      M_SAL_SOCKET_LOG("ERROR: BufferLength is equal to 0");
      status = E_K_COMM_STATUS_DATA;
      break;
    } /* if */

    /* WARNING: if socket never created, will be created as V4 socket */
    status = salSocketCreateIfNeeded(xpThis, E_K_IP_PROTOCOL_V4);
    if (E_K_COMM_STATUS_OK != status)
    {
      M_SAL_SOCKET_LOG("ERROR: Socket has not been vreated properly");
      status = E_K_COMM_STATUS_DATA;
      break;
    } /* if */
#ifndef ENABLE_PC_SOCKETS
    // Check IP adapter info.
    status = salSocketGetNetworkInfo(&bConnected, &mtuValue);
    if (E_K_COMM_STATUS_OK != status)
    {
      break;
    }
    if (false == bConnected)
    {
      M_SAL_SOCKET_LOG("ERROR: No IP connection.");
      status = E_K_COMM_STATUS_NETWORK;
      break;
    }
#endif /* ENABLE_PC_SOCKETS */
    // Read from socket.
    M_SAL_SOCKET_LOG_VAR("Receiving data, size=%d.", *xpBufferLength);
    addrSize = sizeof(struct sockaddr);

    size = recvfrom(xpThis->socketId,
                    (void *)xpBuffer,
                    *xpBufferLength,
                    0,
                    (struct sockaddr*)&address,
                    &addrSize);

    if (size >= 0)
    {
      *xpBufferLength = (size_t)size;

      M_SAL_SOCKET_LOG("Data received.");
      M_SAL_SOCKET_LOG_BUFF("xpBuffer", xpBuffer, *xpBufferLength);

      /* if no data received, no need to parse packet, status is OK */
      if (0 != size)
      {
        if (NULL != xpIp)
        {
          /* revert the bytes of the 32bits value */
          addressReverted = salSocketRevertByteOrder(address.sin_addr.s_addr);
          portReverted =  ((address.sin_port & 0xFF00) >> 8) |
                          ((address.sin_port & 0x00FF) << 8);

          switch (address.sin_family)
          {
          case AF_INET:
            memset(xpIp, 0, sizeof(TKSocketIp));
            xpIp->address.v4.address = addressReverted;
            xpIp->address.v4.port = portReverted;
            break;
          case AF_INET6:
            /* not supported for now */
            break;
          default:
            M_SAL_SOCKET_LOG("ERROR: Invalid socket protocol family");
            status = E_K_COMM_STATUS_DATA;
            break;
          } /* switch */

          if (E_K_COMM_STATUS_DATA == status)
          {
            break;
          } /* if */
        } /* if */
      }
      status = E_K_COMM_STATUS_OK;
    } /* if */
    else if ((C_SAL_SOCKET_ERROR_RET == size) && (errno == EAGAIN))
    {
      /* No data available */
      M_SAL_SOCKET_LOG("ERROR: No data available.");
      status = E_K_COMM_STATUS_MISSING;
    } /* else if */
    else
    {
      /* if another error occurred, status is ERROR */
      M_SAL_SOCKET_LOG("ERROR: Other error.");
      status = E_K_COMM_STATUS_ERROR;
    } /* else */

    break;
  } /* pseudo-loop */

  M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

  return status;
} /* salSocketReceiveFrom */

/*
 *  @brief    Dispose a socket instance.
 */
void salSocketDispose
(
  TKSalSocket* xpThis
)
{
  M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  if (salSocketIsValidInstance(xpThis) && (true == xpThis->isUsed))
  {
    close(xpThis->socketId);
    memset(xpThis, 0, sizeof(TKSalSocket));
    /* already done by previous memset, just for readability */
    xpThis->isUsed = false;
  } /* if */

  M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

} /* salSocketDispose */

/*
 *  @brief    Get the network network MTU (maximum transmission unit).
 */
TKCommStatus salSocketGetNetworkMtu
(
  size_t* xpValue
)
{
  uint32_t mtuValue = 0;
  TKCommStatus status = E_K_COMM_STATUS_OK;
  bool bConnected = false;

  M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  for (;;)
  { /* pseudo-loop */
    if (NULL == xpValue)
    {
      status = E_K_COMM_STATUS_PARAMETER;
      break;
    } /* if */

    // Check IP adapter info.
    status = salSocketGetNetworkInfo(&bConnected, &mtuValue);
    if (E_K_COMM_STATUS_OK != status)
    {
      break;
    }

    if (false == bConnected)
    {
      M_SAL_SOCKET_LOG("ERROR Interface is not connected.");
      status = E_K_COMM_STATUS_MISSING;
      break;
    }

    *xpValue = mtuValue;

    break;
  } /* pseudo-loop */

  M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

  return status;
} /* salSocketGetNetworkMtu */


/*
 *  @brief    Get the ip address from host name.
 */
K_SAL_API TKCommStatus salGetHostByName
(
  const char  *xpHost,
  uint8_t     *xpIpAddress
)
{
  TKCommStatus status = E_K_COMM_STATUS_OK;
  struct addrinfo hints = { 0 };
  struct sockaddr_in *pTarget = NULL;
  struct addrinfo *pAddrInfo = NULL;

  M_SAL_SOCKET_LOG_VAR("Start of %s", __func__);

  for(;;)
  {
    if ((NULL == xpHost) || (NULL == xpIpAddress))
    {
      M_SAL_SOCKET_LOG(("Invalid parameters"));
      status = E_K_COMM_STATUS_PARAMETER;
      break;
    }

    hints.ai_flags    = AI_NUMERICHOST;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int ret = getaddrinfo((char*)xpHost, NULL, &hints, &pAddrInfo);
    if (ret == EAI_NONAME) // not an IP, retry as a hostname
    {
      hints.ai_flags = 0;
      ret = getaddrinfo((char*)xpHost, NULL, &hints, &pAddrInfo);
    }
    if (ret == 0)
    {
      pTarget = (struct sockaddr_in*)(pAddrInfo->ai_addr);
      memcpy(xpIpAddress, inet_ntoa(pTarget->sin_addr), C_SAL__MAX_IP4_ADDRESS_LENGTH - 1);
      freeaddrinfo(pAddrInfo);
      status = E_K_COMM_STATUS_OK;
      M_SAL_SOCKET_LOG(("IP Address[%s]", xpIpAddress));
    }
    else
    {
      M_SAL_SOCKET_LOG(("Error in retriving the IP Address"));
    }
    break;
  }

  M_SAL_SOCKET_LOG_VAR("End of %s", __func__);

  return status;
}

