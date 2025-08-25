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

#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include "k_sal_com.h"



/******************************************************************************/
/*                                                                            */
/*                                 CONSTANTS                                  */
/*                                                                            */
/******************************************************************************/

/******************************************************************************/
/*                                LOCAL MACROS                                */
/******************************************************************************/

#ifdef DEBUG
#define M_SAL_COM_DEBUG(__PRINT__) do { \
                                        printf("\n\tcom %d>",__LINE__); \
                                        printf __PRINT__; \
                                      } while (0)
#define M_SAL_COM_ERROR(__PRINT__) do { \
                                        printf("\n\tcom %d> ERROR ",__LINE__); \
                                        printf __PRINT__; \
                                      } while (0)
#else
#define M_SAL_COM_DEBUG(__PRINT__)
#define M_SAL_COM_ERROR(__PRINT__)
#endif /* DEBUG */

/******************************************************************************/
/*                                                                            */
/*                              TYPES & STRUCTURES                            */
/*                                                                            */
/******************************************************************************/
typedef struct
{
    BOOL    verify;

    mbedtls_net_context         ssl_fd;
    mbedtls_entropy_context     entropy;
    mbedtls_ctr_drbg_context    ctr_drbg;
    mbedtls_ssl_context         ssl;
    mbedtls_ssl_config          conf;
    mbedtls_x509_crt            cacert;
} TKmbedtls;

typedef struct
{
  TKmbedtls com;
  uint32_t  connectTimeOut;
  uint32_t  readTimeOut;
  BOOL      IsHttps;
} TKcomInfo;

/******************************************************************************/
/*                                                                            */
/*                                 VARIABLES                                  */
/*                                                                            */
/******************************************************************************/
static TKcomInfo gcomInfo = { 0 };



/******************************************************************************/
/*                                                                            */
/*                              PRIVATE FUNCTIONS                             */
/*                                                                            */
/******************************************************************************/
/*
 * Initiate a TCP connection with host:port and the given protocol
 * waiting for timeout (ms)
 */
/** 
 * SUPPRESS: MISRA_DEV_KTA_005 : misra_c2012_rule_15.4_violation
 * SUPPRESS: MISRA_DEV_KTA_004 : misra_c2012_rule_15.1_violation
 * Using goto for breaking during the error and return cases. 
 **/
static int mbedtlsNetConnectTimeout( mbedtls_net_context *xpCtx, const char *xpHost, const char *xpPort,
                                        int xProto, uint32_t xTimeout )
{
    int ret;
    struct addrinfo hints;
    struct addrinfo *addr_list;
    struct addrinfo *cur;
    int retVal;


    signal( SIGPIPE, SIG_IGN );

    /* Do name resolution with both IPv6 and IPv4 */
    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = (xProto == MBEDTLS_NET_PROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = (xProto == MBEDTLS_NET_PROTO_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
    retVal = getaddrinfo( xpHost, xpPort, &hints, &addr_list );
    if( retVal != 0 )
    {
      ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
      goto end;
    }

    /* Try the sockaddrs until a connection succeeds */
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for( cur = addr_list; cur != NULL; cur = cur->ai_next )
    {
      xpCtx->fd = (int) socket( cur->ai_family, cur->ai_socktype,
                              cur->ai_protocol );
      if( xpCtx->fd < 0 )
      {
        ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
        continue;
      }
      retVal = mbedtls_net_set_nonblock( xpCtx );
      if( retVal < 0 )
      {
        close( xpCtx->fd );
        xpCtx->fd = -1;
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
        break;
      }
      retVal = connect( xpCtx->fd, cur->ai_addr, cur->ai_addrlen );
      if( retVal == 0 )
      {
        ret = 0;
        break;
      }
      else if( errno == EINPROGRESS )
      {
        int            fd = (int)xpCtx->fd;
        int            opt;
        socklen_t      slen;
        struct timeval tv;
        fd_set         fds;

        while(1)
        {
          FD_ZERO( &fds );
          FD_SET( fd, &fds );

          tv.tv_sec  = xTimeout / 1000;
          tv.tv_usec = ( xTimeout % 1000 ) * 1000;

          ret = select( fd+1, NULL, &fds, NULL, (xTimeout == 0) ? NULL : &tv );
          if( ret == -1 )
          {
            if(errno == EINTR)
            {
              continue;
            }
            else /* To resolve misra check */
            {
              /* Nothing to do here. To resolve misra check */
            }
          }
          else if( ret == 0 )
          {
            close( fd );
            xpCtx->fd = -1;
            ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
          }
          else
          {
            ret = 0;

            slen = sizeof(int);
            retVal = getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&opt, &slen);
            if( (retVal == 0) && (opt > 0) )
            {
                close( fd );
                xpCtx->fd = -1;
                ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
            }
            else /* To resolve misra check */
            {
              /* Nothing to do here. To resolve misra check */
            }
          }
          break;
        }

        break;
      }
      else /* To resolve misra check warning */
      {
        /* Nothing to do here, added to resolve misra warning */
      }

      close( xpCtx->fd );
      xpCtx->fd = -1;
      ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo( addr_list );
    retVal = mbedtls_net_set_block( xpCtx );
    if( (ret == 0) && (retVal < 0) )
    {
      close( xpCtx->fd );
      xpCtx->fd = -1;
      ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

end:
    return( ret );
}


/******************************************************************************/
/*                                                                            */
/*                               PUBLIC FUNCTIONS                             */
/*                                                                            */
/******************************************************************************/
/**
 * @ingroup                 g_sal_com
 * @brief                   Initalize com.
 * @post                    Call salcomClose().
 * @param[in] xVerify       To verify the server authenticity
 * @param[in] xIsHttps      Set to TRUE if its https otherwise FALSE
 * @param[in] xConnectTimeoutInMs  Connection timeout in milliseconds
 * @param[in] xReadTimeoutInMs     Read timeout in milliseconds
 * @param[out] xppcomInfo    Pointer com Info data. should not be NULL
 * @return              - E_K_COMM_STATUS_OK or the error status
 */
K_SAL_API TKCommStatus salComInit
(
  BOOL      xVerify,
  BOOL      xIsHttps,
  uint32_t  xConnectTimeoutInMs,
  uint32_t  xReadTimeoutInMs,
  void    **xppcomInfo
)
{
  TKCommStatus status = E_K_COMM_STATUS_ERROR;
  TKcomInfo *pcomInfo = &gcomInfo;

  M_SAL_COM_DEBUG(("Start of %s", __func__));
  
  if (NULL == xppcomInfo)
  {
    K_SAL_COM_ERROR(("Invalid parameter"));
    status = E_K_COMM_STATUS_PARAMETER;
  }
  else
  {
    memset(&pcomInfo->com, 0, sizeof(pcomInfo->com));
    pcomInfo->connectTimeOut = xConnectTimeoutInMs;
    pcomInfo->readTimeOut = xReadTimeoutInMs;
    pcomInfo->IsHttps = xIsHttps;

    mbedtls_net_init(&pcomInfo->com.ssl_fd);
    *xppcomInfo = pcomInfo;
    status = E_K_COMM_STATUS_OK;
  }

  M_SAL_COM_DEBUG(("End of %s", __func__));
  return status;
}

/**
 * @ingroup               g_sal_com
 * @brief                 Establish connection with server.
 * @param[in] xpcomInfo   com Info data; Should not be NULL
 * @param[in] xpHost      Server Host name. Should not be NULL. must have '\0' at the end
 * @param[in] xpPort      Server Port. Should not be NULL. must have '\0' at the end.
 * @return              - E_K_COMM_STATUS_OK or the error status
 */
TKCommStatus salComConnect
(
  void          *xpcomInfo,
  const uint8_t *xpHost,
  const uint8_t *xpPort
)
{
  TKCommStatus status = E_K_COMM_STATUS_ERROR;
  char  err[100] = { 0 };
  int ret;
  TKcomInfo *pcomInfo = (TKcomInfo *)xpcomInfo;
  M_SAL_COM_DEBUG(("Start of %s", __func__));

  if ((NULL == xpcomInfo) || (NULL == xpHost) || (NULL == xpPort))
  {
    K_SAL_COM_ERROR(("Invalid parameter"));
    status = E_K_COMM_STATUS_PARAMETER;
  }
  else
  {
    salComTerm(pcomInfo);
    ret = mbedtlsNetConnectTimeout(&pcomInfo->com.ssl_fd,
                                      (const char *)xpHost,
                                      (const char *)xpPort,
                                      MBEDTLS_NET_PROTO_TCP,
                                      pcomInfo->connectTimeOut);
    if( ret != 0 )
    {
      mbedtls_strerror(ret, err, 100);
      K_SAL_COM_ERROR(("mbedtlsNetConnectTimeout failed %d %s", ret, err));
    }
    else
    {
      status = E_K_COMM_STATUS_OK;
    }
  }

  M_SAL_COM_DEBUG(("End of %s", __func__));
  return status;
}

/**
 * @ingroup               g_sal_com
 * @brief                 Send data from the server.
 * @pre                   salComConnect should be successfully executed prior to this function
 * @param[in] xpcomInfo   com Info data; Should not be NULL
 * @param[in] xpBuffer    data buffer to send; must point to *xpBufferLen bytes
 * @param[in] xBufferLen  size of the data buffer, in bytes
 * @return              - E_K_COMM_STATUS_OK or the error status
 */
TKCommStatus salcomWrite
(
  void          *xpcomInfo,
  const uint8_t *xpBuffer,
  size_t        xBufferLen
)
{
  TKCommStatus status = E_K_COMM_STATUS_ERROR;
  TKcomInfo *pcomInfo = (TKcomInfo *)xpcomInfo;
  int   ret;
  int   slen = 0;
  char  err[100] = { 0 };

  M_SAL_COM_DEBUG(("Start of %s", __func__));

  if ((NULL == xpcomInfo) || (NULL == xpBuffer) || (0 == xBufferLen))
  {
    K_SAL_COM_ERROR(("Invalid parameter"));
    status = E_K_COMM_STATUS_PARAMETER;
  }
  else
  {
    while(1)
    {
      ret = mbedtls_net_send(&pcomInfo->com.ssl_fd, (u_char *)&xpBuffer[slen], (size_t)(xBufferLen-slen));
      if(ret == MBEDTLS_ERR_SSL_WANT_WRITE)
      {
        continue;
      }
      else if(ret <= 0)
      {
        mbedtls_strerror(ret, err, 100);
        K_SAL_COM_ERROR(("Write Error %d %s", ret, err));
        break;
      }
      else /* Added to resolve misra check */
      {
        /* No functionality, added for misra warning */
      }
      slen += ret;

      if(slen >= xBufferLen)
      {
        status = E_K_COMM_STATUS_OK;
        break;
      }
    }

    if(slen != xBufferLen)
    {
      status = E_K_COMM_STATUS_ERROR;
    }
  }

  M_SAL_COM_DEBUG(("End of %s", __func__));
  return status;
}

/**
 * @ingroup                 g_sal_com
 * @brief                   Receive data from the server.
 * @pre                     salComConnect should be successfully executed prior to this function
 * @param[in] xpcomInfo     com Info data; Should not be NULL
 * @param[out] xpBuffer     data buffer to fill; must point to *xpBufferLen bytes
 * @param[in,out] xBufferLen  in:  size of the data buffer, in bytes
 *                            out: size of the received data, in bytes;
 * @return              - E_K_COMM_STATUS_OK or the error status
 */
TKCommStatus salcomRead
(
  void      *xpcomInfo,
  uint8_t   *xpBuffer,
  size_t    *xpBufferLen
)
{
  int   ret = 0;
  TKcomInfo *pcomInfo = (TKcomInfo *)xpcomInfo;
  char  err[100] = { 0 };
  int   bytesRead = 0;
  TKCommStatus status = E_K_COMM_STATUS_OK;

  M_SAL_COM_DEBUG(("Start of %s", __func__));

  if ((NULL == xpcomInfo) || (NULL == xpBuffer) || (NULL == xpBufferLen) || (0 == *xpBufferLen))
  {
    K_SAL_COM_ERROR(("Invalid parameter"));
    status = E_K_COMM_STATUS_PARAMETER;
  }
  else
  {
    while(1)
    {
      ret = mbedtls_net_recv_timeout( &pcomInfo->com.ssl_fd,
                                        (u_char *)xpBuffer + bytesRead,
                                        (size_t)*xpBufferLen,
                                        pcomInfo->readTimeOut);
      if(ret == MBEDTLS_ERR_SSL_WANT_READ)
      {
        continue;
      }
      else if(ret < 0)
      {
        mbedtls_strerror(ret, err, 100);
        K_SAL_COM_ERROR(("Read Error[%s]", err));
        salComTerm(pcomInfo);
        status = E_K_COMM_STATUS_ERROR;
        break;
      }
      else if(ret == 0)
      {
        status = E_K_COMM_STATUS_OK;
        break;
      }
      else /* To resolve misra warning */
      {
        /* To resolve misra warning */
      }
      
      bytesRead += ret;
      M_SAL_COM_DEBUG(("Bytes Read[%d]", bytesRead));
    }
    *xpBufferLen = bytesRead;
  }

  M_SAL_COM_DEBUG(("End of %s", __func__));
  return status;
}

/**
 * @ingroup                       g_sal_com
 * @brief                         Term com.
 * @return                      - E_K_COMM_STATUS_OK or the error status
 */
TKCommStatus salComTerm
(
  void *xpcomInfo
)
{
  TKCommStatus status = E_K_COMM_STATUS_OK;
  TKcomInfo *pcomInfo = (TKcomInfo *)xpcomInfo;

  M_SAL_COM_DEBUG(("Start of %s", __func__));
  
  if(NULL == xpcomInfo)
  {
    K_SAL_COM_ERROR(("Invalid parameter"));
    status = E_K_COMM_STATUS_PARAMETER;
  }
  else
  {
    mbedtls_net_free(&pcomInfo->com.ssl_fd);
  }

  M_SAL_COM_DEBUG(("End of %s", __func__));

  return status;
}


