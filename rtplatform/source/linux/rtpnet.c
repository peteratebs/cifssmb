 /*
 | RTPNET.C - Runtime Platform Network Services
 |
 |   PORTED TO THE LINUX PLATFORM
 |
 | EBS - RT-Platform
 |
 |  $Author: vmalaiya $
 |  $Date: 2006/11/29 20:14:32 $
 |  $Name:  $
 |  $Revision: 1.4 $
 |
 | Copyright EBS Inc. , 2006-2005
 | All rights reserved.
 | This code may not be redistributed in source or linkable object form
 | without the consent of its author.
 |
 | Module description:
 |  [tbd]
*/

/************************************************************************
* Headers
************************************************************************/
#include "rtp.h"
#include "rtpnet.h"
#include "rtpdebug.h"
#include "rtpstr.h"

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#ifndef IPPROTO_IPV6
#include <netinet/ip6.h>
#endif

/************************************************************************
* Defines
************************************************************************/
#define DEFAULT_FAMILY     PF_UNSPEC // Accept either IPv4 or IPv6
#define DEFAULT_SOCKTYPE   SOCK_STREAM // TCP

/************************************************************************
* Compile Time Possible Porting Errors
************************************************************************/
#if (RTP_FD_SET_MAX > FD_SETSIZE)
#error RTP_FD_SET_MAX SHOULD NEVER BE LARGER THAN THE NATIVE FD_SETSIZE
#error         Adjustments should be made to RTP_FD_SET_MAX in rtpnet.h
#endif

/************************************************************************
* Types
************************************************************************/

/************************************************************************
* Data
************************************************************************/

int rtpnetOpenSockets = 0;

/************************************************************************
* Macros
************************************************************************/
#define SS_PORT(ssp) (((struct sockaddr_in*)(ssp))->sin_port)

/************************************************************************
* Function Prototypes
************************************************************************/
void _fd_set_to_rtp (RTP_FD_SET *rtp, fd_set *set);
void _rtp_to_fd_set (fd_set *set, RTP_FD_SET *rtp);

/************************************************************************
* Function Bodies
************************************************************************/

/*----------------------------------------------------------------------*
                              rtp_net_init
 *----------------------------------------------------------------------*/
int rtp_net_init (void)
{
    return (0);
}


/*----------------------------------------------------------------------*
                              rtp_net_exit
 *----------------------------------------------------------------------*/
void rtp_net_exit (void)
{
}


/*----------------------------------------------------------------------*
                         rtp_net_socket_stream
 *----------------------------------------------------------------------*/
int rtp_net_socket_stream (RTP_HANDLE  *sockHandle)
{
    int sock;

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    sock = socket(PF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        *sockHandle = ((RTP_HANDLE)-1);
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_socket_stream: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    *sockHandle = (RTP_HANDLE) sock;

    rtpnetOpenSockets++;

    return (0);
}

/*----------------------------------------------------------------------*
                         rtp_net_socket_stream_dual
 *----------------------------------------------------------------------*/
int rtp_net_socket_stream_dual (RTP_HANDLE  *sockHandle, int type)
{
    int sock;

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    if (type == RTP_NET_TYPE_IPV4)
    {
        sock = socket(PF_INET, SOCK_STREAM, 0);
    }
    else if (type == RTP_NET_TYPE_IPV6)
    {
        sock = socket(PF_INET6, SOCK_STREAM, 0);
    }
    else
    {
        return (-1);
    }
    if (sock == -1)
    {
        *sockHandle = ((RTP_HANDLE)-1);
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_socket_stream: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    *sockHandle = (RTP_HANDLE) sock;

    rtpnetOpenSockets++;

    return (0);
}

/*----------------------------------------------------------------------*
                        rtp_net_socket_datagram
 *----------------------------------------------------------------------*/
int rtp_net_socket_datagram (RTP_HANDLE  *sockHandle)
{
    int sock;

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    sock = socket(PF_INET, SOCK_DGRAM, 0);

    if (sock == -1)
    {
        *sockHandle = ((RTP_HANDLE)-1);
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_socket_datagram: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    *sockHandle = (RTP_HANDLE) sock;

    rtpnetOpenSockets++;

    return (0);
}

/*----------------------------------------------------------------------*
                        rtp_net_socket_datagram_dual
 *----------------------------------------------------------------------*/
int rtp_net_socket_datagram_dual (RTP_HANDLE  *sockHandle, int type)
{
    int sock;

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    if (type == RTP_NET_TYPE_IPV4)
    {
        sock = socket(PF_INET, SOCK_DGRAM, 0);
    }
    else if (type == RTP_NET_TYPE_IPV6)
    {
        sock = socket(PF_INET6, SOCK_DGRAM, 0);
    }
    else
    {
        return (-1);
    }

    if (sock == -1)
    {
        *sockHandle = ((RTP_HANDLE)-1);
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_socket_datagram: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    *sockHandle = (RTP_HANDLE) sock;

    rtpnetOpenSockets++;

    return (0);
}

/*----------------------------------------------------------------------*
                            rtp_net_bind
 *----------------------------------------------------------------------*/
int rtp_net_bind (RTP_HANDLE sockHandle, unsigned char *ipAddr, int port, int type)
{
    struct sockaddr_in sin;
    unsigned long in_addr = 0;

    memset(&sin, 0, sizeof (sin));

    if (ipAddr)
    {
        unsigned char *ptr = (unsigned char *) &in_addr;

        ptr[0] = ipAddr[0];
        ptr[1] = ipAddr[1];
        ptr[2] = ipAddr[2];
        ptr[3] = ipAddr[3];

        /* ----------------------------------- */
        /* RTP_NET_TYPE_IPV6 not yet supported */
        /* ----------------------------------- */
    }
    else
    {
        in_addr = INADDR_ANY;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = in_addr;
    sin.sin_port = htons((unsigned short)port);

    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;

    if (bind ((int) sockHandle, (struct sockaddr *) &sin, sizeof (sin)) != 0)
    {
        if ((errno == EINVAL) ||
            (errno == EACCES))
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_bind: non-fatal error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-2);
        }
        else
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_bind: error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-1);
        }
    }

    return (0);
}

/*----------------------------------------------------------------------*
                            rtp_net_bind_dual
 *----------------------------------------------------------------------*/
int rtp_net_bind_dual(RTP_HANDLE sockHandle, int sockType,
                      unsigned char *ipAddr, int port, int type)
{
    int result;
    struct addrinfo hints, *res;
    char portStr[32];
    char addrStr[NI_MAXHOST];

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE;
    if(type == RTP_NET_TYPE_IPV6)
    {
        hints.ai_family = PF_INET6;
    }
    else
    {
        hints.ai_family = PF_INET;
    }

    if (sockType == RTP_NET_STREAM)
    {
            hints.ai_socktype = SOCK_STREAM;
    }
    else
    {
            hints.ai_socktype = SOCK_DGRAM;
    }

    if(ipAddr)
    {
        rtp_net_ip_to_str (addrStr, ipAddr, type);
    }
    else
    {
        addrStr[0] = '\0';
    }

    if(port == 0)
    {
        sprintf(portStr, "%d", 0);
    }
    else
    {
        sprintf(portStr, "%d", port);
    }

    result = getaddrinfo(0, portStr, &hints, &res);
    if( result != 0)
    {
        return (-1);
    }

    if (bind((int)sockHandle, res->ai_addr, res->ai_addrlen) != 0)
    {
        freeaddrinfo(res);
        if ((errno == EINVAL) ||
            (errno == EACCES))
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_bind: non-fatal error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-2);
        }
        else
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_bind: error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-1);
        }
    }
    freeaddrinfo(res);
    return (0);
}

/*----------------------------------------------------------------------*
                            rtp_net_listen
 *----------------------------------------------------------------------*/
int rtp_net_listen (RTP_HANDLE sockHandle, int queueSize)
{
#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    if (listen((int) sockHandle, queueSize) != 0)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_listen: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    return (0);
}


/*----------------------------------------------------------------------*
                          rtp_net_getpeername
 *----------------------------------------------------------------------*/
int rtp_net_getpeername (RTP_HANDLE sockHandle, unsigned char *ipAddr, int *port, int *type)
{
    struct sockaddr_storage peerAddr;
    size_t peerLen;
    char addrName[NI_MAXHOST];

    peerLen = sizeof(peerAddr);
    memset(&peerAddr, 0, peerLen);

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    if (getpeername((int) sockHandle, (struct sockaddr *) &peerAddr, &peerLen) != 0)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_getpeername: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    if (getnameinfo((struct sockaddr *) &peerAddr, peerLen, addrName, sizeof(addrName), NULL, 0, NI_NUMERICHOST) != 0)
    {
        strcpy(addrName, "");
    }

    if (ipAddr)
    {
        rtp_net_str_to_ip (ipAddr, addrName, type);
    }

    if (port)
    {
        *port = ntohs(SS_PORT(&peerAddr));
    }

    return (0);
}


/*----------------------------------------------------------------------*
                          rtp_net_getsockname
 *----------------------------------------------------------------------*/
int rtp_net_getsockname (RTP_HANDLE sockHandle, unsigned char *ipAddr, int *port, int *type)
{
    struct sockaddr_storage localAddr;
    char addrName[NI_MAXHOST];
    socklen_t localLen;

    localLen = sizeof(localAddr);
    memset(&localAddr, 0, localLen);

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    if (getsockname ((int) sockHandle, (struct sockaddr *)&localAddr, &localLen) != 0)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_getsockname: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    if (getnameinfo((struct sockaddr *)&localAddr, localLen, addrName, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
    {
        strcpy(addrName, "");
    }

    if (ipAddr)
    {
        rtp_net_str_to_ip (ipAddr, addrName, type);
    }

    if (port)
    {
        *port = ntohs(SS_PORT(&localAddr));
    }


    return (0);
}


/*----------------------------------------------------------------------*
                          rtp_net_gethostbyname
 *----------------------------------------------------------------------*/
int rtp_net_gethostbyname (unsigned char *ipAddr, int *type, char *name)
{
    struct addrinfo hints, *res;
    char addrName[NI_MAXHOST];

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;

    if (getaddrinfo(name ,0 , &hints, &res) != 0)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_getaddrinfo: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    if (getnameinfo(res->ai_addr, res->ai_addrlen, addrName, sizeof(addrName), NULL, 0, NI_NUMERICHOST) != 0)
    {
        strcpy(addrName, "");
    }

    if (ipAddr)
    {
        rtp_net_str_to_ip (ipAddr, addrName, type);
    }

    freeaddrinfo(res);
    return (0);
}


/*----------------------------------------------------------------------*
                           rtp_net_accept
 *----------------------------------------------------------------------*/
int rtp_net_accept (RTP_HANDLE *connectSock, RTP_HANDLE serverSock,
                    unsigned char *ipAddr, int *port, int *type)
{
    struct sockaddr_storage clientAddr;
    socklen_t clientLen;
    int conSocket;
    char clientHost[NI_MAXHOST];

    clientLen = sizeof(clientAddr);
    memset(&clientAddr, 0, clientLen);

    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;

    conSocket = accept((int) serverSock, (struct sockaddr *) &clientAddr, &clientLen);

    if (conSocket == -1)
    {
        *connectSock = ((RTP_HANDLE)-1);
        /* The man page for accept(2) indicates that due to Linux
           passing already-pending errors through accept, the following
           TCP/IP errors should be treated as EAGAIN:
           ENETDOWN, EPROTO, ENOPROTOOPT, EHOSTDOWN, ENONET,
           EHOSTUNREACH, EOPNOTSUPP, and ENETUNREACH. */
        if ((errno == EAGAIN) ||
            (errno == EWOULDBLOCK) ||
            (errno == EINTR) ||
            (errno == ENETDOWN) ||
            (errno == EPROTO) ||
            (errno == ENOPROTOOPT) ||
            (errno == EHOSTDOWN) ||
            (errno == ENONET) ||
            (errno == EHOSTUNREACH) ||
            (errno == EOPNOTSUPP) ||
            (errno == ENETUNREACH))
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_accept: non-fatal error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-2);
        }
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_accept: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    *connectSock = (RTP_HANDLE)conSocket;

    getnameinfo((struct sockaddr *)&clientAddr, clientLen,
                    clientHost, sizeof(clientHost),
                    0, 0, NI_NUMERICHOST);
    if (ipAddr)
    {
        rtp_net_str_to_ip (ipAddr, clientHost, type);
    }

    if (port)
    {
        *port = ntohs(SS_PORT(&clientAddr));
    }

    return (0);
}


/*----------------------------------------------------------------------*
                          rtp_net_connect
 *----------------------------------------------------------------------*/
int rtp_net_connect (RTP_HANDLE sockHandle,
                     unsigned char *ipAddr,
                     int port, int type)
{
    int sinLen;
    struct sockaddr_in sin;
    unsigned long in_addr = 0;

    sinLen = sizeof(sin);
    memset(&sin, 0, (size_t) sinLen);

    if (ipAddr)
    {
        unsigned char *ptr = (unsigned char *) &in_addr;

        ptr[0] = ipAddr[0];
        ptr[1] = ipAddr[1];
        ptr[2] = ipAddr[2];
        ptr[3] = ipAddr[3];
    }
    else
    {
        /* invalid address */
        return (-1);
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = in_addr;
    sin.sin_port = htons((unsigned short)port);

    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;

    if (connect((int) sockHandle, (const struct sockaddr *) &sin, (size_t) sinLen) != 0)
    {
        if ((errno == EINPROGRESS) ||
            (errno == EWOULDBLOCK) ||
            (errno == EALREADY) ||
            (errno == EISCONN))
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_connect: non-fatal error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-2);
        }
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_connect: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    return (0);
}

/*----------------------------------------------------------------------*
                          rtp_net_connect_dual
 *----------------------------------------------------------------------*/
int rtp_net_connect_dual (RTP_HANDLE sockHandle, int sockType,
                          unsigned char *ipAddr,
                          int port, int type)
{
    struct addrinfo hints, *res;
    char portStr[32];
    char addrStr[NI_MAXHOST];

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
    if(type == RTP_NET_TYPE_IPV4)
    {
        hints.ai_family   = PF_INET;
    }
    else if(type == RTP_NET_TYPE_IPV6)
    {
        hints.ai_family   = PF_INET6;
    }
    if (sockType == RTP_NET_STREAM)
    {
        hints.ai_socktype = SOCK_STREAM;
    }
    else
    {
        hints.ai_socktype = SOCK_DGRAM;
    }

    if(ipAddr)
    {
        rtp_net_ip_to_str (addrStr, ipAddr, type);
    }
    else
    {
        addrStr[0] = '\0';
    }

    sprintf(portStr, "%d", port);

    if (getaddrinfo(addrStr, portStr ,&hints, &res) != 0)
    {
        return (-1);
    };

    if (connect ((int) sockHandle, (struct sockaddr *)res->ai_addr, res->ai_addrlen) != 0)
    {
        freeaddrinfo (res);
        if ((errno == EINPROGRESS) ||
            (errno == EWOULDBLOCK) ||
            (errno == EALREADY) ||
            (errno == EISCONN))
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_connect: non-fatal error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-2);
        }
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_connect: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    freeaddrinfo(res);
    return (0);
}

/*----------------------------------------------------------------------*
                         rtp_net_is_connected
 *----------------------------------------------------------------------*/
unsigned  rtp_net_is_connected    (RTP_SOCKET sockHandle)
{
    struct sockaddr_storage peerAddr;
    socklen_t peerLen;

    peerLen = sizeof(peerAddr);
    memset(&peerAddr, 0, peerLen);

    if (getpeername ((int) sockHandle, (struct sockaddr *) &peerAddr, &peerLen) == 0)
    {
        /* this is necessary but not sufficient; now check to make sure the other
           side hasn't shutdown sending data to us */
        fd_set tempSet;
        struct timeval selectTime;
        int result;

        selectTime.tv_sec = 0;
        selectTime.tv_usec = 0;

        FD_ZERO(&tempSet);
        FD_SET((int) sockHandle, &tempSet);

        // check the socket for ready-to-read
        result = select((int) sockHandle + 1, &tempSet, 0, 0, &selectTime);
        if (result != -1)
        {
            unsigned char tempBuffer[1];

            if (!FD_ISSET((int) sockHandle, &tempSet))
            {
                // if we would block, then there is no problem; if the other
                //  side has shut down its end of the connection, we would
                //  return immediately with an error code

                return (1);
            }

            // find out whether this means that:
            //  1. there is data in the buffer from the other side
            //  2. the connection has been closed

            result = recv ((int) sockHandle, tempBuffer, 1, MSG_PEEK);
            if (result == 1)
            {
                // there is data
                return (1);
            }

            if (result == -1)
            {
                switch (errno)
                {
                    case EINTR:
                    case EAGAIN:
                        return (1);
                }
            }
        }
    }

    return (0);
}

/*----------------------------------------------------------------------*
                        rtp_net_write_select
 *----------------------------------------------------------------------*/
int rtp_net_write_select (RTP_HANDLE sockHandle, long msecTimeout)
{
#ifdef LINUXTOBEIMPLEMENTED
struct timeval selectTime;
fd_set write_set;
int result;

    /* ----------------------------------- */
    /*              write list             */
    /* ----------------------------------- */
    FD_ZERO(&write_set);
    FD_SET((SOCKET) sockHandle, &write_set);

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    WSASetLastError(0);
#endif

    if (msecTimeout >= 0)
    {
        selectTime.tv_sec = msecTimeout / 1000;
        selectTime.tv_usec = (msecTimeout % 1000) * 1000;
        result = select(1, (fd_set *) 0, (fd_set *) &write_set, (fd_set *) 0, (const struct timeval *) &selectTime);
    }
    else
    {
        result = select(1, (fd_set *) 0, (fd_set *) &write_set, (fd_set *) 0, (const struct timeval *) NULL);
    }

    /* if an error or if it timed out */
    if ((result == SOCKET_ERROR) || (result == 0))
    {
#ifdef RTP_DEBUG
        result = WSAGetLastError();
        RTP_DEBUG_OUTPUT_STR("rtp_net_write_select: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    return (0);
#else
    return (0);
#endif
}


/*----------------------------------------------------------------------*
                        rtp_net_read_select
 *----------------------------------------------------------------------*/
int rtp_net_read_select (RTP_HANDLE sockHandle, long msecTimeout)
{
#ifdef LINUXTOBEIMPLEMENTED
struct timeval selectTime;
fd_set read_set;
int result;

    /* ----------------------------------- */
    /*              write list             */
    /* ----------------------------------- */
    FD_ZERO(&read_set);
    FD_SET((SOCKET) sockHandle, &read_set);

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    WSASetLastError(0);
#endif

    if (msecTimeout >= 0)
    {
        selectTime.tv_sec = msecTimeout / 1000;
        selectTime.tv_usec = (msecTimeout % 1000) * 1000;
        result = select(1, (fd_set *) &read_set, (fd_set *) 0, (fd_set *) 0, (const struct timeval *) &selectTime);
    }
    else
    {
        result = select(1, (fd_set *) &read_set, (fd_set *) 0, (fd_set *) 0, (const struct timeval *) NULL);
    }

    /* if an error or if it timed out */
    if ((result == SOCKET_ERROR) || (result == 0))
    {
#ifdef RTP_DEBUG
        result = WSAGetLastError();
        RTP_DEBUG_OUTPUT_STR("rtp_net_read_select: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    return (0);
#else
    return (0);
#endif
}


/*----------------------------------------------------------------------*
                           rtp_net_send
 *----------------------------------------------------------------------*/
long rtp_net_send (RTP_HANDLE sockHandle, const unsigned char * buffer, long size)
{
    ssize_t result;

    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;

    result = send((int) sockHandle, (const char *) buffer, (size_t) size, 0);

    if (result == -1)
    {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_send: non-fatal error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-2);
        }
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_send: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return ((long) result);
}


/*----------------------------------------------------------------------*
                           rtp_net_recv
 *----------------------------------------------------------------------*/
long rtp_net_recv (RTP_HANDLE sockHandle, unsigned char * buffer, long size)
{
    ssize_t result;

    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;

    result = recv((int) sockHandle, (char *) buffer, (size_t) size, 0);

    if (result == -1)
    {
        if ((errno == EINTR) || (errno == EAGAIN))
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_recv: non-fatal error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-2);
        }
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_recv: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return ((long) result);
}


/*----------------------------------------------------------------------*
                           rtp_net_sendto
 *----------------------------------------------------------------------*/
long rtp_net_sendto (RTP_HANDLE sockHandle,
                     const unsigned char * buffer, long size,
                     unsigned char * ipAddr, int port, int type)
{
    ssize_t result;
    size_t  sinLen;
    struct sockaddr_storage sin;
    struct addrinfo hints, *res;
    char portStr[32];
    char addrStr[NI_MAXHOST];

    sinLen = sizeof(sin);
    memset(&sin, 0, sinLen);

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
    hints.ai_family   = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if(ipAddr)
    {
        rtp_net_ip_to_str (addrStr, ipAddr, type);
    }
    else
    {
        addrStr[0] = '\0';
    }

    sprintf(portStr, "%d", port);

    if (getaddrinfo(addrStr, portStr ,&hints, &res) != 0)
    {
        return (-1);
    };

    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
    result = (long) sendto((int) sockHandle, (const char *) buffer, (size_t) size, 0, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (result == -1)
    {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_sendto: non-fatal error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-2);
        }
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_sendto: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return ((long) result);
}


/*----------------------------------------------------------------------*
                           rtp_net_recvfrom
 *----------------------------------------------------------------------*/
long rtp_net_recvfrom (RTP_HANDLE sockHandle,
                       unsigned char *buffer, long size,
                       unsigned char *ipAddr, int *port, int *type)
{
    ssize_t result;
    socklen_t remoteLen;
    struct sockaddr_storage remote;
    char remotehost[NI_MAXHOST];

    remoteLen = sizeof(remote);
    memset(&remote, 0, remoteLen);

    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;

    result = (long) recvfrom((int) sockHandle, (char *) buffer, (size_t) size, 0, (struct sockaddr *) &remote,  &remoteLen);

    if (result == -1)
    {
        if ((errno == EINTR) || (errno == EAGAIN))
        {
#ifdef RTP_DEBUG
            RTP_DEBUG_OUTPUT_STR("rtp_net_recvfrom: non-fatal error returned ");
            RTP_DEBUG_OUTPUT_INT(errno);
            RTP_DEBUG_OUTPUT_STR(".\n");
#endif
            return (-2);
        }
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_recvfrom: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    memset(remotehost, 0, sizeof(remotehost));
    getnameinfo((struct sockaddr *)&remote, remoteLen,
                remotehost, sizeof(remotehost),0,0,NI_NUMERICHOST);

    if (ipAddr)
    {
        rtp_net_str_to_ip (ipAddr, remotehost, type);
    }
    if (port)
    {
        *port = ntohs(SS_PORT(&remote));
    }

    return ((long) result);
}

/*----------------------------------------------------------------------*
                          rtp_net_closesocket
 *----------------------------------------------------------------------*/
int rtp_net_closesocket (RTP_HANDLE sockHandle)
{
#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    if (close((int) sockHandle) == -1)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_closesocket: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    rtpnetOpenSockets--;

    return (0);
}


/*----------------------------------------------------------------------*
                            rtp_net_shutdown
 *----------------------------------------------------------------------*/
int rtp_net_shutdown (RTP_HANDLE sockHandle, int how)
{
#ifdef LINUXTOBEIMPLEMENTED
    int result;
#ifdef RTP_DEBUG
    WSASetLastError (0);
#endif
    if (how == 0)
    {
        how = SD_RECEIVE;
    }
    else if (how == 1)
    {
        how = SD_SEND;
    }
    else
    {
        how = SD_BOTH;
    }
    result = shutdown((SOCKET) sockHandle, how);
    if (result == SOCKET_ERROR)
    {
#ifdef RTP_DEBUG
        result = WSAGetLastError();
        RTP_DEBUG_OUTPUT_STR("rtp_net_shutdown: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return(0);
#else
	return (0);
#endif
}


/*----------------------------------------------------------------------*
                           rtp_net_getntoread
 *----------------------------------------------------------------------*/
int rtp_net_getntoread (RTP_HANDLE sockHandle, unsigned long * nToRead)
{
#ifdef LINUXTOBEIMPLEMENTED
    u_long arg;

#ifdef RTP_DEBUG
    int result;
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    //WSASetLastError (0);
#endif

    if (ioctlsocket((SOCKET) sockHandle, FIONREAD, (u_long *) &arg) == SOCKET_ERROR)
    {
#ifdef RTP_DEBUG
        //result = WSAGetLastError();
        RTP_DEBUG_OUTPUT_STR("rtp_net_getntoread: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    *nToRead = arg;
    return (0);
#else
    return (0);
#endif
}


/*----------------------------------------------------------------------*
                           rtp_net_setblocking
 *----------------------------------------------------------------------*/
int rtp_net_setblocking (RTP_HANDLE sockHandle, unsigned int onBool)
{
  int arg;

  arg = (int)(!onBool);
  if (ioctl((int) sockHandle, FIONBIO, &arg) < 0)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_setblocking: error returned ");
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return (0);
}


/*----------------------------------------------------------------------*
                            rtp_net_setnagle
 *----------------------------------------------------------------------*/
int rtp_net_setnagle (RTP_HANDLE sockHandle, unsigned int onBool)
{
#ifdef LINUXTOBEIMPLEMENTED
    int option;

#ifdef RTP_DEBUG
    int result;
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    WSASetLastError (0);
#endif

    option = (int)(!onBool);
    if ( setsockopt((SOCKET) sockHandle, IPPROTO_TCP, TCP_NODELAY, (char *) &option, sizeof (int)) == SOCKET_ERROR )
    {
#ifdef RTP_DEBUG
        result = WSAGetLastError();
        RTP_DEBUG_OUTPUT_STR("rtp_net_setnagle: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return (0);
#else
    return (0);
#endif
}


/*----------------------------------------------------------------------*
                          rtp_net_setlinger
 *----------------------------------------------------------------------*/
int rtp_net_setlinger (RTP_HANDLE sockHandle, unsigned int onBool, long msecTimeout)
{
#ifdef LINUXTOBEIMPLEMENTED
    LINGER arg;
#ifdef RTP_DEBUG
    int result;
#endif

    arg.l_onoff = onBool;
    arg.l_linger = 0;
    if (arg.l_onoff)
    {
        if (msecTimeout > 0)
        {
            arg.l_linger = (u_short) (msecTimeout / 1000);
        }
    }

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    WSASetLastError (0);
#endif

    if (setsockopt((SOCKET) sockHandle, SOL_SOCKET,
                   SO_LINGER, (const char *) &arg,
                   sizeof (struct linger)) < 0)
    {
#ifdef RTP_DEBUG
        result = WSAGetLastError();
        RTP_DEBUG_OUTPUT_STR("rtp_net_setlinger: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return (0);
#else
    return (0);
#endif
}


/*----------------------------------------------------------------------*
                           rtp_net_setreusesock
 *----------------------------------------------------------------------*/
int rtp_net_setreusesock (RTP_HANDLE sockHandle, unsigned int onBool)
{
#ifdef LINUXTOBEIMPLEMENTED
    /* ----------------------------------- */
    /*  Not supported in windows, but also */
    /*  not required in windows.  Return   */
    /*  success.                           */
    /* ----------------------------------- */
    return (0);
#else
    return (0);
#endif
}


/*----------------------------------------------------------------------*
                           rtp_net_setreuseaddr
 *----------------------------------------------------------------------*/
int rtp_net_setreuseaddr (RTP_HANDLE sockHandle, unsigned int onBool)
{
#ifdef LINUXTOBEIMPLEMENTED
#ifdef RTP_DEBUG
    int result;
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    WSASetLastError (0);
#endif

    if ( setsockopt((SOCKET) sockHandle, SOL_SOCKET, SO_REUSEADDR, (char *) &onBool, sizeof (int)) == SOCKET_ERROR )
    {
#ifdef RTP_DEBUG
        result = WSAGetLastError();
        RTP_DEBUG_OUTPUT_STR("rtp_net_setreuseaddr: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return (0);
#else
    return (0);
#endif
}

/*----------------------------------------------------------------------*
                           rtp_net_settcpnocopy
 *----------------------------------------------------------------------*/
int rtp_net_settcpnocopy (RTP_HANDLE sockHandle, unsigned int onBool)
{
#ifdef LINUXTOBEIMPLEMENTED
    /* ----------------------------------- */
    /*  Not supported in windows, but also */
    /*  not required in windows.  Return   */
    /*  success.                           */
    /* ----------------------------------- */
    return (0);
#else
    return (0);
#endif
}


/*----------------------------------------------------------------------*
                         rtp_net_setkeepalive
 *----------------------------------------------------------------------*/
int rtp_net_setkeepalive (RTP_HANDLE sockHandle, unsigned int onBool)
{
#ifdef LINUXTOBEIMPLEMENTED
#ifdef RTP_DEBUG
    int result;
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    WSASetLastError (0);
#endif

    if ( setsockopt((SOCKET) sockHandle, SOL_SOCKET, SO_KEEPALIVE, (char *) &onBool, sizeof (int)) == SOCKET_ERROR )
    {
#ifdef RTP_DEBUG
        result = WSAGetLastError();
        RTP_DEBUG_OUTPUT_STR("rtp_net_setkeepalive: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return (0);
#else
    return (0);
#endif
}


/*----------------------------------------------------------------------*
                         rtp_net_setmembership
 *----------------------------------------------------------------------*/
int rtp_net_setmembership (RTP_HANDLE sockHandle, unsigned char * ipAddr, int type, unsigned int onBool)
{
    long result = -1;
    struct addrinfo hints, *res;
    char addrStr[NI_MAXHOST];

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
    hints.ai_family   = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if(ipAddr)
    {
        rtp_net_ip_to_str (addrStr, ipAddr, type);
    }
    else
    {
        addrStr[0] = '\0';
    }

    if (getaddrinfo(addrStr, 0 ,&hints, &res) != 0)
    {
        return (-1);
    };

    switch (res->ai_family)
    {
        case PF_INET:
        {
            struct ip_mreq mcreq;

            mcreq.imr_multiaddr.s_addr=
                ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
            mcreq.imr_interface.s_addr= INADDR_ANY;

            if (onBool)
            {
                result = setsockopt((int) sockHandle, IPPROTO_IP,
                            IP_ADD_MEMBERSHIP, (const char *)&mcreq,
                            sizeof( struct ip_mreq ));
            }
            else
            {
                result = setsockopt((int) sockHandle, IPPROTO_IP,
                            IP_DROP_MEMBERSHIP, (const char *)&mcreq,
                            sizeof( struct ip_mreq ));
            }
        }
        break;

        case PF_INET6:
        {
            struct ipv6_mreq mcreq6;

            memcpy(&mcreq6.ipv6mr_multiaddr,
                  &(((struct sockaddr_in6 *)res->ai_addr)->sin6_addr),
                  sizeof(struct in6_addr));

            mcreq6.ipv6mr_interface= 0; // cualquier interfaz

            if (onBool)
            {
                result = setsockopt((int) sockHandle, IPPROTO_IPV6,
                            IPV6_ADD_MEMBERSHIP, (const char *)&mcreq6,
                            sizeof( struct ipv6_mreq ));
            }
            else
            {
                result = setsockopt((int) sockHandle, IPPROTO_IPV6,
                            IPV6_DROP_MEMBERSHIP, (const char *)&mcreq6,
                            sizeof( struct ipv6_mreq ));
            }

        }
        break;

    }

    if (result != 0)
    {
#ifdef RTP_DEBUG
        //result = WSAGetLastError();
        RTP_DEBUG_OUTPUT_STR("rtp_net_setmembership: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return (0);
}


/*----------------------------------------------------------------------*
                         rtp_net_setmcastttl
 *----------------------------------------------------------------------*/
int  rtp_net_setmcastttl(RTP_HANDLE sockHandle, int ttl)
{
    struct sockaddr_storage localAddr;
    socklen_t localLen;
    int result;
#ifdef RTP_DEBUG

    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;

#endif
    localLen = sizeof(localAddr);
    memset(&localAddr, 0, localLen);

    result = getsockname ((int) sockHandle, (struct sockaddr*)&localAddr, &localLen);

    if (result != 0)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_getsockname: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    if(localAddr.ss_family == AF_INET)
    {
        result = setsockopt( sockHandle, IPPROTO_IP, IP_MULTICAST_TTL, (char *) &ttl, sizeof (int));
    }
    else if (localAddr.ss_family == AF_INET6)
    {
        result = setsockopt( sockHandle, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *) &ttl, sizeof (int));
    }
    else
    {
        printf("Can not figure out the ip version type");
        return (-1);
    }

    if (result != 0)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_setmembership: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return (0);
}

/*----------------------------------------------------------------------*
                           rtp_net_setbroadcast
 *----------------------------------------------------------------------*/
int rtp_net_setbroadcast (RTP_HANDLE sockHandle, unsigned int onBool)
{
#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    if (setsockopt((int) sockHandle, SOL_SOCKET, SO_BROADCAST, (char *) &onBool, sizeof (int)) == -1)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_setbroadcast: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    return (0);
}



/*----------------------------------------------------------------------*
                            rtp_net_htons
 *----------------------------------------------------------------------*/
short rtp_net_htons (short i)
{
    return ((short)htons((unsigned short)i));
}


/*----------------------------------------------------------------------*
                            rtp_net_ntohs
 *----------------------------------------------------------------------*/
short rtp_net_ntohs (short i)
{
    return ((short)ntohs((unsigned short)i));
}


/*----------------------------------------------------------------------*
                            rtp_net_htonl
 *----------------------------------------------------------------------*/
long rtp_net_htonl (long i)
{
    return ((long)htonl((unsigned long)i));
}


/*----------------------------------------------------------------------*
                            rtp_net_ntohl
 *----------------------------------------------------------------------*/
long rtp_net_ntohl (long i)
{
    return ((long)ntohl((unsigned long)i));
}


/*----------------------------------------------------------------------*
                           rtp_net_ip_to_str
 *----------------------------------------------------------------------*/
int rtp_net_ip_to_str (char *str, unsigned char *ipAddr, int type)
{
    str[0] = '\0';
    if (type != RTP_NET_TYPE_IPV4)
    {
        strcpy(str, (char *)ipAddr);
        return (0);
    }

    sprintf(str, "%i.%i.%i.%i", ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]);

    return ((int)strlen((const char *) str));
}


/*----------------------------------------------------------------------*
                           rtp_net_str_to_ip
 *----------------------------------------------------------------------*/
int rtp_net_str_to_ip (unsigned char *ipAddr, char *str, int *type)
{
    size_t nbytes;
    size_t n, i;
    int ipType = RTP_NET_TYPE_IPV4;

    n = strlen(str);
    for(i=0; i<n; i++)
    {
        if(str[i]==':')
        {
            ipType = RTP_NET_TYPE_IPV6;
            break;
        }
    }

    if(ipType == RTP_NET_TYPE_IPV4)
    {

        *type = RTP_NET_TYPE_IPV4;
        nbytes = 4;

        memset(ipAddr, 0, nbytes);

        for (n=0, i=0; str[n] && i<nbytes; n++)
        {
            if (str[n] >= '0' && str[n] <= '9')
            {
                ipAddr[i] = (unsigned char) ((ipAddr[i] * 10) + (str[n] - '0'));
            }
            else if (str[n] == '.')
            {
                if (n == 0)
                {
                    return (-1);
                }
                i++;
            }
            else
            {
                if (i == 0)
                {
                    return (-1);
                }
                break;
            }
        }
    }
    else
    {
        *type = RTP_NET_TYPE_IPV6;
        strcpy((char *)ipAddr, str);
    }
    return (0);
}


/*----------------------------------------------------------------------*
                                rtp_fd_zero
 *----------------------------------------------------------------------*/
void rtp_fd_zero (RTP_FD_SET  *list)
{
    list->fdCount = 0;
}


/*----------------------------------------------------------------------*
                                rtp_fd_set
 *----------------------------------------------------------------------*/
void rtp_fd_set (RTP_FD_SET  *list, RTP_HANDLE fd)
{
int limit;


    limit = (int) (RTP_FD_SET_MAX > FD_SETSIZE ? FD_SETSIZE : RTP_FD_SET_MAX);

    if (list->fdCount < limit)
    {
        if (!rtp_fd_isset(list, fd))
        {
            list->fdArray[list->fdCount] = fd;
            list->fdCount++;
        }
    }
}


/*----------------------------------------------------------------------*
                                rtp_fd_clr
 *----------------------------------------------------------------------*/
void rtp_fd_clr (RTP_FD_SET  *list, RTP_HANDLE fd)
{
int n;
int limit;


    limit = (int) (RTP_FD_SET_MAX > FD_SETSIZE ? FD_SETSIZE : RTP_FD_SET_MAX);

    if (list->fdCount > limit)
    {
        list->fdCount = limit;
    }

    for (n = 0; n < list->fdCount; n++)
    {
        if (list->fdArray[n] == fd)
        {
            int i;

            for (i = n; i < list->fdCount - 1; i++)
            {
                list->fdArray[i] = list->fdArray[i+1];
            }

            list->fdCount--;
            break;
        }
    }
}


/*----------------------------------------------------------------------*
                               rtp_fd_isset
 *----------------------------------------------------------------------*/
int rtp_fd_isset (RTP_FD_SET  *list, RTP_HANDLE fd)
{
int n;
int limit;


    limit = (int) (RTP_FD_SET_MAX > FD_SETSIZE ? FD_SETSIZE : RTP_FD_SET_MAX);

    if (list->fdCount > limit)
    {
        list->fdCount = limit;
    }

    for (n = 0; n < list->fdCount; n++)
    {
        if (list->fdArray[n] == fd)
        {
            return (1);
        }
    }

    return (0);
}


/*----------------------------------------------------------------------*
                              rtp_net_select
 *----------------------------------------------------------------------*/
int rtp_net_select (RTP_FD_SET  *readList,
                    RTP_FD_SET  *writeList,
                    RTP_FD_SET  *errorList,
                    long msecTimeout)
{
    struct timeval selectTime;
    int result;
    int highest = -1;
    int index;

    fd_set write_set;
    fd_set read_set;
    fd_set error_set;

    FD_ZERO(&write_set);
    FD_ZERO(&read_set);
    FD_ZERO(&error_set);

    /* ----------------------------------- */
    /*              write list             */
    /* ----------------------------------- */
    if (writeList)
    {
        _rtp_to_fd_set(&write_set, writeList);
    }

    /* ----------------------------------- */
    /*               read list             */
    /* ----------------------------------- */
    if (readList)
    {
        _rtp_to_fd_set(&read_set, readList);
    }

    /* ----------------------------------- */
    /*              error list             */
    /* ----------------------------------- */
    if (errorList)
    {
        _rtp_to_fd_set(&error_set, errorList);
    }

#ifdef RTP_DEBUG
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    errno = 0;
#endif

    if (writeList)
    {
        for (index = 0; index < writeList->fdCount; index++)
        {
            if (writeList->fdArray[index] > highest)
                highest = writeList->fdArray[index];
        }
    }
    if (readList)
    {
        for (index = 0; index < readList->fdCount; index++)
        {
            if (readList->fdArray[index] > highest)
                highest = readList->fdArray[index];
        }
    }
    if (errorList)
    {
        for (index = 0; index < errorList->fdCount; index++)
        {
            if (errorList->fdArray[index] > highest)
                highest = errorList->fdArray[index];
        }
    }

    if (msecTimeout >= 0)
    {
        selectTime.tv_sec = msecTimeout / 1000;
        selectTime.tv_usec = (msecTimeout % 1000) * 1000;
        result = select(highest + 1, (fd_set *) &read_set, (fd_set *) &write_set, (fd_set *) &error_set, (struct timeval *) &selectTime);
    }
    else
    {
        result = select(highest + 1, (fd_set *) &read_set, (fd_set *) &write_set, (fd_set *) &error_set, (struct timeval *) NULL);
    }

    if (result >=0)
    {
        if (writeList)
        {
            _fd_set_to_rtp(writeList, &write_set);
        }

        if (readList)
        {
            _fd_set_to_rtp(readList, &read_set);
        }

        if (errorList)
        {
            _fd_set_to_rtp(errorList, &error_set);
        }
    }

    if (result == -1)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_net_select: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    return (result);
}


void _fd_set_to_rtp (RTP_FD_SET *rtp, fd_set *set)
{
int index;

    rtp->fdCount = 0;

    /* This could definitely be optimized by making it less portable and using
       fd_set->__fds_bits. */
    for (index = 0; index < FD_SETSIZE && rtp->fdCount < RTP_FD_SET_MAX; index++)
    {
        if (FD_ISSET (index, set))
        {
            rtp->fdArray[rtp->fdCount] = index;
            rtp->fdCount++;
        }
    }
}

void _rtp_to_fd_set (fd_set *set, RTP_FD_SET *rtp)
{
int index;

    FD_ZERO(set);

    for (index = 0; index < (signed) rtp->fdCount && index < FD_SETSIZE; index++)
    {
        FD_SET((int) rtp->fdArray[index], set);
    }
}

/*----------------------------------------------------------------------*
                           rtp_net_getifaceaddr
 *----------------------------------------------------------------------*/
int rtp_net_getifaceaddr (unsigned char *localAddr, unsigned char *remoteAddr,
                          int remotePort, int remoteType)
{
    RTP_SOCKET tempSock;
    int localPort;
    int localType;

    if (rtp_net_socket_datagram_dual(&tempSock, remoteType) >= 0)
    {
        /* determine the local IP address that is receiving this request by
           creating a temporary UDP socket and connecting it back to the
           sender; we then query the IP address of the temp socket using
           getsockname. */
        if (rtp_net_connect_dual(tempSock, RTP_NET_DATAGRAM, remoteAddr, remotePort, remoteType) >= 0)
        {
            if (rtp_net_getsockname(tempSock, localAddr, &localPort, &localType) >= 0)
            {
                rtp_net_closesocket(tempSock);
                return (0);
            }
        }
        rtp_net_closesocket(tempSock);
    }
    return (-1);
}

/*----------------------------------------------------------------------*
                          rtp_net_get_node_address
 *----------------------------------------------------------------------*/
static const unsigned char fake_node_address[] = {1,2,3,4,5,6};
void rtp_net_get_node_address (unsigned char *node_address)
{
    rtp_memcpy(node_address, fake_node_address, 6);

}
/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
