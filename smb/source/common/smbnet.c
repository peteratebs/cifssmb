//
// SMBNET.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// This file contains routines to do some low-level reading and writing from sockets.
//

#include "smbdefs.h"
#include "smbnb.h"    /* for port number */
#include "smbnbns.h"  /* for port number */
#include "smbnbds.h"  /* for port number */
#include "smbnbss.h"  /* for port number */
#include "rtpstr.h" 
#include "rtpscnv.h" 
#include "rtpnet.h"
#include "rtpprint.h"
#include "smbdebug.h"

RTSMB_STATIC RTSMB_CONST byte rtsmb_net_default_host_ip [4] = {127,   0,   0,   1};
RTSMB_STATIC RTSMB_CONST byte rtsmb_net_default_mask_ip [4] = {255, 255, 255,   0};

RTSMB_STATIC byte rtsmb_net_host_ip [4];
RTSMB_STATIC byte rtsmb_net_broadcast_ip [4];
RTSMB_STATIC BBOOL rtsmb_net_ip_is_set = FALSE;


int rtsmb_net_ip_to_str (PFBYTE pfAddr, PFCHAR pfAddrStr); 

/* global data */
int rtsmb_nbds_port = RTSMB_NBDS_PORT;
int rtsmb_nbns_port = RTSMB_NBNS_PORT;

int rtsmb_nbss_port        = RTSMB_NBSS_PORT;
int rtsmb_nbss_direct_port = RTSMB_NBSS_DIRECT_PORT;

/*
==============
void rtsmb_init_port_alt() - set port numbers to althernative values

    Set port numbers to alternative values.  The values are defined
    in smbnbds.h, smbnbns.h and smbnbss.h.  They are set to the
    well-know port number + 9000.

    This is useful for running RTSMB against RTSMB so that other SMB's
    on the network do not respond.

    You can use the Analyze/Decode As feature in wireshare to map
    alternative port numbers to well-know port numbers to enable
    correct decoding of packets.
==============
*/
void rtsmb_init_port_alt (void)
{
    rtsmb_nbds_port = RTSMB_NBDS_PORT_ALT;
    rtsmb_nbns_port = RTSMB_NBNS_PORT_ALT;

    rtsmb_nbss_port        = RTSMB_NBSS_PORT_ALT;
    rtsmb_nbss_direct_port = RTSMB_NBSS_DIRECT_PORT_ALT;
//    rtsmb_nbss_init_port_alt ();

}

/*
==============
void rtsmb_init_port_well_known() - set port numbers to althernative values

    Set port numbers back to well-known port numbers.
    You can call this after calling rtsmb_init_port_alt() to
    set port numbers back to origional values.
==============
*/
void rtsmb_init_port_well_know (void)
{
    rtsmb_nbds_port = RTSMB_NBDS_PORT;
    rtsmb_nbns_port = RTSMB_NBNS_PORT;

    rtsmb_nbss_port        = RTSMB_NBSS_PORT;
    rtsmb_nbss_direct_port = RTSMB_NBSS_DIRECT_PORT;

//    rtsmb_nbss_init_port_well_know ();

}


/*
==============
int rtsmb_net_read_simple () - Get data sent by a reliable connection.

    RTP_SOCKET sock - the socket over which the connection is operating
    void *pData - the buffer where data should be stored
    int size - the size in bytes of the data

    return - size of data or -1 for error
==============
*/
RTSMB_STATIC
int rtsmb_net_read_simple (RTP_SOCKET sock, PFVOID pData, int size)
{
    int bytesRead;

    if(!pData)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_net_read_simple: NULL buffer\n", RTSMB_DEBUG_TYPE_ASCII);
        return -1;
    }

    bytesRead = rtp_net_recv (sock, pData, size);
    if (bytesRead == 0)
    {
        // other side has closed connection
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_net_read_simple: Connection closed by remote client\n", RTSMB_DEBUG_TYPE_ASCII);
        return -1;
    }

    if(bytesRead < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_net_read_simple: Error in recv\n", RTSMB_DEBUG_TYPE_ASCII);
        return -1;
    }

    return bytesRead;
}

/*
==============
int rtsmb_net_read() - Get data sent by a reliable connection, except
        close if error and only take what we can, discarding extra

    RTP_SOCKET sock - the socket over which the connection is operating
    void *pData - the buffer where data should be stored
    int bufsize - the maximum we can hold
    int size - the size in bytes of the data that we know are on the wire

    return - size of data read, negative if error
==============
*/
int rtsmb_net_read (RTP_SOCKET sock, PFVOID buf, dword bufsize, int size)
{
    dword length;
    int bytesRead;

    /**
     * Decide how much we should take.
     */
    length = MIN ((dword) size, bufsize);

    if (length == 0)
    {
        return 0;
    }

    if ((bytesRead = rtsmb_net_read_simple (sock, buf, (int)length)) < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_net_read: error in rtsmb_net_read_simple.\n", RTSMB_DEBUG_TYPE_ASCII);
        return -1;
    }

    /**
     * If we haven't got all the expected bytes yet, wait until we do.
     */
    while ((dword) bytesRead < length)
    {
        int num_socks;

        num_socks = rtsmb_netport_select_n_for_read (&sock, 1, RTSMB_NB_UCAST_RETRY_TIMEOUT);

        if (num_socks)
        {
            int moreBytesRead = rtsmb_net_read (sock, (PFBYTE) buf + bytesRead,
                (bufsize - (dword) bytesRead),(int) (size - bytesRead));

            if (moreBytesRead == -1)
                return -1;  // previous call printed error, so we don't have to

            bytesRead += moreBytesRead;
        }
        else
        {
            // timeout, signal error
            RTSMB_DEBUG_OUTPUT_STR("rtsmb_net_read: timed out while trying to read all the data.\n", RTSMB_DEBUG_TYPE_ASCII);
            return bytesRead;
        }
    }

    /**
     * Now we clear out any remaining bytes on wire.
     */
    if ((dword) bytesRead >= length && (dword) size > length)
    {
        dword diff = (dword)size - length;
        byte temp [128];

        while (diff > 128)
        {
            if (rtsmb_net_read_simple (sock, temp, 128) == -1)
            {
                RTSMB_DEBUG_OUTPUT_STR("rtsmb_net_read: error while clearing out extra bytes on wire.\n", RTSMB_DEBUG_TYPE_ASCII);
                return -1;
            }

            diff -= 128;
        }

        if (rtsmb_net_read_simple (sock, temp, (int)diff) == -1)
        {
            RTSMB_DEBUG_OUTPUT_STR("rtsmb_net_read: error while clearing out extra bytes on wire.\n", RTSMB_DEBUG_TYPE_ASCII);
            return -1;
        }
    }

    return bytesRead;
}


/**
 * Blocks until |size| bytes from buf have been sent.
 *
 * Returns -1 if an error occurs, 0 else.
 */
int rtsmb_net_write (RTP_SOCKET socket, PFVOID buf, int size)
{
    int bytes_sent;
    int rv = 0;

    do
    {
        bytes_sent = rtp_net_send(socket, buf, size);

        if (bytes_sent < 0) /* an error occurred */
        {
            rv = -1;
            break;
        }

        size -= bytes_sent;
        buf = PADD (buf, bytes_sent);

    } while (size > 0);

    return rv;
}


/*
================
 int rtsmb_net_read_datagram() - Description

    int sock - socket to read from
    void *pData - target buffer
    int size - size of buffer
    PFBYTE remoteAddr - source address (optional)

    return(int) - size of data received
================
*/
int rtsmb_net_read_datagram (RTP_SOCKET sock, PFVOID pData, int size, PFBYTE remoteAddr, PFINT remotePort)
{
    int bytesRead;
    int newPort;
    int ipVer = 4;
    char temp[20];

    if(!pData)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_net_read_datagram: NULL buffer\n", RTSMB_DEBUG_TYPE_ASCII);
        return 0;
    }

    if (remotePort == (PFINT)0)
    {
        remotePort = &newPort;
    }

    bytesRead = rtp_net_recvfrom(sock, pData, size, remoteAddr, remotePort, &ipVer);

    if(bytesRead < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_net_read_datagram: Error in recvfrom\n", RTSMB_DEBUG_TYPE_ASCII);
        return 0;
    }
    rtsmb_net_ip_to_str(remoteAddr, (PFCHAR)temp);

    return bytesRead;
}


int rtsmb_net_write_datagram (RTP_SOCKET socket, PFBYTE remote, int port, PFVOID buf, int size)
{
    int bytes_sent;
    int rv = 0;

    do
    {
        bytes_sent = rtp_net_sendto(socket, buf,size,remote,port, 4);

        if (bytes_sent < 0) /* an error occurred */
        {
            rv = -1;
            break;
        }

        size -= bytes_sent;
        buf = PADD (buf, bytes_sent);

    } while (size > 0);

    return rv;
}


int rtsmb_net_str_to_ip (PFCHAR pfAddrStr, PFBYTE pfAddr)
{

    char * ptr;
    char savech;
    int n;
    int count;

    for (n=0; n<4; n++)
    {
        ptr = pfAddrStr;
        count = 0;
        while (*ptr != '.' && *ptr != '\0')
        {
            if(*ptr < '0' || *ptr > '9')
            {
                return (-1);
            }
            if(count >= 3)
            {
                return (-1);
            }
            else
            {
                ptr++;
                count++;
            }
        }

        savech = *ptr;
        *ptr = '\0';
        pfAddr[n] = (byte) tc_atoi((const char *) pfAddrStr);
        if (savech == '\0')
        {
            break;
        }
        *ptr = savech;

        pfAddrStr = ptr + 1;
    }

    return (0);

}

/* pfAddrStr must be at least 16 bytes large */
int rtsmb_net_ip_to_str (PFBYTE pfAddr, PFCHAR pfAddrStr)
{
    tc_memset(pfAddrStr, 0, 16);
    rtp_sprintf(pfAddrStr,"%i.%i.%i.%i", pfAddr[0], pfAddr[1], pfAddr[2], pfAddr[3]);
    return(0);
}

int rtsmb_net_socket_new (RTP_SOCKET* sock_ptr, int port, BBOOL reliable)
{
    int result;

    if (reliable)
    {
        result = rtp_net_socket_stream(sock_ptr);
    }
    else
    {
        result = rtp_net_socket_datagram(sock_ptr);
    }

    if (result < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_net_socket_new: Unable to get new socket\n", RTSMB_DEBUG_TYPE_ASCII);
        return -1;
    }

    if (rtp_net_bind(*sock_ptr, (unsigned char*)0, port, 4))
    {
        RTSMB_DEBUG_OUTPUT_STR ("rtsmb_net_socket_new: bind to port ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_INT (port);
        RTSMB_DEBUG_OUTPUT_STR (" failed\n", RTSMB_DEBUG_TYPE_ASCII);
        return -1;
    }

    RTSMB_DEBUG_OUTPUT_STR ("rtsmb_net_socket_new: Socket ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_INT ((int) (*sock_ptr));
    RTSMB_DEBUG_OUTPUT_STR (" bound to port ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_INT (port);
    RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);

    return 0;
}


void rtsmb_net_set_ip (PFBYTE host_ip, PFBYTE mask_ip)
{
    int i;
    byte rtsmb_net_mask_ip [4];

    if (host_ip)
    {
        rtp_memcpy (rtsmb_net_host_ip, host_ip, 4);
    }
    else
    {
        rtp_memcpy (rtsmb_net_host_ip, rtsmb_net_default_host_ip, 4);
    }

    if (mask_ip)
    {
        rtp_memcpy (rtsmb_net_mask_ip, mask_ip, 4);
    }
    else
    {
        rtp_memcpy (rtsmb_net_mask_ip, rtsmb_net_default_mask_ip, 4);
    }

    for (i = 0; i < 4; i++)
    {
        rtsmb_net_broadcast_ip[i] = (rtsmb_net_mask_ip[i] & rtsmb_net_host_ip[i]) |
                                    (byte)~(rtsmb_net_mask_ip[i]);
    }

    rtsmb_net_ip_is_set = TRUE;
}


PFBYTE rtsmb_net_get_host_ip (void)
{
    return rtsmb_net_host_ip;
}

PFBYTE rtsmb_net_get_broadcast_ip (void)
{
    return rtsmb_net_broadcast_ip;
}

BBOOL rtsmb_net_are_valid_ips (void)
{
    return rtsmb_net_ip_is_set;
}
