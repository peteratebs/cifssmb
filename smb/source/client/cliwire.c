/*                                                                      */
/* CLIWIRE.C -                                                          */
/*                                                                      */
/* EBSnet - RTSMB                                                       */
/*                                                                      */
/* Copyright EBSnet Inc. , 2003                                         */
/* All rights reserved.                                                 */
/* This code may not be redistributed in source or linkable object form */
/* without the consent of its author.                                   */
/*                                                                      */
/* Module description:                                                  */
/*  [tbd]                                                               */
/*                                                                      */

#include "smbdefs.h"
#ifdef SUPPORT_SMB2
#include "com_smb2.h"
#endif
#include "cliwire.h"

#ifdef SUPPORT_SMB2
smb2_stream  *rtsmb_cli_wire_smb2_stream_attach (PRTSMB_CLI_WIRE_SESSION pSession, word mid, int header_length, RTSMB2_HEADER *pheader_smb2);
#endif

#if (INCLUDE_RTSMB_CLIENT)

#include "cliwire.h"
#include "smbutil.h"
#include "smbnbss.h"
#include "clians.h"
#include "smbnet.h"
#include "clicfg.h"
#include "smbdebug.h"
#include "smbconf.h"

#include "rtpnet.h"
#include "rtptime.h"

extern void Get_Wire_Buffer_State(int a);
extern void Get_Wire_Session_State(int a);
RTSMB_STATIC int rtsmb_cli_wire_connect (PRTSMB_CLI_WIRE_SESSION pSession);
RTSMB_STATIC int rtsmb_cli_wire_send_nbss_request (PRTSMB_CLI_WIRE_SESSION pSession);

int rtsmb_cli_wire_start_connect (PRTSMB_CLI_WIRE_SESSION pSession);

/**
 * This file contains the "wire" abstraction -- clients to this
 * need not keep track of maintaining the connection to the server,
 * sending data over the network, or maintaining and filling buffers.
 */

RTSMB_STATIC
word rtsmb_cli_wire_get_next_mid (PRTSMB_CLI_WIRE_SESSION pSession)
{
    while (pSession->next_mid == 0)
    {
        pSession->next_mid ++;  /* unique per session */
    }

    return pSession->next_mid ++;
}


#define DO_OR_DIE(A, B)             {if (A < 0) return B;}
#define DO_OR_DIE_AND_KEEP(A, B, C) {A = B; if (A < 0) return C;}

RTSMB_STATIC
void rtsmb_cli_wire_buffer_new (PRTSMB_CLI_WIRE_SESSION pSession, int index)
{
    tc_memset (pSession->buffers[index].buffer, 0, prtsmb_cli_ctx->buffer_size);

    pSession->buffers[index].mid = rtsmb_cli_wire_get_next_mid (pSession);

    pSession->buffers[index].last_section     = pSession->buffers[index].buffer;
    pSession->buffers[index].buffer_end       = pSession->buffers[index].buffer;
    pSession->buffers[index].allocated_buffer_size
                                              = prtsmb_cli_ctx->buffer_size;
    pSession->buffers[index].attached_data    = 0;
    pSession->buffers[index].attached_size    = 0;
}

RTSMB_STATIC
void rtsmb_cli_wire_buffer_free (PRTSMB_CLI_WIRE_SESSION pSession, int index)
{
    tc_memset (pSession->buffers[index].buffer, 0, prtsmb_cli_ctx->buffer_size);

    pSession->buffers[index].state = UNUSED;
    pSession->buffers[index].flags = 0;
}

/**
 * Returns a free buffer.
 */
RTSMB_STATIC
PRTSMB_CLI_WIRE_BUFFER rtsmb_cli_wire_get_free_buffer (PRTSMB_CLI_WIRE_SESSION pSession)
{
    int i;

    for (i = 0; i < prtsmb_cli_ctx->max_buffers_per_wire; i++)
    {
        if (pSession->buffers[i].state == UNUSED)
        {
            rtsmb_cli_wire_buffer_new (pSession, i);
            return &pSession->buffers[i];
        }
    }

    return 0;
}

/**
 * Returns the correct buffer.
 */
PRTSMB_CLI_WIRE_BUFFER rtsmb_cli_wire_get_buffer (PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    int i;
    for (i = 0; i < prtsmb_cli_ctx->max_buffers_per_wire; i++)
    {
        if (pSession->buffers[i].state != UNUSED &&
            pSession->buffers[i].mid == mid)
        {
#if (0)
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"rtsmb_cli_wire_get_buffer: found session buffer for message id: %d\n", (int) mid);
#endif
            return &pSession->buffers[i];
        }
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_cli_wire_get_buffer: Failed matching session buffer for message id: %d !!!!!!!!!!!!!!!!!!!!!!!!!!\n", (int) mid);
    return 0;
}


int rtsmb_cli_wire_session_new (PRTSMB_CLI_WIRE_SESSION pSession, PFCHAR name, PFBYTE ip, int blocking)
{
    int i;

    pSession->socket = -1;
    pSession->state = UNCONNECTED;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Session_State(UNCONNECTED);
#endif
    pSession->next_mid = 0;
    pSession->num_nbss_sent = 0;
    pSession->reading = FALSE;
    tc_memcpy (pSession->server_ip, ip, 4);
    if (name)
    {
        tc_strncpy (pSession->server_name, name, RTSMB_NB_NAME_SIZE);
        pSession->server_name[RTSMB_NB_NAME_SIZE] = '\0';
    }
    else
    {
        tc_strcpy (pSession->server_name, RTSMB_NB_DEFAULT_NAME);
    }

    for (i = 0; i < prtsmb_cli_ctx->max_buffers_per_wire; i++)
    {
        rtsmb_cli_wire_buffer_free (pSession, i);
    }
    if (blocking)
    {
        if (rtsmb_cli_wire_connect (pSession) < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_cli_wire_session_new: socket or connect: (blocking) Failed !!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
            return -1;
        }
        if (!pSession->usingSmbOverTcp)
        {
            rtsmb_cli_wire_send_nbss_request (pSession);
        }
        else
        {
            pSession->state = NBS_CONNECTED;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Session_State(NBS_CONNECTED);
#endif
        }
    }
    else
    {
        int r = rtsmb_cli_wire_start_connect(pSession);
        if (r < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_cli_wire_session_new: socket or connect failed(nonblocking) !!!!!!!!!\n",0);
        }
        return r;

    }

    return 0;
}


int rtsmb_cli_wire_session_close (PRTSMB_CLI_WIRE_SESSION pSession)
{
int linger_val = 0;

    /* FIXME -- flesh out   */
    if (pSession->state != UNCONNECTED)
    {
#if (INCLUDE_RTIP)
        if (rtp_net_setsockoopt ((RTP_SOCKET) pSession->socket, RTP_NET_SOL_SOCKET,
                                 RTP_NET_SO_LINGER,
                                 (RTP_PFCHAR)&linger_val, sizeof(int)) < 0)
        {
            RTSMB_DEBUG_OUTPUT_STR ("ERROR IN SETSOCKOPT - SO_LINGER\n", RTSMB_DEBUG_TYPE_ASCII);
        }
#endif

        if (rtp_net_closesocket((RTP_SOCKET) pSession->socket))
        {
            RTSMB_DEBUG_OUTPUT_STR ("ERROR IN CLOSESOCKET\n", RTSMB_DEBUG_TYPE_ASCII);
        }
    }
    return 0;
}

int rtsmb_cli_wire_start_connect (PRTSMB_CLI_WIRE_SESSION pSession)
{
    if (pSession->state != UNCONNECTED)
    {
        SMB_ERROR("rtsmb_cli_wire_start_connect() - RTSMB_CLI_WIRE_ERROR_BAD_STATE");
        return RTSMB_CLI_WIRE_ERROR_BAD_STATE;
    }

    pSession->nbssStatus = 0;
    pSession->tcpStatus = 0;

    if (rtp_net_socket_stream(&pSession->nbssAttempt) < 0)
    {
        pSession->nbssStatus = -1;
    }
    else
    {
        rtp_net_setblocking(pSession->nbssAttempt, 0);

        if (rtp_net_connect(pSession->nbssAttempt, pSession->server_ip, rtsmb_nbss_port, 4) == -1)
        {
            rtp_net_setlinger(pSession->nbssAttempt, 1, 0);
            rtp_net_closesocket(pSession->nbssAttempt);
            pSession->nbssStatus = -1;
        }
    }

  #ifdef RTSMB_ALLOW_SMB_OVER_TCP
    if (rtp_net_socket_stream(&pSession->tcpAttempt) < 0)
    {
        pSession->tcpStatus = -1;
    }
    else
    {
        rtp_net_setblocking(pSession->tcpAttempt, 0);

        if (rtp_net_connect(pSession->tcpAttempt, pSession->server_ip,
                            rtsmb_nbss_direct_port, 4) == -1)
        {
            /* set the socket to do hard-close (RST)   */
            rtp_net_setlinger(pSession->tcpAttempt, 1, 0);
            rtp_net_closesocket(pSession->tcpAttempt);
            pSession->tcpStatus = -1;
        }
    }

    if (pSession->tcpStatus < 0 && pSession->nbssStatus < 0)
    {
        return RTSMB_CLI_SSN_RV_DEAD;
    }
  #else

    if (pSession->nbssStatus < 0)
    {
        return RTSMB_CLI_SSN_RV_DEAD;
    }

  #endif /* RTSMB_ALLOW_SMB_OVER_TCP */

    pSession->startMsec = rtp_get_system_msec();
    return RTSMB_CLI_SSN_RV_OK;
}

int rtsmb_cli_wire_connect_cycle (PRTSMB_CLI_WIRE_SESSION pSession)
{
    RTP_FD_SET writeList;
    RTP_FD_SET errList;
    int result;

    rtp_fd_zero(&writeList);
    rtp_fd_zero(&errList);

#ifdef RTSMB_ALLOW_SMB_OVER_TCP
    if (pSession->tcpStatus == 0)
    {
        rtp_fd_set(&writeList, pSession->tcpAttempt);
        rtp_fd_set(&errList, pSession->tcpAttempt);
    }
#endif

    if (pSession->nbssStatus == 0)
    {
        rtp_fd_set(&writeList, pSession->nbssAttempt);
        rtp_fd_set(&errList, pSession->nbssAttempt);
    }

    result = rtp_net_select(0, &writeList, &errList, 100);
    result = result;

#ifdef RTSMB_ALLOW_SMB_OVER_TCP
    if (pSession->tcpStatus == 0 && rtp_fd_isset(&writeList, pSession->tcpAttempt))
    {
        /* TCP connection succeeded; don't bother waiting for the   */
        /*  NetBIOS session service attempt                         */
        pSession->tcpStatus = 1;
        pSession->socket = pSession->tcpAttempt;
        pSession->usingSmbOverTcp = 1;
        if (pSession->nbssStatus != -1)
        {
            rtp_net_setlinger(pSession->nbssAttempt, 1, 0);
            rtp_net_closesocket(pSession->nbssAttempt);
        }
        pSession->state = NBS_CONNECTED;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Session_State(NBS_CONNECTED);
#endif
        return RTSMB_CLI_SSN_RV_OK;
    }

    RTSMB_ASSERT(pSession->tcpStatus == -1 || pSession->tcpStatus == 0);
#endif

    if (pSession->nbssStatus == 0 && rtp_fd_isset(&writeList, pSession->nbssAttempt))
    {
        pSession->nbssStatus = 1;
        pSession->socket = pSession->nbssAttempt;
    }

#ifdef RTSMB_ALLOW_SMB_OVER_TCP
    if (pSession->tcpStatus == 0 && rtp_fd_isset(&errList, pSession->tcpAttempt))
    {
        pSession->tcpStatus = -1;
        rtp_net_setlinger(pSession->tcpAttempt, 1, 0);
        rtp_net_closesocket(pSession->tcpAttempt);
    }
#endif

    if (pSession->nbssStatus == 0 && rtp_fd_isset(&errList, pSession->nbssAttempt))
    {
        pSession->nbssStatus = -1;
        rtp_net_setlinger(pSession->nbssAttempt, 1, 0);
        rtp_net_closesocket(pSession->nbssAttempt);

#ifdef RTSMB_ALLOW_SMB_OVER_TCP
        if (pSession->tcpStatus < 0)
#endif
        {
            /* both connects failed   */
            return RTSMB_CLI_SSN_RV_DEAD;
        }
    }

    /* connect time-out of 3 minutes?   */
    if (IS_PAST(pSession->startMsec, 5000))
    {
        /* timeout condition   */
#ifdef RTSMB_ALLOW_SMB_OVER_TCP
        if (pSession->tcpStatus == 0)
        {
            rtp_net_setlinger(pSession->tcpAttempt, 1, 0);
            rtp_net_closesocket(pSession->tcpAttempt);
            pSession->tcpStatus = -1;
        }
#endif /* RTSMB_ALLOW_SMB_OVER_TCP */

        if (pSession->nbssStatus == 0)
        {
            rtp_net_setlinger(pSession->nbssAttempt, 1, 0);
            rtp_net_closesocket(pSession->nbssAttempt);

            return RTSMB_CLI_SSN_RV_DEAD;
        }
    }

    if (pSession->nbssStatus == 1)
    {
#ifdef RTSMB_ALLOW_SMB_OVER_TCP
        if (pSession->tcpStatus == 0)
        {
            return RTSMB_CLI_SSN_RV_IN_PROGRESS;
        }
        RTSMB_ASSERT(pSession->tcpStatus == -1);
#endif /* RTSMB_ALLOW_SMB_OVER_TCP */
        pSession->state = CONNECTED;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Session_State(CONNECTED);
#endif
        rtsmb_cli_wire_send_nbss_request (pSession);
        return RTSMB_CLI_SSN_RV_OK;
    }

    return RTSMB_CLI_SSN_RV_IN_PROGRESS;
}

RTSMB_STATIC
int rtsmb_cli_wire_connect (PRTSMB_CLI_WIRE_SESSION pSession)
{
    RTP_SOCKET nbssAttempt;
#ifdef RTSMB_ALLOW_SMB_OVER_TCP
    RTP_SOCKET tcpAttempt;
    int tryingSmbOverTcp = 0;
#endif

    if (pSession->state != UNCONNECTED)
    {
        SMB_ERROR("rtsmb_cli_wire_connect() - RTSMB_CLI_WIRE_ERROR_BAD_STATE");
        return RTSMB_CLI_WIRE_ERROR_BAD_STATE;
    }

#ifdef RTSMB_ALLOW_SMB_OVER_TCP
    pSession->usingSmbOverTcp = 0;
#endif

    if (rtp_net_socket_stream(&nbssAttempt) < 0)
    {
        return -1;
    }

#ifdef RTSMB_ALLOW_SMB_OVER_TCP
    if (rtp_net_socket_stream(&tcpAttempt) >= 0)
    {
        tryingSmbOverTcp = 1;

        /* set both sockets to be non-blocking so we can simultaneously attempt
            to connect to both ports */
        rtp_net_setblocking(nbssAttempt, 0);
    }


    if (rtp_net_connect (nbssAttempt, pSession->server_ip, rtsmb_nbss_port, 4) == -1)
    {
        rtp_net_setlinger(nbssAttempt, 1, 0);
        rtp_net_closesocket(nbssAttempt);

        /* SMB over TCP (port 445) is the only remaining option   */
        if (!tryingSmbOverTcp)
        {
            return -1;
        }

        if (rtp_net_connect (tcpAttempt, pSession->server_ip, rtsmb_nbss_direct_port, 4) < 0)
        {
            /* set the socket to do hard-close (RST)   */
            rtp_net_setlinger(tcpAttempt, 1, 0);
            rtp_net_closesocket(tcpAttempt);

            /* failed to connect to server!   */
            return -1;
        }
        /* fall through to the default case below (success)   */

        pSession->socket = tcpAttempt;
        pSession->usingSmbOverTcp = 1;
    }
    else
    {
        if (tryingSmbOverTcp)
        {
            int cyclesElapsed = 0;
            int nbssStatus = 0;
            int tcpStatus = 0;
            RTP_FD_SET writeList;
            RTP_FD_SET errList;
            int result;

            rtp_net_setblocking(tcpAttempt, 0);
            if (rtp_net_connect(tcpAttempt, pSession->server_ip, rtsmb_nbss_direct_port, 4) == -1)
            {
                tcpStatus = -1;
            }

            do
            {
                rtp_fd_zero(&writeList);
                rtp_fd_zero(&errList);

                if (tcpStatus == 0)
                {
                    rtp_fd_set(&writeList, tcpAttempt);
                    rtp_fd_set(&errList, tcpAttempt);
                }

                if (nbssStatus == 0)
                {
                    rtp_fd_set(&writeList, nbssAttempt);
                    rtp_fd_set(&errList, nbssAttempt);
                }

                result = rtp_net_select(0, &writeList, &errList, 5*1000);
                if (result < 0)
                    return -1;
                if (rtp_fd_isset(&writeList, tcpAttempt))
                {
                    /* TCP connection succeeded; don't bother waiting for the   */
                    /*  NetBIOS session service attempt                         */
                    tcpStatus = 1;
                    if (nbssStatus == 1)
                    {
                        nbssStatus = 0;
                    }
                    pSession->socket = tcpAttempt;
                    pSession->usingSmbOverTcp = 1;
                    break;
                }

                if (rtp_fd_isset(&writeList, nbssAttempt))
                {
                    nbssStatus = 1;
                    pSession->socket = nbssAttempt;
                }

                if (rtp_fd_isset(&errList, tcpAttempt))
                {
                    tcpStatus = -1;
                    rtp_net_setlinger(tcpAttempt, 1, 0);
                    rtp_net_closesocket(tcpAttempt);
                }

                if (rtp_fd_isset(&errList, nbssAttempt))
                {
                    nbssStatus = -1;
                    rtp_net_setlinger(nbssAttempt, 1, 0);
                    rtp_net_closesocket(nbssAttempt);

                    if (tcpStatus < 0)
                    {
                        /* both connects failed   */
                        return -1;
                    }
                }

                cyclesElapsed++;
            }
            while (cyclesElapsed < 5);

            if (tcpStatus == 0)
            {
                rtp_net_setlinger(tcpAttempt, 1, 0);
                rtp_net_closesocket(tcpAttempt);

                if (nbssStatus == 0)
                {
                    rtp_net_setlinger(nbssAttempt, 1, 0);
                    rtp_net_closesocket(nbssAttempt);

                    return -1;
                }
            }
            else if (nbssStatus == 0)
            {
                rtp_net_setlinger(nbssAttempt, 1, 0);
                rtp_net_closesocket(nbssAttempt);
            }
        }
        else
        {
            pSession->socket = nbssAttempt;
        }
    }

  #else
    pSession->socket = nbssAttempt;
    if (rtp_net_connect (pSession->socket, pSession->server_ip, rtsmb_nbss_port, 4) != 0)
    {
        if (rtp_net_closesocket (pSession->socket))
        {
            RTSMB_DEBUG_OUTPUT_STR("ERROR IN CLOSESOCKET\n",RTSMB_DEBUG_TYPE_ASCII);
        }

        return -1;
    }
 #endif

    /* reset the socket's blocking status to true, the default   */
    rtp_net_setblocking(pSession->socket, 1);
    pSession->state = CONNECTED;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Session_State(CONNECTED);
#endif

    return 0;
}

void rtsmb_debug_echo(PRTSMB_CLI_WIRE_SESSION pSession, byte *p, int nbytes)
{
    static byte mybuff[1024];
    RTSMB_NBSS_HEADER header;
    header.type = RTSMB_NBSS_COM_MESSAGE;
    header.size = (word) nbytes; /* - RTSMB_NBSS_HEADER_SIZE); */
    rtsmb_nbss_fill_header (mybuff, RTSMB_NBSS_HEADER_SIZE, &header);
    tc_memcpy(&mybuff[RTSMB_NBSS_HEADER_SIZE], p, (unsigned)nbytes);
    mybuff[56] ='X';
    mybuff[57] ='Y';
    rtsmb_net_write (pSession->socket, mybuff, nbytes+4);
}
RTSMB_STATIC
int rtsmb_cli_wire_send_nbss_request (PRTSMB_CLI_WIRE_SESSION pSession)
{
    int r;
    PFVOID pBuffer;
    RTSMB_NBSS_REQUEST request;
    RTSMB_NBSS_HEADER header;

    if (pSession->state != CONNECTED)
    {
        SMB_ERROR("rtsmb_cli_wire_send_nbss_request() - RTSMB_CLI_WIRE_ERROR_BAD_STATE");
        return RTSMB_CLI_WIRE_ERROR_BAD_STATE;
    }

    pBuffer = pSession->temp_buffer;

    header.type = RTSMB_NBSS_COM_REQUEST;
    header.size = 0;

    rtsmb_util_make_netbios_name (request.calling, RTSMB_NB_DEFAULT_NAME, RTSMB_NB_NAME_TYPE_WORKSTATION);
    rtsmb_util_make_netbios_name (request.called, pSession->server_name, RTSMB_NB_NAME_TYPE_SERVER);

    DO_OR_DIE_AND_KEEP (r, rtsmb_nbss_fill_header (pBuffer,
        prtsmb_cli_ctx->buffer_size, &header), -3);
    pBuffer = PADD (pBuffer, RTSMB_NBSS_HEADER_SIZE);
    DO_OR_DIE_AND_KEEP (r, rtsmb_nbss_fill_request (pBuffer,
        prtsmb_cli_ctx->buffer_size - RTSMB_NBSS_HEADER_SIZE, &request), -3);

    header.size = (dword)r;
    DO_OR_DIE_AND_KEEP (r, rtsmb_nbss_fill_header (pSession->temp_buffer,
        prtsmb_cli_ctx->buffer_size, &header), -3);

    pSession->temp_end_time_base = rtp_get_system_msec ();
    pSession->num_nbss_sent ++;

    DO_OR_DIE(rtsmb_net_write (pSession->socket, pSession->temp_buffer, r + (int)header.size), -2);

    return 0;
}

int rtsmb_cli_wire_awaken_requests (PRTSMB_CLI_WIRE_SESSION pSession)
{
    int i;
    int rv = 0;

    for (i = 0; i < prtsmb_cli_ctx->max_buffers_per_wire; i++)
    {
        if (pSession->buffers[i].state == WAITING_ON_US)
        {
            pSession->buffers[i].state = WAITING_ON_SERVER;

            pSession->buffers[i].end_time_base = rtp_get_system_msec ();

            DO_OR_DIE (rtsmb_net_write (pSession->socket,
                pSession->buffers[i].buffer,
                (int) pSession->buffers[i].buffer_size), -2);

            rv = 1;
        }
    }

    return rv;
}


#ifdef SUPPORT_SMB2

/* Start decryption. Called on a stream from the top level dispatch if the session is set up and known to be encrypted.
   Wraps the stream in a buffer with an SMB2 transform header prepended. The message finalize process will encrypt the outgoing messge.

   call smb2_stream_stop_decryption(smb2_stream *pstream, RTSMB2_TRANSFORM_HEADER *ptransform_header_smb2)

*/

int rtsmb2_decrypt (PFVOID to, PFVOID from, RTSMB2_TRANSFORM_HEADER *ptransform_header_smb2, int max_buffer_size)
{
int i;
byte *Dest = (byte *) to;
byte *Source = (byte *) from;

    /* Fake decrypt by taking every other byte   */
    for(i =0; i < MIN((int)ptransform_header_smb2->OriginalMessageSize,max_buffer_size); i++)
    {
        *Dest++=*Source++;
        Source++;
    }
    return MIN((int)ptransform_header_smb2->OriginalMessageSize,max_buffer_size);
}
#endif

/**
 * precondition: pSession->temp_buffer is full of |size| data.
 *
 * This examines the contents of temp_buffer and sees if we were
 * waiting on this message.  If not, ignore it.  If so, set up state
 * so clients can examine message themselves.
 */
RTSMB_STATIC
int rtsmb_cli_wire_handle_message (PRTSMB_CLI_WIRE_SESSION pSession, rtsmb_size size)
{
#ifdef SUPPORT_SMB2
    RTSMB2_HEADER header_smb2;
    RTSMB2_TRANSFORM_HEADER *ptransform_header_smb2,transform_header_smb2;
#endif
    int smb2_header_length = -1;
    RTSMB_HEADER header;
    int i;
    word mid;


    if (pSession->state < NBS_CONNECTED)
    {
        SMB_ERROR("rtsmb_cli_wire_handle_message() - RTSMB_CLI_WIRE_ERROR_BAD_STATE");
        return RTSMB_CLI_WIRE_ERROR_BAD_STATE;
    }

#ifdef SUPPORT_SMB2
    ptransform_header_smb2 = 0;
    smb2_header_length = -1;
#endif

#ifdef SUPPORT_SMB2
    /* Check if the message is encrypted   */
    if (pSession->temp_buffer[0] == 0xFD)
    {

        smb2_header_length = cmd_read_transform_header_smb2 (pSession->temp_buffer,pSession->temp_buffer,prtsmb_cli_ctx->buffer_size, &transform_header_smb2);
        if (smb2_header_length > 0)
        {
            ptransform_header_smb2 = &transform_header_smb2;
            mid = (word)transform_header_smb2.SessionId;
        }
    }
    else if (pSession->temp_buffer[0] == 0xFE)
    {
        smb2_header_length = cmd_read_header_raw_smb2 (pSession->temp_buffer,pSession->temp_buffer,prtsmb_cli_ctx->buffer_size, &header_smb2);
        if (smb2_header_length > 0)
        {
            mid = (word) header_smb2.MessageId;
        }
    }
#endif

    if (smb2_header_length < 0)
    {
        DO_OR_DIE (cli_cmd_read_header (pSession->temp_buffer,
            pSession->temp_buffer,
            prtsmb_cli_ctx->buffer_size, &header), -1);
        mid = header.mid;
    }

    for (i = 0; i < prtsmb_cli_ctx->max_buffers_per_wire; i++)
    {

        if (pSession->buffers[i].state == WAITING_ON_SERVER &&
            pSession->buffers[i].mid == mid)
        {
            int used_size;

            /* we've found it   */
            pSession->buffers[i].state = DONE;
            used_size = (int) (MIN (size, prtsmb_cli_ctx->buffer_size));

#ifdef SUPPORT_SMB2
            if (smb2_header_length > 0)
            {
                /* if (ptransform_header_smb2) then smb2_header_length is the transform header that has been read in.
                   else smb2_header_length is the smb2 header in the structure header_smb2
                   size is the amount of data in temp buffer
                   used_size is the count of valid bytes
                */
                if (ptransform_header_smb2)
                {
                    /* Decrypt the message from the temporary buffer into the session buffer   */
                    pSession->buffers[i].buffer_size = (dword)rtsmb2_decrypt (pSession->buffers[i].buffer,
                    PADD(pSession->temp_buffer, smb2_header_length),
                    ptransform_header_smb2,
                    used_size-smb2_header_length);
rtsmb_debug_echo(pSession, pSession->buffers[i].buffer, (int)pSession->buffers[i].buffer_size);

                    /* Now read the header from the temprory buffer so we can pass it to the next layer   */
                    smb2_header_length = cmd_read_header_raw_smb2 (pSession->buffers[i].buffer,pSession->buffers[i].buffer,pSession->buffers[i].buffer_size, &header_smb2);
                    if (smb2_header_length < 0)
                        return -i;
                }
                else
                {
                    /* Copy the message from temp buffer to the session buffer  */
                    tc_memcpy (pSession->buffers[i].buffer, pSession->temp_buffer, (unsigned)used_size);
                }

                /* Set up the Stream buffer,
                    Finds the stream associted with the MID in header.
                    Copy the header to the stream's inHdr structure.
                    Set the stream buffer point and size to reflect that the NBSS and SMB headers have been consumed */
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"rtsmb_cli_wire_handle_message: recieved SMB2 message calling: rtsmb_cli_wire_smb2_stream_attach\n",0);
                rtsmb_cli_wire_smb2_stream_attach (pSession, mid, smb2_header_length-RTSMB_NBSS_HEADER_SIZE, &header_smb2);
                return 1;
            }
            else
#endif
            {
                tc_memcpy (pSession->buffers[i].buffer, pSession->temp_buffer, (unsigned) used_size);
                pSession->buffers[i].buffer_size = (rtsmb_size) used_size;
            }
            return 1;

        }
    }

    return 0;
}

/**
 * Reads at most one incoming packet.
 *
 * Returns:
 *  1 if something interesting came in
 *  0 if no read necessary, or internal traffic
 *  -1 if we timed out
 *  -2 if something is wrong with the connection
 *  -3 if session is dead
 *  other negative number if an error occurred
 */
RTSMB_STATIC
int rtsmb_cli_wire_read (PRTSMB_CLI_WIRE_SESSION pSession, long timeout)
{
    int r, rv = 0;
    RTSMB_NBSS_HEADER message;

    if (pSession->state == DEAD)
        return -3;

    if (pSession->state < CONNECTED)
    {
        SMB_ERROR("rtsmb_cli_wire_read() - RTSMB_CLI_WIRE_ERROR_BAD_STATE");
        return RTSMB_CLI_WIRE_ERROR_BAD_STATE;
    }

    /* we restrict the timeout time so that we can catch timeouts of our
       messages */
    if (timeout < 0 || timeout > RTSMB_NB_UCAST_RETRY_TIMEOUT)
    {
        timeout = RTSMB_NB_UCAST_RETRY_TIMEOUT;
    }

    /* block on packet   */
    r = rtsmb_netport_select_n_for_read (&pSession->socket, 1, timeout);
    if (r > 0)
    {
        if (!pSession->reading)
        {
            /* now, we want to read 4 bytes to get netbios header   */
            r = rtsmb_net_read (pSession->socket, pSession->temp_buffer,
                prtsmb_cli_ctx->buffer_size, 4);

            if (r == -1)
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_cli_wire_read: net_read failed !!!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
                return -2;
            }

            r = rtsmb_nbss_read_header (pSession->temp_buffer,
                prtsmb_cli_ctx->buffer_size, &message);
            if (r == -1)
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_cli_wire_read: rtsmb_nbss_read_header failed !!!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
                return -4;
            }

            pSession->reading = TRUE;
            pSession->total_to_read = message.size;
            pSession->total_read = 0;
            pSession->temp_end_time_base = rtp_get_system_msec ();
        }

        /* now, we read rest of message   */
        r = rtsmb_net_read (pSession->socket, pSession->temp_buffer + pSession->total_read,
            prtsmb_cli_ctx->buffer_size - pSession->total_read, (word) (pSession->total_to_read - pSession->total_read));

        if (r == -1)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_cli_wire_read: net_read failed !!!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
            return -2;
        }

        pSession->total_read += (dword)r;
        if (pSession->total_read >= pSession->total_to_read)
        {
            pSession->reading = FALSE;

            /* handle netbios, non-smb messages:   */
            switch (message.type)
            {
            case RTSMB_NBSS_COM_POSITIVE_RESPONSE:
                if (pSession->state == CONNECTED)
                {
                    pSession->state = NBS_CONNECTED;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Session_State(NBS_CONNECTED);
#endif
                }
                rv = rtsmb_cli_wire_awaken_requests (pSession);

                if (rv == -1)
                {
                    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_cli_wire_read: rtsmb_cli_wire_awaken_requests failed !!!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
                    rv = -2;
                }

                break;
            case RTSMB_NBSS_COM_NEGATIVE_RESPONSE:
                if (pSession->state == CONNECTED)
                {
                    pSession->state = DEAD;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Session_State(DEAD);
#endif
                    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"rtsmb_cli_wire_read: RTSMB_NBSS_COM_NEGATIVE_RESPONSE detected !!!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
                    rv = -3;
                }
                else
                {
                    rv = 0;
                }
                break;
            case RTSMB_NBSS_COM_MESSAGE:
                /* ok.  let's find if we are waiting on this.  if not, ignore   */
                if (rtsmb_cli_wire_handle_message (pSession, (rtsmb_size)r) == 1)
                {
                    rv = 1;
                }
                else
                {
                    rv = 0;
                }

                break;
            default:
                rv = 0;
                break;
            }
        }
    }

    /* check for timeouts   */
    for (r = 0; r < prtsmb_cli_ctx->max_buffers_per_wire; r++)
    {
        if (pSession->buffers[r].state != UNUSED && pSession->buffers[r].state != DONE)
        {
            if (ON (pSession->buffers[r].flags, INFO_CAN_TIMEOUT) &&
                IS_PAST (pSession->buffers[r].end_time_base, RTSMB_NB_UCAST_RETRY_TIMEOUT))
            {
                if (pSession->buffers[r].state != TIMEOUT)
                {
                    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_cli_wire_read: Timing out a buffer  !!!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
                    pSession->buffers[r].state = TIMEOUT;
                }
                if (rv == 0)
                {
                    rv = 1;
                }
            }
        }
    }

    if (IS_PAST (pSession->temp_end_time_base, RTSMB_NB_UCAST_RETRY_TIMEOUT))
    {
        if (pSession->reading)
        {
            /* we timed out while reading a large packet   */
            pSession->reading = FALSE;
        }
        else if (pSession->state == CONNECTED)
        {
            /* we timed out while connecting to server.   */
            if (pSession->num_nbss_sent >= RTSMB_NB_UCAST_RETRY_COUNT)
            {
                pSession->state = DEAD;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Session_State(DEAD);
#endif
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_cli_wire_read: Exceed retry count connecting to a server  !!!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
                return -3;
            }
            else
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_cli_wire_read: Re-sending nbss request  !!!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
                rtsmb_cli_wire_send_nbss_request (pSession);
            }
        }
    }

    return rv;
}


/**
 * Reads at most one incoming packet, timeout is milliseconds to wait.
 *
 * Returns:
 *  size of read data on successful read
 *  0 if no read necessary
 *  -1 if we timed out
 *  -2 if an error occurred
 */
int rtsmb_cli_wire_cycle (PRTSMB_CLI_WIRE_SESSION pSession, long timeout)
{
    return rtsmb_cli_wire_read (pSession, timeout);
}


RTSMB_CLI_MESSAGE_STATE rtsmb_cli_wire_check_message (PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    RTSMB_CLI_MESSAGE_STATE rv = NON_EXISTANT;
    int i;

    for (i = 0; i < prtsmb_cli_ctx->max_buffers_per_wire; i++)
    {
        if (pSession->buffers[i].state != UNUSED &&
            pSession->buffers[i].mid == mid)
        {
            /* we've found it   */
            switch (pSession->buffers[i].state)
            {
            case WAITING_ON_SERVER:
            case WAITING_ON_US:
                rv = WAITING;
                break;
            case TIMEOUT:
                rv = TIMED_OUT;
                break;
            case DONE:
                rv = FINISHED;
                break;
            default:
                rv = WAITING;
                break;
            }

            break;
        }
    }

    return rv;
}


/*

    Same as rtsmb_cli_wire_smb_add_start_smb2 but does not change buffer_end to include the NBSS header


*/
int rtsmb_cli_wire_smb2_add_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;

    pBuffer = rtsmb_cli_wire_get_free_buffer (pSession);

    if (!pBuffer)
    {
        return RTSMB_CLI_WIRE_TOO_MANY_REQUESTS;
    }

    if (mid)
    {
        pBuffer->mid = mid;
    }

    pBuffer->last_section = 0;
    pBuffer->buffer_end = PADD (pBuffer->buffer_end, RTSMB_NBSS_HEADER_SIZE);

    pBuffer->state = BEING_FILLED;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(BEING_FILLED);
#endif

    pBuffer->buffer_size = (rtsmb_size) PDIFF(pBuffer->buffer_end, pBuffer->buffer);

    return pBuffer->mid;
}

int rtsmb_cli_wire_smb_add_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;

    pBuffer = rtsmb_cli_wire_get_free_buffer (pSession);

    if (!pBuffer)
    {
        return RTSMB_CLI_WIRE_TOO_MANY_REQUESTS;
    }

    if (mid)
    {
        pBuffer->mid = mid;
    }

    pBuffer->last_section = 0;
    pBuffer->buffer_end = PADD (pBuffer->buffer_end, RTSMB_NBSS_HEADER_SIZE);

    pBuffer->state = BEING_FILLED;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(BEING_FILLED);
#endif

    pBuffer->buffer_size = (rtsmb_size) PDIFF(pBuffer->buffer_end, pBuffer->buffer);

    return pBuffer->mid;
}

int rtsmb_cli_wire_smb_add_header (PRTSMB_CLI_WIRE_SESSION pSession, word mid,
    PRTSMB_HEADER pHeader)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    int r;

    pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);

    if (!pBuffer)
        return RTSMB_CLI_WIRE_BAD_MID;

    pHeader->mid = mid;
    r = cli_cmd_fill_header (pBuffer->buffer_end, pBuffer->buffer_end,
        prtsmb_cli_ctx->buffer_size - (rtsmb_size) PDIFF(pBuffer->buffer_end, pBuffer->buffer),
        pHeader);

    if (r < 0)
        return -3;

    pBuffer->buffer_end = PADD (pBuffer->buffer_end, r);

    pBuffer->buffer_size = (rtsmb_size) PDIFF(pBuffer->buffer_end, pBuffer->buffer);

    return 0;
}

#ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
int rtsmb_cli_wire_smb_add_data (PRTSMB_CLI_WIRE_SESSION pSession, word mid, PFBYTE data, long size)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;

    pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);

    if (!pBuffer)
        return RTSMB_CLI_WIRE_BAD_MID;

    pBuffer->attached_data = data;
    pBuffer->attached_size = (rtsmb_size) size;

    return 0;
}
#endif

int rtsmb_cli_wire_smb_add_end (PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    RTSMB_NBSS_HEADER header;

    pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);

    if (!pBuffer)
        return RTSMB_CLI_WIRE_BAD_MID;

    header.type = RTSMB_NBSS_COM_MESSAGE;
    header.size = (word) (pBuffer->buffer_size - RTSMB_NBSS_HEADER_SIZE);

  #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
    if (pBuffer->attached_data)
    {
        header.size += pBuffer->attached_size;
    }
  #endif

    rtsmb_nbss_fill_header (pBuffer->buffer, RTSMB_NBSS_HEADER_SIZE, &header);

    TURN_ON (pBuffer->flags, INFO_CAN_TIMEOUT);

    if (pSession->state == CONNECTED)
    {
        pBuffer->state = WAITING_ON_US;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(WAITING_ON_US);
#endif
    }
    else
    {
        pBuffer->state = WAITING_ON_SERVER;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(WAITING_ON_SERVER);
#endif
        pBuffer->end_time_base = rtp_get_system_msec ();

        DO_OR_DIE (rtsmb_net_write (pSession->socket,
            pBuffer->buffer, (int)pBuffer->buffer_size), -2);

      #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
        if (pBuffer->attached_data)
        {
            DO_OR_DIE (rtsmb_net_write (pSession->socket,
                pBuffer->attached_data, (int)pBuffer->attached_size), -2);
        }
      #endif
    }

    return 0;
}


int rtsmb_cli_wire_smb_read_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;

    pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);

    if (!pBuffer)
        return RTSMB_CLI_WIRE_BAD_MID;

    if (pBuffer->state != DONE)
    {
        SMB_ERROR("rtsmb_cli_wire_smb_read_start() - RTSMB_CLI_WIRE_ERROR_BAD_STATE");
        return RTSMB_CLI_WIRE_ERROR_BAD_STATE;
    }

    pBuffer->last_section = 0;

    /* nbs header is not present!   */
    pBuffer->buffer_end = pBuffer->buffer;

    return 0;
}

int rtsmb_cli_wire_smb_read_header (PRTSMB_CLI_WIRE_SESSION pSession, word mid,
    PRTSMB_HEADER pHeader)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    int r;

    pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);

    if (!pBuffer)
        return RTSMB_CLI_WIRE_BAD_MID;

    r = cli_cmd_read_header (pBuffer->buffer_end, pBuffer->buffer_end,
        pBuffer->buffer_size,
        pHeader);

    if (r < 0)
        return -3;

    pBuffer->buffer_end = PADD (pBuffer->buffer_end, r);
    pBuffer->buffer_size -= (dword)r;

    return 0;
}

int rtsmb_cli_wire_smb_read_end (PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;

    pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);

    if (!pBuffer)
        return RTSMB_CLI_WIRE_BAD_MID;

    pBuffer->state = UNUSED;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(UNUSED);
#endif

    return 0;
}

int rtsmb_cli_wire_smb_close (PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;

    pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);

    if (!pBuffer)
        return RTSMB_CLI_WIRE_BAD_MID;

    pBuffer->state = UNUSED;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(UNUSED);
#endif

    return 0;
}

#endif /* INCLUDE_RTSMB_CLIENT */
