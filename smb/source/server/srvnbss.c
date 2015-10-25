/*                                                                           */
/* SRVNBSS.C -                                                               */
/*                                                                           */
/* EBSnet - RTSMB                                                            */
/*                                                                           */
/* Copyright EBSnet Inc. , 2003                                              */
/* All rights reserved.                                                      */
/* This code may not be redistributed in source or linkable object form      */
/* without the consent of its author.                                        */
/*                                                                           */
/* Module description:                                                       */
/* This file contains some convenience routines and processing functions for */
/* handling the netbios session layer in the RTSMB server.                   */
/*                                                                           */

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvnet.h"
#include "smbnbss.h"
#include "smbnb.h"
#include "srvnbns.h"
#include "smbnet.h"
#include "smbutil.h"
#include "smbdebug.h"

#include "rtpscnv.h"
/**
 * Convenience function to send a response packet down the socket.
 */
void rtsmb_srv_nbss_send_session_response (RTP_SOCKET sock, BBOOL positive)
{
	char tmp_buf[RTSMB_NBSS_HEADER_SIZE];
	RTSMB_NBSS_HEADER header;
	int r;

	header.type = positive ? RTSMB_NBSS_COM_POSITIVE_RESPONSE : RTSMB_NBSS_COM_NEGATIVE_RESPONSE;
	header.size = 0;

	r = rtsmb_nbss_fill_header (tmp_buf, RTSMB_NBSS_HEADER_SIZE, &header);
	if (r >= 0)
	{
		rtsmb_net_write (sock, tmp_buf, r);
	}
}

/**
 * Convenience function to send a request packet down the socket.
 */
void rtsmb_srv_nbss_send_session_request (RTP_SOCKET sock, PFCHAR server_name, byte server_type)
{
	RTSMB_NBSS_HEADER header;
	RTSMB_NBSS_REQUEST request;
	char tmp_buf[RTSMB_NBSS_HEADER_SIZE + RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE * 2];
	rtsmb_size size = sizeof (tmp_buf);
	int r;

	header.type = RTSMB_NBSS_COM_REQUEST;
	header.size = RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE * 2;

	rtsmb_util_make_netbios_name (request.calling, rtsmb_srv_nbns_get_our_name (), RTSMB_NB_NAME_TYPE_SERVER);
	rtsmb_util_make_netbios_name (request.called, server_name, server_type);

	r = rtsmb_nbss_fill_header (tmp_buf, size, &header);
	ASSURE_V (r >= 0);
	size -= (rtsmb_size)r;

	r = rtsmb_nbss_fill_request (tmp_buf + r, size, &request);
	if (r >= 0)
	{
		rtsmb_net_write (sock, tmp_buf, r);
	}
}


RTSMB_STATIC
BBOOL rtsmb_srv_nbss_process_request (RTP_SOCKET sock, PRTSMB_NBSS_HEADER pHeader)
{
	byte buffer[RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE * 2];
	RTSMB_NBSS_REQUEST request;

	if (rtsmb_net_read (sock, buffer, sizeof (buffer), pHeader->size) < 0)
	{
		return FALSE;
	}

	if (rtsmb_nbss_read_request (buffer, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE * 2, &request) < 0)
	{
		return FALSE;
	}

	if (rtsmb_srv_nbns_is_in_name_table (request.called, TRUE))
	{
		RTSMB_DEBUG_OUTPUT_STR ("rtsmb_srv_nbss_process_request: Allowing connection to ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (request.called, RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR ("from ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (request.calling, RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
		rtsmb_srv_nbss_send_session_response (sock, TRUE);
	}
	else
	{
		RTSMB_DEBUG_OUTPUT_STR ("rtsmb_srv_nbss_process_request: Bad name ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (request.called, RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR ("from ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (request.calling, RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
		rtsmb_srv_nbss_send_session_response (sock, TRUE);
		rtsmb_srv_nbss_send_session_response (sock, FALSE);
		return FALSE;
	}

	return TRUE;
}


/**
 * At this point in the packet's life, only the first few bytes will be
 * read, in order to get the NetBios header.  This gives us the length
 * of the message, which we will then pull from the socket.
 *
 * Returns FALSE if we should end the session.
 */
BBOOL rtsmb_srv_nbss_process_packet (PSMB_SESSIONCTX pSCtx)
{
	RTSMB_NBSS_HEADER header;

	if (rtsmb_net_read (pSCtx->sock, pSCtx->readBuffer, pSCtx->readBufferSize, RTSMB_NBSS_HEADER_SIZE) == -1)
	{
		return FALSE;
	}
	if (rtsmb_nbss_read_header (pSCtx->readBuffer, RTSMB_NBSS_HEADER_SIZE, &header) < 0)
	{
		return FALSE;
	}
	switch (header.type)
	{
		case RTSMB_NBSS_COM_MESSAGE:	/* Session Message */

			if (!SMBS_ProcSMBPacket (pSCtx, header.size))
			{
				return FALSE;
			}
			break;

		case RTSMB_NBSS_COM_REQUEST:	/* Session Request */

			if (!rtsmb_srv_nbss_process_request (pSCtx->sock, &header))
			{
				return FALSE;
			}
			break;

		default:

		{
			char buf[32];
			char* tmpbuf = buf;

			buf[0] = '\0';
			RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_nbss_process_packet: Unhandled packet type 0x", RTSMB_DEBUG_TYPE_ASCII);
			tmpbuf = rtp_itoa(header.type, tmpbuf, 16);
			RTSMB_DEBUG_OUTPUT_STR(tmpbuf, RTSMB_DEBUG_TYPE_ASCII);
			RTSMB_DEBUG_OUTPUT_STR(".\n", RTSMB_DEBUG_TYPE_ASCII);
		}
		break;
	}

	return TRUE;
}

#endif /* INCLUDE_RTSMB_SERVER */
