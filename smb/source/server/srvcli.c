/*                                                                        */
/*                                                                        */
/* EBSnet - RTSMB                                                         */
/*                                                                        */
/* Copyright EBSnet Inc. , 2003                                           */
/* All rights reserved.                                                   */
/* This code may not be redistributed in source or linkable object form   */
/* without the consent of its author.                                     */
/*                                                                        */
/* Module description:                                                    */
/* This is a skeleton SMB client.  It is used exclusively by the server   */
/* to accomplish various tasks for which it needs to connect to other     */
/* servers on the network.  For full client behavior, look at the various */
/* cli*.c files.                                                          */
/*                                                                        */

#include "smbdefs.h"
#include "rtpwcs.h" /* _YI_ 9/24/2004 */
#include "smbdebug.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvcli.h"
#include "smbnb.h"
#include "smbpack.h"
#include "smbread.h"
#include "smbobjs.h"
#include "smb.h"
#include "srvnbns.h"
#include "smbnbss.h"
#include "srvnbss.h"
#include "srvcfg.h"
#include "smbutil.h"
#include "srvans.h"
#include "srvcmds.h"
#include "smbnet.h"

#include "rtptime.h"
#include "rtpnet.h"


/**
 * Some private defines.
 */
#define RTSMB_SRV_CLI_STATE_UNUSED         0 /* no session currently running */
#define RTSMB_SRV_CLI_STATE_IDLE           1 /* ready to receive requests */
#define RTSMB_SRV_CLI_STATE_DEAD           2 /* session was broken */
#define RTSMB_SRV_CLI_STATE_PROCESSING     3 /* reading reply from server */
#define RTSMB_SRV_CLI_STATE_READING        4 /* in the middle of reading a packet */

#define RTSMB_SRV_CLI_JOB_TYPE_NONE        0 /* no job present */
#define RTSMB_SRV_CLI_JOB_TYPE_QUERY_IP    1 /* query name to find ip address */
#define RTSMB_SRV_CLI_JOB_TYPE_CONNECT     2 /* connect to server port */
#define RTSMB_SRV_CLI_JOB_TYPE_NEGOTIATE   3 /* negotiate dialect */
#define RTSMB_SRV_CLI_JOB_TYPE_SETUP       4 /* setup user and share connection */
#define RTSMB_SRV_CLI_JOB_TYPE_SERVER_ENUM 5 /* enumerate servers */

RTSMB_STATIC rtsmb_char dialect_lanman[] = {'L', 'A', 'N', 'M', 'A', 'N', '1', '.', '0', '\0'};


/**
 * Some private variables so that we can remember what's going on.
 */
RTSMB_STATIC char          rtsmb_srv_cli_server_name [RTSMB_NB_NAME_SIZE + 1];
RTSMB_STATIC byte          rtsmb_srv_cli_server_ip [4];
RTSMB_STATIC RTP_SOCKET    rtsmb_srv_cli_socket;
RTSMB_STATIC int           rtsmb_srv_cli_state;
RTSMB_STATIC int           rtsmb_srv_cli_packet_size; /* size of packet being read */
RTSMB_STATIC int           rtsmb_srv_cli_bytes_read; /* number of bytes read so far */
RTSMB_STATIC BBOOL         rtsmb_srv_cli_have_header; /* have we read the nbss header already? */

RTSMB_STATIC word          rtsmb_srv_cli_uid;
RTSMB_STATIC word          rtsmb_srv_cli_tid;

struct
{
	int type;
	unsigned long start_time;

	union
	{
		struct
		{
			PRTSMB_BROWSE_SERVER_INFO answering_infos;
			int answering_infos_size;
			PFINT answering_count;

		} server_enum;

	} data;

} rtsmb_srv_cli_current_job;


/**
 * Now, the private function prototypes.
 */
RTSMB_STATIC int  _rtsmb_srv_cli_continue_read (long timeout);
RTSMB_STATIC void _rtsmb_srv_cli_start_job (int type);
RTSMB_STATIC int  _rtsmb_srv_cli_connect_to_server (void);
RTSMB_STATIC int  _rtsmb_srv_cli_check_ip (void);
RTSMB_STATIC int  _rtsmb_srv_cli_handle_positive_response (void);
RTSMB_STATIC int  _rtsmb_srv_cli_handle_negotiate (void);
RTSMB_STATIC int  _rtsmb_srv_cli_handle_setup (void);
RTSMB_STATIC int  _rtsmb_srv_cli_handle_server_enum (void);
RTSMB_STATIC int  _rtsmb_srv_cli_read_server_info (PFVOID origin, PFVOID buf,
									  rtsmb_size size, PRTSMB_HEADER pHeader,
									  PRTSMB_RAP_SERVER_INFO_1 pInfo);



/**
 * rtsmb_srv_cli_connect_to - Initialize the client and start a connection to a server
 *
 *    server_name - the name of the server to which to connect
 *
 * Description:
 *    This will send a name query for the server, to find its IP address.
 *    rtsmb_srv_cli_cycle will pick up the answer and continue the connection by
 *    sending a negotiate.
 *
 *    Any previous connection established by the client is disrupted.
 *
 * See Also:
 *    rtsmb_srv_cli_cycle, rtsmb_srv_cli_shutdown
 */
void rtsmb_srv_cli_connect_to (PFCHAR server_name)
{
	tc_strncpy (rtsmb_srv_cli_server_name, server_name, RTSMB_NB_NAME_SIZE);
	rtsmb_srv_cli_server_name[RTSMB_NB_NAME_SIZE] = '\0';

	rtsmb_srv_nbns_start_query_for_name (rtsmb_srv_cli_server_name, RTSMB_NB_NAME_TYPE_SERVER);

	rtsmb_srv_cli_current_job.type = RTSMB_SRV_CLI_JOB_TYPE_QUERY_IP;
	rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_PROCESSING;
}



/**
 * rtsmb_srv_cli_shutdown - Stop the client
 *
 * Description:
 *    This will stop the client's connection to the server.
 *
 * See Also:
 *    rtsmb_srv_cli_connect_to
 */
void rtsmb_srv_cli_shutdown (void)
{
	rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_UNUSED;

	if (rtp_net_closesocket((RTP_SOCKET) rtsmb_srv_cli_socket))
	{
		RTSMB_DEBUG_OUTPUT_STR("ERROR IN CLOSESOCKET\n", RTSMB_DEBUG_TYPE_ASCII);
	}
}



/**
 * rtsmb_srv_cli_cycle - Perform internal housekeeping and check for messages
 *
 *    timeout - a cap on how much time to block on the network
 *
 * Description:
 *    This will, depending on the client's state, perform various tasks to carry
 *    out the last instruction given it.  But, the most important task this has is
 *    to wait for new messages and process them.
 *
 * Returns:
 *    a negative value on session being dead, a zero if everything is fine and the
 *    caller should continue cycling, or a positive number if we have gone to the
 *    idle state from a waiting state (the last job sent is done).
 */
int  rtsmb_srv_cli_cycle (long timeout)
{
	int r;

	switch (rtsmb_srv_cli_state)
	{
	case RTSMB_SRV_CLI_STATE_UNUSED:
	case RTSMB_SRV_CLI_STATE_DEAD:
		return -1;

	case RTSMB_SRV_CLI_STATE_IDLE:
		return 0;

	case RTSMB_SRV_CLI_STATE_READING:

		r = _rtsmb_srv_cli_continue_read (timeout);
		if (r < 0)
		{
			rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_DEAD;
			return -1;
		}
		else if (r > 0)
		{
			rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_PROCESSING;
			/* intentional non-return here.  I want to continue to where we
			   process this packet now. */
		}
		else
		{
			return 0;
		}
	}

	/* now, we must be processing something.  Let's see what we are supposed
	   to be doing.  But, first, we should just check the jobs that we do elsewhere.  */
	switch (rtsmb_srv_cli_current_job.type)
	{
	case RTSMB_SRV_CLI_JOB_TYPE_NONE:
		/* this doesn't make sense.  what are we doing?  reset our state */
		rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_IDLE;
		return (1);
		/*break; */


	case RTSMB_SRV_CLI_JOB_TYPE_QUERY_IP:
		/* Waiting on IP address.  Let's see if it's ready. */
		if (_rtsmb_srv_cli_check_ip () < 0)
		{
			rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_DEAD;
			return (-1);
		}
		else
		{
			return (0);
		}
		/*break; */
	}

	/* ok.  the rest of the jobs are now session jobs.  */
	if (rtsmb_srv_cli_have_header)
	{
		/* go straight to different job processing functions -- we have whole thing */
		switch (rtsmb_srv_cli_current_job.type)
		{
		case RTSMB_SRV_CLI_JOB_TYPE_NEGOTIATE:
			if (_rtsmb_srv_cli_handle_negotiate () < 0)
			{
				rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_DEAD;
				return -1;
			}
			return 0; /* we can't go to idle state yet, so we early exit */
			/*break; */

		case RTSMB_SRV_CLI_JOB_TYPE_SETUP:
			if (_rtsmb_srv_cli_handle_setup () < 0)
			{
				rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_DEAD;
				return -1;
			}
			/*break; */

		case RTSMB_SRV_CLI_JOB_TYPE_SERVER_ENUM:
			if (_rtsmb_srv_cli_handle_server_enum () < 0)
			{
				rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_DEAD;
				return -1;
			}
			/*break; */
		}

		rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_IDLE;
		return 1;
	}
	else
	{
		RTSMB_NBSS_HEADER header;

		/* read the header from the buffer */
		rtsmb_nbss_read_header (prtsmb_srv_ctx->client_buffer, RTSMB_NBSS_HEADER_SIZE, &header);

		rtsmb_srv_cli_have_header = TRUE;

		switch (header.type)
		{
		case RTSMB_NBSS_COM_POSITIVE_RESPONSE:
			/* nice.  the server is letting us in. */
			_rtsmb_srv_cli_handle_positive_response ();
			break;

		case RTSMB_NBSS_COM_NEGATIVE_RESPONSE:
			/* man, the server is denying us */
			rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_DEAD;
			return -1;
			/*break; */

		case RTSMB_NBSS_COM_MESSAGE:
			/* set us up to read the rest of it. */
			rtsmb_srv_cli_packet_size = (int)header.size;
			rtsmb_srv_cli_bytes_read = 0;
			rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_READING;
			break;
		}
	}

	return 0;
}


/**
 * rtsmb_srv_cli_server_enum - ask a server for a list of other servers
 *
 *    type - which servers to look for
 *    domain - which domain to get a list for
 *    answering_infos - an array of info blocks to fill out
 *    answering_infos_size - how big that array is
 *    answering_count - how many servers are in the list
 *
 * Description:
 *    This will, depending on the client's state, perform various tasks to carry
 *    out the last instruction given it.  But, the most important task this has is
 *    to wait for new messages and process them.
 *
 * Returns:
 *    a negative value on session being dead, a zero if everything is fine and the
 *    caller should continue cycling, or a positive number if we have gone to the
 *    idle state from a waiting state (the last job sent is done).
 */
int  rtsmb_srv_cli_server_enum (dword type, PFCHAR domain,
								PRTSMB_BROWSE_SERVER_INFO answering_infos,
								int answering_infos_size,
								PFINT answering_count)
{
	RTSMB_NBSS_HEADER nbss_header;
	RTSMB_HEADER smb_header;
	PRTSMB_HEADER pHeader = &smb_header;
	PFVOID buf = prtsmb_srv_ctx->client_buffer;
	PFVOID origin = prtsmb_srv_ctx->client_buffer + RTSMB_NBSS_HEADER_SIZE;
	rtsmb_size size = prtsmb_srv_ctx->small_buffer_size;
	int r;
	rtsmb_char trans_name [13];
	rtsmb_char domain_in_rtsmb [RTSMB_NB_NAME_SIZE + 1];
	rtsmb_size domain_len = domain ? (tc_strlen (domain) + 1) : 0;

	if (rtsmb_srv_cli_state != RTSMB_SRV_CLI_STATE_IDLE)
	{
		return -1;
	}

	/* write request -- nbss header, smb header, transaction, request */

	rtsmb_util_ascii_to_rtsmb ("\\PIPE\\LANMAN", trans_name, CFG_RTSMB_USER_CODEPAGE);
	if (domain)
	{
		rtsmb_util_ascii_to_rtsmb (domain, domain_in_rtsmb, CFG_RTSMB_USER_CODEPAGE);
	}

	nbss_header.type = RTSMB_NBSS_COM_MESSAGE;
	/* size: smb header (32), transaction (44), and server enum (26 + name) */
	nbss_header.size = 32 + 44 + 26 + domain_len;

	smb_header.command = SMB_COM_TRANSACTION;
	smb_header.flags = 0;
	smb_header.flags2 = 0;
	smb_header.status = 0;
	smb_header.tid = rtsmb_srv_cli_tid;
	smb_header.uid = rtsmb_srv_cli_uid;
	smb_header.pid = 0;
	smb_header.mid = 2;
	tc_memset (smb_header.security_sig, 0, 8);

	r = rtsmb_nbss_fill_header (buf, size, &nbss_header);
	ASSURE (r >= 0, -1);
	size -= (rtsmb_size)r;
	buf = PADD (buf, r);

	r = srv_cmd_fill_header (origin, buf, size, &smb_header);
	ASSURE (r >= 0, -1);
	size -= (rtsmb_size) r;
	buf = PADD (buf, r);

	/* pack our transaction stuff */
	RTSMB_PACK_BYTE ((byte) (14)); /* word count */
	RTSMB_PACK_WORD ((word) (26 + domain_len)); /* param count */
	RTSMB_PACK_WORD (0); /* data count */
	RTSMB_PACK_WORD (8); /* max param return */
	RTSMB_PACK_WORD ((word) (SMB_BUFFER_SIZE - 100)); /* max data return */
	RTSMB_PACK_BYTE (0); /* max setup return */
	RTSMB_PACK_BYTE (0); /* reserved */
	RTSMB_PACK_WORD (0); /* flags */
	RTSMB_PACK_DWORD (5000); /* timeout */
	RTSMB_PACK_WORD (0); /* reserved */
	RTSMB_PACK_WORD ((word) (26 + domain_len)); /* param count */
	RTSMB_PACK_WORD (32 + 44); /* param offset */
	RTSMB_PACK_WORD (0); /* data count */
	RTSMB_PACK_WORD (0); /* data offset */
	RTSMB_PACK_BYTE (0); /* setup count */
	RTSMB_PACK_BYTE (0); /* reserved */
	RTSMB_PACK_WORD ((word) (13 + 26 + domain_len));	/* byte count */
	RTSMB_PACK_STRING (trans_name, RTSMB_PACK_ANY);

	/* pack server enum stuff */
	RTSMB_PACK_WORD (104); /* opcode */
	if (domain)
	{
		RTSMB_PACK_ITEM ("WrLehDz", 8);	/* parameter descriptor */
	}
	else
	{
		RTSMB_PACK_ITEM ("WrLehDO", 8);	/* parameter descriptor */
	}
	RTSMB_PACK_ITEM ("B16BBDz", 8); /* return descriptor */
	RTSMB_PACK_WORD (1); /* information level */
	RTSMB_PACK_WORD ((word) (SMB_BUFFER_SIZE - 100)); /* receive size */
	RTSMB_PACK_DWORD (type);
	if (domain)
	{
		RTSMB_PACK_STRING (domain_in_rtsmb, RTSMB_PACK_ASCII);
	}

	if (rtsmb_net_write (rtsmb_srv_cli_socket,
		prtsmb_srv_ctx->client_buffer,
		PDIFF (buf, prtsmb_srv_ctx->client_buffer)) < 0)
	{
		return -1;
	}

	_rtsmb_srv_cli_start_job (RTSMB_SRV_CLI_JOB_TYPE_SERVER_ENUM);
	rtsmb_srv_cli_current_job.data.server_enum.answering_infos = answering_infos;
	rtsmb_srv_cli_current_job.data.server_enum.answering_infos_size = answering_infos_size;
	rtsmb_srv_cli_current_job.data.server_enum.answering_count = answering_count;
	return 0;
}


/**
 * _rtsmb_srv_cli_start_job - initialize job data
 *
 *    type - type of job
 *
 * Description:
 *    This will set up the data necessary for a new job.
 */
RTSMB_STATIC void _rtsmb_srv_cli_start_job (int type)
{
	rtsmb_srv_cli_current_job.type = type;
	rtsmb_srv_cli_current_job.start_time = rtp_get_system_msec ();
	rtsmb_srv_cli_state = RTSMB_SRV_CLI_STATE_READING;
	rtsmb_srv_cli_packet_size = RTSMB_NBSS_HEADER_SIZE;
	rtsmb_srv_cli_bytes_read = 0;
	rtsmb_srv_cli_have_header = FALSE;
}


/**
 * _rtsmb_srv_cli_handle_server_enum - receive server enum data
 *
 * Description:
 *    This will read each server's information from the packet and
 *    put it where we were requested to by rtsmb_srv_cli_server_enum.
 *
 * See Also:
 *    rtsmb_srv_cli_server_enum
 */
RTSMB_STATIC int  _rtsmb_srv_cli_handle_server_enum (void)
{
	RTSMB_HEADER smb_header;
	PFVOID buf = prtsmb_srv_ctx->client_buffer, tmp, data, params, end;
	PFVOID origin = prtsmb_srv_ctx->client_buffer;
	rtsmb_size size = prtsmb_srv_ctx->small_buffer_size;
	int r, i;
	word parameter_offset, data_offset, w;

	r = srv_cmd_read_header (origin, buf, size, &smb_header);
	ASSURE (r >= 0, -1);
	size -= (rtsmb_size)r;
	buf = PADD (buf, r);

	ASSURE (smb_header.status == 0, -1); /* must not have an error */

	/* read our transaction stuff */
	RTSMB_READ_SKIP (9); /* get to parameter offset */
	RTSMB_READ_WORD (&parameter_offset);
	RTSMB_READ_SKIP (4); /* get to data offset */
	RTSMB_READ_WORD (&data_offset);

	end = PADD (buf, size);

	/* go to param section */
	tmp = PADD (origin, parameter_offset);
	ASSURE (tmp <= end, -1);
	params = tmp;

	/* go to data section */
	tmp = PADD (origin, data_offset);
	ASSURE (tmp <= end, -1);
	data = tmp;

	buf = params;
	size = (rtsmb_size) PDIFF (end, buf);
	RTSMB_READ_WORD (&w); /* status */

	if (w != 0)
	{
		/* some error -- bad domain?  Well, we'll just treat it like no
		   servers came through */
		*rtsmb_srv_cli_current_job.data.server_enum.answering_count = 0;
		return 0;
	}

	RTSMB_READ_WORD (&w); /* converter */
	RTSMB_READ_WORD (&w); /* entry count */
	RTSMB_READ_WORD (&w); /* available entries */

	*rtsmb_srv_cli_current_job.data.server_enum.answering_count =
		MIN (w, rtsmb_srv_cli_current_job.data.server_enum.answering_infos_size);

	buf = data;
	size = (rtsmb_size)PDIFF (end, buf);

	/* now, get each data block */
	for (i = 0; i < *rtsmb_srv_cli_current_job.data.server_enum.answering_count; i++)
	{
		RTSMB_RAP_SERVER_INFO_1 info;
		rtsmb_char comment [RTSMB_MAX_COMMENT_SIZE + 1];

		info.info_num = i;
		info.info_total = w;
		info.comment = comment;
		info.comment_size = RTSMB_MAX_COMMENT_SIZE;
		r = _rtsmb_srv_cli_read_server_info (origin, buf, size, &smb_header, &info);
		ASSURE (r >= 0, -1);
		size -= (rtsmb_size)r;
		buf = PADD (buf, r);

		rtsmb_util_rtsmb_to_ascii (info.name, rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].name, CFG_RTSMB_USER_CODEPAGE);
		rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].version_minor = info.version_minor;
		rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].version_major = info.version_major;
		rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].type = info.type;
		rtsmb_util_rtsmb_to_ascii (info.comment, rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].comment, CFG_RTSMB_USER_CODEPAGE);

		rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].time_received = rtp_get_system_msec ();

		/* zero out stuff we don't get from this smb */
		rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].browse_version_minor = 0;
		rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].browse_version_major = 0;
		rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].signature = 0;
		rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].update_count = 0;
		rtsmb_srv_cli_current_job.data.server_enum.answering_infos[i].periodicity = 0;
	}

	return 0;
}


/**
 * _rtsmb_srv_cli_handle_setup - Handle setup response
 *
 * Description:
 *    This will set the client to idle.
 *
 * Returns:
 *    a negative value on failure or a zero if successful
 */
RTSMB_STATIC int  _rtsmb_srv_cli_handle_setup (void)
{
	/* read setup response */

	RTSMB_HEADER smb_header;
	PFVOID buf = prtsmb_srv_ctx->client_buffer;
	PFVOID origin = prtsmb_srv_ctx->client_buffer;
	rtsmb_size size = prtsmb_srv_ctx->small_buffer_size;
	int r;

	r = srv_cmd_read_header (origin, buf, size, &smb_header);
	ASSURE (r >= 0, -1);
	size -= (rtsmb_size)r;
	buf = PADD (buf, r);

	ASSURE (smb_header.status == 0, -1); /* must not have an error */

	rtsmb_srv_cli_uid = smb_header.uid;
	rtsmb_srv_cli_tid = smb_header.tid;

	/* Ok.  So, we successfully setup.  We're done */
	return 0;
}


/**
 * _rtsmb_srv_cli_handle_negotiate - Handle negotiate response
 *
 * Description:
 *    This will set up the next job, a setup packet.
 *
 * Returns:
 *    a negative value on failure or a zero if successful
 */
RTSMB_STATIC int  _rtsmb_srv_cli_handle_negotiate (void)
{
	/* read negotiate response, pack a setup packet, and send it off */

	RTSMB_NBSS_HEADER nbss_header;
	RTSMB_HEADER smb_header;
	PRTSMB_HEADER pHeader = &smb_header;
	PFVOID buf = prtsmb_srv_ctx->client_buffer;
	PFVOID origin = prtsmb_srv_ctx->client_buffer;
	rtsmb_size size = prtsmb_srv_ctx->small_buffer_size;
	int r;
	rtsmb_char share_name [RTSMB_NB_NAME_SIZE + 8];
	rtsmb_char service[] = {'I', 'P', 'C', '\0'};

	r = srv_cmd_read_header (origin, buf, size, &smb_header);
	ASSURE (r >= 0, -1);
	size -= (rtsmb_size)r;
	buf = PADD (buf, r);

	ASSURE (smb_header.status == 0, -1); /* must not have an error */


	/* Ok.  So, we successfully negotiated.  We should now send setup */

	buf = prtsmb_srv_ctx->client_buffer;
	size = prtsmb_srv_ctx->small_buffer_size;

	share_name[0] = '\\';
	share_name[1] = '\\';
	rtsmb_util_ascii_to_rtsmb (rtsmb_srv_cli_server_name, share_name + 2, CFG_RTSMB_USER_CODEPAGE);
	rtsmb_util_ascii_to_rtsmb ("\\IPC$", share_name + rtsmb_len (share_name), CFG_RTSMB_USER_CODEPAGE);

	nbss_header.type = RTSMB_NBSS_COM_MESSAGE;
	/* size: smb header (32), session setup (24), most of treecon (16), plus share string */
	nbss_header.size = 32 + 24 + 16 + rtsmb_len (share_name) + 1;

	smb_header.command = SMB_COM_SESSION_SETUP_ANDX;
	smb_header.flags = 0;
	smb_header.flags2 = 0;
	smb_header.status = 0;
	smb_header.tid = INVALID_TID;
	smb_header.uid = INVALID_UID;
	smb_header.pid = 0;
	smb_header.mid = 1;
	tc_memset (smb_header.security_sig, 0, 8);

	r = rtsmb_nbss_fill_header (buf, size, &nbss_header);
	ASSURE (r >= 0, -1);
	size -= (rtsmb_size)r;
	buf = PADD (buf, r);

	origin = buf;

	r = srv_cmd_fill_header (origin, buf, size, &smb_header);
	ASSURE (r >= 0, -1);
	size -= (rtsmb_size)r;
	buf = PADD (buf, r);

	/* pack our setup stuff */
	RTSMB_PACK_BYTE (10); /* wordcount */
	RTSMB_PACK_BYTE (SMB_COM_TREE_CONNECT_ANDX); /* next command */
	RTSMB_PACK_BYTE (0); /* reserved */
	RTSMB_PACK_WORD (32 + 24); /* offset to next command */
	RTSMB_PACK_WORD ((word) SMB_BUFFER_SIZE); /* max buffer size */
	RTSMB_PACK_WORD (1); /* max mpx */
	RTSMB_PACK_WORD (0); /* vc number */
	RTSMB_PACK_DWORD (0); /* session key */
	RTSMB_PACK_WORD (0); /* password length */
	RTSMB_PACK_DWORD (0); /* reserved */
	RTSMB_PACK_WORD (1); /* byte count */
	RTSMB_PACK_BYTE (0); /* null account name */

	/* pack our tree connect stuff */
	RTSMB_PACK_BYTE (4); /* wordcount */
	RTSMB_PACK_BYTE (SMB_COM_NONE); /* next command */
	RTSMB_PACK_BYTE (0); /* reserved */
	RTSMB_PACK_WORD (0); /* offset to next command */
	RTSMB_PACK_WORD (0); /* flags */
	RTSMB_PACK_WORD (1); /* password length */
	RTSMB_PACK_WORD ((byte) (rtsmb_len (share_name) + 1 + 4 + 1)); /* byte count */
	RTSMB_PACK_BYTE (0); /* null password */
	RTSMB_PACK_STRING (share_name, RTSMB_PACK_ANY);
	RTSMB_PACK_STRING (service, RTSMB_PACK_ASCII);

	if (rtsmb_net_write (rtsmb_srv_cli_socket,
		prtsmb_srv_ctx->client_buffer,
		PDIFF (buf, prtsmb_srv_ctx->client_buffer)) < 0)
	{
		return -1;
	}

	_rtsmb_srv_cli_start_job (RTSMB_SRV_CLI_JOB_TYPE_SETUP);

	return 0;
}


/**
 * _rtsmb_srv_cli_handle_positive_response - Handle positive session response
 *
 * Description:
 *    This will set up the next job, a negotiate packet.
 *
 * Returns:
 *    a negative value on failure or a zero if successful
 */
RTSMB_STATIC int  _rtsmb_srv_cli_handle_positive_response (void)
{
	/* pack a negotiate packet and send it off */

	RTSMB_NBSS_HEADER nbss_header;
	RTSMB_HEADER smb_header;
	PRTSMB_HEADER pHeader = &smb_header;
	PFVOID buf = prtsmb_srv_ctx->client_buffer;
	PFVOID origin = prtsmb_srv_ctx->client_buffer + RTSMB_NBSS_HEADER_SIZE;
	rtsmb_size size = prtsmb_srv_ctx->small_buffer_size;
	int r;

	nbss_header.type = RTSMB_NBSS_COM_MESSAGE;
	/* size: header (32); null, dialect byte, string; and wordcount, bytecount (3) */
	nbss_header.size = 32 + 2 + rtsmb_len (dialect_lanman) + 3;

	smb_header.command = SMB_COM_NEGOTIATE;
	smb_header.flags = 0;
	smb_header.flags2 = 0;
	smb_header.status = 0;
	smb_header.tid = INVALID_TID;
	smb_header.uid = INVALID_UID;
	smb_header.pid = 0;
	smb_header.mid = 0;
	tc_memset (smb_header.security_sig, 0, 8);

	r = rtsmb_nbss_fill_header (buf, size, &nbss_header);
	ASSURE (r >= 0, -1);
	size -= (rtsmb_size)r;
	buf = PADD (buf, r);

	r = srv_cmd_fill_header (origin, buf, size, &smb_header);
	ASSURE (r >= 0, -1);
	size -= (rtsmb_size)r;
	buf = PADD (buf, r);

	/* pack our negotiate stuff */
	RTSMB_PACK_BYTE (0);	/* wordcount */
	RTSMB_PACK_WORD ((byte) (2 + rtsmb_len (dialect_lanman))); /* bytecount - 1 null, 1 dialects byte, 1 string */
	RTSMB_PACK_BYTE (SMB_BF_DIALECT);
	RTSMB_PACK_STRING (dialect_lanman, RTSMB_PACK_ASCII);

	if (rtsmb_net_write (rtsmb_srv_cli_socket,
		prtsmb_srv_ctx->client_buffer,
		PDIFF (buf, prtsmb_srv_ctx->client_buffer)) < 0)
	{
		return -1;
	}

	_rtsmb_srv_cli_start_job (RTSMB_SRV_CLI_JOB_TYPE_NEGOTIATE);

	return 0;
}



/**
 * _rtsmb_srv_cli_check_ip - Handle new name query response and move on to next job
 *
 * Description:
 *    This will read the ip from our cache and then try to connect to the server.  If
 *    the name is not ready, it will just exit successfully.
 *
 * Returns:
 *    a negative value on failure, a zero if successful
 */
RTSMB_STATIC int  _rtsmb_srv_cli_check_ip (void)
{
	char nbs_server_name [RTSMB_NB_NAME_SIZE + 1];

	rtsmb_util_make_netbios_name (nbs_server_name, rtsmb_srv_cli_server_name, RTSMB_NB_NAME_TYPE_SERVER);

	if (rtsmb_srv_nbns_get_ip_from_cache (nbs_server_name, TRUE, rtsmb_srv_cli_server_ip))
	{
		int r;

		/* yay.  it's available. */
		/* move on to next job, connecting */
		r = _rtsmb_srv_cli_connect_to_server ();

		if (r < 0)
		{
			return -1;
		}
		else
		{
			_rtsmb_srv_cli_start_job (RTSMB_SRV_CLI_JOB_TYPE_CONNECT);

			return 0;
		}
	}

	return 0;
}



/**
 * _rtsmb_srv_cli_continue_read - Finish reading a packet
 *
 *    timeout - a cap on how long to block on the socket
 *
 * Description:
 *    This will read from the socket until it times out or gets some data.
 *
 * Returns:
 *    a negative value on failure, a zero if not enough data still, or a
 *    positive number if we have it all
 */
RTSMB_STATIC int  _rtsmb_srv_cli_continue_read (long timeout)
{
	RTP_SOCKET socket;
	int size;

	if (IS_PAST (rtsmb_srv_cli_current_job.start_time, RTSMB_NB_UCAST_RETRY_TIMEOUT))
	{
		/* Job has timed out. */
		return -1;
	}

	socket = rtsmb_srv_cli_socket;

	if (!rtsmb_netport_select_n_for_read (&socket, 1, timeout))
	{
		return 0; /* timed out.  cycle again, please. */
	}

	size = rtsmb_net_read (rtsmb_srv_cli_socket,
	                       PADD (prtsmb_srv_ctx->client_buffer, rtsmb_srv_cli_bytes_read),
	                       (dword) (prtsmb_srv_ctx->small_buffer_size - rtsmb_srv_cli_bytes_read),
	                       (dword) (rtsmb_srv_cli_packet_size - rtsmb_srv_cli_bytes_read));

	if (size < 0)
	{
		return -1;
	}

	rtsmb_srv_cli_bytes_read += size;

	if (rtsmb_srv_cli_bytes_read < rtsmb_srv_cli_packet_size)
	{
		/* still not done */
		return 0;
	}

	/* got it all! */
	return 1;
}


/**
 * _rtsmb_srv_cli_connect_to_server - Establish a session with the server
 *
 * Description:
 *    This will open a socket and send a netbios session request to the server.
 *
 * Returns:
 *    a negative value on failure or a zero if everything is fine
 */
RTSMB_STATIC int  _rtsmb_srv_cli_connect_to_server (void)
{

	if (rtp_net_socket_stream((RTP_HANDLE *) &rtsmb_srv_cli_socket) != 0)
	{
		return -1;
	}
  #ifdef RTSMB_ALLOW_SMB_OVER_TCP
	if (rtp_net_connect ((RTP_SOCKET) rtsmb_srv_cli_socket, rtsmb_srv_cli_server_ip, rtsmb_nbss_direct_port, 4) != 0)
  #else
	if (rtp_net_connect ((RTP_SOCKET) rtsmb_srv_cli_socket, rtsmb_srv_cli_server_ip, rtsmb_nbss_port, 4) != 0)
  #endif
	{
		if (rtp_net_closesocket((RTP_SOCKET) rtsmb_srv_cli_socket))
		{
			RTSMB_DEBUG_OUTPUT_STR("ERROR IN CLOSESOCKET\n", RTSMB_DEBUG_TYPE_ASCII);
		}
		return -1;
	}

	rtsmb_srv_nbss_send_session_request (rtsmb_srv_cli_socket, rtsmb_srv_cli_server_name, RTSMB_NB_NAME_TYPE_SERVER);

	return 0;
}


RTSMB_STATIC int _rtsmb_srv_cli_read_server_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo)
{
	PFVOID s, e, pdatastart, pconverter, pmax, pcomment;
	dword pointer, converter;
	int size_left;
	dword toread;

	s = buf;

	RTSMB_READ_STRING (pInfo->name, 16, RTSMB_READ_ASCII);
	buf = s;
	RTSMB_READ_SKIP (16);	/* 16 ascii characters */

	RTSMB_READ_BYTE (&pInfo->version_major);
	RTSMB_READ_BYTE (&pInfo->version_minor);
	RTSMB_READ_DWORD (&pInfo->type);

	RTSMB_READ_DWORD (&pointer);

	e = buf;

	/* now we need to grab the converter number and jump ahead to where
	   our pointer value leads */
	pdatastart = PADD (s, -26 * pInfo->info_num);
	pconverter = PADD (pdatastart, -8);

	rtsmb_read_dword_unsafe (pconverter, &converter, FALSE);
	pointer = pointer - converter;

	pmax = PADD (buf, size);
	pcomment = PADD (pdatastart, pointer);
	size_left = PDIFF (pmax, pcomment);

	/* is our pointer inside the boundaries of our packet? */
	ASSURE (size_left >= 0, -1);

	toread = MIN ((dword) size_left, pInfo->comment_size);
	RTSMB_READ_STRING (pInfo->comment, toread, RTSMB_READ_ASCII);

	return PDIFF (e, s);
}

#endif /* INCLUDE_RTSMB_SERVER */

