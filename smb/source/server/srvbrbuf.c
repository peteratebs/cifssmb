/*                                                                      */
/* SRVBRBUF.C -                                                         */
/*                                                                      */
/* EBSnet - RTSMB                                                       */
/*                                                                      */
/* Copyright EBSnet Inc. , 2003                                         */
/* All rights reserved.                                                 */
/* This code may not be redistributed in source or linkable object form */
/* without the consent of its author.                                   */
/*                                                                      */
/* Module description:                                                  */
/* Handles half the NETBIOS Browser Service announcements and elections */
/* The other half is handled by srvbrbws.c                              */
/*                                                                      */

#include "smbdefs.h"
#include "rtpwcs.h" /* _YI_ 9/24/2004 */
#if (INCLUDE_RTSMB_SERVER)

#include "srvbrbuf.h"
#include "smbpack.h"
#include "smbread.h"
#include "smbutil.h"
#include "smbbrcfg.h"
#include "srvcfg.h"
#include "srvbrws.h"
#include "srvnbns.h"
#include "smbnet.h"


#include "rtpsignl.h"


RTSMB_STATIC rtsmb_char    rtsmb_nbds_slot_browse[] = {'\\', 'M', 'A', 'I', 'L', 'S', 'L', 'O', 'T', '\\', 'B', 'R', 'O', 'W', 'S', 'E', '\0'};
/* RTSMB_STATIC rtsmb_char    rtsmb_nbds_slot_lanman[] = {'\\', 'M', 'A', 'I', 'L', 'S', 'L', 'O', 'T', '\\', 'L', 'A', 'N', 'M', 'A', 'N', '\0'};   */



int rtsmb_srv_browse_fill_host_announcement (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_HOST_ANNOUNCEMENT pBrowse)
{
	PFVOID s, e;
	int i;

	s = buf;

	RTSMB_PACK_BYTE (pBrowse->opcode);
	RTSMB_PACK_BYTE (pBrowse->update_count);
	RTSMB_PACK_DWORD (pBrowse->periodicity);
	RTSMB_PACK_STRING (pBrowse->server_name, RTSMB_PACK_ASCII);

	for (i = (int)rtsmb_len (pBrowse->server_name) + 1; i < RTSMB_NB_NAME_SIZE; i++)
	{
		RTSMB_PACK_BYTE (0);	/* null pad the string */
	}

	RTSMB_PACK_BYTE (pBrowse->version_major);
	RTSMB_PACK_BYTE (pBrowse->version_minor);
	RTSMB_PACK_DWORD (pBrowse->type);
	RTSMB_PACK_BYTE (pBrowse->browse_version_minor);
	RTSMB_PACK_BYTE (pBrowse->browse_version_major);
	RTSMB_PACK_WORD (pBrowse->signature);
	RTSMB_PACK_STRING (pBrowse->comment, RTSMB_PACK_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

int rtsmb_srv_browse_read_host_announcement (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_HOST_ANNOUNCEMENT pBrowse)
{
	PFVOID s, e;

	s = buf;

	RTSMB_READ_BYTE (&pBrowse->opcode);	/* host announcement opcode */
	RTSMB_READ_BYTE (&pBrowse->update_count);
	RTSMB_READ_DWORD (&pBrowse->periodicity);
	RTSMB_READ_STRING (pBrowse->server_name, RTSMB_NB_NAME_SIZE, RTSMB_READ_ASCII);
	RTSMB_READ_SKIP (RTSMB_NB_NAME_SIZE - rtsmb_len (pBrowse->server_name) - 1);
	RTSMB_READ_BYTE (&pBrowse->version_major);
	RTSMB_READ_BYTE (&pBrowse->version_minor);
	RTSMB_READ_DWORD (&pBrowse->type);
	RTSMB_READ_BYTE (&pBrowse->browse_version_minor);
	RTSMB_READ_BYTE (&pBrowse->browse_version_major);
	RTSMB_READ_WORD (&pBrowse->signature);
	RTSMB_READ_STRING (pBrowse->comment, pBrowse->comment_size, RTSMB_READ_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}


int rtsmb_srv_browse_read_request_election (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_REQUEST_ELECTION prequest)
{
	byte b;
	PFVOID e, s;

	s = buf;
	READ_BYTE (buf, &size, &b, -1);	/* opcode */
	ASSURE (b == RTSMB_NBDS_COM_REQUEST_ELECTION, -1);
	READ_BYTE (buf, &size, &prequest->version, -1);
	READ_DWORD (buf, &size, &prequest->criteria, FALSE, -1);
	READ_DWORD (buf, &size, &prequest->up_time, FALSE, -1);
	READ_SKIP (buf, &size, 4, -1); /* reserved */
	READ_STRING (buf, &size, prequest->server_name, RTSMB_NB_NAME_SIZE, (PFVOID)0, -1);
	e = buf;

	return PDIFF (e, s);
}

int rtsmb_srv_browse_fill_request_election (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_REQUEST_ELECTION prequest)
{
	PFVOID e, s;

	s = buf;
	PACK_BYTE (buf, &size, RTSMB_NBDS_COM_REQUEST_ELECTION, -1);	/* opcode */
	PACK_BYTE (buf, &size, prequest->version, -1);
	PACK_DWORD (buf, &size, prequest->criteria, FALSE, -1);
	PACK_DWORD (buf, &size, prequest->up_time, FALSE, -1);
	PACK_DWORD (buf, &size, 0, FALSE, -1); /* reserved */
	PACK_STRING (buf, &size, prequest->server_name, TRUE, (PFVOID)0, -1);
	e = buf;

	return PDIFF (e, s);
}

int rtsmb_srv_browse_read_become_backup (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_BECOME_BACKUP prequest)
{
	byte b;
	PFVOID e, s;

	s = buf;
	READ_BYTE (buf, &size, &b, -1);	/* opcode */
	ASSURE (b == RTSMB_NBDS_COM_BECOME_BACKUP, -1);
	READ_STRING (buf, &size, prequest->name, RTSMB_NB_NAME_SIZE, (PFVOID)0, -1);
	e = buf;

	return PDIFF (e, s);
}

int rtsmb_srv_browse_fill_become_backup (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_BECOME_BACKUP prequest)
{
	PFVOID e, s;

	s = buf;
	PACK_BYTE (buf, &size, RTSMB_NBDS_COM_BECOME_BACKUP, -1);	/* opcode */
	PACK_STRING (buf, &size, prequest->name, TRUE, (PFVOID)0, -1);
	e = buf;

	return PDIFF (e, s);
}

int rtsmb_srv_browse_fill_announcement_request (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_ANNOUNCEMENT_REQUEST prequest)
{
	PFVOID e, s;

	s = buf;
	PACK_BYTE (buf, &size, RTSMB_NBDS_COM_ANNOUNCEMENT_REQUEST, -1);	/* opcode */
	PACK_BYTE (buf, &size, 0, -1); /* undocumented, unused byte... */
	PACK_STRING (buf, &size, prequest->name, TRUE, (PFVOID)0, -1);
	e = buf;

	return PDIFF (e, s);
}


/* This function breaks the paradigm a little bit.  It actually gets the information
itself, instead of from the struct it is passed.  This is due to efficiency reasons --
I didn't want to keep lots of buffers around to cram just the names into. */
int rtsmb_srv_browse_fill_get_backup_list_response (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_BROWSE_GET_BACKUP_LIST_R presponse)
{
	PFVOID e, s, pserver_count;
/*	BBOOL dead = FALSE;   */
	int i, j;

	s = buf;

	RTSMB_PACK_BYTE (RTSMB_NBDS_COM_GET_BACKUP_LIST_RESPONSE); /* opcode */
	pserver_count = buf;
	RTSMB_PACK_BYTE (0); /* server name count */
	RTSMB_PACK_DWORD (presponse->token);

	/* go through our server list and pack the names */
	/* there's one small trick here:  we go backwards in the list.  This way,
	   we are likely to exhaust backups we've elected rather than ourselves. */

	rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

	for (i = prtsmb_srv_ctx->server_table_size - 1, j = 0; j < presponse->count && i >= 0; i--)
	{
		if (prtsmb_srv_ctx->server_table[i].type & SV_TYPE_BACKUP_BROWSER)
		{
			PFVOID r;
			rtsmb_char server_name [RTSMB_NB_NAME_SIZE + 1];

			rtsmb_util_ascii_to_rtsmb (prtsmb_srv_ctx->server_table[i].name, server_name, CFG_RTSMB_USER_CODEPAGE);
			r = rtsmb_pack_add_string (buf, &size, server_name, TRUE, (PFVOID)0);
			if (!r)
			{
/*				dead = TRUE;   */
				break;
			}

			buf = r;

			j++;
		}
	}

	rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);

	e = buf;

	rtsmb_pack_add_byte_unsafe (pserver_count, (byte) (j & 0xFF));

	return PDIFF (e, s);
}





int rtsmb_srv_browse_fill_whole_announcement (BBOOL domain, BBOOL shutdown)
{
	int r;
	rtsmb_size size = 0;
	PFVOID buf, ds, de, hs, smb_start;
	RTSMB_HEADER header;
	RTSMB_TRANSACTION trans;
	RTSMB_NBDS_HEADER nbs;
	RTSMB_NBDS_HOST_ANNOUNCEMENT host;
	word setup_words [3] = {1, 1, 2};
	rtsmb_char comment [RTSMB_MAX_COMMENT_SIZE + 1];

	header.command = SMB_COM_TRANSACTION;
	header.flags = 0;
	header.flags2 = 0;
	header.status = 0;
	header.tid = 0;
	header.uid = 0;
	header.pid = 0;
	header.mid = 0;
	tc_memset (header.security_sig, 0, 8);

	buf = PADD (prtsmb_browse_ctx->buffer, RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE);

	/* data start */
	ds = buf;
	/* pack mailslot name */
	size = RTSMB_NB_MAX_DATAGRAM_SIZE - (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE);
	PACK_STRING (buf, &size, rtsmb_nbds_slot_browse, TRUE, (PFVOID)0, -1);

	/* host start */
	hs = buf;

	host.update_count = 0;
	host.periodicity = rtsmb_srv_browse_get_announcement_interval ();
	rtsmb_util_ascii_to_rtsmb (rtsmb_srv_nbns_get_our_name (), host.server_name, CFG_RTSMB_USER_CODEPAGE);
	host.version_major = 4;
	host.version_minor = 0;
	host.type = shutdown ? 0 : rtsmb_srv_browse_get_server_type ();
	host.browse_version_major = RTSMB_NBDS_BROWSER_VERSION_MAJOR;
	host.browse_version_minor = RTSMB_NBDS_BROWSER_VERSION_MINOR;
	host.signature = 0xaa55;

	rtsmb_util_ascii_to_rtsmb (CFG_RTSMB_DEFAULT_COMMENT, comment, CFG_RTSMB_USER_CODEPAGE);
	host.comment = comment;

	if (domain)
	{
		tc_strcpy (nbs.destination_name, RTSMB_NB_MASTER_BROWSER_NAME);
		host.opcode = RTSMB_NBDS_COM_DOMAIN_ANNOUNCEMENT;
		host.periodicity = RTSMB_SRV_BROWSE_DOMAIN_ANNOUNCE_DELAY;
		rtsmb_util_ascii_to_rtsmb (rtsmb_srv_nbns_get_our_group (), host.server_name, CFG_RTSMB_USER_CODEPAGE);
		rtsmb_util_ascii_to_rtsmb (rtsmb_srv_nbns_get_our_name (), comment, CFG_RTSMB_USER_CODEPAGE);
		host.type |= SV_TYPE_DOMAIN_ENUM;
	}
	else if (rtsmb_srv_browse_get_role () == RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER)
	{
		rtsmb_util_make_netbios_name (nbs.destination_name, rtsmb_srv_nbns_get_our_group (), RTSMB_NB_NAME_TYPE_ELECTION_SERVICE);
		host.opcode = RTSMB_NBDS_COM_LOCAL_MASTER_ANNOUNCEMENT;
	}
	else
	{
		rtsmb_util_make_netbios_name (nbs.destination_name, rtsmb_srv_nbns_get_our_group (), RTSMB_NB_NAME_TYPE_MASTER_BROWSER);
		host.opcode = RTSMB_NBDS_COM_HOST_ANNOUNCEMENT;
	}

	r = rtsmb_srv_browse_fill_host_announcement (prtsmb_browse_ctx->buffer, buf, size, &header, &host);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);

	de = buf;

	size = RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE;

	/* now the datagram header */
	nbs.type          = RTSMB_NBDS_DIRECT_GROUP_DATAGRAM;
	nbs.flags         = 0x02;
	nbs.id            = rtsmb_nbds_get_next_datagram_id ();
	tc_memcpy (nbs.source_ip, rtsmb_net_get_host_ip (), 4);
	nbs.source_port   = rtsmb_nbds_port;
	nbs.size          = (word) (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE + PDIFF (de, ds));
	nbs.packet_offset = 0;

	rtsmb_util_make_netbios_name (nbs.source_name, rtsmb_srv_nbns_get_our_name (), RTSMB_NB_NAME_TYPE_SERVER);
	/* this is established earlier */
/*	rtsmb_util_make_netbios_name (nbs.destination_name, rtsmb_nbds_announcement_group, RTSMB_NB_NAME_TYPE_MASTER_BROWSER);   */

	r = rtsmb_nbds_fill_header (prtsmb_browse_ctx->buffer, prtsmb_browse_ctx->buffer, size, &nbs);
	ASSURE (r >= 0, -1);
	buf = PADD (prtsmb_browse_ctx->buffer, r);
	size -= (rtsmb_size)r;

	smb_start = buf;

	r = rtsmb_nbds_fill_smb_header (smb_start, buf, size, &header);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	size -= (rtsmb_size)r;

	trans.data_count          = (word) PDIFF (de, hs);
	trans.data_offset         = (word) PDIFF (hs, smb_start);
	trans.flags               = 0;
	trans.max_data_count      = 0;
	trans.max_parameter_count = 0;
	trans.max_setup_count     = 0;
	trans.parameter_count     = 0;
	trans.parameter_offset    = 0;
	trans.setup_size          = 3;
	trans.setup               = setup_words;
	trans.timeout             = 0;
	trans.byte_count          = (word) PDIFF (de, ds);

	r = rtsmb_nbds_fill_transaction (smb_start, buf, size, &header, &trans);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	size -= (rtsmb_size)r;

	return PDIFF (de, prtsmb_browse_ctx->buffer);
}

int rtsmb_srv_browse_fill_whole_request_election (void)
{
	int r;
	rtsmb_size size = 0;
	PFVOID buf, ds, de, hs, smb_start;
	RTSMB_HEADER header;
	RTSMB_TRANSACTION trans;
	RTSMB_NBDS_HEADER nbs;
	RTSMB_NBDS_REQUEST_ELECTION request;
	word setup_words [3] = {1, 1, 2};

	header.command = SMB_COM_TRANSACTION;
	header.flags = 0;
	header.flags2 = 0;
	header.status = 0;
	header.tid = 0;
	header.uid = 0;
	header.pid = 0;
	header.mid = 0;
	tc_memset (header.security_sig, 0, 8);

	buf = PADD (prtsmb_browse_ctx->buffer, RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE);

	/* data start */
	ds = buf;
	/* pack mailslot name */
	size = RTSMB_NB_MAX_DATAGRAM_SIZE - (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE);
	PACK_STRING (buf, &size, rtsmb_nbds_slot_browse, TRUE, (PFVOID)0, -1);

	/* list start */
	hs = buf;

	request.version = RTSMB_NBDS_ELECTION_VERSION;
	request.criteria = rtsmb_srv_browse_get_election_criteria ();
	request.up_time = 0; /* no reliable way to ascertain this */
	rtsmb_util_ascii_to_rtsmb (rtsmb_srv_nbns_get_our_name (), request.server_name, CFG_RTSMB_USER_CODEPAGE);

	r = rtsmb_srv_browse_fill_request_election (prtsmb_browse_ctx->buffer, buf, size, &header, &request);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);

	de = buf;

	size = RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE;

	/* now the datagram header */
	nbs.type = RTSMB_NBDS_DIRECT_GROUP_DATAGRAM;
	nbs.flags = 0x02;
	nbs.id = rtsmb_nbds_get_next_datagram_id ();
	tc_memcpy (nbs.source_ip, rtsmb_net_get_host_ip (), 4);
	nbs.source_port = rtsmb_nbds_port;
	nbs.size = (word) (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE + PDIFF (de, ds));
	nbs.packet_offset = 0;

	rtsmb_util_make_netbios_name (nbs.source_name, rtsmb_srv_nbns_get_our_name (), RTSMB_NB_NAME_TYPE_WORKSTATION);
	rtsmb_util_make_netbios_name (nbs.destination_name, rtsmb_srv_nbns_get_our_group (), RTSMB_NB_NAME_TYPE_ELECTION_SERVICE);

	r = rtsmb_nbds_fill_header (prtsmb_browse_ctx->buffer, prtsmb_browse_ctx->buffer, size, &nbs);
	ASSURE (r >= 0, -1);
	buf = PADD (prtsmb_browse_ctx->buffer, r);
	size -= (rtsmb_size)r;

	smb_start = buf;

	r = rtsmb_nbds_fill_smb_header (smb_start, buf, size, &header);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	size -= (rtsmb_size)r;

	trans.data_count          = (word) PDIFF (de, hs);
	trans.data_offset         = (word) PDIFF (hs, smb_start);
	trans.flags               = 0;
	trans.max_data_count      = 0;
	trans.max_parameter_count = 0;
	trans.max_setup_count     = 0;
	trans.parameter_count     = 0;
	trans.parameter_offset    = 0;
	trans.setup_size          = 3;
	trans.setup               = setup_words;
	trans.timeout             = 0;
	trans.byte_count          = (word) PDIFF (de, ds);

	r = rtsmb_nbds_fill_transaction (smb_start, buf, size, &header, &trans);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	size -= (rtsmb_size)r;

	return PDIFF (de, prtsmb_browse_ctx->buffer);
}

int rtsmb_srv_browse_fill_whole_announcement_request (void)
{
	int r;
	rtsmb_size size = 0;
	PFVOID buf, ds, de, hs, smb_start;
	RTSMB_HEADER header;
	RTSMB_TRANSACTION trans;
	RTSMB_NBDS_ANNOUNCEMENT_REQUEST request;
	RTSMB_NBDS_HEADER nbs;
	word setup_words [3] = {1, 1, 2};

	header.command = SMB_COM_TRANSACTION;
	header.flags = 0;
	header.flags2 = 0;
	header.status = 0;
	header.tid = 0;
	header.uid = 0;
	header.pid = 0;
	header.mid = 0;
	tc_memset (header.security_sig, 0, 8);

	buf = PADD (prtsmb_browse_ctx->buffer, RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE);

	/* data start */
	ds = buf;
	/* pack mailslot name */
	size = RTSMB_NB_MAX_DATAGRAM_SIZE - (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE);
	PACK_STRING (buf, &size, rtsmb_nbds_slot_browse, TRUE, (PFVOID)0, -1);

	/* list start */
	hs = buf;

	rtsmb_util_ascii_to_rtsmb (rtsmb_srv_nbns_get_our_name (), request.name, CFG_RTSMB_USER_CODEPAGE);

	r = rtsmb_srv_browse_fill_announcement_request (prtsmb_browse_ctx->buffer, buf, size, &header, &request);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);

	de = buf;

	size = RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE;

	/* now the datagram header */
	nbs.type = RTSMB_NBDS_DIRECT_GROUP_DATAGRAM;
	nbs.flags = 0x02;
	nbs.id = rtsmb_nbds_get_next_datagram_id ();
	tc_memcpy (nbs.source_ip, rtsmb_net_get_host_ip (), 4);
	nbs.source_port = rtsmb_nbds_port;
	nbs.size = (word) (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE + PDIFF (de, ds));
	nbs.packet_offset = 0;

	rtsmb_util_make_netbios_name (nbs.source_name, rtsmb_srv_nbns_get_our_name (), RTSMB_NB_NAME_TYPE_SERVER);
	rtsmb_util_make_netbios_name (nbs.destination_name, rtsmb_srv_nbns_get_our_group (), RTSMB_NB_NAME_TYPE_SERVER);

	r = rtsmb_nbds_fill_header (prtsmb_browse_ctx->buffer, prtsmb_browse_ctx->buffer, size, &nbs);
	ASSURE (r >= 0, -1);
	buf = PADD (prtsmb_browse_ctx->buffer, r);
	size -= (rtsmb_size)r;

	smb_start = buf;

	r = rtsmb_nbds_fill_smb_header (smb_start, buf, size, &header);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	size -= (rtsmb_size)r;

	trans.data_count          = (word) PDIFF (de, hs);
	trans.data_offset         = (word) PDIFF (hs, smb_start);
	trans.flags               = 0;
	trans.max_data_count      = 0;
	trans.max_parameter_count = 0;
	trans.max_setup_count     = 0;
	trans.parameter_count     = 0;
	trans.parameter_offset    = 0;
	trans.setup_size          = 3;
	trans.setup               = setup_words;
	trans.timeout             = 0;
	trans.byte_count          = (word) PDIFF (de, ds);

	r = rtsmb_nbds_fill_transaction (smb_start, buf, size, &header, &trans);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	size -= (rtsmb_size)r;

	return PDIFF (de, prtsmb_browse_ctx->buffer);
}

int rtsmb_srv_browse_fill_whole_get_backup_list_response (int count, dword token)
{
	int r;
	rtsmb_size size = 0;
	PFVOID buf, ds, de, hs, smb_start;
	RTSMB_HEADER header;
	RTSMB_TRANSACTION trans;
	RTSMB_BROWSE_GET_BACKUP_LIST_R response;
	RTSMB_NBDS_HEADER nbs;
	word setup_words [3] = {1, 1, 2};

	header.command = SMB_COM_TRANSACTION;
	header.flags = 0;
	header.flags2 = 0;
	header.status = 0;
	header.tid = 0;
	header.uid = 0;
	header.pid = 0;
	header.mid = 0;
	tc_memset (header.security_sig, 0, 8);

	buf = PADD (prtsmb_browse_ctx->buffer, RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE);

	/* data start */
	ds = buf;
	/* pack mailslot name -- spec says lanman, reality says browse */
	size = RTSMB_NB_MAX_DATAGRAM_SIZE - (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE);
	PACK_STRING (buf, &size, rtsmb_nbds_slot_browse, TRUE, (PFVOID)0, -1);

	/* list start */
	hs = buf;

	response.count = (byte)count;
	response.token = token;

	r = rtsmb_srv_browse_fill_get_backup_list_response (prtsmb_browse_ctx->buffer, buf, size, &header, &response);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);

	de = buf;

	size = RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE;

	/* now the datagram header */
	nbs.type = RTSMB_NBDS_DIRECT_GROUP_DATAGRAM;
	nbs.flags = 0x02;
	nbs.id = rtsmb_nbds_get_next_datagram_id ();
	tc_memcpy (nbs.source_ip, rtsmb_net_get_host_ip (), 4);
	nbs.source_port = rtsmb_nbds_port;
	nbs.size = (word) (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE + PDIFF (de, ds));
	nbs.packet_offset = 0;

	rtsmb_util_make_netbios_name (nbs.source_name, rtsmb_srv_nbns_get_our_name (), RTSMB_NB_NAME_TYPE_SERVER);
	tc_strcpy (nbs.destination_name, rtsmb_nbds_get_last_remote_name ());

	r = rtsmb_nbds_fill_header (prtsmb_browse_ctx->buffer, prtsmb_browse_ctx->buffer, size, &nbs);
	ASSURE (r >= 0, -1);
	buf = PADD (prtsmb_browse_ctx->buffer, r);
	size -= (rtsmb_size)r;

	smb_start = buf;

	r = rtsmb_nbds_fill_smb_header (smb_start, buf, size, &header);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	size -= (rtsmb_size)r;

	trans.data_count          = (word) PDIFF (de, hs);
	trans.data_offset         = (word) PDIFF (hs, smb_start);
	trans.flags               = 0;
	trans.max_data_count      = 0;
	trans.max_parameter_count = 0;
	trans.max_setup_count     = 0;
	trans.parameter_count     = 0;
	trans.parameter_offset    = 0;
	trans.setup_size          = 3;
	trans.setup               = setup_words;
	trans.timeout             = 0;
	trans.byte_count          = (word) PDIFF (de, ds);

	r = rtsmb_nbds_fill_transaction (smb_start, buf, size, &header, &trans);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	size -= (rtsmb_size)r;

	return PDIFF (de, prtsmb_browse_ctx->buffer);
}

int rtsmb_srv_browse_fill_whole_become_backup (PFCHAR name)
{
	int r;
	rtsmb_size size = 0;
	PFVOID buf, ds, de, hs, smb_start;
	RTSMB_HEADER header;
	RTSMB_TRANSACTION trans;
	RTSMB_NBDS_BECOME_BACKUP command;
	RTSMB_NBDS_HEADER nbs;
	word setup_words [3] = {1, 1, 2};

	header.command = SMB_COM_TRANSACTION;
	header.flags = 0;
	header.flags2 = 0;
	header.status = 0;
	header.tid = 0;
	header.uid = 0;
	header.pid = 0;
	header.mid = 0;
	tc_memset (header.security_sig, 0, 8);

	buf = PADD (prtsmb_browse_ctx->buffer, RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE);

	/* data start */
	ds = buf;
	/* pack mailslot name -- spec says lanman, reality says browse */
	size = RTSMB_NB_MAX_DATAGRAM_SIZE - (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE);
	PACK_STRING (buf, &size, rtsmb_nbds_slot_browse, TRUE, (PFVOID)0, -1);

	/* list start */
	hs = buf;

	rtsmb_util_ascii_to_rtsmb (name, command.name, CFG_RTSMB_USER_CODEPAGE);

	r = rtsmb_srv_browse_fill_become_backup (prtsmb_browse_ctx->buffer, buf, size, &header, &command);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);

	de = buf;

	size = RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE;

	/* now the datagram header */
	nbs.type = RTSMB_NBDS_DIRECT_GROUP_DATAGRAM;
	nbs.flags = 0x02;
	nbs.id = rtsmb_nbds_get_next_datagram_id ();
	tc_memcpy (nbs.source_ip, rtsmb_net_get_host_ip (), 4);
	nbs.source_port = rtsmb_nbds_port;
	nbs.size = (word) (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE + PDIFF (de, ds));
	nbs.packet_offset = 0;

	rtsmb_util_make_netbios_name (nbs.source_name, rtsmb_srv_nbns_get_our_name (), RTSMB_NB_NAME_TYPE_SERVER);
	tc_strcpy (nbs.destination_name, rtsmb_nbds_get_last_remote_name ());

	r = rtsmb_nbds_fill_header (prtsmb_browse_ctx->buffer, prtsmb_browse_ctx->buffer, size, &nbs);
	ASSURE (r >= 0, -1);
	buf = PADD (prtsmb_browse_ctx->buffer, r);
	size -= (rtsmb_size)r;

	smb_start = buf;

	r = rtsmb_nbds_fill_smb_header (smb_start, buf, size, &header);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	size -= (rtsmb_size)r;

	trans.data_count          = (word) PDIFF (de, hs);
	trans.data_offset         = (word) PDIFF (hs, smb_start);
	trans.flags               = 0;
	trans.max_data_count      = 0;
	trans.max_parameter_count = 0;
	trans.max_setup_count     = 0;
	trans.parameter_count     = 0;
	trans.parameter_offset    = 0;
	trans.setup_size          = 3;
	trans.setup               = setup_words;
	trans.timeout             = 0;
	trans.byte_count          = (word) PDIFF (de, ds);

	r = rtsmb_nbds_fill_transaction (smb_start, buf, size, &header, &trans);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	size -= (rtsmb_size)r;

	return PDIFF (de, prtsmb_browse_ctx->buffer);
}

#endif /* INCLUDE_RTSMB_SERVER */
