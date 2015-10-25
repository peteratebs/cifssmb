//
// SRVANS.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Responds to SMB commands with the packed structure
//

#include "smbdefs.h"
#include "rtpwcs.h" /* _YI_ 9/24/2004 */

#if (INCLUDE_RTSMB_SERVER)


#include "srvans.h"
#include "smbpack.h"
#include "smbutil.h"
#include "smbnb.h"

/* --------------------------------------------------- /
 * Fills SMB Data Section with no information, usually
 * means the command only needs to respond success or
 * error.  Only called from this module
 *
 * Returns: Size of Data Section
 * -------------------------------------------------- */
RTSMB_STATIC
int srv_cmd_fill_no_op (PFVOID buf, rtsmb_size size)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (0);	/* wordcount */
	RTSMB_PACK_WORD (0);	/* bytecount */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Header Section with information passed in
 * with pHeader, called by each possible command
 * response
 *
 * Returns: Size of Header Section
 * -------------------------------------------------- */
int srv_cmd_fill_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (0xFF);
	RTSMB_PACK_ITEM ("SMB", 3);
	RTSMB_PACK_BYTE (pHeader->command);
	RTSMB_PACK_DWORD (pHeader->status);
	RTSMB_PACK_BYTE (pHeader->flags);
	RTSMB_PACK_WORD (pHeader->flags2);

	/* high part of pid */
	RTSMB_PACK_WORD ((word) (pHeader->pid >> 16));

	/* 8 bytes of security signature */
	RTSMB_PACK_ITEM (pHeader->security_sig, 8);

	/* 2 bytes of padding */
	RTSMB_PACK_WORD (0);

	RTSMB_PACK_WORD (pHeader->tid);
	RTSMB_PACK_WORD ((word) pHeader->pid);
	RTSMB_PACK_WORD (pHeader->uid);
	RTSMB_PACK_WORD (pHeader->mid);

	e = buf;

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section when protocol negotiation
 * has not been able to agree on a dialect
 * ASSOCIATED COMMANDS: SMB_COM_NEGOTIATE
 *
 * Returns: Size of Data Section
 * -------------------------------------------------- */
int srv_cmd_fill_negotiate_bad (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE_BAD_R pNegotiateR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (1);
	RTSMB_PACK_WORD (pNegotiateR->dialect_index);
	RTSMB_PACK_WORD (0);

	e = buf;

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with one NEGOTIATE response
 * only used when client is not NT-based
 * ASSOCIATED COMMANDS: SMB_COM_NEGOTIATE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_negotiate_pre_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE_R pNegotiateR)
{
	PFVOID s, e;
	PFVOID bs;	/* byte start */
	PFVOID pbytecount;
	word w;

	s = buf;

	RTSMB_PACK_BYTE (13);	/* wordcount */
	RTSMB_PACK_WORD (pNegotiateR->dialect_index);
	w = pNegotiateR->security_mode;
	RTSMB_PACK_WORD (w);
	w = (word) (pNegotiateR->max_buffer_size & 0xFFFF);	/* we only use lower bits for this protocol */
	RTSMB_PACK_WORD (w);
	RTSMB_PACK_WORD (pNegotiateR->max_mpx_count);
	RTSMB_PACK_WORD (pNegotiateR->max_vcs);

	/* raw mode is only supported for the older protocol if the buffer size is
	 65535.  If we say we support it, we have to support that much. */
	w = (pNegotiateR->max_raw_size >= 65535) ? 3 : 0;
	RTSMB_PACK_WORD (w);
	RTSMB_PACK_DWORD (pNegotiateR->session_id);
	RTSMB_PACK_WORD (0);	/* time, not used now */
	RTSMB_PACK_WORD (0);	/* date, not used now */
	RTSMB_PACK_WORD (pNegotiateR->time_zone);
	RTSMB_PACK_WORD (pNegotiateR->challenge_size);
	RTSMB_PACK_WORD (0);	/* reserved */
	pbytecount = buf;	/* we're going to revisit this variable */
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;	/* measure start of data section */

	RTSMB_PACK_ITEM (pNegotiateR->challenge, pNegotiateR->challenge_size);
	if (pNegotiateR->valid_domain)
	{
		RTSMB_PACK_STRING (pNegotiateR->domain, RTSMB_PACK_ASCII);
	}

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return PDIFF (e, s);
}


/* --------------------------------------------------- /
 * Fills SMB Data Section with one NEGOTIATE response
 * only used when client is NT-based
 * ASSOCIATED COMMANDS: SMB_COM_NEGOTIATE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_negotiate_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE_R pNegotiateR)
{
	PFVOID s, e;
	PFVOID bs;	/* byte start */
	PFVOID pbytecount;
	byte b;

	s = buf;

	RTSMB_PACK_BYTE (17);	/* wordcount */
	RTSMB_PACK_WORD (pNegotiateR->dialect_index);
	RTSMB_PACK_BYTE (pNegotiateR->security_mode);
	RTSMB_PACK_WORD (pNegotiateR->max_mpx_count);
	RTSMB_PACK_WORD (pNegotiateR->max_vcs);
	RTSMB_PACK_DWORD (pNegotiateR->max_buffer_size);
	RTSMB_PACK_DWORD (pNegotiateR->max_raw_size);
	RTSMB_PACK_DWORD (pNegotiateR->session_id);
	RTSMB_PACK_DWORD (pNegotiateR->capabilities);
	RTSMB_PACK_DWORD (pNegotiateR->time_low);
	RTSMB_PACK_DWORD (pNegotiateR->time_high);
	RTSMB_PACK_WORD (pNegotiateR->time_zone);
	b = pNegotiateR->challenge_size;
	RTSMB_PACK_BYTE (b);
	pbytecount = buf;	/* we're going to revisit this variable */
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;	/* measure start of data section */

	if (pNegotiateR->valid_guid)
		RTSMB_PACK_ITEM (pNegotiateR->guid, 16);

	RTSMB_PACK_ITEM (pNegotiateR->challenge, pNegotiateR->challenge_size);
	if (pNegotiateR->valid_domain)
		RTSMB_PACK_STRING_D (pNegotiateR->domain, RTSMB_PACK_UNICODE);

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with Echo response
 * ASSOCIATED COMMANDS: SMB_COM_ECHO
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_echo (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_ECHO_R pEchoR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */
	RTSMB_PACK_WORD (pEchoR->sequence_number);
	RTSMB_PACK_WORD (pEchoR->data_size);	/* byte count */
	RTSMB_PACK_ITEM (pEchoR->data, pEchoR->data_size);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with Session Setup response
 * when client is not NT-based
 * ASSOCIATED COMMANDS: SMB_COM_SESSION_SETUP_ANDX
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_session_setup_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_R pSessionR)
{
	PFVOID s, bs, e, poffset, pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (3);	/* word count */
	RTSMB_PACK_BYTE (pSessionR->next_command);
	RTSMB_PACK_BYTE (0);	/* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);	/* offset to next and_x */
	RTSMB_PACK_WORD ((word) ((pSessionR->guest_logon) ? 1 : 0));
	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;	/* measure start of data section */

	if (pSessionR->srv_native_os)
	{
		RTSMB_PACK_STRING (pSessionR->srv_native_os, RTSMB_PACK_ANY);
		if (pSessionR->srv_native_lan_man)
		{
			RTSMB_PACK_STRING (pSessionR->srv_native_lan_man, RTSMB_PACK_ANY);
			if (pSessionR->srv_primary_domain)
			{
				RTSMB_PACK_STRING (pSessionR->srv_primary_domain, RTSMB_PACK_ANY);
			}
		}
	}

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	if (pSessionR->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with Logoff response
 * ASSOCIATED COMMANDS: SMB_COM_LOGOFF_ANDX
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_logoff_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOGOFF_AND_X_R pLogoffR)
{
	PFVOID s, e, poffset;

	s = buf;

	RTSMB_PACK_BYTE (2);	/* word count */
	RTSMB_PACK_BYTE (pLogoffR->next_command);
	RTSMB_PACK_BYTE (0);	/* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);	/* offset to next and_x */
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	if (pLogoffR->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with tree connect response   /
 * if the dialect is older than lanman				   /
 * ASSOCIATED COMMANDS: SMB_COM_TREE_CONNECT_ANDX      /
 *													   /
 * Returns: Size of data on success, -1 if not		   /
 * enough space										   /
 * -------------------------------------------------- */
int srv_cmd_fill_tree_connect_and_x_pre_lanman (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_AND_X_R pTreeR)
{
	PFVOID s, bs, e, poffset, pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (2);	/* word count */
	RTSMB_PACK_BYTE (pTreeR->next_command);
	RTSMB_PACK_BYTE (0);	/* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);	/* offset to next and_x */
	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;	/* measure start of data section */

	RTSMB_PACK_STRING (pTreeR->service, RTSMB_PACK_ASCII);
	if (pTreeR->native_fs)
	{
		RTSMB_PACK_STRING (pTreeR->native_fs, RTSMB_PACK_ANY);
	}

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	if (pTreeR->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with tree connect response
 * if the dialect is at least lanman
 * ASSOCIATED COMMANDS: SMB_COM_TREE_CONNECT_ANDX
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_tree_connect_and_x_lanman (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_AND_X_R pTreeR)
{
	PFVOID s, bs, e, poffset, pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (3);	/* word count */
	RTSMB_PACK_BYTE (pTreeR->next_command);
	RTSMB_PACK_BYTE (0);	/* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);	/* offset to next and_x */
	RTSMB_PACK_WORD (pTreeR->optional_support);
	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;	/* measure start of data section */

	RTSMB_PACK_STRING (pTreeR->service, RTSMB_PACK_ASCII);
	if (pTreeR->native_fs)
	{
		RTSMB_PACK_STRING (pTreeR->native_fs, RTSMB_PACK_ANY);
	}

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	if (pTreeR->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with read andx response
 * ASSOCIATED COMMANDS: SMB_COM_READ_ANDX
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_read_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X_R pReadR)
{
	PFVOID s, bs, e, poffset, pdataoffset;

	s = buf;

	RTSMB_PACK_BYTE (12);	/* word count */
	RTSMB_PACK_BYTE (pReadR->next_command);
	RTSMB_PACK_BYTE (0);	/* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);	/* offset to next and_x */
	RTSMB_PACK_WORD ((word) -1);	/* spec says so; reserved */
	RTSMB_PACK_WORD (0);	/* data compaction mode */
	RTSMB_PACK_WORD (0);	/* reserved */
	RTSMB_PACK_WORD ((word) pReadR->data_size);	/* low 16 bits of data_size */
	pdataoffset = buf;
	RTSMB_PACK_WORD (0);	/* offset to data */
	RTSMB_PACK_WORD ((word) (pReadR->data_size >> 16));	/* high 16 bits of data_size */
	RTSMB_PACK_DWORD (0);	/* reserved */
	RTSMB_PACK_DWORD (0);	/* reserved */
	RTSMB_PACK_WORD ((word) pReadR->data_size);	/* byte count */

	bs = buf;

	RTSMB_PACK_ITEM (pReadR->data, pReadR->data_size);

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pdataoffset, (word) PDIFF (bs, origin), FALSE);

	if (pReadR->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with write andx response
 * ASSOCIATED COMMANDS: SMB_COM_WRITE_ANDX
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_write_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_X_R pWriteR)
{
	PFVOID s, e, poffset;

	s = buf;

	RTSMB_PACK_BYTE (6);	/* word count */
	RTSMB_PACK_BYTE (pWriteR->next_command);
	RTSMB_PACK_BYTE (0);	/* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);	/* offset to next and_x */

	RTSMB_PACK_WORD (pWriteR->count);
	RTSMB_PACK_WORD (0);	/* remaining; reserved */
	RTSMB_PACK_DWORD (0);	/* reserved */

	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	if (pWriteR->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with open andx response
 * ASSOCIATED COMMANDS: SMB_COM_OPEN_ANDX
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_open_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_AND_X_R pOpenR)
{
	PFVOID s, e, poffset;

	s = buf;

	RTSMB_PACK_BYTE (15);	/* word count */
	RTSMB_PACK_BYTE (pOpenR->next_command);
	RTSMB_PACK_BYTE (0);	/* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);	/* offset to next and_x */

	RTSMB_PACK_WORD (pOpenR->fid);
	RTSMB_PACK_WORD (pOpenR->file_attributes);
	RTSMB_PACK_DWORD (pOpenR->last_write_time);
	RTSMB_PACK_DWORD (pOpenR->file_size);
	RTSMB_PACK_WORD (pOpenR->granted_access);
	RTSMB_PACK_WORD (pOpenR->file_type);
	RTSMB_PACK_WORD (pOpenR->device_state);
	RTSMB_PACK_WORD (pOpenR->action);
	RTSMB_PACK_DWORD (pOpenR->server_fid);
	RTSMB_PACK_WORD (0);	/* reserved */

	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	if (pOpenR->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with tree disconnect
 * response, which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_TREE_DISCONNECT
 *
 * Returns: Size of data on success, -1 if not
 * enough space										   /
 * -------------------------------------------------- */
int srv_cmd_fill_tree_disconnect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
		return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with create temporary
 * response
 * ASSOCIATED COMMANDS: SMB_COM_CREATE_TEMPORARY
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_create_temporary (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE_TEMPORARY_R pTempR)
{
	PFVOID s, e;
	PFVOID bs;	/* byte start */
	PFVOID pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* wordcount */
	RTSMB_PACK_WORD (pTempR->fid);

	pbytecount = buf;	/* we're going to revisit this variable */
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;	/* measure start of data section */

	RTSMB_PACK_BYTE (SMB_BF_ASCII);
	RTSMB_PACK_STRING (pTempR->filename, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with seek response
 * ASSOCIATED COMMANDS: SMB_COM_SEEK
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_seek (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEEK_R pSeekR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (2);	/* word count */
	RTSMB_PACK_DWORD (pSeekR->offset);
	RTSMB_PACK_WORD (0);	/* bytecount */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with flush response
 * which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_FLUSH
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_flush (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with close response
 * which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_CLOSE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with close print file
 * response, which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_CLOSE_PRINT_FILE
 *
 * Returns: Size of data on success, -1 if
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_close_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with delete response
 * which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_DELETE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_delete (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with rename response
 * which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_RENAME
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_rename (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with move response
 * ASSOCIATED COMMANDS: SMB_COM_MOVE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_move (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_MOVE_R pMoveR)
{
	PFVOID s, bs, e;
	PFVOID pbytecount;
	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */
	RTSMB_PACK_WORD (pMoveR->count);

	pbytecount = buf;	/* we'll come back to byte count */
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;	/* measure start of data section */

	if (pMoveR->error_filename)
	{
		RTSMB_PACK_BYTE (SMB_BF_ASCII);
		RTSMB_PACK_STRING (pMoveR->error_filename, RTSMB_PACK_ANY);
	}
    *((word *)pbytecount ) = SMB_HTOIW ((word)PDIFF(buf,bs));
	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with copy response
 * ASSOCIATED COMMANDS: SMB_COM_COPY
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_copy (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_COPY_R pCopyR)
{
	PFVOID s, bs, e;
	PFVOID pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */
	RTSMB_PACK_WORD (pCopyR->count);

	pbytecount = buf;	/* we'll come back to byte count */
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;	/* measure start of data section */

	if (pCopyR->error_filename)
	{
		RTSMB_PACK_BYTE (SMB_BF_ASCII);
		RTSMB_PACK_STRING (pCopyR->error_filename, RTSMB_PACK_ANY);
	}
    *((word *)pbytecount ) = SMB_HTOIW ((word)PDIFF(buf,bs));
	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with delete directory
 * response, which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_DELETE_DIRECTORY
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_delete_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with check directory
 * response, which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_CHECK_DIRECTORY
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_check_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with create directory
 * response, which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_CREATE_DIRECTORY
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_create_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with find_close2
 * response, which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_FIND_CLOSE2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_find_close2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with open print file
 * response, just returns smb file identifier
 * ASSOCIATED COMMANDS: SMB_COM_OPEN_PRINT_FILE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_open_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_PRINT_FILE_R pOpenR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */
	RTSMB_PACK_WORD (pOpenR->fid);
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with create response, just
 * returns smb file identifier
 * ASSOCIATED COMMANDS: SMB_COM_CREATE_NEW,
 * SMB_COM_CREATE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_create (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE_R pCreateR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */
	RTSMB_PACK_WORD (pCreateR->fid);
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with open response
 * ASSOCIATED COMMANDS: SMB_COM_OPEN
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_open (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_R pOpenR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (7);	/* word count */
	RTSMB_PACK_WORD (pOpenR->fid);
	RTSMB_PACK_WORD (pOpenR->file_attributes);
	RTSMB_PACK_DWORD (pOpenR->last_write_time);
	RTSMB_PACK_DWORD (pOpenR->file_size);
	RTSMB_PACK_WORD (pOpenR->granted_access);
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query information
 * response
 * ASSOCIATED COMMANDS: SMB_COM_QUERY_INFORMATION
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_INFORMATION_R pQueryR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (10);	/* word count */
	RTSMB_PACK_WORD (pQueryR->file_attributes);
	RTSMB_PACK_DWORD (pQueryR->last_write_time);
	RTSMB_PACK_DWORD (pQueryR->file_size);
	RTSMB_PACK_DWORD (0);	/* reserved */
	RTSMB_PACK_DWORD (0);	/* reserved */
	RTSMB_PACK_WORD (0);	/* reserved */
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query information2
 * response
 * ASSOCIATED COMMANDS: SMB_COM_QUERY_INFORMATION2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_information2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_INFORMATION2_R pQueryR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (11);	/* word count */
	RTSMB_PACK_WORD (pQueryR->creation_date);
	RTSMB_PACK_WORD (pQueryR->creation_time);
	RTSMB_PACK_WORD (pQueryR->last_access_date);
	RTSMB_PACK_WORD (pQueryR->last_access_time);
	RTSMB_PACK_WORD (pQueryR->last_write_date);
	RTSMB_PACK_WORD (pQueryR->last_write_time);
	RTSMB_PACK_DWORD (pQueryR->file_size);
	RTSMB_PACK_DWORD (pQueryR->file_allocation_size);
	RTSMB_PACK_WORD (pQueryR->file_attributes);
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with read response
 * ASSOCIATED COMMANDS: SMB_COM_READ
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_read (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_R pReadR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (5);	/* word count */
	RTSMB_PACK_WORD (pReadR->data_size);
	RTSMB_PACK_DWORD (0);	/* reserved */
	RTSMB_PACK_DWORD (0);	/* reserved */
	RTSMB_PACK_WORD ((word) (3 + pReadR->data_size));	/* byte count */
	RTSMB_PACK_BYTE (SMB_BF_DATA);
	RTSMB_PACK_WORD (pReadR->data_size);
	RTSMB_PACK_ITEM (pReadR->data, pReadR->data_size);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with fill search response
 * ASSOCIATED COMMANDS: SMB_COM_SEARCH
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_search (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEARCH_R pSearchR)
{
	PFVOID s, e;
	int data_size;

	data_size = pSearchR->count * RTSMB_DIRECTORY_INFORMATION_DATA_SIZE;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */
	RTSMB_PACK_WORD (pSearchR->count);
	if (data_size > 0)
	{
		RTSMB_PACK_WORD ((word) (3 + data_size));	/* byte count */
	}
	else
	{
		RTSMB_PACK_WORD (0);
	}
	RTSMB_PACK_BYTE (SMB_BF_VARIABLE);
	RTSMB_PACK_WORD ((word)data_size);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with fill directory
 * information data response
 * ASSOCIATED COMMANDS: SMB_COM_SEARCH
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_directory_information_data (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_DIRECTORY_INFORMATION_DATA pData)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (pData->resume_key.reserved);
	RTSMB_PACK_ITEM (pData->resume_key.filename, 11);
	RTSMB_PACK_ITEM (pData->resume_key.server_data, 5);
	RTSMB_PACK_ITEM (pData->resume_key.client_data, 4);
	RTSMB_PACK_BYTE (pData->file_attributes);
	RTSMB_PACK_WORD (pData->last_write_time);
	RTSMB_PACK_WORD (pData->last_write_date);
	RTSMB_PACK_DWORD (pData->file_size);
	RTSMB_PACK_STRING (pData->filename, RTSMB_PACK_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with fill set information
 * response, which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_SET_INFORMATION
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_set_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with fill set information2
 * response, which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_SET_INFORMATION2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_set_information2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with fill query information
 * disk response
 * ASSOCIATED COMMANDS: SMB_COM_QUERY_INFORMATION_DISK
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_information_disk (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_INFORMATION_DISK_R pQueryR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (5);	/* word count */
	RTSMB_PACK_WORD (pQueryR->total_units);
	RTSMB_PACK_WORD (pQueryR->blocks_per_unit);
	RTSMB_PACK_WORD (pQueryR->block_size);
	RTSMB_PACK_WORD (pQueryR->free_units);
	RTSMB_PACK_WORD (0);	/* reserved */
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with tree connect
 * response
 * ASSOCIATED COMMANDS: SMB_COM_TREE_CONNECT
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_tree_connect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_R pTreeR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (2);	/* word count */
	RTSMB_PACK_WORD (pTreeR->max_buffer_size);
	RTSMB_PACK_WORD (pTreeR->tid);
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with write response
 * ASSOCIATED COMMANDS: SMB_COM_WRITE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_write (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_R pWriteR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */
	RTSMB_PACK_WORD (pWriteR->count);
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with write and close
 * response, just sends count
 * ASSOCIATED COMMANDS: SMB_COM_WRITE_AND_CLOSE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_write_and_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_CLOSE_R pWriteR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */
	RTSMB_PACK_WORD (pWriteR->count);
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with write print file
 * response, which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_WRITE_PRINT_FILE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_write_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with write raw1 response
 * which is just to send remaining
 * ASSOCIATED COMMANDS: SMB_COM_WRITE_RAW
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_write_raw1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW_R1 pWriteR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */
	RTSMB_PACK_WORD (pWriteR->remaining);
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with write raw2 response
 * which is just to send remaining
 * ASSOCIATED COMMANDS: SMB_COM_WRITE_RAW
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_write_raw2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW_R2 pWriteR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */
	RTSMB_PACK_WORD (pWriteR->count);
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with process exit
 * response, which is just to set the error code and
 * send a no op in the data section.
 * ASSOCIATED COMMANDS: SMB_COM_PROCESS_EXIT
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_process_exit (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_fill_no_op (buf, size);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with info allocation
 * response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_FS_INFORMATION
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_info_allocation (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_ALLOCATION pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (pInfo->file_system_id);
	RTSMB_PACK_DWORD (pInfo->sectors_per_unit);
	RTSMB_PACK_DWORD (pInfo->total_units);
	RTSMB_PACK_DWORD (pInfo->available_units);
	RTSMB_PACK_WORD (pInfo->bytes_per_sector);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with info volume response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_FS_INFORMATION
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_info_volume (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_VOLUME pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (pInfo->serial_number);

	if (ON (pHeader->flags2, SMB_FLG2_UNICODESTR))
	{
		RTSMB_PACK_BYTE ((byte) (rtsmb_len (pInfo->label) * 2));
	}
	else
	{
		RTSMB_PACK_BYTE ((byte) (rtsmb_len (pInfo->label)));
	}

	RTSMB_PACK_STRING (pInfo->label, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query fs volume info
 * response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_FS_INFORMATION
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_fs_volume_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FS_VOLUME_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

    // 10/24/2015 - fixed some bugs in this response
	RTSMB_PACK_DWORD (pInfo->low_creation_time);
	RTSMB_PACK_DWORD (pInfo->high_creation_time);
	RTSMB_PACK_DWORD (pInfo->serial_number);

	if (ON (pHeader->flags2, SMB_FLG2_UNICODESTR))
	{
		RTSMB_PACK_DWORD ((dword) (rtsmb_len (pInfo->label) * 2));
	}
	else
	{
		RTSMB_PACK_DWORD ((dword) (rtsmb_len (pInfo->label)));
	}

	RTSMB_PACK_WORD (0);	/* reserved */
	RTSMB_PACK_STRING (pInfo->label, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query fs size info
 * response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_FS_INFORMATION
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_fs_size_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FS_SIZE_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (pInfo->low_total_units);
	RTSMB_PACK_DWORD (pInfo->high_total_units);
	RTSMB_PACK_DWORD (pInfo->low_free_units);
	RTSMB_PACK_DWORD (pInfo->high_free_units);
	RTSMB_PACK_DWORD (pInfo->sectors_per_unit);
	RTSMB_PACK_DWORD (pInfo->bytes_per_sector);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query fs device info
 * response, which is just device type and the
 * characteristics of the device
 * ASSOCIATED COMMANDS: TRANS2_QUERY_FS_INFORMATION
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_fs_device_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FS_DEVICE_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (pInfo->device_type);
	RTSMB_PACK_DWORD (pInfo->characteristics);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query fs attribute info
 * response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_FS_INFORMATION
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_fs_attribute_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FS_ATTRIBUTE_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (pInfo->attributes);
	RTSMB_PACK_DWORD (pInfo->max_filename_size);
	RTSMB_PACK_DWORD ((dword) (rtsmb_len (pInfo->fs_name) * 2));
	RTSMB_PACK_STRING_NO_NULL (pInfo->fs_name, RTSMB_PACK_UNICODE);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section transaction response
 * ASSOCIATED COMMANDS: SMB_COM_TRANSACTION,
 * SMB_COM_TRANSACTION2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION_R pTransactionR)
{
	PFVOID s, bs, e, pparamoffset, pdataoffset, pbytecount;
	int i;

	s = buf;

	RTSMB_PACK_BYTE ((byte) (10 + pTransactionR->setup_size));	/* word count */
	RTSMB_PACK_WORD (pTransactionR->parameter_count);
	RTSMB_PACK_WORD (pTransactionR->data_count);
	RTSMB_PACK_WORD (0);	/* reserved */
	RTSMB_PACK_WORD (pTransactionR->parameter_count);
	pparamoffset = buf;
	RTSMB_PACK_WORD (0);	/* param offset */
	RTSMB_PACK_WORD (0);	/* param displacement */
	RTSMB_PACK_WORD (pTransactionR->data_count);
	pdataoffset = buf;
	RTSMB_PACK_WORD (0);	/* data offset */
	RTSMB_PACK_WORD (0);	/* data displacement */
	RTSMB_PACK_BYTE (pTransactionR->setup_size);
	RTSMB_PACK_BYTE (0);	/* reserved */

	for (i = 0; i < pTransactionR->setup_size; i++)
	{
		RTSMB_PACK_WORD (pTransactionR->setup[i]);
	}

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;

	if (pTransactionR->parameter_count)
	{
		RTSMB_PACK_PAD_TO (4);	/* pad to dword */
		rtsmb_pack_add_word_unsafe (pparamoffset, (word) PDIFF (buf, origin), FALSE);
		RTSMB_PACK_ITEM (pTransactionR->parameter, pTransactionR->parameter_count);
	}
	else
	{
		rtsmb_pack_add_word_unsafe (pparamoffset, (word) PDIFF (buf, origin), FALSE);
	}

	if (pTransactionR->data_count)
	{
		RTSMB_PACK_PAD_TO (4);	/* pad to dword */
		rtsmb_pack_add_word_unsafe (pdataoffset, (word) PDIFF (buf, origin), FALSE);
		RTSMB_PACK_ITEM (pTransactionR->data, pTransactionR->data_count);
	}
	else
	{
		rtsmb_pack_add_word_unsafe (pdataoffset, (word) PDIFF (buf, origin), FALSE);
	}

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with find file info standard
 * response
 * ASSOCIATED COMMANDS: TRANS2_FIND_FIRST2,
 * TRANS2_FIND_NEXT2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_find_file_info_standard (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_INFO_STANDARD pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_PAD_TO (2);

	if (pInfo->valid_resume_key)
	{
		RTSMB_PACK_DWORD (pInfo->resume_key);
	}

	RTSMB_PACK_WORD (pInfo->creation_date);
	RTSMB_PACK_WORD (pInfo->creation_time);
	RTSMB_PACK_WORD (pInfo->last_access_date);
	RTSMB_PACK_WORD (pInfo->last_access_time);
	RTSMB_PACK_WORD (pInfo->last_write_date);
	RTSMB_PACK_WORD (pInfo->last_write_time);
	RTSMB_PACK_DWORD (pInfo->file_size);
	RTSMB_PACK_DWORD (pInfo->allocation_size);
	RTSMB_PACK_WORD (pInfo->attributes);

	if (ON (pHeader->flags2, SMB_FLG2_UNICODESTR))
	{
		RTSMB_PACK_BYTE ((byte) (rtsmb_len (pInfo->filename) * 2 + 2));
	}
	else
	{
		RTSMB_PACK_BYTE ((byte) (rtsmb_len (pInfo->filename) + 1));
	}

	RTSMB_PACK_STRING (pInfo->filename, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with find file info query ea
 * size response
 * ASSOCIATED COMMANDS: TRANS2_FIND_FIRST2,
 * TRANS2_FIND_NEXT2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_find_file_info_query_ea_size (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_INFO_QUERY_EA_SIZE pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_PAD_TO (2);

	if (pInfo->valid_resume_key)
	{
		RTSMB_PACK_DWORD (pInfo->resume_key);
	}

	RTSMB_PACK_WORD (pInfo->creation_date);
	RTSMB_PACK_WORD (pInfo->creation_time);
	RTSMB_PACK_WORD (pInfo->last_access_date);
	RTSMB_PACK_WORD (pInfo->last_access_time);
	RTSMB_PACK_WORD (pInfo->last_write_date);
	RTSMB_PACK_WORD (pInfo->last_write_time);
	RTSMB_PACK_DWORD (pInfo->file_size);
	RTSMB_PACK_DWORD (pInfo->allocation_size);
	RTSMB_PACK_WORD (pInfo->attributes);
	RTSMB_PACK_DWORD (pInfo->ea_size);

	if (ON (pHeader->flags2, SMB_FLG2_UNICODESTR))
	{
		RTSMB_PACK_BYTE ((byte) (rtsmb_len (pInfo->filename) * 2));
	}
	else
	{
		RTSMB_PACK_BYTE ((byte) (rtsmb_len (pInfo->filename)));
	}

	RTSMB_PACK_STRING_D_NO_NULL (pInfo->filename, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with find file directory
 * info response
 * ASSOCIATED COMMANDS: TRANS2_FIND_FIRST2,
 * TRANS2_FIND_NEXT2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_find_file_directory_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_DIRECTORY_INFO pInfo)
{
	PFVOID s, e, pnextoffset;

	s = buf;

	RTSMB_PACK_PAD_TO (2);

	pnextoffset = buf;
	RTSMB_PACK_DWORD (0);	/* offset to next entry */
	RTSMB_PACK_DWORD (pInfo->file_index);
	RTSMB_PACK_DWORD (pInfo->low_creation_time);
	RTSMB_PACK_DWORD (pInfo->high_creation_time);
	RTSMB_PACK_DWORD (pInfo->low_last_access_time);
	RTSMB_PACK_DWORD (pInfo->high_last_access_time);
	RTSMB_PACK_DWORD (pInfo->low_last_write_time);
	RTSMB_PACK_DWORD (pInfo->high_last_write_time);
	RTSMB_PACK_DWORD (pInfo->low_change_time);
	RTSMB_PACK_DWORD (pInfo->high_change_time);
	RTSMB_PACK_DWORD (pInfo->low_end_of_file);
	RTSMB_PACK_DWORD (pInfo->high_end_of_file);
	RTSMB_PACK_DWORD (pInfo->low_allocation_size);
	RTSMB_PACK_DWORD (pInfo->high_allocation_size);
	RTSMB_PACK_DWORD (pInfo->extended_file_attributes);

	if (ON (pHeader->flags2, SMB_FLG2_UNICODESTR))
	{
		RTSMB_PACK_DWORD ((dword) (rtsmb_len (pInfo->filename) * 2));
	}
	else
	{
		RTSMB_PACK_DWORD ((dword) (rtsmb_len (pInfo->filename)));
	}

	RTSMB_PACK_STRING_NO_NULL (pInfo->filename, RTSMB_PACK_ANY);

	RTSMB_PACK_PAD_TO (2);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pnextoffset, (word) PDIFF (e, s), FALSE);

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with find file full
 * directory info response
 * ASSOCIATED COMMANDS: TRANS2_FIND_FIRST2,
 * TRANS2_FIND_NEXT2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_find_file_full_directory_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_FULL_DIRECTORY_INFO pInfo)
{
	PFVOID s, e, pnextoffset;

	s = buf;

	RTSMB_PACK_PAD_TO (2);

	pnextoffset = buf;
	RTSMB_PACK_DWORD (0);	/* offset to next entry */
	RTSMB_PACK_DWORD (pInfo->file_index);
	RTSMB_PACK_DWORD (pInfo->low_creation_time);
	RTSMB_PACK_DWORD (pInfo->high_creation_time);
	RTSMB_PACK_DWORD (pInfo->low_last_access_time);
	RTSMB_PACK_DWORD (pInfo->high_last_access_time);
	RTSMB_PACK_DWORD (pInfo->low_last_write_time);
	RTSMB_PACK_DWORD (pInfo->high_last_write_time);
	RTSMB_PACK_DWORD (pInfo->low_change_time);
	RTSMB_PACK_DWORD (pInfo->high_change_time);
	RTSMB_PACK_DWORD (pInfo->low_end_of_file);
	RTSMB_PACK_DWORD (pInfo->high_end_of_file);
	RTSMB_PACK_DWORD (pInfo->low_allocation_size);
	RTSMB_PACK_DWORD (pInfo->high_allocation_size);
	RTSMB_PACK_DWORD (pInfo->extended_file_attributes);

	if (ON (pHeader->flags2, SMB_FLG2_UNICODESTR))
	{
		RTSMB_PACK_DWORD (rtsmb_len (pInfo->filename) * 2);
	}
	else
	{
		RTSMB_PACK_DWORD (rtsmb_len (pInfo->filename));
	}

	RTSMB_PACK_DWORD (pInfo->ea_size);

	RTSMB_PACK_STRING_NO_NULL (pInfo->filename, RTSMB_PACK_ANY);

	RTSMB_PACK_PAD_TO (2);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pnextoffset, (word) PDIFF (e, s), FALSE);

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with find file both
 * directory info response
 * ASSOCIATED COMMANDS: TRANS2_FIND_FIRST2,
 * TRANS2_FIND_NEXT2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_find_file_both_directory_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_BOTH_DIRECTORY_INFO pInfo)
{
	PFVOID s, e, pnextoffset, buf_backup;
	rtsmb_size size_backup;

	s = buf;

	RTSMB_PACK_PAD_TO (2);

	pnextoffset = buf;
	RTSMB_PACK_DWORD (0);	/* offset to next entry */
	RTSMB_PACK_DWORD (pInfo->file_index);
	RTSMB_PACK_DWORD (pInfo->low_creation_time);
	RTSMB_PACK_DWORD (pInfo->high_creation_time);
	RTSMB_PACK_DWORD (pInfo->low_last_access_time);
	RTSMB_PACK_DWORD (pInfo->high_last_access_time);
	RTSMB_PACK_DWORD (pInfo->low_last_write_time);
	RTSMB_PACK_DWORD (pInfo->high_last_write_time);
	RTSMB_PACK_DWORD (pInfo->low_change_time);
	RTSMB_PACK_DWORD (pInfo->high_change_time);
	RTSMB_PACK_DWORD (pInfo->low_end_of_file);
	RTSMB_PACK_DWORD (pInfo->high_end_of_file);
	RTSMB_PACK_DWORD (pInfo->low_allocation_size);
	RTSMB_PACK_DWORD (pInfo->high_allocation_size);
	RTSMB_PACK_DWORD (pInfo->extended_file_attributes);

	if (ON (pHeader->flags2, SMB_FLG2_UNICODESTR))
	{
		RTSMB_PACK_DWORD (rtsmb_len (pInfo->filename) * 2);
	}
	else
	{
		RTSMB_PACK_DWORD (rtsmb_len (pInfo->filename));
	}

	RTSMB_PACK_DWORD (pInfo->ea_size);

	if (ON (pHeader->flags2, SMB_FLG2_UNICODESTR))
	{
		RTSMB_PACK_BYTE ((byte) (rtsmb_len (pInfo->short_name) * 2));
	}
	else
	{
		RTSMB_PACK_BYTE ((byte) (rtsmb_len (pInfo->short_name)));
	}

	RTSMB_PACK_BYTE (0);	/* reserved */
	buf_backup = buf;
	size_backup = size;
	RTSMB_PACK_STRING (pInfo->short_name, RTSMB_PACK_ANY);
	ASSURE (size_backup >= 24, -1);
	buf = PADD (buf_backup, 24);
	size = size_backup - 24;

	RTSMB_PACK_STRING_NO_NULL (pInfo->filename, RTSMB_PACK_ANY);

	RTSMB_PACK_PAD_TO (2);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pnextoffset, (word) PDIFF (e, s), FALSE);

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with find file names
 * directory info response
 * ASSOCIATED COMMANDS: TRANS2_FIND_FIRST2,
 * TRANS2_FIND_NEXT2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_find_file_names_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_NAMES_INFO pInfo)
{
	PFVOID s, e, pnextoffset;

	s = buf;

	RTSMB_PACK_PAD_TO (2);

	pnextoffset = buf;
	RTSMB_PACK_DWORD (0);	/* offset to next entry */
	RTSMB_PACK_DWORD (pInfo->file_index);

	if (ON (pHeader->flags2, SMB_FLG2_UNICODESTR))
	{
		RTSMB_PACK_DWORD (rtsmb_len (pInfo->filename) * 2);
	}
	else
	{
		RTSMB_PACK_DWORD (rtsmb_len (pInfo->filename));
	}

	RTSMB_PACK_STRING_NO_NULL (pInfo->filename, RTSMB_PACK_ANY);

	RTSMB_PACK_PAD_TO (2);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pnextoffset, (word) PDIFF (e, s), FALSE);

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with find first response
 * ASSOCIATED COMMANDS: SMB_COM_TRANSACTION2
 * SUBCOMMAND: TRANS2_FIND_FIRST2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_find_first (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_FIRST_R pFindR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_WORD (pFindR->sid);
	RTSMB_PACK_WORD (pFindR->search_count);
	RTSMB_PACK_WORD (pFindR->end_of_search);
	RTSMB_PACK_WORD (pFindR->ea_error_offset);
	RTSMB_PACK_WORD (pFindR->last_name_offset);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with find first next
 * response
 * ASSOCIATED COMMANDS: SMB_COM_TRANSACTION2
 * SUBCOMMAND: TRANS2_FIND_NEXT2
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_find_next (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_NEXT_R pFindR)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_WORD (pFindR->search_count);
	RTSMB_PACK_WORD (pFindR->end_of_search);
	RTSMB_PACK_WORD (pFindR->ea_error_offset);
	RTSMB_PACK_WORD (pFindR->last_name_offset);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with info standard response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_PATH_INFORMATION,
 *                      TRANS2_QUERY_FILE_INFORMATION
 * INFO LEVEL: SMB_INFO_STANDARD
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_info_standard (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_STANDARD pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_WORD (pInfo->creation_date);
	RTSMB_PACK_WORD (pInfo->creation_time);
	RTSMB_PACK_WORD (pInfo->last_access_date);
	RTSMB_PACK_WORD (pInfo->last_access_time);
	RTSMB_PACK_WORD (pInfo->last_write_date);
	RTSMB_PACK_WORD (pInfo->last_write_time);
	RTSMB_PACK_DWORD (pInfo->file_size);
	RTSMB_PACK_DWORD (pInfo->allocation_size);
	RTSMB_PACK_WORD (pInfo->attributes);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with info query ea size
 * response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_PATH_INFORMATION,
 *                      TRANS2_QUERY_FILE_INFORMATION
 * INFO LEVEL: SMB_INFO_QUERY_EA_SIZE
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_info_query_ea_size (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_QUERY_EA_SIZE pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_WORD (pInfo->creation_date);
	RTSMB_PACK_WORD (pInfo->creation_time);
	RTSMB_PACK_WORD (pInfo->last_access_date);
	RTSMB_PACK_WORD (pInfo->last_access_time);
	RTSMB_PACK_WORD (pInfo->last_write_date);
	RTSMB_PACK_WORD (pInfo->last_write_time);
	RTSMB_PACK_DWORD (pInfo->file_size);
	RTSMB_PACK_DWORD (pInfo->allocation_size);
	RTSMB_PACK_WORD (pInfo->attributes);
	RTSMB_PACK_DWORD (pInfo->ea_size);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query file basic info
 * response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_PATH_INFORMATION,
 *                      TRANS2_QUERY_FILE_INFORMATION
 * INFO LEVEL: SMB_QUERY_FILE_BASIC_INFO
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_file_basic_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_BASIC_INFO pInfo)
{
	PFVOID s, e;
	unsigned long empty_long = 0;
	unsigned short empty_short = 0;
	s = buf;

	RTSMB_PACK_DWORD (pInfo->low_creation_time);
	RTSMB_PACK_DWORD (pInfo->high_creation_time);
	RTSMB_PACK_DWORD (pInfo->low_last_access_time);
	RTSMB_PACK_DWORD (pInfo->high_last_access_time);
	RTSMB_PACK_DWORD (pInfo->low_last_write_time);
	RTSMB_PACK_DWORD (pInfo->high_last_write_time);
	RTSMB_PACK_DWORD (pInfo->low_change_time);
	RTSMB_PACK_DWORD (pInfo->high_change_time);
	RTSMB_PACK_WORD (pInfo->attributes);
	RTSMB_PACK_DWORD (empty_long);
	RTSMB_PACK_WORD (empty_short); //pack 2 empty dwords for unknown data
	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query file standard
 * info response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_PATH_INFORMATION,
 *                      TRANS2_QUERY_FILE_INFORMATION
 * INFO LEVEL: SMB_QUERY_FILE_STANDARD_INFO
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_file_standard_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_STANDARD_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (pInfo->low_allocation_size);
	RTSMB_PACK_DWORD (pInfo->high_allocation_size);
	RTSMB_PACK_DWORD (pInfo->low_end_of_file);
	RTSMB_PACK_DWORD (pInfo->high_end_of_file);
	RTSMB_PACK_DWORD (pInfo->number_of_links);
	RTSMB_PACK_BYTE (pInfo->delete_pending);
	RTSMB_PACK_BYTE (pInfo->is_directory);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query file ea info
 * response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_PATH_INFORMATION,
 *                      TRANS2_QUERY_FILE_INFORMATION
 * INFO LEVEL: SMB_QUERY_FILE_EA_INFO
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_file_ea_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_EA_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (pInfo->ea_size);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query file name info
 * response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_PATH_INFORMATION,
 *                      TRANS2_QUERY_FILE_INFORMATION
 * INFO LEVEL: SMB_QUERY_FILE_NAME_INFO,
               SMB_QUERY_FILE_ALT_NAME_INFO
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_file_name_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_NAME_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (pInfo->filename_size);
	RTSMB_PACK_STRING (pInfo->filename, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query file stream info
 * response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_PATH_INFORMATION,
 *                      TRANS2_QUERY_FILE_INFORMATION
 * INFO LEVEL: SMB_QUERY_FILE_STREAM_INFO
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_file_stream_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_STREAM_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (0);	/* next entry offset */

	/* name size in bytes */
	if (ON (pHeader->flags2, SMB_FLG2_UNICODESTR))
	{
		RTSMB_PACK_DWORD ((dword) (rtsmb_len (pInfo->stream_name) * 2) + 2);
	}
	else
	{
		RTSMB_PACK_DWORD ((dword) (rtsmb_len (pInfo->stream_name)) + 1);
	}

	RTSMB_PACK_DWORD (pInfo->low_stream_size);
	RTSMB_PACK_DWORD (pInfo->high_stream_size);
	RTSMB_PACK_DWORD (pInfo->low_allocation_size);
	RTSMB_PACK_DWORD (pInfo->high_allocation_size);
	RTSMB_PACK_STRING (pInfo->stream_name, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with query file compression
 * info response
 * ASSOCIATED COMMANDS: TRANS2_QUERY_PATH_INFORMATION,
 *                      TRANS2_QUERY_FILE_INFORMATION
 * INFO LEVEL: SMB_QUERY_FILE_COMPRESSION_INFO
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_query_file_compression_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_COMPRESSION_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (pInfo->low_compressed_file_size);
	RTSMB_PACK_DWORD (pInfo->high_compressed_file_size);
	RTSMB_PACK_WORD (pInfo->compression_format);
	RTSMB_PACK_BYTE (pInfo->compression_unit_shift);
	RTSMB_PACK_BYTE (pInfo->chunk_shift);
	RTSMB_PACK_BYTE (pInfo->cluster_shift);
	RTSMB_PACK_BYTE (0);	/* reserved */
	RTSMB_PACK_WORD (0);	/* reserved */

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* --------------------------------------------------- /
 * Fills SMB Data Section with rap response
 *
 * Returns: Size of data on success, -1 if not
 * enough space
 * -------------------------------------------------- */
int srv_cmd_fill_rap_response (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_RESPONSE pRAP)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_WORD (pRAP->status);
	RTSMB_PACK_WORD (pRAP->converter);
	RTSMB_PACK_WORD (pRAP->available_bytes);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* rap functions are a little different than normal functions
   Each function has a complement that tells the caller how mRTSMB_PACK_ANY
   bytes would be needed to store the data.
*/

RTSMB_STATIC rtsmb_size sizeof_string (PRTSMB_HEADER pHeader, PFRTCHAR str, int type)
{
	if (str)
	{
		switch (type)
		{
		case RTSMB_PACK_ASCII:
			return rtsmb_len (str) + 1;
		case RTSMB_PACK_UNICODE:
			return rtsmb_len (str) * 2 + 2;
		default:
			return ON (pHeader->flags2, SMB_FLG2_UNICODESTR) ?
				(rtsmb_len (str) * 2 + 2) :
				(rtsmb_len (str) + 1);
		}
	}
	else
	{
		switch (type)
		{
		case RTSMB_PACK_ASCII:
			return 1;
		case RTSMB_PACK_UNICODE:
			return 2;
		default:
			return ON (pHeader->flags2, SMB_FLG2_UNICODESTR) ? 2 : 1;
		}
	}
}

rtsmb_size srv_cmd_sizeof_rap_wksta_info (PRTSMB_HEADER pHeader, PRTSMB_RAP_WKSTA_INFO pInfo)
{
	return 22 + sizeof_string (pHeader, pInfo->computer_name, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->username, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->lan_group, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->logon_domain, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->other_domains, RTSMB_PACK_ASCII);
}

int srv_cmd_fill_rap_wksta_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_WKSTA_INFO pInfo)
{
	PFVOID s, e, data;

	s = buf;

	data = buf;

	RTSMB_PACK_DWORD (0);
	RTSMB_PACK_DWORD (0);
	RTSMB_PACK_DWORD (0);
	RTSMB_PACK_BYTE (pInfo->version_major);
	RTSMB_PACK_BYTE (pInfo->version_minor);
	RTSMB_PACK_DWORD (0);
	RTSMB_PACK_DWORD (0);

	/* now we are at the string section */
	rtsmb_pack_add_dword_unsafe (PADD (data, 18), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->other_domains, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (data, 14), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->logon_domain, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (data, 8), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->lan_group, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (data, 4), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->username, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (data, (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->computer_name, RTSMB_PACK_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

int srv_cmd_fill_rap_share_enum_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_ENUM_HEADER_R pRAP)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_WORD (pRAP->status);
	RTSMB_PACK_WORD (pRAP->converter);
	RTSMB_PACK_WORD (pRAP->entry_count);
	RTSMB_PACK_WORD (pRAP->available_entries);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* info structs are supposed to get called last to first.
   That is, pass the Nth of N first, then call with the (N-1)th of N, etc. */
/* Also, the value you get back from this function is merely a sum of the data written
   to the buffer -- do not use it to increment your own pointer into the buffer.  Keep
   passing this function the pointer to the start of the enum info section. */
int srv_cmd_fill_rap_share_enum_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SHARE_ENUM_INFO_R pInfo)
{
	PFVOID s, e, info_end, actual_start, string_start, comment;
	int i;

	/* move to appropriate place in buffer, since we know the size of an
	   info_1 struct in the buffer. */
	actual_start = buf;
	buf = PADD (buf, 20 * pInfo->share_num);

	s = buf;

	RTSMB_PACK_STRING (pInfo->share_data.name, RTSMB_PACK_ASCII);

	for (i = (int)rtsmb_len (pInfo->share_data.name) + 1; i < 13; i++)
	{
		RTSMB_PACK_BYTE (0);	/* null pad the string */
	}
	RTSMB_PACK_BYTE (0);	/* reserved */
	RTSMB_PACK_WORD (pInfo->share_data.type);
	comment = buf;
	RTSMB_PACK_DWORD (0);	/* comment */

	info_end = buf;

	/* Move to end of info area, to string area. */
	buf = PADD (actual_start, 20 * pInfo->total_shares);

	/* Find appropriate place in this
	   region by skipping past (total_shares - share_num - 1) strings. */
	for (i = 0; i < pInfo->total_shares - pInfo->share_num - 1; i++)
	{
		int j = 0, null_found = 0;
		PFCHAR chbuf = (PFCHAR) buf;

		while (!null_found)
		{
			{
				if (chbuf[j] == 0)
				{
					buf = PADD (buf, j + 1);
					null_found = 1;
				}

				j += 1;
			}
		}
	}

	string_start = buf;

	/* now we are at the string section */
	rtsmb_pack_add_dword_unsafe (comment, (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->share_data.comment, RTSMB_PACK_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (info_end, s) + PDIFF (e, string_start);
}

/* info structs are supposed to get called last to first.
   That is, pass the Nth of N first, then call with the (N-1)th of N, etc. */
/* Also, the value you get back from this function is merely a sum of the data written
   to the buffer -- do not use it to increment your own pointer into the buffer.  Keep
   passing this function the pointer to the start of the enum info section. */
int srv_cmd_fill_rap_server_enum_info_0 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo)
{
	PFVOID s, e;
	int i;

	/* move to appropriate place in buffer, since we know the size of an
	   info_1 struct in the buffer. */
	buf = PADD (buf, 16 * pInfo->info_num);

	s = buf;

	RTSMB_PACK_STRING (pInfo->name, RTSMB_PACK_ASCII);

	for (i = (int)rtsmb_len (pInfo->name) + 1; i < 16; i++)
	{
		RTSMB_PACK_BYTE (0);	/* null pad the string */
	}

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

/* info structs are supposed to get called last to first.
   That is, pass the Nth of N first, then call with the (N-1)th of N, etc. */
/* Also, the value you get back from this function is merely a sum of the data written
   to the buffer -- do not use it to increment your own pointer into the buffer.  Keep
   passing this function the pointer to the start of the enum info section. */
int srv_cmd_fill_rap_server_enum_info_1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo)
{
	PFVOID s, e, info_end, actual_start, string_start, comment;
	int i;

	/* move to appropriate place in buffer, since we know the size of an
	   info_1 struct in the buffer. */
	actual_start = buf;
	buf = PADD (buf, 26 * pInfo->info_num);

	s = buf;

	RTSMB_PACK_STRING (pInfo->name, RTSMB_PACK_ASCII);

	for (i = (int) rtsmb_len (pInfo->name) + 1; i < 16; i++)
	{
		RTSMB_PACK_BYTE (0);	/* null pad the string */
	}
	RTSMB_PACK_BYTE (pInfo->version_major);
	RTSMB_PACK_BYTE (pInfo->version_minor);
	RTSMB_PACK_DWORD (pInfo->type);
	comment = buf;
	RTSMB_PACK_DWORD (0);	/* comment */

	info_end = buf;

	/* Move to end of info area, to string area. */
	buf = PADD (actual_start, 26 * pInfo->info_total);

	/* Find appropriate place in this
	   region by skipping past (total_shares - share_num - 1) strings. */
	for (i = 0; i < pInfo->info_total - pInfo->info_num - 1; i++)
	{
		int j = 0, null_found = 0;
		PFCHAR chbuf = (PFCHAR) buf;

		while (!null_found)
		{
			{
				if (chbuf[j] == 0)
				{
					buf = PADD (buf, j + 1);
					null_found = 1;
				}

				j += 1;
			}
		}
	}

	string_start = buf;

	/* now we are at the string section */
	rtsmb_pack_add_dword_unsafe (comment, (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->comment, RTSMB_PACK_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (info_end, s) + PDIFF (e, string_start);
}

int srv_cmd_fill_rap_share_info_0 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SHARE_INFO_0 pInfo)
{
	PFVOID s, e;
	int i;

	s = buf;

	RTSMB_PACK_STRING (pInfo->name, RTSMB_PACK_ASCII);

	for (i = (int)rtsmb_len (pInfo->name) + 1; i < 13; i++)
	{
		RTSMB_PACK_BYTE (0);	/* null pad the string */
	}

	e = buf;	/* measure end of data section */
	return PDIFF (e, s);
}

int srv_cmd_fill_rap_share_info_1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SHARE_INFO_1 pInfo)
{
	PFVOID s, e, data;
	int i;

	s = buf;

	data = buf;

	RTSMB_PACK_STRING (pInfo->name, RTSMB_PACK_ASCII);

	for (i = (int)rtsmb_len (pInfo->name) + 1; i < 13; i++)
	{
		RTSMB_PACK_BYTE (0);	/* null pad the string */
	}

	RTSMB_PACK_BYTE (0);	/* reserved */
	RTSMB_PACK_WORD (pInfo->type);
	RTSMB_PACK_DWORD (0);

	rtsmb_pack_add_dword_unsafe (PADD (data, 16), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->comment, RTSMB_PACK_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

rtsmb_size srv_cmd_sizeof_rap_printer_queue_info_0 (PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_0 pInfo)
{
	return 16;
}

int srv_cmd_fill_rap_server_info_0 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo)
{
	PFVOID s, e;
	int i;

	s = buf;

	RTSMB_PACK_STRING (pInfo->name, RTSMB_PACK_ASCII);

	for (i = (int)rtsmb_len (pInfo->name) + 1; i < 16; i++)
	{
		RTSMB_PACK_BYTE (0);	/* null pad the string */
	}

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

int srv_cmd_fill_rap_server_info_1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo)
{
	PFVOID s, e;
	int i;

	s = buf;

	RTSMB_PACK_STRING (pInfo->name, RTSMB_PACK_ASCII);

	for (i = (int)rtsmb_len (pInfo->name) + 1; i < 16; i++)
	{
		RTSMB_PACK_BYTE (0);	/* null pad the string */
	}

	RTSMB_PACK_BYTE (pInfo->version_major);
	RTSMB_PACK_BYTE (pInfo->version_minor);
	RTSMB_PACK_DWORD (pInfo->type);
	RTSMB_PACK_DWORD (0);	/* comment */

	rtsmb_pack_add_dword_unsafe (PADD (s, 22), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->comment, RTSMB_PACK_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

int srv_cmd_fill_rap_printer_queue_info_0 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_0 pInfo)
{
	PFVOID s, e;
	int i;

	s = buf;

	RTSMB_PACK_STRING (pInfo->name, RTSMB_PACK_ASCII);

	for (i = (int)rtsmb_len (pInfo->name) + 1; i < 13; i++)
	{
		RTSMB_PACK_BYTE (0);	/* null pad the string */
	}

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);

}

rtsmb_size srv_cmd_sizeof_rap_printer_queue_info_1 (PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_1 pInfo)
{
	return 44 + sizeof_string (pHeader, pInfo->comment, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->parameters, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->destinations, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->preprocessor, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->sep_file, RTSMB_PACK_ASCII);
}

int srv_cmd_fill_rap_printer_queue_info_1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_1 pInfo)
{
	PFVOID s, e;
	int i;

	s = buf;

	RTSMB_PACK_STRING (pInfo->name, RTSMB_PACK_ASCII);

	for (i = (int)rtsmb_len (pInfo->name) + 1; i < 13; i++)
	{
		RTSMB_PACK_BYTE (0);	/* null pad the string */
	}

	RTSMB_PACK_BYTE (0);	/* padding */
	RTSMB_PACK_WORD (pInfo->priority);
	RTSMB_PACK_WORD (pInfo->start_time);
	RTSMB_PACK_WORD (pInfo->until_time);
	RTSMB_PACK_DWORD (0);	/* sep_file */
	RTSMB_PACK_DWORD (0);	/* preprocessor */
	RTSMB_PACK_DWORD (0);	/* destinations */
	RTSMB_PACK_DWORD (0);	/* parameters */
	RTSMB_PACK_DWORD (0);	/* comment */
	RTSMB_PACK_WORD (pInfo->status);
	RTSMB_PACK_WORD (pInfo->num_jobs);

	/* now we are at the string section */
	rtsmb_pack_add_dword_unsafe (PADD (s, 36), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->comment, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (s, 32), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->parameters, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (s, 28), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->destinations, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (s, 24), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->preprocessor, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (s, 20), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->sep_file, RTSMB_PACK_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

rtsmb_size srv_cmd_sizeof_rap_printer_queue_info_3 (PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_3 pInfo)
{
	return 44 + sizeof_string (pHeader, pInfo->driver_data, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->driver_name, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->printers, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->comment, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->preprocessor, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->sep_file, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->name, RTSMB_PACK_ASCII) +
		sizeof_string (pHeader, pInfo->parameters, RTSMB_PACK_ASCII);
}

int srv_cmd_fill_rap_printer_queue_info_3 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_3 pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (0);	/* name */
	RTSMB_PACK_WORD (pInfo->priority);
	RTSMB_PACK_WORD (pInfo->start_time);
	RTSMB_PACK_WORD (pInfo->until_time);
	RTSMB_PACK_WORD (0);	/* padding */
	RTSMB_PACK_DWORD (0);	/* sep_file */
	RTSMB_PACK_DWORD (0);	/* preprocessor */
	RTSMB_PACK_DWORD (0);	/* parameters */
	RTSMB_PACK_DWORD (0);	/* comment */
	RTSMB_PACK_WORD (pInfo->status);
	RTSMB_PACK_WORD (pInfo->num_jobs);
	RTSMB_PACK_DWORD (0);	/* printers */
	RTSMB_PACK_DWORD (0);	/* driver name */
	RTSMB_PACK_DWORD (0);	/* driver data */

	/* now we are at the string section */
	if (pInfo->driver_data) /* driver data is only put in if it exists */
	{
		rtsmb_pack_add_dword_unsafe (PADD (s, 40), (dword) buf, FALSE);
		RTSMB_PACK_STRING (pInfo->driver_data, RTSMB_PACK_ASCII);
	}
	rtsmb_pack_add_dword_unsafe (PADD (s, 36), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->driver_name, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (s, 32), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->printers, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (s, 24), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->comment, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (s, 20), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->parameters, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (s, 16), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->preprocessor, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (s, 12), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->sep_file, RTSMB_PACK_ASCII);
	rtsmb_pack_add_dword_unsafe (PADD (s, 0), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->name, RTSMB_PACK_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

rtsmb_size srv_cmd_sizeof_rap_printer_queue_info_5 (PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_5 pInfo)
{
	return 4 + sizeof_string (pHeader, pInfo->name, RTSMB_PACK_ASCII);
}

int srv_cmd_fill_rap_printer_queue_info_5 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_5 pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_DWORD (0);	/* name */

	/* now we are at the string section */
	rtsmb_pack_add_dword_unsafe (PADD (s, 0), (dword) buf, FALSE);
	RTSMB_PACK_STRING (pInfo->name, RTSMB_PACK_ASCII);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

int srv_cmd_fill_mailslot_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_MAILSLOT_HEADER pMailslot)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_WORD (pMailslot->opcode);
	RTSMB_PACK_WORD (pMailslot->priority);
	RTSMB_PACK_WORD (pMailslot->type);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

int srv_cmd_fill_transaction_cmd (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION pTransaction)
{
	PFVOID s, e;
	int i;

	s = buf;

	RTSMB_PACK_BYTE (17);	/* word count */
	RTSMB_PACK_WORD (pTransaction->parameter_count);
	RTSMB_PACK_WORD (pTransaction->data_count);
	RTSMB_PACK_WORD (pTransaction->max_parameter_count);
	RTSMB_PACK_WORD (pTransaction->max_data_count);
	RTSMB_PACK_BYTE (pTransaction->max_setup_count);
	RTSMB_PACK_BYTE (0);	/* reserved */
	RTSMB_PACK_WORD (pTransaction->flags);
	RTSMB_PACK_DWORD (pTransaction->timeout);
	RTSMB_PACK_WORD (0);	/* reserved */
	RTSMB_PACK_WORD (pTransaction->parameter_count);
	RTSMB_PACK_WORD (pTransaction->parameter_offset);
	RTSMB_PACK_WORD (pTransaction->data_count);
	RTSMB_PACK_WORD (pTransaction->data_offset);
	RTSMB_PACK_BYTE (pTransaction->setup_size);
	RTSMB_PACK_BYTE (0);	/* reserved */

	for (i = 0; i < pTransaction->setup_size; i++)
	{
		RTSMB_PACK_WORD (pTransaction->setup[i]);
	}

	RTSMB_PACK_WORD (pTransaction->byte_count);

	RTSMB_PACK_STRING (pTransaction->name, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	return PDIFF (e, s);
}

int srv_cmd_fill_nt_create_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NT_CREATE_AND_X_R pCreateR)
{
	PFVOID s, e, poffset;

	s = buf;

	RTSMB_PACK_BYTE (26);	/* word count */
	RTSMB_PACK_BYTE (pCreateR->next_command);
	RTSMB_PACK_BYTE (0);	/* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);	/* offset to next and_x */

	RTSMB_PACK_BYTE (pCreateR->oplock_level);
	RTSMB_PACK_WORD (pCreateR->fid);
	RTSMB_PACK_DWORD (pCreateR->create_action);
	RTSMB_PACK_DWORD (pCreateR->creation_time_low);
	RTSMB_PACK_DWORD (pCreateR->creation_time_high);
	RTSMB_PACK_DWORD (pCreateR->last_access_time_low);
	RTSMB_PACK_DWORD (pCreateR->last_access_time_high);
	RTSMB_PACK_DWORD (pCreateR->last_write_time_low);
	RTSMB_PACK_DWORD (pCreateR->last_write_time_high);
	RTSMB_PACK_DWORD (pCreateR->change_time_low);
	RTSMB_PACK_DWORD (pCreateR->change_time_high);
	RTSMB_PACK_DWORD (pCreateR->ext_file_attributes);
	RTSMB_PACK_DWORD (pCreateR->allocation_size_low);
	RTSMB_PACK_DWORD (pCreateR->allocation_size_high);
	RTSMB_PACK_DWORD (pCreateR->end_of_file_low);
	RTSMB_PACK_DWORD (pCreateR->end_of_file_high);
	RTSMB_PACK_WORD (pCreateR->file_type);
	RTSMB_PACK_WORD (pCreateR->device_state);
	RTSMB_PACK_BYTE (pCreateR->directory);

	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;

	if (pCreateR->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return PDIFF (e, s);
}

int srv_cmd_fill_locking_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOCKING_AND_X_R pLockingR)
{
	PFVOID s, e, poffset;

	s = buf;

	RTSMB_PACK_BYTE (2);	/* word count */
	RTSMB_PACK_BYTE (pLockingR->next_command);
	RTSMB_PACK_BYTE (0);	/* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);	/* offset to next and_x */
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;

	if (pLockingR->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return PDIFF (e, s);
}

#endif /* INCLUDE_RTSMB_SERVER */
