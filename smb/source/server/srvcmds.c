//
// SRVCMDS.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles the parsing of all SMB request packets for the server
//
#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)


#include "srvcmds.h"
#include "smbread.h"
#include "smbutil.h"




RTSMB_STATIC
int srv_cmd_read_no_op (PFVOID buf, rtsmb_size size)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 0, -1);
	RTSMB_READ_WORD (&w); /* byte count */
	ASSURE (w == 0, -1);

	e = buf;

	return PDIFF (e, s);
}


int srv_cmd_read_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader)
{
	PFVOID s, e;
	byte b;
	word pidHigh;
	word pidLow;
	word w;
	char string [3];

	s = buf;

	RTSMB_READ_BYTE (&b);
	if (b != 0xFF)
		return -1;

	RTSMB_READ_ITEM (string, 3);
	if (tc_strncmp (string, "SMB", 3) != 0)
		return -1;

	/* ok, it appears to be a valid SMB */

	RTSMB_READ_BYTE (&pHeader->command);
	RTSMB_READ_DWORD (&pHeader->status);
	RTSMB_READ_BYTE (&pHeader->flags);
	RTSMB_READ_WORD (&pHeader->flags2);
	RTSMB_READ_WORD (&pidHigh);
	RTSMB_READ_ITEM (&pHeader->security_sig, 8);
	RTSMB_READ_WORD (&w);
	RTSMB_READ_WORD (&pHeader->tid);
	RTSMB_READ_WORD (&pidLow);
	RTSMB_READ_WORD (&pHeader->uid);
	RTSMB_READ_WORD (&pHeader->mid);

	pHeader->pid = ((dword)pidHigh << 16) | (dword)pidLow;

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_negotiate (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE pNegotiate)
{
	PFVOID s, e;
	PFVOID stated_end;
	byte b;
	word w;
	int i;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 0, -1);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w > 1, -1);

	stated_end = PADD (buf, w);

	i = 0;
	while ((buf < stated_end) && (i < pNegotiate->num_dialects))
	{
		RTSMB_READ_BYTE (&b);
		ASSURE (b == SMB_BF_DIALECT, -1);

		RTSMB_READ_STRING (pNegotiate->dialects[i], (rtsmb_size)pNegotiate->string_size, RTSMB_READ_ASCII);

		i++;
	}
	pNegotiate->num_dialects = i;

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_echo (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_ECHO pEcho)
{
	PFVOID s, e;
	byte b;
	word w;
	word min;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pEcho->count);
	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 1, -1);

	min = MIN (w, pEcho->data_size);
	RTSMB_READ_ITEM (pEcho->data, min);
	pEcho->data_size = min;

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_session_setup_and_x_pre_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_PRE_NT pSession)
{
	PFVOID s, e, stated_end, bend;
	byte b;
	word w, passsize;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 10, -1);

	RTSMB_READ_BYTE (&pSession->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);	/* stated offset to next command */
	stated_end = PADD (origin, w);

	RTSMB_READ_WORD (&pSession->max_buffer_size);
	RTSMB_READ_WORD (&pSession->max_mpx_count);
	RTSMB_READ_WORD (&pSession->vc_number);
	RTSMB_READ_DWORD (&pSession->session_id);
	RTSMB_READ_WORD (&passsize);
	RTSMB_READ_SKIP (4);	/* reserved */

	RTSMB_READ_WORD (&w);	/* byte count */

	bend = PADD (buf, w);

	if (passsize == 0 && pSession->password_size > 0 && pSession->password)
	{
		pSession->password[0] = '\0';
	}
	else
	{
		ASSURE (passsize <= pSession->password_size, -1);
		pSession->password_size = passsize;
		RTSMB_READ_ITEM (pSession->password, pSession->password_size);
	}

	if (PDIFF (bend, buf) > 0)
	{
		RTSMB_READ_STRING (pSession->account_name, pSession->account_name_size, RTSMB_READ_ANY);
	}
	else if (pSession->account_name && pSession->account_name_size > 0)
	{
		pSession->account_name[0] = '\0';
	}

	if (PDIFF (bend, buf) > 0)
	{
		RTSMB_READ_STRING (pSession->primary_domain, pSession->primary_domain_size, RTSMB_READ_ANY);
	}
	else if (pSession->primary_domain && pSession->primary_domain_size > 0)
	{
		pSession->primary_domain[0] = '\0';
	}

	if (PDIFF (bend, buf) > 0)
	{
		RTSMB_READ_STRING (pSession->native_os, pSession->native_os_size, RTSMB_READ_ANY);
	}
	else if (pSession->native_os && pSession->native_os_size > 0)
	{
		pSession->native_os[0] = '\0';
	}

	if (PDIFF (bend, buf) > 0)
	{
		RTSMB_READ_STRING (pSession->native_lan_man, pSession->native_lan_man_size, RTSMB_READ_ANY);
	}
	else if (pSession->native_lan_man && pSession->native_lan_man_size > 0)
	{
		pSession->native_lan_man[0] = '\0';
	}

	if (pSession->next_command != SMB_COM_NONE)
	{
		ASSURE (PDIFF (stated_end, buf) >= 0, -1);
		RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (stated_end, buf)));
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_session_setup_and_x_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_NT pSession)
{
	PFVOID s, e, stated_end, bend;
	byte b;
	word w;
	word asize, usize; /* ansi and unicode password sizes from packet */

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 13, -1);

	RTSMB_READ_BYTE (&pSession->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);	/* stated offset to next command */
	stated_end = PADD (origin, w);

	RTSMB_READ_WORD (&pSession->max_buffer_size);
	RTSMB_READ_WORD (&pSession->max_mpx_count);
	RTSMB_READ_WORD (&pSession->vc_number);
	RTSMB_READ_DWORD (&pSession->session_id);
	RTSMB_READ_WORD (&asize);	/* ansi password size */
	RTSMB_READ_WORD (&usize); /* unicode password size */
	RTSMB_READ_SKIP (4);	/* reserved */
	RTSMB_READ_DWORD (&pSession->capabilities);

	RTSMB_READ_WORD (&w);	/* byte count */

	bend = PADD (buf, w);

	if (asize == 0 && pSession->ansi_password_size > 0 && pSession->ansi_password)
	{
		pSession->ansi_password[0] = '\0';
	}
	else
	{
		ASSURE (asize <= pSession->ansi_password_size, -1);
		pSession->ansi_password_size = asize;
		RTSMB_READ_ITEM (pSession->ansi_password, pSession->ansi_password_size);
	}

	if (usize == 0 && pSession->unicode_password_size > 0 && pSession->unicode_password)
	{
		pSession->unicode_password[0] = '\0';
	}
	else
	{
		ASSURE (usize <= pSession->unicode_password_size, -1);
		pSession->unicode_password_size = usize;
		RTSMB_READ_ITEM (pSession->unicode_password, pSession->unicode_password_size);
	}

	if (PDIFF (bend, buf) > 0)
	{
		RTSMB_READ_STRING (pSession->account_name, pSession->account_name_size, RTSMB_READ_ANY);
	}
	else if (pSession->account_name && pSession->account_name_size > 0)
	{
		pSession->account_name[0] = '\0';
	}

	if (PDIFF (bend, buf) > 0)
	{
		RTSMB_READ_STRING (pSession->primary_domain, pSession->primary_domain_size, RTSMB_READ_ANY);
	}
	else if (pSession->primary_domain && pSession->primary_domain_size > 0)
	{
		pSession->primary_domain[0] = '\0';
	}

	if (PDIFF (bend, buf) > 0)
	{
		RTSMB_READ_STRING (pSession->native_os, pSession->native_os_size, RTSMB_READ_ANY);
	}
	else if (pSession->native_os && pSession->native_os_size > 0)
	{
		pSession->native_os[0] = '\0';
	}

	if (PDIFF (bend, buf) > 0)
	{
		RTSMB_READ_STRING (pSession->native_lan_man, pSession->native_lan_man_size, RTSMB_READ_ANY);
	}
	else if (pSession->native_lan_man && pSession->native_lan_man_size > 0)
	{
		pSession->native_lan_man[0] = '\0';
	}

	if (pSession->next_command != SMB_COM_NONE)
	{
		ASSURE (PDIFF (stated_end, buf) >= 0, -1);
		RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (stated_end, buf)));
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_logoff_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOGOFF_AND_X pLogoff)
{
	PFVOID s, e, stated_end;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 2, -1);

	RTSMB_READ_BYTE (&pLogoff->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);	/* stated offset to next command */
	stated_end = PADD (origin, w);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	if (pLogoff->next_command != SMB_COM_NONE)
	{
		ASSURE (PDIFF (stated_end, buf) >= 0, -1);
		RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (stated_end, buf)));
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_locking_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOCKING_AND_X pLocking)
{
	PFVOID s, e, stated_end;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 8, -1);

	RTSMB_READ_BYTE (&pLocking->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);	/* stated offset to next command */
	stated_end = PADD (origin, w);

	RTSMB_READ_WORD (&pLocking->fid);
	RTSMB_READ_BYTE (&pLocking->lock_type);
	RTSMB_READ_BYTE (&pLocking->oplock_level);
	RTSMB_READ_DWORD (&pLocking->timeout);
	RTSMB_READ_WORD (&pLocking->num_unlocks);
	RTSMB_READ_WORD (&pLocking->num_locks);

	RTSMB_READ_WORD (&w);	/* byte count */

	/* We don't bother reading the lock info.  For one, we
	   don't use it yet.  For another, that's best left to
	   another function to grab each info one at a time. */
	RTSMB_READ_SKIP (w);

	if (pLocking->next_command != SMB_COM_NONE)
	{
		ASSURE (PDIFF (stated_end, buf) >= 0, -1);
		RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (stated_end, buf)));
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_tree_connect_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_AND_X pTree)
{
	PFVOID s, e, stated_end;
	byte b;
	word w;
	word psize;

	s = buf;
	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 4, -1);

	RTSMB_READ_BYTE (&pTree->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);	/* stated offset to next command */
	stated_end = PADD (origin, w);

	RTSMB_READ_WORD (&pTree->flags);
	RTSMB_READ_WORD (&psize);

	RTSMB_READ_WORD (&w);	/* byte count */

	ASSURE (psize <= pTree->password_size, -1);
	pTree->password_size = psize;
	RTSMB_READ_ITEM (pTree->password, pTree->password_size);
	RTSMB_READ_STRING (pTree->share, pTree->share_size, RTSMB_READ_ANY);
	RTSMB_READ_STRING (pTree->service, pTree->service_size, RTSMB_READ_ASCII);


	if (pTree->next_command != SMB_COM_NONE)
	{
		ASSURE (PDIFF (stated_end, buf) >= 0, -1);
		RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (stated_end, buf)));
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_read_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X pRead)
{
	PFVOID s, e, stated_end;
	byte b;
	word w;
	dword d;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 10 || b == 12, -1);

	RTSMB_READ_BYTE (&pRead->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);	/* stated offset to next command */
	stated_end = PADD (origin, w);

	RTSMB_READ_WORD (&pRead->fid);
	RTSMB_READ_DWORD (&pRead->offset);

	RTSMB_READ_WORD (&w);	/* low 16 bits of max_count */
	pRead->max_count = w;
	RTSMB_READ_SKIP (2);	/* min count; reserved for old requests */
	RTSMB_READ_DWORD (&d);	/* high 16 bits of max_count */
	/* spec says upper bits must be 0 if you don't support this, but some clients don't
	   do that and instead send all 1's.  We check for that here. */
	if (d != 0xFFFFFFFF)
	{
		pRead->max_count |= (d << 16);
	}
	RTSMB_READ_SKIP (2);	/* remaining; reserved for old requests */

	if (b == 12)
	{
		RTSMB_READ_DWORD (&pRead->offset_high);
	}
	else
		pRead->offset_high = 0;

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	if (pRead->next_command != SMB_COM_NONE)
	{
		ASSURE (PDIFF (stated_end, buf) >= 0, -1);
		RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (stated_end, buf)));
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_write_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_X pWrite)
{
	PFVOID s, e, stated_end, pdataoffset;
	byte b;
	word w;
	dword receive_size;

	receive_size = pWrite->data_size;
	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 12 || b == 14, -1);

	RTSMB_READ_BYTE (&pWrite->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);	/* stated offset to next command */
	stated_end = PADD (origin, w);

	RTSMB_READ_WORD (&pWrite->fid);
	RTSMB_READ_DWORD (&pWrite->offset);

	RTSMB_READ_SKIP (4);	/* reserved */
	RTSMB_READ_WORD (&pWrite->write_mode);
	RTSMB_READ_SKIP (2);	/* bytes remaining for request */
	RTSMB_READ_WORD (&w);	/* high 16 bits of dataLength */
	pWrite->data_size = 0;
	pWrite->data_size |= ((dword)w << 16);
	RTSMB_READ_WORD (&w);	/* low 16 bits of dataLength */
	pWrite->data_size |= w;
	RTSMB_READ_WORD (&w);	/* data offset */
	pdataoffset = PADD (origin, w);

	if (b == 14)
	{
		RTSMB_READ_DWORD (&pWrite->offset_high);
	}
	else
		pWrite->offset_high = 0;

	RTSMB_READ_WORD (&w);	/* byte count */

	ASSURE (pdataoffset >= buf, -1);
	RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (pdataoffset, buf)));

	receive_size = MIN (pWrite->data_size, receive_size);
	RTSMB_READ_ITEM (pWrite->data, receive_size);

	if (pWrite->next_command != SMB_COM_NONE)
	{
		ASSURE (PDIFF (stated_end, buf) >= 0, -1);
		RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (stated_end, buf)));
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_open_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_AND_X pOpen)
{
	PFVOID s, e, stated_end;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 15, -1);

	RTSMB_READ_BYTE (&pOpen->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);	/* stated offset to next command */
	stated_end = PADD (origin, w);

	RTSMB_READ_WORD (&pOpen->flags);
	RTSMB_READ_WORD (&pOpen->desired_access);
	RTSMB_READ_WORD (&pOpen->search_attributes);
	RTSMB_READ_WORD (&pOpen->file_attributes);
	RTSMB_READ_DWORD (&pOpen->creation_time);
	RTSMB_READ_WORD (&pOpen->open_function);
	RTSMB_READ_DWORD (&pOpen->allocation_size);
	RTSMB_READ_SKIP (8);	/* reserved */

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w > 0, -1);

/*	Spec says a buffer format byte here, but in practice, it is not sent.
	RTSMB_READ_BYTE (&b);
	ASSURE (b == SMB_BF_ASCII, -1);*/

	RTSMB_READ_STRING (pOpen->filename, pOpen->filename_size, RTSMB_READ_ANY);

	if (pOpen->next_command != SMB_COM_NONE)
	{
		ASSURE (PDIFF (stated_end, buf) >= 0, -1);
		RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (stated_end, buf)));
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_tree_disconnect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_read_no_op (buf, size);
}

int srv_cmd_read_create_temporary (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE_TEMPORARY pTemp)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 3, -1);

	RTSMB_READ_SKIP (2);	/* reserved */
	RTSMB_READ_DWORD (&pTemp->creation_time);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 2, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);

	RTSMB_READ_STRING (pTemp->directory, pTemp->directory_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_seek (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEEK pSeek)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 4, -1);

	RTSMB_READ_WORD (&pSeek->fid);
	RTSMB_READ_WORD (&pSeek->mode);
	RTSMB_READ_DWORD (&pSeek->offset);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_flush (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FLUSH pFlush)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pFlush->fid);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CLOSE pClose)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 3, -1);

	RTSMB_READ_WORD (&pClose->fid);
	RTSMB_READ_DWORD (&pClose->last_write_time);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_close_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CLOSE_PRINT_FILE pClose)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pClose->fid);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_delete (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_DELETE pDelete)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pDelete->search_attributes);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 2, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pDelete->filename, pDelete->filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_rename (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RENAME pRename)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pRename->search_attributes);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 4, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pRename->old_filename, pRename->old_filename_size, RTSMB_READ_ANY);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pRename->new_filename, pRename->new_filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_move (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_MOVE pMove)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 3, -1);

	RTSMB_READ_WORD (&pMove->tid2);
	RTSMB_READ_WORD (&pMove->open_function);
	RTSMB_READ_WORD (&pMove->flags);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 4, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pMove->old_filename, pMove->old_filename_size, RTSMB_READ_ANY);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pMove->new_filename, pMove->new_filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_copy (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_COPY pCopy)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 3, -1);

	RTSMB_READ_WORD (&pCopy->tid2);
	RTSMB_READ_WORD (&pCopy->open_function);
	RTSMB_READ_WORD (&pCopy->flags);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 4, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pCopy->old_filename, pCopy->old_filename_size, RTSMB_READ_ANY);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pCopy->new_filename, pCopy->new_filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_delete_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_DELETE_DIRECTORY pDelete)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 0, -1);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 2, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pDelete->directory, pDelete->directory_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_check_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CHECK_DIRECTORY pCheck)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 0, -1);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 2, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pCheck->directory, pCheck->directory_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_create_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE_DIRECTORY pCreate)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 0, -1);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 2, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pCreate->directory, pCreate->directory_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_find_close2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_CLOSE2 pClose)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pClose->sid);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_open_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_PRINT_FILE pOpen)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 2, -1);

	RTSMB_READ_WORD (&pOpen->setup_length);
	RTSMB_READ_WORD (&pOpen->mode);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 2, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pOpen->identifier, pOpen->identifier_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_create (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE pCreate)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 3, -1);

	RTSMB_READ_WORD (&pCreate->file_attributes);
	RTSMB_READ_DWORD (&pCreate->creation_time);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 2, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pCreate->filename, pCreate->filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_open (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN pOpen)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 2, -1);

	RTSMB_READ_WORD (&pOpen->desired_access);
	RTSMB_READ_WORD (&pOpen->search_attributes);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 2, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pOpen->filename, pOpen->filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_query_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_INFORMATION pQuery)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 0, -1);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 2, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pQuery->filename, pQuery->filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_query_information2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_INFORMATION2 pQuery)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pQuery->fid);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_read (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ pRead)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 5, -1);

	RTSMB_READ_WORD (&pRead->fid);
	RTSMB_READ_WORD (&pRead->count);
	RTSMB_READ_DWORD (&pRead->offset);
	RTSMB_READ_WORD (&pRead->remaining);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_read_raw (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_RAW pRead)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 8 || b == 10, -1);

	RTSMB_READ_WORD (&pRead->fid);
	RTSMB_READ_DWORD (&pRead->offset);
	RTSMB_READ_WORD (&pRead->max_count);
	RTSMB_READ_WORD (&pRead->min_count);
	RTSMB_READ_DWORD (&pRead->timeout);
	RTSMB_READ_SKIP (2);	/* reserved */

	if (b == 10)	/* if we are reading a large offset request */
	{
		RTSMB_READ_DWORD (&pRead->offset_high);
		pRead->valid_offset_high = TRUE;
	}
	else
	{
		pRead->offset_high = 0;
		pRead->valid_offset_high = FALSE;
	}

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_search (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEARCH pSearch)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 2, -1);

	RTSMB_READ_WORD (&pSearch->max_count);
	RTSMB_READ_WORD (&pSearch->search_attributes);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 5, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pSearch->filename, pSearch->filename_size, RTSMB_READ_ANY);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_VARIABLE, -1);

	RTSMB_READ_WORD (&w);	/* resume key size */

	if (w == 0)
	{
		pSearch->valid_resume_key = FALSE;
	}
	else
	{
		pSearch->valid_resume_key = TRUE;

		RTSMB_READ_BYTE (&pSearch->resume_key.reserved);
		RTSMB_READ_ITEM (pSearch->resume_key.filename, 11);
		RTSMB_READ_ITEM (pSearch->resume_key.server_data, 5);
		RTSMB_READ_ITEM (pSearch->resume_key.client_data, 4);
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_set_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SET_INFORMATION pSet)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 8, -1);

	RTSMB_READ_WORD (&pSet->file_attributes);
	RTSMB_READ_DWORD (&pSet->last_write_time);
	RTSMB_READ_SKIP (10);	/* reserved */

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 2, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pSet->filename, pSet->filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_set_information2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SET_INFORMATION2 pSet)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 7, -1);

	RTSMB_READ_WORD (&pSet->fid);
	RTSMB_READ_WORD (&pSet->creation_date);
	RTSMB_READ_WORD (&pSet->creation_time);
	RTSMB_READ_WORD (&pSet->last_access_date);
	RTSMB_READ_WORD (&pSet->last_access_time);
	RTSMB_READ_WORD (&pSet->last_write_date);
	RTSMB_READ_WORD (&pSet->last_write_time);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w == 0, -1);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_query_information_disk (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_read_no_op (buf, size);
}

int srv_cmd_read_tree_connect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT pTree)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 0, -1);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 4, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pTree->share, pTree->share_size, RTSMB_READ_ANY);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pTree->password, pTree->password_size, RTSMB_READ_ASCII);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_ASCII, -1);
	RTSMB_READ_STRING (pTree->service, pTree->service_size, RTSMB_READ_ASCII);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_write (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE pWrite)
{
	PFVOID s, e;
	byte b;
	word w, data_length;

	s = buf;

	//RTSMB_READ_BYTE (&b);	/* _yi_ */
	if (!(buf = rtsmb_read_byte (buf, &size, &b)))
		return -1;

	ASSURE (b == 5, -1);

	RTSMB_READ_WORD (&pWrite->fid);
	RTSMB_READ_WORD (&pWrite->count);
	RTSMB_READ_DWORD (&pWrite->offset);
	RTSMB_READ_WORD (&pWrite->remaining);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 3, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_DATA, -1);

	RTSMB_READ_WORD (&data_length);

	data_length = MIN (data_length, pWrite->data_size);
	RTSMB_READ_ITEM (pWrite->data, data_length);
	pWrite->data_size = data_length;

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_write_and_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_CLOSE pWrite)
{
	PFVOID s, e;
	byte b;
	word w, data_length;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 6 || b == 12, -1);

	RTSMB_READ_WORD (&pWrite->fid);
	RTSMB_READ_WORD (&pWrite->count);
	RTSMB_READ_DWORD (&pWrite->offset);
	RTSMB_READ_DWORD (&pWrite->last_write_time);

	if (b == 12)
	{
		RTSMB_READ_SKIP (6);	/* reserved */
	}

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 3, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_DATA, -1);

	RTSMB_READ_WORD (&data_length);

	data_length = MIN (data_length, pWrite->data_size);
	RTSMB_READ_ITEM (pWrite->data, data_length);
	pWrite->data_size = data_length;

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_write_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_PRINT_FILE pWrite)
{
	PFVOID s, e;
	byte b;
	word w, data_length;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pWrite->fid);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= 4, -1);

	RTSMB_READ_BYTE (&b);	/* buffer format */
	ASSURE (b == SMB_BF_DATA, -1);

	RTSMB_READ_WORD (&data_length);

	ASSURE (data_length <= pWrite->data_size, -1);	/* we must have room */
	RTSMB_READ_ITEM (pWrite->data, data_length);
	pWrite->data_size = data_length;

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_write_raw (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW pWrite)
{
	PFVOID s, e;
	byte b;
	word w, data_length, data_offset;
	int skip_bytes;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 12 || b == 14, -1);

	RTSMB_READ_WORD (&pWrite->fid);
	RTSMB_READ_WORD (&pWrite->count);
	RTSMB_READ_SKIP (2);	/* reserved */
	RTSMB_READ_DWORD (&pWrite->offset);
	RTSMB_READ_DWORD (&pWrite->timeout);
	RTSMB_READ_WORD (&pWrite->write_mode);
	RTSMB_READ_SKIP (4);	/* reserved */
	RTSMB_READ_WORD (&data_length);
	RTSMB_READ_WORD (&data_offset);

	if (b == 14)	/* high offset */
	{
		RTSMB_READ_DWORD (&pWrite->offset_high);
		pWrite->valid_offset_high = TRUE;
	}
	else
	{
		pWrite->offset_high = 0;
		pWrite->valid_offset_high = FALSE;
	}

	RTSMB_READ_WORD (&w);	/* byte count */

	skip_bytes = PDIFF (PADD (origin, data_offset), buf);
	ASSURE (skip_bytes >= 0, -1);	/* can't point to stuff we've passed */
	RTSMB_READ_SKIP ((rtsmb_size)skip_bytes);

	ASSURE (data_length <= pWrite->data_size, -1);	/* we must have room */
	RTSMB_READ_ITEM (pWrite->data, data_length);
	pWrite->data_size = data_length;

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_process_exit (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return srv_cmd_read_no_op (buf, size);
}

int srv_cmd_read_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION pTransaction)
{
	PFVOID s, e;
	byte b;
	word w;
	word possible_setups;
	int i;

	possible_setups = pTransaction->setup_size;
	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b >= 14, -1);

	RTSMB_READ_WORD (&pTransaction->parameter_count);
	RTSMB_READ_WORD (&pTransaction->data_count);
	RTSMB_READ_WORD (&pTransaction->max_parameter_count);
	RTSMB_READ_WORD (&pTransaction->max_data_count);
	RTSMB_READ_BYTE (&pTransaction->max_setup_count);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&pTransaction->flags);
	RTSMB_READ_DWORD (&pTransaction->timeout);
	RTSMB_READ_SKIP (2);	/* reserved */
	RTSMB_READ_SKIP (2);	/* parameter bytes this message */
	RTSMB_READ_WORD (&pTransaction->parameter_offset);
	RTSMB_READ_SKIP (2);	/* data bytes this message */
	RTSMB_READ_WORD (&pTransaction->data_offset);
	RTSMB_READ_BYTE (&pTransaction->setup_size);
	RTSMB_READ_SKIP (1);	/* reserved */

	ASSURE (possible_setups >= pTransaction->setup_size, -1);
	for (i = 0; i < pTransaction->setup_size; i++)
	{
		RTSMB_READ_WORD (&pTransaction->setup[i]);
	}

	RTSMB_READ_WORD (&w);	/* byte count */

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_query_fs_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_QUERY_FS_INFORMATION pQuery)
{
	PFVOID s, e, place;

	s = buf;

	place = PADD (origin, pQuery->parent->parameter_offset);
	ASSURE (place >= buf, -1);
	ASSURE (place < PADD (buf, size), -1);

	RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (place, buf)));

	RTSMB_READ_WORD (&pQuery->information_level);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_find_first2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_FIRST2 pFind)
{
	PFVOID s, e, place;

	s = buf;

	/* get parameters */
	place = PADD (origin, pFind->parent->parameter_offset);
	ASSURE (place < PADD (buf, size), -1);
	RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (place, buf)));

	RTSMB_READ_WORD (&pFind->search_attributes);
	RTSMB_READ_WORD (&pFind->search_count);
	RTSMB_READ_WORD (&pFind->flags);
	RTSMB_READ_WORD (&pFind->information_level);
	RTSMB_READ_DWORD (&pFind->search_storage_type);
	RTSMB_READ_STRING (pFind->filename, pFind->filename_size, RTSMB_READ_ANY);

	/* get data */
	if (pFind->parent->data_count)
	{
		ASSURE (pFind->data_size >= pFind->parent->data_count, -1);

		place = PADD (origin, pFind->parent->data_offset);
		ASSURE (place < PADD (buf, size), -1);
		RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (place, buf)));

		RTSMB_READ_ITEM (pFind->data, pFind->parent->data_count);
		pFind->data_size = pFind->parent->data_count;
	}
	else
	{
		pFind->data_size = 0;
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_find_next2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_NEXT2 pFind)
{
	PFVOID s, e, place;

	s = buf;

	/* get parameters */
	place = PADD (origin, pFind->parent->parameter_offset);
	ASSURE (place < PADD (buf, size), -1);
	RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (place, buf)));

	RTSMB_READ_WORD (&pFind->sid);
	RTSMB_READ_WORD (&pFind->search_count);
	RTSMB_READ_WORD (&pFind->information_level);
	RTSMB_READ_DWORD (&pFind->resume_key);
	RTSMB_READ_WORD (&pFind->flags);
	RTSMB_READ_STRING (pFind->filename, pFind->filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_query_file_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_QUERY_FILE_INFORMATION pQuery)
{
	PFVOID s, e, place;

	s = buf;

	/* get parameters */
	place = PADD (origin, pQuery->parent->parameter_offset);
	ASSURE (place < PADD (buf, size), -1);
	RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (place, buf)));

	RTSMB_READ_WORD (&pQuery->fid);
	RTSMB_READ_WORD (&pQuery->information_level);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_query_path_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_QUERY_PATH_INFORMATION pQuery)
{
	PFVOID s, e, place;

	s = buf;

	/* get parameters */
	place = PADD (origin, pQuery->parent->parameter_offset);
	ASSURE (place < PADD (buf, size), -1);
	RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (place, buf)));

	RTSMB_READ_WORD (&pQuery->information_level);
	RTSMB_READ_SKIP (4);	/* reserved */
	RTSMB_READ_STRING (pQuery->filename, pQuery->filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_trans2_set_path_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_SET_PATH_INFORMATION pSet)
{
	PFVOID s, e, place;

	s = buf;

	/* get parameters */
	place = PADD (origin, pSet->parent->parameter_offset);
	ASSURE (place < PADD (buf, size), -1);
	RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (place, buf)));

	RTSMB_READ_WORD (&pSet->information_level);
	RTSMB_READ_SKIP (4);	/* reserved */
	RTSMB_READ_STRING (pSet->filename, pSet->filename_size, RTSMB_READ_ANY);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_trans2_set_file_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_SET_FILE_INFORMATION pSet)
{
	PFVOID s, e, place;

	s = buf;

	/* get parameters */
	place = PADD (origin, pSet->parent->parameter_offset);
	ASSURE (place < PADD (buf, size), -1);
	RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (place, buf)));

	RTSMB_READ_WORD (&pSet->fid);
	RTSMB_READ_WORD (&pSet->information_level);
	RTSMB_READ_SKIP (2);	/* reserved */

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_info_standard (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_STANDARD pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_READ_WORD (&pInfo->creation_date);
	RTSMB_READ_WORD (&pInfo->creation_time);
	RTSMB_READ_WORD (&pInfo->last_access_date);
	RTSMB_READ_WORD (&pInfo->last_access_time);
	RTSMB_READ_WORD (&pInfo->last_write_date);
	RTSMB_READ_WORD (&pInfo->last_write_time);
	RTSMB_READ_DWORD (&pInfo->file_size);
	RTSMB_READ_DWORD (&pInfo->allocation_size);
	RTSMB_READ_WORD (&pInfo->attributes);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_allocation_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FILE_ALLOCATION_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_READ_DWORD (&pInfo->low_allocation_size);
	RTSMB_READ_DWORD (&pInfo->high_allocation_size);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_end_of_file_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FILE_END_OF_FILE_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_READ_DWORD (&pInfo->low_end_of_file);
	RTSMB_READ_DWORD (&pInfo->high_end_of_file);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_basic_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_BASIC_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_READ_DWORD (&pInfo->low_creation_time);
	RTSMB_READ_DWORD (&pInfo->high_creation_time);
	RTSMB_READ_DWORD (&pInfo->low_last_access_time);
	RTSMB_READ_DWORD (&pInfo->high_last_access_time);
	RTSMB_READ_DWORD (&pInfo->low_last_write_time);
	RTSMB_READ_DWORD (&pInfo->high_last_write_time);
	RTSMB_READ_DWORD (&pInfo->low_change_time);
	RTSMB_READ_DWORD (&pInfo->high_change_time);
	RTSMB_READ_WORD (&pInfo->attributes);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_rap_request (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_REQUEST pRAP)
{
	PFVOID s, e, place;

	s = buf;

	/* get parameters */
	place = PADD (origin, pRAP->parent->parameter_offset);
	ASSURE (place < PADD (buf, size), -1);
	RTSMB_READ_SKIP ((rtsmb_size)(PDIFF (place, buf)));

	RTSMB_READ_WORD (&pRAP->opcode);
	RTSMB_READ_STRING (pRAP->parameter, pRAP->parameter_size, RTSMB_READ_ASCII);
	RTSMB_READ_STRING (pRAP->answer, pRAP->answer_size, RTSMB_READ_ASCII);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_rap_get_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_GET_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_READ_WORD (&pInfo->information_level);
	RTSMB_READ_WORD (&pInfo->receive_size);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_rap_server_enum2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_ENUM2 penum)
{
	PFVOID s, e;

	s = buf;

	RTSMB_READ_WORD (&penum->information_level);
	RTSMB_READ_WORD (&penum->receive_size);
	RTSMB_READ_DWORD (&penum->server_type);

	/* it's possible that domain is non-existant in buffer, which should be treated
	   as an empty string */
	if (size == 0 && penum->domain && penum->domain_size > 0)
	{
		penum->domain[0] = '\0';
	}
	else
	{
		RTSMB_READ_STRING (penum->domain, penum->domain_size, RTSMB_READ_ASCII);
	}

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_rap_share_get_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SHARE_GET_INFO pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_READ_STRING (pInfo->share, pInfo->share_size, RTSMB_READ_ASCII);
	RTSMB_READ_WORD (&pInfo->information_level);
	RTSMB_READ_WORD (&pInfo->receive_size);

	e = buf;

	return PDIFF (e, s);
}

int srv_cmd_read_nt_create_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NT_CREATE_AND_X pCreate)
{
	PFVOID s, e, stated_end;
	byte b;
	word w, name_size;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 24, -1);

	RTSMB_READ_BYTE (&pCreate->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);	/* stated offset to next command */
	stated_end = PADD (origin, w);

	RTSMB_READ_SKIP (1);	/* reserved */

	RTSMB_READ_WORD (&name_size);
	ASSURE (pCreate->filename_size >= name_size, -1);

	RTSMB_READ_DWORD (&pCreate->flags);
	RTSMB_READ_DWORD (&pCreate->root_directory_fid);
	RTSMB_READ_DWORD (&pCreate->desired_access);
	RTSMB_READ_DWORD (&pCreate->allocation_size_low);
	RTSMB_READ_DWORD (&pCreate->allocation_size_high);
	RTSMB_READ_DWORD (&pCreate->ext_file_attributes);
	RTSMB_READ_DWORD (&pCreate->share_access);
	RTSMB_READ_DWORD (&pCreate->create_disposition);
	RTSMB_READ_DWORD (&pCreate->create_options);
	RTSMB_READ_DWORD (&pCreate->impersonation_level);
	RTSMB_READ_BYTE (&pCreate->security_flags);

	RTSMB_READ_WORD (&w);	/* byte count */
	ASSURE (w >= name_size, -1);	/* they promised a certain size */

	RTSMB_READ_STRING (pCreate->filename, pCreate->filename_size, RTSMB_READ_ANY);
	pCreate->filename_size = name_size;

	if (pCreate->next_command != SMB_COM_NONE)
	{
		ASSURE (PDIFF (stated_end, buf) >= 0, -1);
		RTSMB_READ_SKIP ( (rtsmb_size)(PDIFF (stated_end, buf)));
	}

	e = buf;

	return PDIFF (e, s);
}

#endif /* INCLUDE_RTSMB_SERVER */
