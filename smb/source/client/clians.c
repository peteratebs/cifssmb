//
// CLIANS.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  [tbd]
//

#include "smbdefs.h"
#if (INCLUDE_RTSMB_CLIENT)

#include "clians.h"
#include "smbread.h"
#include "smbpack.h"
#include "smbutil.h"


RTSMB_STATIC
int cli_cmd_read_no_op (PFVOID buf, rtsmb_size size)
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

	return (int) PDIFF (e, s);
}

int cli_cmd_read_header (PFVOID origin, PFVOID buf, rtsmb_size size,
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
    {
		return -1;
    }

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

	pHeader->pid = (((dword)pidHigh) << 16) | (dword)pidLow;

	e = buf;

	return (int) PDIFF (e, s);
}

RTSMB_STATIC
int cli_cmd_read_negotiate_pre_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE_R pNegotiateR)
{
	PFVOID s, e;
	word key_length;
	byte b;
	word w, stated_key_length;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	if (b != 13)
		return -1;

	pNegotiateR->capabilities = 0;

	/* we adjust the size of some of the incoming parameters
	   because we are using one struct for two dialects of the
	   negotiate response */
	RTSMB_READ_WORD (&pNegotiateR->dialect_index);
	RTSMB_READ_WORD (&w);	/* security_mode */
	pNegotiateR->security_mode = (byte) w;
	RTSMB_READ_WORD (&w);	/* max_buffer_size */
	pNegotiateR->max_buffer_size = w;
	RTSMB_READ_WORD (&pNegotiateR->max_mpx_count);
	RTSMB_READ_WORD (&pNegotiateR->max_vcs);
	RTSMB_READ_WORD (&w);	/* max_raw_size */
	switch (w)
	{
	case 3:	pNegotiateR->max_raw_size = 0xFFFF;	/* presumably what the default is */
			break;
	default:
			pNegotiateR->max_raw_size = 0;
			break;
	}
	RTSMB_READ_DWORD (&pNegotiateR->session_id);
	RTSMB_READ_WORD (&w);	/* time, not used now */
	RTSMB_READ_WORD (&w);	/* date, not used now */
	RTSMB_READ_WORD (&pNegotiateR->time_zone);
	RTSMB_READ_WORD (&stated_key_length);	/* challenge key length */
	RTSMB_READ_WORD (&w); /* reserved */
	RTSMB_READ_WORD (&w); /* byte count */

	key_length = MIN (stated_key_length, pNegotiateR->challenge_size);
	RTSMB_READ_ITEM (&pNegotiateR->challenge, key_length);
	pNegotiateR->challenge_size = (byte) key_length & 0xFF;	/* we only do 8-byte challenges right now */

	RTSMB_READ_STRING (pNegotiateR->domain, pNegotiateR->domain_size, 0);
	pNegotiateR->valid_domain = TRUE;

	if (pNegotiateR->max_raw_size)
	{
		TURN_ON (pNegotiateR->capabilities, CAP_RAW_MODE);
	}

	pNegotiateR->valid_guid = FALSE;
	pNegotiateR->time_low = pNegotiateR->time_high = 0;

	e = buf;

	return (int) PDIFF (e, s);
}

RTSMB_STATIC
int cli_cmd_read_negotiate_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE_R pNegotiateR)
{
	PFVOID s, e;
	byte key_length;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	if (b != 17)
		return -1;

	RTSMB_READ_WORD (&pNegotiateR->dialect_index);
	RTSMB_READ_BYTE (&pNegotiateR->security_mode);
	RTSMB_READ_WORD (&pNegotiateR->max_mpx_count);
	RTSMB_READ_WORD (&pNegotiateR->max_vcs);
	RTSMB_READ_DWORD (&pNegotiateR->max_buffer_size);
	RTSMB_READ_DWORD (&pNegotiateR->max_raw_size);
	RTSMB_READ_DWORD (&pNegotiateR->session_id);
	RTSMB_READ_DWORD (&pNegotiateR->capabilities);
	RTSMB_READ_DWORD (&pNegotiateR->time_low);
	RTSMB_READ_DWORD (&pNegotiateR->time_high);
	RTSMB_READ_WORD (&pNegotiateR->time_zone);
	RTSMB_READ_BYTE (&b);	/* challenge key length */
	RTSMB_READ_WORD (&w); /* byte count */

	/* guid is only present if extended security is on */
	if (ON (pNegotiateR->capabilities, CAP_EXTENDED_SECURITY))
	{
		RTSMB_READ_ITEM (&pNegotiateR->guid, 16);
		pNegotiateR->valid_guid = TRUE;
		w = (word) (w - 16);
	}
	else
	{
		pNegotiateR->valid_guid = FALSE;
	}

	key_length = MIN (b, pNegotiateR->challenge_size);
	RTSMB_READ_ITEM (pNegotiateR->challenge, key_length);
	pNegotiateR->challenge_size = key_length;

	/* domain is only present if extended security is off */
	if (OFF (pNegotiateR->capabilities, CAP_EXTENDED_SECURITY))
	{
		RTSMB_READ_STRING (pNegotiateR->domain, pNegotiateR->domain_size, 1);
		pNegotiateR->valid_domain = TRUE;
	}
	else
	{
		pNegotiateR->valid_domain = FALSE;
	}

	e = buf;

	return (int) PDIFF (e, s);
}


int cli_cmd_read_negotiate (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE_R pNegotiateR)
{
	PFVOID buf_backup = buf;
	rtsmb_size size_backup = size;
	byte b;

	RTSMB_READ_BYTE (&b);

	switch (b)
	{
	case 13:
		return cli_cmd_read_negotiate_pre_nt (origin, buf_backup, size_backup, pHeader, pNegotiateR);

	case 17:
		return cli_cmd_read_negotiate_nt (origin, buf_backup, size_backup, pHeader, pNegotiateR);

	default:
		return -1;
	}
}

int cli_cmd_read_session_setup_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_R pSetupR)
{
	PFVOID s, e;
	byte b;
	word w, offset;
	RTP_ADDR diff;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	if (b != 3)
		return -1;

	RTSMB_READ_BYTE (&pSetupR->next_command);
	RTSMB_READ_BYTE (&b);	/* reserved */
	RTSMB_READ_WORD (&offset);
	RTSMB_READ_WORD (&w);	/* action */

	pSetupR->guest_logon = ON (w, 1);

	RTSMB_READ_WORD (&w); /* byte count */
	RTSMB_READ_STRING (pSetupR->srv_native_os, pSetupR->srv_native_os_size, 0);
	RTSMB_READ_STRING (pSetupR->srv_native_lan_man, pSetupR->srv_native_lan_man_size, 0);
	RTSMB_READ_STRING (pSetupR->srv_primary_domain, pSetupR->srv_primary_domain_size, 0);

	diff = PDIFF (PADD (origin, offset), buf);
	if (diff >= 0)	{RTSMB_READ_SKIP ((rtsmb_size)diff);}
	else			{return -1;}

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_session_setup_and_x_ext_sec (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_EXT_SEC_R pSetupR)
{
	PFVOID s, e;
	byte b;
	word w, offset;
	RTP_ADDR diff;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	if (b != 3)
		return -1;

	RTSMB_READ_BYTE (&pSetupR->next_command);
	RTSMB_READ_BYTE (&b);	/* reserved */
	RTSMB_READ_WORD (&offset);

	RTSMB_READ_WORD (&w);	/* action */
	pSetupR->guest_logon = ON (w, 1);

	RTSMB_READ_WORD (&w);	/* blob size */
	pSetupR->blob_size = w;
	RTSMB_READ_WORD (&w); /* byte count */
	RTSMB_READ_STRING (pSetupR->srv_native_os, pSetupR->srv_native_os_size, 0);
	RTSMB_READ_STRING (pSetupR->srv_native_lan_man, pSetupR->srv_native_lan_man_size, 0);
	RTSMB_READ_STRING (pSetupR->srv_primary_domain, pSetupR->srv_primary_domain_size, 0);

	diff = PDIFF (PADD (origin, offset), buf);
	if (diff >= 0)	{RTSMB_READ_SKIP ((rtsmb_size)diff);}
	else			{return -1;}

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_logoff_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOGOFF_AND_X_R pLogoffR)
{
	PFVOID s, e;
	byte b;
	word w, offset;
	RTP_ADDR diff;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	if (b != 2)
		return -1;

	RTSMB_READ_BYTE (&pLogoffR->next_command);
	RTSMB_READ_WORD (&offset);
	RTSMB_READ_WORD (&w); /* byte count */
	if (w != 0)
		return -1;

	diff = PDIFF (PADD (origin, offset), buf);
	if (diff >= 0)	{RTSMB_READ_SKIP ((rtsmb_size)diff);}
	else			{return -1;}

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_tree_connect_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_AND_X_R pTreeR)
{
	PFVOID s, e;
	byte b, word_count;
	word w, offset;
	RTP_ADDR diff;

	s = buf;

	RTSMB_READ_BYTE (&word_count);	/* word count */
	if (word_count != 3 && word_count != 2)
		return -1;

	RTSMB_READ_BYTE (&pTreeR->next_command);
	RTSMB_READ_BYTE (&b);	/* reserved */
	RTSMB_READ_WORD (&offset);

	if (word_count == 3)
	{
		RTSMB_READ_WORD (&pTreeR->optional_support);
	}
	else
	{
		pTreeR->optional_support = 0;
	}

	RTSMB_READ_WORD (&w); /* byte count */
	RTSMB_READ_STRING (pTreeR->service, pTreeR->service_size, -1);
	RTSMB_READ_STRING (pTreeR->native_fs, pTreeR->native_fs_size, 0);

	diff = PDIFF (PADD (origin, offset), buf);
	if (diff >= 0)	{RTSMB_READ_SKIP ((rtsmb_size)diff);}
	else			{return -1;}

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_tree_disconnect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return cli_cmd_read_no_op (buf, size);
}

int cli_cmd_read_echo (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_ECHO_R pEchoR)
{
	PFVOID s, e;
	byte b;
	word w;
	word read_data_size;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	if (b != 1)
		return -1;

	RTSMB_READ_WORD (&pEchoR->sequence_number);
	RTSMB_READ_WORD (&w); /* byte count */

	if (w > pEchoR->data_size)
		read_data_size = pEchoR->data_size;
	else
		read_data_size = w;

	RTSMB_READ_ITEM (pEchoR->data, read_data_size);
	RTSMB_READ_SKIP ((word) (w - read_data_size));

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_read_and_x_up_to_data (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X_R pReadR)
{
	PFVOID s, e;
	byte b;
	word w, data_offset;
	RTP_ADDR data_diff;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	if (b != 12)
		return -1;

	RTSMB_READ_BYTE (&pReadR->next_command);
	RTSMB_READ_BYTE (&b);	/* reserved */
	RTSMB_READ_WORD (&pReadR->offset);
	RTSMB_READ_WORD (&w);	/* remaining; reserved */
	RTSMB_READ_WORD (&w);	/* data compaction mode; reserved */
	RTSMB_READ_WORD (&w);	/* reserved */
	RTSMB_READ_WORD (&pReadR->real_data_length);

	if (pReadR->real_data_length <= pReadR->data_size)
		pReadR->data_size = pReadR->real_data_length;

	RTSMB_READ_WORD (&data_offset);
	RTSMB_READ_SKIP (10);	/* reserved */
	RTSMB_READ_WORD (&w); /* byte count */

	data_diff = PDIFF (PADD (origin, data_offset), buf);
	if (data_diff >= 0)
	{
		RTSMB_READ_SKIP ((rtsmb_size)data_diff);
	}
	else
	{
		return -1;
	}

	e = buf;

	return (int) PDIFF (e, s);
}


int cli_cmd_read_read_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X_R pReadR)
{
	PFVOID s, e;
	RTP_ADDR diff;
	int read_header_len;

	s = buf;

	read_header_len = cli_cmd_read_read_and_x_up_to_data(origin, buf, size, pHeader, pReadR);
	if (read_header_len < 0)
	{
		return -1;
	}

	buf = PADD(buf, read_header_len);
	size -= (rtsmb_size)read_header_len;

	RTSMB_READ_ITEM (pReadR->data, pReadR->data_size);

	if (pReadR->data_size < pReadR->real_data_length)
	{
		RTSMB_READ_SKIP (pReadR->real_data_length - pReadR->data_size);
	}

	diff = PDIFF (PADD (origin, pReadR->offset), buf);
	if (diff >= 0)
	{
		RTSMB_READ_SKIP ((rtsmb_size)diff);
	}
	else
	{
		return -1;
	}

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_open_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_AND_X_R pOpenR)
{
	PFVOID s, e, stated_end;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 15, -1);

	RTSMB_READ_BYTE (&pOpenR->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);
	stated_end = PADD (origin, w);
	RTSMB_READ_WORD (&pOpenR->fid);
	RTSMB_READ_WORD (&pOpenR->file_attributes);
	RTSMB_READ_DWORD (&pOpenR->last_write_time);
	RTSMB_READ_DWORD (&pOpenR->file_size);
	RTSMB_READ_WORD (&pOpenR->granted_access);
	RTSMB_READ_WORD (&pOpenR->file_type);
	RTSMB_READ_WORD (&pOpenR->device_state);
	RTSMB_READ_WORD (&pOpenR->action);
	RTSMB_READ_DWORD (&pOpenR->server_fid);
	RTSMB_READ_SKIP (2);

	RTSMB_READ_WORD (&w); /* byte count */
	ASSURE (w == 0, -1);

	ASSURE (PDIFF (stated_end, buf) >= 0, -1);
	RTSMB_READ_SKIP ((rtsmb_size) PDIFF (stated_end, buf));

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_create_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NT_CREATE_AND_X_R pCreateR)
{
	PFVOID s, e, stated_end;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 34, -1);

	RTSMB_READ_BYTE (&pCreateR->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);
	stated_end = PADD (origin, w);
	RTSMB_READ_BYTE (&pCreateR->oplock_level);
	RTSMB_READ_WORD (&pCreateR->fid);
	RTSMB_READ_DWORD (&pCreateR->create_action);
	RTSMB_READ_DWORD (&pCreateR->creation_time_low);
	RTSMB_READ_DWORD (&pCreateR->creation_time_high);
	RTSMB_READ_DWORD (&pCreateR->last_access_time_low);
	RTSMB_READ_DWORD (&pCreateR->last_access_time_high);
	RTSMB_READ_DWORD (&pCreateR->last_write_time_low);
	RTSMB_READ_DWORD (&pCreateR->last_write_time_high);
	RTSMB_READ_DWORD (&pCreateR->change_time_low);
	RTSMB_READ_DWORD (&pCreateR->change_time_high);
	RTSMB_READ_DWORD (&pCreateR->ext_file_attributes);
	RTSMB_READ_DWORD (&pCreateR->allocation_size_low);
	RTSMB_READ_DWORD (&pCreateR->allocation_size_high);
	RTSMB_READ_DWORD (&pCreateR->end_of_file_low);
	RTSMB_READ_DWORD (&pCreateR->end_of_file_high);
	RTSMB_READ_WORD (&pCreateR->file_type);
	RTSMB_READ_WORD (&pCreateR->device_state);
	RTSMB_READ_BYTE (&pCreateR->directory);

	RTSMB_READ_WORD (&w); /* byte count */
	ASSURE (w == 0, -1);

	ASSURE (PDIFF (stated_end, buf) >= 0, -1);
	RTSMB_READ_SKIP ((rtsmb_size) PDIFF (stated_end, buf));

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return cli_cmd_read_no_op (buf, size);
}

int cli_cmd_read_write_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_X_R pWriteR)
{
	PFVOID s, e, stated_end;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 6, -1);

	RTSMB_READ_BYTE (&pWriteR->next_command);
	RTSMB_READ_SKIP (1);	/* reserved */
	RTSMB_READ_WORD (&w);
	stated_end = PADD (origin, w);
	RTSMB_READ_WORD (&pWriteR->count);
	RTSMB_READ_SKIP (2);	/* remaining; reserved */
	RTSMB_READ_SKIP (4);	/* reserved */

	RTSMB_READ_WORD (&w); /* byte count */
	ASSURE (w == 0, -1)

	ASSURE (PDIFF (stated_end, buf) >= 0, -1);
	RTSMB_READ_SKIP ((rtsmb_size) PDIFF (stated_end, buf));

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_write_raw_r1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW_R1 pWriteR)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pWriteR->remaining);
	RTSMB_READ_WORD (&w);

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_write_raw_r2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW_R2 pWriteR)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pWriteR->count);
	RTSMB_READ_WORD (&w);

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_seek (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEEK_R pSeekR)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 2, -1);

	RTSMB_READ_DWORD (&pSeekR->offset);

	RTSMB_READ_WORD (&w); /* byte count */
	ASSURE (w == 0, -1)

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_write (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_R pWriteR)
{
	PFVOID s, e;
	byte b;
	word w;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b == 1, -1);

	RTSMB_READ_WORD (&pWriteR->count);

	RTSMB_READ_WORD (&w); /* byte count */
	ASSURE (w == 0, -1)

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION_R pTransactionR)
{
	PFVOID s, e;
	byte b;
	int i;

	s = buf;

	RTSMB_READ_BYTE (&b);	/* word count */
	ASSURE (b >= 10, -1);

	RTSMB_READ_SKIP((rtsmb_size)(b-1)*2);

	RTSMB_READ_BYTE (&b);	/* setup size */
	RTSMB_READ_SKIP (1);	/* reserved */

	ASSURE (b <= pTransactionR->setup_size, -1);	/* we must have room */
	pTransactionR->setup_size = b;

	for (i = 0; i < pTransactionR->setup_size; i++)
	{
		RTSMB_READ_WORD (&pTransactionR->setup[i]);
	}

	RTSMB_READ_SKIP (2);	/* byte count */

	e = buf;

	return (int) PDIFF (e, s);
}

#define RTRTSMB_READ_TRANS2_COUNT_OFFSET 39	/* the offset from origin to a transaction2's param count */
#define RTRTSMB_READ_TRANS1_COUNT_OFFSET 51	/* the offset from origin to a transaction's param count */

int cli_cmd_read_find_first2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_FIRST_R pFindR)
{
	PFVOID reals, s, e, allowed_end;
	word param_count, param_offset;
	word data_count, data_offset;
	rtsmb_size fake_size = 4;

	reals = buf;

	s = PADD (origin, RTRTSMB_READ_TRANS2_COUNT_OFFSET);

	READ_WORD (s, &fake_size, &param_count, FALSE, -1);
	READ_WORD (s, &fake_size, &param_offset, FALSE, -1);

	s = PADD (origin, param_offset);
	allowed_end = PADD (buf, size);

	ASSURE (s <= allowed_end, -1);

	size = (rtsmb_size) PDIFF (allowed_end, s);
	buf = s;

	RTSMB_READ_WORD (&pFindR->sid);
	RTSMB_READ_WORD (&pFindR->search_count);
	RTSMB_READ_WORD (&pFindR->end_of_search);
	RTSMB_READ_WORD (&pFindR->ea_error_offset);
	RTSMB_READ_WORD (&pFindR->last_name_offset);

	/* now we move to the data section so that subsequent calls to grab data will work right */
	e = PADD (origin, RTRTSMB_READ_TRANS2_COUNT_OFFSET + 6);	/* we want data count, not param */

	fake_size = 4;
	READ_WORD (e, &fake_size, &data_count, FALSE, -1);
	READ_WORD (e, &fake_size, &data_offset, FALSE, -1);

	e = PADD (origin, data_offset);
	allowed_end = PADD (buf, size);

	ASSURE (e <= allowed_end, -1);

	return (int) PDIFF (e, reals);
}

int cli_cmd_read_find_next2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_NEXT_R pFindR)
{
	PFVOID reals, s, e, allowed_end;
	word param_count, param_offset;
	word data_count, data_offset;
	rtsmb_size fake_size = 4;

	reals = buf;

	s = PADD (origin, RTRTSMB_READ_TRANS2_COUNT_OFFSET);

	READ_WORD (s, &fake_size, &param_count, FALSE, -1);
	READ_WORD (s, &fake_size, &param_offset, FALSE, -1);

	s = PADD (origin, param_offset);
	allowed_end = PADD (buf, size);

	ASSURE (s <= allowed_end, -1);

	size = (rtsmb_size) PDIFF (allowed_end, s);
	buf = s;

	RTSMB_READ_WORD (&pFindR->search_count);
	RTSMB_READ_WORD (&pFindR->end_of_search);
	RTSMB_READ_WORD (&pFindR->ea_error_offset);
	RTSMB_READ_WORD (&pFindR->last_name_offset);

	/* now we move to the data section so that subsequent calls to grab data will work right */
	e = PADD (origin, RTRTSMB_READ_TRANS2_COUNT_OFFSET + 6);	/* we want data count, not param */

	fake_size = 4;
	READ_WORD (e, &fake_size, &data_count, FALSE, -1);
	READ_WORD (e, &fake_size, &data_offset, FALSE, -1);

	e = PADD (origin, data_offset);
	allowed_end = PADD (buf, size);

	ASSURE (e <= allowed_end, -1);

	return (int) PDIFF (e, reals);
}

int cli_cmd_read_find_file_info_standard (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_INFO_STANDARD pInfo)
{
	PFVOID s, e;
	byte b;

	s = buf;

	if (pInfo->valid_resume_key)
	{
		RTSMB_READ_DWORD (&pInfo->resume_key);
	}

	RTSMB_READ_WORD (&pInfo->creation_date);
	RTSMB_READ_WORD (&pInfo->creation_time);
	RTSMB_READ_WORD (&pInfo->last_access_date);
	RTSMB_READ_WORD (&pInfo->last_access_time);
	RTSMB_READ_WORD (&pInfo->last_write_date);
	RTSMB_READ_WORD (&pInfo->last_write_time);
	RTSMB_READ_DWORD (&pInfo->file_size);
	RTSMB_READ_DWORD (&pInfo->allocation_size);
	RTSMB_READ_WORD (&pInfo->attributes);
	RTSMB_READ_BYTE (&b);	/* filename size */
	pInfo->filename_size = b;
// PVO dont say 'NULL' oy vay because we read in the null as part of the string
//	RTSMB_READ_STRING_BYTES (pInfo->filename, pInfo->filename_size, b, TRUE, RTSMB_READ_ANY);
	RTSMB_READ_STRING_BYTES (pInfo->filename, pInfo->filename_size, b, FALSE, RTSMB_READ_ANY);

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_info_standard (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_STANDARD pInfo)
{
	PFVOID reals, s, e, allowed_end;
	word data_count, data_offset;
	rtsmb_size fake_size = 4;

	reals = buf;

	s = PADD (origin, RTRTSMB_READ_TRANS2_COUNT_OFFSET + 6); /* data count/offset */

	READ_WORD (s, &fake_size, &data_count, FALSE, -1);
	READ_WORD (s, &fake_size, &data_offset, FALSE, -1);

	s = PADD (origin, data_offset);
	allowed_end = PADD (buf, size);

	ASSURE (s <= allowed_end, -1);

	size = (rtsmb_size) PDIFF (allowed_end, s);
	buf = s;

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

	return (int) PDIFF (e, reals);
}

int cli_cmd_read_query_file_all_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_ALL_INFO pInfo)
{
	PFVOID reals, s, e, allowed_end;
	word data_count, data_offset;
	rtsmb_size fake_size = 4;

	reals = buf;

	s = PADD (origin, RTRTSMB_READ_TRANS2_COUNT_OFFSET + 6); /* data count/offset */

	READ_WORD (s, &fake_size, &data_count, FALSE, -1);
	READ_WORD (s, &fake_size, &data_offset, FALSE, -1);

	s = PADD (origin, data_offset);
	allowed_end = PADD (buf, size);

	ASSURE (s <= allowed_end, -1);

	size = (rtsmb_size) PDIFF (allowed_end, s);
	buf = s;

	RTSMB_READ_DWORD (&pInfo->low_creation_time);
	RTSMB_READ_DWORD (&pInfo->high_creation_time);
	RTSMB_READ_DWORD (&pInfo->low_last_access_time);
	RTSMB_READ_DWORD (&pInfo->high_last_access_time);
	RTSMB_READ_DWORD (&pInfo->low_last_write_time);
	RTSMB_READ_DWORD (&pInfo->high_last_write_time);
	RTSMB_READ_DWORD (&pInfo->low_change_time);
	RTSMB_READ_DWORD (&pInfo->high_change_time);
	RTSMB_READ_WORD (&pInfo->attributes);
	RTSMB_READ_DWORD (&pInfo->low_allocation_size);
	RTSMB_READ_DWORD (&pInfo->high_allocation_size);
	RTSMB_READ_DWORD (&pInfo->low_end_of_file);
	RTSMB_READ_DWORD (&pInfo->high_end_of_file);
	RTSMB_READ_DWORD (&pInfo->number_of_links);
	RTSMB_READ_BYTE (&pInfo->delete_pending);
	RTSMB_READ_BYTE (&pInfo->is_directory);
	RTSMB_READ_DWORD (&pInfo->low_index_number);
	RTSMB_READ_DWORD (&pInfo->high_index_number);
	RTSMB_READ_DWORD (&pInfo->ea_size);
	RTSMB_READ_DWORD (&pInfo->access_flags);
	RTSMB_READ_DWORD (&pInfo->low_index_number2);
	RTSMB_READ_DWORD (&pInfo->high_index_number2);
	RTSMB_READ_DWORD (&pInfo->low_current_offset);
	RTSMB_READ_DWORD (&pInfo->high_current_offset);
	RTSMB_READ_DWORD (&pInfo->mode);
	RTSMB_READ_DWORD (&pInfo->alignment_requirement);
	RTSMB_READ_SKIP (4); /* file name size */
	RTSMB_READ_STRING (pInfo->filename, pInfo->filename_size, RTSMB_READ_ANY);

	e = buf;

	return (int) PDIFF (e, reals);
}

int cli_cmd_read_enum_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_ENUM_HEADER_R pEnumR)
{
	PFVOID reals, s, e, allowed_end;
	word param_count, param_offset;
	word data_count, data_offset;
	rtsmb_size fake_size = 4;

	reals = buf;

	s = PADD (origin, RTRTSMB_READ_TRANS2_COUNT_OFFSET);

	READ_WORD (s, &fake_size, &param_count, FALSE, -1);
	READ_WORD (s, &fake_size, &param_offset, FALSE, -1);

	s = PADD (origin, param_offset);
	allowed_end = PADD (buf, size);

	ASSURE (s <= allowed_end, -1);

	size = (rtsmb_size) PDIFF (allowed_end, s);
	buf = s;

	RTSMB_READ_WORD (&pEnumR->status);
	RTSMB_READ_WORD (&pEnumR->converter);
	RTSMB_READ_WORD (&pEnumR->entry_count);
	RTSMB_READ_WORD (&pEnumR->available_entries);

	/* now we move to the data section so that subsequent calls to grab data will work right */
	e = PADD (origin, RTRTSMB_READ_TRANS2_COUNT_OFFSET + 6);	/* we want data count, not param */

	fake_size = 4;
	READ_WORD (e, &fake_size, &data_count, FALSE, -1);
	READ_WORD (e, &fake_size, &data_offset, FALSE, -1);

	e = PADD (origin, data_offset);
	allowed_end = PADD (buf, size);

	ASSURE (e <= allowed_end, -1);

	return (int) PDIFF (e, reals);
}

/* buf must always be start of info section */
int cli_cmd_read_share_enum_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SHARE_ENUM_INFO_R pInfo)
{
	PFVOID s, e, pdatastart, pconverter, pmax, pcomment;
	dword pointer, converter;
	RTP_ADDR size_left;
	dword toread;

	s = buf;

	RTSMB_READ_STRING (pInfo->share_data.name, 13, RTSMB_READ_ASCII);

	buf = s;
	RTSMB_READ_SKIP (14);	/* thirteen ascii characters and a pad */

	RTSMB_READ_WORD (&pInfo->share_data.type);
	RTSMB_READ_DWORD (&pointer);

	e = buf;

	/* now we need to grab the converter number and jump ahead to where
	   our pointer value leads */
	pdatastart = PADD (s, -20 * pInfo->share_num);
	pconverter = PADD (pdatastart, -8);

	rtsmb_read_dword_unsafe (pconverter, &converter, FALSE);
	pointer = pointer - converter;

	pmax = PADD (buf, size);
	pcomment = PADD (pdatastart, pointer);
	size_left = PDIFF (pmax, pcomment);

	/* is our pointer inside the boundaries of our packet? */
	ASSURE (size_left >= 0, -1);

	toread = MIN ((dword) size_left, pInfo->share_data.comment_size);
	RTSMB_READ_STRING (pInfo->share_data.comment, toread, RTSMB_READ_ASCII);

	return (int) PDIFF (e, s);
}


int cli_cmd_read_server_info_0 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_0 pInfo)
{
	PFVOID s, e;

	s = buf;

	RTSMB_READ_STRING (pInfo->name, 16, RTSMB_READ_ASCII);
	buf = s;
	RTSMB_READ_SKIP (16);	/* 16 ascii characters */

	e = buf;

	return (int) PDIFF (e, s);
}

int cli_cmd_read_server_info_1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo)
{
	PFVOID s, e, pdatastart, pconverter, pmax, pcomment;
	dword pointer, converter;
	RTP_ADDR size_left;
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

	return (int) PDIFF (e, s);
}

int cli_cmd_read_backup_list (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_BROWSE_GET_BACKUP_LIST_R pList)
{
	PFVOID reals, s, e, allowed_end;
	word data_count, data_offset;
	rtsmb_size fake_size = 4;
	byte b, count, i;

	reals = buf;

	s = PADD (origin, RTRTSMB_READ_TRANS1_COUNT_OFFSET + 4); /* data count/offset */

	READ_WORD (s, &fake_size, &data_count, FALSE, -1);
	READ_WORD (s, &fake_size, &data_offset, FALSE, -1);

	s = PADD (origin, data_offset);
	allowed_end = PADD (buf, size);

	ASSURE (s <= allowed_end, -1);

	size = (rtsmb_size) PDIFF (allowed_end, s);
	buf = s;

	RTSMB_READ_BYTE (&b);	/* command opcode */
	ASSURE (b == 0x0a, -1);
	RTSMB_READ_BYTE (&count);	/* count of names */
	b = MIN (count, pList->count);	/* it's not a failure if we don't have enough names */
	RTSMB_READ_DWORD (&pList->token);

	for (i = 0; i < b; i++)
	{
		RTSMB_READ_STRING (pList->servers[i], 16, RTSMB_READ_ASCII);
	}

	pList->count = b;

	for (; i < count; i++)
	{
		RTSMB_READ_STRING (0, 16, RTSMB_READ_ASCII);
	}

	e = buf;

	return (int) PDIFF (e, reals);
}

int cli_cmd_read_info_allocation (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_ALLOCATION pInfo)
{
	PFVOID reals, s, e, allowed_end;
	word data_count, data_offset;
	rtsmb_size fake_size = 4;

	reals = buf;

	s = PADD (origin, RTRTSMB_READ_TRANS2_COUNT_OFFSET + 6); /* data count/offset */

	READ_WORD (s, &fake_size, &data_count, FALSE, -1);
	READ_WORD (s, &fake_size, &data_offset, FALSE, -1);

	s = PADD (origin, data_offset);
	allowed_end = PADD (buf, size);

	ASSURE (s <= allowed_end, -1);

	size = (rtsmb_size) PDIFF (allowed_end, s);
	buf = s;

	RTSMB_READ_DWORD (&pInfo->file_system_id);
	RTSMB_READ_DWORD (&pInfo->sectors_per_unit);
	RTSMB_READ_DWORD (&pInfo->total_units);
	RTSMB_READ_DWORD (&pInfo->available_units);
	RTSMB_READ_WORD (&pInfo->bytes_per_sector);

	e = buf;

	return (int) PDIFF (e, reals);
}

#endif /* INCLUDE_RTSMB_CLIENT */
