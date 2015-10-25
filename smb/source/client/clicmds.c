//
// CLICMDS.C -
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

#include "clicmds.h"
#include "smbpack.h"
#include "smbutil.h"
#include "smbconf.h"

#define DEBUG_AUTH 1
#if (DEBUG_AUTH)
#include "rtpprint.h"
#endif
RTSMB_STATIC
int cli_cmd_fill_no_op (PFVOID buf, rtsmb_size size)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (0);	/* wordcount */
	RTSMB_PACK_WORD (0);	/* bytecount */

	e = buf;	/* measure end of data section */

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_header (PFVOID origin, PFVOID buf, rtsmb_size size,
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

	return (int) PDIFF (e, s);
}


/**
 * Fills a buffer with one NEGOTIATE command.
 *
 * Return values:
 *  positive integer: success, returned value is size of data
 *  -1: not enough space
 */
int cli_cmd_fill_negotiate (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE pNegotiate)
{
	PFVOID s, e;
	PFVOID bs;	/* byte start */
	PFVOID pbytecount;
	int i;

	s = buf;

	RTSMB_PACK_BYTE (0);	/* wordcount */

	pbytecount = buf;	/* we're going to revisit this variable */
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;	/* measure start of data section */

	for (i = 0; i < pNegotiate->num_dialects; i++)
	{
		RTSMB_PACK_BYTE (SMB_BF_DIALECT);
		RTSMB_PACK_STRING (pNegotiate->dialects[i], -1);
	}

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_session_setup_and_x_pre_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_PRE_NT pSetup)
{
	PFVOID s, e;
	PFVOID bs;	/* byte start */
	PFVOID pbytecount;
	PFVOID poffset;
#if (DEBUG_AUTH)
    {
    int i;
    rtp_printf("cli_cmd_fill_session_setup_and_x_pre_nt: \n");
    for (i=0; i < pSetup->password_size; i++)
    {
        rtp_printf("%x ", pSetup->password[i]);
    }
    rtp_printf("\n");
    }
#endif

	s = buf;

	RTSMB_PACK_BYTE (10);	/* wordcount */
	RTSMB_PACK_BYTE (pSetup->next_command);
	RTSMB_PACK_BYTE (0); /* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0); /* offset to next and_x */
	RTSMB_PACK_WORD (pSetup->max_buffer_size);
	RTSMB_PACK_WORD (pSetup->max_mpx_count);
	RTSMB_PACK_WORD (pSetup->vc_number);
	RTSMB_PACK_DWORD (pSetup->session_id);
	RTSMB_PACK_WORD (pSetup->password_size);
	RTSMB_PACK_DWORD (0); /* reserved */

	pbytecount = buf;	/* we're going to revisit this variable */
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;	/* measure start of data section */

	RTSMB_PACK_ITEM (pSetup->password, pSetup->password_size);
	RTSMB_PACK_STRING (pSetup->account_name, RTSMB_PACK_ANY);
	RTSMB_PACK_STRING (pSetup->primary_domain, RTSMB_PACK_ANY);
	RTSMB_PACK_STRING (pSetup->native_os, RTSMB_PACK_ANY);
	RTSMB_PACK_STRING (pSetup->native_lan_man, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	if (pSetup->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_session_setup_and_x_nt_ext_sec (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_EXT_SEC pSetup)
{
	PFVOID s, e;
	PFVOID bs;	/* byte start */
	PFVOID pbytecount;
	PFVOID poffset;

	s = buf;

	RTSMB_PACK_BYTE (12);	/* wordcount */
	RTSMB_PACK_BYTE (pSetup->next_command);
	RTSMB_PACK_BYTE (0); /* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0); /* offset to next and_x */
	RTSMB_PACK_WORD (pSetup->max_buffer_size);
	RTSMB_PACK_WORD (pSetup->max_mpx_count);
	RTSMB_PACK_WORD (pSetup->vc_number);
	RTSMB_PACK_DWORD (pSetup->session_id);
	RTSMB_PACK_WORD ((word) (pSetup->blob_size & 0xFFFF));
	RTSMB_PACK_DWORD (0); /* reserved */
	RTSMB_PACK_DWORD (pSetup->capabilities);

	pbytecount = buf;	/* we're going to revisit this variable */
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;	/* measure start of data section */

	RTSMB_PACK_ITEM (pSetup->blob, pSetup->blob_size);
	RTSMB_PACK_STRING (pSetup->native_os, RTSMB_PACK_ANY);
	RTSMB_PACK_STRING (pSetup->native_lan_man, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	if (pSetup->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_session_setup_and_x_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_NT pSetup)
{
	PFVOID s, e;
	PFVOID bs;	/* byte start */
	PFVOID pbytecount;
	PFVOID poffset;
#if (DEBUG_AUTH)
    {
    int i;
    rtp_printf("cli_cmd_fill_session_setup_and_x_nt: \n");
    for (i=0; i < pSetup->ansi_password_size; i++)
    {
        rtp_printf("%x ", pSetup->ansi_password[i]);
    }
    rtp_printf("\n");
    for (i=0; i < pSetup->unicode_password_size; i++)
    {
        rtp_printf("%x ", pSetup->unicode_password[i]);
    }
    rtp_printf("\n");
    }
#endif

	s = buf;

	RTSMB_PACK_BYTE (13);	/* wordcount */
	RTSMB_PACK_BYTE (pSetup->next_command);
	RTSMB_PACK_BYTE (0); /* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0); /* offset to next and_x */
	RTSMB_PACK_WORD (pSetup->max_buffer_size);
	RTSMB_PACK_WORD (pSetup->max_mpx_count);
	RTSMB_PACK_WORD (pSetup->vc_number);
	RTSMB_PACK_DWORD (pSetup->session_id);
	RTSMB_PACK_WORD (pSetup->ansi_password_size);
	RTSMB_PACK_WORD (pSetup->unicode_password_size);
	RTSMB_PACK_DWORD (0); /* reserved */
	RTSMB_PACK_DWORD (pSetup->capabilities);

	pbytecount = buf;	/* we're going to revisit this variable */
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;	/* measure start of data section */

	RTSMB_PACK_ITEM (pSetup->ansi_password, pSetup->ansi_password_size);
	RTSMB_PACK_ITEM (pSetup->unicode_password, pSetup->unicode_password_size);
	RTSMB_PACK_STRING (pSetup->account_name, RTSMB_PACK_ANY);
	RTSMB_PACK_STRING (pSetup->primary_domain, RTSMB_PACK_ANY);
	RTSMB_PACK_STRING (pSetup->native_os, RTSMB_PACK_ANY);
	RTSMB_PACK_STRING (pSetup->native_lan_man, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	if (pSetup->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_logoff_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOGOFF_AND_X pLogoff)
{
	PFVOID s, e;
	PFVOID poffset;

	s = buf;

	RTSMB_PACK_BYTE (2);	/* wordcount */
	RTSMB_PACK_BYTE (pLogoff->next_command);
	RTSMB_PACK_BYTE (0); /* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0); /* offset to next and_x */
	RTSMB_PACK_WORD (0);	/* bytecount */

	e = buf;	/* measure end of data section */

	if (pLogoff->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_tree_connect_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_AND_X pTree)
{
	PFVOID s, e;
	PFVOID bs;	/* byte start */
	PFVOID pbytecount;
	PFVOID poffset;

	s = buf;

	RTSMB_PACK_BYTE (4);	/* wordcount */
	RTSMB_PACK_BYTE (pTree->next_command);
	RTSMB_PACK_BYTE (0); /* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0); /* offset to next and_x */
	RTSMB_PACK_WORD (pTree->flags);
	RTSMB_PACK_WORD (pTree->password_size);
	pbytecount = buf;	/* we're going to revisit this variable */
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;	/* measure start of data section */

	RTSMB_PACK_ITEM (pTree->password, pTree->password_size);
	RTSMB_PACK_STRING (pTree->share, 0);
	RTSMB_PACK_STRING (pTree->service, -1);

	e = buf;	/* measure end of data section */

	/* will succeed, since we already passed this segment */
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	if (pTree->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_tree_disconnect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none)
{
	return cli_cmd_fill_no_op (buf, size);
}

int cli_cmd_fill_read_and_x_pre_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X pRead)
{
	PFVOID s, e;
	PFVOID poffset;

	s = buf;

	RTSMB_PACK_BYTE (10);	/* word count */
	RTSMB_PACK_BYTE (pRead->next_command);
	RTSMB_PACK_BYTE (0); /* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0); /* offset to next and_x */
	RTSMB_PACK_WORD (pRead->fid);
	RTSMB_PACK_DWORD (pRead->offset);
	RTSMB_PACK_WORD ((word) (pRead->max_count & 0xFFFF));
	RTSMB_PACK_WORD (0);	/* reserved */
	RTSMB_PACK_DWORD ((pRead->max_count & 0xFFFF0000) >> 16);
	RTSMB_PACK_WORD (0);	/* reserved */
	RTSMB_PACK_WORD (0);	/* bytecount */

	e = buf;	/* measure end of data section */

	if (pRead->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_open_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_AND_X pOpen)
{
	PFVOID s, bs, e;
	PFVOID poffset, pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (15);	/* word count */
	RTSMB_PACK_BYTE (pOpen->next_command);
	RTSMB_PACK_BYTE (0); /* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0); /* offset to next and_x */
	RTSMB_PACK_WORD (pOpen->flags);
	RTSMB_PACK_WORD (pOpen->desired_access);
	RTSMB_PACK_DWORD ((dword) pOpen->search_attributes);
	RTSMB_PACK_DWORD (pOpen->creation_time);
	RTSMB_PACK_WORD (pOpen->open_function);
	RTSMB_PACK_DWORD (pOpen->allocation_size);
	RTSMB_PACK_DWORD (0);	/* reserved */
	RTSMB_PACK_DWORD (0);	/* reserved */

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;

	/* Spec says to write this, but implementations die if we do */
	/* RTSMB_PACK_BYTE (SMB_BF_RTSMB_PACK_ASCII); */

	RTSMB_PACK_STRING (pOpen->filename, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	if (pOpen->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_create_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NT_CREATE_AND_X pCreate)
{
	PFVOID s, bs, e;
	PFVOID poffset, pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (24);	                          /* word count */
	RTSMB_PACK_BYTE (pCreate->next_command);
	RTSMB_PACK_BYTE (0);                              /* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);                              /* offset to next and_x */
	RTSMB_PACK_BYTE (0);                              /* Reserved */
	RTSMB_PACK_WORD (pCreate->filename_size);         /* NameLength (in bytes) */
	RTSMB_PACK_DWORD (pCreate->flags);                /* flags */
	RTSMB_PACK_DWORD (pCreate->root_directory_fid);   /* FID of directory relative to which
	                                                     filename is interpreted */
	RTSMB_PACK_DWORD (pCreate->desired_access);       /* Access Desired */
	RTSMB_PACK_DWORD (pCreate->allocation_size_high); /* high part of allocation size */
	RTSMB_PACK_DWORD (pCreate->allocation_size_low);  /* low part of allocation size */
	RTSMB_PACK_DWORD (pCreate->ext_file_attributes);
	RTSMB_PACK_DWORD (pCreate->share_access);
	RTSMB_PACK_DWORD (pCreate->create_disposition);
	RTSMB_PACK_DWORD (pCreate->create_options);
	RTSMB_PACK_DWORD (pCreate->impersonation_level);
	RTSMB_PACK_BYTE (pCreate->security_flags);

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;

	RTSMB_PACK_STRING (pCreate->filename, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	if (pCreate->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CLOSE pClose)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (3);	/* word count */
	RTSMB_PACK_WORD (pClose->fid);
	RTSMB_PACK_DWORD (pClose->last_write_time);
	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_write_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_X pWrite)
{
	PFVOID s, bs, e;
	PFVOID poffset, pdataoffset, pdatastart, pbytecount;
	RTSMB_UINT16 data_length_low  = (RTSMB_UINT16) (pWrite->data_size & 0xffff);
	RTSMB_UINT16 data_length_high = (RTSMB_UINT16) ((pWrite->data_size >> 16) & 0xffff);

	s = buf;

	if (pWrite->offset_high || pWrite->is_large_write)
	{
		RTSMB_PACK_BYTE (14);	/* word count */
	}
	else
	{
		RTSMB_PACK_BYTE (12);	/* word count */
	}

	RTSMB_PACK_BYTE (pWrite->next_command);
	RTSMB_PACK_BYTE (0);                  /* reserved */
	poffset = buf;
	RTSMB_PACK_WORD (0);                  /* offset to next and_x */
	RTSMB_PACK_WORD (pWrite->fid);
	RTSMB_PACK_DWORD (pWrite->offset);
	RTSMB_PACK_DWORD (0);                 /* reserved */
	RTSMB_PACK_WORD (pWrite->write_mode);
	RTSMB_PACK_WORD (0);                  /* remaining; not used by us */
	RTSMB_PACK_WORD (data_length_high);   /* data length high */
	RTSMB_PACK_WORD (data_length_low);    /* data length low */
	pdataoffset = buf;
	RTSMB_PACK_WORD (0);                  /* data offset */

	if (pWrite->offset_high || pWrite->is_large_write)
	{
		RTSMB_PACK_DWORD (pWrite->offset_high);
	}

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;

	RTSMB_PACK_PAD_TO (2);

	pdatastart = buf;
  #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
	if (pWrite->limited_copy)
	{
		RTSMB_PACK_ITEM (pWrite->data, pWrite->copy_data_size);
	}
	else
  #endif
	{
		RTSMB_PACK_ITEM (pWrite->data, pWrite->data_size);
	}

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pdataoffset, (word) PDIFF (pdatastart, origin), FALSE);
	rtsmb_pack_add_word_unsafe (pbytecount,  (word) (pWrite->data_size + (dword)PDIFF (pdatastart, bs)), FALSE);

	if (pWrite->next_command != SMB_COM_NONE)
	{
		/* fill in offset */
		rtsmb_pack_add_word_unsafe (poffset, (word) PDIFF (e, origin), FALSE);
	}

	return (int) PDIFF (e, s);
}

#if 0
int cli_cmd_fill_write_raw (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW pWrite)
{
	PFVOID s, bs, e;
	PFVOID pdatasize, pdataoffset, pdatastart, pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (12);	/* word count */
	RTSMB_PACK_WORD (pWrite->fid);
	RTSMB_PACK_WORD (pWrite->count);
	RTSMB_PACK_WORD (0);    /* reserved */
	RTSMB_PACK_DWORD (pWrite->offset);
	RTSMB_PACK_DWORD (pWrite->timeout);
	RTSMB_PACK_WORD (pWrite->write_mode);
	RTSMB_PACK_DWORD (0);    /* reserved */

	pdatasize = buf;
	RTSMB_PACK_WORD (pWrite->data_size); /* data length */

	pdataoffset = buf;
	RTSMB_PACK_WORD (0);	/* data offset */

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* bytecount */

	bs = buf;

	RTSMB_PACK_PAD_TO (2);

	pdatastart = buf;
	RTSMB_PACK_ITEM (pWrite->data, pWrite->data_size);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pdatasize, (word) PDIFF (e, pdatastart), FALSE);
	rtsmb_pack_add_word_unsafe (pdataoffset, (word) PDIFF (pdatastart, origin), FALSE);
	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return PDIFF (e, s);
}
#endif

int cli_cmd_fill_seek (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEEK pSeek)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (4);	/* word count */

	RTSMB_PACK_WORD (pSeek->fid);
	RTSMB_PACK_WORD (pSeek->mode);
	RTSMB_PACK_DWORD (pSeek->offset);

	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_write (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE pWrite)
{
	PFVOID s, bs, e;
	PFVOID pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (5);	/* word count */

	RTSMB_PACK_WORD (pWrite->fid);
	RTSMB_PACK_WORD (pWrite->data_size);
	RTSMB_PACK_DWORD (pWrite->offset);
	RTSMB_PACK_WORD (pWrite->remaining);

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;

	RTSMB_PACK_BYTE (SMB_BF_DATA);
	RTSMB_PACK_WORD (pWrite->data_size);
	RTSMB_PACK_ITEM (pWrite->data, pWrite->data_size);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_flush (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FLUSH pFlush)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */

	RTSMB_PACK_WORD (pFlush->fid);

	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_rename (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RENAME pRename)
{
	PFVOID s, bs, e;
	PFVOID pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */

	RTSMB_PACK_WORD (pRename->search_attributes);

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;

	RTSMB_PACK_BYTE (SMB_BF_ASCII);
	RTSMB_PACK_STRING (pRename->old_filename, RTSMB_PACK_ANY);
	RTSMB_PACK_BYTE (SMB_BF_ASCII);
	RTSMB_PACK_STRING (pRename->new_filename, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_delete (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_DELETE pDelete)
{
	PFVOID s, bs, e;
	PFVOID pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */

	RTSMB_PACK_WORD (pDelete->search_attributes);

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;

	RTSMB_PACK_BYTE (SMB_BF_ASCII);
	RTSMB_PACK_STRING (pDelete->filename, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return (int) PDIFF (e, s);
}


int cli_cmd_fill_set_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SET_INFORMATION pSet)
{
	PFVOID s, bs, e;
	PFVOID pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (8);	/* word count */

	RTSMB_PACK_WORD (pSet->file_attributes);
	RTSMB_PACK_DWORD (pSet->last_write_time);
	RTSMB_PACK_WORD (0);	/* five reserved words */
	RTSMB_PACK_WORD (0);
	RTSMB_PACK_WORD (0);
	RTSMB_PACK_WORD (0);
	RTSMB_PACK_WORD (0);

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;

	RTSMB_PACK_BYTE (SMB_BF_ASCII);
	RTSMB_PACK_STRING (pSet->filename, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_create_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE_DIRECTORY pCreate)
{
	PFVOID s, bs, e;
	PFVOID pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (0);	/* word count */

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;

	RTSMB_PACK_BYTE (SMB_BF_ASCII);
	RTSMB_PACK_STRING (pCreate->directory, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_delete_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_DELETE_DIRECTORY pDelete)
{
	PFVOID s, bs, e;
	PFVOID pbytecount;

	s = buf;

	RTSMB_PACK_BYTE (0);	/* word count */

	pbytecount = buf;
	RTSMB_PACK_WORD (0);	/* byte count */

	bs = buf;

	RTSMB_PACK_BYTE (SMB_BF_ASCII);
	RTSMB_PACK_STRING (pDelete->directory, RTSMB_PACK_ANY);

	e = buf;	/* measure end of data section */

	rtsmb_pack_add_word_unsafe (pbytecount, (word) PDIFF (e, bs), FALSE);

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION pTransaction)
{
	PFVOID s, e;
	int i;

	s = buf;

	RTSMB_PACK_BYTE ((byte) (14 + pTransaction->setup_size));	/* word count */
	RTSMB_PACK_WORD (0);	/* param count; to be filled in later */
	RTSMB_PACK_WORD (0);	/* data count; to be filled in later */
	RTSMB_PACK_WORD (pTransaction->max_parameter_count);
	RTSMB_PACK_WORD (pTransaction->max_data_count);
	RTSMB_PACK_BYTE (pTransaction->max_setup_count);
	RTSMB_PACK_BYTE (0);	/* reserved */
	RTSMB_PACK_WORD (pTransaction->flags);
	RTSMB_PACK_DWORD (pTransaction->timeout);
	RTSMB_PACK_WORD (0);	/* reserved */
	RTSMB_PACK_WORD (0);	/* param count; to be filled in later */
	RTSMB_PACK_WORD (0);	/* param offset; to be filled in later */
	RTSMB_PACK_WORD (0);	/* data count; to be filled in later */
	RTSMB_PACK_WORD (0);	/* data offset; to be filled in later */
	RTSMB_PACK_BYTE (pTransaction->setup_size);
	RTSMB_PACK_BYTE (0);	/* reserved */

	for (i = 0; i < pTransaction->setup_size; i++)
	{
		RTSMB_PACK_WORD (pTransaction->setup[i]);
	}

	RTSMB_PACK_WORD (0);	/* byte count */

	if (pTransaction->name)
	{
		RTSMB_PACK_STRING (pTransaction->name, RTSMB_PACK_ANY);
	}

	e = buf;

	return (int) PDIFF (e, s);
}

#define RTRTSMB_PACK_TRANS2_TOTAL_COUNT_OFFSET 33	/* the offset from origin to a transaction's total param count */
#define RTRTSMB_PACK_TRANS2_COUNT_OFFSET 51	/* the offset from origin to a transaction's param count */
#define RTRTSMB_PACK_TRANS2_BYTE_COUNT_BASE 61

int cli_cmd_fill_trans2_find_first2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_FIRST2 pFind)
{
	PFVOID pres, s, e, p;

	pres = buf;

	RTSMB_PACK_PAD_TO (2);

	s = buf;

	RTSMB_PACK_WORD (pFind->search_attributes);
	RTSMB_PACK_WORD (pFind->search_count);
	RTSMB_PACK_WORD (pFind->flags);
	RTSMB_PACK_WORD (pFind->information_level);
	RTSMB_PACK_DWORD (pFind->search_storage_type);
	RTSMB_PACK_STRING (pFind->filename, RTSMB_PACK_ANY);

	e = buf;

	p = PADD (origin, RTRTSMB_PACK_TRANS2_TOTAL_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);
	p = PADD (p, 2);	/* param offset */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (s, origin), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_BYTE_COUNT_BASE + 2);	/* byte count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, pres), FALSE);

	return (int) PDIFF (e, pres);
}

int cli_cmd_fill_trans2_find_next2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_NEXT2 pFind)
{
	PFVOID pres, s, e, p;

	pres = buf;

	RTSMB_PACK_PAD_TO (2);

	s = buf;

	RTSMB_PACK_WORD (pFind->sid);
	RTSMB_PACK_WORD (pFind->search_count);
	RTSMB_PACK_WORD (pFind->information_level);
	RTSMB_PACK_DWORD (pFind->resume_key);
	RTSMB_PACK_WORD (pFind->flags);
	RTSMB_PACK_STRING (pFind->filename, RTSMB_PACK_ANY);

	e = buf;

	p = PADD (origin, RTRTSMB_PACK_TRANS2_TOTAL_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);
	p = PADD (p, 2);	/* param offset */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (s, origin), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_BYTE_COUNT_BASE + 2);	/* byte count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, pres), FALSE);

	return (int) PDIFF (e, pres);
}


int cli_cmd_fill_find_close2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_CLOSE2 pFind)
{
	PFVOID s, e;

	s = buf;

	RTSMB_PACK_BYTE (1);	/* word count */

	RTSMB_PACK_WORD (pFind->sid);

	RTSMB_PACK_WORD (0);	/* byte count */

	e = buf;	/* measure end of data section */

	return (int) PDIFF (e, s);
}

int cli_cmd_fill_share_enum (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_GET_INFO pInfo)
{
	PFVOID pres, s, e, p;

	pres = buf;

	/* This follows a TRANSACTION, so we need to pad. */
	RTSMB_PACK_PAD_TO (2);

	s = buf;

	RTSMB_PACK_WORD (0);	/* opcode */
	RTSMB_PACK_ITEM ("WrLeh", 6);	/* parameter descriptor */
	RTSMB_PACK_ITEM ("B13BWz", 7); /* return descriptor */
	RTSMB_PACK_WORD (pInfo->information_level);
	RTSMB_PACK_WORD (pInfo->receive_size);

	e = buf;	/* measure end of data section */

	p = PADD (origin, RTRTSMB_PACK_TRANS2_TOTAL_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);
	p = PADD (p, 2);	/* param offset */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (s, origin), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_BYTE_COUNT_BASE);	/* byte count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, PADD (p, 2)), FALSE);

	return (int) PDIFF (e, pres);
}

int cli_cmd_fill_rap_server_enum2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_ENUM2 pEnum)
{
	PFVOID pres, s, e, p;

	pres = buf;

	/* This follows a TRANSACTION, so we need to pad. */
	RTSMB_PACK_PAD_TO (2);

	s = buf;

	RTSMB_PACK_WORD (104);	/* opcode */

	if (pEnum->domain)
	{
		RTSMB_PACK_ITEM ("WrLehDz", 8);	/* parameter descriptor */
	}
	else
	{
		RTSMB_PACK_ITEM ("WrLehDO", 8);	/* parameter descriptor */
	}

	if (pEnum->information_level == 1)
	{
		RTSMB_PACK_ITEM ("B16BBDz", 8); /* return descriptor */
	}
	else
	{
		RTSMB_PACK_ITEM ("B16", 4); /* return descriptor */
	}

	RTSMB_PACK_WORD (pEnum->information_level);
	RTSMB_PACK_WORD (pEnum->receive_size);
	RTSMB_PACK_DWORD (pEnum->server_type);
	if (pEnum->domain)
	{
		RTSMB_PACK_STRING (pEnum->domain, RTSMB_PACK_ASCII);
	}

	e = buf;	/* measure end of data section */

	p = PADD (origin, RTRTSMB_PACK_TRANS2_TOTAL_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);

	p = PADD (p, 2);	/* param offset */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (s, origin), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_BYTE_COUNT_BASE + 0);	/* byte count + setup */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, PADD (p, 2)), FALSE);

	return (int) PDIFF (e, pres);
}

int cli_cmd_fill_query_fs_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_QUERY_FS_INFORMATION pQuery)
{
	PFVOID pres, s, e, p;

	pres = buf;

	/* Follows a transaction2, so we must pad. */
	RTSMB_PACK_PAD_TO (2);

	s = buf;

	RTSMB_PACK_WORD (pQuery->information_level);

	e = buf;

	p = PADD (origin, RTRTSMB_PACK_TRANS2_TOTAL_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);
	p = PADD (p, 2);	/* param offset */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (s, origin), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_BYTE_COUNT_BASE + 2);	/* byte count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, pres), FALSE);

	return (int) PDIFF (e, pres);
}

int cli_cmd_fill_trans2_query_path_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_QUERY_PATH_INFORMATION pQuery)
{
	PFVOID pres, s, e, p;

	pres = buf;

	/* Follows a transaction2, so we must pad. */
	RTSMB_PACK_PAD_TO (2);

	s = buf;

	RTSMB_PACK_WORD (pQuery->information_level);
	RTSMB_PACK_DWORD (0);	/* reserved */
	RTSMB_PACK_STRING (pQuery->filename, RTSMB_PACK_ANY);

	e = buf;

	p = PADD (origin, RTRTSMB_PACK_TRANS2_TOTAL_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_COUNT_OFFSET);	/* param count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);
	p = PADD (p, 2);	/* param offset */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (s, origin), FALSE);

	p = PADD (origin, RTRTSMB_PACK_TRANS2_BYTE_COUNT_BASE + 2);	/* byte count */
	rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, pres), FALSE);

	return (int) PDIFF (e, pres);
}

#endif /* INCLUDE_RTSMB_CLIENT */
