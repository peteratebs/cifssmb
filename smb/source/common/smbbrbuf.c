//
// SMBBRBUF.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// NETBIOS Datagram Service processing packets
//
#include "smbbrbuf.h"
#include "smbpack.h"
#include "smbread.h"
#include "smbutil.h"
#include "smbnbds.h"
#include "smbbrcfg.h"
#include "smbnet.h"


//String for Browse Service
RTSMB_STATIC rtsmb_char    rtsmb_nbds_slot_browse[] = {'\\', 'M', 'A', 'I', 'L', 'S', 'L', 'O', 'T', '\\', 'B', 'R', 'O', 'W', 'S', 'E', '\0'};

/**
 * Writes NETBIOS Datagram Service header from values in
 * pHeader, returns size of header
 */
int rtsmb_nbds_fill_header (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_NBDS_HEADER pHeader)
{
    PFVOID e, s;
    char decompressed_source [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];
    char decompressed_destination [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];

    rtsmb_nb_fill_name (decompressed_source, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pHeader->source_name);
    rtsmb_nb_fill_name (decompressed_destination, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pHeader->destination_name);

    s = buf;

    PACK_BYTE (buf, &size, pHeader->type, -1);
    PACK_BYTE (buf, &size, pHeader->flags, -1);
    PACK_WORD (buf, &size, pHeader->id, TRUE, -1);
    PACK_ITEM (buf, &size, pHeader->source_ip, 4, -1);
    PACK_WORD (buf, &size, pHeader->source_port, TRUE, -1);
    PACK_WORD (buf, &size, (word) ((pHeader->size + RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE * 2) & 0xFFFF), TRUE, -1);
    PACK_WORD (buf, &size, pHeader->packet_offset, TRUE, -1);
    PACK_ITEM (buf, &size, decompressed_source, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);
    PACK_ITEM (buf, &size, decompressed_destination, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);

    e = buf;

    return (int) PDIFF (e, s);
}


/**
 * Reads NETBIOS Datagram Service header and stores values in
 * pHeader, returns size of header
 */
int rtsmb_nbds_read_header (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_NBDS_HEADER pHeader)
{
    PFVOID e, s;
    char decompressed_source [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];
    char decompressed_destination [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];

    s = buf;

    READ_BYTE (buf, &size, &pHeader->type, -1);
    READ_BYTE (buf, &size, &pHeader->flags, -1);
    READ_WORD (buf, &size, &pHeader->id, TRUE, -1);
    READ_ITEM (buf, &size, pHeader->source_ip, 4, -1);
    READ_WORD (buf, &size, &pHeader->source_port, TRUE, -1);
    READ_WORD (buf, &size, &pHeader->size, TRUE, -1);
    READ_WORD (buf, &size, &pHeader->packet_offset, TRUE, -1);
    READ_ITEM (buf, &size, decompressed_source, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);
    READ_ITEM (buf, &size, decompressed_destination, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);

    e = buf;

    rtsmb_nb_read_name (decompressed_source, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pHeader->source_name);
    rtsmb_nb_read_name (decompressed_destination, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pHeader->destination_name);

    /* Reduce pHeader->size because we don't want other layers to get confused by it
       counting part of the header (this makes the size count consistent with the
       rest of smb. */
    pHeader->size =  (word) ((pHeader->size < RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE * 2) ?
                    0 : (pHeader->size - RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE * 2));

    return (int) PDIFF (e, s);
}

int rtsmb_nbds_fill_smb_header (PFVOID origin, PFVOID buf, rtsmb_size size,
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

int rtsmb_nbds_read_smb_header (PFVOID origin, PFVOID buf, rtsmb_size size,
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

    return (int) PDIFF (e, s);
}


int rtsmb_nbds_fill_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
    PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION pTransaction)
{
    PFVOID s, e;
    int i;

    s = buf;

    RTSMB_PACK_BYTE (17);   /* word count */
    RTSMB_PACK_WORD (pTransaction->parameter_count);
    RTSMB_PACK_WORD (pTransaction->data_count);
    RTSMB_PACK_WORD (pTransaction->max_parameter_count);
    RTSMB_PACK_WORD (pTransaction->max_data_count);
    RTSMB_PACK_BYTE (pTransaction->max_setup_count);
    RTSMB_PACK_BYTE (0);    /* reserved */
    RTSMB_PACK_WORD (pTransaction->flags);
    RTSMB_PACK_DWORD (pTransaction->timeout);
    RTSMB_PACK_WORD (0);    /* reserved */
    RTSMB_PACK_WORD (pTransaction->parameter_count);
    RTSMB_PACK_WORD (pTransaction->parameter_offset);
    RTSMB_PACK_WORD (pTransaction->data_count);
    RTSMB_PACK_WORD (pTransaction->data_offset);
    RTSMB_PACK_BYTE (pTransaction->setup_size);
    RTSMB_PACK_BYTE (0);    /* reserved */

    for (i = 0; i < pTransaction->setup_size; i++)
    {
        RTSMB_PACK_WORD (pTransaction->setup[i]);
    }

    RTSMB_PACK_WORD (pTransaction->byte_count);

    e = buf;    /* measure end of data section */

    return (int) PDIFF (e, s);
}


int rtsmb_nbds_read_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
    PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION pTransaction)
{
    PFVOID s, e;
    byte b;
    word w;

    s = buf;

    RTSMB_READ_BYTE (&b);   /* word count */
    ASSURE (b >= 14, -1);

    RTSMB_READ_WORD (&pTransaction->parameter_count);
    RTSMB_READ_WORD (&pTransaction->data_count);
    RTSMB_READ_WORD (&pTransaction->max_parameter_count);
    RTSMB_READ_WORD (&pTransaction->max_data_count);
    RTSMB_READ_BYTE (&pTransaction->max_setup_count);
    RTSMB_READ_SKIP (1);    /* reserved */
    RTSMB_READ_WORD (&pTransaction->flags);
    RTSMB_READ_DWORD (&pTransaction->timeout);
    RTSMB_READ_SKIP (2);    /* reserved */
    RTSMB_READ_SKIP (2);    /* parameter bytes this message */
    RTSMB_READ_WORD (&pTransaction->parameter_offset);
    RTSMB_READ_SKIP (2);    /* data bytes this message */
    RTSMB_READ_WORD (&pTransaction->data_offset);
    RTSMB_READ_BYTE (&pTransaction->setup_size);
    RTSMB_READ_SKIP (1);    /* reserved */

    ASSURE (3 == pTransaction->setup_size, -1);
    RTSMB_READ_WORD (&w);
    ASSURE (w == 1, -1);
    RTSMB_READ_WORD (&w);
    /* We let the priority be whatever it likes.  Some seem to send 0, more often, 1. */
/*  ASSURE (w == 1, -1);*/
    RTSMB_READ_WORD (&w);
    ASSURE (w == 2, -1);

    RTSMB_READ_WORD (&w);   /* byte count */

    RTSMB_READ_STRING (pTransaction->name, pTransaction->name_size, RTSMB_PACK_ANY);

    e = buf;

    return (int) PDIFF (e, s);
}

int rtsmb_nbds_read_get_backup_list (PFVOID origin, PFVOID buf, rtsmb_size size,
    PRTSMB_HEADER pHeader, PRTSMB_BROWSE_GET_BACKUP_LIST pGet)
{
    PFVOID e, s;
    byte b;

    s = buf;

    RTSMB_READ_BYTE (&b);   /* word count */
    ASSURE (b >= RTSMB_NBDS_COM_GET_BACKUP_LIST_REQUEST, -1);

    RTSMB_READ_BYTE (&pGet->count);
    RTSMB_READ_DWORD (&pGet->token);

    e = buf;

    return (int) PDIFF (e, s);
}


int rtsmb_nbds_fill_get_backup_list (PFVOID origin, PFVOID buf, rtsmb_size size,
    PRTSMB_HEADER pHeader, PRTSMB_BROWSE_GET_BACKUP_LIST pGet)
{
    PFVOID s, e;

    s = buf;

    RTSMB_PACK_BYTE (RTSMB_NBDS_COM_GET_BACKUP_LIST_REQUEST);   /* opcode */
    RTSMB_PACK_BYTE (pGet->count);
    RTSMB_PACK_DWORD (pGet->token);

    e = buf;

    return (int) PDIFF (e, s);
}

int rtsmb_nbds_fill_whole_backup_list (dword token)
{
    int r;
    rtsmb_size size = 0;
    PFVOID buf, ds, de, hs, smb_start;
    RTSMB_HEADER header;
    RTSMB_TRANSACTION trans;
    RTSMB_NBDS_HEADER nbs;
    RTSMB_BROWSE_GET_BACKUP_LIST list;
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

    list.count = 1; /* only want one from each domain */
    list.token = token;

    r = rtsmb_nbds_fill_get_backup_list (prtsmb_browse_ctx->buffer, buf, size, &header, &list);
    ASSURE (r >= 0, -1);
    buf = PADD (buf, r);

    de = buf;

    size = RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE;

    /* now the datagram header */
    nbs.type = RTSMB_NBDS_DIRECT_GROUP_DATAGRAM;
    nbs.flags = 0x02;
    nbs.id = rtsmb_nbds_get_next_datagram_id ();
    tc_memcpy (nbs.source_ip, rtsmb_net_get_host_ip (), 4);
    nbs.source_port = (word) rtsmb_nbds_port;
    nbs.size = (word) (RTSMB_NBDS_DATAGRAM_HEADER_SIZE + RTSMB_NBDS_SMB_SIZE + PDIFF (de, ds));
    nbs.packet_offset = 0;

    rtsmb_util_make_netbios_name (nbs.source_name, (char *)RTSMB_NB_DEFAULT_NAME, (char)RTSMB_NB_NAME_TYPE_WORKSTATION);
    tc_strcpy (nbs.destination_name, RTSMB_NB_MASTER_BROWSER_NAME);

    r = rtsmb_nbds_fill_header (prtsmb_browse_ctx->buffer, prtsmb_browse_ctx->buffer, size, &nbs);
    ASSURE (r >= 0, -1);
    buf = PADD (prtsmb_browse_ctx->buffer, r);
    size -= (rtsmb_size)r;

    smb_start = buf;

    r = rtsmb_nbds_fill_smb_header (smb_start, buf, size, &header);
    ASSURE (r >= 0, -1);
    buf = PADD (buf, r);
    size -= (rtsmb_size) r;

    trans.data_count = (word) PDIFF (de, hs);
    trans.data_offset = (word) PDIFF (hs, smb_start);
    trans.flags = 0;
    trans.max_data_count = 0;
    trans.max_parameter_count = 0;
    trans.max_setup_count = 0;
    trans.parameter_count = 0;
    trans.parameter_offset = 0;
    trans.setup_size = 3;
    trans.setup = setup_words;
    trans.timeout = 0;
    trans.byte_count = (word) PDIFF (de, ds);

    r = rtsmb_nbds_fill_transaction (smb_start, buf, size, &header, &trans);
    ASSURE (r >= 0, -1);
    buf = PADD (buf, r);
    size -= (rtsmb_size) r;

    return (int) PDIFF (de, prtsmb_browse_ctx->buffer);
}

