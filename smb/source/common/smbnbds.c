//
// SMBNBDS.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Controls the NETBIOS Datagram Service layer
//

#include "smbdefs.h"
#include "smbnbds.h"
#include "smbpack.h"
#include "smbread.h"
#include "smbnb.h"
#include "smbutil.h"
#include "smbnet.h"
#include "smbobjs.h"
#include "smbbrcfg.h"
#include "smbbrbuf.h"
#include "smbglue.h"
#include "smbdebug.h"



#include "rtptime.h"
#include "rtpnet.h"
#include "rtpsignl.h"
#include "rtpwcs.h"
#if (INCLUDE_RTIP_RTPLATFORM)
#include "rtpdbapi.h"
#else
#include "rtpdebug.h"
#endif
#define DEBUG_BACKUP_TABLE 1  /* debug BACKUP TABLE */

/**
 * Private data for the netbios datagram service.
 */
RTSMB_STATIC RTP_SOCKET    rtsmb_nbds_datagram_socket;
RTSMB_STATIC RTP_MUTEX     rtsmb_nbds_mutex;
RTSMB_STATIC int           rtsmb_nbds_initialized_count = 0;
RTSMB_STATIC BBOOL         rtsmb_nbds_initialized_ever = 0;
RTSMB_STATIC word          rtsmb_nbds_datagram_id;
RTSMB_STATIC unsigned long rtsmb_nbds_last_cycle_time;

RTSMB_STATIC unsigned long rtsmb_nbds_backup_table_expiration_base;
RTSMB_STATIC unsigned long rtsmb_nbds_backup_table_expiration_delay;
RTSMB_STATIC dword         rtsmb_nbds_backup_table_token;

RTSMB_STATIC byte          rtsmb_nbds_last_remote_ip [4];
RTSMB_STATIC int           rtsmb_nbds_last_remote_port;
RTSMB_STATIC char          rtsmb_nbds_last_remote_name [RTSMB_NB_NAME_SIZE + 1];
#if (DEBUG_BACKUP_TABLE)
void smb_print_unicode(char * comment, rtsmb_char *unicode_name)
{
    char printable_name[RTSMB_NB_NAME_SIZE + 1];
    int   i;
    char *unicode_name_ptr = (char *)unicode_name;
    rtp_printf("%s ", comment);
    for (i=0; unicode_name_ptr[i*2] != '\0' && i < RTSMB_NB_NAME_SIZE;i++)
    {
        printable_name[i] = unicode_name_ptr[i*2];
    }
    printable_name[i] = '\0';
    rtp_printf("%s\n", printable_name);
}
#endif

int  rtsmb_nbds_write (PFVOID data, rtsmb_size size, PFBYTE remote, int port)
{
    int rv;
    rv = rtp_net_sendto(rtsmb_nbds_datagram_socket, data, (long)size, remote, port, 4);
    return rv;
}

word rtsmb_nbds_get_next_datagram_id (void)
{
    return rtsmb_nbds_datagram_id ++;
}

PFCHAR rtsmb_nbds_get_last_remote_name (void)
{
    return rtsmb_nbds_last_remote_name;
}

int rtsmb_nbds_get_last_remote_port (void)
{
    return rtsmb_nbds_last_remote_port;
}

PFBYTE rtsmb_nbds_get_last_remote_ip (void)
{
    return rtsmb_nbds_last_remote_ip;
}



RTSMB_STATIC
int rtsmb_nbds_send_get_backup_list (void)
{
    int r;

    r = rtsmb_nbds_fill_whole_backup_list (rtsmb_nbds_backup_table_token + 1);

    if (r >= 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_nbds_send_get_backup_list: Requesting backup list.\n", RTSMB_DEBUG_TYPE_ASCII);

        r = rtsmb_nbds_write (prtsmb_browse_ctx->buffer, (rtsmb_size)r, rtsmb_net_get_broadcast_ip (), rtsmb_nbds_port);
    }

    return r;
}

RTSMB_STATIC
void _clear_backup_table (void)
{
    int i,j;
#if (DEBUG_BACKUP_TABLE)
    rtp_printf("_clear_backup_table called\n");
#endif
    for (i = 0; i < CFG_RTSMB_BROWSE_MAX_DOMAINS; i++)
    {
        for (j = 0; j < CFG_RTSMB_BROWSE_MAX_BACKUP_SERVERS; j++)
        {
            prtsmb_browse_ctx->domain[i].server_name[j] = prtsmb_browse_ctx->backup_list_data;
        }
        prtsmb_browse_ctx->domain[i].num_backups = 0;
    }
    prtsmb_browse_ctx->backup_list_data[0] = 0;
    prtsmb_browse_ctx->backup_list_used = 0;
    prtsmb_browse_ctx->num_domains = 0;
}

RTSMB_STATIC
int _get_next_domain (void)
{
    if (prtsmb_browse_ctx->num_domains < CFG_RTSMB_BROWSE_MAX_DOMAINS)
    {
        prtsmb_browse_ctx->num_domains++;
        return (prtsmb_browse_ctx->num_domains - 1);
    }

    return -1;
}

RTSMB_STATIC
void _add_to_domain (int domain_index, PFRTCHAR server_name, int name_len)
{
    if (prtsmb_browse_ctx->domain[domain_index].num_backups < CFG_RTSMB_BROWSE_MAX_BACKUP_SERVERS &&
        prtsmb_browse_ctx->backup_list_used + name_len + 1 < prtsmb_browse_ctx->backup_list_size)
    {
        PFRTCHAR s;
        s = prtsmb_browse_ctx->backup_list_data + prtsmb_browse_ctx->backup_list_used;
        rtsmb_cpy(s, server_name);
        prtsmb_browse_ctx->backup_list_used += name_len + 1;

        prtsmb_browse_ctx->domain[domain_index].server_name[prtsmb_browse_ctx->domain[domain_index].num_backups++] = s;
    }
}

RTSMB_STATIC
int rtsmb_nbds_process_backup_list_response (PFVOID buf, rtsmb_size size)
{
    byte b, count;
    dword token;
    int d;

    READ_BYTE (buf, &size, &b, -1); /* opcode */
    ASSURE (b == 10, -1);
    READ_BYTE (buf, &size, &count, -1);
    READ_DWORD (buf, &size, &token, FALSE, -1);

#if (DEBUG_BACKUP_TABLE)
    rtp_printf("rtsmb_nbds_process_backup_list_response() - GOT RESPONSE %d %d\n",
            token, rtsmb_nbds_backup_table_token);
#endif
    /* If this is a new token request, we overwrite the table.
       If this is an old token request, we append to the table. */
    if (token != rtsmb_nbds_backup_table_token)
    {
#if (DEBUG_BACKUP_TABLE)
        rtp_printf("rtsmb_nbds_process_backup_list_response() - token does not match so 1st response %d %d\n",
            token, rtsmb_nbds_backup_table_token);
#endif
        /* we are overwriting table */
        _clear_backup_table();
        rtsmb_nbds_backup_table_token = token;
        rtsmb_nbds_backup_table_expiration_base = rtp_get_system_msec ();
        rtsmb_nbds_backup_table_expiration_delay = RTSMB_NBDS_BACKUP_EXPIRE_DELAY;
    }

    d = _get_next_domain();
    if (d >= 0)
    {
#if (DEBUG_BACKUP_TABLE)
        rtp_printf("rtsmb_nbds_process_backup_list_response() - count returned %d\n",
            count);
#endif
        for (; count > 0; count--)
        {
            rtsmb_char name [RTSMB_NB_NAME_SIZE+1];
            READ_STRING (buf, &size, name, (RTSMB_NB_NAME_SIZE+1), (PFVOID)0, -1);
#if (DEBUG_BACKUP_TABLE)
            smb_print_unicode("rtsmb_nbds_process_backup_list_response() - writing in backup table", 
                name);
#endif
            _add_to_domain (d, name, RTSMB_NB_NAME_SIZE);
        }
    }

    return 0;
}


void rtsmb_nbds_init (void)
{
    unsigned long current_time = rtp_get_system_msec ();

    // sprspr - move outside of if do can redo rtsmb_cli_session_server_enum()
    rtsmb_nbds_backup_table_expiration_base = current_time;
    rtsmb_nbds_backup_table_expiration_delay = 0;

    if (rtsmb_nbds_initialized_ever == 0)
    {
        rtsmb_browse_config ();

        rtsmb_nbds_backup_table_token = 0;

        rtp_sig_mutex_alloc(&rtsmb_nbds_mutex, (const char*)0);
    }

    RTSMB_CLAIM_MUTEX(rtsmb_nbds_mutex);

    if (rtsmb_nbds_initialized_count == 0)
    {
        _clear_backup_table();

        if (rtsmb_net_socket_new (&rtsmb_nbds_datagram_socket, rtsmb_nbds_port, FALSE) >= 0)
        {
            if (rtp_net_setbroadcast(rtsmb_nbds_datagram_socket, 1) < 0)
            {
                RTSMB_DEBUG_OUTPUT_STR("Error occurred while trying to set broadcast on socket\n", RTSMB_DEBUG_TYPE_ASCII);
            }
        }
        else
        {
            RTSMB_DEBUG_OUTPUT_STR("Socket alloc failed\n", RTSMB_DEBUG_TYPE_ASCII);
        }

        rtsmb_nbds_last_cycle_time = current_time;
    }

    rtsmb_nbds_initialized_count += 1;
    rtsmb_nbds_initialized_ever = 1;

    RTSMB_RELEASE_MUTEX(rtsmb_nbds_mutex);
}

void rtsmb_nbds_cycle (long timeout)
{
    RTP_SOCKET socket;

    RTSMB_CLAIM_MUTEX(rtsmb_nbds_mutex);

    socket = rtsmb_nbds_datagram_socket;

    while (rtsmb_netport_select_n_for_read (&socket, 1, timeout))
    {
        int size;
        byte remote_ip [4];

        /* so that future selects will happen instantly */
        timeout = 0;

        size = rtsmb_net_read_datagram (socket, prtsmb_browse_ctx->buffer, prtsmb_browse_ctx->buffer_size, remote_ip, (PFINT)0);

        if (tc_memcmp (remote_ip,rtsmb_net_get_host_ip(), 4) != 0)
        {
            /* only handle datagrams that don't originate from us */
            if (size >= 0)
            {
                RTSMB_NBDS_HEADER nbs_header;
                RTSMB_HEADER smb_header;
                RTSMB_TRANSACTION trans;
                rtsmb_char mailslot_name [20];
                PFVOID buf, smb_start;
                int r;
                byte command;

                trans.name = mailslot_name;
                trans.name_size = 19;

                buf = prtsmb_browse_ctx->buffer;
                r = rtsmb_nbds_read_header (prtsmb_browse_ctx->buffer, buf, (rtsmb_size) size, &nbs_header);
                if (r < 0) {continue;}
                buf = PADD (buf, r);
                size -= r;

                tc_memcpy (rtsmb_nbds_last_remote_ip, nbs_header.source_ip, 4);
                tc_strcpy (rtsmb_nbds_last_remote_name, nbs_header.source_name);
                rtsmb_nbds_last_remote_port = nbs_header.source_port;

                smb_start = buf;
                r = rtsmb_nbds_read_smb_header (prtsmb_browse_ctx->buffer, buf, (rtsmb_size) size, &smb_header);
                if (r < 0) {continue;}
                buf = PADD (buf, r);
                size -= r;

                r = rtsmb_nbds_read_transaction (prtsmb_browse_ctx->buffer, buf, (rtsmb_size) size, &smb_header, &trans);
                if (r < 0) {continue;}
                buf = PADD (buf, r);
                size -= r;

                /* ok, we're in browse country.  let's peek at the command */
                if (size < 1) {continue;}
                tc_memcpy (&command, buf, 1);

                /* we only handle one command ourselves.  The rest we punt to the server
                   if it is around */
                switch (command)
                {
                    case RTSMB_NBDS_COM_GET_BACKUP_LIST_RESPONSE:
                        /* backup list response */
#if (DEBUG_BACKUP_TABLE)
                        rtp_printf("process BACKUP LIST response\n");
#endif
                        rtsmb_nbds_process_backup_list_response (buf, (rtsmb_size)size);
                        break;
                }

                RTSMB_CLAIM_MUTEX(prtsmb_browse_ctx->mutex);

                if (rtsmb_glue_process_nbds_message)
                {
                    (*rtsmb_glue_process_nbds_message) (nbs_header.destination_name,
                        command, smb_start, buf, (rtsmb_size)size, &smb_header);
                }

                RTSMB_RELEASE_MUTEX((RTP_MUTEX) prtsmb_browse_ctx->mutex);
            }
        }
#if (DEBUG_BACKUP_TABLE)
        else
        {
            rtp_printf("rtsmb_nbds_cycle - ignore response from self %d.%d.%d.%d\n",
                remote_ip[0],
                remote_ip[1],
                remote_ip[2],
                remote_ip[3]);
        }
#endif
    }

    rtsmb_nbds_last_cycle_time = rtp_get_system_msec ();

    RTSMB_RELEASE_MUTEX(rtsmb_nbds_mutex);
}

void rtsmb_nbds_shutdown (void)
{
    RTSMB_CLAIM_MUTEX(rtsmb_nbds_mutex);

    rtsmb_nbds_initialized_count -= 1;

    if (rtsmb_nbds_initialized_count == 0)
    {
        if (rtp_net_closesocket(rtsmb_nbds_datagram_socket))
        {
            RTSMB_DEBUG_OUTPUT_STR("ERROR IN CLOSESOCKET\n", RTSMB_DEBUG_TYPE_ASCII);
        }
    }

    RTSMB_RELEASE_MUTEX(rtsmb_nbds_mutex);
}

/* get's the i'th backup server, which corresponds to the i'th domain available */
int rtsmb_nbds_get_backup_server (int domain_index, PFCHAR dest, int alt_index)
{
    int rv;
    unsigned long current_time;

    RTSMB_CLAIM_MUTEX(rtsmb_nbds_mutex);

    current_time = rtp_get_system_msec ();

    /* only send if we are expired and we have cycled since we have expired */
    if (IS_PAST_THIS (current_time, rtsmb_nbds_backup_table_expiration_base, rtsmb_nbds_backup_table_expiration_delay) &&
        IS_PAST_THIS (rtsmb_nbds_last_cycle_time, rtsmb_nbds_backup_table_expiration_base, rtsmb_nbds_backup_table_expiration_delay))
    {
        /* clear the table */
        _clear_backup_table();

        /* and try to fill it */
        if (rtsmb_nbds_send_get_backup_list () < 0)
        {
            RTSMB_DEBUG_OUTPUT_STR("rtsmb_nbds_get_backup_server: Error sending backup list request\n", RTSMB_DEBUG_TYPE_ASCII);
        }

        /* set delay 'til the next time we try */
        rtsmb_nbds_backup_table_expiration_base = current_time;
        rtsmb_nbds_backup_table_expiration_delay = RTSMB_NBDS_BACKUP_RETRY_DELAY;
    }

    if (domain_index < 0 ||
        domain_index >= prtsmb_browse_ctx->num_domains ||
        alt_index < 0 ||
        alt_index >= prtsmb_browse_ctx->domain[domain_index].num_backups)
    {
        rv = -1;
    }
    else
    {
        //sends the request using the Latin codepage
        rtsmb_util_rtsmb_to_ascii (prtsmb_browse_ctx->domain[domain_index].server_name[alt_index], 
                                   dest, RTSMB_CODEPAGE_LATIN1);
        rv = 0;
    }

    RTSMB_RELEASE_MUTEX(rtsmb_nbds_mutex);

    return rv;
}

RTP_SOCKET rtsmb_nbds_get_socket (void)
{
    return rtsmb_nbds_datagram_socket;
}
