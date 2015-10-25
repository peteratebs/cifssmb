/*                                                                          */
/* SRVBRWS.C -                                                              */
/*                                                                          */
/* EBSnet - RTSMB                                                           */
/*                                                                          */
/* Copyright EBSnet Inc. , 2003                                             */
/* All rights reserved.                                                     */
/* This code may not be redistributed in source or linkable object form     */
/* without the consent of its author.                                       */
/*                                                                          */
/* Module description:                                                      */
/* Handles half of the NETBIOS Browser Service elections and announcements. */
/* The other half handled by srvbrbuf.c                                     */
/*                                                                          */

#include "smbdefs.h"
#include "rtprand.h" /* _YI_ 9/24/2004 */
#if (INCLUDE_RTSMB_SERVER)

#include "srvbrws.h"
#include "smbnb.h"
#include "smbnbds.h"
#include "smbbrcfg.h"
#include "srvcfg.h"
#include "srvnbns.h"
#include "srvbrbuf.h"
#include "smbutil.h"
#include "smbnet.h"
#include "srvbrbak.h"
#include "smbdebug.h"


#include "rtptime.h"
#include "rtpsignl.h"

/* these two are for testing purposes   */
#define CFG_RTSMB_SRV_BROWSE_FORCE_MASTER             0 /* set to 1 to force RTSMB as the master browser */
#define CFG_RTSMB_SRV_BROWSE_FORCE_BACKUP             0 /* set to 1 to force RTSMB as a backup browser */


#define RTSMB_SRV_BROWSE_NORMALS_TO_BACKUPS           4 /* how many normal servers each backup server can be expected to handle */

#define RTSMB_SRV_BROWSE_ELECTION_TIMEOUT             3000 /* 3 seconds, the max another server can challenge us within */
#define RTSMB_SRV_BROWSE_MASTER_BROWSER_EXPIRE_DELAY  900000 /* 15 minutes */


/**
 * Private data for the browser service.
 */

RTSMB_STATIC BBOOL         rtsmb_srv_browse_announcement_send = FALSE;
RTSMB_STATIC byte          rtsmb_srv_browse_announcement_count;
RTSMB_STATIC unsigned long rtsmb_srv_browse_announcement_next_base;
RTSMB_STATIC unsigned long rtsmb_srv_browse_announcement_next_delay;

RTSMB_STATIC BBOOL         rtsmb_srv_browse_election_waiting_to_send;
RTSMB_STATIC unsigned long rtsmb_srv_browse_election_next_base;
RTSMB_STATIC unsigned long rtsmb_srv_browse_election_next_delay;
RTSMB_STATIC unsigned long rtsmb_srv_browse_election_last_send;
RTSMB_STATIC int           rtsmb_srv_browse_election_win_count; /* if negative, means we have lost and aren't participating */

RTSMB_STATIC unsigned long rtsmb_srv_browse_master_last_domain_announcement;

RTSMB_STATIC int           rtsmb_srv_browse_role;

RTSMB_STATIC BBOOL         rtsmb_srv_browse_query_master_are_querying;
RTSMB_STATIC unsigned long rtsmb_srv_browse_query_master_expire_base;
RTSMB_STATIC unsigned long rtsmb_srv_browse_query_master_expire_delay;


int rtsmb_srv_browse_get_role (void)
{
    return rtsmb_srv_browse_role;
}

dword rtsmb_srv_browse_get_announcement_interval (void)
{
    dword rv;

    /* return a value for the *next* interval -- so that servers
       don't get confused on why we are not posting our next
       announcement in the interval specified. */

    if      (rtsmb_srv_browse_announcement_count + 1 < 5)  /* 30 seconds */
        rv = 30000;
    else if (rtsmb_srv_browse_announcement_count + 1 < 10)  /* 1 minute */
        rv = 60000;
    else if (rtsmb_srv_browse_announcement_count + 1 < 15)  /* 5 minutes */
        rv = 300000;
    else
        rv = 720000;      /* 12 minutes */

    return rv;
}

dword rtsmb_srv_browse_get_server_type (void)
{
    dword rv = SV_TYPE_SERVER | SV_TYPE_PRINTQ_SERVER | SV_TYPE_POTENTIAL_BROWSER;

    switch (rtsmb_srv_browse_get_role ())
    {
    case RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER:
        rv |= SV_TYPE_MASTER_BROWSER;
        rv |= SV_TYPE_BACKUP_BROWSER;
        break;

    case RTSMB_SRV_BROWSE_ROLE_DOMAIN_MASTER_BROWSER:
        rv |= SV_TYPE_DOMAIN_MASTER;
        rv |= SV_TYPE_MASTER_BROWSER;
        rv |= SV_TYPE_BACKUP_BROWSER;
        break;

    case RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER:
        rv |= SV_TYPE_BACKUP_BROWSER;
        break;
    }

    return rv;
}


RTSMB_STATIC
void rtsmb_srv_browse_switch_role (int new_role)
{
    if (rtsmb_srv_browse_get_role () == new_role)
        return;

    switch (rtsmb_srv_browse_get_role ())
    {
    case RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER:
        rtsmb_srv_browse_backup_stop ();
        break;
    }

    rtsmb_srv_browse_role = new_role;

    switch (rtsmb_srv_browse_get_role ())
    {
    case RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER:
        rtsmb_srv_browse_backup_start ();
        break;

        /* must set up our timers for querying the master   */
    case RTSMB_SRV_BROWSE_ROLE_POTENTIAL_BROWSER:
        rtsmb_srv_browse_query_master_expire_base = rtp_get_system_msec();
        rtsmb_srv_browse_query_master_expire_delay = 0;
        rtsmb_srv_browse_query_master_are_querying = FALSE;
        break;
    }
}



RTSMB_STATIC void rtsmb_srv_browse_our_info (PRTSMB_BROWSE_SERVER_INFO pinfo)
{
    pinfo->update_count = 0;
    pinfo->periodicity = rtsmb_srv_browse_get_announcement_interval ();
    tc_strcpy (pinfo->name, rtsmb_srv_nbns_get_our_name ());
    tc_strcpy (pinfo->comment, CFG_RTSMB_DEFAULT_COMMENT);
    pinfo->version_major = 4;
    pinfo->version_minor = 0;
    pinfo->type = rtsmb_srv_browse_get_server_type ();
    pinfo->browse_version_major = RTSMB_NBDS_BROWSER_VERSION_MAJOR;
    pinfo->browse_version_minor = RTSMB_NBDS_BROWSER_VERSION_MINOR;
    pinfo->signature = 0xaa55;
    pinfo->time_received = rtp_get_system_msec();
}

RTSMB_STATIC void rtsmb_srv_browse_update_entry (PRTSMB_BROWSE_SERVER_INFO plist, rtsmb_size list_size, PRTSMB_BROWSE_SERVER_INFO pinfo)
{
    int i, empty_entry = -1;

    for (i = (int)list_size - 1; i >= 0; i--)
    {
        if (plist[i].type == 0)
        {
            empty_entry = i;
        }
        else
        {
            if (rtsmb_strcasecmp (plist[i].name, pinfo->name, CFG_RTSMB_USER_CODEPAGE) == 0)
            {
                /* we found it on our list already -- update info   */
                empty_entry = i;
                break;
            }
        }
    }

    if (empty_entry >= 0)
    {
        /* ok.  fill out 'empty_entry' with this new info and mark it authoritative   */
        plist[empty_entry] = *pinfo;
        plist[empty_entry].type |= SV_TYPE_LOCAL_LIST_ONLY;
    }
}



RTSMB_STATIC int rtsmb_srv_browse_send_host_announcement (BBOOL shutdown)
{
    int r;

    r = rtsmb_srv_browse_fill_whole_announcement (FALSE, shutdown);

    if (r >= 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_browse_send_host_announcement: Broadcasting a host announcement.\n", RTSMB_DEBUG_TYPE_ASCII);

        rtsmb_srv_browse_announcement_count ++;
        r = rtsmb_nbds_write (prtsmb_browse_ctx->buffer, (rtsmb_size)r, rtsmb_net_get_broadcast_ip (), 
                              rtsmb_nbds_port);
    }

    return r;
}

RTSMB_STATIC int rtsmb_srv_browse_send_domain_announcement (void)
{
    int r;

    r = rtsmb_srv_browse_fill_whole_announcement (TRUE, FALSE);

    if (r >= 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_nbds_send_domain_announcement: Broadcasting a domain announcement.\n", RTSMB_DEBUG_TYPE_ASCII);

        r = rtsmb_nbds_write (prtsmb_browse_ctx->buffer, (rtsmb_size)r, rtsmb_net_get_broadcast_ip (), 
                              rtsmb_nbds_port);
    }

    return r;
}


RTSMB_STATIC int rtsmb_srv_browse_send_request_election (void)
{
    int r;

    r = rtsmb_srv_browse_fill_whole_request_election ();

    if (r >= 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_nbds_send_request_election: Sending election request.\n", RTSMB_DEBUG_TYPE_ASCII);

        r = rtsmb_nbds_write (prtsmb_browse_ctx->buffer, (rtsmb_size)r, rtsmb_net_get_broadcast_ip (), 
                              rtsmb_nbds_port);

        /* in three seconds, if we have not heard back from anybody, we should broadcast again   */
        rtsmb_srv_browse_election_last_send = rtp_get_system_msec();
    }

    return r;
}

RTSMB_STATIC int rtsmb_srv_browse_send_become_backup (PFCHAR name)
{
    int r;

    r = rtsmb_srv_browse_fill_whole_become_backup (name);

    if (r >= 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_nbds_send_become_backup: Sending become backup promotion.\n", RTSMB_DEBUG_TYPE_ASCII);

        r = rtsmb_nbds_write (prtsmb_browse_ctx->buffer, (rtsmb_size)r, rtsmb_net_get_broadcast_ip (), 
                              rtsmb_nbds_port);
    }

    return r;
}

RTSMB_STATIC int rtsmb_srv_browse_send_announcement_request (void)
{
    int r;

    r = rtsmb_srv_browse_fill_whole_announcement_request ();

    if (r >= 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_browse_send_announcement_request: Sending announcement request.\n", RTSMB_DEBUG_TYPE_ASCII);

        r = rtsmb_nbds_write (prtsmb_browse_ctx->buffer, (rtsmb_size)r, rtsmb_net_get_broadcast_ip (), 
                              rtsmb_nbds_port);
    }

    return r;
}

dword rtsmb_srv_browse_get_election_criteria (void)
{
    dword rv = 0;

#if (CFG_RTSMB_SRV_BROWSE_FORCE_MASTER)
    /* give ourselves the best criteria possible   */
    return 0xFFFFFFFF;
#endif

    /* version   */
    rv |= (RTSMB_NBDS_BROWSER_VERSION << 8);

    /* role   */
    switch (rtsmb_srv_browse_get_role ())
    {
    case RTSMB_SRV_BROWSE_ROLE_DOMAIN_MASTER_BROWSER:
        rv |= 0x80;
        break;

    case RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER:
        rv |= 0x04;
        break;

    case RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER:
        rv |= 0x1;
        break;
    }

    return rv;
}

RTSMB_STATIC BBOOL rtsmb_srv_browse_have_won_election (PRTSMB_NBDS_REQUEST_ELECTION pinfo)
{
    char server_name_ascii [17];

    /* This function follows draft-leach-cifs-browser-spec-00.txt rules for winning
       an election. */

    if (rtsmb_srv_browse_election_win_count < 0) /* if we lost in this election already */
    {
        return FALSE;
    }

    if (pinfo->version < RTSMB_NBDS_ELECTION_VERSION)
    {
        return TRUE;
    }
    if (pinfo->criteria < rtsmb_srv_browse_get_election_criteria ())
    {
        return TRUE;
    }
#if (0)
    if (pinfo->up_time < 0) /* FIXME: need some way to tell our uptime? */ 
    {                
        return TRUE; 
    }                
#endif

    rtsmb_util_rtsmb_to_ascii (pinfo->server_name, server_name_ascii, CFG_RTSMB_USER_CODEPAGE);

    if (tc_strcmp (server_name_ascii, rtsmb_srv_nbns_get_our_name ()) > 0)
    {
        return TRUE;
    }

    return FALSE;
}


void rtsmb_srv_browse_force_election (void)
{
    int r;

    if (rtsmb_srv_browse_election_win_count != 0)
    {
        /* there is already an election going on   */
        return;
    }

    r = rtsmb_srv_browse_fill_whole_request_election ();

    if (r >= 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_nbds_force_election: Forcing election.\n", RTSMB_DEBUG_TYPE_ASCII);

        r = rtsmb_nbds_write (prtsmb_browse_ctx->buffer, (rtsmb_size)r, rtsmb_net_get_broadcast_ip (), 
                              rtsmb_nbds_port);

        /* in three seconds, if we have not heard back from anybody, we should broadcast again   */
        rtsmb_srv_browse_election_last_send = rtp_get_system_msec();

        rtsmb_srv_browse_election_win_count = 1;
    }
}


/* this makes sure that there aren't too many more normal servers to backup servers.
   If there are, it promotes a random potential browser */
RTSMB_STATIC void rtsmb_srv_browse_ensure_backup_ratio (void)
{
    int i, num_total = 0, num_backup = 0, num_potentials = 0, backup_server = -1;

    for (i = 0; i < prtsmb_srv_ctx->server_table_size; i++)
    {
        if (prtsmb_srv_ctx->server_table[i].type)
        {
            num_total ++;

            if (ON (prtsmb_srv_ctx->server_table[i].type, SV_TYPE_BACKUP_BROWSER))
            {
                num_backup ++;
            }
            else if (ON (prtsmb_srv_ctx->server_table[i].type, SV_TYPE_POTENTIAL_BROWSER))
            {
                num_potentials ++;
            }
        }
    }

    if (num_backup * RTSMB_SRV_BROWSE_NORMALS_TO_BACKUPS < num_total)
    {
        /* not enough backups, we need to promote someone   */
        int target = tc_rand () % num_potentials;

        for (i = 0; i < prtsmb_srv_ctx->server_table_size; i++)
        {
            if (prtsmb_srv_ctx->server_table[i].type)
            {
                if (OFF (prtsmb_srv_ctx->server_table[i].type, SV_TYPE_BACKUP_BROWSER) &&
                    ON  (prtsmb_srv_ctx->server_table[i].type, SV_TYPE_POTENTIAL_BROWSER))
                {
                    if (target == 0)
                    {
                        backup_server = i;
                        break;
                    }
                    else
                    {
                        target --;
                    }
                }
            }
        }
    }

    if (backup_server >= 0)
    {
        rtsmb_srv_browse_send_become_backup (prtsmb_srv_ctx->server_table[backup_server].name);
    }
}


RTSMB_STATIC int rtsmb_srv_browse_election_takeover (void)
{
    RTSMB_BROWSE_SERVER_INFO info;

    RTSMB_DEBUG_OUTPUT_STR("rtsmb_nbds_election_takeover: Taking over master browser role\n", RTSMB_DEBUG_TYPE_ASCII);

    rtsmb_srv_browse_election_win_count = 0;

    rtsmb_srv_browse_switch_role (RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER);

    rtsmb_srv_browse_announcement_next_base = rtp_get_system_msec();
    rtsmb_srv_browse_announcement_next_delay = 0;

    /* always request announcements, since our list from being a backup browser
       does not contain all the info a host announcement does */
/*  if (rtsmb_browse_server_list_is_empty ())   */
    {
        rtsmb_srv_browse_send_announcement_request ();
    }

    /* fill in one spot in our lists with ourselves   */
    rtsmb_srv_browse_our_info (&info);

    /* Except, change the periodicity to the maximum value
       so that we don't often try to remove ourselves from
       the list, which causes a costly comparison with the
       name to make sure it's not us. */
    info.periodicity = 0xFFFFFFFF;

    rtsmb_srv_browse_update_entry (prtsmb_srv_ctx->server_table,
        (rtsmb_size )prtsmb_srv_ctx->server_table_size, &info);

    tc_strcpy (info.name, rtsmb_srv_nbns_get_our_group ());
    tc_strcpy (info.comment, rtsmb_srv_nbns_get_our_name ());
    info.type |= SV_TYPE_DOMAIN_ENUM;

    rtsmb_srv_browse_update_entry (prtsmb_srv_ctx->domain_table,
        (rtsmb_size )prtsmb_srv_ctx->domain_table_size, &info);


    /* register master browser names for our group   */
    rtsmb_srv_nbns_add_name (rtsmb_srv_nbns_get_our_group (), FALSE, RTSMB_NB_NAME_TYPE_MASTER_BROWSER, TRUE);
    rtsmb_srv_nbns_add_name (RTSMB_NB_MASTER_BROWSER_NAME, TRUE, 0x1, TRUE);


    /* check if we have enough backup browsers   */
    rtsmb_srv_browse_ensure_backup_ratio ();


    /* make sure that we immediately announce our domain   */
    rtsmb_srv_browse_master_last_domain_announcement = rtp_get_system_msec() - RTSMB_SRV_BROWSE_DOMAIN_ANNOUNCE_DELAY;

    return 0;
}


RTSMB_STATIC int rtsmb_srv_browse_process_request_election (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_HEADER pheader)
{
    RTSMB_NBDS_REQUEST_ELECTION request;

    if (rtsmb_srv_browse_read_request_election (origin, buf, size, pheader, &request) < 0)
    {
        return -1;
    }

    /* check if we won.  If so, send out another request.  If not, ignore   */
    if (rtsmb_srv_browse_have_won_election (&request))
    {
        rtsmb_srv_browse_election_win_count ++;

        if (rtsmb_srv_browse_election_win_count >= 4)
        {
            rtsmb_srv_browse_election_takeover ();
            return 0;
        }

        rtsmb_srv_browse_election_next_base = rtp_get_system_msec();

        switch (rtsmb_srv_browse_get_role ())
        {
        case RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER:
        case RTSMB_SRV_BROWSE_ROLE_DOMAIN_MASTER_BROWSER:
            rtsmb_srv_browse_election_next_delay = 100;
            break;

        case RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER:
            rtsmb_srv_browse_election_next_delay = (dword) (tc_rand () % 401 + 200);
            break;

        default:
            rtsmb_srv_browse_election_next_delay = (dword) (tc_rand () % 2201 + 800);
            break;
        }
        rtsmb_srv_browse_election_waiting_to_send = TRUE;
    }
    else
    {
        /* we've lost this election   */

        if (rtsmb_srv_browse_election_win_count >= 0) /* do this just once */
        {
            if (rtsmb_srv_browse_get_role () == RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER)
            {
                rtsmb_srv_browse_switch_role (RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER);

                rtsmb_srv_nbns_remove_name (rtsmb_srv_nbns_get_our_group (), RTSMB_NB_NAME_TYPE_MASTER_BROWSER);
                rtsmb_srv_nbns_remove_name (RTSMB_NB_MASTER_BROWSER_NAME, 0x1);
            }
        }

        rtsmb_srv_browse_election_win_count = -1;
    }

    return 0;
}

RTSMB_STATIC int rtsmb_srv_browse_process_become_backup (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_HEADER pheader)
{
    RTSMB_NBDS_BECOME_BACKUP request;
    char name [RTSMB_NB_NAME_SIZE + 1];

    if (rtsmb_srv_browse_read_become_backup (origin, buf, size, pheader, &request) < 0)
    {
        return -1;
    }

    rtsmb_util_rtsmb_to_ascii (request.name, name, CFG_RTSMB_USER_CODEPAGE);

    /* check if we are to become a backup browser.  If not, ignore   */
    if (rtsmb_strcasecmp (rtsmb_srv_nbns_get_our_name (), name, CFG_RTSMB_USER_CODEPAGE) == 0)
    {
        rtsmb_srv_browse_switch_role (RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER);
    }

    return 0;
}


RTSMB_STATIC int rtsmb_srv_browse_process_domain_announcement (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_HEADER pheader)
{
    RTSMB_NBDS_HOST_ANNOUNCEMENT host;
    char group_name [RTSMB_NB_NAME_SIZE + 1];
    rtsmb_char master_name_rt [RTSMB_NB_NAME_SIZE + 1];

    host.comment = master_name_rt;
    host.comment_size = RTSMB_NB_NAME_SIZE;
    if (rtsmb_srv_browse_read_host_announcement (origin, buf, size, pheader, &host) < 0)
    {
        return -1;
    }

    rtsmb_util_rtsmb_to_ascii (host.server_name, group_name, CFG_RTSMB_USER_CODEPAGE);

    if (rtsmb_srv_browse_get_role () == RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER)
    {
        RTSMB_BROWSE_SERVER_INFO info;

        /* if this group is our group, someone is encroaching on our responsibilities.
           force election to see who is really master */
        if (tc_strcmp (group_name, rtsmb_srv_nbns_get_our_group ()) == 0)
        {
            rtsmb_srv_browse_force_election ();
            return 0;
        }

        /* search through our list and update entry   */

        rtsmb_util_rtsmb_to_ascii (host.server_name, info.name, CFG_RTSMB_USER_CODEPAGE);
        info.type = host.type;
        info.version_minor = host.version_minor;
        info.version_major = host.version_major;
        info.browse_version_minor = host.browse_version_major;
        info.browse_version_major = host.browse_version_major;
        info.signature = host.signature;
        info.update_count = host.update_count;
        info.periodicity = host.periodicity;
        rtsmb_util_rtsmb_to_ascii (host.comment, info.comment, CFG_RTSMB_USER_CODEPAGE);

        info.time_received = rtp_get_system_msec();

        rtsmb_srv_browse_update_entry (prtsmb_srv_ctx->domain_table,
            (rtsmb_size )prtsmb_srv_ctx->domain_table_size, &info);
    }

    return 0;
}

RTSMB_STATIC int rtsmb_srv_browse_process_host_announcement (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_HEADER pheader)
{
    RTSMB_NBDS_HOST_ANNOUNCEMENT host;
    RTSMB_BROWSE_SERVER_INFO info;
    rtsmb_char comment_rt [RTSMB_MAX_COMMENT_SIZE + 1];

    host.comment = comment_rt;
    host.comment_size = RTSMB_MAX_COMMENT_SIZE;
    if (rtsmb_srv_browse_read_host_announcement (origin, buf, size, pheader, &host) < 0)
    {
        return -1;
    }

    if (host.opcode == RTSMB_NBDS_COM_LOCAL_MASTER_ANNOUNCEMENT)
    {
        /* cache this name of our local master browser   */
        rtsmb_util_rtsmb_to_ascii (host.server_name, prtsmb_srv_ctx->local_master, CFG_RTSMB_USER_CODEPAGE);
    }
    else if (host.opcode == RTSMB_NBDS_COM_HOST_ANNOUNCEMENT)
    {
        if (host.type == 0)
        {
            char server_name [RTSMB_NB_NAME_SIZE + 1];

            rtsmb_util_rtsmb_to_ascii (host.server_name, server_name, CFG_RTSMB_USER_CODEPAGE);

            /* if the local master is shutting down, we need to force an election   */
            if (tc_strcmp (server_name, prtsmb_srv_ctx->local_master) == 0)
            {
                rtsmb_srv_browse_force_election ();
            }
        }
    }

    if (rtsmb_srv_browse_get_role () == RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER)
    {
        /* if the type indicates a master browser, someone is encroaching on our responsibilities.
           Force election to see who is really master */
        if (ON (host.type, SV_TYPE_MASTER_BROWSER))
        {
            rtsmb_srv_browse_force_election ();
            return 0;
        }

        /* search through our list and update entry   */

        rtsmb_util_rtsmb_to_ascii (host.server_name, info.name, CFG_RTSMB_USER_CODEPAGE);
        info.type = host.type;
        info.version_minor = host.version_minor;
        info.version_major = host.version_major;
        info.browse_version_minor = host.browse_version_major;
        info.browse_version_major = host.browse_version_major;
        info.signature = host.signature;
        info.update_count = host.update_count;
        info.periodicity = host.periodicity;
        rtsmb_util_rtsmb_to_ascii (host.comment, info.comment, CFG_RTSMB_USER_CODEPAGE);

        info.time_received = rtp_get_system_msec();

        rtsmb_srv_browse_update_entry (prtsmb_srv_ctx->server_table,
            (rtsmb_size )prtsmb_srv_ctx->server_table_size, &info);

        /* check if we have enough backup browsers   */
        rtsmb_srv_browse_ensure_backup_ratio ();
    }

    return 0;
}

RTSMB_STATIC int rtsmb_srv_browse_process_backup_list_request (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_HEADER pheader)
{
    RTSMB_BROWSE_GET_BACKUP_LIST command;
    int r;

    if (rtsmb_srv_browse_get_role () != RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER)
        return 0;

    if (rtsmb_nbds_read_get_backup_list (origin, buf, size, pheader, &command) < 0)
    {
        return -1;
    }

    r = rtsmb_srv_browse_fill_whole_get_backup_list_response (command.count, command.token);

    if (r >= 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_browse_process_get_backup_list: Sending get backup list response.\n", RTSMB_DEBUG_TYPE_ASCII);

        r = rtsmb_nbds_write (prtsmb_browse_ctx->buffer, (rtsmb_size)r, rtsmb_nbds_get_last_remote_ip (), rtsmb_nbds_get_last_remote_port ());
    }

    return r;
}

RTSMB_STATIC void rtsmb_srv_browse_check_dead_servers (void)
{
    int i;
    BBOOL killed_server = FALSE;
    unsigned long current_time;

    current_time = rtp_get_system_msec();

    /* clear out old (3 times the periodicity) server entries   */
    for (i = 0; i < prtsmb_srv_ctx->server_table_size; i++)
    {
        if (prtsmb_srv_ctx->server_table[i].type)
        {
            if (IS_PAST_THIS (current_time, prtsmb_srv_ctx->server_table[i].time_received,
                              prtsmb_srv_ctx->server_table[i].periodicity * 3) &&
                rtsmb_strcasecmp (prtsmb_srv_ctx->server_table[i].name, rtsmb_srv_nbns_get_our_name (), CFG_RTSMB_USER_CODEPAGE))
            {
                /* kill it   */
                prtsmb_srv_ctx->server_table[i].type = 0;
                RTSMB_DEBUG_OUTPUT_STR ("rtsmb_browse_check_dead_servers: Removing ", RTSMB_DEBUG_TYPE_ASCII);
                RTSMB_DEBUG_OUTPUT_STR (prtsmb_srv_ctx->server_table[i].name, RTSMB_DEBUG_TYPE_ASCII);
                RTSMB_DEBUG_OUTPUT_STR (" from server list due to unresponsiveness.\n", RTSMB_DEBUG_TYPE_ASCII);
                killed_server = TRUE;
            }
        }
    }

    /* do the same for domains   */
    for (i = 0; i < prtsmb_srv_ctx->domain_table_size; i++)
    {
        if (prtsmb_srv_ctx->domain_table[i].type)
        {
            if (IS_PAST_THIS (current_time, prtsmb_srv_ctx->domain_table[i].time_received,
                              prtsmb_srv_ctx->domain_table[i].periodicity * 3) &&
                rtsmb_strcasecmp (prtsmb_srv_ctx->domain_table[i].name, rtsmb_srv_nbns_get_our_group (), CFG_RTSMB_USER_CODEPAGE))
            {
                /* kill it   */
                prtsmb_srv_ctx->domain_table[i].type = 0;
                RTSMB_DEBUG_OUTPUT_STR ("rtsmb_browse_check_dead_servers: Removing ", RTSMB_DEBUG_TYPE_ASCII);
                RTSMB_DEBUG_OUTPUT_STR (prtsmb_srv_ctx->domain_table[i].name, RTSMB_DEBUG_TYPE_ASCII);
                RTSMB_DEBUG_OUTPUT_STR (" from domain list due to unresponsiveness.\n", RTSMB_DEBUG_TYPE_ASCII);

            }
        }
    }

    if (killed_server)
    {
        /* check if we have enough backup browsers   */
        rtsmb_srv_browse_ensure_backup_ratio ();
    }
}


void rtsmb_srv_browse_server_list_remove_all (void)
{
    int i;

    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    for (i = 0; i < prtsmb_srv_ctx->server_table_size; i++)
    {
        prtsmb_srv_ctx->server_table[i].type = 0;
    }

    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
}

void rtsmb_srv_browse_server_list_add (PRTSMB_BROWSE_SERVER_INFO pinfo)
{
    int i;

    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    for (i = 0; i < prtsmb_srv_ctx->server_table_size; i++)
    {
        if (prtsmb_srv_ctx->server_table[i].type == 0)
        {
            prtsmb_srv_ctx->server_table[i] = *pinfo;
            break;
        }
    }

    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
}

void rtsmb_srv_browse_domain_list_remove_all (void)
{
    int i;

    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    for (i = 0; i < prtsmb_srv_ctx->domain_table_size; i++)
    {
        prtsmb_srv_ctx->domain_table[i].type = 0;
    }

    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
}

void rtsmb_srv_browse_domain_list_add (PRTSMB_BROWSE_SERVER_INFO pinfo)
{
    int i;

    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    for (i = 0; i < prtsmb_srv_ctx->domain_table_size; i++)
    {
        if (prtsmb_srv_ctx->domain_table[i].type == 0)
        {
            prtsmb_srv_ctx->domain_table[i] = *pinfo;
            break;
        }
    }

    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
}

long rtsmb_srv_browse_get_next_wake_timeout (void)
{
    long rv = 0x7FFFFFFF;
    unsigned long current_time = rtp_get_system_msec();

    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    if (rtsmb_srv_browse_announcement_send)
    {
        rv = MIN (rv, (long) (rtsmb_srv_browse_announcement_next_base + rtsmb_srv_browse_announcement_next_delay - current_time));
        rv = MAX (0, rv);
    }

    if (rtsmb_srv_browse_election_win_count > 0)
    {
        rv = MIN (rv, (long) (rtsmb_srv_browse_election_next_base + rtsmb_srv_browse_election_next_delay - current_time));
        rv = MAX (0, rv);
    }

    if (rtsmb_srv_browse_get_role () == RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER)
    {
        rv = MIN (rv, (long) (rtsmb_srv_browse_master_last_domain_announcement + RTSMB_SRV_BROWSE_DOMAIN_ANNOUNCE_DELAY - current_time));
        rv = MAX (0, rv);
    }

    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    return (rv == 0x7FFFFFFF) ? -1 : rv;
}

void rtsmb_srv_browse_restart_announcements (void)
{

    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    rtsmb_srv_browse_announcement_count = 0;
    rtsmb_srv_browse_announcement_next_base = rtp_get_system_msec();
    rtsmb_srv_browse_announcement_next_delay = 0;

    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
}

void rtsmb_srv_browse_set_announcement_info (BBOOL send)
{
    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    rtsmb_srv_browse_announcement_send = send;

    if (!send)
    {
        /* if we're stopping browser service, demote ourselves to potential
           browser */
        rtsmb_srv_browse_switch_role (RTSMB_SRV_BROWSE_ROLE_POTENTIAL_BROWSER);
    }

    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
}

RTSMB_STATIC void rtsmb_srv_browse_check_master_browser (void)
{
    if (rtsmb_srv_browse_election_win_count != 0)
    {
        /* An election is going on.
           We shouldn't mess with master browser until that is done. */
        return;
    }

    if (rtsmb_srv_browse_query_master_are_querying)
    {
        if (IS_PAST (rtsmb_srv_browse_query_master_expire_base,
                          rtsmb_srv_browse_query_master_expire_delay))
        {
            /* The master server has not responded in a timely fashion.  We must therefore
               force an election. */
            rtsmb_srv_browse_force_election ();
            rtsmb_srv_browse_query_master_are_querying = FALSE;
            return;
        }
    }
    else
    {
        if (IS_PAST (rtsmb_srv_browse_query_master_expire_base,
                          rtsmb_srv_browse_query_master_expire_delay))
        {
            /* The master server's cache value has expired.
               We should remove the master server from our cache and try to find it again.
               This takes care of the problem of a crashed server or whatever. */
            rtsmb_srv_nbns_invalidate_one_name (rtsmb_srv_nbns_get_our_group (), RTSMB_NB_NAME_TYPE_MASTER_BROWSER);
        }
        else
        {
            /* we're not querying, and the name hasn't expired, so we aren't interested anymore   */
            return;
        }
    }

    if (rtsmb_srv_nbns_is_in_name_cache (rtsmb_srv_nbns_get_our_group (), RTSMB_NB_NAME_TYPE_MASTER_BROWSER))
    {
        /* fine, the master browser exists   */

        /* if this is the first time we've found it (i.e., while querying), set an expire
           time for it */
        if (rtsmb_srv_browse_query_master_are_querying)
        {
            rtsmb_srv_browse_query_master_are_querying = FALSE;
            rtsmb_srv_browse_query_master_expire_base = rtp_get_system_msec();
            rtsmb_srv_browse_query_master_expire_delay = RTSMB_SRV_BROWSE_MASTER_BROWSER_EXPIRE_DELAY;
        }
    }
    else if (!rtsmb_srv_browse_query_master_are_querying)
    {
        rtsmb_srv_nbns_start_query_for_name (rtsmb_srv_nbns_get_our_group (), RTSMB_NB_NAME_TYPE_MASTER_BROWSER);
        rtsmb_srv_browse_query_master_are_querying = TRUE;
        rtsmb_srv_browse_query_master_expire_base = rtp_get_system_msec();
        rtsmb_srv_browse_query_master_expire_delay = RTSMB_NB_BCAST_RETRY_TIMEOUT * 3; /* three tries at the name is fair */
    }
}


void rtsmb_srv_browse_init (void)
{
    rtsmb_nbds_init ();

    rtsmb_srv_browse_election_waiting_to_send = FALSE;
    rtsmb_srv_browse_election_win_count = 0;

    rtsmb_srv_browse_announcement_count = 0;
    rtsmb_srv_browse_announcement_next_base = rtp_get_system_msec();
    rtsmb_srv_browse_announcement_next_delay = 0;

    rtsmb_srv_browse_role = RTSMB_SRV_BROWSE_ROLE_POTENTIAL_BROWSER;

    rtsmb_srv_browse_query_master_expire_base = rtp_get_system_msec();
    rtsmb_srv_browse_query_master_expire_delay = 0;
    rtsmb_srv_browse_query_master_are_querying = FALSE;

#if (CFG_RTSMB_SRV_BROWSE_FORCE_MASTER)
    rtsmb_srv_browse_force_election ();
#elif (CFG_RTSMB_SRV_BROWSE_FORCE_BACKUP)
    rtsmb_srv_browse_switch_role (RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER);
#endif
}


void rtsmb_srv_browse_shutdown (void)
{
    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    if (rtsmb_srv_browse_announcement_send)
    {
        rtsmb_srv_browse_send_host_announcement (TRUE);
    }

    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
}


/* prtsmb_browse_ctx->mutex must be claimed before calling this function   */
void rtsmb_srv_browse_process_message (int command, PFVOID origin, PFVOID buf,
                                       rtsmb_size size, PRTSMB_HEADER pheader)
{
    if (!rtsmb_srv_browse_announcement_send)
    {
        return;
    }

    switch (command)
    {
    case RTSMB_NBDS_COM_DOMAIN_ANNOUNCEMENT:
        rtsmb_srv_browse_process_domain_announcement (origin, buf, size, pheader);
        break;

    case RTSMB_NBDS_COM_LOCAL_MASTER_ANNOUNCEMENT:
        /* someone won a recent election   */
        rtsmb_srv_browse_election_win_count = 0; /* we are ready to receive election requests again */

        /* intentional no-break here.  we want to treat local master announcements just like host announcements   */

    case RTSMB_NBDS_COM_HOST_ANNOUNCEMENT:
        rtsmb_srv_browse_process_host_announcement (origin, buf, size, pheader);
        break;

    case RTSMB_NBDS_COM_MASTER_ANNOUNCEMENT:
        break;

    case RTSMB_NBDS_COM_ANNOUNCEMENT_REQUEST:
        /* send announcement                         */
        /* send an announcement within 30 seconds    */
        rtsmb_srv_browse_announcement_next_base = rtp_get_system_msec();
        rtsmb_srv_browse_announcement_next_delay = (dword)(tc_rand () % 30000);
        break;

    case RTSMB_NBDS_COM_REQUEST_ELECTION:
        /* do we win this election?   */
        rtsmb_srv_browse_process_request_election (origin, buf, size, pheader);
        break;

    case RTSMB_NBDS_COM_GET_BACKUP_LIST_REQUEST:
        if (rtsmb_srv_browse_get_role () == RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER)
        {
            rtsmb_srv_browse_process_backup_list_request (origin, buf, size, pheader);
        }
        break;

    case RTSMB_NBDS_COM_BECOME_BACKUP:
        rtsmb_srv_browse_process_become_backup (origin, buf, size, pheader);
        break;
    }
}

void rtsmb_srv_browse_cycle (void)
{
    unsigned long current_time;

    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    if (!rtsmb_srv_browse_announcement_send)
    {

        rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
        return;
    }

    current_time = rtp_get_system_msec ();

    /* Now, do periodic items that we need to fulfill our role.   */

    if (IS_PAST_THIS (current_time, rtsmb_srv_browse_announcement_next_base,
                      rtsmb_srv_browse_announcement_next_delay))
    {
        rtsmb_srv_browse_send_host_announcement (FALSE);
        rtsmb_srv_browse_announcement_next_base = current_time;
        rtsmb_srv_browse_announcement_next_delay = rtsmb_srv_browse_get_announcement_interval ();
    }

    if (rtsmb_srv_browse_election_win_count > 0 && rtsmb_srv_browse_election_waiting_to_send &&
        IS_PAST_THIS (current_time, rtsmb_srv_browse_election_next_base, rtsmb_srv_browse_election_next_delay))
    {
        rtsmb_srv_browse_send_request_election ();
        rtsmb_srv_browse_election_waiting_to_send = FALSE;
    }

    if (rtsmb_srv_browse_election_win_count > 0 &&
        IS_PAST_THIS (current_time,
                      rtsmb_srv_browse_election_last_send, RTSMB_SRV_BROWSE_ELECTION_TIMEOUT))
    {
        /* no one has responded to our election request.  try again or takeover   */
        rtsmb_srv_browse_election_win_count ++;

        if (rtsmb_srv_browse_election_win_count > 4)
        {
            rtsmb_srv_browse_election_takeover ();
        }
        else
        {
            rtsmb_srv_browse_send_request_election ();
        }
    }

    /* do routine job-specific duties   */
    switch (rtsmb_srv_browse_get_role ())
    {
    case RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER:
        rtsmb_srv_browse_backup_cycle ();

        /* INTENTIONAL FALLTHROUGH   */

    /* check for existance of master browser   */
    case RTSMB_SRV_BROWSE_ROLE_POTENTIAL_BROWSER:
        rtsmb_srv_browse_check_master_browser ();
        break;

    case RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER:
        rtsmb_srv_browse_check_dead_servers ();

        if (IS_PAST_THIS (current_time,
                          rtsmb_srv_browse_master_last_domain_announcement,
                          RTSMB_SRV_BROWSE_DOMAIN_ANNOUNCE_DELAY))
        {
            rtsmb_srv_browse_send_domain_announcement ();
            rtsmb_srv_browse_master_last_domain_announcement = rtp_get_system_msec ();
        }

        break;
    }

    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
}

#endif /* INCLUDE_RTSMB_SERVER */
