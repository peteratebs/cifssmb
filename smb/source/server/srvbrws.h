#ifndef __SRV_BROWSE_H__
#define __SRV_BROWSE_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "smbobjs.h"
#include "smbnbds.h"

#define RTSMB_SRV_BROWSE_DOMAIN_ANNOUNCE_DELAY   900000L /* 15 minutes in milliseconds */

/**
 * Browser roles
 */
#define RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER        0
#define RTSMB_SRV_BROWSE_ROLE_DOMAIN_MASTER_BROWSER 1
#define RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER        2
#define RTSMB_SRV_BROWSE_ROLE_POTENTIAL_BROWSER     3



void rtsmb_srv_browse_restart_announcements (void);
void rtsmb_srv_browse_set_announcement_info (BBOOL send);

void rtsmb_srv_browse_init (void);
void rtsmb_srv_browse_cycle (void);
void rtsmb_srv_browse_shutdown (void);

void rtsmb_srv_browse_process_message (int command, PFVOID origin, PFVOID buf, 
									   rtsmb_size size, PRTSMB_HEADER pheader);


dword rtsmb_srv_browse_get_announcement_interval (void);
dword rtsmb_srv_browse_get_election_criteria (void);
int rtsmb_srv_browse_get_role (void);
void rtsmb_srv_browse_force_election (void);

long rtsmb_srv_browse_get_next_wake_timeout (void);

void rtsmb_srv_browse_domain_list_remove_all (void);
void rtsmb_srv_browse_domain_list_add (PRTSMB_BROWSE_SERVER_INFO pinfo);
void rtsmb_srv_browse_server_list_remove_all (void);
void rtsmb_srv_browse_server_list_add (PRTSMB_BROWSE_SERVER_INFO pinfo);

dword rtsmb_srv_browse_get_server_type (void);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_BROWSE_H__ */
