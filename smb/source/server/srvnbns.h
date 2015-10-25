#ifndef __SRV_NBNS_H__
#define __SRV_NBNS_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

void rtsmb_srv_nbns_init (PFCHAR net_name, PFCHAR group_name);
void rtsmb_srv_nbns_cycle (void);
void rtsmb_srv_nbns_restart (void);
void rtsmb_srv_nbns_shutdown (void);

BBOOL rtsmb_srv_nbns_is_in_name_table (PFCHAR name, BBOOL lookAtSuffix);

BBOOL rtsmb_srv_nbns_process_packet (PFBYTE buf, rtsmb_size size);

BBOOL rtsmb_srv_nbns_is_in_name_cache (PFCHAR name, byte type);
BBOOL rtsmb_srv_nbns_get_ip_from_cache (PFCHAR name, BBOOL lookAtSuffix, PFBYTE dest);

void rtsmb_srv_nbns_invalidate_all_names (PFCHAR name);
void rtsmb_srv_nbns_invalidate_one_name (PFCHAR name, byte type);
void rtsmb_srv_nbns_invalidate_ip (PFBYTE ip);

void rtsmb_srv_nbns_start_query_for_name (PFCHAR name, byte type);

/* these all return a null-ended string of, at most, size 16 */
/* 'full' versions pad out the 16 chars with spaces */
PFCHAR rtsmb_srv_nbns_get_our_group_full (void);
PFCHAR rtsmb_srv_nbns_get_our_group (void);
PFCHAR rtsmb_srv_nbns_get_our_name_full (void);
PFCHAR rtsmb_srv_nbns_get_our_name (void);

BBOOL rtsmb_srv_nbns_add_name (PFCHAR newName, BBOOL group, char suf, BBOOL announce);
BBOOL rtsmb_srv_nbns_remove_name (PFCHAR name, char suf);

long rtsmb_srv_nbns_get_next_wake_timeout (void);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_NBNS_H__ */
