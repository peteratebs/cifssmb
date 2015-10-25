#ifndef __SRV_API_H__
#define __SRV_API_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "psmbfile.h"
#include "srvshare.h"
#include "srvauth.h"

int rtsmb_srv_read_config (PFCHAR filename);
int rtsmb_srv_share_add_tree (PFCHAR name, PFCHAR comment, PSMBFILEAPI api, PFCHAR path, byte flags, byte permissions, PFCHAR password);
int rtsmb_srv_share_add_ipc (PFCHAR password);
int rtsmb_srv_share_add_printer (PFCHAR name, PFCHAR comment, int n, PSMBFILEAPI api, PFCHAR path, byte flags, PFCHAR password, PFCHAR printerfile);
int rtsmb_srv_share_modify(PFCHAR cur_share_name, PFCHAR new_share_name, byte newpermissions);
int rtsmb_srv_printer_modify(PFCHAR cur_share_name, PFCHAR new_share_name);
int rtsmb_srv_share_remove (PFCHAR name);
BBOOL rtsmb_srv_register_group (PFCHAR name);
BBOOL rtsmb_srv_register_user (PFCHAR name, PFCHAR password);
BBOOL rtsmb_srv_delete_user (PFCHAR name);
BBOOL rtsmb_srv_add_user_to_group (PFCHAR user, PFCHAR group);
BBOOL rtsmb_srv_remove_user_from_group (PFCHAR user, PFCHAR group);
BBOOL rtsmb_srv_set_group_permissions (PFCHAR group, PFCHAR share, byte permissions);

#if (INCLUDE_RTSMB_UNICODE)
int rtsmb_srv_read_config_uc (PFWCS filename);
int rtsmb_srv_share_add_tree_uc (PFWCS name, PFWCS comment, PSMBFILEAPI api, PFWCS path, byte flags, byte permissions, PFCHAR password);
int rtsmb_srv_share_add_printer_uc (PFWCS name, PFWCS comment, int n, PSMBFILEAPI api, PFWCS path, byte flags, PFCHAR password, PFWCS printerfile);
int rtsmb_srv_share_remove_uc (PFWCS name);
BBOOL rtsmb_srv_register_group_uc (PFWCS name);
BBOOL rtsmb_srv_register_user_uc (PFWCS name, PFCHAR password);
BBOOL rtsmb_delete_user_uc (PFWCS name);
BBOOL rtsmb_srv_add_user_to_group_uc (PFWCS user, PFWCS group);
BBOOL rtsmb_srv_remove_user_from_group_uc (PFWCS user, PFWCS group);
BBOOL rtsmb_srv_set_group_permissions_uc (PFWCS group, PFWCS share, byte permissions);
#endif

void rtsmb_srv_set_mode (byte mode);
byte rtsmb_srv_get_mode (void);
void rtsmb_srv_init (PFBYTE ip, PFBYTE mask_ip, PFCHAR net_name, PFCHAR group_name);
void rtsmb_srv_set_ip (PFBYTE ip, PFBYTE mask_ip);
long rtsmb_srv_cycle (long timeout);
void rtsmb_srv_disable (void);
void rtsmb_srv_enable (PFCHAR net_name, PFCHAR group_name);
void rtsmb_srv_shutdown (void);

/****************************************************************************** */
void rtsmb_init_port_alt (void);
void rtsmb_init_port_well_know (void);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_API_H__ */
