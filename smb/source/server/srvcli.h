#ifndef __SRV_CLI_H__
#define __SRV_CLI_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "smbnbds.h"

void rtsmb_srv_cli_connect_to (PFCHAR server_name);

int  rtsmb_srv_cli_cycle (long timeout);

void rtsmb_srv_cli_shutdown (void);

int  rtsmb_srv_cli_server_enum (dword type, PFCHAR server, 
								PRTSMB_BROWSE_SERVER_INFO answering_infos, 
								int answering_infos_size,
								PFINT answering_count);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_CLI_H__ */
