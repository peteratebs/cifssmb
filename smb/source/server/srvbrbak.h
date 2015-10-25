#ifndef __SRV_BROWSE_BACKUP_H__
#define __SRV_BROWSE_BACKUP_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvssn.h"

void rtsmb_srv_browse_backup_start (void);
void rtsmb_srv_browse_backup_stop (void);
void rtsmb_srv_browse_backup_cycle (void);

void rtsmb_srv_browse_finish_server_enum (PSMB_SESSIONCTX pCtx);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_BROWSE_BACKUP_H__ */
