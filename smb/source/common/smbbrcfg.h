#ifndef __SMB_BROWSE_CFG_H__
#define __SMB_BROWSE_CFG_H__

#include "smbdefs.h"
#include "smbnbds.h"

#ifndef CFG_RTSMB_BROWSE_MAX_BACKUP_SERVERS
#define CFG_RTSMB_BROWSE_MAX_BACKUP_SERVERS               5
#endif

#ifndef CFG_RTSMB_BROWSE_MAX_DOMAINS
#define CFG_RTSMB_BROWSE_MAX_DOMAINS                      5
#endif

typedef struct _RTSMB_BROWSE_CONTEXT
{
    /* CONFIGURATION PARAMETERS */

    /* MUTEXES */
    unsigned long               mutex;

    /* BUFFER POOLS */
    PFBYTE                      buffer;
    int                         buffer_size;

    PFRTCHAR                    backup_list_data;
    int                         backup_list_used;
    int                         backup_list_size;
    int                         num_domains;
    
    /* BACKUP LIST */
    struct
    {
        int      num_backups;
        PFRTCHAR server_name [CFG_RTSMB_BROWSE_MAX_BACKUP_SERVERS];
    }
    domain [CFG_RTSMB_BROWSE_MAX_DOMAINS];  
}
RTSMB_BROWSE_CONTEXT;

typedef RTSMB_BROWSE_CONTEXT *PRTSMB_BROWSE_CONTEXT;

extern PRTSMB_BROWSE_CONTEXT prtsmb_browse_ctx;

int rtsmb_browse_config(void);

extern int rtsmb_browse_config_initialized;

#endif
