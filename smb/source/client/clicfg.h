#ifndef __CLI_CFG_H__
#define __CLI_CFG_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_CLIENT)

#include "clissn.h"
#include "cliez.h"

typedef struct _RTSMB_CLIENT_CONTEXT
{
    /* CONFIGURATION PARAMETERS */
    int                        max_sessions;
    int                        max_searches_per_session;
    int                        max_fids_per_session;
    int                        max_shares_per_session;
    int                        max_jobs_per_session;
    int                        max_buffers_per_wire;
    rtsmb_size                     buffer_size;
    int                        max_shares_per_search;
    int                        max_server_searches;
    int                        max_servers_per_search;
    int                        max_files_per_search;
    int                        max_supported_threads;

    /* MUTEXES */
    RTP_MUTEX              sessions_mutex;
    RTP_MUTEX              server_search_mutex;
#if (INCLUDE_RTSMB_CLIENT_EZ)
    RTP_MUTEX              ez_threads_mutex;
#endif

    /* BUFFER POOLS */
    PRTSMB_CLI_SESSION               sessions;
    PRTSMB_CLI_SESSION_SERVER_SEARCH server_search_results;
    PFBBOOL                          server_search_in_use;

#if (INCLUDE_RTSMB_CLIENT_EZ)
    PRTSMB_CLI_EZ_SEARCH             ez_share_searches;
    PRTSMB_CLI_EZ_SEARCH             ez_server_searches;
    PRTSMB_CLI_SESSION_SRVSTAT       ez_server_stats;
    PRTSMB_CLI_EZ_THREAD             ez_threads;
#endif
}
RTSMB_CLIENT_CONTEXT;

typedef RTSMB_CLIENT_CONTEXT *PRTSMB_CLIENT_CONTEXT;

extern PRTSMB_CLIENT_CONTEXT prtsmb_cli_ctx;

int rtsmb_client_config(void);

extern int rtsmb_client_config_initialized;

#endif /* INCLUDE_RTSMB_CLIENT */

#endif
