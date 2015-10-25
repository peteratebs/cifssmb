/*                                                                      */
/* CLICFG.C -                                                           */
/*                                                                      */
/* EBSnet - RTSMB                                                       */
/*                                                                      */
/* Copyright EBSnet Inc. , 2003                                         */
/* All rights reserved.                                                 */
/* This code may not be redistributed in source or linkable object form */
/* without the consent of its author.                                   */
/*                                                                      */
/* Module description:                                                  */
/*  [tbd]                                                               */
/*                                                                      */


/******************************************************************************
    RTSMB_CONFIG() - Set up the RTSMB configuration block and allocate
   or assign memory blocks for RTSMB usage.

    The user must modify this code if he wishes to reconfigure RTSMB.

   Tutorial:
      rtsmb_client_config(void) initializes the rtsmb configuration block and
      provides RTSMB with the addresses of memory that it needs.

   This routine is designed to be modified by the user if he or she wishes to
   change the default configuration. To simplify the user's task we
   define some configuration constants in this file that may be modified
   to change the configuration. These constants are only used locally to
   this file. If another method of configuring RTSMB is more appropriate
   for your environment then devise an alternate method to initialize the
   configuration block.

*/

#include "smbdefs.h"

#if (INCLUDE_RTSMB_CLIENT)

#include "clicfg.h"
#include "psmbos.h"
#include "smbnb.h"
#include "rtpsignl.h"
#include "rtpprint.h"

#ifndef ALLOC_FROM_HEAP
#define ALLOC_FROM_HEAP  0
#else
#define ALLOC_FROM_HEAP 1
#endif

#if ALLOC_FROM_HEAP
#include "rtpmem.h"
#endif

/* GLOBAL and STATIC VARIABLES */
RTSMB_STATIC RTSMB_CLIENT_CONTEXT rtsmb_cli_cfg_core;
PRTSMB_CLIENT_CONTEXT prtsmb_cli_ctx = &rtsmb_cli_cfg_core;
int rtsmb_client_config_initialized = 0;

/**
 * The following #defines decide the resources RTSMB will set aside to deal with
 * server connections.  If RTSMB runs out of resources, it will refuse requests
 * for them until there are enough again.  Setting these too high will waste memory;
 * setting them too low will limit functionality.  I recommend testing heavily what the
 * expected demand will be.
 */


/**
 * The maximum number of simultaneous sessions that can exist.  This is synonymous with
 * the maximum number of servers we can connect to at once.  Very often, setting this to
 * 1 is fine.
 *
 * These sessions are quite large; be careful if setting this high.
 */
#ifndef CFG_RTSMB_CLI_MAX_SESSIONS
#define CFG_RTSMB_CLI_MAX_SESSIONS                                3
#endif

/**
 * The number of file searches that can exist at once on a session.
 * It is unlikely that you would need this much higher than 1.
 *
 * Cannot be over 255.
 */
#ifndef CFG_RTSMB_CLI_MAX_SEARCHES_PER_SESSION
#define CFG_RTSMB_CLI_MAX_SEARCHES_PER_SESSION                    2
#endif

/**
 * The number of files that can be returned in one search.
 */
#ifndef CFG_RTSMB_CLI_MAX_FILES_PER_SEARCH
#define CFG_RTSMB_CLI_MAX_FILES_PER_SEARCH                        10
#endif

/**
 * The number of open files that can exist at once on a session.
 *
 * Cannot be over 255.
 */
#ifndef CFG_RTSMB_CLI_MAX_FIDS_PER_SESSION
#define CFG_RTSMB_CLI_MAX_FIDS_PER_SESSION                        10
#endif

/**
 * The number of shares that a client can be connected to at once.
 * This includes the IPC share which a client is always connected to.
 */
#ifndef CFG_RTSMB_CLI_MAX_SHARES_PER_SESSION
#define CFG_RTSMB_CLI_MAX_SHARES_PER_SESSION                      4
#endif

/**
 * The number of shares that can be returned in one share enumeration.
 */
#ifndef CFG_RTSMB_CLI_MAX_SHARES_PER_SEARCH
#define CFG_RTSMB_CLI_MAX_SHARES_PER_SEARCH                       10
#endif

/**
 * The number of servers enumerations that can simultaneously exist.
 * This is unlikely to be wanted much larger than 1.
 *
 * Do not make this larger than 255.
 */
#ifndef CFG_RTSMB_CLI_MAX_SERVER_SEARCHES
#define CFG_RTSMB_CLI_MAX_SERVER_SEARCHES                         CFG_RTSMB_CLI_MAX_SUPPORTED_THREADS
#endif

/**
 * This controls how many servers one search can return at once.  This means that this
 * controls how many servers you will find from each workgroup on the network.  Since
 * each server only takes up 16 bytes of information, it seems low-risk to leave this high.
 */
#ifndef CFG_RTSMB_CLI_MAX_SERVERS_PER_SEARCH
#define CFG_RTSMB_CLI_MAX_SERVERS_PER_SEARCH                     50
#endif

/**
 * This controls how much data can be sent per packet.  Lower values
 * decrease network performance due to more packets sent and the overhead
 * they cost.  Higher values use more memory.  Pick your poison.
 *
 * Must be at least 1028.  Windows 95 uses around 2k.  Windows XP uses around 4k.
 */
#ifndef CFG_RTSMB_CLI_BUFFER_SIZE
#define CFG_RTSMB_CLI_BUFFER_SIZE                                2924
#endif

/**
 * This controls how many buffers we have per wire.  A wire is essentially a connection
 * to a server.  If we have more buffers, we can do more simultaneous activities on that
 * connection.
 *
 * This only needs to be non-1 if you are using the raw rtsmb_cli_session_* API and want to
 * do asynchronous jobs.  Otherwise, just set this to 1 and save some memory (each
 * buffer takes up CFG_RTSMB_CLI_BUFFER_SIZE bytes).
 *
 * However, this should be set to whatever you want, plus 1 because if we need to recover
 * from a bad connection, we need to be able to hijack a buffer without overwriting what
 * you are doing.  So a good default is 2.
 */
#ifndef CFG_RTSMB_CLI_MAX_BUFFERS_PER_WIRE
#define CFG_RTSMB_CLI_MAX_BUFFERS_PER_WIRE                       2
#endif

/**
 * This controls how many jobs a session is allowed to have outstanding.  Since each job uses
 * one buffer in the wire, there is no reason to have this different than the number of
 * buffers per wire.
 *
 * However, there should be one extra job alloted because if we need to recover
 * from a bad connection, we can hijack a buffer and keep old job data around.
 */
#ifndef CFG_RTSMB_CLI_MAX_JOBS_PER_SESSION
#define CFG_RTSMB_CLI_MAX_JOBS_PER_SESSION                       (CFG_RTSMB_CLI_MAX_BUFFERS_PER_WIRE + 1)
#endif

/**
 * This controls how many different threads the EZ API can be run on with no problems.
 * Right now, this is only used to control how many different 'current working
 * directories' we keep track of (one per thread).
 */
#ifndef CFG_RTSMB_CLI_MAX_SUPPORTED_THREADS
#define CFG_RTSMB_CLI_MAX_SUPPORTED_THREADS                      CFG_RTSMB_CLI_MAX_SESSIONS
#endif

#if ALLOC_FROM_HEAP == 0

RTSMB_STATIC RTSMB_CLI_SESSION               sessions                 [CFG_RTSMB_CLI_MAX_SESSIONS];
RTSMB_STATIC RTSMB_CLI_SESSION_JOB           jobs                     [CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_JOBS_PER_SESSION];
RTSMB_STATIC RTSMB_CLI_SESSION_SHARE         shares                   [CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_SHARES_PER_SESSION];
RTSMB_STATIC RTSMB_CLI_SESSION_FID           fids                     [CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_FIDS_PER_SESSION];
RTSMB_STATIC RTSMB_CLI_SESSION_SEARCH        searches                 [CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_SEARCHES_PER_SESSION];
RTSMB_STATIC RTSMB_CLI_SESSION_SSTAT         share_search_stats       [CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_SHARES_PER_SEARCH];
RTSMB_STATIC RTSMB_CLI_SESSION_DSTAT         file_search_stats        [CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_SEARCHES_PER_SESSION * CFG_RTSMB_CLI_MAX_FILES_PER_SEARCH];
RTSMB_STATIC byte                            wire_temp_buffers        [CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_BUFFER_SIZE];
RTSMB_STATIC RTSMB_CLI_WIRE_BUFFER           wire_buffers             [CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_BUFFERS_PER_WIRE];
RTSMB_STATIC byte                            wire_buffer_buffers      [CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_BUFFERS_PER_WIRE * CFG_RTSMB_CLI_BUFFER_SIZE];
RTSMB_STATIC RTSMB_CLI_SESSION_SERVER_SEARCH server_search_results    [CFG_RTSMB_CLI_MAX_SERVER_SEARCHES];
RTSMB_STATIC BBOOL                           server_search_in_use     [CFG_RTSMB_CLI_MAX_SERVER_SEARCHES];
RTSMB_STATIC RTSMB_CHAR16                    server_search_names      [CFG_RTSMB_CLI_MAX_SERVER_SEARCHES * CFG_RTSMB_CLI_MAX_SERVERS_PER_SEARCH * RTSMB_NB_NAME_SIZE];

#if (INCLUDE_RTSMB_CLIENT_EZ)
RTSMB_STATIC RTSMB_CLI_EZ_SEARCH             ez_share_searches        [CFG_RTSMB_CLI_MAX_SESSIONS];
RTSMB_STATIC RTSMB_CLI_EZ_SEARCH             ez_server_searches       [CFG_RTSMB_CLI_MAX_SERVER_SEARCHES];
RTSMB_STATIC RTSMB_CLI_SESSION_SRVSTAT       ez_server_stats          [CFG_RTSMB_CLI_MAX_SERVER_SEARCHES];
RTSMB_STATIC RTSMB_CLI_EZ_THREAD             ez_threads               [CFG_RTSMB_CLI_MAX_SUPPORTED_THREADS];
#endif

#else /* ALLOC_FROM_HEAP == 1 */


RTSMB_STATIC RTSMB_CLI_SESSION               *sessions                 ;
RTSMB_STATIC RTSMB_CLI_SESSION_JOB           *jobs                     ;
RTSMB_STATIC RTSMB_CLI_SESSION_SHARE         *shares                   ;
RTSMB_STATIC RTSMB_CLI_SESSION_FID           *fids                     ;
RTSMB_STATIC RTSMB_CLI_SESSION_SEARCH        *searches                 ;
RTSMB_STATIC RTSMB_CLI_SESSION_SSTAT         *share_search_stats       ;
RTSMB_STATIC RTSMB_CLI_SESSION_DSTAT         *file_search_stats        ;
RTSMB_STATIC byte                            *wire_temp_buffers        ;
RTSMB_STATIC RTSMB_CLI_WIRE_BUFFER           *wire_buffers             ;
RTSMB_STATIC byte                            *wire_buffer_buffers      ;
RTSMB_STATIC RTSMB_CLI_SESSION_SERVER_SEARCH *server_search_results    ;
RTSMB_STATIC BBOOL                           *server_search_in_use     ;
RTSMB_STATIC RTSMB_CHAR16                    *server_search_names      ;

#if (INCLUDE_RTSMB_CLIENT_EZ)
RTSMB_STATIC RTSMB_CLI_EZ_SEARCH             *ez_share_searches        ;
RTSMB_STATIC RTSMB_CLI_EZ_SEARCH             *ez_server_searches       ;
RTSMB_STATIC RTSMB_CLI_SESSION_SRVSTAT       *ez_server_stats          ;
RTSMB_STATIC RTSMB_CLI_EZ_THREAD             *ez_threads               ;
#endif


static void * safemalloc(rtsmb_size bytes)
{
   void * Result = rtp_malloc(bytes);

   if (bytes && !Result)
   {
      rtp_printf(("SMB Server: out of heap space\n"));
      exit(1);
   }
   tc_memset(Result, 0, bytes);
   return Result;
}

#endif /* (ALLOC_FROM_HEAP) */


int rtsmb_client_config(void)
{
   int i, j;

    if (rtsmb_client_config_initialized)
    {
        return 1;
    }
#if ALLOC_FROM_HEAP
    else
    {
        RTSMB_CLI_SESSION               * sessions                 = safemalloc(sizeof(RTSMB_CLI_SESSION              ) * CFG_RTSMB_CLI_MAX_SESSIONS);
        RTSMB_CLI_SESSION_JOB           * jobs                     = safemalloc(sizeof(RTSMB_CLI_SESSION_JOB          ) * CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_JOBS_PER_SESSION);
        RTSMB_CLI_SESSION_SHARE         * shares                   = safemalloc(sizeof(RTSMB_CLI_SESSION_SHARE        ) * CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_SHARES_PER_SESSION);
        RTSMB_CLI_SESSION_FID           * fids                     = safemalloc(sizeof(RTSMB_CLI_SESSION_FID          ) * CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_FIDS_PER_SESSION);
        RTSMB_CLI_SESSION_SEARCH        * searches                 = safemalloc(sizeof(RTSMB_CLI_SESSION_SEARCH       ) * CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_SEARCHES_PER_SESSION);
        RTSMB_CLI_SESSION_SSTAT         * share_search_stats       = safemalloc(sizeof(RTSMB_CLI_SESSION_SSTAT        ) * CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_SHARES_PER_SEARCH);
        RTSMB_CLI_SESSION_DSTAT         * file_search_stats        = safemalloc(sizeof(RTSMB_CLI_SESSION_DSTAT        ) * CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_SEARCHES_PER_SESSION * CFG_RTSMB_CLI_MAX_FILES_PER_SEARCH);
        byte                            * wire_temp_buffers        = safemalloc(sizeof(byte                           ) * CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_BUFFER_SIZE);
        RTSMB_CLI_WIRE_BUFFER           * wire_buffers             = safemalloc(sizeof(RTSMB_CLI_WIRE_BUFFER          ) * CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_BUFFERS_PER_WIRE);
        byte                            * wire_buffer_buffers      = safemalloc(sizeof(byte                           ) * CFG_RTSMB_CLI_MAX_SESSIONS * CFG_RTSMB_CLI_MAX_BUFFERS_PER_WIRE * CFG_RTSMB_CLI_BUFFER_SIZE);
        RTSMB_CLI_SESSION_SERVER_SEARCH * server_search_results    = safemalloc(sizeof(RTSMB_CLI_SESSION_SERVER_SEARCH) * CFG_RTSMB_CLI_MAX_SERVER_SEARCHES);
        BBOOL                           * server_search_in_use     = safemalloc(sizeof(BBOOL                          ) * CFG_RTSMB_CLI_MAX_SERVER_SEARCHES);
        RTSMB_CHAR16                    * server_search_names      = safemalloc(sizeof(RTSMB_CHAR16                   ) * CFG_RTSMB_CLI_MAX_SERVER_SEARCHES * CFG_RTSMB_CLI_MAX_SERVERS_PER_SEARCH * RTSMB_NB_NAME_SIZE);

        #if (INCLUDE_RTSMB_CLIENT_EZ)
        RTSMB_CLI_EZ_SEARCH             * ez_share_searches        = safemalloc(sizeof(RTSMB_CLI_EZ_SEARCH            ) * CFG_RTSMB_CLI_MAX_SESSIONS);
        RTSMB_CLI_EZ_SEARCH             * ez_server_searches       = safemalloc(sizeof(RTSMB_CLI_EZ_SEARCH            ) * CFG_RTSMB_CLI_MAX_SERVER_SEARCHES);
        RTSMB_CLI_SESSION_SRVSTAT       * ez_server_stats          = safemalloc(sizeof(RTSMB_CLI_SESSION_SRVSTAT      ) * CFG_RTSMB_CLI_MAX_SERVER_SEARCHES);
        RTSMB_CLI_EZ_THREAD             * ez_threads               = safemalloc(sizeof(RTSMB_CLI_EZ_THREAD            ) * CFG_RTSMB_CLI_MAX_SUPPORTED_THREADS);
        #endif
    }
#endif

 #ifdef INCLUDE_RTSMB_THREADSAFE
   if (rtp_sig_mutex_alloc((RTP_MUTEX *) &prtsmb_cli_ctx->sessions_mutex, 0) < 0)
   {
       return 0;
   }

   if (rtp_sig_mutex_alloc((RTP_MUTEX *) &prtsmb_cli_ctx->server_search_mutex, 0) < 0)
   {
       rtp_sig_mutex_free(prtsmb_cli_ctx->sessions_mutex);
       return 0;
   }

  #if (INCLUDE_RTSMB_CLIENT_EZ)
   if (rtp_sig_mutex_alloc((RTP_MUTEX *) &prtsmb_cli_ctx->ez_threads_mutex, 0) < 0)
   {
       rtp_sig_mutex_free(prtsmb_cli_ctx->server_search_mutex);
       rtp_sig_mutex_free(prtsmb_cli_ctx->sessions_mutex);
       return 0;
   }
  #endif
 #endif /* INCLUDE_RTSMB_THREADSAFE */

   prtsmb_cli_ctx->max_sessions             = CFG_RTSMB_CLI_MAX_SESSIONS;
   prtsmb_cli_ctx->max_searches_per_session = CFG_RTSMB_CLI_MAX_SEARCHES_PER_SESSION;
   prtsmb_cli_ctx->max_fids_per_session     = CFG_RTSMB_CLI_MAX_FIDS_PER_SESSION;
   prtsmb_cli_ctx->max_shares_per_session   = CFG_RTSMB_CLI_MAX_SHARES_PER_SESSION;
   prtsmb_cli_ctx->max_jobs_per_session     = CFG_RTSMB_CLI_MAX_JOBS_PER_SESSION;
   prtsmb_cli_ctx->max_buffers_per_wire     = CFG_RTSMB_CLI_MAX_BUFFERS_PER_WIRE;
   prtsmb_cli_ctx->buffer_size              = CFG_RTSMB_CLI_BUFFER_SIZE;
   prtsmb_cli_ctx->max_shares_per_search    = CFG_RTSMB_CLI_MAX_SHARES_PER_SEARCH;
   prtsmb_cli_ctx->max_server_searches      = CFG_RTSMB_CLI_MAX_SERVER_SEARCHES;
   prtsmb_cli_ctx->max_servers_per_search   = CFG_RTSMB_CLI_MAX_SERVERS_PER_SEARCH;
   prtsmb_cli_ctx->max_files_per_search     = CFG_RTSMB_CLI_MAX_FILES_PER_SEARCH;
   prtsmb_cli_ctx->max_supported_threads    = CFG_RTSMB_CLI_MAX_SUPPORTED_THREADS;

   prtsmb_cli_ctx->sessions                 = sessions;
   prtsmb_cli_ctx->server_search_results    = server_search_results;
   prtsmb_cli_ctx->server_search_in_use     = server_search_in_use;

#if (INCLUDE_RTSMB_CLIENT_EZ)
   prtsmb_cli_ctx->ez_share_searches        = ez_share_searches;
   prtsmb_cli_ctx->ez_server_searches       = ez_server_searches;
   prtsmb_cli_ctx->ez_server_stats          = ez_server_stats;
   prtsmb_cli_ctx->ez_threads               = ez_threads;
#endif

#if (INCLUDE_RTSMB_CLIENT_EZ)
   for (i = 0; i < prtsmb_cli_ctx->max_supported_threads; i++)
   {
      prtsmb_cli_ctx->ez_threads[i].in_use = FALSE;
   }
#endif

   for (i = 0; i < prtsmb_cli_ctx->max_server_searches; i++)
   {
#if (INCLUDE_RTSMB_CLIENT_EZ)
      prtsmb_cli_ctx->ez_server_stats[i].sid = -1;
#endif
      prtsmb_cli_ctx->server_search_results[i].srvstats = &server_search_names[i * prtsmb_cli_ctx->max_servers_per_search * RTSMB_NB_NAME_SIZE];
   }

    for (i = 0; i < prtsmb_cli_ctx->max_sessions; i++)
    {
        sessions[i].state = CSSN_STATE_UNUSED;

        sessions[i].jobs                = &jobs                [i * prtsmb_cli_ctx->max_jobs_per_session];
        sessions[i].shares              = &shares              [i * prtsmb_cli_ctx->max_shares_per_session];
        sessions[i].fids                = &fids                [i * prtsmb_cli_ctx->max_fids_per_session];
        sessions[i].searches            = &searches            [i * prtsmb_cli_ctx->max_searches_per_session];
        sessions[i].wire.temp_buffer    = &wire_temp_buffers   [(dword)i * prtsmb_cli_ctx->buffer_size];
        sessions[i].wire.buffers        = &wire_buffers        [i * prtsmb_cli_ctx->max_buffers_per_wire];

        /* default to TCP over ethernet payload size */
        sessions[i].wire.physical_packet_size = 1460;

        sessions[i].share_search.sstats = &share_search_stats  [i * prtsmb_cli_ctx->max_shares_per_search];

        for (j = 0; j < prtsmb_cli_ctx->max_buffers_per_wire; j++)
        {
            sessions[i].wire.buffers[j].buffer = &wire_buffer_buffers [(dword)(i * prtsmb_cli_ctx->max_buffers_per_wire + j) * prtsmb_cli_ctx->buffer_size];
        }

        for (j = 0; j < prtsmb_cli_ctx->max_searches_per_session; j++)
        {
            sessions[i].searches[j].dstats = &file_search_stats [(i * prtsmb_cli_ctx->max_searches_per_session + j) * prtsmb_cli_ctx->max_files_per_search];
        }
    }

    rtsmb_client_config_initialized = 1;

    return 1;
}

#endif /* INCLUDE_RTSMB_CLIENT */
