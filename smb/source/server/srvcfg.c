//
// SRVCFG.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Set up the RTSMB configuration block and allocate
// or assign memory blocks for RTSMB usage.

#include "smbdefs.h"


#if (INCLUDE_RTSMB_SERVER)


#include "srvcfg.h"
#include "psmbos.h"
#include "rtpsignl.h"
#include "smbdebug.h"

#ifndef ALLOC_FROM_HEAP
#define ALLOC_FROM_HEAP  0
#endif


/**
 * The following #defines decide the resources RTSMB will set aside to deal with
 * client connections.  If RTSMB runs out of resources, it will refuse client requests
 * for them until there are enough again.  Setting these too high will waste memory;
 * setting them too low will limit functionality.  I recommend testing heavily what the
 * expected demand will be.
 */

/**
 * The maximum number of *extra* threads you want to use for smb processing.
 * The more of these, the more responsive the server is to requests.  (The main loop
 * can receive session requests and hand these off to helper threads.)  Setting this
 * to 0 disables multithreading.
 *
 * Setting this higher than the maximum number of sessions is pointless.
 * You might lower this to save on footprint.  If you are experiencing bottlenecks
 * with large I/O operations on one session, you might increase this to allow other
 * sessions to be serviced at the same time.
 */
#ifndef CFG_RTSMB_MAX_THREADS
#define CFG_RTSMB_MAX_THREADS               0
#endif

/**
 * The maximum amount of sessions you want to be able to support simultaneously.
 *
 * Must be at least 1.
 *
 * You might increase this to allow more clients to connect to the server at once.
 * If the server is at maximum, new session requests will be denied.
 */
#ifndef CFG_RTSMB_MAX_SESSIONS
#define CFG_RTSMB_MAX_SESSIONS              4
#endif

/**
 * The maximum amount of simultaneous users logged in on each session.
 * This can safely be low, as it is not common for more than one user to share
 * a session.
 */
#ifndef CFG_RTSMB_MAX_UIDS_PER_SESSION
#define CFG_RTSMB_MAX_UIDS_PER_SESSION      3
#endif

/**
 * This controls how many files can be open at one time.
 *
 * You might increase this if your clients are doing a lot
 * of intensive reading and writing such that they would need
 * to have many simultaneously open files.
 */
#ifndef CFG_RTSMB_MAX_FIDS_PER_SESSION
#define CFG_RTSMB_MAX_FIDS_PER_SESSION      5
#endif

/**
 * You might lower these restrictions on fids if you want to restrict
 * how many disk resources any one user can monopolize.
 */
#ifndef CFG_RTSMB_MAX_FIDS_PER_TREE
#define CFG_RTSMB_MAX_FIDS_PER_TREE         CFG_RTSMB_MAX_FIDS_PER_SESSION
#endif

#ifndef CFG_RTSMB_MAX_FIDS_PER_UID
#define CFG_RTSMB_MAX_FIDS_PER_UID          CFG_RTSMB_MAX_FIDS_PER_SESSION
#endif

/**
 * There is no in-smb way to indicate that the
 * maximum number of searches has been exceeded and thus to do deny the request.
 * If the request is denied for some random reason, clients get very confused.
 * So, the oldest search is just overridden when we run out of search id's.
 *
 * Therefore, do not set this lower than about 2-3, unless you know what requests you
 * are going to receive.  Setting this too high, however, will leave dangling searches
 * because the win95 client, at least, can forget to close searches.
 *
 * Warning: Searches are about the most costly item, memory wise, because they hold
 *          a dstat object to pass to gfirst.  Be careful when raising this.
 */
#ifndef CFG_RTSMB_MAX_SEARCHES_PER_UID
#define CFG_RTSMB_MAX_SEARCHES_PER_UID      2
#endif

/**
 * The maximum number of shares you want to make available at one time.
 * This does count IPC$.
 *
 * Increase this if you need to share more directories.  If you don't,
 * lower it to decrease footprint.
 */
#ifndef CFG_RTSMB_MAX_SHARES
#define CFG_RTSMB_MAX_SHARES                5
#endif

/**
 * This controls how many shares one session can be connected to at one time.
 *
 * Warning: Some versions of windows like to open a lot of simultaneous shares.
 *          If you want RTSMB to work for all of them, you should leave this
 *          value reasonably high (around 10).
 */
#ifndef CFG_RTSMB_MAX_TREES_PER_SESSION
#define CFG_RTSMB_MAX_TREES_PER_SESSION     10
#endif

/**
 * The maximum number of registered groups and users you want to enable.
 *
 * See srvauth.h for an explanation of groups and users.
 *
 * Increase these if you need more fine-grained control over your users.
 * If you plan to always run in share mode, these can be set to 0 to save memory.
 */
#ifndef CFG_RTSMB_MAX_GROUPS
#define CFG_RTSMB_MAX_GROUPS                4
#endif
#ifndef CFG_RTSMB_MAX_USERS
#define CFG_RTSMB_MAX_USERS                 8
#endif

/**
 * This buffer size is used for everyday smbs.  Each thread will have three of
 * its own private buffers of CFG_RTSMB_SMALL_BUFFER_SIZE bytes that it uses for reading
 * and writing to network.  Four bytes of each are reserved for the Netbios layer.
 *
 * Win95 sends 2920 for its SMB buffer size, so set this to 2924 to emulate that.
 * It is quite fine to go much lower, like around 1k -- a lot of standard messages
 * are small -- but that creates more traffic because reads and writes can't hold as
 * much information per packet.
 *
 * MINIMUM IS 1028!!
 */
#ifndef CFG_RTSMB_SMALL_BUFFER_SIZE
#define CFG_RTSMB_SMALL_BUFFER_SIZE         2924
#endif

#if (CFG_RTSMB_SMALL_BUFFER_SIZE < 1028)
#error MUST set CFG_RTSMB_SMALL_BUFFER_SIZE >= 1028
#endif
/**
 * This controls how large the big buffers are.  These buffers are
 * used for raw reads and writes (an efficient way of writing or
 * reading lots of data).  This value is not used if CFG_RTSMB_NUM_BIG_BUFFERS
 * is 0. The maximum value is 65539.
 *
 * Many clients don't properly respect negotiated big buffer size.
 * Rather, they expect full big buffer support (up to 65k bytes).
 * Thus, it is recommended that you leave this at the maximum value.
 * However, most new clients are good about it.  If you only expect NT and
 * onward clients, then set this to anything you like.
 */
#ifndef CFG_RTSMB_BIG_BUFFER_SIZE
#define CFG_RTSMB_BIG_BUFFER_SIZE           65539
#endif

/**
 * This controls how many big buffers of size CFG_RTSMB_BIG_BUFFER_SIZE you want to reserve
 * for raw reading and writing.  If 0, raw read/write support is disabled.
 *
 * Increase this if you can handle the increased footprint and expect to do large
 * reading and writing.  However, many clients don't always use raw reads/writes when they
 * can, so you may not get as much mileage from this as you might hope.
 */
#ifndef CFG_RTSMB_NUM_BIG_BUFFERS
#define CFG_RTSMB_NUM_BIG_BUFFERS           0
#endif

/**
 * This controls how many servers we can keep track of at once.  The higher this is,
 * the larger networks RTSMB can support.
 *
 * Memory used by this is around 140 bytes per info.
 */
#ifndef CFG_RTSMB_BROWSE_MAX_SERVER_INFOS
#define CFG_RTSMB_BROWSE_MAX_SERVER_INFOS                 30
#endif

/**
 * This controls how many workgroups we can keep track of at once.  The higher this is,
 * the larger networks RTSMB can support.  Each domain info block is around 70 bytes.
 */
#ifndef CFG_RTSMB_BROWSE_MAX_DOMAIN_INFOS
#define CFG_RTSMB_BROWSE_MAX_DOMAIN_INFOS                 5
#endif


#if ALLOC_FROM_HEAP == 0

/**
 * These lists hold large buffers for reading and writing raw.
 */
#if CFG_RTSMB_NUM_BIG_BUFFERS
RTSMB_STATIC unsigned char    bigBuffers     [CFG_RTSMB_BIG_BUFFER_SIZE * CFG_RTSMB_NUM_BIG_BUFFERS];
RTSMB_STATIC char             bigBufferInUse [CFG_RTSMB_NUM_BIG_BUFFERS];
#endif

/**
 * These lists are used by smbnet.c to hold session threading info.
 */
RTSMB_STATIC NET_THREAD_T     threads        [CFG_RTSMB_MAX_THREADS + 1];
RTSMB_STATIC char             threadsInUse   [CFG_RTSMB_MAX_THREADS + 1];
RTSMB_STATIC NET_SESSIONCTX_T sessions       [CFG_RTSMB_MAX_SESSIONS];
RTSMB_STATIC char             sessionsInUse  [CFG_RTSMB_MAX_SESSIONS];
RTSMB_STATIC unsigned long    activeSessions [CFG_RTSMB_MAX_SESSIONS];
RTSMB_STATIC USER_T           uids           [CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_UIDS_PER_SESSION];
RTSMB_STATIC SEARCH_T         searches       [CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_UIDS_PER_SESSION * CFG_RTSMB_MAX_SEARCHES_PER_UID];
RTSMB_STATIC PFID             uid_fids       [CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_UIDS_PER_SESSION * CFG_RTSMB_MAX_FIDS_PER_UID];
RTSMB_STATIC TREE_T           trees          [CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_TREES_PER_SESSION];
RTSMB_STATIC PFID             tree_fids      [CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_TREES_PER_SESSION * CFG_RTSMB_MAX_FIDS_PER_TREE];
RTSMB_STATIC FID_T            fids           [CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_FIDS_PER_SESSION];
RTSMB_STATIC PNET_SESSIONCTX  sessionList    [(CFG_RTSMB_MAX_THREADS + 1) * CFG_RTSMB_MAX_SESSIONS];
RTSMB_STATIC byte             inBuffer       [(CFG_RTSMB_MAX_THREADS + 1) * CFG_RTSMB_SMALL_BUFFER_SIZE];
RTSMB_STATIC byte             outBuffer      [(CFG_RTSMB_MAX_THREADS + 1) * CFG_RTSMB_SMALL_BUFFER_SIZE];
RTSMB_STATIC byte             tmpBuffer      [(CFG_RTSMB_MAX_THREADS + 1) * CFG_RTSMB_SMALL_BUFFER_SIZE];
RTSMB_STATIC byte             namesrvBuffer  [CFG_RTSMB_SMALL_BUFFER_SIZE];
RTSMB_STATIC byte             client_buffer  [CFG_RTSMB_SMALL_BUFFER_SIZE];
RTSMB_STATIC SR_RESOURCE_T    shareTable     [CFG_RTSMB_MAX_SHARES];
RTSMB_STATIC USERDATA_T       users          [CFG_RTSMB_MAX_USERS];
RTSMB_STATIC BBOOL            user_groups    [CFG_RTSMB_MAX_USERS * CFG_RTSMB_MAX_GROUPS];
RTSMB_STATIC byte             access_table   [((CFG_RTSMB_MAX_SHARES * BITS_PER_TABLE_ENTRY / 8) + 1) * CFG_RTSMB_MAX_GROUPS];
RTSMB_STATIC ACCESS_TABLE_T   groups         [CFG_RTSMB_MAX_GROUPS];

RTSMB_STATIC char                        local_master                 [RTSMB_NB_NAME_SIZE + 1];
RTSMB_STATIC RTSMB_BROWSE_SERVER_INFO    server_table                 [CFG_RTSMB_BROWSE_MAX_SERVER_INFOS];
RTSMB_STATIC RTSMB_BROWSE_SERVER_INFO    domain_table                 [CFG_RTSMB_BROWSE_MAX_DOMAIN_INFOS];

#if CFG_RTSMB_BROWSE_MAX_SERVER_INFOS > CFG_RTSMB_BROWSE_MAX_DOMAIN_INFOS
RTSMB_STATIC RTSMB_BROWSE_SERVER_INFO    enum_results                 [CFG_RTSMB_BROWSE_MAX_SERVER_INFOS];
#else
RTSMB_STATIC RTSMB_BROWSE_SERVER_INFO    enum_results                 [CFG_RTSMB_BROWSE_MAX_DOMAIN_INFOS];
#endif

#else // ALLOC_FROM_HEAP == 1


static void * safemalloc(rtsmb_size bytes)
{
   void * Result;
   Result = malloc(bytes);

   if (bytes && !Result)
   {
      RTSMB_DEBUG_OUTPUT_STR("SMB Server: out of heap space\n", RTSMB_DEBUG_TYPE_ASCII);
      exit(1);
   }
   tc_memset(Result, 0, bytes);
   return Result;
}

#endif /* (ALLOC_FROM_HEAP) */

RTSMB_STATIC RTSMB_SERVER_CONTEXT rtsmb_srv_cfg_core;
PRTSMB_SERVER_CONTEXT prtsmb_srv_ctx = &rtsmb_srv_cfg_core;

int rtsmb_server_config(void)
{
   int i;
   prtsmb_srv_ctx = &rtsmb_srv_cfg_core;

#if ALLOC_FROM_HEAP
   unsigned char    * bigBuffers     = safemalloc(sizeof(unsigned char   ) * CFG_RTSMB_BIG_BUFFER_SIZE * CFG_RTSMB_NUM_BIG_BUFFERS);
   char             * bigBufferInUse = safemalloc(sizeof(char            ) * CFG_RTSMB_NUM_BIG_BUFFERS);
   NET_THREAD_T     * threads        = safemalloc(sizeof(NET_THREAD_T    ) * (CFG_RTSMB_MAX_THREADS + 1));
   char             * threadsInUse   = safemalloc(sizeof(char            ) * (CFG_RTSMB_MAX_THREADS + 1));
   NET_SESSIONCTX_T * sessions       = safemalloc(sizeof(NET_SESSIONCTX_T) * CFG_RTSMB_MAX_SESSIONS);
   char             * sessionsInUse  = safemalloc(sizeof(char            ) * CFG_RTSMB_MAX_SESSIONS);
   unsigned long    * activeSessions = safemalloc(sizeof(unsigned long   ) * CFG_RTSMB_MAX_SESSIONS);
   USER_T           * uids           = safemalloc(sizeof(USER_T          ) * CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_UIDS_PER_SESSION);
   SEARCH_T         * searches       = safemalloc(sizeof(SEARCH_T        ) * CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_UIDS_PER_SESSION * CFG_RTSMB_MAX_SEARCHES_PER_UID);
   PFID             * uid_fids       = safemalloc(sizeof(PFID            ) * CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_UIDS_PER_SESSION * CFG_RTSMB_MAX_FIDS_PER_UID);
   TREE_T           * trees          = safemalloc(sizeof(TREE_T          ) * CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_TREES_PER_SESSION);
   PFID             * tree_fids      = safemalloc(sizeof(PFID            ) * CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_TREES_PER_SESSION * CFG_RTSMB_MAX_FIDS_PER_TREE);
   FID_T            * fids           = safemalloc(sizeof(FID_T           ) * CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_FIDS_PER_SESSION);
   PNET_SESSIONCTX  * sessionList    = safemalloc(sizeof(PNET_SESSIONCTX ) * (CFG_RTSMB_MAX_THREADS + 1) * CFG_RTSMB_MAX_SESSIONS);
   byte             * inBuffer       = safemalloc(sizeof(byte            ) * (CFG_RTSMB_MAX_THREADS + 1) * CFG_RTSMB_SMALL_BUFFER_SIZE);
   byte             * outBuffer      = safemalloc(sizeof(byte            ) * (CFG_RTSMB_MAX_THREADS + 1) * CFG_RTSMB_SMALL_BUFFER_SIZE);
   byte             * tmpBuffer      = safemalloc(sizeof(byte            ) * (CFG_RTSMB_MAX_THREADS + 1) * CFG_RTSMB_SMALL_BUFFER_SIZE);
   byte             * namesrvBuffer  = safemalloc(sizeof(byte            ) * CFG_RTSMB_SMALL_BUFFER_SIZE);
   byte             * client_buffer  = safemalloc(sizeof(byte            ) * CFG_RTSMB_SMALL_BUFFER_SIZE);
   SR_RESOURCE_T    * shareTable     = safemalloc(sizeof(SR_RESOURCE_T   ) * CFG_RTSMB_MAX_SHARES);
   USERDATA_T       * users          = safemalloc(sizeof(USERDATA_T      ) * CFG_RTSMB_MAX_USERS);
   BBOOL            * user_groups    = safemalloc(sizeof(BBOOL           ) * CFG_RTSMB_MAX_USERS * CFG_RTSMB_MAX_GROUPS);
   byte             * access_table   = safemalloc(sizeof(byte            ) * ((CFG_RTSMB_MAX_SHARES * BITS_PER_TABLE_ENTRY / 8) + 1) * CFG_RTSMB_MAX_GROUPS);
   ACCESS_TABLE_T   * groups         = safemalloc(sizeof(ACCESS_TABLE_T  ) * CFG_RTSMB_MAX_GROUPS);
   char             * local_master   = safemalloc(sizeof(char            ) * (RTSMB_NB_NAME_SIZE + 1));
   RTSMB_BROWSE_SERVER_INFO * server_table = safemalloc(sizeof(RTSMB_BROWSE_SERVER_INFO) * CFG_RTSMB_BROWSE_MAX_SERVER_INFOS);
   RTSMB_BROWSE_SERVER_INFO * domain_table = safemalloc(sizeof(RTSMB_BROWSE_SERVER_INFO) * CFG_RTSMB_BROWSE_MAX_DOMAIN_INFOS);
   RTSMB_BROWSE_SERVER_INFO * enum_results = safemalloc(sizeof(RTSMB_BROWSE_SERVER_INFO) * MAX(CFG_RTSMB_BROWSE_MAX_SERVER_INFOS, CFG_RTSMB_BROWSE_MAX_DOMAIN_INFOS));
#endif

   prtsmb_srv_ctx->max_threads           = CFG_RTSMB_MAX_THREADS;
   prtsmb_srv_ctx->max_sessions          = CFG_RTSMB_MAX_SESSIONS;
   prtsmb_srv_ctx->max_uids_per_session  = CFG_RTSMB_MAX_UIDS_PER_SESSION;
   prtsmb_srv_ctx->max_fids_per_tree     = CFG_RTSMB_MAX_FIDS_PER_TREE;
   prtsmb_srv_ctx->max_searches_per_uid  = CFG_RTSMB_MAX_SEARCHES_PER_UID;
   prtsmb_srv_ctx->max_shares            = CFG_RTSMB_MAX_SHARES;
   prtsmb_srv_ctx->max_groups            = CFG_RTSMB_MAX_GROUPS;
   prtsmb_srv_ctx->max_users             = CFG_RTSMB_MAX_USERS;
   prtsmb_srv_ctx->small_buffer_size     = CFG_RTSMB_SMALL_BUFFER_SIZE;
   prtsmb_srv_ctx->big_buffer_size       = CFG_RTSMB_BIG_BUFFER_SIZE;
   prtsmb_srv_ctx->num_big_buffers       = CFG_RTSMB_NUM_BIG_BUFFERS;
   prtsmb_srv_ctx->max_fids_per_uid      = CFG_RTSMB_MAX_FIDS_PER_UID;
   prtsmb_srv_ctx->max_fids_per_session  = CFG_RTSMB_MAX_FIDS_PER_SESSION;
   prtsmb_srv_ctx->max_trees_per_session = CFG_RTSMB_MAX_TREES_PER_SESSION;
   prtsmb_srv_ctx->server_table_size     = CFG_RTSMB_BROWSE_MAX_SERVER_INFOS;
   prtsmb_srv_ctx->domain_table_size     = CFG_RTSMB_BROWSE_MAX_DOMAIN_INFOS;
   prtsmb_srv_ctx->enum_results_size     = MAX (CFG_RTSMB_BROWSE_MAX_DOMAIN_INFOS, CFG_RTSMB_BROWSE_MAX_SERVER_INFOS);

   rtp_sig_mutex_alloc ((RTP_MUTEX *) &prtsmb_srv_ctx->bufsem, (const char*)0);
   rtp_sig_mutex_alloc ((RTP_MUTEX *) &prtsmb_srv_ctx->authsem, (const char*)0);
   rtp_sig_mutex_alloc ((RTP_MUTEX *) &prtsmb_srv_ctx->sharesem, (const char*)0);
   rtp_sig_mutex_alloc ((RTP_MUTEX *) &prtsmb_srv_ctx->printersem, (const char*)0);
   rtp_sig_mutex_alloc ((RTP_MUTEX *) &prtsmb_srv_ctx->cachesem, (const char*)0);
   rtp_sig_mutex_alloc ((RTP_MUTEX *) &prtsmb_srv_ctx->mailPDCNameSem, (const char*)0);
   rtp_sig_mutex_alloc ((RTP_MUTEX *) &prtsmb_srv_ctx->netsem, (const char*)0);
   rtp_sig_mutex_alloc ((RTP_MUTEX *) &prtsmb_srv_ctx->enum_results_mutex, (const char*)0);

  #if CFG_RTSMB_NUM_BIG_BUFFERS
   prtsmb_srv_ctx->bigBuffers           = bigBuffers;
   prtsmb_srv_ctx->bigBufferInUse       = bigBufferInUse;

  #endif
   prtsmb_srv_ctx->threads              = threads;
   prtsmb_srv_ctx->threadsInUse         = threadsInUse;

   prtsmb_srv_ctx->sessions             = sessions;
   prtsmb_srv_ctx->sessionsInUse        = sessionsInUse;

   prtsmb_srv_ctx->activeSessions       = activeSessions;
   prtsmb_srv_ctx->namesrvBuffer        = namesrvBuffer;
   prtsmb_srv_ctx->client_buffer        = client_buffer;
   prtsmb_srv_ctx->shareTable           = shareTable;
   prtsmb_srv_ctx->userList.users       = users;
   prtsmb_srv_ctx->groupList.groups     = groups;
   prtsmb_srv_ctx->local_master         = local_master;
   prtsmb_srv_ctx->server_table         = server_table;
   prtsmb_srv_ctx->domain_table         = domain_table;
   prtsmb_srv_ctx->enum_results         = enum_results;

   for (i = 0; i < CFG_RTSMB_MAX_GROUPS; i++)
   {
      prtsmb_srv_ctx->groupList.groups[i].table = &access_table[i * ((CFG_RTSMB_MAX_SHARES * BITS_PER_TABLE_ENTRY / 8) + 1)];
   }

   for (i = 0; i < CFG_RTSMB_MAX_USERS; i++)
   {
      prtsmb_srv_ctx->userList.users[i].groups = &user_groups[i * CFG_RTSMB_MAX_GROUPS];
   }

   for (i = 0; i < CFG_RTSMB_MAX_SESSIONS; i++)
   {
	  rtp_sig_mutex_alloc((RTP_MUTEX *) &prtsmb_srv_ctx->activeSessions[i], (const char*)0);

      prtsmb_srv_ctx->sessions[i].smbCtx.uids  = &uids  [i * CFG_RTSMB_MAX_UIDS_PER_SESSION];
      prtsmb_srv_ctx->sessions[i].smbCtx.trees = &trees [i * CFG_RTSMB_MAX_TREES_PER_SESSION];
      prtsmb_srv_ctx->sessions[i].smbCtx.fids  = &fids  [i * CFG_RTSMB_MAX_FIDS_PER_SESSION];
   }

   for (i=0; i < CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_UIDS_PER_SESSION; i++)
   {
      uids[i].searches = &searches [i * CFG_RTSMB_MAX_SEARCHES_PER_UID];
      uids[i].fids     = &uid_fids [i * CFG_RTSMB_MAX_FIDS_PER_UID];
   }

   for (i=0; i < CFG_RTSMB_MAX_SESSIONS * CFG_RTSMB_MAX_TREES_PER_SESSION; i++)
   {
      trees[i].fids = &tree_fids [i * CFG_RTSMB_MAX_FIDS_PER_TREE];
   }

   for (i=0; i < CFG_RTSMB_MAX_THREADS + 1; i++)
   {
      threads[i].sessionList = &sessionList [i * CFG_RTSMB_MAX_SESSIONS];
      threads[i].inBuffer    = &inBuffer    [i * CFG_RTSMB_SMALL_BUFFER_SIZE];
      threads[i].outBuffer   = &outBuffer   [i * CFG_RTSMB_SMALL_BUFFER_SIZE];
      threads[i].tmpBuffer   = &tmpBuffer   [i * CFG_RTSMB_SMALL_BUFFER_SIZE];
   }

   tc_strcpy (prtsmb_srv_ctx->local_master, "");
   prtsmb_srv_ctx->enum_results_in_use = FALSE;

   for (i = 0; i < prtsmb_srv_ctx->server_table_size; i++)
   {
      prtsmb_srv_ctx->server_table[i].type = 0;
   }

   for (i = 0; i < prtsmb_srv_ctx->domain_table_size; i++)
   {
      prtsmb_srv_ctx->domain_table[i].type = 0;
   }

   return 1;
}

#endif /* INCLUDE_RTSMB_SERVER */
