#ifndef __SRV_CFG_H__
#define __SRV_CFG_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvnet.h"
#include "srvauth.h"
#include "smbnbds.h"

#define CFG_RTSMB_PRINT_SIZES 0 /* temp config for testing purposes */

typedef struct _RTSMB_SERVER_CONTEXT
{
	/* CONFIGURATION PARAMETERS */
	unsigned short    max_threads;
	unsigned short    max_sessions;
	unsigned short    max_uids_per_session;
	unsigned short    max_fids_per_tree;
	unsigned short    max_fids_per_uid;
	unsigned short    max_fids_per_session;
	unsigned short    max_trees_per_session;
	unsigned short    max_searches_per_uid;
	unsigned short    max_shares;
	unsigned short    max_users;
	unsigned short    max_groups;
	unsigned short    small_buffer_size;
	unsigned long     big_buffer_size;
	unsigned short    num_big_buffers;
	int               enum_results_size;
	BBOOL             enum_results_in_use;
	int               server_table_size;
	int               domain_table_size;
	
	/* MUTEX HANDLES */
	unsigned long     bufsem;
	unsigned long     authsem;
	unsigned long     sharesem;
	unsigned long     printersem;
	unsigned long     cachesem;
	unsigned long     mailPDCNameSem;
	unsigned long     netsem;
	unsigned long    *activeSessions;
	unsigned long     enum_results_mutex;
	
	/* BUFFER POOLS */
	PFBYTE                      bigBuffers;
	PFCHAR                      bigBufferInUse;
	PNET_THREAD                 threads;
	PFCHAR                      threadsInUse;
	PNET_SESSIONCTX             sessions;
	PFCHAR                      sessionsInUse;
	PFBYTE                      namesrvBuffer;
	PFBYTE                      client_buffer;
	PSR_RESOURCE                shareTable;
	PRTSMB_BROWSE_SERVER_INFO   enum_results;
	PRTSMB_BROWSE_SERVER_INFO   server_table;
	PRTSMB_BROWSE_SERVER_INFO   domain_table;

	/* OTHER STUFF */
	byte              shareMode;
	short             guestAccount;
	GROUPS_T          groupList;
	USERLIST_T        userList;
	PFCHAR            local_master;
}
RTSMB_SERVER_CONTEXT;

typedef RTSMB_SERVER_CONTEXT *PRTSMB_SERVER_CONTEXT;

extern PRTSMB_SERVER_CONTEXT prtsmb_srv_ctx;

int rtsmb_server_config(void);

#endif /* INCLUDE_RTSMB_SERVER */

#endif
