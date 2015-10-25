//
// SMBBRCFG.C - 
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Configure the NETBIOS Browser Layer
//

#include "smbdefs.h"


#include "smbbrcfg.h"
#include "psmbos.h"
#include "smbnb.h"
#include "rtpsignl.h"

#ifndef ALLOC_FROM_HEAP
#define ALLOC_FROM_HEAP  0   /* Set this to 1 to use malloc() to allocate 
                                RTSMB memory at startup, set to 0 to use
                                declare memory arrays and provide ertfs 
                                with the addresses of those arrays */
#endif
                                
#if (ALLOC_FROM_HEAP)
// #error Set ALLOC_FROM_HEAP to 0
#endif


/**
 * This controls how large the buffer we use for sending and receiving datagrams
 * is.  It's wise to let this be the maximum datagram size, so that we can receive
 * any datagram sent to us.
 */
#ifndef CFG_RTSMB_BROWSE_BUFFER_SIZE
#define CFG_RTSMB_BROWSE_BUFFER_SIZE                      RTSMB_NB_MAX_DATAGRAM_SIZE
#endif

/**
 * This controls how many backup servers we can discover at once.  Since we discover
 * one backup server per workgroup, this is actually how many workgroups we can discover
 * at once.  This is used when the client is alone without a server and wants to query
 * the network to find other servers.
 */
#ifndef CFG_RTSMB_BROWSE_BACKUP_LIST_SIZE
#define CFG_RTSMB_BROWSE_BACKUP_LIST_SIZE                 (10 * (RTSMB_NB_NAME_SIZE + 1))
#endif


RTSMB_STATIC byte                        browse_buffer               [CFG_RTSMB_BROWSE_BUFFER_SIZE];
RTSMB_STATIC rtsmb_char                  backup_table                [CFG_RTSMB_BROWSE_BACKUP_LIST_SIZE];


PRTSMB_BROWSE_CONTEXT prtsmb_browse_ctx;
int rtsmb_browse_config_initialized = 0;


RTSMB_STATIC RTSMB_BROWSE_CONTEXT rtsmb_browse_cfg_core;   /* The user must initialize this value to point */

#if (ALLOC_FROM_HEAP)
/* Using rtp_malloc to allocate memory at startup.*/
#include "rtpmem.h"
#else
/* Not using malloc to allocate memory so declare arrays that we can send 
   assign to the configuration block at startup. */

#endif /* (ALLOC_FROM_HEAP) */

int rtsmb_browse_config(void)
{
    /* Important: prtsmb_browse_ctx must point to a configuration block */
    prtsmb_browse_ctx = &rtsmb_browse_cfg_core;

    /* Important: the configuration block must be zeroed */
    tc_memset(prtsmb_browse_ctx, 0, sizeof(rtsmb_browse_cfg_core));

    rtp_sig_mutex_alloc((RTP_MUTEX *) &prtsmb_browse_ctx->mutex, (const char*)0);

    prtsmb_browse_ctx->buffer                  = browse_buffer;
    prtsmb_browse_ctx->buffer_size             = CFG_RTSMB_BROWSE_BUFFER_SIZE;
    prtsmb_browse_ctx->backup_list_data        = backup_table;
    prtsmb_browse_ctx->backup_list_size        = CFG_RTSMB_BROWSE_BACKUP_LIST_SIZE;
    
    tc_memset (prtsmb_browse_ctx->backup_list_data, 0, sizeof (prtsmb_browse_ctx->backup_list_data));

    /* Core that must be provided by the user */
#if (!ALLOC_FROM_HEAP)

    /* Not using malloc() so assign memory arrays to the configuration block */
    
    return (1);

#else
    /* Use Malloc do allocated RTSMB data */

    return (1);

malloc_failed:  
    return (0);
#endif
}
