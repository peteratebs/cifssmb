#ifndef __SMB_GLUE_H__
#define __SMB_GLUE_H__

#include "smbdefs.h"
#include "smbobjs.h"

/**
 * This file contains 'glue' functions between the server and client.  Sometimes,
 * the client will need access to certain server functions.  Here, that happens.
 *
 * When the server starts up, it will initialize these functions to point
 * to its own functions.  Then, the client will call these and get the right ones.
 *
 * The reason this is done is so that inclusion of the client or server is a link-
 * time decision, not compile-time.
 *
 * Currently, all these functions relate to the browse service and you are supposed
 * to claim prtsmb_browse_ctx->mutex before calling them or setting them.
 */



/* This gets the next server name from the server's collected table.  If the server
   is not collecting names, then it returns NULL.  If the server names are exhausted,
   it returns NULL.  Initialize 'i' to 0 before passing it to this function.  Don't use
   the value of 'i' for your own purposes.  It just a counter for this function.
*/
extern PFCHAR (*rtsmb_glue_get_server_name_from_cache) (PFINT i);



/* This sees if there are other workgroups on the network that we could query.  If
   the server doesn't know or if it does know that there are, it returns TRUE.  Otherwise
   it returns FALSE (it does know that there are none).
*/
extern BBOOL (*rtsmb_glue_are_other_workgroups) (void);



/* This returns TRUE if we are keeping a table of which domains are on the network.
*/
extern BBOOL (*rtsmb_glue_do_we_have_server_list) (void);



/* This returns our network name.
*/
extern PFCHAR (*rtsmb_glue_get_our_server_name) (void);


/* This processes the browser part of a browser packet.
*/
extern void (*rtsmb_glue_process_nbds_message) (PFCHAR dest_name, 
												  byte command, 
												  PFVOID origin, 
												  PFVOID buf, 
												  rtsmb_size size, 
												  PRTSMB_HEADER pheader);


#endif /* __SMB_GLUE_H__ */
