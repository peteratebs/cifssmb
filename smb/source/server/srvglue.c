//
// SRVGLUE.C - 
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Functions to respond to queries of the Master Browser, if we are the 
// Master Browser.
//
#include "smbglue.h"
#include "srvbrws.h"
#include "srvcfg.h"
#include "smbbrcfg.h"
#include "srvnbns.h"

#include "rtpsignl.h"


/* This gets the next server name from the server's collected table.  If the server
   is not collecting names, then it returns NULL.  If the server names are exhausted,
   it returns NULL.  Initialize 'i' to 0 before passing it to this function.  Don't use
   the value of 'i' for your own purposes.  It just a counter for this function.
*/
RTSMB_STATIC PFCHAR _rtsmb_srv_glue_get_server_name_from_cache (PFINT i)
{
	int j;

	if (*i < 0 || *i >= prtsmb_srv_ctx->server_table_size)
	{
		return (PFCHAR)0;
	}

	for (j = *i; j < prtsmb_srv_ctx->server_table_size; j++)
	{
		if (prtsmb_srv_ctx->server_table[j].type)
		{
			break;
		}
	}

	*i = j + 1;

	if (j == prtsmb_srv_ctx->server_table_size)
	{
		return (PFCHAR)0;
	}
	else
	{
		return prtsmb_srv_ctx->server_table[j].name;
	}
}



/* This sees if there are other workgroups on the network that we could query.  If
   the server doesn't know or if it does know that there are, it returns TRUE.  Otherwise
   it returns FALSE (it does know or that there are none).
*/
RTSMB_STATIC BBOOL _rtsmb_srv_glue_are_other_workgroups (void)
{
	int i, num;

	switch (rtsmb_srv_browse_get_role ())
	{
	case RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER:
	case RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER:

		num = 0;
		for (i = 0; i < prtsmb_srv_ctx->domain_table_size; i++)
		{
			if (prtsmb_srv_ctx->domain_table[i].type)
			{
				num ++;
			}
		}

		if (num <= 1) /* only our own domain or none(?) */
		{
			return FALSE;
		}
		break;
	}

	return TRUE;
}



/* This returns TRUE if we are keeping a table of which domains are on the network.
*/
RTSMB_STATIC BBOOL _rtsmb_srv_glue_do_we_have_server_list (void)
{
	switch (rtsmb_srv_browse_get_role ())
	{
	case RTSMB_SRV_BROWSE_ROLE_MASTER_BROWSER:
	case RTSMB_SRV_BROWSE_ROLE_BACKUP_BROWSER:
		return TRUE;

	default:
		return FALSE;
	}
}



/* This returns our network name.
*/
RTSMB_STATIC PFCHAR _rtsmb_srv_glue_get_our_server_name (void)
{
	return rtsmb_srv_nbns_get_our_name ();
}


/* This processes the browser part of a browser packet.
*/
RTSMB_STATIC void _rtsmb_srv_glue_process_nbds_message (PFCHAR dest_name, 
							byte command, 
							PFVOID origin, 
							PFVOID buf, 
							rtsmb_size size, 
							PRTSMB_HEADER pheader)
{
	/* we should only respond if we own the destination name */
	if (rtsmb_srv_nbns_is_in_name_table (dest_name, TRUE))
	{
		rtsmb_srv_browse_process_message (command, origin, buf, size, pheader);
	}
}



/* This sets up the bindings to the glue layer */
void rtsmb_srv_glue_init (void)
{
	rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

	rtsmb_glue_get_server_name_from_cache = _rtsmb_srv_glue_get_server_name_from_cache;
	rtsmb_glue_are_other_workgroups = _rtsmb_srv_glue_are_other_workgroups;
	rtsmb_glue_do_we_have_server_list = _rtsmb_srv_glue_do_we_have_server_list;
	rtsmb_glue_get_our_server_name = _rtsmb_srv_glue_get_our_server_name;
	rtsmb_glue_process_nbds_message = _rtsmb_srv_glue_process_nbds_message;

	rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
}

/* This releases the bindings to the glue layer */
void rtsmb_srv_glue_shutdown (void)
{
	rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

	rtsmb_glue_get_server_name_from_cache = 0;
	rtsmb_glue_are_other_workgroups = 0;
	rtsmb_glue_do_we_have_server_list = 0;
	rtsmb_glue_get_our_server_name = 0;
	rtsmb_glue_process_nbds_message = 0;

	rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);
}
