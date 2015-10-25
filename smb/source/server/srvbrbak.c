//
// SRVBRBAK.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles the backup browser role of the NETBIOS Browser Service.
//

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvbrws.h"
#include "smbbrcfg.h"
#include "srvcfg.h"
#include "srvcli.h"
#include "srvssn.h"
#include "smbutil.h"
#include "srvutil.h"
#include "srvnbns.h"

#include "rtptime.h"
#include "rtpsignl.h"

#ifdef STATE_DIAGNOSTICS
extern void Get_Srv_Session_State(int a);
#endif

#define RTSMB_SRV_BROWSE_BACKUP_NETENUM_INTERVAL   900000 /* 15 minutes == 900000 ms */


RTSMB_STATIC unsigned long rtsmb_srv_browse_backup_next_send_base;
RTSMB_STATIC int           rtsmb_srv_browse_job_count;
RTSMB_STATIC int           rtsmb_srv_browse_enum_count;


RTSMB_STATIC void _rtsmb_srv_browse_enum_cleanup (void)
{
	if (rtsmb_srv_browse_job_count >= 0)
	{
		rtsmb_srv_cli_shutdown ();
		rtsmb_srv_browse_job_count = -1;

		rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->enum_results_mutex);
		prtsmb_srv_ctx->enum_results_in_use = FALSE;

		rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->enum_results_mutex);
	}
}

RTSMB_STATIC void _rtsmb_srv_browse_finish_net_enum_domains (void)
{
	int i;

	/* read results, pack them into our domain table. */
	rtsmb_srv_browse_domain_list_remove_all ();

	for (i = 0; i < rtsmb_srv_browse_enum_count; i++)
	{
		rtsmb_srv_browse_domain_list_add (&prtsmb_srv_ctx->enum_results[i]);
	}

	_rtsmb_srv_browse_enum_cleanup ();
}


RTSMB_STATIC void _rtsmb_srv_browse_finish_periodic_update (void)
{
	int i;

	/* read results, pack them into our server table. */
	rtsmb_srv_browse_server_list_remove_all ();

	for (i = 0; i < rtsmb_srv_browse_enum_count; i++)
	{
		rtsmb_srv_browse_server_list_add (&prtsmb_srv_ctx->enum_results[i]);
	}

	/* Now, start a job for listing domains */
	rtsmb_srv_cli_server_enum (SV_TYPE_DOMAIN_ENUM, (PFCHAR)0,
		prtsmb_srv_ctx->enum_results, prtsmb_srv_ctx->enum_results_size,
		&rtsmb_srv_browse_enum_count);
}

RTSMB_STATIC void _rtsmb_srv_browse_start_periodic_update (void)
{
	/* for any type, only our own domain */
	rtsmb_srv_cli_server_enum (0xFFFFFFFF, rtsmb_srv_nbns_get_our_group (),
		prtsmb_srv_ctx->enum_results, prtsmb_srv_ctx->enum_results_size,
		&rtsmb_srv_browse_enum_count);
}


RTSMB_STATIC void _rtsmb_srv_browse_start_net_enum_servers (PSMB_SESSIONCTX pCtx)
{
	/* for any type, only the server's domain */
	rtsmb_srv_cli_server_enum (0xFFFFFFFF, pCtx->server_enum_domain,
		prtsmb_srv_ctx->enum_results, prtsmb_srv_ctx->enum_results_size,
		&rtsmb_srv_browse_enum_count);
}


void rtsmb_srv_browse_finish_server_enum (PSMB_SESSIONCTX pCtx)
{
	BBOOL go_ahead;
	int i, r;

	switch (pCtx->state)
	{
	case BROWSE_MUTEX:

		/* First, make sure that we know about the domain requested. */
		rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

		for (i = 0; i < prtsmb_srv_ctx->domain_table_size; i++)
		{
			if (prtsmb_srv_ctx->domain_table[i].type)
			{
				if (rtsmb_strcasecmp (pCtx->server_enum_domain, prtsmb_srv_ctx->domain_table[i].name, CFG_RTSMB_USER_CODEPAGE) == 0)
				{
					break;
				}
			}
		}

		rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);

		if (i == prtsmb_srv_ctx->domain_table_size) /* didn't find domain */
		{
#ifdef STATE_DIAGNOSTICS
Get_Srv_Session_State (BROWSE_FAIL);
#endif
			pCtx->state = BROWSE_FAIL;
			return;
		}

		/* Now, claim the enum_results mutex so that only we will be using it. */
		rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->enum_results_mutex);

		go_ahead = prtsmb_srv_ctx->enum_results_in_use ? FALSE : TRUE;
		prtsmb_srv_ctx->enum_results_in_use = TRUE;

		rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->enum_results_mutex);

		if (!go_ahead)
		{
			/* We have to wait until enum_results is free. */
			return;
		}

		/* Connect to the master server for the requested domain. */
		rtsmb_srv_cli_connect_to (prtsmb_srv_ctx->domain_table[i].comment);
		rtsmb_srv_browse_job_count = 0;
#ifdef STATE_DIAGNOSTICS
Get_Srv_Session_State (BROWSE_SENT);
#endif
		pCtx->state = BROWSE_SENT;
		break;

	case BROWSE_SENT:

		r = rtsmb_srv_cli_cycle (0);
		if (r < 0)
		{
#ifdef STATE_DIAGNOSTICS
Get_Srv_Session_State (BROWSE_FAIL);
#endif
			pCtx->state = BROWSE_FAIL;
		}
		else if (r > 0)
		{
			rtsmb_srv_browse_job_count ++;

			switch (rtsmb_srv_browse_job_count)
			{
			case 1: /* just connected/negotiated, etc.  Send net enum */
				_rtsmb_srv_browse_start_net_enum_servers (pCtx);
				break;

			case 2: /* just finished net enum. */
#ifdef STATE_DIAGNOSTICS
Get_Srv_Session_State (BROWSE_FINISH);
#endif
				pCtx->state = BROWSE_FINISH;
				break;
			}
		}
		break;

	case BROWSE_FINISH:
	case BROWSE_FAIL:

		/* we might be here because of an error or because of success -- either way,
		   we ship out a packet */

		/* here, we process the packet again (it's still in our buffers), but our
		   state will tell the appropriate function to read from our results here */
		if (SMBS_ProcSMBBody (pCtx)) /* do send */
		{
			SMBS_SendMessage (pCtx, pCtx->outBodySize, TRUE);
		}

		_rtsmb_srv_browse_enum_cleanup ();
#ifdef STATE_DIAGNOSTICS
Get_Srv_Session_State (IDLE);
#endif
		pCtx->state = IDLE;

		break;
#ifdef SUPPORT_SMB2   
	case NOTCONNECTED:
#endif
	case IDLE:
	case READING:
	case WAIT_ON_PDC_NAME:
	case WAIT_ON_PDC_IP:
	case FAIL_NEGOTIATE:
	case FINISH_NEGOTIATE:
	case WRITING_RAW:
	case WRITING_RAW_READING:
		break;
	}

}


void rtsmb_srv_browse_backup_start (void)
{
	rtsmb_srv_browse_job_count = -1;
	rtsmb_srv_browse_backup_next_send_base = rtp_get_system_msec() - RTSMB_SRV_BROWSE_BACKUP_NETENUM_INTERVAL;
}


void rtsmb_srv_browse_backup_stop (void)
{
	_rtsmb_srv_browse_enum_cleanup ();
}


void rtsmb_srv_browse_backup_cycle (void)
{
	int r;
	BBOOL dead_local_master = FALSE;

	if (rtsmb_srv_browse_job_count >= 0)
	{
		r = rtsmb_srv_cli_cycle (0);

		if (r < 0)
		{
			_rtsmb_srv_browse_enum_cleanup ();
			dead_local_master = TRUE;
		}
		else if (r > 0)
		{
			rtsmb_srv_browse_job_count ++;

			switch (rtsmb_srv_browse_job_count)
			{
			case 1: /* just connected/negotiated, etc.  Send net enum */
				_rtsmb_srv_browse_start_periodic_update ();
				break;

			case 2: /* just finished net enum.  Send domain enum */
				_rtsmb_srv_browse_finish_periodic_update ();
				break;

			case 3: /* just finished domain enum. */
				_rtsmb_srv_browse_finish_net_enum_domains ();
				break;
			}
		}
	}

	if (dead_local_master)
	{
		rtsmb_srv_browse_force_election ();
	}

	if (IS_PAST (rtsmb_srv_browse_backup_next_send_base, RTSMB_SRV_BROWSE_BACKUP_NETENUM_INTERVAL))
	{
		/* Start a net enum on our local master */
		BBOOL go_ahead;

		rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->enum_results_mutex);

		go_ahead = prtsmb_srv_ctx->enum_results_in_use ? FALSE : TRUE;
		prtsmb_srv_ctx->enum_results_in_use = TRUE;

		rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->enum_results_mutex);

		if (go_ahead)
		{
			if (prtsmb_srv_ctx->local_master[0] != '\0')
			{
				rtsmb_srv_cli_connect_to (prtsmb_srv_ctx->local_master);
				rtsmb_srv_browse_job_count = 0;
			}
			else
			{

				rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->enum_results_mutex);

				prtsmb_srv_ctx->enum_results_in_use = FALSE;

				rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->enum_results_mutex);
			}

			rtsmb_srv_browse_backup_next_send_base = rtp_get_system_msec();
		}
	}
}

#endif /* INCLUDE_RTSMB_SERVER */
