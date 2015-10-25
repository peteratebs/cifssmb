//
// SRVRSRCS.C - 
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles NETBIOS Session Layer including claiming and freeing sessions
//

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvrsrcs.h"
#include "srvcfg.h"
#include "rtpsignl.h"
#include "smbdebug.h"

void claimSession (PNET_SESSIONCTX pCtx)
{
	int i;
	i = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);
	
	rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->activeSessions[i]);
}

void releaseSession (PNET_SESSIONCTX pCtx)
{
	int i;
	i = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);
	rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->activeSessions[i]);

}
PNET_SESSIONCTX firstSession (void)
{
	PNET_SESSIONCTX rv = (PNET_SESSIONCTX)0;
	word i;
	
	CLAIM_NET ();
	for (i = 0; i < prtsmb_srv_ctx->max_sessions; i++)
	{
		if (prtsmb_srv_ctx->sessionsInUse[i])
		{
			rv = &prtsmb_srv_ctx->sessions[i];
			break;
		}
	}
	RELEASE_NET ();
	
	return rv;
}

PNET_SESSIONCTX nextSession (PNET_SESSIONCTX pCtx)
{
	int i;
	PNET_SESSIONCTX rv = (PNET_SESSIONCTX)0;
	i = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);
		
	CLAIM_NET ();
	for (i = i + 1; i < prtsmb_srv_ctx->max_sessions; i++)
	{
		if (prtsmb_srv_ctx->sessionsInUse[i])
		{
			rv = &prtsmb_srv_ctx->sessions[i];
			break;
		}
	}
	RELEASE_NET ();
	
	return rv;
}

PNET_SESSIONCTX allocateSession (void)
{
	word i;
	PNET_SESSIONCTX rv = (PNET_SESSIONCTX)0;
	
	CLAIM_NET ();
	for (i = 0; i < prtsmb_srv_ctx->max_sessions; i++)
	{
		if (!prtsmb_srv_ctx->sessionsInUse[i])
		{
			RTSMB_DEBUG_OUTPUT_STR("Allocating session ", RTSMB_DEBUG_TYPE_ASCII);
			RTSMB_DEBUG_OUTPUT_INT(i);
			RTSMB_DEBUG_OUTPUT_STR("\n", RTSMB_DEBUG_TYPE_ASCII);
			prtsmb_srv_ctx->sessionsInUse[i] = 1;
			rv = &prtsmb_srv_ctx->sessions[i];
			break;
		}
	}
	RELEASE_NET ();
	
	return rv;
}

void freeSession (PNET_SESSIONCTX p)
{
	int location;
	location = INDEX_OF (prtsmb_srv_ctx->sessions, p);
	
	RTSMB_DEBUG_OUTPUT_STR ("Freeing session ", RTSMB_DEBUG_TYPE_ASCII);
	RTSMB_DEBUG_OUTPUT_INT (location);
	RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);
	
	CLAIM_NET ();
	prtsmb_srv_ctx->sessionsInUse[location] = 0;
	RELEASE_NET ();
}


PFBYTE allocateBigBuffer (void)
{
	word i;
	PFBYTE rv = (PFBYTE)0;
	
	CLAIM_BUF ();
	for (i = 0; i < prtsmb_srv_ctx->num_big_buffers; i++)
	{
		if (!prtsmb_srv_ctx->bigBufferInUse[i])
		{
			prtsmb_srv_ctx->bigBufferInUse[i] = 1;
			rv = &prtsmb_srv_ctx->bigBuffers[i * prtsmb_srv_ctx->big_buffer_size];
			break;
		}
	}
	RELEASE_BUF ();
	
	return rv;
}

void freeBigBuffer (PFBYTE p)
{
	int location;
	location = INDEX_OF (prtsmb_srv_ctx->bigBuffers, p);
	
	CLAIM_BUF ();
	prtsmb_srv_ctx->bigBufferInUse[location] = 0;
	RELEASE_BUF ();
}

#endif /* INCLUDE_RTSMB_SERVER */
