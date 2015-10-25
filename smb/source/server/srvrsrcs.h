#ifndef __SRV_RSRCS_H__
#define __SRV_RSRCS_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvnet.h"
#include "srvcfg.h"
#include "psmbos.h"

/**
 * These defines handle reentrant management of resources
 * that are not stored here.  It is up to the code to not
 * abuse the semaphores.
 */


#define CLAIM_AUTH()          rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->authsem)
#define RELEASE_AUTH()        rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->authsem)

#define CLAIM_SHARE()         rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->sharesem)
#define RELEASE_SHARE()       rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->sharesem)

#define CLAIM_PRINTERS()      rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->printersem)
#define RELEASE_PRINTERS()    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->printersem)

#define CLAIM_NAME_CACHE()    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->cachesem)
#define RELEASE_NAME_CACHE()  rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->cachesem)

#define CLAIM_BUF()           rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->bufsem)
#define RELEASE_BUF()         rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->bufsem)

#define CLAIM_NET()           rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->netsem)
#define RELEASE_NET()         rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->netsem)

/**
 * These functions tightly control access to resources stored here.
 */
PNET_SESSIONCTX allocateSession (void);
void freeSession (PNET_SESSIONCTX p);

PFBYTE allocateBigBuffer (void);
void freeBigBuffer (PFBYTE p);

void claimSession (PNET_SESSIONCTX pCtx);
void releaseSession (PNET_SESSIONCTX pCtx);
PNET_SESSIONCTX firstSession (void);
PNET_SESSIONCTX nextSession (PNET_SESSIONCTX pCtx);

#endif /* INCLUDE_RTSMB_SERVER */

#endif
