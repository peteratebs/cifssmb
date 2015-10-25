#ifndef __SRV_NBSS_H__
#define __SRV_NBSS_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvssn.h"

void  rtsmb_srv_nbss_send_session_response (RTP_SOCKET sock, BBOOL positive);
void  rtsmb_srv_nbss_send_session_request (RTP_SOCKET sock, PFCHAR server_name, byte server_type);
BBOOL rtsmb_srv_nbss_process_packet (PSMB_SESSIONCTX pSCtx);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_NBSS_H__ */
