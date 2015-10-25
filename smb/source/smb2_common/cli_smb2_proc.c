//
// CLI_SMB2_PROC.C -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2013
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  SMB2 client session level interface
//

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#if (INCLUDE_RTSMB_CLIENT)
#include "com_smb2.h"


#include "clissn.h"
#include "smbutil.h"
#include "clians.h"
#include "clicmds.h"
#include "smbnbns.h"
#include "smbnbds.h"
#include "smbnet.h"
#include "smbpack.h"
#include "smbnb.h"
#include "clicfg.h"
#include "smbbrcfg.h"
#include "smbglue.h"
#include "smbdebug.h"
#include "smbconf.h"

#include "rtptime.h"
#include "rtpnet.h"
#include "rtpthrd.h"
#include "rtpwcs.h"
#include "smbobjs.h"
#include <assert.h>

extern void rtsmb_cli_session_job_cleanup (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, int r);
extern void rtsmb_cli_session_user_close (PRTSMB_CLI_SESSION_USER pUser);


static Rtsmb2ClientSession Rtsmb2ClientSessionArray[32];


extern PRTSMB_CLI_WIRE_BUFFER rtsmb_cli_wire_get_free_buffer (PRTSMB_CLI_WIRE_SESSION pSession);

int rtsmb_cli_wire_smb2_add_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

static Rtsmb2ClientSession *NewRtsmb2ClientSession(void);

/* Called when a new_session is created sepcifying an SMBV2 dialect. Calls NewRtsmb2ClientSession() to allocate a new V2 session..
   Currently holds SessionId, building it up. */
void rtsmb_cli_smb2_session_init (PRTSMB_CLI_SESSION pSession)
{
    pSession->psmb2Session = NewRtsmb2ClientSession();
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_smb2_session_init called: Session == %X  pSession->psmb2Session == %X\n",(int)pSession, (int) pSession->psmb2Session);
}

void rtsmb_cli_smb2_session_release (PRTSMB_CLI_SESSION pSession)
{
    if (pSession->psmb2Session)
    {
        pSession->psmb2Session->inUse = FALSE;
        pSession->psmb2Session = 0;
    }
}


static Rtsmb2ClientSession *NewRtsmb2ClientSession(void)
{
int i;
    for (i = 0; i < 32; i++)
    {
        if (!Rtsmb2ClientSessionArray[i].inUse)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Session number %d of %d just allocated\n", i,TABLE_SIZE(Rtsmb2ClientSessionArray) );
            Rtsmb2ClientSessionArray[i].inUse = TRUE;
            return &Rtsmb2ClientSessionArray[i];
        }
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "No client sessions available\n",0);
    return 0;
}

smb2_stream  *rtsmb_cli_wire_smb2_stream_construct (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    BBOOL EncryptMessage = FALSE; // HEREHERE
    int v1_mid;

    /* Attach a buffer to the wire session */
    v1_mid = rtsmb_cli_wire_smb2_add_start (&pSession->wire, pJob->mid);
    if (v1_mid<0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_construct: rtsmb_cli_wire_smb2_add_start Failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
        return 0;
    }

    pJob->mid = (word)v1_mid;
    pBuffer = rtsmb_cli_wire_get_buffer (&pSession->wire, (word) v1_mid);
    if (!pBuffer)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_construct: rtsmb_cli_wire_get_buffer Failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",0);
        return 0;
    }

    /* Initialize stream structure from V1 buffer structure */
    tc_memset(&pBuffer->smb2stream, 0, sizeof(pBuffer->smb2stream));

    /* Reads and writes don't interleave so the streams are initialized the same */

    /* Reads will be performed starting form the session buffer origin using size values and offset from the session buffer */
    pBuffer->smb2stream.Success=TRUE;
    pBuffer->smb2stream.read_origin             = pBuffer->buffer;
    pBuffer->smb2stream.pInBuf                  = pBuffer->buffer_end;
    pBuffer->smb2stream.read_buffer_size        = pBuffer->allocated_buffer_size;                               /* read buffer_size is the buffer size minus NBSS header */
    pBuffer->smb2stream.read_buffer_remaining   = pBuffer->smb2stream.read_buffer_size-(rtsmb_size)PDIFF(pBuffer->smb2stream.pInBuf,pBuffer->smb2stream.read_origin); // RTSMB_NBSS_HEADER_SIZE;

    /* Writes will be performed starting form the session buffer origin using size values and offset from the session buffer */
    pBuffer->smb2stream.OutHdr.StructureSize    = 64;
    pBuffer->smb2stream.write_origin            = pBuffer->smb2stream.read_origin;                  /* write_buffer_size is the buffer size minus NBSS header */
    pBuffer->smb2stream.write_buffer_size       = pBuffer->smb2stream.read_buffer_size;
    pBuffer->smb2stream.pOutBuf                 = pBuffer->smb2stream.pInBuf;
    pBuffer->smb2stream.write_buffer_remaining  = pBuffer->smb2stream.read_buffer_remaining;
    pBuffer->smb2stream.OutBodySize = 0;

    pBuffer->smb2stream.pBuffer = pBuffer;
    pBuffer->smb2stream.pSession = pSession;
    if (!(pBuffer->smb2stream.pSession && pBuffer->smb2stream.pSession->psmb2Session))
    {
        if (!pSession)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_construct: NewRtsmb2ClientSession Failed no PRTSMB_CLI_SESSION !!!!!!!!!\n", 0);
        }
        else
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_construct: NewRtsmb2ClientSession Failed no psmb2Session !!!!!!!!!!!!!!!!!\n", 0);
        }
        return 0;
    }
    pBuffer->smb2stream.pJob     = pJob;
    if (EncryptMessage)
        smb2_stream_start_encryption(&pBuffer->smb2stream);
    return &pBuffer->smb2stream;
}

smb2_stream  *rtsmb_cli_wire_smb2_stream_get(PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);
    if (pBuffer)
    {
        return &pBuffer->smb2stream;
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_get: rtsmb_cli_wire_get_buffer Failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!\n", 0);
    return 0;
}


smb2_stream  *rtsmb_cli_wire_smb2_stream_attach (PRTSMB_CLI_WIRE_SESSION pSession, word mid, int header_length, RTSMB2_HEADER *pheader_smb2)
{
    smb2_stream  *pStream = rtsmb_cli_wire_smb2_stream_get(pSession, mid);

    if (pStream )
    {
        pStream->InHdr     = *pheader_smb2;
        ((PFBYTE)pStream->pInBuf)    += header_length;
        pStream->read_buffer_remaining -= (rtsmb_size)header_length;
    }
   return pStream;
}

int rtsmb_cli_wire_smb2_stream_flush(PRTSMB_CLI_WIRE_SESSION pSession, smb2_stream  *pStream)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    RTSMB_NBSS_HEADER header;
    pBuffer = pStream->pBuffer;

    pBuffer->buffer_size = pStream->write_buffer_size-pStream->write_buffer_remaining;

    header.type = RTSMB_NBSS_COM_MESSAGE;
    header.size = (word) (pBuffer->buffer_size - RTSMB_NBSS_HEADER_SIZE);

  #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
    if (pBuffer->attached_data)
    {
        header.size += pBuffer->attached_size;
    }
  #endif
    rtsmb_nbss_fill_header (pBuffer->buffer, RTSMB_NBSS_HEADER_SIZE, &header);

    TURN_ON (pBuffer->flags, INFO_CAN_TIMEOUT);

    if (pSession->state == CONNECTED)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_wire_smb2_stream_flush: Set state Waiting on us\n",0);
        pBuffer->state = WAITING_ON_US;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(WAITING_ON_US);
#endif
    }
    else
    {
        pBuffer->end_time_base = rtp_get_system_msec ();
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_wire_smb2_stream_flush: Writing %d bytes\n",(int)pBuffer->buffer_size);
        if (rtsmb_net_write (pSession->socket, pBuffer->buffer, (int)pBuffer->buffer_size)<0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_flush: Error writing %d bytes !!!!!!!!!!!!!!!!!\n",(int)pBuffer->buffer_size);
            return -2;
        }

      #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
        if (pBuffer->attached_data)
        {
            if (rtsmb_net_write (pSession->socket, pBuffer->attached_data, (int)pBuffer->attached_size)<0)
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_flush: Error writing %d attached bytes !!!!!!!!!!!!!!!!!\n",(int)pBuffer->attached_size);
                return -2;
            }
        }
      #endif
        pBuffer->state = WAITING_ON_SERVER;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_wire_smb2_stream_flush: Set state Waiting on server\n",0);
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(WAITING_ON_SERVER);
#endif
    }
    return 0;
}


static void rtsmb2_cli_session_init_header(smb2_stream  *pStream, word command, ddword mid64, ddword SessionId)
{

    tc_memset(&pStream->OutHdr, 0, sizeof(pStream->OutHdr));
    tc_memcpy(pStream->OutHdr.ProtocolId,"\xfeSMB",4);
    pStream->OutHdr.StructureSize=64;
    pStream->OutHdr.CreditCharge = 0;
    pStream->OutHdr.Status_ChannelSequenceReserved=0; /*  (4 bytes): */
    pStream->OutHdr.Command = command;
    pStream->OutHdr.CreditRequest_CreditResponse = 0;
    pStream->OutHdr.Flags = 0;
    pStream->OutHdr.NextCommand = 0;
    pStream->OutHdr.MessageId = mid64;
    pStream->OutHdr.SessionId = SessionId;
    pStream->OutHdr.Reserved=0;
    pStream->OutHdr.TreeId=0;
    tc_strcpy((char *)pStream->OutHdr.Signature,"IAMTHESIGNATURE");

}

int RtsmbStreamEncodeCommand(smb2_stream *pStream, PFVOID pItem);
int RtsmbStreamDecodeResponse(smb2_stream *pStream, PFVOID pItem);


/* Encode with RtsmbStreamEncodeCommand */
int rtsmb2_cli_session_send_negotiate (smb2_stream  *pStream)
{
    RTSMB2_NEGOTIATE_C command_pkt;
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));
    rtsmb2_cli_session_init_header (pStream, SMB2_NEGOTIATE, (ddword) pStream->pBuffer->mid, 0);

    command_pkt.StructureSize = 36;
    command_pkt.DialectCount=1;
    command_pkt.SecurityMode  = SMB2_NEGOTIATE_SIGNING_ENABLED;
    command_pkt.Reserved=0;
    command_pkt.Capabilities = 0; // SMB2_GLOBAL_CAP_DFS  et al
    tc_strcpy((char *)command_pkt.guid, "IAMTHEGUID     ");
    command_pkt.ClientStartTime = 0; // rtsmb_util_get_current_filetime();  // ???  TBD
    /* GUID is zero for SMB2002 */
    // tc_memset(command_pkt.ClientGuid, 0, 16);
    command_pkt.Dialects[0] = SMB2_DIALECT_2002;

    /* Packs the SMB2 header and negotiate command into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
rtp_printf("PVO Send negotiate complet\n");
    return send_status;
}


int rtsmb2_cli_session_receive_negotiate (smb2_stream  *pStream)
{
int recv_status = RTSMB_CLI_SSN_RV_OK;
RTSMB2_NEGOTIATE_R response_pkt;
byte securiy_buffer[255];

    pStream->ReadBufferParms[0].byte_count = sizeof(securiy_buffer);
    pStream->ReadBufferParms[0].pBuffer = securiy_buffer;
    if (RtsmbStreamDecodeResponse(pStream, &response_pkt) < 0)
        return RTSMB_CLI_SSN_RV_MALFORMED;
    pStream->pSession->server_info.dialect =  response_pkt.DialectRevision;


#if (0)

##    pSession->server_info.dialect = 0;
##    if (nr.DialectRevision == SMB2_DIALECT_2002)
##        pSession->server_info.dialect = CSSN_DIALECT_SMB2_2002;
##    ASSURE (pSession->server_info.dialect != 0, RTSMB_CLI_SSN_RV_MALFORMED);
##
##//    pSession->server_info.user_mode = ON (nr.security_mode, 0x1);
##    pSession->server_info.capabilities = nr.Capabilities;
##//    pSession->server_info.encrypted = ON (nr.security_mode, 0x2);
##    pSession->server_info.buffer_size = nr.MaxReadSize;
##    pSession->server_info.raw_size = nr.MaxTransactSize;
##//    pSession->server_info.vcs = nr.max_vcs;
##//    pSession->server_info.session_id = nr.session_id;
##//    pSession->server_info.mpx_count = (word) MIN (nr.max_mpx_count, prtsmb_cli_ctx->max_jobs_per_session);
##
##HEREHERE - Do the session
##    int r = 0;
##
##    nr.challenge_size = 8;
##    nr.challenge = pSession->server_info.challenge;
##    nr.domain = 0;
##    nr.dialect_index = 0;
##    nr.security_mode = 0;
##    nr.capabilities = 0;
##    nr.max_buffer_size = 0;
##    nr.max_raw_size = 0;
##    nr.max_vcs = 0;
##    nr.session_id = 0;
##    nr.max_mpx_count = 0;
##
#####    rtsmb_cli_wire_smb2_read (&pSession->wire, pHeader->mid, cmd_read_negotiate_smb2, &nr, r);
##    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
##
##    /* make sure we have a valid dialect */
##    ASSURE (nr.dialect_index != 0xFF, RTSMB_CLI_SSN_RV_DEAD);
##    ASSURE (nr.dialect_index < NUM_SPOKEN_DIALECTS, RTSMB_CLI_SSN_RV_MALICE);
##
##    pSession->server_info.dialect = dialect_types[nr.dialect_index];
##    pSession->server_info.user_mode = ON (nr.security_mode, 0x1);
##    pSession->server_info.capabilities = nr.capabilities;
##    pSession->server_info.encrypted = ON (nr.security_mode, 0x2);
##    pSession->server_info.buffer_size = nr.max_buffer_size;
##    pSession->server_info.raw_size = nr.max_raw_size;
##    pSession->server_info.vcs = nr.max_vcs;
##    pSession->server_info.session_id = nr.session_id;
##    pSession->server_info.mpx_count = (word) MIN (nr.max_mpx_count, prtsmb_cli_ctx->max_jobs_per_session);
##
##    if (pSession->server_info.encrypted)
##    {
##        /* we currently only support 8-bytes */
##        ASSURE (nr.challenge_size == 8, RTSMB_CLI_SSN_RV_DEAD);
##    }
##rtp_printf("PVO Receive RTSMB2_NEGOTIATE_R returning ok\n");
#endif
    return recv_status;
}

int rtsmb2_cli_session_send_session_setup (smb2_stream  *pStream)
{
    RTSMB2_SESSION_SETUP_C command_pkt;
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));
    rtsmb2_cli_session_init_header (pStream, SMB2_SESSION_SETUP, (ddword) pStream->pBuffer->mid,0);

rtp_printf("PVO Send session setup entered\n");


    command_pkt.StructureSize = 25;
    command_pkt.Flags = 0;
    command_pkt.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED;
    command_pkt.Capabilities = 0;
    command_pkt.Channel = 0;
    command_pkt.SecurityBufferOffset = (word)(pStream->OutHdr.StructureSize+command_pkt.StructureSize-1);
    command_pkt.SecurityBufferLength = (word)pStream->pSession->user.spnego_blob_size;
//    Command.PreviousSessionId[]
    pStream->WriteBufferParms[0].byte_count = pStream->pSession->user.spnego_blob_size;
    pStream->WriteBufferParms[0].pBuffer = pStream->pSession->user.spnego_blob;

    /* Packs the SMB2 header and setup command/blob into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    return send_status;
}

int rtsmb2_cli_session_receive_session_setup (smb2_stream  *pStream)
{
int recv_status = RTSMB_CLI_SSN_RV_OK;
RTSMB2_SESSION_SETUP_R response_pkt;
byte securiy_buffer[255];

rtp_printf("PVO Recv session setup entered\n");

    pStream->ReadBufferParms[0].byte_count = sizeof(securiy_buffer);
    pStream->ReadBufferParms[0].pBuffer = securiy_buffer;

//    recv_status = cmd_read_header_smb2 (pStream);
//    ASSURE (recv_status > 0, RTSMB_CLI_SSN_RV_MALFORMED);
    if (RtsmbStreamDecodeResponse(pStream, &response_pkt) < 0)
        return RTSMB_CLI_SSN_RV_MALFORMED;

    pStream->pSession->psmb2Session->SessionId = pStream->InHdr.SessionId;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_session_setup: Set stream's session id to %X\n", (int)pStream->pSession->psmb2Session->SessionId);

	/* make sure we have a valid user */
	if (pStream->pJob->data.session_setup.user_struct->state != CSSN_USER_STATE_LOGGING_ON)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb2_cli_session_receive_session_setup: %s\n", "pStream->pJob->data.session_setup.user_struct->state != CSSN_USER_STATE_LOGGING_ON");
	    return RTSMB_CLI_SSN_RV_BAD_UID;
    }

//	pStream->pJob->data.session_setup.user_struct->uid = pHeader->uid;
	pStream->pJob->data.session_setup.user_struct->state = CSSN_USER_STATE_LOGGED_ON;


#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_USER_STATE (CSSN_USER_STATE_LOGGED_ON);
#endif
	rtsmb_cpy (pStream->pJob->data.session_setup.user_struct->name, pStream->pJob->data.session_setup.account_name);
	tc_strcpy (pStream->pJob->data.session_setup.user_struct->password, pStream->pJob->data.session_setup.password);
	rtsmb_cpy (pStream->pJob->data.session_setup.user_struct->domain_name, pStream->pJob->data.session_setup.domain_name);

    return recv_status;
}

int rtsmb2_cli_session_send_tree_connect (smb2_stream  *pStream)
{
    RTSMB2_TREE_CONNECT_C command_pkt;
    rtsmb_char share_name [RTSMB_NB_NAME_SIZE + RTSMB_MAX_SHARENAME_SIZE + 4]; /* 3 for '\\'s and 1 for null */
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));

    rtsmb2_cli_session_init_header (pStream, SMB2_TREE_CONNECT, (ddword) pStream->pBuffer->mid,pStream->pSession->psmb2Session->SessionId);

    tc_memset (share_name, 0, sizeof (share_name));
    if (tc_strcmp (pStream->pSession->server_name, "") != 0)
    {
        share_name[0] = '\\';
        share_name[1] = '\\';
        rtsmb_util_ascii_to_rtsmb (pStream->pSession->server_name, &share_name[2], CFG_RTSMB_USER_CODEPAGE);
        share_name [rtsmb_len (share_name)] = '\\';
    }
    rtsmb_util_ascii_to_rtsmb (pStream->pJob->data.tree_connect.share_name, &share_name [rtsmb_len (share_name)], CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_string_to_upper (share_name, CFG_RTSMB_USER_CODEPAGE);
    pStream->WriteBufferParms[0].pBuffer = share_name;
    pStream->WriteBufferParms[0].byte_count = (rtsmb_len (share_name)+1)*sizeof(rtsmb_char);

    command_pkt.StructureSize   = 9;
    command_pkt.Reserved        = 0;
    command_pkt.PathOffset      = (word) (pStream->OutHdr.StructureSize+command_pkt.StructureSize-1);
    command_pkt.PathLength      = (word)pStream->WriteBufferParms[0].byte_count;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_tree_connect called: Sharename == %s\n",share_name);
    rtp_printf("PVO : Set pJob->data.tree_connect.share_struct->connect_mid = pJob->mid == %d, by buffer == %d\n",  (int)pStream->pJob->mid, (int)pStream->pBuffer->mid);
    /* Save the message ID in the share sructure */
	pStream->pJob->data.tree_connect.share_struct->connect_mid = pStream->pJob->mid;


//=====
//	r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
//	ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
//	pJob->mid = (word) r;
//	pJob->data.tree_connect.share_struct->connect_mid = pJob->mid;
//	rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
//	rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_tree_connect_and_x, &t, r);
//	rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);
// ================
    /* Packs the SMB2 header and tree connect command/blob into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    return send_status;
}


int rtsmb2_cli_session_receive_tree_connect (smb2_stream  *pStream)
{
int recv_status = RTSMB_CLI_SSN_RV_OK;
RTSMB2_TREE_CONNECT_R response_pkt;

    if (RtsmbStreamDecodeResponse(pStream, &response_pkt) < 0)
        return RTSMB_CLI_SSN_RV_MALFORMED;

// ====================================
//int rtsmb_cli_session_receive_tree_connect (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    PRTSMB_CLI_SESSION pSession;
	PRTSMB_CLI_SESSION_SHARE pShare;
	int r = 0;

	pShare = 0;
    pSession  = pStream->pSession;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_connect called\n",0);
    if(!pSession)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_connect: No sesion info !!!! \n",0);
    }
    if(pSession)
    {
	    for (r = 0; r < prtsmb_cli_ctx->max_shares_per_session; r++)
    	{
      		if (pSession->shares[r].state != CSSN_SHARE_STATE_UNUSED &&
    		    pSession->shares[r].connect_mid == (word) pStream->InHdr.MessageId)
    		{
    			pShare = &pSession->shares[r];
    		    break;
    		}
    	}
    }
   	if (!pShare)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_connect: No Share found !!!!!!! \n", 0);
        return RTSMB_CLI_SSN_RV_MALFORMED;
    }

	pShare->tid = (word)pStream->InHdr.TreeId;
	pShare->state = CSSN_SHARE_STATE_CONNECTED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SHARE_STATE (CSSN_SHARE_STATE_CONNECTED);
#endif
	tc_strcpy (pShare->share_name, pStream->pJob->data.tree_connect.share_name);
	tc_strcpy (pShare->password, pStream->pJob->data.tree_connect.password);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_connect: Share found: Names == %s\n",pShare->share_name);

	/* We special-case a situation where we have just connected to the IPC$ share.  This
	   means that we are now a fully-negotiated session and should alert our consumer. */
	if (tc_strcmp (pShare->share_name, "IPC$") == 0)
	{
		/* To denote this, we find the pseudo-job that was waiting on this and finish it. */
		for (r = 0; r < prtsmb_cli_ctx->max_jobs_per_session; r++)
		{
			if (pSession->jobs[r].state == CSSN_JOB_STATE_FAKE)
			{
			    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_connect IPC$: Finish logon by calling rtsmb_cli_session_job_cleanup\n",0);
				rtsmb_cli_session_job_cleanup (pSession, &pSession->jobs[r], RTSMB_CLI_SSN_RV_OK);
			}
		}
	}

	if (pSession->state == CSSN_STATE_RECOVERY_TREE_CONNECTING)
	{
		pSession->state = CSSN_STATE_RECOVERY_TREE_CONNECTED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_USER_STATE (CSSN_STATE_RECOVERY_TREE_CONNECTED);
#endif
	}

    recv_status = RTSMB_CLI_SSN_RV_OK;
}
// ====================================
/*
    response_pkt.StructureSize;
    response_pkt.ShareType;
    response_pkt.Reserved;
    response_pkt.ShareFlags;
    response_pkt.Capabilities;
    response_pkt.MaximalAccess;
*/
    return recv_status;
}
int rtsmb2_cli_session_send_tree_connect_error_handler (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_session_setup_error_handler (smb2_stream  *pStream)
{
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb2_cli_session_send_session_setup_error_handler: called with error == %X\n", (int)pStream->InHdr.Status_ChannelSequenceReserved);
    return RTSMB_CLI_SSN_RV_INVALID_RV;  /* Don't intercept the message */
}

int rtsmb2_cli_session_send_logoff (smb2_stream  *pStream)
{
    RTSMB2_LOGOFF_C command_pkt;
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));
    rtsmb2_cli_session_init_header (pStream, SMB2_LOGOFF, (ddword) pStream->pBuffer->mid,pStream->pSession->psmb2Session->SessionId);
    command_pkt.StructureSize   = 4;
    command_pkt.Reserved        = 0;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_logoff called:\n",0);
    /* Packs the SMB2 header and tree disconnect into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    return send_status;
}
int rtsmb2_cli_session_receive_logoff (smb2_stream  *pStream)
{
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_logoff called for session (%d):\n",(int)pStream->InHdr.SessionId);
 	/* make sure we have a valid user */
	if (pStream->pSession->user.state != CSSN_USER_STATE_LOGGED_ON)
	{
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_logoff: error: (pStream->pSession->user.state != CSSN_USER_STATE_LOGGED_ON) \n",0);
	    return RTSMB_CLI_SSN_RV_BAD_UID;
    }

//	ASSURE (pSession->user.uid == pHeader->uid, RTSMB_CLI_SSN_RV_BAD_UID);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_logoff: calling: rtsmb_cli_session_user_close \n",0);
	rtsmb_cli_session_user_close (&pStream->pSession->user);


    return RTSMB_CLI_SSN_RV_OK;
}

int rtsmb2_cli_session_send_tree_disconnect (smb2_stream  *pStream)
{
    RTSMB2_TREE_DISCONNECT_C command_pkt;
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));


    rtsmb2_cli_session_init_header (pStream, SMB2_TREE_DISCONNECT, (ddword) pStream->pBuffer->mid,pStream->pSession->psmb2Session->SessionId);

    pStream->OutHdr.TreeId = (ddword) pStream->pJob->data.tree_disconnect.tid;
    command_pkt.StructureSize   = 4;
    command_pkt.Reserved        = 0;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_tree_disconnect called:\n",0);
    /* Packs the SMB2 header and tree disconnect into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    return send_status;
}
int rtsmb2_cli_session_receive_tree_disconnect (smb2_stream  *pStream)
{
int recv_status = RTSMB_CLI_SSN_RV_OK;
int rv;
RTSMB2_TREE_DISCONNECT_R response_pkt;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_disconnect: called with error == %X\n", (int)pStream->InHdr.Status_ChannelSequenceReserved);
    if ((rv=RtsmbStreamDecodeResponse(pStream, &response_pkt)) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_disconnect: RtsmbStreamDecodeResponse failed with error == %X\n", rv);
        return RTSMB_CLI_SSN_RV_MALFORMED;
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_disconnect: RtsmbStreamDecodeResponse success on treeId == %d\n", (int) pStream->InHdr.TreeId);
    return RTSMB_CLI_SSN_RV_OK;
}

int rtsmb2_cli_session_send_read (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_read (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}

int rtsmb2_cli_session_send_write (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_write (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_open (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_open (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_close (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_close (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_seek (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_seek (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_truncate (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_truncate (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_flush (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_rename (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_delete (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_mkdir (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_rmdir (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}

/* RTSMB2_QUERY_DIRECTORY_C.FileInformationClass */
#define SMB2_QUERY_FileDirectoryInformation 0x01        /*  Basic information about a file or directory. Basic information is defined as the file's name, time stamp, size and attributes. File attributes are as specified in [MS-FSCC] section 2.6. */
#define SMB2_QUERY_FileFullDirectoryInformation 0x02    /*  Full information about a file or directory. Full information is defined as all the basic information plus extended attribute size. */
#define SMB2_QUERY_FileIdFullDirectoryInformation 0x26  /*  Full information plus volume file ID about a file or directory. A volume file ID is defined as a number assigned by the underlying object store that uniquely identifies a file within a volume. */
#define SMB2_QUERY_FileBothDirectoryInformation 0x03    /*  Basic information plus extended attribute size and short name about a file or directory. */
#define SMB2_QUERY_FileIdBothDirectoryInformation 0x25  /*  FileBothDirectoryInformation plus volume file ID about a file or directory. */
#define SMB2_QUERY_FileNamesInformation 0x0C            /*  Detailed information on the names of files and directories in a directory. */
/* RTSMB2_QUERY_DIRECTORY_C.Flags */
#define SMB2_QUERY_SMB2_RESTART_SCANS          0x01     /*  The server MUST restart the enumeration from the beginning, but the search pattern is not changed. */
#define SMB2_QUERY_SMB2_RETURN_SINGLE_ENTRY    0x02     /*  The server MUST only return the first entry of the search results. */
#define SMB2_QUERY_SMB2_INDEX_SPECIFIED        0x04     /*  The server SHOULD<64> return entries beginning at the byte number specified by FileIndex. */
#define SMB2_QUERY_SMB2_REOPEN                 0x10     /*  The server MUST restart the enumeration from the beginning, and the search pattern MUST be changed to the provided value. This often involves silently closing and reopening the directory on the server side. */

int rtsmb2_cli_session_send_find_first (smb2_stream  *pStream)
{
    RTSMB2_QUERY_DIRECTORY_C command_pkt;
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_find_first: Session == %X \n",(int)pStream->pSession);

    rtsmb2_cli_session_init_header (pStream, SMB2_QUERY_DIRECTORY, (ddword) pStream->pBuffer->mid,pStream->pSession->psmb2Session->SessionId);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_find_first: pStream->pSession->psmb2Session == %X \n",(int)pStream->pSession->psmb2Session);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_find_first: pStream->pJob == %X \n",(int)pStream->pJob);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_find_first: pStream->pJob->data.findfirst.search_struct == %X \n",(int)pStream->pJob->data.findfirst.search_struct);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_find_first: pStream->pJob->data.findfirst.search_struct->share_struct == %X \n",(int)pStream->pJob->data.findfirst.search_struct->share_struct);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_find_first: pStream->pJob->data.findfirst.search_struct->share_struct->tid == %X \n",(int)pStream->pJob->data.findfirst.search_struct->share_struct->tid);

    pStream->OutHdr.TreeId = (ddword) pStream->pJob->data.findfirst.search_struct->share_struct->tid;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_find_first: TreeId == %X \n",(int)pStream->OutHdr.TreeId);

    command_pkt.StructureSize   = 33;

	command_pkt.FileInformationClass    = SMB2_QUERY_FileNamesInformation;
	command_pkt.Flags                   = SMB2_QUERY_SMB2_INDEX_SPECIFIED;
	command_pkt.FileIndex               = 0;
    /* The File Id was filled in by a call to SMB2_Create_Request and then pmaced in the SMB2FileId filed */
	tc_memcpy(command_pkt.FileId, pStream->pJob->data.findfirst.search_struct->SMB2FileId, 16);
    command_pkt.FileNameOffset          = (word) (pStream->OutHdr.StructureSize+command_pkt.StructureSize-1);

    if (pStream->pJob->data.findfirst.pattern)
    {
        pStream->WriteBufferParms[0].pBuffer = pStream->pJob->data.findfirst.pattern;
        pStream->WriteBufferParms[0].byte_count = rtsmb_len (pStream->pJob->data.findfirst.pattern)*sizeof(rtsmb_char);
        command_pkt.FileNameLength   = (word)pStream->WriteBufferParms[0].byte_count;
    }

    /* Tell the server that the maximum we can accept is what remains in our read buffer */
	command_pkt.OutputBufferLength      = (word)pStream->read_buffer_remaining;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_find_first: Call encode \n",0);

    /* Packs the SMB2 header and tree connect command/blob into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_send_find_first: back encode \n",0);
    return send_status;
}

int rtsmb2_cli_session_send_find_first_error_handler (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_find_first (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}

int rtsmb2_cli_session_send_find_next (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_find_next (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_find_close (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_stat (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_stat (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_chmode (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_full_server_enum (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_full_server_enum (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_get_free (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_get_free (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_share_find_first (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_share_find_first (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_server_enum (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_server_enum (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}


#endif /* INCLUDE_RTSMB_CLIENT */
#endif