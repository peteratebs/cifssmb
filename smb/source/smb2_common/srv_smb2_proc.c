//
// SRV_SMB2_SSN.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles most of the actual processing of packets for the RTSMB server.
//

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#include <stdio.h>
#if (INCLUDE_RTSMB_SERVER)
#include "com_smb2.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"

#include "rtpfile.h"
#include "rtprand.h"
#include "rtpwcs.h"
#include "smbdebug.h"
#include "rtpscnv.h"


#include "srvtran2.h"
#include "srvssn.h"
#include "srvrap.h"
#include "srvshare.h"
#include "srvrsrcs.h"
#include "srvfio.h"
#include "srvassrt.h"
#include "srvauth.h"
#include "srvutil.h"
#include "smbnb.h"
#include "srvnbns.h"
#include "srvans.h"
#include "srvcmds.h"
#include "smbutil.h"
#include "smbnbss.h"
#include "srvcfg.h"
#include "smbnet.h"


#include "rtptime.h"
#define HEREHERE
#define CLAIM_SEMAPHORE
#define RELEASE_SEMAPHORE


extern int RtsmbStreamDecodeCommand(smb2_stream *pStream, PFVOID pItem);
extern int RtsmbStreamEncodeResponse(smb2_stream *pStream, PFVOID pItem);
extern int RtsmbWriteSrvError(smb2_stream *pStream, byte errorClass, word errorCode, word ErrorByteCount, byte *ErrorBytes);
extern int RtsmbWriteSrvStatus(smb2_stream *pStream, dword statusCode);
extern pSmb2SrvModel_Global pSmb2SrvGlobal;

static struct smb2_dialect_entry_s *RTSMB_FindBestDialect(int inDialectCount, word inDialects[]);


static BBOOL Proc_smb2_NegotiateProtocol (smb2_stream  *pStream);
static BBOOL Proc_smb2_SessionSetup (smb2_stream  *pStream);
static BBOOL Proc_smb2_LogOff(smb2_stream  *pStream);

static BBOOL Proc_smb2_TreeConnect(smb2_stream  *pStream);
static BBOOL Proc_smb2_TreeDisConnect(smb2_stream  *pStream);

static BBOOL Proc_smb2_Create(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_Close(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_Flush(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_Read(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_Write(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_Lock(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_Ioctl(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_Cancel(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_Echo(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_QueryDirectory(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_ChangeNotify(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_QueryInfo(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_SetInfo(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_OplockBreak(smb2_stream  *pStream){return FALSE;}
static void DebugOutputSMB2Command(int command);

static void Smb1SrvCtxtToStream(smb2_stream * pStream, PSMB_SESSIONCTX pSctx)
{
    tc_memset(pStream, 0, sizeof(*pStream));
    pStream->doSessionClose         =  FALSE;
    pStream->doSocketClose          =  FALSE;
	pStream->Success                =  TRUE;
	pStream->read_origin            = (PFVOID) SMB_INBUF (pSctx);
	pStream->pInBuf                 =  pStream->read_origin;

	pStream->InBodySize             =  pSctx->current_body_size;
	pStream->read_buffer_size       =  pSctx->readBufferSize;                /* read buffer_size is the buffer size minus NBSS header */
	pStream->read_buffer_remaining  = (pStream->read_buffer_size - pStream->InBodySize);

    pStream->write_origin = (PFVOID) SMB_OUTBUF (pSctx);                      /* write_buffer_size is the buffer size minus NBSS header */
    pStream->write_buffer_size = pSctx->writeBufferSize;
	pStream->pOutBuf = pStream->write_origin;
	pStream->write_buffer_remaining = pStream->write_buffer_size;
    pStream->psmb2Session = pSctx->pCtxtsmb2Session;
}

static void RTSmb2_SessionShutDown(struct s_Smb2SrvModel_Session  *pStreamSession)
{
    /* The server MUST remove the session object from GlobalSessionTable and Connection.SessionTable */
    Smb2SrvModel_Global_Remove_SessionFromSessionList(pStreamSession);
    /*  3.3.4.12 ?? */
    /* The server MUST close every Open in Session.OpenTable as specified in section 3.3.4.17. */
    /* The server MUST deregister every TreeConnect in Session.TreeConnectTable by providing
       the tuple <TreeConnect.Share.ServerName, TreeConnect.Share.Name> and TreeConnect.TreeGlobalId as the input parameters
       and invoking the event specified in [MS-SRVS] section 3.1.6.7. */
    /* For each deregistered TreeConnect, TreeConnect.Share.CurrentUses MUST be decreased by 1. */
    /* All the tree connects in Session.TreeConnectTable MUST be removed and freed. */
//    RTSmb2_SessionShutDown(pStreamSession);
    Smb2SrvModel_Free_Session(pStreamSession);
}
static void Smb1SrvCtxtFromStream(PSMB_SESSIONCTX pSctx,smb2_stream * pStream)
{
    pSctx->outBodySize      = pStream->OutBodySize;
    pSctx->pCtxtsmb2Session = pStream->psmb2Session;
    pSctx->doSocketClose    = pStream->doSocketClose;
    if (pStream->doSessionClose && pStream->psmb2Session)
    {
        RTSmb2_SessionShutDown(pStream->psmb2Session);
        pStream->psmb2Session = 0;
        pStream->doSessionClose = FALSE;
    }
}

/**
    Called from SMBS_ProcSMBPacket when it receives an SMB2 packet.

    Dispatches to the appropriate SMB2 handler and returns TRUE if a response must be sent back over the NBSS link.

    Response information is placed in the buffer at pCtx->write_origin, and the length is placed in pCtx->outBodySize.


*/

BBOOL SMBS_ProcSMB2_Body (PSMB_SESSIONCTX pSctx)
{
	int header_size;
	int length;
	BBOOL doSend = FALSE;
	BBOOL doFinalize = FALSE;
    smb2_stream  smb2stream;
    smb2_stream * pStream;

    pStream = &smb2stream;

    /* Initialize memory stream pointers and set pStream->psmb2Session from value saved in the session context structure  */
    Smb1SrvCtxtToStream(&smb2stream, pSctx);
	/* read header and advance the stream pointer */
	if ((header_size = cmd_read_header_raw_smb2 (smb2stream.read_origin, smb2stream.read_origin, smb2stream.InBodySize, &smb2stream.InHdr)) == -1)
	{
		RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMB2_Body: Badly formed header", RTSMB_DEBUG_TYPE_ASCII);
		return FALSE;
	}
	smb2stream.pInBuf               = PADD (smb2stream.read_origin, header_size);

	/**
	 * Set up outgoing header.
	 */
	smb2stream.OutHdr = smb2stream.InHdr;
    tc_memset(smb2stream.OutHdr.Signature,0, sizeof(smb2stream.OutHdr.Signature));
    smb2stream.OutHdr.Flags |= SMB2_FLAGS_SERVER_TO_REDIR;
    smb2stream.OutHdr.StructureSize = 64;

	/* fill it in once, just so we have something reasonable in place */
	cmd_fill_header_smb2 (&smb2stream, &smb2stream.OutHdr);

    /* Reset the stream */
	smb2stream.pOutBuf = smb2stream.write_origin;
	smb2stream.write_buffer_remaining = smb2stream.write_buffer_size;
	smb2stream.OutBodySize = 0;


#if (0)
// HEREHERE -- todo/uid pid stuff
	/**
	 * Set up some helper variables.
	 */
	if (pSctx->accessMode == AUTH_SHARE_MODE)
	{
		pSctx->uid = 0;
	}
	else
	{
		pSctx->uid = outCliHdr.uid;
	}
	pSctx->pid = outCliHdr.pid;
	pSctx->tid = outCliHdr.tid;
// HEREHERE
#endif
	/**
	 * Do a quick check here that the first command we receive is a negotiate.
	 */

	if (!smb2stream.psmb2Session)
    {
	    RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMB2_Body:  No Session structures available !!!!!.\n", RTSMB_DEBUG_TYPE_ASCII);
		RtsmbWriteSrvError(&smb2stream, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR,0,0);
		doSend = TRUE;
    }
	else if (smb2stream.psmb2Session->Connection->NegotiateDialect == 0 && smb2stream.InHdr.Command != SMB2_NEGOTIATE)
	{
		RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMB2_Body:  Bad first packet -- was not a NEGOTIATE.\n", RTSMB_DEBUG_TYPE_ASCII);
		RtsmbWriteSrvError(&smb2stream, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR,0,0);
		doSend = TRUE;
	}
	else
	{
	    DebugOutputSMB2Command(smb2stream.InHdr.Command);
        doFinalize = TRUE;

        if (smb2stream.InHdr.Command != SMB2_NEGOTIATE)
        {
            /* Decide here if we should encrypt  */
            BBOOL EncryptMessage = FALSE;
            if (EncryptMessage)
                smb2_stream_start_encryption(&smb2stream);
        }

		/**
		 * Ok, we now see what kind of command has been requested, and
		 * call an appropriate helper function to fill out details of
		 * pOutSmbHdr.  Most return a BBOOL, indicating whether we should
		 * send a response or not.
		 */
		switch (smb2stream.InHdr.Command)
		{
            case SMB2_NEGOTIATE:
    			doSend = Proc_smb2_NegotiateProtocol (&smb2stream);
    			break;
            case SMB2_SESSION_SETUP  :
    			doSend = Proc_smb2_SessionSetup(&smb2stream);
    			break;
            case SMB2_LOGOFF         :
    			doSend = Proc_smb2_LogOff(&smb2stream);
    			break;
            case SMB2_TREE_CONNECT   :
    			doSend = Proc_smb2_TreeConnect(&smb2stream);
    			break;
            case SMB2_TREE_DISCONNECT:
    			doSend = Proc_smb2_TreeDisConnect(&smb2stream);
    			break;
            case SMB2_CREATE         :
    			doSend = Proc_smb2_Create(&smb2stream);
    			break;
            case SMB2_CLOSE          :
    			doSend = Proc_smb2_Close(&smb2stream);
    			break;
            case SMB2_FLUSH          :
    			doSend = Proc_smb2_Flush(&smb2stream);
    			break;
            case SMB2_READ           :
    			doSend = Proc_smb2_Read(&smb2stream);
    			break;
            case SMB2_WRITE          :
    			doSend = Proc_smb2_Write(&smb2stream);
    			break;
            case SMB2_LOCK           :
    			doSend = Proc_smb2_Lock(&smb2stream);
    			break;
            case SMB2_IOCTL          :
    			doSend = Proc_smb2_Ioctl(&smb2stream);
    			break;
            case SMB2_CANCEL         :
    			doSend = Proc_smb2_Cancel(&smb2stream);
    			break;
            case SMB2_ECHO           :
    			doSend = Proc_smb2_Echo(&smb2stream);
    			break;
            case SMB2_QUERY_DIRECTORY:
    			doSend = Proc_smb2_QueryDirectory(&smb2stream);
    			break;
            case SMB2_CHANGE_NOTIFY  :
    			doSend = Proc_smb2_ChangeNotify(&smb2stream);
    			break;
            case SMB2_QUERY_INFO     :
    			doSend = Proc_smb2_QueryInfo(&smb2stream);
    			break;
            case SMB2_SET_INFO       :
    			doSend = Proc_smb2_SetInfo(&smb2stream);
    			break;
            case SMB2_OPLOCK_BREAK   :
    			doSend = Proc_smb2_OplockBreak(&smb2stream);
    			break;
    		default:
    		    RtsmbWriteSrvError(&smb2stream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
    		    doFinalize = FALSE;
    		    doSend = TRUE;
    		break;
		}
	}
    if (doSend)
    {
	    if (doFinalize)
        {
            if (RtsmbWriteFinalizeSmb2(&smb2stream,smb2stream.InHdr.MessageId)<0)
            {
                RtsmbWriteSrvError(&smb2stream, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR,0,0);
            }
        }
        Smb2SrvModel_Global_Stats_Send_Update(smb2stream.OutBodySize);
    }
    Smb1SrvCtxtFromStream(pSctx, &smb2stream);
	return doSend;
}

/*
Proccess Negotiate protocol requests.  This function figures out what the highest supported dialog on both machines can be used for the remainder of the session.

    3.3.5.4 Receiving an SMB2 NEGOTIATE Request   ................ 258

    pStream->psmb2Session and pStream->psmb2Session->Connection are already partially initialized.

    Process the incoming negotiate command and complete setup commands.

*/

static BBOOL Proc_smb2_NegotiateProtocol (smb2_stream  *pStream)
{
	RTSMB2_NEGOTIATE_C command;
	RTSMB2_NEGOTIATE_R response;
    BBOOL select_3x_only  = FALSE;
    struct smb2_dialect_entry_s *pEntry=0;

    if (pSmb2SrvGlobal->EncryptData && pSmb2SrvGlobal->RejectUnencryptedAccess)
    {
        select_3x_only = TRUE;
    }

    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
        return TRUE;
    /*
        If Connection.NegotiateDialect is 0x0202, 0x0210, 0x0300, or 0x0302 the server MUST disconnect the connection,
        as specified in section 3.3.7.1, and not reply.
    */
    if (pStream->psmb2Session->Connection->NegotiateDialect)
    {
        pStream->doSocketClose = TRUE;
		return FALSE;
    }

    /* The server MUST set Connection.ClientCapabilities to the capabilities received in the SMB2 NEGOTIATE request. */
    pStream->psmb2Session->Connection->ClientCapabilities = command.Capabilities;

    /* If the server implements the SMB 3.x dialect family, the server MUST set Connection.ClientSecurityMode to the SecurityMode field of the SMB2 NEGOTIATE Request. */
    pStream->psmb2Session->Connection->ClientSecurityMode = command.SecurityMode;

    /* If the server implements the SMB2.1 or 3.x dialect family, the server MUST set Connection.ClientGuid to the ClientGuid field of the SMB2 NEGOTIATE Request. */
    tc_memcpy(pStream->psmb2Session->Connection->ClientGuid, command.guid, 16);

    /* If SMB2_NEGOTIATE_SIGNING_REQUIRED is set in SecurityMode, the server MUST set Connection.ShouldSign to TRUE. */
    if (command.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED)
        pStream->psmb2Session->Connection->ShouldSign = TRUE;

    /*  If the DialectCount of the SMB2 NEGOTIATE Request is 0, the server MUST fail the request with STATUS_INVALID_PARAMETER. */
    if (command.DialectCount == 0)
    {
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
		return TRUE;
    }
    pEntry = RTSMB_FindBestDialect(command.DialectCount, command.Dialects);
    /* If a common dialect is not found, the server MUST fail the request with STATUS_NOT_SUPPORTED. */
    if (pEntry == 0)
    {
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_NOT_SUPPORTED);
		return TRUE;
    }
    /*
        If a common dialect is found, the server MUST set Connection.Dialect to "2.002", "2.100", "3.000", or "3.002", and Connection.NegotiateDialect to
        0x0202, 0x0210, 0x0300, or 0x0302 accordingly, to reflect the dialect selected.
    */
    pStream->psmb2Session->Connection->NegotiateDialect = pEntry->dialect;
    pStream->psmb2Session->Connection->Dialect = pEntry->dialect;

    if (select_3x_only && !SMB2IS3XXDIALECT(pEntry->dialect))
    {
        RtsmbWriteSrvError(pStream, SMB_EC_ERRSRV, SMB_ERRSRV_ACCESS,0,0);
		return TRUE;
    }

    /* If the common dialect is SMB 2.1 or 3.x dialect family and the underlying connection is either TCP port 445 or RDMA,
       Connection.SupportsMultiCredit MUST be set to TRUE; otherwise, it MUST be set to FALSE.
    */
    if (pStream->psmb2Session->Connection->Dialect != SMB2_DIALECT_2002)
    {
        if (pStream->psmb2Session->Connection->TransportName & (RTSMB2_TRANSPORT_SMB_OVER_RDMA|RTSMB2_TRANSPORT_SMB_OVER_TCP) )
            pStream->psmb2Session->Connection->SupportsMultiCredit = TRUE;
    }
    MEMCLEAROBJ(response);
    response.StructureSize      = 65;
    /* SecurityMode MUST have the SMB2_NEGOTIATE_SIGNING_ENABLED bit set. */
    response.SecurityMode       = SMB2_NEGOTIATE_SIGNING_ENABLED;
    /* If RequireMessageSigning is TRUE, the server MUST also set SMB2_NEGOTIATE_SIGNING_REQUIRED in the SecurityMode field. */
    if (pSmb2SrvGlobal->RequireMessageSigning)
    {
        response.SecurityMode   |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
        pStream->psmb2Session->SigningRequired = TRUE;
    }
    /* DialectRevision MUST be set to the common dialect. */
    response.DialectRevision    = pStream->psmb2Session->Connection->Dialect;
    response.Reserved = 0;
    /* ServerGuid is set to the global ServerGuid value. */
    tc_memcpy(response.ServerGuid,pSmb2SrvGlobal->ServerGuid,16);
    /* The Capabilities field MUST be set to a combination of zero or more of the following bit values, as specified in section 2.2.4 */
    response.Capabilities       = Smb2_util_get_global_caps(pStream->psmb2Session->Connection, &command);

    /* MaxTransactSize is set to the maximum buffer size<221>,in bytes, that the server will accept on this connection for QUERY_INFO,
       QUERY_DIRECTORY, SET_INFO and CHANGE_NOTIFY operations. */
    response.MaxTransactSize    =  pStream->psmb2Session->Connection->MaxTransactSize;
    /* MaxReadSize is set to the maximum size,<222> in bytes, of the Length in an SMB2 READ Request */
    response.MaxReadSize        =  pStream->psmb2Session->Connection->MaxReadSize;
    /* MaxWriteSize is set to the maximum size,<223> in bytes, of the Length in an SMB2 WRITE Request */
    response.MaxWriteSize       =  pStream->psmb2Session->Connection->MaxWriteSize;
    /* SystemTime is set to the current time */
    response.SystemTime         =  rtsmb_util_get_current_filetime();
    /* ServerStartTime is set to the global ServerStartTime value */
    response.ServerStartTime    =  pSmb2SrvGlobal->ServerStartTime;

    /* SecurityBufferOffset is set to the offset to the Buffer field in the response, in bytes, from the beginning of the SMB2 header.
        SecurityBufferLength is set to the length of the data being returned in the Buffer field. */
    response.SecurityBufferLength = 0;
    pStream->WriteBufferParms[0].pBuffer = RTSmb2_Encryption_Get_Spnego_Default(&pStream->WriteBufferParms[0].byte_count);
    response.SecurityBufferLength = (word) pStream->WriteBufferParms[0].byte_count;
    if (response.SecurityBufferLength)
    {
        response.SecurityBufferOffset = (word) (pStream->OutHdr.StructureSize + response.StructureSize-1);
    }
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    if (response.SecurityBufferLength)
        RTSmb2_Encryption_Release_Spnego_Default(pStream->WriteBufferParms[0].pBuffer);
    return TRUE;
} // End ProcNegotiateProtocol


/*
Proccess SESSION_SETUP requests.


3.3.5.5 Receiving an SMB2 SESSION_SETUP Request .................... 260


*/

static BBOOL Proc_smb2_SessionSetup (smb2_stream  *pStream)
{
	int i;
	RTSMB2_SESSION_SETUP_C command;
	RTSMB2_SESSION_SETUP_R response;
	BBOOL  Connection3XXDIALECT = (BBOOL)SMB2IS3XXDIALECT(pStream->psmb2Session->Connection->NegotiateDialect);
    BBOOL  freesession=FALSE;
    BBOOL  reject=FALSE;
    BBOOL  finish=FALSE;
    BBOOL  send_next_token=FALSE;
    BBOOL  more_processing_required = FALSE;
    dword  reject_status=SMB2_STATUS_ACCESS_DENIED;
    struct s_Smb2SrvModel_Session  *pStreamSession;

    pSmb2SrvModel_Channel pChannel = 0;

    ////// pStream->EncryptMessage = TRUE;

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    response.StructureSize          = 9;

    /* Get a temporary buffer for holding the incoming security token, released upon exit */
    pStream->ReadBufferParms[0].pBuffer = RTSmb2_Encryption_Get_Spnego_InBuffer(&pStream->ReadBufferParms[0].byte_count);

    /* Read into command, if a security token is passed it will be placed in command_args.pBuffer which came from RTSmb2_Encryption_Get_Spnego_InBuffer */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
        return TRUE;

    pStreamSession = pStream->psmb2Session;
    if (pSmb2SrvGlobal->EncryptData && pSmb2SrvGlobal->RejectUnencryptedAccess)
    {
        /* 1. If the server implements the SMB 3.x dialect family, Connection.Dialect does not belong to the SMB 3.x dialect
           family, EncryptData is TRUE, and RejectUnencryptedAccess is TRUE, the server MUST fail the request with STATUS_ACCESS_DENIED.  */
        if (!Connection3XXDIALECT)
            reject=TRUE;
        else
        {
            /* 2. If Connection.Dialect belongs to the SMB 3.x dialect family, EncryptData is TRUE, RejectUnencryptedAccess is TRUE, and Connection.ClientCapabilities
               does not include the SMB2_GLOBAL_CAP_ENCRYPTION bit, the server MUST fail the request with STATUS_ACCESS_DENIED. */
            if ((pStreamSession->Connection->ClientCapabilities & SMB2_GLOBAL_CAP_ENCRYPTION)==0)
                reject=TRUE;
        }
    }
    finish=reject;
    /* Pg 260 3. If SessionId in the SMB2 header of the request is zero, the server MUST process the authentication request as specified in section 3.3.5.5.1. */
    if (!finish && pStream->InHdr.SessionId==0)
    {
        /* Section 3.3.5.5.1 .. pg 262 */
        /* Use the session that was assigned to the stream by SMBS_InitSessionCtx_smb2() */
	    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_SessionSetup binding session:  pStreamSession == %X pStreamSession == %d\n",(int)pStreamSession, (int) pStreamSession->SessionId);

        /* A session object MUST be allocated for this request. The session MUST be inserted into the GlobalSessionTable and a unique Session.SessionId is assigned to serve as a lookup key
           in the table. The session MUST be inserted into Connection.SessionTable. The server MUST register the session by invoking the event specified in [MS-SRVS] section 3.1.6.2 and
           assign the return value to Session.SessionGlobalId. ServerStatistics.sts0_sopens MUST be increased by 1. The SMB2 server MUST reserve -1 as an invalid SessionId and 0 as a S
           essionId for which no session exists. The other values MUST be initialized as follows:
        */
        Smb2SrvModel_Global_Stats_Open_Update(1);
        /* Session.Connection is set to the connection on which the request was received. (already done) */
        /* Session.State is set to InProgress */
        pStreamSession->State = Smb2SrvModel_Session_State_InProgress;
        /*  Already Done by New.
            Session.SecurityContext is set to NULL.
            Session.SessionKey is set to NULL, indicating that it is uninitialized.
            Session.SigningRequired is set to FALSE.
            Session.OpenTable is set to an empty table.
            Session.TreeConnectTable is set to an empty table.
            Session.IsAnonymous is set to FALSE.
        */

        /*  Session.CreationTime is set to the current time. */
        pStreamSession->CreationTime = rtsmb_util_get_current_filetime();
        /*    Session.IdleTime is set to the current time. */
        pStreamSession->IdleTime = rtp_get_system_msec();
        /*  If Connection.Dialect belongs to the SMB 3.x dialect family, Session.EncryptData is set to global EncryptData. */
        if (Connection3XXDIALECT)
        {
           pStream->EncryptMessage = pStreamSession->EncryptData = pSmb2SrvGlobal->EncryptData;
            /* If Connection.Dialect belongs to the SMB 3.x dialect family, Session.ChannelList MUST be set to an empty list. */
        }
        /* Using this session, authentication is continued as specified in section 3.3.5.5.3 */
        pStreamSession->SessionGlobalId = RTSmb2_Encryption_Get_Spnego_New_SessionGlobalId();

        if (!Smb2SrvModel_Global_Set_SessionInSessionList(pStreamSession))
        {
            reject_status = SMB2_STATUS_INSUFFICIENT_RESOURCES;
            finish=reject=TRUE;
        }
        else
        {
            finish=send_next_token=TRUE;
        }

    }

    /* 4. If Connection.Dialect belongs to the SMB 3.x dialect family, IsMultiChannelCapable is TRUE, and the SMB2_SESSION_FLAG_BINDING bit is set in the
          Flags field of the request, the server MUST perform the following:
    */
    if (finish==FALSE&&pStream->InHdr.SessionId!=0&&Connection3XXDIALECT && pSmb2SrvGlobal->IsMultiChannelCapable && (command.Flags & SMB2_SESSION_FLAG_BINDING)!=0)
    {
        /* The server MUST look up the session in GlobalSessionTable using the SessionId from the SMB2 header. If the session is not found, the server MUST
           fail the session setup request with STATUS_USER_SESSION_DELETED. */
        struct s_Smb2SrvModel_Session  *pCurrSession;   // For a server. points to the session

        pCurrSession = Smb2SrvModel_Global_Get_SessionById(pStream->InHdr.SessionId);
        if (!pCurrSession)
        {
            reject_status = SMB2_STATUS_USER_SESSION_DELETED;
            finish=reject=TRUE;
        }
        else
        {
            /* If a session is found, the server MUST do the following */
            /* If Connection.Dialect is not the same as Session.Connection.Dialect, the server MUST fail the request with STATUS_INVALID_PARAMETER. */
            if (pStreamSession->Connection->NegotiateDialect != pCurrSession->Connection->NegotiateDialect)
            {
                reject_status = SMB2_STATUS_INVALID_PARAMETER;
                finish=reject=TRUE;
            }
           /* If the SMB2_FLAGS_SIGNED bit is not set in the Flags field in the header, the server MUST fail the request with error STATUS_INVALID_PARAMETER. */
            if (finish==FALSE && (pStream->InHdr.Flags & SMB2_FLAGS_SIGNED)== 0)
            {
                reject_status = SMB2_STATUS_INVALID_PARAMETER;
                finish=reject=TRUE;
            }
           /* If Session.State is InProgress, the server MUST fail the request with STATUS_REQUEST_NOT_ACCEPTED. */
            if (finish==FALSE && (pCurrSession->State == Smb2SrvModel_Session_State_InProgress))
            {
                reject_status = SMB2_STATUS_REQUEST_NOT_ACCEPTED;
                finish=reject=TRUE;
            }
           /* If Session.State is Expired, the server MUST fail the request with STATUS_NETWORK_SESSION_EXPIRED. */
            if (finish==FALSE && (pCurrSession->State == Smb2SrvModel_Session_State_Expired))
            {
                reject_status = SMB2_STATUS_NETWORK_SESSION_EXPIRED;
                finish=reject=TRUE;
            }
           /* If Session.IsAnonymous or Session.IsGuest is TRUE, the server MUST fail the request with STATUS_NOT_SUPPORTED. */
            if (finish==FALSE && (pCurrSession->IsAnonymous||pCurrSession->IsGuest))
            {
                reject_status = SMB2_STATUS_NOT_SUPPORTED;
                finish=reject=TRUE;
            }

           /* If there is a session in Connection.SessionTable identified by the SessionId in the request, the server MUST fail
              the request with STATUS_REQUEST_NOT_ACCEPTED. */
            if (finish==FALSE)
            {
                if (Smb2SrvModel_Global_Get_SessionByConnectionAndId(pStreamSession->Connection,pStream->InHdr.SessionId))
                {
                    reject_status = SMB2_STATUS_REQUEST_NOT_ACCEPTED;
                    finish=reject=TRUE;
                }
            }

           /* The server MUST verify the signature as specified in section 3.3.5.2.4, using the Session.SessionKey.*/
            if (finish==FALSE)
            {
                if (!RTSmb2_Encryption_SignatureVerify(pCurrSession->SessionGlobalId, pCurrSession->SecurityContext, pCurrSession->SessionKey,pStream->InHdr.Signature))
                {
                    reject_status = SMB2_STATUS_ACCESS_DENIED;
                    finish=reject=TRUE;
                }
            }
           /* The server MUST obtain the security context from the GSS authentication subsystem, and it MUST invoke the GSS_Inquire_context call as specified in [RFC2743]
              section 2.2.6, passing the security context as the input parameter. If the returned "src_name" does not match with the Session.Username, the server MUST fail
              the request with error code STATUS_NOT_SUPPORTED. */
            if (finish==FALSE)
            {
                pCurrSession->SecurityContext = RTSmb2_Encryption_GetSecurityContext(pCurrSession->SessionGlobalId);
                if (RTSmb2_Encryption_ValidateNameWithSecurityContext(pCurrSession->SessionGlobalId, pCurrSession->SecurityContext, pCurrSession->UserName)==FALSE)
                {
                    reject_status = SMB2_STATUS_NOT_SUPPORTED;
                    finish=reject=TRUE;
                }
            }
            /*If a session is found, proceed with the following steps. */
            if (finish==FALSE)
            {
                /* Free the session we came in with and use the one we just found */
                if (pStreamSession != pCurrSession)
                {
                    RTSmb2_SessionShutDown(pStreamSession);
                    pStream->psmb2Session = pCurrSession;
                    pStreamSession = pCurrSession;
                }
                /* If Session.State is Expired, the server MUST process the session setup request as specified in section 3.3.5.5.2. */
                /*  If Session.State is Valid, the server SHOULD<225> process the session setup request as specified in section 3.3.5.5.2. */
                if (pCurrSession->State == Smb2SrvModel_Session_State_Expired || pCurrSession->State == Smb2SrvModel_Session_State_Valid)
                {
                    /* 3.3.5.5.2 Reauthenticating an Existing Session
                    Session.State MUST be set to InProgress, and Session.SecurityContext set to NULL. Authentication is continued as specified in section 3.3.5.5.3.
                    Note that the existing Session.SessionKey will be retained.
                    */
                    /* 7. The server MUST continue processing the request as specified in section 3.3.5.5.3. */
                    pCurrSession->State = Smb2SrvModel_Session_State_InProgress;
                    finish=send_next_token=TRUE;
                }
            }
        }
    }
    if (send_next_token==TRUE)
    {
        dword status = 0;
        int Spnego_isLast_token = 1;
        finish=FALSE; /* We may have set finished up above, so clear it now */
        /* Pg 262 - 3.3.5.5.3 Handling GSS-API Authentication */
        /* The server SHOULD use the configured authentication protocol to obtain the next GSS output token for the authentication exchange.<226> */
        pStream->WriteBufferParms[0].pBuffer = RTSmb2_Encryption_Get_Spnego_Next_token(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext, &pStream->WriteBufferParms[0].byte_count, &Spnego_isLast_token, &status, pStream->ReadBufferParms[0].pBuffer, command.SecurityBufferLength);
        if (!pStream->WriteBufferParms[0].pBuffer)
        {
           /* If the authentication protocol indicates an error, the server MUST fail the session setup request with the error received by placing the 32-bit NTSTATUS code received into the
              Status field of the SMB2 header. */


           /* and deregister the session by invoking the event
              specified in [MS-SRVS] section 3.1.6.3, providing Session.SessionGlobalId as an input parameter.*/
            RTSmb2_Encryption_Spnego_Clear_SessionGlobalId(pStreamSession->SessionGlobalId);

           /* ServerStatistics.sts0_sopens MUST be decreased by 1. */
           Smb2SrvModel_Global_Stats_Open_Update(-1);

           /* set pStream->doSessionClose to instruct Smb1SrvCtxtFromStream to Unlink the session from all lists,
              free connections associated with the session and free the session */
           pStream->doSessionClose = TRUE;

            /* ServerStatistics.sts0_pwerrors MUST be increased by 1. */
            Smb2SrvModel_Global_Stats_Error_Update();

            /* The session object MUST also be freed, and the error response MUST be sent to the client. */
            reject_status = status;
            finish=reject=TRUE;

        }
        else
        {
            if (!Spnego_isLast_token)
                more_processing_required = TRUE;
            /*
                The output token received from the GSS mechanism MUST be returned in the response. SecurityBufferLength indicates the length of the output token,
                and SecurityBufferOffset indicates its offset, in bytes, from the beginning of the SMB2 header.
            */
            if (pStream->WriteBufferParms[0].byte_count)
            {
                response.SecurityBufferOffset = (word)(pStream->OutHdr.StructureSize + response.StructureSize-1);
                response.SecurityBufferLength = (word)(pStream->WriteBufferParms[0].byte_count);
            }
            /* Session.SessionId MUST be placed in the SessionId field of the SMB2 header.
                pStreamSession->SessionId was established when SMBS_InitSessionCtx_smb2 was called
            */
            pStream->OutHdr.SessionId = pStreamSession->SessionId;
            /* Return the security tokens to the client and wait for another response packet */
            finish=TRUE;

            /* But first - If the GSS mechanism indicates that this is the final message in the authentication exchange, the server MUST verify the dialect as follows: */
            if (more_processing_required == FALSE)
            {
                pSmb2SrvModel_Connection Connection=pStreamSession->Connection;
                /* The server MUST look up all existing connections from the client in the global ConnectionList
                   where Connection.ClientGuid matches Session.Connection.ClientGuid. */
                CLAIM_SEMAPHORE    // TBD
                for (i=0; i < RTSMB2_CFG_MAX_CONNECTIONS; i++)
                {
                    pSmb2SrvModel_Connection p=pSmb2SrvGlobal->ConnectionList[i];
                    if (p && tc_memcmp(p->ClientGuid, Connection->ClientGuid, 16)==0)
                    {
                        if (p->NegotiateDialect != Connection->NegotiateDialect)
                        {
                        /* For any matching Connection, if Connection.Dialect is not the same as Session.Connection.Dialect,
                            the server SHOULD<227> close the newly created Session, as specified in section 3.3.4.12,
                            by providing Session.SessionGlobalId as the input parameter, and fail the session setup
                            request with STATUS_USER_SESSION_DELETED. */
                            reject_status = SMB2_STATUS_USER_SESSION_DELETED;
                            finish=reject=TRUE;
                            break;
                        }
                    }
                }
                RELEASE_SEMAPHORE
                /* If Connection.Dialect belongs to the SMB 3.x dialect family */
                if (Connection3XXDIALECT)
                {
                    /* the server MUST insert the Session into Connection.SessionTable. */
                    if (!Smb2SrvModel_Connection_Set_SessionInSessionList(Connection, pStreamSession))
                    {
                        reject_status = SMB2_STATUS_INSUFFICIENT_RESOURCES;
                        finish=reject=TRUE;
                    }

                    if (finish==FALSE)
                    {
                        /* If Session.ChannelList does not have a channel entry for which Channel.Connection matches the connection on which this request is received,
                           the server MUST allocate a new Channel object with the following values and insert it into
                           Session.ChannelList:
                            Channel.SigningKey is set to NULL.
                            Channel.Connection is set to the connection on which this request is received.
                        */
                        pChannel = Smb2SrvModel_Session_Get_ChannelInChannelList(pStreamSession, Connection);

                        if (pChannel==0)
                        {
                            pChannel = Smb2SrvModel_New_Channel(Connection);
                            if (!pChannel || !Smb2SrvModel_Session_Set_ChannelInChannelList(pStreamSession, pChannel))
                            {
                                reject_status = SMB2_STATUS_INSUFFICIENT_RESOURCES;
                                finish=reject=TRUE;
                            }
                        }
                    }
                }
                /* 2. If Connection.ClientCapabilities is 0, the server MUST set Connection.ClientCapabilities to the capabilities received in the
                   SMB2 SESSION_SETUP Request. */
                if (Connection->ClientCapabilities == 0)
                {
                    Connection->ClientCapabilities = command.Capabilities;
                }
                /* 3. If Session.SecurityContext is NULL, it MUST be set to a value representing the user which successfully authenticated this connection.
                   The security context MUST be obtained from the GSS authentication subsystem.
                */
                if (!pStreamSession->SecurityContext)
                {
                    pStreamSession->SecurityContext = RTSmb2_Encryption_GetSecurityContext(pStreamSession->SessionGlobalId);
                }
                else
                {
                    /*  If it is not NULL, no changes are necessary. The server MUST invoke the GSS_Inquire_context call as specified in [RFC2743] section 2.2.6,
                        passing the Session.SecurityContext as the input parameter, and set Session.UserName to the returned "src_name".   */
                    RTSmb2_Encryption_SetNameFromSecurityContext(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->UserName);
                }
                /* 4. The server MUST invoke the GSS_Inquire_context call as specified in [RFC2743] section 2.2.6, passing the Session.SecurityContext as the
                      context_handle parameter. */
                if (RTSmb2_Encryption_InquireContextAnon(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext))
                {
                    /* If the returned anon_state is TRUE, the server MUST set Session.IsAnonymous to TRUE and the server MAY set the
                       SMB2_SESSION_FLAG_IS_NULL flag in the SessionFlags field of the SMB2 SESSION_SETUP Response.*/
                    pStreamSession->IsAnonymous = TRUE;
                    response.SessionFlags |= SMB2_SESSION_FLAG_IS_NULL;
                }
                else if (RTSmb2_Encryption_InquireContextGuest(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext))
                {
                  /* Otherwise, if the returned src_name corresponds to an implementation-specific guest user,<228> the server MUST set the SMB2_SESSION_FLAG_
                     IS_GUEST in the SessionFlags field of the SMB2 SESSION_SETUP Response and MUST set Session.IsGuest to TRUE. */
                     response.SessionFlags |= SMB2_SESSION_FLAG_IS_GUEST;
                     pStreamSession->IsGuest = TRUE;
                }
                /* 5. Session.SigningRequired MUST be set to TRUE under the following conditions:
                     If the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is set in the SecurityMode field of the client request.
                     If the SMB2_SESSION_FLAG_IS_GUEST bit is not set in the SessionFlags field and Session.IsAnonymous
                     is FALSE and either Connection.ShouldSign or global RequireMessageSigning is TRUE. */
                if (
                       (command.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED)!=0 &&
                       (response.SessionFlags&SMB2_SESSION_FLAG_IS_GUEST)==0 &&
                       !pStreamSession->IsAnonymous &&
                       (Connection->ShouldSign||pSmb2SrvGlobal->RequireMessageSigning)
                   )
                       pStreamSession->SigningRequired = TRUE;
                /* 6. The server MUST query the session key for this authentication from the underlying authentication protocol and store
                      the session key in Session.SessionKey, if Session.SessionKey is NULL. Session.SessionKey MUST be set as specified in
                      section 3.3.1.8, using the value queried from the GSS protocol.
                      For how this value is calculated for Kerberos authentication via GSS-API, see [MS-KILE] section 3.1.1.2.
                      When NTLM authentication via GSS-API is used, Session.SessionKey MUST be set to ExportedSessionKey,
                      see [MS-NLMP] section 3.1.5.1. The server SHOULD choose an authentication mechanism that provides unique and
                      randomly generated session keys in order to secure the integrity of the signing key, encryption key, and decryption key,
                      which are derived using the session key. */
                if (pStreamSession->SessionKey == 0)
                {
                    RTSmb2_Encryption_SetSessionKey(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->SessionKey);
                }
                /*  7. If Connection.Dialect belongs to the SMB 3.x dialect family,
                       the server MUST generate Session.SigningKey as specified in section 3.1.4.2 by providing the following inputs:
                       Session.SessionKey as the key derivation key.
                       The case-sensitive ASCII string "SMB2AESCMAC" as the label.
                       The label buffer size in bytes, including the terminating null character. The size of "SMB2AESCMAC" is 12.
                       The case-sensitive ASCII string "SmbSign" as context for the algorithm.
                       The context buffer size in bytes, including the terminating null character. The size of "SmbSign" is 8.
                */
                if (Connection3XXDIALECT)
                {
                    RTSmb2_Encryption_Get_Session_SigningKeyFromSessionKey(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->SigningKey,pStreamSession->SessionKey);
                }
                /* 8. If Connection.Dialect belongs to the SMB 3.x dialect family, Session.ApplicationKey MUST be generated as specified in section 3.1.4.2 and passing the
                    following inputs:
                        Session.SessionKey as the key derivation key.
                        The case-sensitive ASCII string "SMB2APP" as the label.
                        The label buffer size in bytes, including the terminating null character. The size of "SMB2APP" is 8.
                        The case-sensitive ASCII string "SmbRpc" as context for the algorithm.
                            The context buffer size in bytes, including the terminating null character. The size of "SmbRpc" is 7.
                */
                if (Connection3XXDIALECT)
                    RTSmb2_Encryption_Get_Session_ApplicationKeyFromSessionKey(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->ApplicationKey,pStreamSession->SessionKey);

                /*
                    9. If Connection.Dialect belongs to the SMB 3.x dialect family, the server MUST generate Channel.SigningKey by providing the following input values:
                        If SMB2_SESSION_FLAG_BINDING is not set in the Flags field of the request,
                            Session.SessionKey as the key derivation key;
                        otherwise,
                            the session key returned by the authentication protocol (in step 6) as the key derivation key.
                        The case-sensitive ASCII string "SMB2AESCMAC" as the label.
                        The label buffer size in bytes, including the terminating null character. The size of "SMB2AESCMAC" is 12.
                        The case-sensitive ASCII string "SmbSign" as context for the algorithm.
                        The context buffer size in bytes, including the terminating null character. The size of "SmbSign" is 8.
                */
                if (Connection3XXDIALECT)
                {
                    byte RTSMB_FAR *pKey;
                    if ((command.Flags & SMB2_SESSION_FLAG_BINDING)==0)
                        pKey = pStreamSession->SessionKey;
                    else
                        pKey = pStreamSession->SessionKey;  // TBD - Not sure about this

                    RTSmb2_Encryption_Get_Session_ChannelKeyFromSessionKey(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->SigningKey,pKey);
                }
                /* 10.If Connection.Dialect belongs to the SMB 3.x dialect family, global EncryptData is TRUE, and Connection.ClientCapabilities includes
                   the SMB2_GLOBAL_CAP_ENCRYPTION bit, the server MUST do the following:
                   Set the SMB2_SESSION_FLAG_ENCRYPT_DATA flag in the SessionFlags field of the SMB2 SESSION_SETUP Response.
                   Set Session.SigningRequired to FALSE.
                   Generate Session.EncryptionKey and Session.DecryptionKey as specified in section 3.1.4.2 by providing the following inputs:
                      Session.SessionKey as the key derivation key.
                      The case-sensitive ASCII string "SMB2AESCCM" as the label.
                      The label buffer length in bytes, including the terminating null character. The size of "SMB2AESCCM" is 11.
                      The case-sensitive ASCII string as key derivation context. For generating the encryption key, this MUST be "ServerOut".
                      For generating the decryption key, this MUST be "ServerIn "; note the blank space at the end.
                      The context buffer size in bytes, including the terminating null character. For generating both the encryption key and decryption key,
                      the string size is 10.
                */
                if (Connection3XXDIALECT && pSmb2SrvGlobal->EncryptData && (Connection->ClientCapabilities&SMB2_GLOBAL_CAP_ENCRYPTION)!=0)
                {
                    response.SessionFlags |= SMB2_SESSION_FLAG_ENCRYPT_DATA;
                    pStreamSession->SigningRequired = FALSE;
                    RTSmb2_Encryption_Get_Session_EncryptionKeyFromSessionKey( pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->EncryptionKey, pStreamSession->SessionKey);
                    RTSmb2_Encryption_Get_Session_DecryptionKeyFromSessionKey( pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->DecryptionKey, pStreamSession->SessionKey);
                }
                /*
                    11.If Session.SigningRequired is TRUE, the server MUST sign the final session setup response before sending it to the client.
                    Otherwise, if Connection.Dialect belongs to the SMB 3.x dialect family, and if the SMB2_SESSION_FLAG_BINDING is set in the Flags
                    field of the request, the server MUST sign the response using Channel.SigningKey.
                */
                if (!more_processing_required && pStreamSession->SigningRequired)
                {
                    pStream->SigningKey = pStreamSession->SigningKey;
                    if (Connection3XXDIALECT)
                        pStream->SigningRule = SIGN_AES_CMAC_128;
                    else
                        pStream->SigningRule = SIGN_HMAC_SHA256;
                }
                else if (!more_processing_required && Connection3XXDIALECT  && (command.Flags & SMB2_SESSION_FLAG_BINDING)!=0)
                {
                    RTSMB_ASSERT(pChannel)
                    pStream->SigningKey = pChannel->SigningKey;
                    pStream->SigningRule = SIGN_AES_CMAC_128;
                }

                /*
                    12.If the PreviousSessionId field of the request is not equal to zero, the server MUST take the following actions:
                        1. The server MUST look up the old session in GlobalSessionTable, where Session.SessionId matches PreviousSessionId. If no session is found,
                           no other processing is necessary.
                        2. If a session is found with Session.SessionId equal to PreviousSessionId, the server MUST determine if the old session and the newly established
                           session are created by the same user by comparing the user identifiers obtained from the Session.SecurityContext on the new and old session.
                            1. If the PreviousSessionId and SessionId values in the SMB2 header of the request are equal, the server SHOULD<229> ignore PreviousSessionId
                               and no other processing is required.
                            2. Otherwise, if the server determines the authentications were for the same user, the server MUST remove the old session from the GlobalSessionTable
                               and also from the Connection.SessionTable, as specified in section 3.3.7.1.
                            3. Otherwise, if the server determines that the authentications were for different users, the server MUST ignore the PreviousSessionId value.

                */
                HEREHERE
                /* 13.Session.State MUST be set to Valid */
                pStreamSession->State = Smb2SrvModel_Session_State_Valid;

                /* 14.Session.ExpirationTime MUST be set to the expiration time returned by the GSS authentication subsystem. If the GSS authentication subsystem does not
                   return an expiration time, the Session.ExpirationTime should be set to infinity.
                */
                HEREHERE

                /*
                    The GSS-API can indicate that this is not the final message in authentication exchange using the GSS_S_CONTINUE_NEEDED semantics as specified in
                    [MS-SPNG] section 3.3.1. If the GSS mechanism indicates that this is not the final message of the authentication exchange, the following additional
                    step MUST be taken:
                        The status code in the SMB2 header of the response MUST be set to STATUS_MORE_PROCESSING_REQUIRED.
                        If Connection.Dialect belongs to the SMB 3.x dialect family, and if the SMB2_SESSION_FLAG_BINDING is set in the Flags field of the request,
                        the server MUST sign the response by using Session.SessionKey
                */
                if (more_processing_required)
                {
                    pStream->OutHdr.Status_ChannelSequenceReserved = SMB2_STATUS_MORE_PROCESSING_REQUIRED;
                    if (Connection3XXDIALECT)
                    {
                        RTSmb2_Encryption_SignMessage(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->SessionKey,pStream->InHdr.Signature);
                    }
                }

            }
        }
    }
    if (pStream->WriteBufferParms[0].pBuffer)
        RTSmb2_Encryption_Release_Spnego_Next_token(pStream->WriteBufferParms[0].pBuffer);
    if (pStream->ReadBufferParms[0].pBuffer)
        RTSmb2_Encryption_Release_Spnego_InBuffer(pStream->ReadBufferParms[0].pBuffer);
    if (reject)
    {
		RtsmbWriteSrvStatus (pStream, reject_status);
        pStream->doSessionClose = TRUE;
    }
    else
    {
        pStream->OutHdr.SessionId       = pStreamSession->SessionId;
        /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
        RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    }
    return TRUE;
} // End Proc_smb2_SessionSetup


/* --------------------------------------------------- /
 * Proc_smb2_LogOff Command			           /
 *	                                                   /
 *                                                     /
 * smb2_stream  *pStream                               /
 *  Has inbuffer and outbuffer stream pointers         /
 *  Has links to SMB2 session and SMB1 session info    /
 *  PSMB_HEADER InHdr - the incoming smb header        /
 *  PSMB_HEADER OutHdr - the outgoing smb header       /
 *													   /
 * This command logs the user off, and frees resource   /
 *                                                     /
 * Returns: TRUE if there is data to write.            /
 *          FALSE otherwise.                           /
 *          If a communication error occurs the command/
 *          The may instruct the session to shut down  /
 *          and/or the socket to be closed.            /
 * -------------------------------------------------- */
static BBOOL Proc_smb2_LogOff(smb2_stream  *pStream)
{
	RTSMB2_LOGOFF_C command;
	RTSMB2_LOGOFF_R response;
	dword error_status = 0;
	pSmb2SrvModel_Session pSmb2Session;
    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    rtp_printf("In logoff handler \n");
    /* Read into command */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
    {
   		RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
        return TRUE;
    }

    RTSmb2_SessionShutDown(pStream->psmb2Session);



    response.StructureSize          = 4;
    response.Reserved               = 0;
    pStream->OutHdr.SessionId       = pStream->psmb2Session->SessionId;
    /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);

    pStream->psmb2Session = 0;

    return TRUE;

}

/* --------------------------------------------------- /
 * Proc_smb2_TreeConnect Command			           /
 *	                                                   /
 *                                                     /
 * smb2_stream  *pStream                               /
 *  Has inbuffer and outbuffer stream pointers         /
 *  Has links to SMB2 session and SMB1 session info    /
 *  PSMB_HEADER InHdr - the incoming smb header        /
 *  PSMB_HEADER OutHdr - the outgoing smb header       /
 *													   /
 * This command connects the client to a given share.  /
 * The spec says that every Session Setup command      /
 * must be followed by a tree connect, but that rule   /
 * is sometimes broken.                                /
 *
 * Formats the output buffer with either a positive or /
 * response message.                                   /
 *                                                     /
 * Returns: TRUE if there is data to write.            /
 *          FALSE otherwise.                           /
 *          If a communication error occurs the command/
 *          The may instruct the session to shut down  /
 *          and/or the socket to be closed.            /
 * -------------------------------------------------- */

static byte MapRTSMB_To_Smb2_ShareType(enum RTSMB_SHARE_TYPE inType)
{
byte b=0;
 switch (inType){
 case RTSMB_SHARE_TYPE_DISK:
     b = 1;
     break;
 case RTSMB_SHARE_TYPE_PRINTER:
     b = 3;
     break;
 case RTSMB_SHARE_TYPE_DEVICE:
 case RTSMB_SHARE_TYPE_IPC:
     b = 2;
     break;
 }
 return b;
};

static BBOOL Proc_smb2_TreeConnect(smb2_stream  *pStream)
{
	RTSMB2_TREE_CONNECT_C command;
	RTSMB2_TREE_CONNECT_R response;
	rtsmb_char share_name [RTSMB_NB_NAME_SIZE + RTSMB_MAX_SHARENAME_SIZE + 4]; /* 3 for '\\'s and 1 for null */
	dword error_status = 0;
	pSmb2SrvModel_Session pSmb2Session;
    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    rtp_printf("In tree connect handler \n");

     /* Set up a temporary buffer to hold incoming share name */
    pStream->ReadBufferParms[0].pBuffer = share_name;
    pStream->ReadBufferParms[0].byte_count = sizeof(share_name);
    /* Read into command, share name will be placed in command_args.pBuffer which came from RTSmb2_Encryption_Get_Spnego_InBuffer */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
    {
   		RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
        return TRUE;
    }

    rtp_printf("Trying to find session from session id in header %d\n", (int) pStream->InHdr.SessionId);
    pSmb2Session = Smb2SrvModel_Global_Get_SessionById(pStream->InHdr.SessionId);



    rtp_printf("Got v == %X by stream pointer == %X\n", (unsigned int)pSmb2Session,(unsigned int)pStream->psmb2Session);

    rtp_printf("Got share name == [%c %c %c %c]\n", (char )share_name[0], (char )share_name[1],(char )share_name[2],(char )share_name[3],(char )share_name[4]);

    /* Tie into the V1 share mechanism for now */
    {
        int tid;

        CLAIM_SHARE ();
        tid = SR_GetTreeIdFromName ( share_name );
        if (tid <0)
        {
           error_status = SMB2_STATUS_BAD_NETWORK_NAME;
        }
        else
        {
			byte access;
			PSR_RESOURCE pResource;

			pResource = SR_ResourceById ((word) tid);

#if (1)
            access = SECURITY_ANY;
#else
			/**
			 * We first see what mode the server was in when the user logged in.
			 * This will let us know how to get access info.
			 */
			switch (pCtx->accessMode)
			{
				case AUTH_SHARE_MODE:
					if (Auth_DoPasswordsMatch (pCtx, 0, 0, pResource->password, (PFBYTE) password, (PFBYTE) password) == TRUE)
						access = pResource->permission;
					else
					{
						pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_BADPW);
					}
					break;
				case AUTH_USER_MODE:
				default:
					access = Auth_BestAccess (pCtx, (word) tid);
					break;
			}
#endif
			/**
			 * If they have *some* access, let them connect and browse the share.
			 */
			if (access != SECURITY_NONE)
			{
				PTREE tree;

				tree = SMBU_GetTree (pStream->psmb2Session->pSmbCtx, -1);

				if (!tree)
				{
					/* no free tree structs */
					error_status = SMB2_STATUS_INSUFFICIENT_RESOURCES;
				}
                else
                {
				word externaltid;

				    error_status = 0;

				    response.StructureSize = 16;
				    response.ShareType              = MapRTSMB_To_Smb2_ShareType(pResource->stype);
				    response.ShareFlags             = SMB2_SHAREFLAG_NO_CACHING|SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS;
				    response.Capabilities           = 0; // SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY;
				    if (access == SECURITY_READ)
				        response.MaximalAccess          = SMB2_FPP_ACCESS_MASK_FILE_READ_DATA;
				    else
				        response.MaximalAccess          =   SMB2_FPP_ACCESS_MASK_FILE_READ_DATA|
				                                            SMB2_FPP_ACCESS_MASK_FILE_WRITE_DATA|
				                                            SMB2_FPP_ACCESS_MASK_FILE_APPEND_DATA;
				    externaltid = (word) (((int) (tree)) & 0xFFFF);
				    pStream->OutHdr.TreeId = (dword) externaltid;

				    tree->external = externaltid;
				    tree->internal = (word) tid;

				    Tree_Init (tree);
				    tree->access = access;
				    tree->type = pResource->stype;
				}
			}
			else
			{
				error_status = SMB2_STATUS_ACCESS_DENIED;
			}
       }
       RELEASE_SHARE ();
    }


    if (error_status)
    {
		RtsmbWriteSrvStatus (pStream, error_status);
    }
    else
    {
        /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
        RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    }
    return TRUE;
} // Proc_smb2_TreeConnect

/*
================
	PSMB_SESSIONCTX pSmbCtx - x
	PSMB_HEADER1 pInHdr1 - x
	PSMB_HEADER2 pInHdr2 - x
================
*/
static BBOOL Proc_smb2_TreeDisConnect(smb2_stream  *pStream)
{
	RTSMB2_TREE_DISCONNECT_C command;
	RTSMB2_TREE_DISCONNECT_R response;
	dword error_status = 0;

	pSmb2SrvModel_Session pSmb2Session;
    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  called\n",0);
    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  RtsmbStreamDecodeCommand failed...\n",0);
   		RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
        return TRUE;
    }
    else
    {
        PTREE tree;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  RtsmbStreamDecodeCommand succeded Tree = %d\n",(int)pStream->InHdr.TreeId);
        tree = SMBU_GetTree (pStream->psmb2Session->pSmbCtx, (word) pStream->InHdr.TreeId);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  SMBU_GetTree returned %X\n",(int)tree);
        if (tree)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  call Tree_Shutdown session == %X\n",(int)pStream->psmb2Session);
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  call Tree_Shutdown session->pSmbCtx == %X\n",(int)pStream->psmb2Session->pSmbCtx);
            Tree_Shutdown (pStream->psmb2Session->pSmbCtx, tree);
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  back Tree_Shutdown X\n",0);
        }
    }
	response.StructureSize = 4;
    if (error_status)
    {
		RtsmbWriteSrvStatus (pStream, error_status);
    }
    else
    {
        /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
        RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    }
    return TRUE;
} // Proc_smb2_TreeDisConnect

// BBOOL ProcTreeDisconnect (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)




static  rtsmb_char srv_dialect_smb2002[] = {'S', 'M', 'B', '2', '.', '0', '0', '2', '\0'};
static struct smb2_dialect_entry_s smb2_dialectList[] =
{
	{SMB2_DIALECT_2002, srv_dialect_smb2002, 1},
};
#define NUM_SMB2_DIALECTS (int)(sizeof(smb2_dialectList)/sizeof(smb2_dialectList[0]))
static struct smb2_dialect_entry_s *RTSMB_FindBestDialect(int inDialectCount, word inDialects[])
{
int i,entry;
word dialect = 0;
struct smb2_dialect_entry_s *pEntry = 0;

   for (entry = 0; entry < inDialectCount; entry++)
   {//check dialect field against dialect list
        for (i = 0; i < NUM_SMB2_DIALECTS; i++)
        {
	        if (inDialects[entry] == smb2_dialectList[i].dialect)
	        {
	            if ((dialect == 0)	|| (smb2_dialectList[dialect].priority < smb2_dialectList[i].priority))
	            {
				    dialect = smb2_dialectList[i].dialect;
				    pEntry = &smb2_dialectList[i];
	            }
	        }
        }
   }
   return pEntry;
}



const char *DebugSMB2CommandToString(int command);


static void DebugOutputSMB2Command(int command)
{
#ifdef RTSMB_DEBUG
char tmpBuffer[32];
    char* buffer = tmpBuffer;
    tmpBuffer[0] = '\0';
    RTSMB_DEBUG_OUTPUT_STR ("SMBS_ProcSMB2_Body:  Processing a packet with command: ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR((char *)DebugSMB2CommandToString(command), RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);

#endif // RTSMB_DEBUG
}


#endif /* INCLUDE_RTSMB_SERVER */
#endif