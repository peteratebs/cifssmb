//
// CLI_SMB_WIRE.C -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2013
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  Exports two public functions:
//      RtsmbStreamEncodeCommand(smb2_stream *pStream, PFVOID pItem) - Encode an SMB request in the local structure pointed to by pItem into the output buffer managed by pStream.
//      RtsmbStreamDecodeResponse(smb2_stream *pStream, PFVOID pItem)- Decode an SMB response into the local structure pointed to by pItem from the input buffer managed by pStream.
//
//      These two routines are called to encode and decode packets at the request of logic in the file cli_smb_proc.c
//
//      Variable length output parameters like path names, write data, security blobs etc are passed to RtsmbStreamEncodeCommand in pStream->WriteBufferParms[0]
//      If a second variable length output parameters is needed like channel names are passed to RtsmbStreamEncodeCommand in pStream->WriteBufferParms[1]
//
//      Variable length input parameters like read data, security blobs etc are passed to RtsmbStreamDecodeCommand in pStream->ReadBufferParms[0]
//      If a second variable length input parameter is needed like channel names are passed to RtsmbStreamDecodeCommand in pStream->ReadBufferParms[1]
//
//
//
//

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#if (INCLUDE_RTSMB_CLIENT)
#include "com_smb2.h"
#include "smbpack.h"
#include "smbread.h"


#include "cliwire.h"
#include "smbutil.h"
#include "smbnbss.h"
#include "clians.h"
#include "smbnet.h"
#include "clicfg.h"
#include "smbdebug.h"
#include "smbconf.h"

#include "rtpnet.h"
#include "rtptime.h"

extern int RtsmbStreamEncodeCommand(smb2_stream *pStream, PFVOID pItem);
extern int RtsmbStreamDecodeResponse(smb2_stream *pStream, PFVOID pItem);

static int RtsmbWireVarEncodeNegotiateCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeSessionSetupCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeTreeConnectCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeCreateCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeReadCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeWriteCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeWriteLockCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeIoctlCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeQueryDirectoryCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeQueryInfoCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeSetInfoCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeNegotiateResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeSessionSetupResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeCreateResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeReadResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeIoctlResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeQueryDirectoryResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeChangeNotifyResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeQueryInfoResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);




int RtsmbStreamEncodeCommand(smb2_stream *pStream, PFVOID pItem)
{
int rv = -1;
    pStream->Success = FALSE;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"RtsmbStreamEncodeResponse: Encoding command: (%d): %s\n", (int) pStream->OutHdr.Command,DebugSMB2CommandToString((int) pStream->OutHdr.Command));

    switch (pStream->OutHdr.Command)
    {
        case SMB2_NEGOTIATE:
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 36, RtsmbWireVarEncodeNegotiateCommandCb);
            break;
        case SMB2_SESSION_SETUP  :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 25, RtsmbWireVarEncodeSessionSetupCommandCb);
            break;
        case SMB2_LOGOFF         :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 4, 0);
            break;
        case SMB2_TREE_CONNECT   :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 8, RtsmbWireVarEncodeTreeConnectCommandCb);
            break;
        case SMB2_TREE_DISCONNECT:
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 4, 0);
            break;
        case SMB2_CREATE         :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 56, RtsmbWireVarEncodeCreateCommandCb);
            break;
        case SMB2_CLOSE          :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 24, 0);
            break;
        case SMB2_FLUSH          :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 24, 0);
            break;
        case SMB2_READ           :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 48, RtsmbWireVarEncodeReadCommandCb);
            break;
        case SMB2_WRITE          :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 48, RtsmbWireVarEncodeWriteCommandCb);
            break;
        case SMB2_LOCK           :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 48, RtsmbWireVarEncodeWriteLockCommandCb);
            break;
        case SMB2_IOCTL          :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 48, RtsmbWireVarEncodeIoctlCommandCb);
            break;
        case SMB2_CANCEL         :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 4, 0);
            break;
        case SMB2_ECHO           :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 4, 0);
            break;
        case SMB2_QUERY_DIRECTORY:
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 32, RtsmbWireVarEncodeQueryDirectoryCommandCb);
            break;
        case SMB2_CHANGE_NOTIFY  :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 32, 0);
            break;
        case SMB2_QUERY_INFO     :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 40, RtsmbWireVarEncodeQueryInfoCommandCb);
            break;
        case SMB2_SET_INFO       :
            rv = RtsmbWireEncodeSmb2(pStream,  pItem, 32, RtsmbWireVarEncodeSetInfoCommandCb);
            break;
        case SMB2_OPLOCK_BREAK   :
            HEREHERE // Lease break. How do we do this (by size ?) LEASE is 36 .
            rv = RtsmbWireEncodeSmb2(pStream, pItem, 24, 0);
    	default:
    	break;
    }
    if (rv >= 0)
        pStream->Success = TRUE;
    return rv;
}

extern const char *DebugSMB2CommandToString(int command);

int RtsmbStreamDecodeResponse(smb2_stream *pStream, PFVOID pItem)
{
int rv = -1;
    pStream->Success = FALSE;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"RtsmbStreamDecodeResponse: processing command: (%d): %s\n", (int) pStream->InHdr.Command,DebugSMB2CommandToString((int) pStream->InHdr.Command));

    switch (pStream->InHdr.Command)
    {
        case SMB2_NEGOTIATE:
            /* The packet size is 65 bytes but byte 65 is the start of the variable part so pass 64 as the fixed part */
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 64, RtsmbWireVarDecodeNegotiateResponseCb);
            break;
        case SMB2_SESSION_SETUP  :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 8, RtsmbWireVarDecodeSessionSetupResponseCb);
            break;
        case SMB2_LOGOFF         :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 4, 0);
            break;
        case SMB2_TREE_CONNECT   :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 16, 0);
            break;
        case SMB2_TREE_DISCONNECT:
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 4, 0);
            break;
        case SMB2_CREATE         :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 88, RtsmbWireVarDecodeCreateResponseCb);
            break;
        case SMB2_CLOSE          :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 60, 0);
            break;
        case SMB2_FLUSH          :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 4, 0);
            break;
        case SMB2_READ           :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 16, RtsmbWireVarDecodeReadResponseCb);
            break;
        case SMB2_WRITE          :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 16, 0);
            break;
        case SMB2_LOCK           :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 4, 0);
            break;
        case SMB2_IOCTL          :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 88, RtsmbWireVarDecodeIoctlResponseCb);
            break;
        case SMB2_CANCEL         :
            break;
        case SMB2_ECHO           :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 4, 0);
            break;
        case SMB2_QUERY_DIRECTORY:
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 8, RtsmbWireVarDecodeQueryDirectoryResponseCb);
            break;
        case SMB2_CHANGE_NOTIFY  :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 8, RtsmbWireVarDecodeChangeNotifyResponseCb);
            break;
        case SMB2_QUERY_INFO     :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 8, RtsmbWireVarDecodeQueryInfoResponseCb);
            break;
        case SMB2_SET_INFO       :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 2, 0);
            break;
        case SMB2_OPLOCK_BREAK   :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 24, 0);
            break;
    	default:
    	break;
    }
    if (rv >= 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"Success processing command: %d, positive response is %d\n", (int) pStream->InHdr.Command, rv);
        pStream->Success = TRUE;
    }
    else
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Failed processing command: %d, error response is %d\n", (int) pStream->InHdr.Command, rv);
    }
    return rv;
}


static int RtsmbWireVarEncodeNegotiateCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
int i;
PFVOID s=buf;
    pStream=pStream;
    for(i = 0; i < ((PRTSMB2_NEGOTIATE_C )pItem)->DialectCount; i++)
    {
	    RTSMB_PACK_WORD ( ((PRTSMB2_NEGOTIATE_C )pItem)->Dialects[i] );
    }
    return PDIFF (buf, s);
}

static int RtsmbWireVarEncodeSessionSetupCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_SESSION_SETUP_C pCommand = (PRTSMB2_SESSION_SETUP_C) pItem;
    return RtsmbWireVarEncode(pStream, origin, buf, size, pCommand->SecurityBufferOffset, pCommand->SecurityBufferLength, pCommand->StructureSize);
}

static int RtsmbWireVarEncodeTreeConnectCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_TREE_CONNECT_C pCommand = (PRTSMB2_TREE_CONNECT_C) pItem;
    return RtsmbWireVarEncode(pStream, origin, buf, size, pCommand->PathOffset, pCommand->PathLength, pCommand->StructureSize);
}
static int RtsmbWireVarEncodeCreateCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PFVOID s=buf;
PRTSMB2_CREATE_C pCommand = (PRTSMB2_CREATE_C) pItem;
int rv;
    rv = RtsmbWireVarEncode (pStream, origin, buf, size, pCommand->NameOffset, pCommand->NameLength, pCommand->StructureSize);

    if (rv >= 0)
    {
        if (pCommand->CreateContextsLength)
        {
            dword UsedSize;
            buf = PADD(buf, rv);
            size -= (rtsmb_size) rv;
            UsedSize = (dword) PDIFF (buf, s);
            rv = RtsmbWireVarEncodePartTwo(pStream, origin, buf, size, pCommand->CreateContextsOffset,  pCommand->CreateContextsLength, UsedSize);
        }
    }
    return rv;
}
static int RtsmbWireVarEncodeReadCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_READ_C pCommand = (PRTSMB2_READ_C) pItem;
    return RtsmbWireVarEncode (pStream, origin, buf, size, pCommand->ReadChannelInfoOffset, pCommand->ReadChannelInfoLength, pCommand->StructureSize);

}
static int RtsmbWireVarEncodeWriteCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_WRITE_C pCommand = (PRTSMB2_WRITE_C) pItem;
int rv;
PFVOID s=buf;
    rv = RtsmbWireVarEncode (pStream, origin, buf, size, pCommand->DataOffset, pCommand->Length, pCommand->StructureSize);
    if (rv >= 0)
    {
        HEREHERE // This may be reversed, need validation
        if (pCommand->WriteChannelInfoLength)
        {
            dword UsedSize;
            buf = PADD(buf, rv);
            size = size - (rtsmb_size)  rv;
            UsedSize = (dword) PDIFF (buf, s);
            rv = RtsmbWireVarEncodePartTwo(pStream, origin, buf, size, pCommand->WriteChannelInfoOffset, pCommand->WriteChannelInfoLength, UsedSize);
        }
    }
    return rv;
}
static int RtsmbWireVarEncodeWriteLockCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
// PRTSMB2_LOCK_REQUEST_C pCommand = (PRTSMB2_LOCK_REQUEST_C) pItem;

    HEREHERE // - Relying on PACK attribute and intel byte ordering to unpack Locks directly.
    pStream = pStream ;
    origin  = origin  ;
    buf    = buf    ;
    size= size;
    pItem  = pItem  ;
    return -1;
}
static int RtsmbWireVarEncodeIoctlCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
    HEREHERE // Complicated
    pStream = pStream ;
    origin  = origin  ;
    buf    = buf    ;
    size= size;
    pItem  = pItem  ;
    return -1;

}
static int RtsmbWireVarEncodeQueryDirectoryCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_QUERY_DIRECTORY_C pCommand = (PRTSMB2_QUERY_DIRECTORY_C) pItem;
    return RtsmbWireVarEncode (pStream, origin, buf, size, pCommand->FileNameOffset, pCommand->FileNameLength, pCommand->StructureSize);
}
static int RtsmbWireVarEncodeQueryInfoCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_QUERY_INFO_C pCommand = (PRTSMB2_QUERY_INFO_C) pItem;
    return RtsmbWireVarEncode (pStream, origin, buf, size, pCommand->InputBufferOffset, pCommand->InputBufferLength, pCommand->StructureSize);
}
static int RtsmbWireVarEncodeSetInfoCommandCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_SET_INFO_C pCommand = (PRTSMB2_SET_INFO_C) pItem;
    return RtsmbWireVarEncode (pStream, origin, buf, size, pCommand->BufferOffset, pCommand->BufferLength, pCommand->StructureSize);
}



static int RtsmbWireVarDecodeNegotiateResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_NEGOTIATE_R pResponse = (PRTSMB2_NEGOTIATE_R) pItem;
    return RtsmbWireVarDecode (pStream, origin, buf, size, pResponse->SecurityBufferOffset, pResponse->SecurityBufferLength, pResponse->StructureSize);
}

static int RtsmbWireVarDecodeSessionSetupResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_SESSION_SETUP_R pResponse = (PRTSMB2_SESSION_SETUP_R) pItem;
    return RtsmbWireVarDecode (pStream, origin, buf, size, pResponse->SecurityBufferOffset, pResponse->SecurityBufferLength, pResponse->StructureSize);
}

static int RtsmbWireVarDecodeCreateResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_CREATE_R pResponse = (PRTSMB2_CREATE_R )pItem;
    return RtsmbWireVarDecode(pStream, origin, buf, size, pResponse->CreateContextsOffset, pResponse->CreateContextsLength, pResponse->StructureSize);
}
static int RtsmbWireVarDecodeReadResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_READ_R pResponse = (PRTSMB2_READ_R )pItem;
    return RtsmbWireVarDecode(pStream, origin, buf, size, pResponse->DataOffset, pResponse->DataLength, pResponse->StructureSize);
}
static int RtsmbWireVarDecodeIoctlResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PFVOID s=buf;
    HEREHERE // Complex needs work
//PRTSMB2_IOCTL_R pResponse = (PRTSMB2_IOCTL_R )pItem;
//    return RtsmbWireVarEncodeResponseCb(pStream, origin, buf, size, pResponse->DataOffset, pResponse->DataLength, pResponse->StructureSize);
    return PDIFF (buf, s);
}
static int RtsmbWireVarDecodeQueryDirectoryResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_QUERY_DIRECTORY_R pResponse = (PRTSMB2_QUERY_DIRECTORY_R )pItem;
    return RtsmbWireVarDecode(pStream, origin, buf, size, pResponse->OutputBufferOffset, pResponse->OutputBufferLength, pResponse->StructureSize);
}
static int RtsmbWireVarDecodeChangeNotifyResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_CHANGE_NOTIFY_R pResponse = (PRTSMB2_CHANGE_NOTIFY_R )pItem;
    return RtsmbWireVarDecode(pStream, origin, buf, size, pResponse->OutputBufferOffset, pResponse->OutputBufferLength, pResponse->StructureSize);
}
static int RtsmbWireVarDecodeQueryInfoResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_QUERY_INFO_R pResponse = (PRTSMB2_QUERY_INFO_R )pItem;
    return RtsmbWireVarDecode(pStream, origin, buf, size, pResponse->OutputBufferOffset, pResponse->OutputBufferLength, pResponse->StructureSize);
}



#endif /* INCLUDE_RTSMB_CLIENT */
#endif