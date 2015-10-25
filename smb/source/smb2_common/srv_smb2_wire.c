//
// SRV_SMB2_WIRE.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//
// Handles the encoding and decoding of SMB2 packets for the server
//
//  Exports two public functions:
//      RtsmbStreamEncodeResponse(smb2_stream *pStream, PFVOID pItem) - Encode an SMB response in the local structure pointed to by pItem into the output buffer managed by pStream.
//      RtsmbStreamDecodeCommand(smb2_stream *pStream, PFVOID pItem)  - Decode an SMB response into the local structure pointed to by pItem from the input buffer managed by pStream.
//
//      These two routines are called to encode and decode packets at the request of logic in the file srv_smb_proc.c
//
//      Variable length output parameters like path names, write data, security blobs etc are passed to RtsmbStreamEncodeResponse in pStream->WriteBufferParms[0]
//      If a second variable length output parameters is needed like channel names are passed to RtsmbStreamEncodeResponse in pStream->WriteBufferParms[1]
//
//      Variable length input parameters like read data, security blobs etc are passed to RtsmbStreamDecodeCommand in pStream->ReadBufferParms[0]
//      If a second variable length input parameter is needed like channel names are passed to RtsmbStreamDecodeCommand in pStream->ReadBufferParms[1]
//
//
#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#include "com_smb2.h"
#include "com_smb2_wiredefs.h"


#include "srvcmds.h"
#include "srvutil.h"
#include "smbread.h"
#include "smbutil.h"
#include "smbpack.h"
#include "smbread.h"



extern int RtsmbStreamEncodeResponse(smb2_stream *pStream, PFVOID pItem);
extern int RtsmbStreamDecodeCommand(smb2_stream *pStream, PFVOID pItem);

static int RtsmbWireVarEncodeNegotiateResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeSessionSetupResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeCreateResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeReadResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeIoctlResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeQueryDirectoryResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeChangeNotifyResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarEncodeQueryInfoResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeNegotiateCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeSessionSetupCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeTreeConnectCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem);
static int RtsmbWireVarCreateCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem);
static int RtsmbWireVarDecodeReadCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem);
static int RtsmbWireVarDecodeWriteCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem);
static int RtsmbWireVarDecodeLockCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem);
static int RtsmbWireVarDecodeIoctlCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem);
static int RtsmbWireVarDecodeQueryDirectoryCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeQueryInfoCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static int RtsmbWireVarDecodeSetInfoCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);




int RtsmbStreamDecodeCommand(smb2_stream *pStream, PFVOID pItem)
{
int rv = -1;
    pStream->Success = FALSE;
    switch (pStream->InHdr.Command)
    {
        case SMB2_NEGOTIATE:
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 36, RtsmbWireVarDecodeNegotiateCommandCb);
            break;
        case SMB2_SESSION_SETUP  :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 25, RtsmbWireVarDecodeSessionSetupCommandCb);
            break;
        case SMB2_LOGOFF         :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 4, 0);
            break;
        case SMB2_TREE_CONNECT   :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 8, RtsmbWireVarDecodeTreeConnectCommandCb);
            break;
        case SMB2_TREE_DISCONNECT:
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 4, 0);
            break;
        case SMB2_CREATE         :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 56, RtsmbWireVarCreateCommandCb);
            break;
        case SMB2_CLOSE          :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 24, 0);
            break;
        case SMB2_FLUSH          :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 24, 0);
            break;
        case SMB2_READ           :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 48, RtsmbWireVarDecodeReadCommandCb);
            break;
        case SMB2_WRITE          :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 48, RtsmbWireVarDecodeWriteCommandCb);
            break;
        case SMB2_LOCK           :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 48, RtsmbWireVarDecodeLockCommandCb);
            break;
        case SMB2_IOCTL          :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 56, RtsmbWireVarDecodeIoctlCommandCb);
            break;
        case SMB2_CANCEL         :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 4, 0);
            break;
        case SMB2_ECHO           :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 4, 0);
            break;
        case SMB2_QUERY_DIRECTORY:
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 32, RtsmbWireVarDecodeQueryDirectoryCommandCb);
            break;
        case SMB2_CHANGE_NOTIFY  :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 32, 0);
            break;
        case SMB2_QUERY_INFO     :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 40, RtsmbWireVarDecodeQueryInfoCommandCb);
            break;
        case SMB2_SET_INFO       :
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 32, RtsmbWireVarDecodeSetInfoCommandCb);
            break;
        case SMB2_OPLOCK_BREAK   :
            HEREHERE // Lease break. How do we do this (by size ?) LEASE is 36 .
            rv = RtsmbWireDecodeSmb2(pStream, pItem, 24, 0);
            break;
    	default:
    	break;
    }
    if (rv >= 0)
        pStream->Success = TRUE;
    return rv;
}



int RtsmbStreamEncodeResponse(smb2_stream *pStream, PFVOID pItem)
{
int rv = -1;
    pStream->Success = FALSE;
    switch (pStream->OutHdr.Command)
    {
        case SMB2_NEGOTIATE:
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem, 64, RtsmbWireVarEncodeNegotiateResponseCb);
            break;
        case SMB2_SESSION_SETUP  :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  8, RtsmbWireVarEncodeSessionSetupResponseCb);
            break;
        case SMB2_LOGOFF         :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  4, 0);
            break;
        case SMB2_TREE_CONNECT   :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  16, 0);
            break;
        case SMB2_TREE_DISCONNECT:
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  4, 0);
            break;
        case SMB2_CREATE         :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  88, RtsmbWireVarEncodeCreateResponseCb);
            break;
        case SMB2_CLOSE          :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  60, 0);
            break;
        case SMB2_FLUSH          :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  4, 0);
            break;
        case SMB2_READ           :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  16, RtsmbWireVarEncodeReadResponseCb);
            break;
        case SMB2_WRITE          :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  16, 0);
            break;
        case SMB2_LOCK           :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  4, 0);
            break;
        case SMB2_IOCTL          :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  88, RtsmbWireVarEncodeIoctlResponseCb);
            break;
        case SMB2_CANCEL         :
            break;
        case SMB2_ECHO           :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  4, 0);
            break;
        case SMB2_QUERY_DIRECTORY:
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  8, RtsmbWireVarEncodeQueryDirectoryResponseCb);
            break;
        case SMB2_CHANGE_NOTIFY  :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  8, RtsmbWireVarEncodeChangeNotifyResponseCb);
            break;
        case SMB2_QUERY_INFO     :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  8, RtsmbWireVarEncodeQueryInfoResponseCb);
            break;
        case SMB2_SET_INFO       :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  2, 0);
            break;
        case SMB2_OPLOCK_BREAK   :
            rv = RtsmbWireEncodeSmb2(pStream, (PFVOID) pItem,  24, 0);
    	default:
    	break;
    }
    if (rv >= 0)
        pStream->Success = TRUE;
    else
        RtsmbWriteSrvError(pStream, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR,0,0);
    return rv;
}


static int RtsmbWireVarEncodeNegotiateResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_NEGOTIATE_R pResponse = (PRTSMB2_NEGOTIATE_R )pItem;
    return RtsmbWireVarEncode(pStream, origin, buf, size, pResponse->SecurityBufferOffset, pResponse->SecurityBufferLength, pResponse->StructureSize);
}
static int RtsmbWireVarEncodeSessionSetupResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_SESSION_SETUP_R pResponse = (PRTSMB2_SESSION_SETUP_R )pItem;
    return RtsmbWireVarEncode(pStream, origin, buf, size, pResponse->SecurityBufferOffset, pResponse->SecurityBufferLength, pResponse->StructureSize);
}
static int RtsmbWireVarEncodeCreateResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_CREATE_R pResponse = (PRTSMB2_CREATE_R )pItem;
    return RtsmbWireVarEncode (pStream, origin, buf, size, pResponse->CreateContextsOffset, pResponse->CreateContextsLength, pResponse->StructureSize);
}
static int RtsmbWireVarEncodeReadResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_READ_R pResponse = (PRTSMB2_READ_R )pItem;
    return RtsmbWireVarEncode(pStream, origin, buf, size, pResponse->DataOffset, pResponse->DataLength, pResponse->StructureSize);
}

static int RtsmbWireVarEncodeIoctlResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PFVOID s=buf;
    HEREHERE // Complex needs work
   pStream  =    pStream;
   origin  =    origin;
   buf  =    buf;
   size  =    size;
   pItem   =    pItem ;
//PRTSMB2_IOCTL_R pResponse = (PRTSMB2_IOCTL_R )pItem;
//    return RtsmbWireVarEncode(pStream, origin, buf, size, pResponse->DataOffset, pResponse->DataLength, pResponse->StructureSize);
    return PDIFF (buf, s);
}

static int RtsmbWireVarEncodeQueryDirectoryResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_QUERY_DIRECTORY_R pResponse = (PRTSMB2_QUERY_DIRECTORY_R )pItem;
    return RtsmbWireVarEncode(pStream, origin, buf, size, pResponse->OutputBufferOffset, pResponse->OutputBufferLength, pResponse->StructureSize);
}

static int RtsmbWireVarEncodeChangeNotifyResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_CHANGE_NOTIFY_R pResponse = (PRTSMB2_CHANGE_NOTIFY_R )pItem;
    return RtsmbWireVarEncode(pStream, origin, buf, size, pResponse->OutputBufferOffset, pResponse->OutputBufferLength, pResponse->StructureSize);
}

static int RtsmbWireVarEncodeQueryInfoResponseCb(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_QUERY_INFO_R pResponse = (PRTSMB2_QUERY_INFO_R )pItem;
    return RtsmbWireVarEncode(pStream, origin, buf, size, pResponse->OutputBufferOffset, pResponse->OutputBufferLength, pResponse->StructureSize);
}



static int RtsmbWireVarDecodeNegotiateCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PFVOID s=buf;
PRTSMB2_NEGOTIATE_C pCommand = (PRTSMB2_NEGOTIATE_C) pItem;
int i;
   pStream  =    pStream;
   origin  =    origin;

   	for (i=0; i < (int)RTSMB_MIN(pCommand->DialectCount,sizeof(pCommand->Dialects)/sizeof(pCommand->Dialects[0]));i++)
	{
		RTSMB_READ_WORD(&pCommand->Dialects[i]);
	}
    return PDIFF (buf, s);
}


static int RtsmbWireVarDecodeSessionSetupCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_SESSION_SETUP_C pCommand = (PRTSMB2_SESSION_SETUP_C) pItem;
    return RtsmbWireVarDecode (pStream, origin, buf, size, (dword)pCommand->SecurityBufferOffset, pCommand->SecurityBufferLength, pCommand->StructureSize);
}
static int RtsmbWireVarDecodeTreeConnectCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem)
{
PRTSMB2_TREE_CONNECT_C pCommand = (PRTSMB2_TREE_CONNECT_C) pItem;
    return RtsmbWireVarDecode (pStream, origin, buf, size, pCommand->PathOffset, pCommand->PathLength, pCommand->StructureSize);
}
static int RtsmbWireVarCreateCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem)
{
PRTSMB2_CREATE_C pCommand = (PRTSMB2_CREATE_C) pItem;
int rv;
    rv = RtsmbWireVarDecode (pStream, origin, buf, size, pCommand->NameOffset, pCommand->NameLength, pCommand->StructureSize);

    if (rv >= 0)
    {
        if (pCommand->CreateContextsLength)
        {
           HEREHERE  // - Have to decode Context and pass it up. Might need additional inbuff to do so
           ; //  rv = RtsmbWireVarDecode (pStream, origin, buf, size, pCommand->CreateContextsOffset, pCommand->CreateContextsLength, pCommand->StructureSize);
        }

    }
    return rv;
}
static int RtsmbWireVarDecodeReadCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem)
{
PRTSMB2_READ_C pCommand = (PRTSMB2_READ_C) pItem;
    return RtsmbWireVarDecode (pStream, origin, buf, size, pCommand->ReadChannelInfoOffset, pCommand->ReadChannelInfoLength, pCommand->StructureSize);
}

static int RtsmbWireVarDecodeWriteCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem)
{
PRTSMB2_WRITE_C pCommand = (PRTSMB2_WRITE_C) pItem;
int rv;
    rv = RtsmbWireVarDecode (pStream, origin, buf, size, pCommand->DataOffset, pCommand->Length, pCommand->StructureSize);
    if (rv >= 0)
    {
        HEREHERE  // - Have to decode WriteChannelInfo and pass it up. Might need additional inbuff to do so. 3.X only
        ; // return RtsmbWireVarDecode (pStream, origin, buf, size, pCommand->WriteChannelInfoOffset, pCommand->WriteChannelInfoLength, pCommand->StructureSize);
    }
    return rv;
}

static int RtsmbWireVarDecodeLockCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem)
{
PFVOID s=buf;
   pStream  =    pStream;   origin  =    origin;   buf  =    buf;   size  =    size;   pItem   =    pItem ;

#if (0)
PRTSMB2_LOCK_REQUEST_C pCommand = (PRTSMB2_LOCK_REQUEST_C) pItem;
RTSMB2_LOCK_ELEMENT *pLock;
int i;

    HEREHERE // - BROKEN
    pStream  =    pStream;
   origin  =    origin;
   buf  =    buf;
   size  =    size;
   pItem   =    pItem ;



    pLock = &pCommand->Locks;
	for (i=0; i < pCommand->LockCount;i++, pLock++)
	{
		RTSMB_READ_ITEM(pLock, sizeof(*pLock));
	}
#endif
    return PDIFF (buf, s);
}

static int RtsmbWireVarDecodeIoctlCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, PFVOID pItem)
{
PFVOID s=buf;
   pStream  =    pStream;   origin  =    origin;   buf  =    buf;   size  =    size;   pItem   =    pItem ;
#if (0)
//PRTSMB2_IOCTL_C pCommand = (PRTSMB2_IOCTL_C) pItem;

    HEREHERE // - This is complicated, needs work
#endif
    return PDIFF (buf, s);
}

static int RtsmbWireVarDecodeQueryDirectoryCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_QUERY_DIRECTORY_C pCommand = (PRTSMB2_QUERY_DIRECTORY_C) pItem;
    return RtsmbWireVarDecode (pStream, origin, buf, size, pCommand->FileNameOffset, pCommand->FileNameLength, pCommand->StructureSize);
}

static int RtsmbWireVarDecodeQueryInfoCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_QUERY_INFO_C pCommand = (PRTSMB2_QUERY_INFO_C) pItem;
    return RtsmbWireVarDecode (pStream, origin, buf, size, pCommand->InputBufferOffset, pCommand->InputBufferLength, pCommand->StructureSize);
}

static int RtsmbWireVarDecodeSetInfoCommandCb (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_SET_INFO_C pCommand = (PRTSMB2_SET_INFO_C) pItem;
    return RtsmbWireVarDecode (pStream, origin, buf, size, pCommand->BufferOffset, pCommand->BufferLength, pCommand->StructureSize);
}



/* Packet processing failed. Restore pointers. If encryption is enabled release the buffer  */
static int _smb2_stream_write_error(smb2_stream *pStream, dword statusCode, word ErrorByteCount, byte *ErrorBytes)
{
int write_header_size;
    if (pStream->EncryptMessage)
    {
        RTSmb2_Encryption_Release_Encrypt_Buffer(pStream->write_origin);
        pStream->write_origin = pStream->saved_write_origin;
    }
    pStream->OutBodySize = 0;
	pStream->OutHdr.Status_ChannelSequenceReserved = statusCode;
    pStream->write_buffer_remaining  = pStream->write_buffer_size;
	write_header_size = cmd_fill_header_smb2 (pStream, &pStream->OutHdr);
	if (write_header_size >= 0)
    {
    rtsmb_size size;
	PFVOID buf, s;
    RTSMB2_ERROR_R reply;
        buf     = pStream->pOutBuf;
        size    = pStream->write_buffer_remaining;
        s = buf;
        reply.StructureSize = 9; // 9
        reply.Reserved      = 0;
        reply.ByteCount     = ErrorByteCount;
        if (ErrorByteCount)
        {
            reply.Buffer         =  *ErrorBytes++;
            ErrorByteCount--;
        }
        else
            reply.Buffer         = 0;

        PACK_STRUCT_TO_WIRE(&reply,RTSMB2_ERROR_R,9);
        if ( ErrorBytes )
        {
            PACK_STRUCT_TO_WIRE(ErrorBytes,BLOB,ErrorByteCount);
        }

        pStream->OutBodySize = (rtsmb_size) (write_header_size + PDIFF (buf, s));
    }
	pStream->Success=FALSE;
    return 0;
}

/* Packet processing failed. Restore pointers. If encryption is enabled release the buffer  */
int RtsmbWriteSrvError(smb2_stream *pStream, byte errorClass, word errorCode, word ErrorByteCount, byte *ErrorBytes)
{
dword dw = SMBU_MakeError (errorClass, errorCode);

    return _smb2_stream_write_error(pStream, dw,   ErrorByteCount,   ErrorBytes);
}

/* Packet processing failed. Restore pointers. If encryption is enabled release the buffer  */
int RtsmbWriteSrvStatus(smb2_stream *pStream, dword statusCode)
{
    return _smb2_stream_write_error(pStream, statusCode,0,0);
}
#endif