#ifndef __SMB2_COMMONNBSS_H__
#define __SMB2_COMMONNBSS_H__

//****************************************************************************
//**
//**    smb2_commonnbss.h
//**    Header - Description
//**    Definitions for stream cooms for SMB2 server and client.
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================

/* Building up a client session definition here to aid in building the server. Move this later when it is complete */
typedef struct Rtsmb2ClientSession_s
{
    BBOOL inUse;
    ddword SessionId;
} Rtsmb2ClientSession;

/* Used to pass buffers along with command/response/headers to/from SMB2 encode/decode */
typedef struct
{
    void *pBuffer;
    rtsmb_size  byte_count;
} RTSMB2_BUFFER_PARM;
typedef RTSMB2_BUFFER_PARM RTSMB_FAR *PRTSMB2_BUFFER_PARM;


typedef struct smb2_stream_s {
     // Signing rules. Set by calling smb2_stream_set_signing_rule
    byte     *SigningKey;                           // For writes, the key for signing, For reads the key for checking the signature
#define SIGN_NONE         0                         // - Used for 3.x. Generates 16 byte hash over entire message including Header and padding.
#define SIGN_AES_CMAC_128 1                         // - Used for 3.x. Generates 16 byte hash over entire message including Header and padding.
#define SIGN_HMAC_SHA256  2                         // - Used for 2.002 and 2.100 generates 32 byte hash over entire message including Header and padding. Copy low 16 bytes into the keyfield
    byte     SigningRule;
    struct s_Smb2SrvModel_Session  *psmb2Session;   // For a server. points to the session
    struct smb2_sessionCtx_s *psmb2Ctxt;            // For a server. points to the context
    struct RTSMB_CLI_WIRE_BUFFER_s *pBuffer;        // For a client. points to the controlling SMBV1 buffer structure.
    struct RTSMB_CLI_SESSION_T     *pSession;       // For a client. points to the controlling SMBV1 session structure.
//    struct Rtsmb2ClientSession_s   *psmb2Session;   // For a client. points to smb2 session structure
    struct RTSMB_CLI_SESSION_JOB_T *pJob;           // For a client points to the controlling SMBV1 job structure.


    int      PadValue;                              // If the stream contains a compound message, set to the proper pad value between commands.
    BBOOL    EncryptMessage;                        // For write operations, encryption is required. For reads decryption is required.
    BBOOL    Success;                               // Indicates the current state of read or write operation is succesful.
    BBOOL    doSocketClose;                         // Indicates that the processing layer detected or enacted a session close and the socket should be closed.
    BBOOL    doSessionClose;                        // Indicates that the processing layer is requesting a session close.
    RTSMB2_HEADER OutHdr;                           // Buffer control and header for response
	RTSMB2_BUFFER_PARM WriteBufferParms[2];         // For writes, points to data source for data. Second slot is used in rare cases where 2 variable length parameters are present.
	PFVOID   write_origin;                          // Points to the beginning of the buffer, the NBSS header.
	PFVOID   saved_write_origin;                    // Original origin if the packet is beign encrypted
    PFVOID   pOutBuf;                               // Current position in the output stream buffer.
    rtsmb_size write_buffer_size;
    rtsmb_size write_buffer_remaining;
    rtsmb_size OutBodySize;

    RTSMB2_HEADER InHdr;                            // Buffer control and header from command
	RTSMB2_BUFFER_PARM ReadBufferParms[2];          // For reads points to sink for extra data.  Second slot is used in rare cases where 2 variable length parameters are present.
	PFVOID   read_origin;
    rtsmb_size read_buffer_size;
    rtsmb_size read_buffer_remaining;
    rtsmb_size InBodySize;

	PFVOID   saved_read_origin;
    PFVOID   pInBuf;



} smb2_stream;




//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================

extern int cmd_read_header_raw_smb2 (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB2_HEADER pHeader);
extern int cmd_read_transform_header_smb2(PFVOID origin, PFVOID buf, rtsmb_size size, RTSMB2_TRANSFORM_HEADER *pHeader);
extern int cmd_read_header_smb2 (smb2_stream *pStream);
extern int cmd_fill_header_smb2 (smb2_stream *pstream, PRTSMB2_HEADER pItem);
extern int cmd_fill_transform_header_smb2 (smb2_stream *pstream, PRTSMB2_TRANSFORM_HEADER pItem);
extern void  smb2_stream_set_signing_rule(smb2_stream *pstream, byte  *SigningKey, byte SigningRule);
extern void  smb2_stream_start_encryption(smb2_stream *pstream);

extern int RtsmbWireVarDecode (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, dword BufferOffset, dword BufferLength, word StructureSize);
extern int RtsmbWireVarDecodePartTwo (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, dword BufferOffset, dword BufferLength, word StructureSize);
extern int RtsmbWireVarEncode(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, dword BufferOffset, dword BufferLength, word StructureSize);
extern int RtsmbWireVarEncodePartTwo(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,dword BufferOffset, dword BufferLength, dword UsedSize);


typedef int (* pVarEncodeFn_t) (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
extern int RtsmbWireEncodeSmb2(smb2_stream *pStream, PFVOID pItem, rtsmb_size FixedSize, pVarEncodeFn_t pVarEncodeFn);
typedef int (* pVarDecodeFn_t) (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);;
int RtsmbWireDecodeSmb2(smb2_stream *pStream, PFVOID pItem, rtsmb_size FixedSize, pVarDecodeFn_t pVarDecodeFn);
int RtsmbWriteFinalizeSmb2(smb2_stream *pStream,ddword SessionId);

extern int RtsmbWriteSrvError(smb2_stream *pStream, byte errorClass, word errorCode, word ErrorByteCount, byte *ErrorBytes);
extern int RtsmbWriteSrvStatus(smb2_stream *pStream, dword statusCode);





#define FILL_PROLOG_TEMPLATE \
    PFVOID origin,buf;\
    rtsmb_size size;\
    rtsmb_size consumed;\
    PFVOID s, e;\
    origin  = pStream->write_origin;\
    buf     = pStream->pOutBuf;\
    size    = (rtsmb_size)pStream->write_buffer_remaining; \
    s = buf;


#define FILL_EPILOG_TEMPLATE \
	e = buf;\
    if (pStream->PadValue) RTSMB_PACK_PAD_TO(pStream->PadValue);\
    consumed = (rtsmb_size)PDIFF (e, s);\
    ((PFBYTE)pStream->pOutBuf) += consumed;\
    pStream->write_buffer_remaining-=consumed;\
    pStream->OutBodySize+=consumed;\
	return (int) consumed;

#define READ_PROLOG_TEMPLATE \
PFVOID origin,buf;\
rtsmb_size size;\
PFVOID s, e;\
    origin  = pStream->read_origin;\
    buf     = pStream->pInBuf;\
    size    = (rtsmb_size)pStream->read_buffer_remaining;\
	s = buf;\
	origin = origin; /* origin = origin Quiets compiler */

#define READ_EPILOG_TEMPLATE \
    {\
    int consumed;\
	e = buf;\
    consumed = PDIFF (e, s);\
    pStream->pInBuf+=consumed;\
    pStream->read_buffer_remaining-=consumed;\
	return (int) consumed;\
    }




//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================
//****************************************************************************
//**
//**    END HEADER smb2.h
//**
//****************************************************************************
#endif // __SMB2_COMMONNBSS_H__
