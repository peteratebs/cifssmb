#ifndef __SRV_SSN_H__
#define __SRV_SSN_H__
/*****************************************************************************   */
/***                                                                             */
/***    SRVSSN.H                                                                 */
/***    Header - Description                                                     */
/***                                                                             */
/***                                                                             */
/*****************************************************************************   */
/*============================================================================   */
/*    INTERFACE REQUIRED HEADERS                                                 */
/*============================================================================   */
#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "psmbfile.h"
#include "srvshare.h"
#include "smb.h"
#include "smbobjs.h"
#include "smbnb.h"
#include "smbnbss.h"

/*============================================================================   */
/*    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS                     */
/*============================================================================   */

#define SMB_BUFFER_SIZE     (prtsmb_srv_ctx->small_buffer_size - RTSMB_NBSS_HEADER_SIZE)
#define SMB_BIG_BUFFER_SIZE (prtsmb_srv_ctx->big_buffer_size - RTSMB_NBSS_HEADER_SIZE)

/* A is a smb context   */
#define SMB_INBUF(A)    (&A->readBuffer[RTSMB_NBSS_HEADER_SIZE])
#define SMB_OUTBUF(A)   (&A->writeBuffer[RTSMB_NBSS_HEADER_SIZE])

/* A is a smb header   */
#define SMB_PID(A)      ((((dword) A->extra.pidHigh) << 16) | A->pid)

typedef enum
{
#ifdef SUPPORT_SMB2
    NOTCONNECTED,       /* -> IDLE                             - ready and waiting for input, protocol V1 or V2 not yet identified */ 
#endif
    IDLE,               /* -> anything                         - ready and waiting for input */ 
    READING,            /* -> IDLE                             - in the middle of reading a packet */ 
    BROWSE_MUTEX,       /* -> BROWSE_SENT, BROWSE_FAIL         - waiting for resources to clear so we can netenum2 */ 
    BROWSE_SENT,        /* -> BROWSE_FINISH, BROWSE_FAIL       - waiting on response to our netenum2 */ 
    BROWSE_FINISH,      /* -> IDLE                             - data is here (or error occured), send answer to netenum2 */ 
    BROWSE_FAIL,        /* -> IDLE                             - something bad happened during enum (no domain) */ 
    WAIT_ON_PDC_NAME,   /* -> FINISH_NEGOTIATE, FAIL_NEGOTIATE - waiting to discover primary domain controller's name */ 
    WAIT_ON_PDC_IP,     /* -> FINISH_NEGOTIATE, FAIL_NEGOTIATE - waiting to discover primary domain controller's ip */ 
    FAIL_NEGOTIATE,     /* -> IDLE                             - negotiation failed -- send error message back */ 
    FINISH_NEGOTIATE,   /* -> IDLE                             - authentication succeeded, continue with negotiate */ 
    WRITING_RAW,        /* -> IDLE, WRITING_RAW_READING        - awaiting a large packet as part of a write raw request */ 
    WRITING_RAW_READING /* -> IDLE                             - in the middle of reading a large packet for write raw */ 
} SMBS_SESSION_STATE;

/*============================================================================   */
/*    INTERFACE STRUCTURES / UTILITY CLASSES                                     */
/*============================================================================   */

/**
 * Here's the deal with trees, fids, and users.
 *
 * A session can hold any number of user ids, trees and fids.
 * Trees can be accessed by any user.  Fids can only be accessed by
 * the creating user.  When a tree is disconnected (by any user), all
 * files it held are closed.  When a user logs off, all files he/she owned
 * are closed.
 */

#define FID_FLAG_DIRECTORY      0x0001
#define FID_FLAG_ALL            0xFFFF
typedef struct fid_s
{
    int internal;   /* -1 means not in use */
    word external;

    word flags;

    word tid;       /* owning tree */
    word uid;       /* owning user */
    dword pid;      /* owning process */
    dword error;    /* delayed error */
    rtsmb_char name[SMBF_FILENAMESIZE + 1];
} FID_T;
typedef FID_T RTSMB_FAR *PFID;

typedef struct tree_s
{
    BBOOL inUse;
    byte access;

    byte type;      /* type of tree */

    word external;  /* public tid */
    word internal;  /* private tid */

    /* nulls can be interspersed in this array   */
    PFID *fids;

} TREE_T;
typedef TREE_T RTSMB_FAR *PTREE;

typedef struct search_s
{
    BBOOL inUse;

    unsigned long lastUse;
    word tid; /* tid this belongs to.  struct maybe should be put in TREE_T */
    dword pid; /* pid this belongs to. */
    SMBDSTAT stat;

} SEARCH_T;
typedef SEARCH_T RTSMB_FAR *PSEARCH;

typedef struct user_s
{
    byte inUse;
    word uid;
    word authId;
    BBOOL canonicalized;

    SEARCH_T *searches;

    /* nulls can be interspersed in this array   */
    PFID *fids;

} USER_T;
typedef USER_T RTSMB_FAR *PUSER;

/**
 * This holds data for raw writing operations.
 * This could be cleaned up.
 */
typedef struct write_raw_info
{
    BBOOL amWritingRaw;
    BBOOL writeThrough;
    int internal;
    word external;
    RTSMB_HEADER hdr;
    word maxCount;

} WRITE_RAW_INFO_T;


typedef struct smb_sessionCtx_s
{
    RTP_SOCKET sock;

    SMB_DIALECT_T dialect;      /* dialect we are speaking */
    BBOOL isSMB2;               /* Set true when SMB2 negotiated */
    BBOOL doSocketClose;        /* Set true when SMB command handler wants the network layer code to close the socket when it is convenient. */
    SMBS_SESSION_STATE state;   /* are we idle or waiting on something? */

    /**
     * Pointers to the buffers we are currently using for reading or writing.
     */
    PFBYTE readBuffer;
    PFBYTE writeBuffer;

    /**
     * We list the size of the current read/write buffers so that we know
     * what is safe to read from wire.
     */
    dword readBufferSize;
    dword writeBufferSize;

    /**
     * Here we house default reading/writing buffers that can handle everyday
     * messaging needs.
     */
    PFBYTE smallReadBuffer;
    PFBYTE smallWriteBuffer;

    /**
     * Points to beginning of SMB.
     */
    PFBYTE read_origin;
    PFBYTE write_origin;


    /**
     * We also need to keep track of the size we are willing to use from small
     * buffers, since client's buffer may be smaller than ours.
     */
    dword useableBufferSize;

    /**
     * Used to record how large the body of our currently-being-procesed
     * incoming SMB is.
     */
    dword current_body_size;

    /**
     * Used to record how big the current incoming packet is.
     */
    dword in_packet_size;

    /**
     * Used to record when we will stop trying to complete the current packet.
     */
    dword in_packet_timeout_base;

    /**
     * Size of our current outgoing packet.
     */
    dword outBodySize;

    /**
     * Holds temporary read and write data.
     */
    PFBYTE tmpBuffer;
    dword tmpSize;


    /**
     * A helper variable to hold on raw writes.
     */
    WRITE_RAW_INFO_T writeRawInfo;

#ifdef SUPPORT_SMB2
    struct s_Smb2SrvModel_Session  *pCtxtsmb2Session;
#endif
    /* Below here is all smbv1 and should be in a seperate union.   */
    /**
     * headers
     */
    PRTSMB_HEADER pInHeader;
    PRTSMB_HEADER pOutHeader;



    byte encryptionKey [8]; /* encryptionKey used for password encryption */

    byte accessMode;        /* access mode of server when session is set up */

    word sessionId;         /* this keeps value across session closes/opens */

    /**
     * Set some flags to let processing functions know what's going on without
     * having to pass a lot of info on around on the stack.
     *
     * These are the values for the smb being processed.
     */
    word uid;
    dword pid;
    word tid;

    /**
     * Some helper data we keep around to answer net_server_enum's.
     */
    char  server_enum_domain [RTSMB_NB_NAME_SIZE + 1];
    dword server_enum_type;


    /**
     * This array holds all the information on
     * all the users logged in over this session.
     */
    /* list of users for this session   */
    USER_T *uids;

    /* holds tree data   */
    TREE_T *trees;

    /* fids for this session   */
    FID_T  *fids;

} SMB_SESSIONCTX_T;
typedef SMB_SESSIONCTX_T RTSMB_FAR *PSMB_SESSIONCTX;


#define READ_SMB(A) \
{\
    if (A (pCtx->read_origin, pInBuf, (rtsmb_size) (pCtx->current_body_size - (rtsmb_size)PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &command) == -1)\
    {\
        SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);\
        return TRUE;\
    }\
}


#define WRITE_SMB(A) \
{\
    PFVOID buf;\
    int tmp_size = srv_cmd_fill_header (pCtx->write_origin, pOutBuf,\
        (rtsmb_size)SMB_BUFFER_SIZE, pOutHdr);\
    if (tmp_size == -1)\
    {\
        SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);\
        return TRUE;\
    }\
    buf = PADD (pOutBuf, tmp_size);\
    pCtx->outBodySize = (rtsmb_size)tmp_size;\
    if ((tmp_size = A (pCtx->write_origin, buf, (rtsmb_size)(SMB_BUFFER_SIZE - tmp_size), \
        pOutHdr, &response)) == -1)\
    {\
        SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);\
        return TRUE;\
    }\
    pCtx->outBodySize += (rtsmb_size)tmp_size;\
}


/*============================================================================   */
/*    INTERFACE DATA DECLARATIONS                                                */
/*============================================================================   */

/*============================================================================   */
/*    INTERFACE FUNCTION PROTOTYPES                                              */
/*============================================================================   */
void SMBS_InitSessionCtx (PSMB_SESSIONCTX pSmbCtx, RTP_SOCKET sock);
void SMBS_CloseSession (PSMB_SESSIONCTX pSmbCtx);
void SMBS_CloseShare (PSMB_SESSIONCTX pCtx, word handle);
void SMBS_SetBuffers (PSMB_SESSIONCTX pCtx, PFBYTE inBuf, dword inSize, PFBYTE outBuf, dword outSize, PFBYTE tmpBuf, dword tmpSize);

BBOOL SMBS_StateWaitOnPDCName (PSMB_SESSIONCTX pCtx);
BBOOL SMBS_StateWaitOnPDCIP (PSMB_SESSIONCTX pCtx);
BBOOL SMBS_StateContinueNegotiate (PSMB_SESSIONCTX pCtx);
BBOOL SMBS_ProcSMBPacket (PSMB_SESSIONCTX pSctx, dword packetSize);

BBOOL SMBS_ProcSMBBody (PSMB_SESSIONCTX pSctx);
BBOOL SMBS_SendMessage (PSMB_SESSIONCTX pCtx, dword size, BBOOL translate);

/*============================================================================   */
/*    INTERFACE TRAILING HEADERS                                                 */
/*============================================================================   */


/*****************************************************************************   */
/***                                                                             */
/***    END HEADER SRVSSN.H                                                      */
/***                                                                             */
/*****************************************************************************   */

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_SSN_H__ */
