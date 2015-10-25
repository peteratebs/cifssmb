/*                                                                        */
/* SRVSSN.C -                                                             */
/*                                                                        */
/* EBSnet - RTSMB                                                         */
/*                                                                        */
/* Copyright EBSnet Inc. , 2003                                           */
/* All rights reserved.                                                   */
/* This code may not be redistributed in source or linkable object form   */
/* without the consent of its author.                                     */
/*                                                                        */
/* Module description:                                                    */
/* Handles most of the actual processing of packets for the RTSMB server. */
/*                                                                        */

#include "smbdefs.h"

#include "rtpfile.h"
#include "rtprand.h"
#include "rtpwcs.h"
#include "smbdebug.h"
#include "rtpscnv.h"

#if (INCLUDE_RTSMB_SERVER)

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

/*============================================================================   */
/*    SERVER STATE DIAGNOSTICS (COMPILE TIME)                                    */
/*============================================================================   */

#ifdef STATE_DIAGNOSTICS
#include <stdio.h>
typedef struct s_RTSMB_SRV_STATE_DIAGNOSIS
{
    SMBS_SESSION_STATE srvSessionState;
}RTSMB_SRV_STATE_DIAGNOSIS;

RTSMB_SRV_STATE_DIAGNOSIS SRV_STATE_LOG = {0};

int  DIAGNOSTIC_INDEX = 1;

const char *SrvSessionStateName[] = {
#ifdef SUPPORT_SMB2
                                    "NOTCONNECTED",
#endif
                                     "IDLE", "READING", "BROWSE_MUTEX", "BROWSE_SENT", "BROWSE_FINISH",
                                     "BROWSE_FAIL","WAIT_ON_PDC_NAME", "WAIT_ON_PDC_IP", "FAIL_NEGOTIATE",
                                     "FINISH_NEGOTIATE", "WRITING_RAW", "WRITING_RAW_READING"};


#define PRINT_SRV_STATE_CHANGE(a, b)  {rtp_printf("%.2d %5d  Session::%s -> %s\n" , DIAGNOSTIC_INDEX++, rtp_get_system_msec(), a, b);}

#define RTSMB_GET_SRV_SESSION_STATE(a) {if(SRV_STATE_LOG.srvSessionState != a){\
                                        PRINT_SRV_STATE_CHANGE(SrvSessionStateName[SRV_STATE_LOG.srvSessionState], SrvSessionStateName[a]);\
                                        SRV_STATE_LOG.srvSessionState = a;}}

void Get_Srv_Session_State(int a)
{
    RTSMB_GET_SRV_SESSION_STATE(a);
}

#endif /*#ifdef STATE_DIAGNOSTICS */

static char *trans2Commandname(int command);
static void DebugOutputSMBCommand(int command);
static void DebugOutputTrans2Command(int command);

/*============================================================================   */
/*    IMPLEMENTATION PRIVATE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS        */
/*============================================================================   */
#define SMB_MAKE_SESSIONKEY(A)  (dword) A/*((((dword) A) & 0x0000FFFF) | (A->sessionId++ << 16)) */

/*============================================================================   */
/*    IMPLEMENTATION PRIVATE STRUCTURES                                          */
/*============================================================================   */

RTSMB_STATIC rtsmb_char srv_dialect_core[] = {'P', 'C', ' ', 'N', 'E', 'T', 'W', 'O', 'R', 'K', ' ',
'P', 'R', 'O', 'G', 'R', 'A', 'M', ' ', '1', '.', '0', '\0'};
RTSMB_STATIC rtsmb_char srv_dialect_lanman[] = {'L', 'A', 'N', 'M', 'A', 'N', '1', '.', '0', '\0'};
RTSMB_STATIC rtsmb_char srv_dialect_lm1_2x[] = {'L', 'M', '1', '.', '2', 'X', '0', '0', '2', '\0'};
RTSMB_STATIC rtsmb_char srv_dialect_lanman2[] = {'L', 'A', 'N', 'M', 'A', 'N', '2', '.', '1', '\0'};
RTSMB_STATIC rtsmb_char srv_dialect_ntlm[] = {'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', '\0'};
#ifdef SUPPORT_SMB2    /* Some branching to SMB2 from this file, no major processing */
RTSMB_STATIC rtsmb_char srv_dialect_smb2002[] = {'S', 'M', 'B', '2', '.', '0', '0', '2', '\0'};
RTSMB_STATIC rtsmb_char srv_dialect_smb2xxx[] = {'S', 'M', 'B', '2', '.', '?', '?', '?', '\0'};
#endif
struct dialect_entry_s
{
    SMB_DIALECT_T dialect;
    PFRTCHAR name;
    int priority;
}
 dialectList[] =
{
    {PC_NETWORK, srv_dialect_core, 0},
    {LANMAN_1_0, srv_dialect_lanman, 1},
    {LM1_2X002, srv_dialect_lm1_2x, 2},
    {LANMAN_2_1, srv_dialect_lanman2, 4},
    {NT_LM, srv_dialect_ntlm, 5},
#ifdef SUPPORT_SMB2
    {SMB2_2002, srv_dialect_smb2002, 6},
    {SMB2_2xxx, srv_dialect_smb2xxx, 7}
#endif
};
/*============================================================================   */
/*    IMPLEMENTATION REQUIRED EXTERNAL REFERENCES (AVOID)                        */
/*============================================================================   */
/*============================================================================   */
/*    IMPLEMENTATION PRIVATE DATA                                                */
/*============================================================================   */
/*============================================================================   */
/*    INTERFACE DATA                                                             */
/*============================================================================   */
/*============================================================================   */
/*    IMPLEMENTATION PRIVATE FUNCTION PROTOTYPES                                 */
/*============================================================================   */

RTSMB_STATIC void SMBS_InitSessionCtx_smb1(PSMB_SESSIONCTX pSmbCtx);

BBOOL SMBS_ProcSMBBody (PSMB_SESSIONCTX pCtx);
BBOOL SMBS_SendMessage (PSMB_SESSIONCTX pCtx, dword size, BBOOL translate);


void Tree_Init (PTREE user);
void Tree_Shutdown (PSMB_SESSIONCTX pCtx, PTREE tree);
void User_Init (PUSER user);
void User_Shutdown (PSMB_SESSIONCTX pCtx, PUSER user);

/*============================================================================   */
/*    IMPLEMENTATION PRIVATE FUNCTIONS                                           */
/*============================================================================   */
/* --------------------------------------------------- /
 * Macro to read smb packet if it is an andx packet.   /
 * ANDX packets are specific to NT based clients.      /
 * A is a function to handle the specific type of SMB  /
 * packet.                                             /
 *                                                     /
 * Returns: -1 on failure, does not return on success  /
 * -------------------------------------------------- */
#define READ_SMB_AND_X(A) \
{\
    int size_andx ;\
    size_andx = A (\
        pCtx->read_origin, *pInBuf, pCtx->current_body_size - (word) PDIFF (*pInBuf, pCtx->read_origin), \
        pInHdr, &command);\
    if (size_andx == -1) { RTSMB_DEBUG_OUTPUT_STR("FAILED TO READ ANDX SMB!!!\n", RTSMB_DEBUG_TYPE_ASCII); return -1; }\
    *pInBuf = PADD (*pInBuf, size_andx);\
}

/* --------------------------------------------------- /
 * Macro to write smb packet if it is an andx packet.  /
 * ANDX packets are specific to NT based clients.      /
 * A is a function to handle the specific type of SMB  /
 * packet.                                             /
 *                                                     /
 * Returns: -1 on failure, does not return on success  /
 * -------------------------------------------------- */
#define WRITE_SMB_AND_X(A) \
{\
    int size_andx;\
    size_andx = A (\
        pCtx->write_origin, *pOutBuf, (rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (*pOutBuf, pCtx->write_origin)), \
        pOutHdr, &response);\
    if (size_andx == -1) {RTSMB_DEBUG_OUTPUT_STR("FAILED TO WRITE ANDX SMB!!!\n", RTSMB_DEBUG_TYPE_ASCII); return -1; }\
    *pOutBuf = PADD (*pOutBuf, size_andx);\
    pCtx->outBodySize += (rtsmb_size)size_andx;\
}

/* --------------------------------------------------- /
 * Find the next available Server User ID              /
 *                                                     /
 * Returns: returns the next available uid             /
 * -------------------------------------------------- */
static word NewUID(const PUSER u, int Max)
{
    int i, uid;

    for (uid=100; ; uid++)
    {
        for (i=0; i<Max; i++)
            if (u[i].inUse && (u[i].uid == uid))
                goto NextUID;
        return (word)uid;
NextUID:  ;
    }
}

/* --------------------------------------------------- /
 * SMB Session Setup Andx Command                      /
 *                                                     /
 * PSMB_SESSIONCTX pCtx - the session ctx              /
 * PSMB_HEADER pInHdr - the incoming smb header        /
 * PFVOID *pInBuf - pointer to input buffer            /
 * PSMB_HEADER pOutHdr - the outgoing smb header       /
 * PFVOID *pOutBuf - pointer to output buffer          /
 *                                                     /
 * This command is different than the session in the   /
 * NETBIOS layer.  This session is set up to           /
 * authenticate a user session with the client.        /
 *                                                     /
 * Returns: returns the command value of the next      /
 * command in the Andx                                 /
 * -------------------------------------------------- */
int ProcSetupAndx (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID *pInBuf, PRTSMB_HEADER pOutHdr, PFVOID *pOutBuf)
{
    RTSMB_SESSION_SETUP_AND_X_R response;
    rtsmb_char password_buf[CFG_RTSMB_MAX_PASSWORD_SIZE];
    rtsmb_char password_buf2[CFG_RTSMB_MAX_PASSWORD_SIZE];
    rtsmb_char username[CFG_RTSMB_MAX_USERNAME_SIZE + 1];
    rtsmb_char domainname[CFG_RTSMB_MAX_USERNAME_SIZE + 1];
    byte next_command;
    word max_buffer_size;
    /* word max_mpx_count;   */
    /* word vc_number;       */
    /* dword session_id;     */

    response.guest_logon = FALSE;
    response.next_command = SMB_COM_NONE;
    response.srv_native_os = (PFRTCHAR)0;
    response.srv_native_lan_man = (PFRTCHAR)0;
    response.srv_primary_domain = (PFRTCHAR)0;

    if (pCtx->dialect < NT_LM)
    {
        RTSMB_SESSION_SETUP_AND_X_PRE_NT command;

        command.password_size = CFG_RTSMB_MAX_PASSWORD_SIZE;
        command.password = (PFBYTE) password_buf;
        command.account_name_size = CFG_RTSMB_MAX_USERNAME_SIZE + 1;
        command.account_name = username;
        command.primary_domain = domainname;
        command.native_os = (PFRTCHAR)0;
        command.native_lan_man = (PFRTCHAR)0;

        tc_strcpy ((char *)password_buf2, "");  /* not used */


        READ_SMB_AND_X (srv_cmd_read_session_setup_and_x_pre_nt);

        next_command = command.next_command;
        max_buffer_size = command.max_buffer_size;
/*      max_mpx_count = command.max_mpx_count;   */
/*      vc_number = command.vc_number;           */
/*      session_id = command.session_id;         */
    }
    else
    {
        RTSMB_SESSION_SETUP_AND_X_NT command;

        command.ansi_password_size = CFG_RTSMB_MAX_PASSWORD_SIZE;
        command.ansi_password = (PFBYTE) password_buf;
        command.unicode_password_size = CFG_RTSMB_MAX_PASSWORD_SIZE;
        command.unicode_password = (PFBYTE)password_buf2;
        command.account_name_size = CFG_RTSMB_MAX_USERNAME_SIZE + 1;
        command.account_name = username;
        command.primary_domain = domainname;
        command.native_os = (PFRTCHAR)0;
        command.native_lan_man = (PFRTCHAR)0;

        READ_SMB_AND_X (srv_cmd_read_session_setup_and_x_nt);

        next_command = command.next_command;
        max_buffer_size = command.max_buffer_size;
/*      max_mpx_count = command.max_mpx_count;   */
/*      vc_number = command.vc_number;           */
/*      session_id = command.session_id;         */
    }

    if (pCtx->accessMode == AUTH_USER_MODE)
    {
        int i;
        word access, authId;
        BBOOL firstTime = TRUE;
        PUSER user = (PUSER)0;

        access = Auth_AuthenticateUser (pCtx, username, domainname, (PFCHAR)password_buf, (PFCHAR) password_buf2, &authId);

        if (access == AUTH_NOACCESS)
        {
            pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_BADPW);
        }
        else
        {
            for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
            {
                if (pCtx->uids[i].inUse)
                {
                    firstTime = FALSE;
                    break;
                }
            }

            /* If pInHdr->uid != 0: if we have that UID, use it,                   */
            /* If pInHdr->uid == 0: if the client already has a UID for that user, */
            /* reuse it, else allocate new UID                                     */

            if (pInHdr->uid != 0) /* reuse existing uid */
            {
                for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
                {
                    if (pCtx->uids[i].inUse && (pInHdr->uid == pCtx->uids[i].uid))
                    {
                        user = &pCtx->uids[i];
                        break;
                    }
                }

            }

            /* if this is a guest loging, reuse old guests   */
            if ((user == (PUSER)0) && (authId == 0))
            {

                for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
                {
                    if (pCtx->uids[i].inUse && (authId == pCtx->uids[i].authId))
                    {
/*                      rtp_printf("reuse uid: %i, authid: %i \n", pInHdr->uid, authId);   */
                        user = &pCtx->uids[i];
                        break;
                    }
                }
            }
            /* allocate a new UID   */
            if (user == (PUSER)0)
            {
                for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
                {
                    if (pCtx->uids[i].inUse == FALSE)
                    {
                        user = &pCtx->uids[i];
                        User_Init(user);
                        user->uid    = (word) (pInHdr->uid ? pInHdr->uid : NewUID(pCtx->uids, prtsmb_srv_ctx->max_uids_per_session));
                        user->authId = authId;
                        user->canonicalized = (BBOOL) (pInHdr->flags & SMB_FLG_CANONICALIZED);
                        break;
                    }
                }
            }

            if (user == (PUSER)0)
            {
                pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_TOOMANYUIDS);
            }
            else
            {
                pOutHdr->uid = user->uid;
                pInHdr->uid  = user->uid;
                pCtx->uid    = user->uid;

                if (firstTime)
                {
                    pCtx->useableBufferSize = (word) MIN (max_buffer_size, pCtx->writeBufferSize);
                    pCtx->writeBufferSize = pCtx->useableBufferSize;
                }

                if (access == AUTH_GUEST)
                {
                    response.guest_logon = TRUE;
                }
            }
        }
    }
    else
    {
        /* If we're in share mode, there is no concept of users, so pretty much ignore this   */
        pCtx->useableBufferSize = (word) MIN (max_buffer_size, pCtx->writeBufferSize);
        pCtx->writeBufferSize = pCtx->useableBufferSize;

        pOutHdr->uid = 0;

        pCtx->uids[0].canonicalized = (BBOOL) (pInHdr->flags & SMB_FLG_CANONICALIZED);
    }

    response.next_command = next_command;

    WRITE_SMB_AND_X (srv_cmd_fill_session_setup_and_x);

    return next_command;
} /* End ProcSetupAndx */

/* --------------------------------------------------- /
 * SMB Tree Connect Andx Command                       /
 *                                                     /
 * PSMB_SESSIONCTX pCtx - the session ctx              /
 * PSMB_HEADER pInHdr - the incoming smb header        /
 * PFVOID *pInBuf - pointer to input buffer            /
 * PSMB_HEADER pOutHdr - the outgoing smb header       /
 * PFVOID *pOutBuf - pointer to output buffer          /
 *                                                     /
 * This command connects the client to a given share.  /
 * The spec says that every Session Setup command      /
 * must be followed by a tree connect, but that rule   /
 * is sometimes broken.                                /
 *                                                     /
 * Returns: 0 on error, value of next andx command on  /
 *          success                                    /
 * -------------------------------------------------- */
int ProcTreeConAndx (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID *pInBuf, PRTSMB_HEADER pOutHdr, PFVOID *pOutBuf)
{
    int tid;
    rtsmb_char path [SMBF_FILENAMESIZE + 1];
    rtsmb_char service [20];
    rtsmb_char password [CFG_RTSMB_MAX_PASSWORD_SIZE + 1];
    RTSMB_TREE_CONNECT_AND_X command;
    RTSMB_TREE_CONNECT_AND_X_R response;


    ASSURE (!assertUid (pCtx), 0);

    command.password_size = CFG_RTSMB_MAX_PASSWORD_SIZE + 1;
    command.password = (PFBYTE) password;
    command.share_size = SMBF_FILENAMESIZE + 1;
    command.share = path;
    command.service_size = 20;
    command.service = service;

    READ_SMB_AND_X (srv_cmd_read_tree_connect_and_x);

    tid = SR_GetTreeId (path, service);

    if (tid >= 0)
    {
        byte access;
        PSR_RESOURCE pResource;

        CLAIM_SHARE ();

        pResource = SR_ResourceById ((word) tid);

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
                    RELEASE_SHARE ();
                    return 0;
                }
                break;
            case AUTH_USER_MODE:
            default:
                access = Auth_BestAccess (pCtx, (word) tid);
                break;
        }

        /**
         * If they have *some* access, let them connect and browse the share.
         */
        if (access != SECURITY_NONE)
        {
            PTREE tree;
            word externaltid;

            response.optional_support = 0;
            response.service = SR_ServiceToStr(pResource->stype);
            response.native_fs = (PFRTCHAR)0;

            tree = SMBU_GetTree (pCtx, -1);

            if (!tree)
            {
                /* no free tree structs   */
                pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
                return 0;
            }

            externaltid = (word) (((int) (tree)) & 0xFFFF);
            pOutHdr->tid = externaltid;
            tree->external = externaltid;
            tree->internal = (word) tid;

            Tree_Init (tree);
            tree->access = access;
            tree->type = pResource->stype;

            RELEASE_SHARE ();

            response.next_command = command.next_command;

            if (pCtx->dialect < LANMAN_2_1)
            {
                WRITE_SMB_AND_X (srv_cmd_fill_tree_connect_and_x_pre_lanman);
            }
            else
            {
                WRITE_SMB_AND_X (srv_cmd_fill_tree_connect_and_x_lanman);
            }
        }
        else
        {
            RELEASE_SHARE ();
            pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_ACCESS);
            return 0;
        }
    }
    else
    {
        pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_INVNETNAME);
        return 0;
    }

    return command.next_command;
} /* End ProcTreeConAndX */



/* --------------------------------------------------- /
 *Open Or Create Command                               /
 *                                                     /
 * PSMB_SESSIONCTX pCtx - the session ctx              /
 * PTREE pTree - tree structure containing share info  /
 * PFRTCHAR filename - filename to open                /
 * word flags - flags to pass to open                  /
 * word mode - mode to pass to open                    /
 * PFWORD answer_external_fid - fid that smb client    /
                                should use             /
 * PFINT answer_fid - actual fid from filesystem       /
 *                                                     /
 * This command opens or creates a file or directory   /
 *                                                     /
 * Returns: 0 on success, ERROR CODE  on failure       /
            ERROR_CODE                                 /
 * -------------------------------------------------- */

RTSMB_STATIC dword OpenOrCreate (PSMB_SESSIONCTX pCtx, PTREE pTree, PFRTCHAR filename, word flags, word mode, PFWORD answer_external_fid, PFINT answer_fid)
{
    SMBFSTAT stat;
    int fid;

    /**
     * Here we handle pipes.
     */
    if (pTree->type == ST_IPC)
    {
        /* The correct behavior for non-supported pipe files is that they      */
        /* are not-found files.  However, 2K at least, will die if we do that. */
        /* This way (denying access) makes them think we support it, but they  */
        /* just don't have the right priviledges, and they fall back to normal */
        /* packets.                                                            */
        return SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_ACCESS);
        /*return -1 * SMBU_MakeError (SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);   */
    }
    else if (pTree->type == ST_PRINTQ)
    {
        rtsmb_char empty[] = {'\0'};

        /* Ignore whatever they wanted to open, make a temporary filename for them.   */
        /* Usually clients will just send "" anyway.                                  */
        if (SMBU_TemporaryFileName (pCtx, empty, filename))
        {
            return SMBU_MakeError (SMB_EC_ERRDOS, SMB_ERRDOS_FILEEXISTS);
        }

        /* don't fail if file doesn't exist.  rather, create it   */
        flags |= RTP_FILE_O_CREAT;
        mode = 0;
    }

    /**
     * Bug fix - 12-2009 we were making sure the path to the file existed
     * even if we were not creating. Was moved below to do it in the correct place.
     */

    if (SMBFIO_Stat (pCtx, pCtx->tid, filename, &stat))
    {
        if (ON (flags, RTP_FILE_O_CREAT | RTP_FILE_O_EXCL))
        {
            return SMBU_MakeError (SMB_EC_ERRDOS, SMB_ERRDOS_FILEEXISTS);
        }

        /**
         * Don't allow clients to open directories (not all file systems can take it).
         */
        if (stat.f_attributes & RTP_FILE_ATTRIB_ISDIR)
        {
            /* We create a dummy file entry that can only be opened and closed.   */
            int externalFid = SMBU_SetInternalFid (pCtx, 0, filename, FID_FLAG_DIRECTORY);


            if (externalFid < 0)
            {
                RTSMB_DEBUG_OUTPUT_STR("OpenOrCreate: Not enough file handles to pass around for dummy directory!\n", RTSMB_DEBUG_TYPE_ASCII);
                return SMBU_MakeError (SMB_EC_ERRDOS, SMB_ERRDOS_NOFIDS);
            }

            *answer_fid = 0;
            *answer_external_fid = (word)externalFid;
            return 0;
        }
    }
    else if (OFF (flags, RTP_FILE_O_CREAT)) /* not found and we aren't creating, so... */
    {
        return SMBU_MakeError (SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
    }
    /**
     * The Samba client at least, and probably others, expects that if the create
     * flag is set, we will make the whole directory tree too.  So, here we go.
    */
    if (ON (flags, RTP_FILE_O_CREAT))
    {
        SMBU_MakePath (pCtx, filename);
    }
    fid = SMBFIO_Open (pCtx, pCtx->tid, filename, flags, mode);

    if(fid < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("Open denied.\n", RTSMB_DEBUG_TYPE_ASCII);
        return SMBU_MakeError (SMB_EC_ERRDOS, SMB_ERRDOS_NOACCESS); /* dunno what went wrong... */
    }
    else
    {
        int externalFid = SMBU_SetInternalFid (pCtx, fid, filename, 0);

        if (externalFid < 0)
        {
            SMBFIO_Close (pCtx, pCtx->tid, fid);
            RTSMB_DEBUG_OUTPUT_STR("OpenOrCreate: Not enough file handles to pass around!\n", RTSMB_DEBUG_TYPE_ASCII);
            return SMBU_MakeError (SMB_EC_ERRDOS, SMB_ERRDOS_NOFIDS);
        }
        *answer_fid = fid;
        *answer_external_fid = (word)externalFid;
        return 0;
    }
}

/* --------------------------------------------------- /
 * Open Andx Command                                   /
 *                                                     /
 * PSMB_SESSIONCTX pCtx - the session ctx              /
 * PSMB_HEADER pInHdr - the incoming smb header        /
 * PFVOID *pInBuf - pointer to input buffer            /
 * PSMB_HEADER pOutHdr - the outgoing smb header       /
 * PFVOID *pOutBuf - pointer to output buffer          /
 *                                                     /
 * This command is used by a client to open a file,    /
 * or directory, however, the spec lists NT Open Andx  /
 * as the preferred way to do that.  Even newer        /
 * clients still use it though                         /
 *                                                     /
 * Returns: 0 on error, value of next andx command on  /
 *          success                                    /
 * -------------------------------------------------- */

int ProcOpenAndx (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID *pInBuf, PRTSMB_HEADER pOutHdr, PFVOID *pOutBuf)
{
    RTSMB_OPEN_AND_X command;
    PTREE pTree;
    int flags = 0, mode;
    byte permissions;
    int fid;
    dword r;
    word externalFid;

    /*ASSURE (!assertUid (pCtx), 0);   */
    /*ASSURE (!assertTid (pCtx), 0);   */

    ASSERT_UID (pCtx);
    ASSERT_TID (pCtx);

    command.filename_size = pCtx->tmpSize;
    command.filename = (PFRTCHAR) pCtx->tmpBuffer;
    READ_SMB_AND_X (srv_cmd_read_open_and_x);

    switch(SMB_ACCESS_MODE_ACCESS (command.desired_access))
    {
    case 0:/*reading */
        flags |= RTP_FILE_O_RDONLY;
        permissions = SECURITY_READ;
        break;
    case 3:/* execute */
        flags |= RTP_FILE_O_RDONLY;
        permissions = SECURITY_READ;
        break;
    case 1:/*writing */
        flags |= RTP_FILE_O_RDWR;
        permissions = SECURITY_WRITE;
        break;
    case 2:/* reading and writing */
        flags |= RTP_FILE_O_RDWR;
        permissions = SECURITY_READWRITE;
        break;
    default:
        pOutHdr->status = SMBU_MakeError (SMB_EC_ERRDOS, SMB_ERRDOS_BADACCESS);
        return 0;
    }

    ASSERT_PERMISSION (pCtx, SECURITY_READ);

    /* do we make the file if it doesn't exist?   */
    if(SMB_OPEN_FUNCTION_CREATE(command.open_function) == 1)
    {
        if (flags & RTP_FILE_O_RDONLY)
            mode = RTP_FILE_S_IREAD;
        else if (flags & RTP_FILE_O_WRONLY)
            mode = RTP_FILE_S_IWRITE;
        else
            mode = RTP_FILE_S_IWRITE | RTP_FILE_S_IREAD;

        flags |= RTP_FILE_O_CREAT;
    }
/*  mode =  command.file_attributes & 0x01 ? RTP_FILE_S_IWRITE : 0;   */
    mode |= command.file_attributes & 0x02 ? RTP_FILE_S_HIDDEN : 0;
    mode |= command.file_attributes & 0x04 ? RTP_FILE_S_SYSTEM : 0;
    mode |= command.file_attributes & 0x20 ? RTP_FILE_S_ARCHIVE : 0;

    /* what do we do if the file exists?   */
    switch(SMB_OPEN_FUNCTION_OPEN(command.open_function))
    {
    case 0:/*fail */
        flags |= RTP_FILE_O_CREAT | RTP_FILE_O_EXCL;
        break;
    case 1:/*open file */
        break;
    case 2:/*truncate file */
        flags |= RTP_FILE_O_TRUNC;
        break;
    default:
        break;
    }

    pTree = SMBU_GetTree (pCtx, pCtx->tid);
    r = OpenOrCreate (pCtx, pTree, command.filename, (word)flags, (word)mode, &externalFid, &fid);

    if (r != 0)
    {
        pOutHdr->status = r;
        return 0;
    }
    else
    {
        RTSMB_OPEN_AND_X_R response;
        SMBFSTAT stat;

        SMBFIO_Stat (pCtx, pCtx->tid, command.filename, &stat);

        response.next_command = command.next_command;
        response.fid = (word) externalFid;
        response.server_fid = (dword)fid;

        if (flags & RTP_FILE_O_CREAT)
            response.action = 2;
        else if (flags & RTP_FILE_O_TRUNC)
            response.action = 3;
        else
            response.action = 1;

        response.device_state = 0;
        response.file_type = pTree->type == ST_PRINTQ ? SMB_FILE_TYPE_PRINTER : SMB_FILE_TYPE_DISK;
        response.granted_access = 0;
        SMB_ACCESS_MODE_SET_SHARING (response.granted_access, 4);   /* deny none.  VFILE limitation */
        SMB_ACCESS_MODE_SET_ACCESS (response.granted_access, permissions);
        response.file_size = stat.f_size;
        response.last_write_time = rtsmb_util_time_ms_to_unix (stat.f_wtime64);
        response.file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);

        WRITE_SMB_AND_X (srv_cmd_fill_open_and_x);
    }

    return command.next_command;
} /* End ProcTreeConAndx */


/* --------------------------------------------------- /
 * NT Create Andx Command                              /
 *                                                     /
 * PSMB_SESSIONCTX pCtx - the session ctx              /
 * PSMB_HEADER pInHdr - the incoming smb header        /
 * PFVOID *pInBuf - pointer to input buffer            /
 * PSMB_HEADER pOutHdr - the outgoing smb header       /
 * PFVOID *pOutBuf - pointer to output buffer          /
 *                                                     /
 * This command opens or creates a file or directory   /
 *                                                     /
 * Returns: 0 on error, value of next andx command on  /
 *          success                                    /
 * -------------------------------------------------- */

int ProcNTCreateAndx (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID *pInBuf, PRTSMB_HEADER pOutHdr, PFVOID *pOutBuf)
{
    RTSMB_NT_CREATE_AND_X command;
    PTREE pTree;
    int flags = 0, mode;
    byte permissions = 5; /* HAD TO SET IT TO A USELESS VALUE _YI_ */
    int fid;
    dword r;
    word externalFid;
    RTSMB_NT_CREATE_AND_X_R response;
    SMBFSTAT stat;
    BBOOL wants_read = FALSE, wants_write = FALSE, wants_attr_write = FALSE;


    ASSERT_UID (pCtx);
    ASSERT_TID (pCtx);

    command.filename_size = (word) (pCtx->tmpSize & 0xFFFF);
    command.filename = (PFRTCHAR) pCtx->tmpBuffer;
    READ_SMB_AND_X (srv_cmd_read_nt_create_and_x);


    if (ON (command.desired_access, 0x1) ||
        ON (command.desired_access, 0x20) ||
        ON (command.desired_access, 0x20000) ||
        ON (command.desired_access, 0x10000000) ||
        ON (command.desired_access, 0x20000000) ||
        ON (command.desired_access, 0x80000000))
    {
        wants_read = TRUE;
    }
    if (ON (command.desired_access, 0x2) ||
        ON (command.desired_access, 0x4) ||
        ON (command.desired_access, 0x40) ||
        ON (command.desired_access, 0x10000) ||
        ON (command.desired_access, 0x10000000) ||
        ON (command.desired_access, 0x40000000))
    {
        wants_write = TRUE;
    }
    if (ON (command.desired_access, 0x10) ||
        ON (command.desired_access, 0x100) ||
        ON (command.desired_access, 0x4000) ||
        ON (command.desired_access, 0x8000) ||
        ON (command.desired_access, 0x2000000))
    {
        wants_attr_write = TRUE;
    }
    if (wants_read && wants_write)
    {
        /* reading and writing   */
        flags |= RTP_FILE_O_RDWR;
        permissions = SECURITY_READWRITE;
    }
    else if (wants_read)
    {
        /* reading only   */
        flags |= RTP_FILE_O_RDONLY;
        permissions = SECURITY_READ;
    }
    else if (wants_write)
    {
        /* writing only   */
        flags |= RTP_FILE_O_WRONLY; /* was RTP_FILE_O_RDWR _YI_ */
        permissions = SECURITY_WRITE;
    }

    if (wants_attr_write)
    {
        permissions = SECURITY_READWRITE;
    }

    ASSERT_PERMISSION (pCtx, permissions);

    /* do we make the file if it doesn't exist?   */
    switch (command.create_disposition)
    {
        case NT_CREATE_NEW:
            flags |= RTP_FILE_O_CREAT | RTP_FILE_O_EXCL;
            break;
        case NT_CREATE_ALWAYS:
            flags |= RTP_FILE_O_CREAT | RTP_FILE_O_TRUNC;
            break;
        default:
        case NT_OPEN_EXISTING:
            break;
        case NT_OPEN_ALWAYS:
            flags |= RTP_FILE_O_CREAT;
            break;
        case NT_TRUNCATE:
            flags |= RTP_FILE_O_TRUNC;
            break;
    }

    if (command.ext_file_attributes & 0x80)
    {
            mode = RTP_FILE_S_IWRITE | RTP_FILE_S_IREAD |
                   RTP_FILE_ATTRIB_ARCHIVE; /* VM */
    }
    else
    {
        mode =  command.ext_file_attributes & 0x01 ? RTP_FILE_S_IREAD   : 0;
        mode |= command.ext_file_attributes & 0x02 ? RTP_FILE_S_HIDDEN  : 0;
        mode |= command.ext_file_attributes & 0x04 ? RTP_FILE_S_SYSTEM  : 0;
        mode |= command.ext_file_attributes & 0x20 ? RTP_FILE_S_ARCHIVE : 0;
    }

    pTree = SMBU_GetTree (pCtx, pCtx->tid);

    /* We check if the client is trying to make a directory.  If so, make it   */
    if (ON (command.flags, 0x80) | ON (command.create_options, 0x1))
    {
        if (ON (flags, RTP_FILE_O_CREAT))
        {
            ASSERT_PERMISSION (pCtx, SECURITY_READWRITE);
            SMBFIO_Mkdir (pCtx, pCtx->tid, command.filename);
            TURN_OFF (flags, RTP_FILE_O_EXCL);
        }

        response.directory = TRUE;
    }
    else
    {
        response.directory = FALSE;
    }
    r = OpenOrCreate (pCtx, pTree, command.filename, (word)flags, (word)mode, &externalFid, &fid);
    if (r != 0)
    {
        pOutHdr->status = r;
        return 0;
    }

    SMBFIO_Stat (pCtx, pCtx->tid, command.filename, &stat);

    response.next_command = command.next_command;
    response.oplock_level = 0;
    response.fid = (word) externalFid;

    response.create_action = command.create_disposition;

    response.device_state = 0;
    response.file_type = pTree->type == ST_PRINTQ ? SMB_FILE_TYPE_PRINTER : SMB_FILE_TYPE_DISK;
    response.creation_time_high = stat.f_ctime64.high_time;
    response.creation_time_low = stat.f_ctime64.low_time;
    response.allocation_size_high = 0;
    response.allocation_size_low = stat.f_size;
    response.end_of_file_high = 0;
    response.end_of_file_low = stat.f_size;
    response.change_time_high = stat.f_htime64.high_time;
    response.change_time_low = stat.f_htime64.low_time;
    response.last_access_time_high = stat.f_atime64.high_time;
    response.last_access_time_low = stat.f_atime64.low_time;
    response.last_write_time_high = stat.f_wtime64.high_time;
    response.last_write_time_low = stat.f_wtime64.low_time;
    response.ext_file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);

    WRITE_SMB_AND_X (srv_cmd_fill_nt_create_and_x);

    return command.next_command;
} /* End ProcTreeConAndx */


/* --------------------------------------------------- /
 * Read Andx Command                                   /
 *                                                     /
 * PSMB_SESSIONCTX pCtx - the session ctx              /
 * PSMB_HEADER pInHdr - the incoming smb header        /
 * PFVOID *pInBuf - pointer to input buffer            /
 * PSMB_HEADER pOutHdr - the outgoing smb header       /
 * PFVOID *pOutBuf - pointer to output buffer          /
 *                                                     /
 * This command is used by a client to read from a     /
 * file                                                /
 *                                                     /
 * Returns: 0 on error, value of next andx command on  /
 *          success                                    /
 * -------------------------------------------------- */

int ProcReadAndx (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID *pInBuf, PRTSMB_HEADER pOutHdr, PFVOID *pOutBuf)
{
    dword toRead;
    long bytesRead;
    int fid;
    RTSMB_READ_AND_X command;
    RTSMB_READ_AND_X_R response;

    ASSURE (!assertUid (pCtx), 0);
    ASSURE (!assertTid (pCtx), 0);
    ASSURE (!assertDisk (pCtx), 0);
    ASSURE (!assertPermission (pCtx, SECURITY_READ), 0);

    READ_SMB_AND_X (srv_cmd_read_read_and_x);

    ASSURE (!assertFid (pCtx, command.fid, 0), 0);

    fid = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL,0);

    /* special case return of 0 bytes for reads completely beyond end of file            */
    /* this is not explicit in spec but it makes some sense for very simple file systems */
    /* this kills the file system performance though, so only choose enable this if your */
    /* filesystem needs this                                                             */
#if 0
    if ((bytesRead = SMBFIO_Seek (pCtx, pCtx->tid, fid, 0, RTSMB_SEEK_END)) >= 0 && ((dword) bytesRead) < command.offset)
    {
        response.data_size = 0;
        response.data = (PFBYTE)0;
    }
    else
#endif
    {
        toRead = (dword) MIN (pCtx->tmpSize, command.max_count);

        if (SMBFIO_Seeku32 (pCtx, pCtx->tid, fid, command.offset) == 0xffffffff)
        {
            pOutHdr->status = SMBU_MakeError (SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
            return 0;
        }
        else if ((bytesRead = SMBFIO_Read (pCtx, pCtx->tid, fid, pCtx->tmpBuffer, toRead)) < 0)
        {
            pOutHdr->status = SMBU_MakeError (SMB_EC_ERRHRD, SMB_ERRHRD_READ);
            return 0;
        }
        else
        {
            response.next_command = command.next_command;
            response.data_size = (dword)bytesRead;
            response.data = pCtx->tmpBuffer;
/*          PRINTF (("asked for %i bytes, got %i bytes @ offset %i\n", spaceLeft, bytesRead, pInParam->offset));   */
        }
    }

    WRITE_SMB_AND_X (srv_cmd_fill_read_and_x);

    return command.next_command;
} /* End ProcReadAndx */

/*
================

    PSMB_SESSIONCTX pCtx - The context for this smb session
    PSMB_HEADER1 pInSmbHdr - the top-level header for the incoming smb packet
    PSMB_HEADER1 pOutSmbHdr - the top-level header for the out going smb packet
================
*/
int ProcWriteAndx (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID *pInBuf, PRTSMB_HEADER pOutHdr, PFVOID *pOutBuf)
{
    RTSMB_WRITE_AND_X command;
    int fid;
    int resp;

    ASSURE (!assertUid (pCtx), 0);
    ASSURE (!assertTid (pCtx), 0);
    ASSURE (!assertDisk (pCtx), 0);
    ASSURE (!assertPermission (pCtx, SECURITY_WRITE), 0);

    command.data_size = pCtx->tmpSize;
    command.data = pCtx->tmpBuffer;
    READ_SMB_AND_X (srv_cmd_read_write_and_x);

    ASSURE (!assertFid (pCtx, command.fid, 0), 0);

    fid = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL,0);

    if (SMBFIO_Seeku32 (pCtx, pCtx->tid, fid, command.offset) == 0xffffffff)
    {
        pOutHdr->status = SMBU_MakeError (SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
        return 0;
    }
    else if ((resp = SMBFIO_Write (pCtx, pCtx->tid, fid, pCtx->tmpBuffer, (word) command.data_size)) < 0)
    {
        pOutHdr->status = SMBU_MakeError (SMB_EC_ERRHRD, SMB_ERRHRD_WRITE);
        return 0;
    }
    else
    {
        RTSMB_WRITE_AND_X_R response;

        response.count = (word)resp;
        response.next_command = command.next_command;

        if (ON (command.write_mode, 1))
            SMBFIO_Flush (pCtx, pCtx->tid, fid);

        WRITE_SMB_AND_X (srv_cmd_fill_write_and_x);
    }

    return command.next_command;
} /* End ProcWriteAndx */

/*
================

    PSMB_SESSIONCTX pCtx - The context for this smb session
    PSMB_HEADER1 pInSmbHdr - the top-level header for the incoming smb packet
    PSMB_HEADER1 pOutSmbHdr - the top-level header for the out going smb packet
================
*/
int ProcLogoffAndx (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID *pInBuf, PRTSMB_HEADER pOutHdr, PFVOID *pOutBuf)
{
    RTSMB_LOGOFF_AND_X command;
    RTSMB_LOGOFF_AND_X_R response;

    ASSURE (!assertUid (pCtx), 0);

    READ_SMB_AND_X (srv_cmd_read_logoff_and_x);

    if (pCtx->uid)   /* sprsprspr */
    {
        User_Shutdown (pCtx, SMBU_GetUser (pCtx, pCtx->uid));
    }

    response.next_command = command.next_command;
    WRITE_SMB_AND_X (srv_cmd_fill_logoff_and_x);

    return command.next_command;
} /* End ProcLogoffAndx */

/*
================

    PSMB_SESSIONCTX pCtx - The context for this smb session
    PSMB_HEADER1 pInSmbHdr - the top-level header for the incoming smb packet
    PSMB_HEADER1 pOutSmbHdr - the top-level header for the out going smb packet
================
*/
int ProcLockingAndx (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID *pInBuf, PRTSMB_HEADER pOutHdr, PFVOID *pOutBuf)
{
    RTSMB_LOCKING_AND_X command;
    RTSMB_LOCKING_AND_X_R response;

    ASSURE (!assertUid (pCtx), 0);

    READ_SMB_AND_X (srv_cmd_read_locking_and_x);

    /* Don't do anything.  This is terrible, since we are claiming we are locking
        byte ranges when we really aren't.  However, this makes some operations a lot
        smoother (since Windows clients get really confused when they are unilaterally
        denied locking requests).  Notably, this allows attribute viewing of files in
        Windows Explorer not overwrite the current attributes.

        This same problem could be fixed in a much better way by actually supporting
        byte range locks.  But, we aren't there yet.
    */

    response.next_command = command.next_command;
    WRITE_SMB_AND_X (srv_cmd_fill_locking_and_x);

    return command.next_command;
} /* End ProcLogoffAndx */

/*
================
ProcAndx is the proccess function for all andx commands.
  ProcAndx will attempt to handle each embeded andx command

    PSMB_HEADER1 pInSmbHdr - the incoming smb
    PSMB_HEADER1 pOutSmbHdr - the outgoing smb

    ret(int) - the total size of the SMB packet
================
*/
BBOOL ProcAndx (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    int next_command;
    int header_size;
    dword last_body_size;


    next_command = pInHdr->command;

    header_size = srv_cmd_fill_header (pOutBuf, pOutBuf, (rtsmb_size)SMB_BUFFER_SIZE, pOutHdr);
    ASSURE (header_size != -1, FALSE);
    pOutBuf = PADD (pOutBuf, header_size);
    pCtx->outBodySize = (dword)header_size;

    while (next_command != SMB_COM_NONE)
    {
        last_body_size = pCtx->outBodySize;
        switch (next_command)
        {
        case SMB_COM_SESSION_SETUP_ANDX:
            next_command = ProcSetupAndx (pCtx, pInHdr, &pInBuf, pOutHdr, &pOutBuf);
            break;
        case SMB_COM_TREE_CONNECT_ANDX:
            next_command = ProcTreeConAndx (pCtx, pInHdr, &pInBuf, pOutHdr, &pOutBuf);
            break;
        case SMB_COM_OPEN_ANDX:
            next_command = ProcOpenAndx (pCtx, pInHdr, &pInBuf, pOutHdr, &pOutBuf);
            break;
        case SMB_COM_READ_ANDX:
            next_command = ProcReadAndx (pCtx, pInHdr, &pInBuf, pOutHdr, &pOutBuf);
            break;
        case SMB_COM_WRITE_ANDX:
            next_command = ProcWriteAndx (pCtx, pInHdr, &pInBuf, pOutHdr, &pOutBuf);
            break;
        case SMB_COM_LOGOFF_ANDX:
            next_command = ProcLogoffAndx (pCtx, pInHdr, &pInBuf, pOutHdr, &pOutBuf);
            break;
        case SMB_COM_NT_CREATE_ANDX:
            next_command = ProcNTCreateAndx (pCtx, pInHdr, &pInBuf, pOutHdr, &pOutBuf);
            break;
        case SMB_COM_LOCKING_ANDX:
            /* we don't really handle byte range locking yet (mike)   */
            next_command = ProcLockingAndx (pCtx, pInHdr, &pInBuf, pOutHdr, &pOutBuf);
            /*pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_NOSUPPORT);   */
            break;
        default:
            pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD);
            break;
        }

        if (next_command < 0)
        {
            pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);
            break;
        }

        if (next_command == 0 || pOutHdr->status != 0)
        {
            break;
        }
    }

    /* fill in header again, because it might have changed   */
    header_size = srv_cmd_fill_header (pCtx->write_origin, pCtx->write_origin,
        (rtsmb_size)SMB_BUFFER_SIZE, pOutHdr);
    if (header_size == -1)
    {
        pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);
    }

    if (pOutHdr->status)
    {
        pCtx->outBodySize = last_body_size + 3;
        tc_memset (PADD (pCtx->write_origin, last_body_size), 0, 3);
    }

    return TRUE;
} /* End ProcAndx */


/*
================
Proccess Negotiate protocol requests.  This function
  figures out what the highest supported dialog on both machines can be used for the
  remainder of the session.

================
*/
BBOOL ProcNegotiateProtocol (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    int i, entry, bestEntry;
    SMB_DIALECT_T dialect = DIALECT_NONE;
    int authmode;
    rtsmb_char dialect_bufs[10][21];
    PFRTCHAR dialects[10];
    RTSMB_NEGOTIATE command;

    for (i = 0; i < 10; i++)
    {
        dialects[i] = dialect_bufs[i];
        *dialects[i]=0;
    }

    command.num_dialects = 10;
    command.string_size = 20;
    command.dialects = dialects;
    READ_SMB (srv_cmd_read_negotiate);

    /**
     * Sending more than one negotiate is an error, cannot renegotiate
     * the dialect
     */
    if (pCtx->dialect != DIALECT_NONE)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
        return TRUE;
    }

    for (entry = 0; entry < command.num_dialects; entry++)
    {
        /*check dialect field against dialect list   */
        for (i = PC_NETWORK; i < NUM_DIALECTS; i++)
        {
#ifdef SUPPORT_SMB2   /* exclude rest of file */
            if (dialectList[i].name == srv_dialect_smb2002 || dialectList[i].name == srv_dialect_smb2xxx)
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "ProcNegotiateProtocol:  Temporarilly Ignoring client COM_NEGOTIATE request with 2.002 option. !!!!!!!!!!!!!!\n",0);
                continue;
            }
#endif
            if (SMBU_DoesContain (dialects[entry], dialectList[i].name) == TRUE)
            {
                if ((dialect == DIALECT_NONE)
                    || (dialectList[dialect].priority < dialectList[i].priority))
                {
                    dialect = dialectList[i].dialect;
                    bestEntry = entry;
                }
            }
        }
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "ProcNegotiateProtocol:  dialect == %d Best entry == %X\n",(int)dialect,(int)bestEntry );
    authmode = pCtx->accessMode;

    if ((dialect <= PC_NETWORK) || (dialectList[dialect].priority < 1))
    {
        RTSMB_NEGOTIATE_BAD_R response;

        response.dialect_index = (word)bestEntry;

        WRITE_SMB (srv_cmd_fill_negotiate_bad);
    }
    else if (dialect >= NT_LM)
    {
        RTSMB_NEGOTIATE_R response;
        response.dialect_index = (word)bestEntry;
        response.security_mode = 0;
        response.security_mode = 0;
        if (authmode == AUTH_USER_MODE)  response.security_mode |= 1;
#if (INCLUDE_RTSMB_ENCRYPTION)
        response.security_mode |= 2; /* encrypted */
#endif
        response.max_mpx_count = 1; /* mpx not supported, BUT WARNING: setting this to 0 freezes at least win95 */
        response.max_vcs = prtsmb_srv_ctx->max_uids_per_session;
        response.max_buffer_size = pCtx->readBufferSize;
        response.max_raw_size = SMB_BIG_BUFFER_SIZE;
        response.session_id = SMB_MAKE_SESSIONKEY (pCtx);   /* unique identifier for this session */
        response.capabilities = 0;

        if (prtsmb_srv_ctx->num_big_buffers > 0)
        {
            response.capabilities |= CAP_RAW_MODE;
        }


#if (INCLUDE_RTSMB_UNICODE)
        response.capabilities |= CAP_UNICODE;
#endif

        /**
         * If we don't set this, WinNT will send malformed FIND_FIRST2
         * commands to us.  So, NT_FIND needs to be on.
         */
        response.capabilities |= CAP_NT_FIND;

        /**
         * If we don't set this, Win2K will send malformed commands to us.
         * (unicode strings, but header says ASCII)  So, NT_SMBS needs to be on.
         */
        response.capabilities |= CAP_NT_SMBS;

        response.time_high = 0;
        response.time_low = 0;
        response.time_zone = 0x00F0;
        response.challenge_size = 8;

        for (i = 0; i < 4; i++)
        {
            word randnum = (word) tc_rand();    /* returns 15 bits of random data */
            tc_memcpy (&(pCtx->encryptionKey[i * 2]), &randnum, 2);
        }

        response.challenge = pCtx->encryptionKey;

        response.valid_guid = FALSE;
        response.valid_domain = FALSE;

#ifdef SUPPORT_SMB2
#if (0)
THIS IS WRONG
        if (dialect >= SMB2_2002) /* PVO */
        {
            RTSMB2_NEGOTIATE_R response;

            response.StructureSize      = 65;
            response.SecurityMode       = SMB2_NEGOTIATE_SIGNING_ENABLED;
            response.DialectRevision    = dialect;
            response.Reserved = 0;
            response.MaxTransactSize    =  pCtx->readBufferSize;
            response.MaxReadSize        =  pCtx->readBufferSize;
            response.MaxWriteSize       =  pCtx->readBufferSize;

            /* These may be wrong. Check with sniffer   */
            response.SystemTime_low        = 0;
            response.SystemTime_high       = 0;
            response.ServerStartTime_low   = 0;
            response.ServerStartTime_high  = 0;
            /* Set to zero. This should cause the client to revert to security non   */
            response.SecurityBufferOffset = 0;
            response.SecurityBufferLength = 0;
            response.pSecurityBuffer = 0;
            response.Reserved2 = 0;
    
            /* Passes srv_cmd_fill_negotiate_smb2 pOutHdr, and &response   */
            WRITE_SMB2 (cmd_fill_negotiate_response_smb2);
        }
        else
#endif
#endif
        {
            /* and copy to buffer   */
            WRITE_SMB (srv_cmd_fill_negotiate_nt);
        }
    }
    else
    {
        RTSMB_NEGOTIATE_R response;

        response.dialect_index = (word)bestEntry;
        response.security_mode = authmode == AUTH_USER_MODE ? 1 : 0; /* user based */
#if (INCLUDE_RTSMB_ENCRYPTION)
        response.security_mode |= 2; /* encrypted */
#endif
        response.max_mpx_count = 1; /* mpx not supported, BUT WARNING: setting this to 0 freezes at least win95 */
        response.max_vcs = prtsmb_srv_ctx->max_uids_per_session;
        response.max_buffer_size = pCtx->readBufferSize;
        response.max_raw_size = SMB_BIG_BUFFER_SIZE;
        response.session_id = SMB_MAKE_SESSIONKEY (pCtx);   /* unique identifier for this session */
        response.time_zone = 0x00F0;
        response.challenge_size = 8;

        for (i = 0; i < 4; i++)
        {
            word randnum = (word) tc_rand();    /* returns 15 bits of random data */
            tc_memcpy (&(pCtx->encryptionKey[i * 2]), &randnum, 2);
        }

        response.challenge = pCtx->encryptionKey;

        response.valid_guid = FALSE;
        response.valid_domain = FALSE;

        /* and copy to buffer   */
        WRITE_SMB (srv_cmd_fill_negotiate_pre_nt);
    }

    pCtx->dialect = dialect;

    if (authmode == AUTH_SHARE_MODE)
    {
        /* set up defaults for these, so we don't need session setup command   */
        pCtx->useableBufferSize = (word) (SMB_BUFFER_SIZE & 0xFFFF);
        pCtx->writeBufferSize = pCtx->useableBufferSize;
        pCtx->readBufferSize = pCtx->useableBufferSize;

        User_Init (&pCtx->uids[0]);
        pCtx->uids[0].uid = INVALID_UID;
        pOutHdr->uid = INVALID_UID;
        pCtx->uid = INVALID_UID;
        pCtx->uids[0].authId = 0;
    }

    pOutHdr->flags &= NOT_FLAG(byte,SMB_FLG_SUBDIALECTSUPPORT); /* ~SMB_FLG_SUBDIALECTSUPPORT;  we don't support locking */

    return TRUE;
} /* End ProcNegotiateProtocol */

/*
================
Handles requests for connecting to a tree.
    SMB_SESSIONCTX_T RTSMB_FAR *pSmbCtx - contect for this session
    SMB_HEADER1_T RTSMB_FAR *pHdr1 - First half of smb header pair
    SMB_HEADER2_T RTSMB_FAR *pHdr2 - Second hafl of smb header pair
================
*/
BBOOL ProcTreeConnect (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_TREE_CONNECT command;
    rtsmb_char service[12];
    rtsmb_char share[RTSMB_MAX_SHARENAME_SIZE + 1];
    int tid;

    ASSERT_UID (pCtx)

    command.service = service;
    command.service_size = 11;
    command.password = (PFRTCHAR) pCtx->tmpBuffer;
    command.password_size = CFG_RTSMB_MAX_PASSWORD_SIZE;
    command.share = share;
    command.share_size = RTSMB_MAX_SHARENAME_SIZE;
    READ_SMB (srv_cmd_read_tree_connect);

    /* make sure the password field an array of bytes   */
    rtsmb_util_rtsmb_to_ascii (command.password, (PFCHAR) command.password, CFG_RTSMB_USER_CODEPAGE);

    tid = SR_GetTreeId(command.share, command.service);

    if (tid >= 0)
    {
        byte access;
        PSR_RESOURCE pResource;

        CLAIM_SHARE ();

        pResource = SR_ResourceById ((word) tid);

        /**
         * We first see what mode the server was in when the user logged in.
         * This will let us know how to get access info.
         */
        switch (pCtx->accessMode)
        {
        case AUTH_SHARE_MODE:
            if (Auth_DoPasswordsMatch (pCtx, 0, 0, pResource->password, 0, (PFBYTE) command.password) == TRUE)
            {
                access = pResource->permission;
            }
            else
            {
                SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_BADPW);
                RELEASE_SHARE ();
                return TRUE;
            }
            break;
        case AUTH_USER_MODE:
        default:
            access = Auth_BestAccess (pCtx, (word) tid);
            break;
        }

        /**
         * If they have *some* access, let them connect and browse the share.
         */
        if (access != SECURITY_NONE)
        {
            PTREE tree;
            RTSMB_TREE_CONNECT_R response;
            word external;

            tree = SMBU_GetTree (pCtx, -1);

            if (!tree)
            {
                SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
                RELEASE_SHARE ();
                return TRUE;
            }

            external = (word) (((dword) tree) & 0x0000FFFF);
            pOutHdr->tid = tree->external = external;
            tree->internal = (word)tid;

            Tree_Init (tree);
            tree->access = access;
            tree->type = pResource->stype;

            response.max_buffer_size = (word)pCtx->readBufferSize;
            response.tid = pOutHdr->tid;
            WRITE_SMB (srv_cmd_fill_tree_connect);
        }
        else
        {
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ACCESS);
        }

        RELEASE_SHARE ();
    }
    else
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_INVNID);
    }

    return TRUE;
} /* End ProcTreeConnect */

/*
================
    PSMB_SESSIONCTX pSmbCtx - x
    PSMB_HEADER1 pInHdr1 - x
    PSMB_HEADER2 pInHdr2 - x
================
*/
BBOOL ProcTreeDisconnect (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    /* command and response aren't actually used -- no data for this request   */
    PFVOID command;
    PFVOID response;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)

    READ_SMB (srv_cmd_read_tree_disconnect);

    Tree_Shutdown (pCtx, SMBU_GetTree (pCtx, pCtx->tid));

    WRITE_SMB (srv_cmd_fill_tree_disconnect);

    return TRUE;
} /* End ProcTreeDisconnect */

/*
================
SMB_COM_SEARCH is an older command.  I don't think Win98 supports
  it correctly thus this function is unreliable

    SMB_SESSIONCTX_T RTSMB_FAR *pCtx - contex for this session
    SMB_HEADER1_T RTSMB_FAR *pHdr1 - first header of header pair
    SMB_HEADER2_T RTSMB_FAR *pHdr2 - second header of header pair
================
*/
BBOOL ProcSearch (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_SEARCH command;
    RTSMB_SEARCH_R response;
    RTSMB_DIRECTORY_INFORMATION_DATA data;
    RTSMB_RESUME_KEY key;
    PUSER user;
    PFVOID buf;
    PSMBDSTAT stat;
    byte sid;
    BBOOL isFound;
    int size=0, extra_size;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_DISK (pCtx)

    command.filename = (PFRTCHAR) pCtx->tmpBuffer;
    command.filename_size = pCtx->tmpSize;
    READ_SMB (srv_cmd_read_search);

    user = SMBU_GetUser (pCtx, pCtx->uid);

    if (!command.valid_resume_key) /* first request */
    {
        /**
         * Here we do the same thing as for TRANS2_FIND's.  We associate a search id to the
         * search request, possibly invalidating an older search (because clients often don't
         * close the request properly).  This sid is kept in the resumekey, so if the client
         * wants to resume the search, we know what she is talking about.
         */
        for (sid = 0; sid < prtsmb_srv_ctx->max_searches_per_uid; sid++)
        {
            if (!user->searches[sid].inUse)
            {
                break;
            }
        }

        if (sid == prtsmb_srv_ctx->max_searches_per_uid) /* no free searches */
        {
            byte i;
            sid = 0;

            /* find oldest search, kill it.   */
            for (i = 1; i < prtsmb_srv_ctx->max_searches_per_uid; i++)
            {
                if (user->searches[sid].lastUse < user->searches[i].lastUse)
                {
                    sid = i;
                }
            }

            SMBFIO_GDone (pCtx, user->searches[sid].tid, &user->searches[sid].stat);
        }

        /* build resume key of mostly 0's (except that we do insert the sid)   */
        key.reserved = 0;
        tc_memset (key.filename, 0, 11);
        tc_memset (key.server_data, 0, 5);
        tc_memset (key.client_data, 0, 4);
        key.server_data[0] = sid;

        stat = &user->searches[sid].stat;
        isFound = SMBFIO_GFirst (pCtx, pCtx->tid, stat, command.filename);
    }
    else
    {
        sid = command.resume_key.server_data[0];

        ASSERT_SID (pCtx, sid);

        /* build resumeKey (a straight copy of the client's)   */
        key = command.resume_key;

        stat = &user->searches[sid].stat;
        isFound = SMBFIO_GNext (pCtx, pCtx->tid, stat);
    }

    user->searches[sid].lastUse = rtp_get_system_msec();
    user->searches[sid].inUse = TRUE;
    user->searches[sid].tid = pOutHdr->tid;
    user->searches[sid].pid = pOutHdr->pid;

    response.count = 0;

    WRITE_SMB (srv_cmd_fill_search);
    buf = PADD (pCtx->write_origin, pCtx->outBodySize);
    extra_size = 0;

    while (isFound == TRUE && response.count < command.max_count)
    {
        DATE_STR date;

        data.resume_key = key;
        /* we could fill in the filename for the resumeKey each time,   */
        /* but since we don't use it to resume, I haven't bothered      */

        date = rtsmb_util_time_ms_to_date (stat->fwtime64);
        data.file_size = stat->fsize;
        data.file_attributes = (byte) rtsmb_util_rtsmb_to_smb_attributes (stat->fattributes);
        data.last_write_time = date.time;
        data.last_write_date = date.date;

        if (((PFRTCHAR) stat->short_filename)[0] == '\0')
        {
            /* The filesystem did not give us a short name.  We'll have to make one up.   */
            SMBU_DOSifyName ((PFRTCHAR) stat->filename, data.filename, ' ');
        }
        else
        {
            rtsmb_cpy (data.filename, (PFRTCHAR) stat->short_filename);
        }

        size = srv_cmd_fill_directory_information_data (pCtx->write_origin, buf,
                (rtsmb_size)(SMB_BUFFER_SIZE - size), pOutHdr, &data);
        if (size == -1)
        {
            SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);
            return TRUE;
        }
        buf = PADD (buf, size);
        pCtx->outBodySize += (rtsmb_size)size;
        extra_size += size;

        response.count ++;
        isFound = SMBFIO_GNext (pCtx, user->searches[sid].tid, stat);
    }

    if (isFound == FALSE)
    {
        user->searches[sid].inUse = FALSE;
        SMBFIO_GDone (pCtx, user->searches[sid].tid, stat);
    }

    WRITE_SMB (srv_cmd_fill_search);
    pCtx->outBodySize += (rtsmb_size)extra_size;

    return TRUE;
} /* End ProcSearch */

/*
================
sees if a file exists, and if so, return some info on it
    PSMB_SESSIONCTX pCtx - The current session context
    PSMB_HEADER1 pInHdr1 - incoming smb header
    PSMB_HEADER1 pOutHdr1 - outgoing smb header
================
*/
BBOOL ProcQueryInformation (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_QUERY_INFORMATION command;
    SMBFSTAT stat;
    BBOOL worked;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_DISK (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_READ)

    command.filename = (PFRTCHAR) pCtx->tmpBuffer;
    command.filename_size = SMBF_FILENAMESIZE;
    READ_SMB (srv_cmd_read_query_information);

    worked = SMBFIO_Stat (pCtx, pCtx->tid, command.filename, &stat);

    if(worked == FALSE)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
    }
    else
    {
        RTSMB_QUERY_INFORMATION_R response;

        response.file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);
        response.last_write_time = rtsmb_util_time_ms_to_unix (stat.f_wtime64);
        response.file_size = stat.f_size;

        WRITE_SMB (srv_cmd_fill_query_information);
    }

    return TRUE;
} /* End ProcQueryInformation */

/*
================
return some info on an already opened file
    PSMB_SESSIONCTX pCtx - The current session context
    PSMB_HEADER1 pInHdr1 - incoming smb header
    PSMB_HEADER1 pOutHdr1 - outgoing smb header
================
*/
BBOOL ProcQueryInformation2 (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_QUERY_INFORMATION2 command;
    SMBFSTAT stat;
    BBOOL worked;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_DISK (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_READ)

    READ_SMB (srv_cmd_read_query_information2);

    ASSERT_FID (pCtx, command.fid, FID_FLAG_DIRECTORY)

    worked = SMBFIO_Stat (pCtx, pCtx->tid, SMBU_GetFileNameFromFid (pCtx, command.fid), &stat);

    if(worked == FALSE)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
    }
    else
    {
        RTSMB_QUERY_INFORMATION2_R response;
        DATE_STR adate, wdate, cdate;

        adate = rtsmb_util_time_ms_to_date (stat.f_atime64);
        wdate = rtsmb_util_time_ms_to_date (stat.f_wtime64);
        cdate = rtsmb_util_time_ms_to_date (stat.f_ctime64);
        response.last_access_date = adate.date;
        response.last_access_time = adate.time;
        response.creation_date = cdate.date;
        response.creation_time = cdate.time;
        response.last_write_date = wdate.date;
        response.last_write_time = wdate.time;
        response.file_size = stat.f_size;
        response.file_allocation_size = stat.f_size;
        response.file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);

        WRITE_SMB (srv_cmd_fill_query_information2);
    }

    return TRUE;
} /* End ProcQueryInformation2 */

BBOOL ProcQueryInformationDisk (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    byte command;   /* not used */
    RTSMB_QUERY_INFORMATION_DISK_R response;
    dword blocks;
    dword bfree;
    dword sectors;
    word bytes;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_DISK (pCtx)

    READ_SMB (srv_cmd_read_query_information_disk);

    if (!SMBFIO_GetFree (pCtx, pCtx->tid, &blocks, &bfree, &sectors, &bytes))
    {
        RTSMB_DEBUG_OUTPUT_STR("ProcQueryInformationDisk: Error getting free space.\n", RTSMB_DEBUG_TYPE_ASCII);
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);
    }
    else
    {
    dword t;
        t = blocks > 0xFFFF ? 0xFFFF : (blocks & 0xFFFF);
        response.total_units = (word) t;
        t = sectors > 0xFFFF ? 0xFFFF : (sectors & 0xFFFF);
        response.blocks_per_unit = (word) t;
        response.block_size = bytes;
        t = bfree > 0xFFFF ? 0xFFFF : (bfree & 0xFFFF);
        response.free_units = (word) t;
        WRITE_SMB (srv_cmd_fill_query_information_disk);
    }

    return TRUE;
} /* End ProcQueryInformationDisk */

/*
================

================
*/
BBOOL ProcTransaction (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_TRANSACTION command;
    RTSMB_TRANSACTION_R response;
    int size;
    word setups[5];
    PFVOID buf = pOutBuf;
    rtsmb_char name [75];

    command.name = name;
    command.name_size = 74;
    command.setup = setups;
    command.setup_size = 5;
    size = srv_cmd_read_transaction (pCtx->read_origin, pInBuf,
        (rtsmb_size)(pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin))), pInHdr, &command);

    if (size == -1)
        return FALSE;

    pInBuf = PADD (pInBuf, size);

    /* now write a dummy response so we know where the buffer will be and sub
        functions can write to the correct place.  We will do this again later */
    size = srv_cmd_fill_header (pCtx->write_origin, buf,
        (rtsmb_size)SMB_BUFFER_SIZE, pOutHdr);
    if (size == -1) return FALSE;
    buf = PADD (buf, size);
    response.parameter_count = 0;
    response.parameter = (PFBYTE)0;
    response.data_count = 0;
    response.data = (PFBYTE)0;
    response.setup_size = 0;
    response.setup = (PFWORD)0;
    size = srv_cmd_fill_transaction (pCtx->write_origin, buf,
        (rtsmb_size)(SMB_BUFFER_SIZE - size), pOutHdr, &response);
    if (size == -1) return FALSE;
    buf = PADD (buf, size);

    if (RAP_Proc (pCtx, pInHdr, &command, pInBuf, pOutHdr, &response,
            (rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (buf, pCtx->write_origin))) < 0)
    {
        return FALSE;
    }

    buf = pOutBuf;
    size = srv_cmd_fill_header (pCtx->write_origin, buf,
        (rtsmb_size)SMB_BUFFER_SIZE, pOutHdr);
    if (size == -1) return FALSE;
    pCtx->outBodySize += (rtsmb_size)size;

    buf = PADD (buf, size);
    size = srv_cmd_fill_transaction (pCtx->write_origin, buf,
        (rtsmb_size)(SMB_BUFFER_SIZE - size), pOutHdr, &response);
    if (size == -1) return FALSE;
    pCtx->outBodySize += (rtsmb_size)size;

    return TRUE;
} /* End ProcTransaction */

/*
================

================
*/
BBOOL ProcTransaction2 (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_TRANSACTION command;
    RTSMB_TRANSACTION_R response;
    BBOOL doSend;
    int size;
    word setups[5];
    PFVOID buf = pOutBuf;

    command.name = (PFRTCHAR)0; /* name doesn't matter for trans2's */
    command.setup = setups;
    command.setup_size = 5;
    size = srv_cmd_read_transaction (pCtx->read_origin, pInBuf,
        (rtsmb_size)(pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin))), pInHdr, &command);

    if (size == -1)
        return FALSE;

    pInBuf = PADD (pInBuf, size);

    /* now write a dummy response so we know where the buffer will be and sub
        functions can write to the correct place.  We will do this again later */
    size = srv_cmd_fill_header (pCtx->write_origin, buf,
        (rtsmb_size)SMB_BUFFER_SIZE, pOutHdr);
    if (size == -1) return FALSE;
    pCtx->outBodySize = (rtsmb_size)size;
    buf = PADD (buf, size);
    response.parameter_count = 0;
    response.parameter = (PFBYTE)0;
    response.data_count = 0;
    response.data = (PFBYTE)0;
    response.setup_size = 0;
    response.setup = (PFWORD)0;
    size = srv_cmd_fill_transaction (pCtx->write_origin, buf,
        (rtsmb_size)(SMB_BUFFER_SIZE - size), pOutHdr, &response);
    if (size == -1) return FALSE;
    buf = PADD (buf, size);

    pCtx->outBodySize += (rtsmb_size) size;

    /* Log the command if debugging is enabled   */
    DebugOutputTrans2Command(command.setup[0]);

    switch (command.setup[0])
    {
    case TRANS2_FIND_FIRST2:
        doSend = ST2_FindFirst2 (pCtx, pInHdr, &command, pInBuf, pOutHdr, &response,
            (rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (buf, pCtx->write_origin)));
        break;
    case TRANS2_FIND_NEXT2:
        doSend = ST2_FindNext2 (pCtx, pInHdr, &command, pInBuf, pOutHdr, &response,
            (rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (buf, pCtx->write_origin)));
        break;
    case TRANS2_QUERY_FILE_INFORMATION:
        doSend = ST2_QueryFileInfo (pCtx, pInHdr, &command, pInBuf, pOutHdr, &response,
            (rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (buf, pCtx->write_origin)));
        break;
    case TRANS2_QUERY_FS_INFORMATION:
        doSend = ST2_QueryFSInformation (pCtx, pInHdr, &command, pInBuf, pOutHdr, &response,
            (rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (buf, pCtx->write_origin)));
        break;
    case TRANS2_QUERY_PATH_INFORMATION:
        doSend = ST2_QueryPathInfo (pCtx, pInHdr, &command, pInBuf, pOutHdr, &response,
            (rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (buf, pCtx->write_origin)));
        break;
    case TRANS2_SET_PATH_INFORMATION:
        doSend = ST2_SetPathInformation (pCtx, pInHdr, &command, pInBuf, pOutHdr, &response,
            (rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (buf, pCtx->write_origin)));
        break;
    case TRANS2_SET_FILE_INFORMATION:
        doSend = ST2_SetFileInformation (pCtx, pInHdr, &command, pInBuf, pOutHdr, &response,
            (rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (buf, pCtx->write_origin)));
        break;
    default:
#ifdef RTP_DEBUG
        {
            char* tmpbuf;
            tmpbuf = trans2Commandname(command.setup[0]);
            if (tmpbuf)
            {
                RTSMB_DEBUG_OUTPUT_STR("ProcTransaction2: sub command (", RTSMB_DEBUG_TYPE_ASCII);
                RTSMB_DEBUG_OUTPUT_STR(tmpbuf, RTSMB_DEBUG_TYPE_ASCII);
                RTSMB_DEBUG_OUTPUT_STR(") unhandled\n", RTSMB_DEBUG_TYPE_ASCII);
            }
            else
            {
            char buf[32];
                tmpbuf = buf;
                buf[0] = '\0';
                RTSMB_DEBUG_OUTPUT_STR("ProcTransaction2: unknown sub command <0x ", RTSMB_DEBUG_TYPE_ASCII);
                tmpbuf = rtp_itoa(command.setup[0], tmpbuf, 16);
                RTSMB_DEBUG_OUTPUT_STR(tmpbuf, RTSMB_DEBUG_TYPE_ASCII);
                RTSMB_DEBUG_OUTPUT_STR("> unhandled\n", RTSMB_DEBUG_TYPE_ASCII);
            }
        }
#endif
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD);
        return TRUE;
    }

    buf = pOutBuf;
    size = srv_cmd_fill_header (pCtx->write_origin, buf,
        (rtsmb_size)SMB_BUFFER_SIZE, pOutHdr);
    if (size == -1) return FALSE;
    pCtx->outBodySize = (rtsmb_size)size;
    if (doSend)
    {
        buf = PADD (buf, size);
        size = srv_cmd_fill_transaction (pCtx->write_origin, buf,
            (rtsmb_size)(SMB_BUFFER_SIZE - size), pOutHdr, &response);
        if (size == -1) return FALSE;
        pCtx->outBodySize += (rtsmb_size)size;
    }

    return doSend;
} /* End ProcTransaction2 */

/*
================
This procedure will free resources used by findFirst, findNext
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcFindClose2 (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_FIND_CLOSE2 command;
    byte response;  /* not used */
    PUSER user;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)

    READ_SMB (srv_cmd_read_find_close2);

    ASSERT_SID (pCtx, command.sid);

    user = SMBU_GetUser(pCtx, pCtx->uid);
    SMBFIO_GDone (pCtx, user->searches[command.sid].tid, &user->searches[command.sid].stat);
    user->searches[command.sid].inUse = FALSE;

    WRITE_SMB (srv_cmd_fill_find_close2);

    return TRUE;
} /* End ProcFindClose2 */


/*
================
 This procedure makes sure a directory exists
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcCheckDirectory (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_CHECK_DIRECTORY command;
    byte response;  /* not used */
    PFRTCHAR string;
    SMBFSTAT stat;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_DISK (pCtx)

    string = (PFRTCHAR) pCtx->tmpBuffer;
    command.directory = string;
    command.directory_size = SMBF_FILENAMESIZE;
    READ_SMB (srv_cmd_read_check_directory);

    /**
     * Stat the file.  If it is not present, or is not a directory, return an error.
     */
    if (!SMBFIO_Stat (pCtx, pCtx->tid, string, &stat) ||
        !(stat.f_attributes & RTP_FILE_ATTRIB_ISDIR))
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADPATH);
    }
    else
    {
        WRITE_SMB (srv_cmd_fill_check_directory);
    }

    return TRUE;
} /* End ProcCheckDirectory */


/*
================
This procedure opens a file
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcOpen (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_OPEN command;
    RTSMB_OPEN_R response;
    SMBFSTAT stat;
    PFRTCHAR string;
    word flags = 0, mode;
    int imode;
/*  byte permissions;   */
    int fid;
    PTREE pTree;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)

    command.filename_size = pCtx->tmpSize;
    string = (PFRTCHAR) pCtx->tmpBuffer;
    command.filename = string;
    command.filename_size = SMBF_FILENAMESIZE;
    READ_SMB (srv_cmd_read_open);

    switch (SMB_ACCESS_MODE_ACCESS (command.desired_access))
    {
        case 0: /* read only */
            flags = RTP_FILE_O_RDONLY;
/*          permissions = SECURITY_READ;   */
            response.granted_access = 0;
            break;
        case 1: /* write only */
            flags = RTP_FILE_O_WRONLY;
/*          permissions = SECURITY_WRITE;   */
            response.granted_access = 1;
            break;
        default:
        case 2: /* read and write */
            flags = RTP_FILE_O_RDWR;
/*          permissions = SECURITY_READWRITE;   */
            response.granted_access = 2;
            break;
        case 3: /* execute */
            flags = RTP_FILE_O_RDONLY;
/*          permissions = SECURITY_READ;   */
            response.granted_access = 0;
            break;
    }

    ASSERT_PERMISSION (pCtx, SECURITY_READ)

    pTree = SMBU_GetTree (pCtx, pCtx->tid);

    /**
     * Here we handle pipes.
     */
    if (pTree->type == ST_IPC)/* && !strnicmp (string, "\\PIPE\\", 6)) */
    {
        /* the correct behavior for non-supported pipe files is that they   */
        /* are not-found files                                              */
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
        return TRUE;
    }
    else if (pTree->type == ST_PRINTQ)
    {
        rtsmb_char empty[] = {'\0'};

        /* Ignore whatever they wanted to open, make a temporary filename for them.   */
        /* Usually clients will just send "" anyway.                                  */
        if (SMBU_TemporaryFileName (pCtx, empty, string))
        {
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_FILEEXISTS);
            return TRUE;
        }

        /* don't fail if file doesn't exist.  rather, create it   */
        flags |= RTP_FILE_O_CREAT;
    }

    /**
     * Don't allow clients to open directories.
     */
    if (SMBFIO_Stat (pCtx, pCtx->tid, string, &stat))
    {
        if (stat.f_attributes & RTP_FILE_ATTRIB_ISDIR)
        {
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_NOACCESS);
            return TRUE;
        }
    }

    imode =  command.search_attributes & 0x01 ? RTP_FILE_S_IWRITE  : 0;
    imode |= command.search_attributes & 0x02 ? RTP_FILE_S_HIDDEN  : 0;
    imode |= command.search_attributes & 0x04 ? RTP_FILE_S_SYSTEM  : 0;
    imode |= command.search_attributes & 0x20 ? RTP_FILE_S_ARCHIVE : 0;
    mode = (word) imode;
    fid = SMBFIO_Open (pCtx, pCtx->tid, string, flags, mode);

    if (fid < 0)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
    }
    else
    {
        int external;

        if ((external = SMBU_SetInternalFid (pCtx, fid, string, 0)) < 0)
        {
            SMBFIO_Close (pCtx, pCtx->tid, fid);
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_NOFIDS);
            return TRUE;
        }

        response.fid = (word)external;
        response.file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);
        response.last_write_time = rtsmb_util_time_ms_to_unix (stat.f_wtime64);
        response.file_size = stat.f_size;

        pOutHdr->flags &= NOT_FLAG(byte,SMB_FLG_OPLOCK); /* ~SMB_FLG_OPLOCK;    we refuse all oplock requests */

        WRITE_SMB (srv_cmd_fill_open);
    }

    return TRUE;
} /* End ProcOpen */

/*
================
This procedure closes an open file, sends a small confirmation message
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcClose (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_CLOSE command;
    byte response;
    int fid;
    PTREE pTree;
    word fidflags=0;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)

    READ_SMB (srv_cmd_read_close);

    ASSERT_FID (pCtx, command.fid, FID_FLAG_ALL)

    pTree = SMBU_GetTree (pCtx, pCtx->tid);
    fid = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL, &fidflags);

    /**
     * If we are closing a print file, print it before exit and delete it afterwards.
     */
    if (pTree->type == ST_PRINTQ)
    {
        if (SMBU_PrintFile (pCtx, fid))
            RTSMB_DEBUG_OUTPUT_STR("ProcClose: Printing file on close failed.\n", RTSMB_DEBUG_TYPE_ASCII);
        SMBFIO_Close (pCtx, pCtx->tid, fid);
        SMBFIO_Delete (pCtx, pCtx->tid, SMBU_GetFileNameFromFid (pCtx, command.fid));
    }
    else
    {
        if (fidflags != FID_FLAG_DIRECTORY)
        {
            SMBFIO_Close (pCtx, pCtx->tid, fid);
        }
    }

    SMBU_ClearInternalFid (pCtx, command.fid);

    WRITE_SMB (srv_cmd_fill_close);

    return TRUE;
} /* End ProcClose */

/*
================
This procedure closes an open print file, prints the file, deletes the file
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcClosePrintFile (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_CLOSE_PRINT_FILE command;
    byte response;
    int fid;
/*  PTREE pTree;   */

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)

    READ_SMB (srv_cmd_read_close_print_file);

    ASSERT_FID (pCtx, command.fid, 0)

/*  pTree = SMBU_GetTree (pCtx, pCtx->tid);   */
    fid = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL,0);

    if (SMBU_PrintFile (pCtx, fid))
        RTSMB_DEBUG_OUTPUT_STR("ProcClosePrintFile: Printing file on close failed.\n", RTSMB_DEBUG_TYPE_ASCII);
    SMBFIO_Close (pCtx, pCtx->tid, fid);
    SMBFIO_Delete (pCtx, pCtx->tid, SMBU_GetFileNameFromFid (pCtx, command.fid));

    SMBU_ClearInternalFid (pCtx, command.fid);

    WRITE_SMB (srv_cmd_fill_close_print_file);

    return TRUE;
} /* End ProcClosePrintFile */

/*
================
This procedure reads an open file
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcRead (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_READ command;
    RTSMB_READ_R response;
    word spaceLeft;
    long bytesRead;
    int fid;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_READ)

    READ_SMB (srv_cmd_read_read);

    ASSERT_FID (pCtx, command.fid, 0)

    fid = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL,0);

    response.data = pCtx->tmpBuffer;

    /* special case return of 0 bytes for reads completely beyond end of file            */
    /* this is not explicit in spec but it makes some sense for very simple file systems */
    /* this kills the file system performance though, so only choose enable this if your */
    /* filesystem needs this                                                             */
#if 0
    if ((bytesRead = SMBFIO_Seek (pCtx, pCtx->tid, fid, 0, RTSMB_SEEK_END)) >= 0 && ((dword) bytesRead) < command.offset)
    {
        response.data_size = 0;

        WRITE_SMB (srv_cmd_fill_read);

        return TRUE;
    }
#endif
    spaceLeft = (word) (MIN (command.count, (word) (pCtx->tmpSize & 0xFFFF)));

    if (SMBFIO_Seeku32 (pCtx, pCtx->tid, fid, command.offset) == 0xffffffff)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
    }
    else if ((bytesRead = SMBFIO_Read (pCtx, pCtx->tid, fid, response.data, spaceLeft)) < 0)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRHRD, SMB_ERRHRD_READ);
    }
    else
    {
        response.data_size = (word) (bytesRead & 0xFFFF);

        WRITE_SMB (srv_cmd_fill_read);
    }

    return TRUE;
} /* End ProcRead */

/*
================
This procedure seeks to a location in an open file
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcSeek (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_SEEK command;
    long offset;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_DISK (pCtx)

    READ_SMB (srv_cmd_read_seek);

    ASSERT_FID (pCtx, command.fid, 0)

    offset = SMBFIO_Seek (pCtx, pCtx->tid, SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL, 0),
            (long)command.offset, command.mode);
    if (offset < 0)
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
    else
    {
        RTSMB_SEEK_R response;

        response.offset = (dword) offset;

        WRITE_SMB (srv_cmd_fill_seek);
    }

    return TRUE;
} /* End ProcSeek */


/*
================
This procedure deletes files --may be more than one due to wildcards--

        COMPLIANCE  The field 'searchAttributes' is not respected.  Nor is bit0 of flags2.

    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcDelete (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_DELETE command;
    byte response;
    BBOOL isFound;
    SMBDSTAT stat;
    PFRTCHAR temp;
    PFRTCHAR path = (PFRTCHAR) pCtx->tmpBuffer;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_DISK (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    command.filename = path;
    command.filename_size = SMBF_FILENAMESIZE + 1;
    READ_SMB (srv_cmd_read_delete);

    isFound = SMBFIO_GFirst (pCtx, pCtx->tid, &stat, path);

    SMBU_GetPath (path, path);
    temp = &path[rtsmb_len (path)];
    temp[0] = '\\';
    temp[1] = '\0';

    if (!isFound)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
    }
    else
    {
        while (isFound)
        {
            rtsmb_cat (path, (PFRTCHAR) stat.filename);

            /**
             * We should take on the responsibility of making sure the client does not
             * try and delete an open file.
             */
            if (SMBU_GetInternalFidFromName (pCtx, path) >= 0)
            {
                SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_NOACCESS);
                break;
            }

            /* bail on first error.  Could be made to try and delete the rest.       */
            /* but, there is no way to report which file was erroneous, so I think   */
            /* doing as little as possible is better, so the client can then do some */
            /* detective work.                                                       */
            if (!SMBFIO_Delete (pCtx, pCtx->tid, path))
            {
                /* maybe they tried deleting while the file was open?   */
                SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_NOACCESS);
                break;
            }
            temp[1] = '\0';

            isFound = SMBFIO_GNext (pCtx, pCtx->tid, &stat);
        }
    }

    SMBFIO_GDone (pCtx, pCtx->tid, &stat);

    WRITE_SMB (srv_cmd_fill_delete);

    return TRUE;
}


/*
================
This procedure writes data to a file
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcWrite (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_WRITE command;
    word written;
    word spaceLeft;
    int fid;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    command.data = pCtx->tmpBuffer;
    command.data_size = (word) (pCtx->tmpSize & 0xFFFF);    /* only use what protocol can handle */

    if (srv_cmd_read_write (pCtx->read_origin, pInBuf, pCtx->current_body_size - (rtsmb_size)(PDIFF(pInBuf, pCtx->read_origin)), pInHdr, &command) == -1)
    {
        SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);
        return TRUE;
    }

    ASSERT_FID (pCtx, command.fid, 0)

    fid = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL,0);

    spaceLeft = MIN (command.count, command.data_size);


    written = SMBU_WriteToFile (pCtx, fid, command.data, spaceLeft, FALSE, command.offset);
    if (command.data_size == 0)
    {
        SMBFIO_Truncate (pCtx, pCtx->tid, fid, command.offset);
    }
    if (written != 0 || command.count == 0)
    {
        RTSMB_WRITE_R response;
        response.count = written;

        WRITE_SMB (srv_cmd_fill_write);
    }

    return TRUE;
}

/*
================
This procedure echos data sent to the server from a client
Different than most Proc* functions, this does not rely on procsmbpacket
to send its info, instead sending out data itself.
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcEcho (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_ECHO command;
    RTSMB_ECHO_R response;
    word i;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)

    command.data = pCtx->tmpBuffer;
    command.data_size = (word) (pCtx->tmpSize & 0xFFFF); /* only use what protocol can handle */
    READ_SMB (srv_cmd_read_echo);

    response.data = pCtx->tmpBuffer;
    response.data_size = command.data_size;
    for (i = 0; i < command.count; i++)
    {
        response.sequence_number = i;
        WRITE_SMB (srv_cmd_fill_echo);

        SMBS_SendMessage (pCtx, pCtx->outBodySize, TRUE);
    }

    return FALSE;
}

/*
================
This procedure writes all changes to a file to disk
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcFlush (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_FLUSH command;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)

    READ_SMB (srv_cmd_read_flush);

    /**
     * Special Case:  According to spec, if a fid of 0xFFFF is
     * passed, we flush all the files this uid/pid pair has open.
     */
    if (command.fid == 0xFFFF)
    {
        PUSER user = SMBU_GetUser (pCtx, pCtx->uid);
        int i;

        for (i = 0; i < prtsmb_srv_ctx->max_fids_per_uid; i++)
        {
            PFID fid = user->fids[i];

            if (!fid)
                continue;

            if (fid->pid == pCtx->pid)
            {
                int internal;

                internal = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL, 0);

                /* this isn't amazingly helpful, but at least they'll know   */
                /* *something* went wrong                                    */
                if (!SMBFIO_Flush (pCtx, pCtx->tid, internal))
                    SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRHRD, SMB_ERRHRD_GENERAL);
            }
        }
    }
    else
    {
        int fid;

        ASSERT_FID (pCtx, command.fid, 0)

        fid = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL,0);

        if (!SMBFIO_Flush (pCtx, pCtx->tid, fid))
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRHRD, SMB_ERRHRD_GENERAL);
        else
        {
            byte response;

            WRITE_SMB (srv_cmd_fill_flush);
        }
    }

    return TRUE;
}

/*
================
This procedure renames a file (or files with wildcards)

                COMPLIANCE: does not respect search attributes
                            doesn't fail if already there

    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcRename (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_RENAME command;
    byte response;  /* not used */
    SMBDSTAT stat;
    BBOOL isFound;
    rtsmb_char oldpattern[SMBF_FILENAMESIZE + 1];
    rtsmb_char newpattern[SMBF_FILENAMESIZE + 1];
    rtsmb_char matched[SMBF_FILENAMESIZE + 1];
    rtsmb_char newname [SMBF_FILENAMESIZE + 1];
    PFRTCHAR temp;
    rtsmb_char slashslash[] = {'\\', '\\', '\0'};

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    command.old_filename = oldpattern;
    command.old_filename_size = SMBF_FILENAMESIZE + 1;
    command.new_filename = newpattern;
    command.new_filename_size = SMBF_FILENAMESIZE + 1;
    READ_SMB (srv_cmd_read_rename);

    /* both must be relative to a tid   */
    if (rtsmb_ncmp (oldpattern, slashslash, 2) == 0 ||
        rtsmb_ncmp (newpattern, slashslash, 2) == 0)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_DIFFDEVICE);
        return TRUE;
    }

    /* must make sure the paths of each name exist   */
    ASSERT_PATH (pCtx, oldpattern)
    ASSERT_PATH (pCtx, newpattern)

    SMBU_GetPath (oldpattern, matched);

    /* append to destination string but only if directories are specified   */
    temp = &matched[rtsmb_len (matched)];
    if (rtsmb_len (matched))  /* sprspr */
    {
        temp[0] = '\\';
        temp[1] = '\0';
    }

    isFound = SMBFIO_GFirst (pCtx, pCtx->tid, &stat, oldpattern);

    while (isFound == TRUE)
    {
        PFRTCHAR result;

        rtsmb_cat (matched, (PFRTCHAR) stat.filename);
        result = SMBU_FitWildcards (oldpattern, matched, newpattern, newname);

        if (result == (PFRTCHAR)0)
        {
            /*PRINTF (("Odd.  GFirst failed to match " RTSMB_STR_TOK "->" RTSMB_STR_TOK
                " to get " RTSMB_STR_TOK "->" RTSMB_STR_TOK ".\n",
                oldpattern, newpattern, matched, result)); */

            RTSMB_DEBUG_OUTPUT_STR ("Odd.  GFirst failed to match ", RTSMB_DEBUG_TYPE_ASCII);
            RTSMB_DEBUG_OUTPUT_STR (oldpattern, RTSMB_DEBUG_TYPE_SYS_DEFINED);
            RTSMB_DEBUG_OUTPUT_STR ("->", RTSMB_DEBUG_TYPE_ASCII);
            RTSMB_DEBUG_OUTPUT_STR (newpattern, RTSMB_DEBUG_TYPE_SYS_DEFINED);
            RTSMB_DEBUG_OUTPUT_STR (" to get ", RTSMB_DEBUG_TYPE_ASCII);
            RTSMB_DEBUG_OUTPUT_STR (matched, RTSMB_DEBUG_TYPE_SYS_DEFINED);
            RTSMB_DEBUG_OUTPUT_STR ("->", RTSMB_DEBUG_TYPE_ASCII);
/*            RTSMB_DEBUG_OUTPUT_STR (result, RTSMB_DEBUG_TYPE_SYS_DEFINED);   */
            RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRHRD, SMB_ERRHRD_GENERAL);
            break;
        }

/*      PRINTF (("renaming " RTSMB_STR_TOK " to " RTSMB_STR_TOK "\n", matched, result));   */
        /* if we fail, it's probably because of the target existing                        */
        if (!SMBFIO_Rename (pCtx, pCtx->tid, matched, result))
        {
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_FILEEXISTS);
            break;
        }

        temp[1] = '\0';

        isFound = SMBFIO_GNext (pCtx, pCtx->tid, &stat);
    }

    SMBFIO_GDone (pCtx, pCtx->tid, &stat);

    WRITE_SMB (srv_cmd_fill_rename);

    return TRUE;
}

/* helper file for copy                                    */
/* returns true if all good, false if something went wrong */
/* an offset of 0 means truncate                           */
BBOOL transferFileTo (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pHdr, PFVOID pBuf, PFRTCHAR source, word sourceTid,
    PFRTCHAR dest, word destTid, BBOOL truncate)
{
#define TRANSFER_FILE_TO_BUFFER_SIZE 1024
    byte buf [TRANSFER_FILE_TO_BUFFER_SIZE];
    int sourceFid, destFid;
    word flags;
    long read, written;
    BBOOL done;

    flags = RTP_FILE_O_RDONLY;

    if ((sourceFid = SMBFIO_Open (pCtx, sourceTid, source, flags, RTP_FILE_S_IREAD | RTP_FILE_S_IWRITE)) < 0) {
        SMBU_FillError (pCtx, pHdr, SMB_EC_ERRHRD, SMB_ERRHRD_GENERAL); return FALSE; }

    flags = RTP_FILE_O_WRONLY | RTP_FILE_O_CREAT;
    if (truncate == TRUE) flags |= RTP_FILE_O_TRUNC;

    if ((destFid = SMBFIO_Open (pCtx, destTid, dest, flags, RTP_FILE_S_IREAD | RTP_FILE_S_IWRITE)) < 0) {
        SMBU_FillError (pCtx, pHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE); return FALSE; }

    if (SMBFIO_Seek (pCtx, destTid, destFid, 0, RTSMB_SEEK_END) == -1) {
        SMBU_FillError (pCtx, pHdr, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK); return FALSE; }

    do {
        if ((read = SMBFIO_Read (pCtx, sourceTid, sourceFid, buf, TRANSFER_FILE_TO_BUFFER_SIZE)) < 0) {
            SMBU_FillError (pCtx, pHdr, SMB_EC_ERRHRD, SMB_ERRHRD_READ); return FALSE; }

        if (read < TRANSFER_FILE_TO_BUFFER_SIZE)
            done = TRUE;

        if ((written = SMBFIO_Write (pCtx, destTid, destFid, buf, (dword)read)) < 0) {
            SMBU_FillError (pCtx, pHdr, SMB_EC_ERRHRD, SMB_ERRHRD_WRITE); return FALSE; }
    } while (done == FALSE);

    return TRUE;
}

/**
 * Copy and Move share so much code, that I wrote this helper function to make
 * things easier to maintain.  Although the 'move' structs are used here, they are
 * identical to copy's struct.  |isCopy| indicates whether we are copying or moving.
 */
BBOOL ProcCopyMove (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, BBOOL isCopy)
{
    SMBDSTAT stat;
    BBOOL isFound;
/*  word oldFileNameSize, newFileNameSize;   */
    rtsmb_char oldpattern[SMBF_FILENAMESIZE + 1];
    rtsmb_char newpattern[SMBF_FILENAMESIZE + 1];
    rtsmb_char matched[SMBF_FILENAMESIZE + 1];
    rtsmb_char newname [SMBF_FILENAMESIZE + 1];
    PFRTCHAR temp;
    word count = 0;
    word tid2;
    word open_function;
    word flags;
    rtsmb_char slashslash[] = {'\\', '\\', '\0'};

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    if (isCopy)
    {
        RTSMB_COPY command;

        command.old_filename = oldpattern;
        command.old_filename_size = SMBF_FILENAMESIZE;
        command.new_filename = newpattern;
        command.new_filename_size = SMBF_FILENAMESIZE;

        READ_SMB (srv_cmd_read_copy);

        tid2 = command.tid2;
        open_function = command.open_function;
        flags = command.flags;
    }
    else
    {
        RTSMB_MOVE command;

        command.old_filename = oldpattern;
        command.old_filename_size = SMBF_FILENAMESIZE;
        command.new_filename = newpattern;
        command.new_filename_size = SMBF_FILENAMESIZE;

        READ_SMB (srv_cmd_read_move);

        tid2 = command.tid2;
        open_function = command.open_function;
        flags = command.flags;
    }

/*  oldFileNameSize = rtsmb_len (oldpattern);   */
/*  newFileNameSize = rtsmb_len (newpattern);   */

    if (tid2 == 0xFFFF) /* if tid2 is -1, we use same tid as smb header */
        tid2 = pOutHdr->tid;

    ASSERT_THIS_TID (pCtx, tid2)
    ASSERT_PERMISSION_FOR_TID (pCtx, SECURITY_WRITE, tid2)

    /* both must be relative to a tid   */
    if (rtsmb_ncmp (oldpattern, slashslash, 2) == 0 ||
        rtsmb_ncmp (newpattern, slashslash, 2) == 0)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_DIFFDEVICE);
        return TRUE;
    }

    /* must make sure the paths of each name exist   */
    ASSERT_PATH (pCtx, oldpattern)
    ASSERT_PATH (pCtx, newpattern)

    SMBU_GetPath (oldpattern, matched);
    temp = &matched[rtsmb_len (matched)];
    temp[0] = '\\';
    temp[1] = '\0';

    isFound = SMBFIO_GFirst (pCtx, pCtx->tid, &stat, oldpattern);

    while (isFound == TRUE)
    {
        SMBFSTAT fileStat;
        PFRTCHAR result;
        BBOOL exit = FALSE;
        BBOOL truncate;

        rtsmb_cat (matched, (PFRTCHAR) stat.filename);
        result = SMBU_FitWildcards (oldpattern, matched, newpattern, newname);

        rtsmb_cpy ((PFRTCHAR) pCtx->tmpBuffer, SMBU_NormalizeFileName (pCtx, result));

        if (result == (PFRTCHAR)0)
        {
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRHRD, SMB_ERRHRD_GENERAL);
            break;
        }

        if (SMBFIO_Stat (pCtx, pCtx->tid, result, &fileStat) == TRUE)
        {
            if ((ON (flags, 0x2) && !(fileStat.f_attributes & RTP_FILE_ATTRIB_ISDIR)) ||
                (ON (flags, 0x1) &&  (fileStat.f_attributes & RTP_FILE_ATTRIB_ISDIR)))
            {
                SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_FILEEXISTS);
                break;
            }

            if (fileStat.f_attributes & RTP_FILE_ATTRIB_ISDIR)
            {
                rtsmb_char sep[] = {'\\', '\0'};
                rtsmb_cat (result, sep);
                rtsmb_cat (result, (PFRTCHAR) stat.filename);
            }
        }

        if (SMBFIO_Stat (pCtx, pCtx->tid, result, &fileStat) == TRUE)
        {
            switch (SMB_OPEN_FUNCTION_OPEN(open_function))
            {
            case 0: /* fail */
                SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_FILEEXISTS);
                exit = TRUE;
                break;
            case 1: /* open */
                truncate = FALSE;
                break;
            case 2: /* truncate; will be overwritten */
                /* just deleting the file worries me, because if the rename fails, the user   */
                /* is left without the target file.                                           */
                truncate = TRUE;
                break;
            default:
                truncate = TRUE;
                break;
            }
        }
        if (exit) break;

        if (isCopy)
        {
            if (transferFileTo (pCtx, pOutHdr, pOutBuf, matched, pOutHdr->tid,
                 result, tid2, truncate) == FALSE)
                break;  /* error code has already been filled in */
        }
        else /* is move */
        {
            if (transferFileTo (pCtx, pOutHdr, pOutBuf, matched, pOutHdr->tid,
                 result, tid2, TRUE) == FALSE)
                break;
            SMBFIO_Delete (pCtx, pCtx->tid, matched);
        }

        count ++;

        temp[1] = '\0';

        isFound = SMBFIO_GNext (pCtx, pCtx->tid, &stat);
    }

    SMBFIO_GDone (pCtx, pCtx->tid, &stat);

    if (isCopy)
    {
        RTSMB_COPY_R response;

        response.count = count;

        if (pOutHdr->status != 0)
        {
            response.error_filename = (PFRTCHAR) pCtx->tmpBuffer;
        }
        else
        {
            response.error_filename = (PFRTCHAR)0;
        }

        WRITE_SMB (srv_cmd_fill_copy);
    }
    else
    {
        RTSMB_MOVE_R response;

        response.count = count;

        if (pOutHdr->status != 0)
        {
            response.error_filename = (PFRTCHAR) pCtx->tmpBuffer;
        }
        else
        {
            response.error_filename = (PFRTCHAR)0;
        }

        WRITE_SMB (srv_cmd_fill_move);
    }

    return TRUE;
}

/*
================
This procedure creates an empty directory
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcCreateDirectory (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_CREATE_DIRECTORY command;
    byte response;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    command.directory = (PFRTCHAR) pCtx->tmpBuffer;
    command.directory_size = SMBF_FILENAMESIZE;
    READ_SMB (srv_cmd_read_create_directory);

    if (SMBFIO_Mkdir (pCtx, pCtx->tid, command.directory) == FALSE)
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_FILEEXISTS);
    else
    {
        WRITE_SMB (srv_cmd_fill_create_directory);
    }

    return TRUE;
}

/**
 * A simple helper function for deleting directories.
 *
 * Returns zero if the directory is not a directory we need
 * to keep around, like the root of a share.  Else, returns non-zero.
 */
BBOOL isUnusedDir (PSMB_SESSIONCTX pCtx, PFRTCHAR dir)
{
    BBOOL rv = TRUE;
    PSR_RESOURCE pResource;
    rtsmb_char string[SMBF_FILENAMESIZE + 1];
    word size;

    /*SMBFIO_ExpandName (pCtx, dir, string, SMBF_FILENAMESIZE + 1);   */
    SMBFIO_ExpandName (pCtx, pCtx->tid, dir, string, SMBF_FILENAMESIZE + 1);
    size = (word)rtsmb_len (string);

    CLAIM_SHARE ();

    for (pResource = SR_FirstResource (); pResource; pResource = SR_NextResource (pResource))
    {
        if (pResource->stype == ST_DISKTREE)
            if (!rtsmb_ncmp (pResource->u.disktree.path, string, size))
            {
                rv = FALSE;
                break;
            }
    }

    RELEASE_SHARE ();

    return rv;
}

/*
================
This procedure deletes an empty directory
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcDeleteDirectory (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_DELETE_DIRECTORY command;
    byte response;  /* not used */
    SMBFSTAT stat;
    PFRTCHAR string;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    string = (PFRTCHAR) pCtx->tmpBuffer;
    command.directory = string;
    command.directory_size = SMBF_FILENAMESIZE;
    READ_SMB (srv_cmd_read_delete_directory);

    if (!isUnusedDir (pCtx, string))
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_REMCD);
        return TRUE;
    }
    else if (!SMBFIO_Stat (pCtx, pCtx->tid, string, &stat))
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADPATH);
        return TRUE;
    }
    else if (SMBFIO_Rmdir (pCtx, pCtx->tid, string) == FALSE)
    {
        /* here i must make a guess as to the problem                     */
        /* we're going to assume it is because the directory is not empty */
        SMBU_AddError (pOutHdr, pOutBuf, SMB_EC_ERRDOS, SMB_ERRDOS_NOACCESS);
    }

    WRITE_SMB (srv_cmd_fill_delete_directory);

    return TRUE;
}

/*
================
This procedure creates a new blank file or truncates to 0 an existing one
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcCreate (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_CREATE command;
    PFRTCHAR string;
    int fid, imode;
    word mode;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    string = (PFRTCHAR) pCtx->tmpBuffer;
    command.filename = string;
    command.filename_size = SMBF_FILENAMESIZE;
    READ_SMB (srv_cmd_read_create);

    imode =  command.file_attributes & 0x01 ? RTP_FILE_S_IWRITE  : 0;
    imode |= command.file_attributes & 0x02 ? RTP_FILE_S_HIDDEN  : 0;
    imode |= command.file_attributes & 0x04 ? RTP_FILE_S_SYSTEM  : 0;
    imode |= command.file_attributes & 0x20 ? RTP_FILE_S_ARCHIVE : 0;
    mode = (word) imode;

    if ((fid = SMBFIO_Open (pCtx, pCtx->tid, string,
        RTP_FILE_O_CREAT | RTP_FILE_O_TRUNC | RTP_FILE_O_RDWR, mode)) < 0)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
    }
    else
    {
        int external;

        if ((external = SMBU_SetInternalFid (pCtx, fid, string, 0)) < 0)
        {
            SMBFIO_Close (pCtx, pCtx->tid, fid);
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_NOFIDS);
        }
        else
        {
            RTSMB_CREATE_R response;

            response.fid = (word)external;
            pOutHdr->flags &= NOT_FLAG(byte,SMB_FLG_OPLOCK); /* ~SMB_FLG_OPLOCK;    we refuse all oplock requests */

            WRITE_SMB (srv_cmd_fill_create);
        }
    }

    return TRUE;
}

/*
================
This procedure creates a new blank file with unique name
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcCreateTemporary (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_CREATE_TEMPORARY command;
    int fid;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    command.directory = (PFRTCHAR) pCtx->tmpBuffer;
    command.directory_size = SMBF_FILENAMESIZE + 1;
    READ_SMB (srv_cmd_read_create_temporary);

    if (SMBU_TemporaryFileName (pCtx, (PFRTCHAR) pCtx->tmpBuffer, (PFRTCHAR) pCtx->tmpBuffer) != 0)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
    }
    else if ((fid = SMBFIO_Open (pCtx, pCtx->tid, (PFRTCHAR) pCtx->tmpBuffer, RTP_FILE_O_CREAT | RTP_FILE_O_RDWR, RTP_FILE_S_IREAD | RTP_FILE_S_IWRITE)) < 0)
    {
        /* this shouldn't happen, hence the 'internal error' message   */
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
    }
    else
    {
        int external;

        if ((external = SMBU_SetInternalFid (pCtx, fid, (PFRTCHAR) pCtx->tmpBuffer, 0)) < 0)
        {
            SMBFIO_Close (pCtx, pCtx->tid, fid);
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_NOFIDS);
        }
        else
        {
            RTSMB_CREATE_TEMPORARY_R response;

            response.fid = (word)external;
            response.filename = SMBU_GetFilename ((PFRTCHAR) pCtx->tmpBuffer);

            WRITE_SMB (srv_cmd_fill_create_temporary);
        }
    }

    return TRUE;
}

/*
================
This procedure sets info of a file
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcSetInformation (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_SET_INFORMATION command;
    byte response;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    /**
     * The two fields, lastWriteTime and fileAttributes, are optional.  We don't yet
     * handle lastWriteTime.
     */

    command.filename = (PFRTCHAR) pCtx->tmpBuffer;
    command.filename_size = SMBF_FILENAMESIZE;
    READ_SMB (srv_cmd_read_set_information);

    /**
     * We return badfile error if chmode fails.
     */
    if (!SMBFIO_Chmode (pCtx, pCtx->tid, command.filename, rtsmb_util_smb_to_rtsmb_attributes (command.file_attributes)))
    {
        SMBU_AddError (pOutHdr, pOutBuf, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
    }

    WRITE_SMB (srv_cmd_fill_set_information);

    return TRUE;
}

/*
================
This procedure sets info of a file
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcSetInformation2 (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_SET_INFORMATION2 command;
    byte response;
    PFRTCHAR name;
    SMBFSTAT stat;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    /**
     * Changing time stamps are not implemented yet in VFS, so we do nothing
     * for now and silently ignore requests.  This will not cause problems on the client side since
     * they can't expect file stamps not to change and thus won't depend on the stamp being a
     * certain thing, and we help programs that are confused by error messages on this operation.
     */

    READ_SMB (srv_cmd_read_set_information2);

    name = SMBU_GetFileNameFromFid (pCtx, command.fid);

    /**
     * We should return badfile error if file doesn't exist.
     */
    if (!SMBFIO_Stat (pCtx, pCtx->tid, name, &stat))
        SMBU_AddError (pOutHdr, pOutBuf, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);

    WRITE_SMB (srv_cmd_fill_set_information2);

    return TRUE;
}

/*
================
This procedure takes all the resources owned by pid and closes them
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcProcessExit (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    byte command, response;
    word i, j;

    ASSERT_UID (pCtx)

    READ_SMB (srv_cmd_read_process_exit);

    /* find all resources claimed by us and free them   */
    for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
    {
        for (j = 0; j < prtsmb_srv_ctx->max_searches_per_uid; j++)
        {
            if (pCtx->uids[i].searches[j].pid == pCtx->pid &&
                pCtx->uids[i].searches[j].inUse)
            {
                SMBFIO_GDone (pCtx, pCtx->tid, &pCtx->uids[i].searches[j].stat);
                pCtx->uids[i].searches[j].inUse = FALSE;
            }
        }

        for (j = 0; j < prtsmb_srv_ctx->max_fids_per_session; j++)
        {
            if (pCtx->fids[j].internal >= 0 &&
                pCtx->fids[j].pid == pCtx->pid)
            {
                if (pCtx->fids[j].flags != FID_FLAG_DIRECTORY)
                {
                    SMBFIO_Close (pCtx, pCtx->tid, pCtx->fids[j].internal);
                }
                SMBU_ClearInternalFid (pCtx, pCtx->fids[j].external);
            }
        }
    }

    WRITE_SMB (srv_cmd_fill_process_exit);

    return TRUE;
}


/*
================
This procedure writes to a file and then closes it
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcWriteAndClose (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_WRITE_AND_CLOSE command;
    RTSMB_WRITE_AND_CLOSE_R response;
    word written;
    int fid;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    command.data = pCtx->tmpBuffer;
    command.data_size = (word) (pCtx->tmpSize & 0xFFFF); /* only use what protocol can handle */
    READ_SMB (srv_cmd_read_write_and_close);

    ASSERT_FID (pCtx, command.fid, 0)

    fid = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL,0);

    written = SMBU_WriteToFile (pCtx, fid, command.data, command.data_size, FALSE, command.offset);

    if (written != 0 || command.data_size == 0)
        response.count = written;
    else
        response.count = 0;

    SMBU_ClearInternalFid (pCtx, command.fid);
    SMBFIO_Close (pCtx, pCtx->tid, fid);

    WRITE_SMB (srv_cmd_fill_write_and_close);

    return TRUE;
}

/*
================
This procedure reads from a file raw style
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcReadRaw (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_READ_RAW command;
    dword spaceLeft;
    int fid;
    long bytesRead;
    PFBYTE temp = (PFBYTE) 0x1; /* just need some non-NULL value. */

    READ_SMB (srv_cmd_read_read_raw);

    /**
     * If there are any problems, return 0 for raw reads (client would mistake an
     * error smb as data).  Client will retry with normal read and get error that way.
     */
    if (assertUid (pCtx) || assertTid (pCtx) || assertPermission (pCtx, SECURITY_READ) ||
        assertFid (pCtx, command.fid, 0) || ((temp = allocateBigBuffer ()) != 0))
    {
        RTSMB_DEBUG_OUTPUT_STR ("ReadRaw: Failed major check", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR ((temp ? "" : " -- no buffers"), RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
        SMBS_SendMessage (pCtx, 0, FALSE);
        return FALSE;
    }

    fid = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL,0);

    /* special case return of 0 bytes for reads completely beyond end of file            */
    /* this is not explicit in spec but it makes some sense for very simple file systems */
    /* this kills the file system performance though, so only choose enable this if your */
    /* filesystem needs this                                                             */
#if 0
    if ((bytesRead = SMBFIO_Seek (pCtx, pCtx->tid, fid, 0, RTSMB_SEEK_END)) >= 0 && (dword) (bytesRead) < command.offset)
    {
        RTSMB_DEBUG_OUTPUT_STR("ReadRaw: bad seek\n", RTSMB_DEBUG_TYPE_ASCII);
        freeBigBuffer (pCtx->writeBuffer);
        SMBS_SendMessage (pCtx, 0, FALSE);
        return FALSE;
    }
#endif

    pCtx->writeBuffer = temp;
    pCtx->writeBufferSize = (word) (SMB_BIG_BUFFER_SIZE & 0xFFFF);

    /* see if we have enough space for all of it   */
    spaceLeft = MIN (pCtx->writeBufferSize, command.max_count);
    if (SMBFIO_Seeku32 (pCtx, pCtx->tid, fid, command.offset)==0xffffffff)
        bytesRead = -1;
    else
        bytesRead = SMBFIO_Read (pCtx, pCtx->tid, fid, pOutBuf, spaceLeft);

    /* upon read error, we send 0 byte answer   */
    if (bytesRead < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("ReadRaw: read error\n", RTSMB_DEBUG_TYPE_ASCII);
        bytesRead = 0;
    }

    SMBS_SendMessage (pCtx, (dword)bytesRead, FALSE);

    freeBigBuffer (pCtx->writeBuffer);
    pCtx->writeBuffer = pCtx->smallWriteBuffer;
    pCtx->writeBufferSize = pCtx->useableBufferSize;

    return FALSE;
}

/*
================
This procedure writes to a file raw style
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcWriteRaw1 (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_WRITE_RAW command;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_READ)

    command.data = pCtx->tmpBuffer;
    command.data_size = pCtx->tmpSize;
    READ_SMB (srv_cmd_read_write_raw);

    ASSERT_FID (pCtx, command.fid, 0)

    if (command.count > SMB_BIG_BUFFER_SIZE)
    {
        SMBU_AddError (pOutHdr, pOutBuf, SMB_EC_ERRSRV, SMB_ERRSRV_USESTD);
        return TRUE;
    }

    pCtx->writeRawInfo.internal = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL,0);
    pCtx->writeRawInfo.external = command.fid;
    pCtx->writeRawInfo.hdr = *pOutHdr;
    pCtx->writeRawInfo.maxCount = (word) ((command.count - command.data_size) & 0xFFFF);
    pCtx->writeRawInfo.writeThrough = ON (command.write_mode, 1);

    SMBFIO_Seeku32 (pCtx, pCtx->tid, pCtx->writeRawInfo.internal, command.offset);

    /**
     * Write the data sent to us now.
     * If there is an error, send final response.
     */
    if (command.data_size &&
        SMBFIO_Write (pCtx, pCtx->tid, pCtx->writeRawInfo.internal,
                      command.data, (word) (command.data_size & 0xFFFF)) < 0)
    {
        RTSMB_WRITE_RAW_R2 response;

        pOutHdr->command = SMB_COM_WRITE_COMPLETE;
        SMBU_AddError (pOutHdr, pOutBuf, SMB_EC_ERRHRD, SMB_ERRHRD_WRITE);

        response.count = 0; /* I have no way of getting number of bytes written */
        WRITE_SMB (srv_cmd_fill_write_raw2);
    }
    else
    {
        RTSMB_WRITE_RAW_R1 response;

        response.remaining = 0;
        WRITE_SMB (srv_cmd_fill_write_raw1);
    }

    return TRUE;
}

/* call this second to process the raw data on the wire   */
BBOOL ProcWriteRaw2 (PSMB_SESSIONCTX pCtx, PFBYTE data, PFVOID pOutBuf, word bytesRead)
{
    RTSMB_HEADER outHdr;
    PRTSMB_HEADER pOutHdr = &outHdr;
    word spaceLeft;
    int written;

    spaceLeft = (word) (MIN (pCtx->readBufferSize, pCtx->writeRawInfo.maxCount));

    written = SMBFIO_Write (pCtx, pCtx->writeRawInfo.hdr.tid, pCtx->writeRawInfo.internal, data,
            spaceLeft);

    if (pCtx->writeRawInfo.writeThrough)
    {
        /* must wait on a write-through   */
        SMBFIO_Flush (pCtx, pCtx->writeRawInfo.hdr.tid, pCtx->writeRawInfo.internal);

        outHdr = pCtx->writeRawInfo.hdr;
        outHdr.command = SMB_COM_WRITE_COMPLETE;

        if (written < 0)
        {
            SMBU_AddError (pOutHdr, pOutBuf, SMB_EC_ERRHRD, SMB_ERRHRD_WRITE);
        }
        else
        {
            RTSMB_WRITE_RAW_R2 response;

            response.count = (word)written;

            WRITE_SMB (srv_cmd_fill_write_raw2);
        }

        return TRUE;
    }
    else
    {
        if (written < 0)
            SMBU_SetFidError (pCtx, pCtx->writeRawInfo.external, SMB_EC_ERRHRD, SMB_ERRHRD_WRITE);

        return FALSE;
    }
}

/*
================
This procedure sets up a file for printing
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcOpenPrintFile (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_OPEN_PRINT_FILE command;
    RTSMB_OPEN_PRINT_FILE_R response;
    PFRTCHAR string;
    rtsmb_char empty[] = {'\0'};
    word flags;
    int fid;
    PTREE pTree;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    command.identifier = (PFRTCHAR)0;
    READ_SMB (srv_cmd_read_open_print_file);

    flags = 0;
    flags |= RTP_FILE_O_RDWR;
    flags |= RTP_FILE_O_CREAT;

    pTree = SMBU_GetTree (pCtx, pCtx->tid);

    if (pTree->type != ST_PRINTQ)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_INVDEVICE);
        return TRUE;
    }

    /* get filename to use   */
    string = (PFRTCHAR) pCtx->tmpBuffer;
    if (SMBU_TemporaryFileName (pCtx, empty, string))
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_FILEEXISTS);
        return TRUE;
    }

    fid = SMBFIO_Open (pCtx, pCtx->tid, string, flags, RTP_FILE_S_IREAD | RTP_FILE_S_IWRITE);

    if(fid < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("Open failed for unknown reason.\n", RTSMB_DEBUG_TYPE_ASCII);
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_NOACCESS); /* dunno what went wrong... */
    }
    else
    {

        int externalFid = SMBU_SetInternalFid (pCtx, fid, string, 0);

        if (externalFid < 0)
        {
            SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_NOFIDS);
            SMBFIO_Close (pCtx, pCtx->tid, fid);
            return TRUE;
        }

        response.fid = (word) externalFid;

        pOutHdr->flags &= NOT_FLAG(byte,SMB_FLG_OPLOCK); /* ~SMB_FLG_OPLOCK;    we refuse all oplock requests */

        WRITE_SMB (srv_cmd_fill_open_print_file);
    }

    return TRUE;
}

/*
================
This procedure writes to a print file
    PSMB_SESSIONCTX pCtx - current smb context
    PSMB_HEADER1 pInSmbHdr - incoming header
    PSMB_HEADER1 pOutSmbHdr - out going header, flags |= response all other fields equal to pInSmbHdr
================
*/
BBOOL ProcWritePrintFile (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    RTSMB_WRITE_PRINT_FILE command;
    byte response;  /* not used */
    int fid;

    ASSERT_UID (pCtx)
    ASSERT_TID (pCtx)
    ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

    command.data = pCtx->tmpBuffer;
    command.data_size = (word) (pCtx->tmpSize & 0xFFFF);    /* only use what protocol can handle */

    READ_SMB (srv_cmd_read_write_print_file);

    ASSERT_FID (pCtx, command.fid, 0)

    fid = SMBU_GetInternalFid (pCtx, command.fid, FID_FLAG_ALL,0);

    SMBU_WriteToFile (pCtx, fid, command.data, command.data_size, TRUE, 0);

    WRITE_SMB (srv_cmd_fill_write_print_file);

    return TRUE;
}

void Tree_Init (PTREE tree)
{
    int i;

    for (i = 0; i < prtsmb_srv_ctx->max_fids_per_tree; i++)
    {
        tree->fids[i] = 0;
    }

    tree->inUse = TRUE;
}

void Tree_Shutdown (PSMB_SESSIONCTX pCtx, PTREE tree)
{
    word i;

    for (i = 0; i < prtsmb_srv_ctx->max_fids_per_tree; i++)
    {
        if (tree->fids[i])
        {
            if (tree->fids[i]->flags != FID_FLAG_DIRECTORY)
                SMBFIO_Close (pCtx, tree->external, tree->fids[i]->internal);
            SMBU_ClearInternalFid (pCtx, tree->fids[i]->external);
        }
    }

    tree->inUse = FALSE;
}

void User_Init (PUSER user)
{
    word i;

    for (i = 0; i < prtsmb_srv_ctx->max_searches_per_uid; i++)
    {
        user->searches[i].inUse = FALSE;
    }

    for (i = 0; i < prtsmb_srv_ctx->max_fids_per_uid; i++)
    {
        user->fids[i] = 0;
    }
    user->inUse = TRUE;
}

void User_Shutdown (PSMB_SESSIONCTX pCtx, PUSER user)
{
    word i;

    for (i = 0; i < prtsmb_srv_ctx->max_searches_per_uid; i++)
        if (user->searches[i].inUse)
            SMBFIO_GDone (pCtx, user->searches[i].tid, &user->searches[i].stat);

    /* shut down all of the users files   */
    for (i = 0; i < prtsmb_srv_ctx->max_fids_per_uid; i++)
    {
        if (user->fids[i])
        {
            /* Do not call close if it is a directory   */
            if (user->fids[i]->flags != FID_FLAG_DIRECTORY)
                SMBFIO_Close (pCtx, user->fids[i]->tid, user->fids[i]->internal);
            SMBU_ClearInternalFid (pCtx, user->fids[i]->external);
        }
    }

    user->inUse = FALSE;
}

/*============================================================================   */
/*   INTERFACE FUNCTIONS                                                         */
/*============================================================================   */
BBOOL SMBS_SendMessage (PSMB_SESSIONCTX pCtx, dword size, BBOOL translate)
{
    RTSMB_NBSS_HEADER header;
    int r;

    size = MIN (size, pCtx->writeBufferSize);

    header.type = RTSMB_NBSS_COM_MESSAGE;
    header.size = size;

    r = rtsmb_nbss_fill_header (pCtx->writeBuffer, RTSMB_NBSS_HEADER_SIZE, &header);
    if (r < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("SMBS_SendMessage: Error writing netbios header!\n", RTSMB_DEBUG_TYPE_ASCII);
        return FALSE;
    }
    else
    {
        r =  rtsmb_net_write (pCtx->sock, pCtx->writeBuffer, (int)(RTSMB_NBSS_HEADER_SIZE + size));
        if (r < 0)
            return FALSE;
    }
    return TRUE;
}

void SMBS_CloseShare ( PSMB_SESSIONCTX pCtx, word handle)
{
    word i;

    for (i = 0; i < prtsmb_srv_ctx->max_trees_per_session; i++)
    {
        if (pCtx->trees[i].internal == handle)
        {
            Tree_Shutdown (pCtx, &pCtx->trees[i]);
        }
    }
}

/*
================
 This function intializes the session context portions that are shared by SMBV1 and SMBV2.

    @pSmbCtx: This is the session context to initialize.
    @sock: This is the sock we are connected to.

    return: Nothing.
================
*/
void SMBS_InitSessionCtx (PSMB_SESSIONCTX pSmbCtx, RTP_SOCKET sock)
{

    pSmbCtx->sock = sock;
    pSmbCtx->dialect = DIALECT_NONE;
    pSmbCtx->isSMB2 = FALSE;

    pSmbCtx->accessMode = Auth_GetMode ();

#ifdef SUPPORT_SMB2
#ifdef STATE_DIAGNOSTICS
    RTSMB_GET_SRV_SESSION_STATE (NOTCONNECTED);
#endif

    pSmbCtx->state = NOTCONNECTED;

#else  /* SUPPORT_SMB2 */
#ifdef STATE_DIAGNOSTICS
    RTSMB_GET_SRV_SESSION_STATE (IDLE);
#endif
    pSmbCtx->state = IDLE;
    SMBS_InitSessionCtx_smb1(pSmbCtx);
#endif
    /**
     * See srvssn.h for a more detailed description of what these do.
     */
    pSmbCtx->writeRawInfo.amWritingRaw = FALSE;

/*  pSmbCtx->num = num++;  */
}

/*
================
 This function intializes the session context portions that is unique to SMBV1.

 This is performed when the server state goes from NOTCONNECTED to IDLE after accepting it's fir bytes and identifying smbv1

    @pSmbCtx: This is the session context to initialize.

    return: Nothing.
================
*/
RTSMB_STATIC void SMBS_InitSessionCtx_smb1(PSMB_SESSIONCTX pSmbCtx)
{
    word i;
    /**
     * Outsource our user initialization.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
    {
        User_Init (&pSmbCtx->uids[i]);
        pSmbCtx->uids[i].inUse = FALSE;
    }

    /**
     * Outsource our tree initialization.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_trees_per_session; i++)
    {
        Tree_Init (&pSmbCtx->trees[i]);
        pSmbCtx->trees[i].inUse = FALSE;
    }

    /**
     * Clear fids.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_fids_per_session; i++)
    {
        pSmbCtx->fids[i].internal = -1;
    }

}

/* this changes the permenant buffers used by this session   */
void SMBS_SetBuffers (PSMB_SESSIONCTX pCtx, PFBYTE inBuf, dword inSize, PFBYTE outBuf, dword outSize, PFBYTE tmpBuf, dword tmpSize)
{
    pCtx->smallReadBuffer = inBuf;
    pCtx->smallWriteBuffer = outBuf;
    pCtx->readBuffer = inBuf;
    pCtx->readBufferSize = inSize - RTSMB_NBSS_HEADER_SIZE;
    pCtx->writeBuffer = outBuf;
    pCtx->writeBufferSize = outSize - RTSMB_NBSS_HEADER_SIZE;
    pCtx->tmpBuffer = tmpBuf;
    pCtx->tmpSize = tmpSize;
}

/*
================
This function frees resources held by an SMB session context.

    @pSmbCtx: This is the session context to free.

    return: Nothing.
================
*/
void SMBS_CloseSession(PSMB_SESSIONCTX pSmbCtx)
{
    word i;

    /**
     * Only data worth freeing is in user data and trees.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
        if (pSmbCtx->uids[i].inUse)
            User_Shutdown (pSmbCtx, &pSmbCtx->uids[i]);

    for (i = 0; i < prtsmb_srv_ctx->max_trees_per_session; i++)
        if (pSmbCtx->trees[i].inUse)
            Tree_Shutdown (pSmbCtx, &pSmbCtx->trees[i]);
}

#if (INCLUDE_RTSMB_DC)
BBOOL SMBS_StateWaitOnPDCName (PSMB_SESSIONCTX pCtx)
{
    if (pCtx->state != WAIT_ON_PDC_NAME)
        return TRUE;

    if (MS_IsKnownPDCName ())
    {
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (FINISH_NEGOTIATE);
#endif
        pCtx->state = FINISH_NEGOTIATE;
    }
    else if (pCtx->end_time <= rtp_get_system_msec() ())
    {
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (FAIL_NEGOTIATE);
#endif
        pCtx->state = FAIL_NEGOTIATE;
    }

    return TRUE;
}

BBOOL SMBS_StateWaitOnPDCIP (PSMB_SESSIONCTX pCtx)
{
    char pdc [RTSMB_NB_NAME_SIZE + 1];

    if (pCtx->state != WAIT_ON_PDC_IP)
        return TRUE;

    if (!MS_GetPDCName (pdc))
    {
        /* we've should've already alotted time and sent out a query.   */
        /* let's not do it again                                        */
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (WAIT_ON_PDC_NAME);
#endif
        pCtx->state = WAIT_ON_PDC_NAME;
        return TRUE;
    }

    if (rtsmb_srv_nbns_is_in_name_cache (pdc, RTSMB_NB_NAME_TYPE_SERVER))
    {
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (FINISH_NEGOTIATE);
#endif
        pCtx->state = FINISH_NEGOTIATE;
    }
    else if (pCtx->end_time <= rtp_get_system_msec())
    {
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (FAIL_NEGOTIATE);
#endif
        pCtx->state = FAIL_NEGOTIATE;
    }

    return TRUE;
}

BBOOL SMBS_StateContinueNegotiate (PSMB_SESSIONCTX pCtx)
{
    PFBYTE pInBuf;
    PFVOID pOutBuf;

    /**
     * Set up incoming and outgoing header.
     */
    pInBuf = (PFBYTE) SMB_INBUF (pCtx);
    pOutBuf = SMB_OUTBUF (pCtx);

    /* since we are coming here from a pdc discovery, restore state   */
    pInBuf[0] = 0xFF;
    pInBuf[1] = 'S';
    pInBuf[2] = 'M';
    pInBuf[3] = 'B';
    pInBuf[4] = SMB_COM_NEGOTIATE;

    SMBS_ProcSMBBody (pCtx);
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (IDLE);
#endif
    pCtx->state = IDLE;

    return SMBS_SendMessage (pCtx, pCtx->outBodySize, TRUE);
}
#endif


/*
================
This function processes one smb packet.

    @packetSize: This is the declared size of the incoming packet.

    return: If an error occurs which is a breach of client trust, we return FALSE,
        indicating that the connection to the client should be shut off.  This happens
        if the client sends more data than we negotiated or if the client is not sending
        valid smbs, for example.
================
*/

extern void SMBS_InitSessionCtx_smb2(PSMB_SESSIONCTX pSctx);
#ifdef SUPPORT_SMB2
extern BBOOL SMBS_ProcSMB2_Body (PSMB_SESSIONCTX pSctx);
#endif

BBOOL SMBS_ProcSMBPacket (PSMB_SESSIONCTX pSctx, dword packetSize)
{
    PFBYTE pInBuf;
    PFVOID pOutBuf;
    BBOOL doSend = FALSE;
    BBOOL doSocketClose = FALSE;
    int length;

    pSctx->doSocketClose = FALSE;
    /**
     * If they are sending larger packets than we told them to, shut off contact.
     */
    if (packetSize > pSctx->readBufferSize)
    {
        char tmpBuffer[32];
        char * buffer = tmpBuffer;
        tmpBuffer[0] = '\0';

        RTSMB_DEBUG_OUTPUT_STR ("SMBS_ProcSMBPacket:  Packet of size ", RTSMB_DEBUG_TYPE_ASCII);
        buffer = rtp_ultoa (packetSize, buffer, 10);
        RTSMB_DEBUG_OUTPUT_STR (buffer, RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR ("too big for buffer of size ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_INT ((int)pSctx->readBufferSize);
#if 0
        RTSMB_DEBUG_OUTPUT_STR (".  Ending session.\n", RTSMB_DEBUG_TYPE_ASCII);
        return FALSE;
#else
        RTSMB_DEBUG_OUTPUT_STR (".  Tossing packet.\n", RTSMB_DEBUG_TYPE_ASCII);
        return TRUE; /* eat the packet */
#endif
    }

    /**
     * We need to make sure we are making some progress (i.e. packetSize != 0)
     */
    if (packetSize < 1)
    {
        RTSMB_DEBUG_OUTPUT_STR("Warning: enlargening 0-length packet\n", RTSMB_DEBUG_TYPE_ASCII);
        packetSize = 1;
    }

    /**
     * Set up incoming and outgoing header.
     */
    pInBuf = (PFBYTE) SMB_INBUF (pSctx);
    pOutBuf = SMB_OUTBUF (pSctx);

    switch (pSctx->state)
    {
    case WRITING_RAW:

        pSctx->in_packet_size = (word) packetSize;
        pSctx->current_body_size = 0;
        pSctx->in_packet_timeout_base = rtp_get_system_msec();

    case WRITING_RAW_READING:
        /**
         * Read bytes from wire.
         */
        if ((length = rtsmb_net_read (pSctx->sock, pInBuf + pSctx->current_body_size,
            pSctx->readBufferSize - pSctx->current_body_size, packetSize - pSctx->current_body_size)) < 0)
        {
            RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMBPacket:  Error on read.  Ending session.\n", RTSMB_DEBUG_TYPE_ASCII);
            return FALSE;
        }
        pSctx->current_body_size += (dword)length;

        if (pSctx->current_body_size < pSctx->in_packet_size)
        {
            /* We didn't get it all.  We'll have to stop and try again.   */
            /* are we out of time?                                        */
            if (IS_PAST (pSctx->in_packet_timeout_base, RTSMB_NB_UCAST_RETRY_TIMEOUT))
            {
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (IDLE);
#endif
                pSctx->state = IDLE;
            }
            else
            {
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (WRITING_RAW_READING);
#endif
                pSctx->state = WRITING_RAW_READING;
            }
            return TRUE;
        }

        /**
         * If we are writing raw data from net to disk, don't try to interpret
         * header and rather just call ProcWriteRaw2.
         *
         * pInSmbHdr will contain raw data, pOutSmbHdr will be the same as the
         * WriteRaw call immediately prior, since we haven't emptied the writeBuffer.
         */
        doSend = ProcWriteRaw2 (pSctx, pInBuf, pOutBuf, (word) length);
        freeBigBuffer (pSctx->readBuffer);  /* safe to release, since all write raws are only one packet large */
        pSctx->readBuffer = pSctx->smallReadBuffer;
        pSctx->readBufferSize = (dword)SMB_BUFFER_SIZE;
        pSctx->writeRawInfo.amWritingRaw = FALSE;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (IDLE);
#endif
        pSctx->state = IDLE;
        break;
#ifdef SUPPORT_SMB2
    case NOTCONNECTED:
#endif
    case IDLE:
        /**
         * Read starting bytes from the wire.
         */
        if ((length = rtsmb_net_read (pSctx->sock, pInBuf,
            pSctx->readBufferSize, 5)) < 0)
        {
            RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMBPacket:  Error on read.  Ending session.\n", RTSMB_DEBUG_TYPE_ASCII);
            return FALSE;
        }

        /**
         * If the packet is not an SMB, end connection.
         */
#ifdef SUPPORT_SMB2
        if ( ((pInBuf[0] != 0xFF)&&(pInBuf[0] != 0xFE)) || (pInBuf[1] != 'S') ||
             (pInBuf[2] != 'M')  || (pInBuf[3] != 'B'))
#else
        if ((pInBuf[0] != 0xFF) || (pInBuf[1] != 'S') ||
             (pInBuf[2] != 'M')  || (pInBuf[3] != 'B'))
#endif

        {
            RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMBPacket: Badly formed packet\n", RTSMB_DEBUG_TYPE_ASCII);
            /* If we were nice, we'd send a message saying we don't understand.            */
            /* But, we don't know any values to fill it with (like tid, uid) or whatever,  */
            /* so the client won't know which message was bad.  Plus, if they are          */
            /* sending bad messages, they're up to no good, so we should just end contact. */
/*          SMBU_CreateDummySmb (pOutSmbHdr);                                              */
/*          SMBU_FillError (pOutSmbHdr, SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD);                 */
/*          return SMBS_SendMessage (pSctx, SMBU_GetSize (pOutSmbHdr), TRUE);              */
            return FALSE;
        }
#ifdef SUPPORT_SMB2
        if (pSctx->state == NOTCONNECTED)
        {
            if (pInBuf[0] == 0xFE)
                SMBS_InitSessionCtx_smb2(pSctx);
            else
                SMBS_InitSessionCtx_smb1(pSctx);
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (IDLE);
#endif
        }
#endif
        pSctx->in_packet_size = (word) (packetSize);
        pSctx->current_body_size = 5;
        pSctx->in_packet_timeout_base = rtp_get_system_msec();

    case READING:
        doSend = SMBS_ProcSMBBody (pSctx);
        break;
    default:
        return TRUE;
    }

    /**
     * We clear the incoming buffer as a precaution, because we don't want
     * malicious clients somehow tricking us into accepting bad data if we
     * see an old packet or random data here.
     */
    /* It's not clear we need this, and not doing it let's us interrupt ourselves   */
    /* in the middle of a packet and reprocess it later.                            */
    /*tc_memset (pInBuf, 0, pSctx->readBufferSize);                                 */

    if (doSend)
    {
        return SMBS_SendMessage (pSctx, pSctx->outBodySize, TRUE);
    }
    if (pSctx->doSocketClose)
        return FALSE;
    else
        return TRUE;
}


BBOOL SMBS_ProcSMBBody (PSMB_SESSIONCTX pSctx)
{
    RTSMB_HEADER inCliHdr;
    RTSMB_HEADER outCliHdr;
    PFBYTE pInBuf;
    PFVOID pOutBuf;
    int header_size;
    int length;
    BBOOL doSend = FALSE;

    /**
     * Set up incoming and outgoing packet header.
     */
    pInBuf = (PFBYTE) SMB_INBUF (pSctx);
    pOutBuf = SMB_OUTBUF (pSctx);

#if (INCLUDE_RTSMB_DC)
    if (pInBuf[4] == SMB_COM_NEGOTIATE &&
        pSctx->accessMode == AUTH_USER_MODE && pSctx->state == IDLE)
    {
        char pdc [RTSMB_NB_NAME_SIZE + 1];

        /* we must connect with the dc first   */
        if (!MS_GetPDCName (pdc))
        {
            RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMBBody:  NEGOTIATE being processed, must find PDC name.\n", RTSMB_DEBUG_TYPE_ASCII);

            /* change our state to waiting on pdc name   */
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (WAIT_ON_PDC_NAME);
#endif
            pSctx->state = WAIT_ON_PDC_NAME;

            MS_SendPDCQuery (); /* jump start the search */

            pSctx->end_time = rtp_get_system_msec() + RTSMB_NBNS_KEEP_ALIVE_TIMEOUT;

            return FALSE;
        }

        if (!rtsmb_srv_nbns_is_in_name_cache (pdc, RTSMB_NB_NAME_TYPE_SERVER))
        {
            RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMBBody:  NEGOTIATE being processed, must find PDC ip.\n", RTSMB_DEBUG_TYPE_ASCII);

            /* change our state to waiting on pdc ip   */
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (WAIT_ON_PDC_IP);
#endif
            pSctx->state = WAIT_ON_PDC_IP;

            rtsmb_srv_nbns_start_query_for_name (pdc, RTSMB_NB_NAME_TYPE_SERVER);

            pSctx->end_time = rtp_get_system_msec() + RTSMB_NBNS_KEEP_ALIVE_TIMEOUT;

            return FALSE;
        }

        /* ok, we can continue   */
        RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMBBody:  NEGOTIATE being processed, we've got all the information we need.\n", RTSMB_DEBUG_TYPE_ASCII);
    }
#endif

    /**
     * Read remaining bytes from wire (there should be a header there already).
     */
    if ((length = rtsmb_net_read (pSctx->sock, (PFBYTE) PADD (pInBuf, pSctx->current_body_size),
        (word) (pSctx->readBufferSize - pSctx->current_body_size), pSctx->in_packet_size - pSctx->current_body_size)) < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMBBody:  Error on read.\n", RTSMB_DEBUG_TYPE_ASCII);
        return FALSE;
    }
    pSctx->current_body_size += (dword)length;

    if (pSctx->current_body_size < pSctx->in_packet_size)
    {
        /* We didn't get it all.  We'll have to stop and try again.   */

        /* are we out of time?   */
        if (IS_PAST (pSctx->in_packet_timeout_base, RTSMB_NB_UCAST_RETRY_TIMEOUT))
        {
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (IDLE);
#endif
            pSctx->state = IDLE;
        }
        else
        {
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (READING);
#endif
            pSctx->state = READING;
        }
        return FALSE;
    }

#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (IDLE);
#endif
    pSctx->state = IDLE;

#ifdef SUPPORT_SMB2
    /* Now we have all the data from the wire. call smb2 if it's an smb2 session.   */
    if (pSctx->isSMB2)
    {
        return SMBS_ProcSMB2_Body (pSctx);
    }
#endif

    /* read header   */
    if ((header_size = srv_cmd_read_header (pInBuf,
        pInBuf, pSctx->current_body_size, &inCliHdr)) == -1)
    {
        RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMBBody: Badly formed header", RTSMB_DEBUG_TYPE_ASCII);
        return FALSE;
    }

    /**
     * Clear the write buffer.  Proc* functions assume that all unused bytes of
     * the buffer are zero.  (This shouldn't be true anymore, but can't hurt as
     * a precaution either.)
     */
    tc_memset (pOutBuf, 0, pSctx->writeBufferSize);

    pSctx->read_origin = pInBuf;
    pInBuf = PADD (pInBuf, header_size);

    /**
     * Set up outgoing header.
     */
    outCliHdr = inCliHdr;
    outCliHdr.flags |= SMB_FLG_RESPONSE;
    outCliHdr.flags &= NOT_FLAG(byte, SMB_FLG_CASELESSPATH);  /* ~SMB_FLG_CASELESSPATH;  we always send case sensitive */
    outCliHdr.flags &= NOT_FLAG(byte, SMB_FLG_CANONICALIZED); /* ~SMB_FLG_CANONICALIZED; nor do we canonicalize file names */
    outCliHdr.flags2 = 0;

    if (ON (inCliHdr.flags2, SMB_FLG2_UNICODESTR))
    {
        outCliHdr.flags2 |= SMB_FLG2_UNICODESTR;
    }

    pSctx->write_origin = (PFBYTE) pOutBuf;
    pSctx->pInHeader = &inCliHdr;
    pSctx->pOutHeader = &outCliHdr;

    /* fill it in once, just so we have something reasonable in place   */
    srv_cmd_fill_header (pSctx->write_origin, pSctx->write_origin, prtsmb_srv_ctx->small_buffer_size,
        &outCliHdr);

    pSctx->outBodySize = 0;

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

    /**
     * Do a quick check here that the first command we receive is a negotiate.
     */
    if (pSctx->dialect == DIALECT_NONE && inCliHdr.command != SMB_COM_NEGOTIATE)
    {
        RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMBBody:  Bad first packet -- was not a NEGOTIATE.\n", RTSMB_DEBUG_TYPE_ASCII);
        SMBU_FillError (pSctx, &outCliHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
        doSend = TRUE;
    }
    else if (pSctx->state == FAIL_NEGOTIATE)
    {
        RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMBBody:  Failing pending negotiation.\n", RTSMB_DEBUG_TYPE_ASCII);
        SMBU_FillError (pSctx, &outCliHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
        doSend = TRUE;
    }
    else
    {
        char tmpBuffer[32];
        char* buffer = tmpBuffer;
        tmpBuffer[0] = '\0';
        RTSMB_DEBUG_OUTPUT_STR ("SMBS_ProcSMBBody:  Processing a packet with command: ", RTSMB_DEBUG_TYPE_ASCII);
        DebugOutputSMBCommand(inCliHdr.command);
        RTSMB_DEBUG_OUTPUT_STR (" (", RTSMB_DEBUG_TYPE_ASCII);
        buffer = rtp_itoa (inCliHdr.command, buffer, 16);
        RTSMB_DEBUG_OUTPUT_STR (buffer, RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (").\n", RTSMB_DEBUG_TYPE_ASCII);

        /**
         * Ok, we now see what kind of command has been requested, and
         * call an appropriate helper function to fill out details of
         * pOutSmbHdr.  Most return a BBOOL, indicating whether we should
         * send a response or not.
         */
        switch (inCliHdr.command)
        {
        case SMB_COM_NEGOTIATE:
            doSend = ProcNegotiateProtocol (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_TREE_CONNECT:
            doSend = ProcTreeConnect (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_TREE_DISCONNECT:
            doSend = ProcTreeDisconnect (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_QUERY_INFORMATION:
            doSend = ProcQueryInformation (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_QUERY_INFORMATION2:
            doSend = ProcQueryInformation2 (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_QUERY_INFORMATION_DISK:
            doSend = ProcQueryInformationDisk (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_SESSION_SETUP_ANDX:
        case SMB_COM_TREE_CONNECT_ANDX:
        case SMB_COM_OPEN_ANDX:
        case SMB_COM_READ_ANDX:
        case SMB_COM_LOGOFF_ANDX:
        case SMB_COM_WRITE_ANDX:
        case SMB_COM_LOCKING_ANDX:
        case SMB_COM_NT_CREATE_ANDX:
            doSend = ProcAndx (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_TRANSACTION:
            doSend = ProcTransaction (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_TRANSACTION2:
            doSend = ProcTransaction2 (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_FIND_CLOSE2:
            doSend = ProcFindClose2 (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_CHECK_DIRECTORY:
            doSend = ProcCheckDirectory (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_OPEN:
            doSend = ProcOpen (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_CLOSE:
            doSend = ProcClose (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_READ:
            doSend = ProcRead (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_SEEK:
            doSend = ProcSeek (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_DELETE:
            doSend = ProcDelete (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_WRITE:
            doSend = ProcWrite (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_ECHO:
            doSend = ProcEcho (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_FLUSH:
            doSend = ProcFlush (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_RENAME:
            doSend = ProcRename (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_MOVE:
            doSend = ProcCopyMove (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf, FALSE);
            break;
        case SMB_COM_COPY:
            doSend = ProcCopyMove (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf, TRUE);
            break;
        case SMB_COM_CREATE_DIRECTORY:
            doSend = ProcCreateDirectory (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_DELETE_DIRECTORY:
            doSend = ProcDeleteDirectory (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_CREATE_NEW:
        case SMB_COM_CREATE:
            doSend = ProcCreate (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_CREATE_TEMPORARY:
            doSend = ProcCreateTemporary (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_PROCESS_EXIT:
            doSend = ProcProcessExit (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_WRITE_AND_CLOSE:
            doSend = ProcWriteAndClose (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_SEARCH:
            doSend = ProcSearch (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_NT_CANCEL:
            /**
             * NT_CANCEL is used to cancel a process already going on.
             * The server is supposed to 'hurry it along'.  We don't
             * implement anything that needs to be 'hurried along',
             * so just quietly ignore (this smb does not need a response).
             */
            doSend = FALSE;
            break;
        case SMB_COM_SET_INFORMATION:
            doSend = ProcSetInformation (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_SET_INFORMATION2:
            doSend = ProcSetInformation2 (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_OPEN_PRINT_FILE:
            doSend = ProcOpenPrintFile (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_CLOSE_PRINT_FILE:
            doSend = ProcClosePrintFile (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_WRITE_PRINT_FILE:
            doSend = ProcWritePrintFile (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;

        case SMB_COM_READ_RAW:
            doSend = ProcReadRaw (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
            break;
        case SMB_COM_WRITE_RAW:
        {
            PFBYTE temp;

            doSend = ProcWriteRaw1 (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);

            /**
             * Request a big buffer.  If other sessions are using up these resources,
             * don't bother waiting, just tell client to use normal write.
             */
            temp = allocateBigBuffer ();

            if (temp == (PFBYTE)0)
            {
                SMBU_FillError (pSctx, &outCliHdr, SMB_EC_ERRSRV, SMB_ERRSRV_USESTD);
            }
            else
            {
                if (outCliHdr.status == 0)
                {
                    pSctx->readBuffer = temp;
                    pSctx->readBufferSize = (word) (SMB_BIG_BUFFER_SIZE & 0xFFFF);
                    pSctx->writeRawInfo.amWritingRaw = TRUE;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SRV_SESSION_STATE (WRITING_RAW);
#endif
                    pSctx->state = WRITING_RAW;
                    pInBuf = (PFBYTE) SMB_INBUF (pSctx);
                }
                else
                {
                    /**
                     * If an error was encountered, free the big buffer.
                     */
                    freeBigBuffer (pSctx->readBuffer);
                }
            }
        }
            break;

        /**
         * We don't yet fully support print queuing.
         */
        case SMB_COM_GET_PRINT_QUEUE:   /* OPTIONAL command -- win95 doesn't have it */

        /**
         * SMBFile doesn't support bulk.
         */
        case SMB_COM_READ_BULK:
        case SMB_COM_WRITE_BULK:
        case SMB_COM_WRITE_BULK_DATA:


        /**
         * SMBFile doesn't support range locking or file attributes.
         */
        case SMB_COM_LOCK_BYTE_RANGE:
        case SMB_COM_UNLOCK_BYTE_RANGE:
        case SMB_COM_WRITE_AND_UNLOCK:
        case SMB_COM_LOCK_AND_READ:

        /**
         * The following are only used in connection-less transports.
         * Since TCP/IP is connection-oriented, we ignore these.
         */
        case SMB_COM_READ_MPX:
        case SMB_COM_WRITE_MPX:
        case SMB_COM_READ_MPX_SECONDARY:
        case SMB_COM_TRANSACTION_SECONDARY:
        case SMB_COM_TRANSACTION2_SECONDARY:
        case SMB_COM_NT_TRANSACT_SECONDARY:

        /**
         * Not supported but in SNIA technical reference
         */
        case SMB_COM_QUERY_SERVER:
        case SMB_COM_NEW_FILE_SIZE:

        /**
         * The following rely on Windows specific functionality.
         */
        case SMB_COM_IOCTL:
        case SMB_COM_IOCTL_SECONDARY:
        case SMB_COM_NT_TRANSACT:

        /**
         * The following do not have any documentation that I can find
         * and are not widely used it seems (I have never sniffed these on the wire).
         */
        case SMB_COM_FIND:
        case SMB_COM_FIND_UNIQUE:
        case SMB_COM_FIND_NOTIFY_CLOSE:
        case SMB_COM_CLOSE_AND_TREE_DISC:
            {
                char tmpBuffer[32];
                char* buffer = tmpBuffer;
                tmpBuffer[0] = '\0';
                /*RTSMB_DEBUG_OUTPUT_STR ("SMBS_ProcSMBBody: Unimplemented Command ", RTSMB_DEBUG_TYPE_ASCII);   */
                buffer = rtp_itoa (inCliHdr.command, buffer, 16);
                /*RTSMB_DEBUG_OUTPUT_STR (buffer, RTSMB_DEBUG_TYPE_ASCII);   */
                /*RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);     */

            }
            SMBU_FillError (pSctx, &outCliHdr, SMB_EC_ERRSRV, SMB_ERRSRV_NOSUPPORT);
            doSend = TRUE;
            break;

        default:
            {
                char tmpBuffer[32];
                char* buffer = tmpBuffer;
                tmpBuffer[0] = '\0';
                /*RTSMB_DEBUG_OUTPUT_STR ("SMBS_ProcSMBBody: Unknown Command", RTSMB_DEBUG_TYPE_ASCII);   */
                buffer = rtp_itoa (inCliHdr.command, buffer, 16);
                /*RTSMB_DEBUG_OUTPUT_STR (buffer, RTSMB_DEBUG_TYPE_ASCII);   */
                /*RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);     */
            }
            SMBU_FillError (pSctx, &outCliHdr, SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD);
            doSend = TRUE;
            break;
        }
    }

    return doSend;
}

static void DebugOutputSMBCommand(int command)
{
#ifdef RTSMB_DEBUG
    switch(command)
    {
    case SMB_COM_CREATE_DIRECTORY :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_CREATE_DIRECTORY", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_DELETE_DIRECTORY:
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_DELETE_DIRECTORY", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_OPEN:
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_OPEN", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_CREATE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_CREATE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_CLOSE:
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_CLOSE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_FLUSH:
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_FLUSH", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_DELETE:
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_DELETE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_RENAME:
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_RENAME", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_QUERY_INFORMATION :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_QUERY_INFORMATION", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_SET_INFORMATION :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_SET_INFORMATION", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_READ :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_READ", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_WRITE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_WRITE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_LOCK_BYTE_RANGE :
        RTSMB_DEBUG_OUTPUT_STR ("", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_UNLOCK_BYTE_RANGE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_LOCK_BYTE_RANGE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_CREATE_TEMPORARY :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_CREATE_TEMPORARY", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_CREATE_NEW :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_CREATE_NEW", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_CHECK_DIRECTORY :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_CHECK_DIRECTORY", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_PROCESS_EXIT :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_PROCESS_EXIT", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_SEEK :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_SEEK", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_LOCK_AND_READ :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_LOCK_AND_READ", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_WRITE_AND_UNLOCK :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_WRITE_AND_UNLOCK", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_READ_RAW :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_READ_RAW", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_READ_MPX :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_READ_MPX", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_READ_MPX_SECONDARY :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_READ_MPX_SECONDARY", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_WRITE_RAW :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_WRITE_RAW", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_WRITE_MPX :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_WRITE_MPX", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_QUERY_SERVER :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_QUERY_SERVER", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_WRITE_COMPLETE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_WRITE_COMPLETE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_SET_INFORMATION2 :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_SET_INFORMATION2", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_QUERY_INFORMATION2 :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_QUERY_INFORMATION2", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_LOCKING_ANDX :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_LOCKING_ANDX", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_TRANSACTION :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_TRANSACTION", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_TRANSACTION_SECONDARY :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_TRANSACTION_SECONDARY", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_IOCTL :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_IOCTL", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_IOCTL_SECONDARY :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_IOCTL_SECONDARY", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_COPY :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_COPY", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_MOVE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_MOVE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_ECHO :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_ECHO", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_WRITE_AND_CLOSE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_WRITE_AND_CLOSE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_OPEN_ANDX :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_OPEN_ANDX", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_READ_ANDX :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_READ_ANDX", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_WRITE_ANDX :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_WRITE_ANDX", RTSMB_DEBUG_TYPE_ASCII);
        break;

    case SMB_COM_CLOSE_AND_TREE_DISC :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_CLOSE_AND_TREE_DISC", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_TRANSACTION2 :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_TRANSACTION2", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_TRANSACTION2_SECONDARY :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_TRANSACTION2_SECONDARY", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_FIND_CLOSE2 :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_FIND_CLOSE2", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_FIND_NOTIFY_CLOSE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_FIND_NOTIFY_CLOSE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_TREE_CONNECT :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_TREE_CONNECT", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_TREE_DISCONNECT :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_TREE_DISCONNECT", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_NEGOTIATE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_NEGOTIATE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_SESSION_SETUP_ANDX :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_SESSION_SETUP_ANDX", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_LOGOFF_ANDX :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_LOGOFF_ANDX", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_TREE_CONNECT_ANDX :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_TREE_CONNECT_ANDX", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_QUERY_INFORMATION_DISK :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_QUERY_INFORMATION_DISK", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_SEARCH :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_SEARCH", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_FIND :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_FIND", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_FIND_UNIQUE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_FIND_UNIQUE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_NT_TRANSACT :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_NT_TRANSACT", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_NT_TRANSACT_SECONDARY :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_NT_TRANSACT_SECONDARY", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_NT_CREATE_ANDX :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_NT_CREATE_ANDX", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_NT_CANCEL :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_NT_CANCEL", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_OPEN_PRINT_FILE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_OPEN_PRINT_FILE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_WRITE_PRINT_FILE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_WRITE_PRINT_FILE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_CLOSE_PRINT_FILE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_CLOSE_PRINT_FILE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    case SMB_COM_GET_PRINT_QUEUE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_GET_PRINT_QUEUE", RTSMB_DEBUG_TYPE_ASCII);
        break;

#define SMB_COM_READ_BULK 0xD8
#define SMB_COM_WRITE_BULK 0xD9
#define SMB_COM_WRITE_BULK_DATA 0xDA

    case SMB_COM_NONE :
        RTSMB_DEBUG_OUTPUT_STR ("SMB_COM_NONE", RTSMB_DEBUG_TYPE_ASCII);
        break;
    default:
        RTSMB_DEBUG_OUTPUT_STR ("UNKOWN COMMAND", RTSMB_DEBUG_TYPE_ASCII);
        break;
    }
#endif /* RTSMB_DEBUG */
}

static void DebugOutputTrans2Command(int command)
{
#ifdef RTSMB_DEBUG
/*char *Commandname;                                                                   */
/*  Commandname = trans2Commandname(command);                                          */
/*  if (!Commandname)                                                                  */
/*      Commandname = "UNKOWN TRANS2 COMMAND";                                         */
    /*RTSMB_DEBUG_OUTPUT_STR ("Processing trans 2 command: ", RTSMB_DEBUG_TYPE_ASCII); */
    /*RTSMB_DEBUG_OUTPUT_STR (Commandname, RTSMB_DEBUG_TYPE_ASCII);                    */
    /*RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);                           */
#endif
}
static char *trans2Commandname(int command)
{
#ifdef RTSMB_DEBUG
    switch(command)
    {
    case TRANS2_OPEN2:
        return("TRANS2_OPEN2");
    case TRANS2_FIND_FIRST2:
        return("TRANS2_FIND_FIRST2");
    case TRANS2_FIND_NEXT2:
        return("TRANS2_FIND_NEXT2");
    case TRANS2_QUERY_FS_INFORMATION:
        return("TRANS2_QUERY_FS_INFORMATION");
    case TRANS2_QUERY_PATH_INFORMATION:
        return("TRANS2_QUERY_PATH_INFORMATION");
    case TRANS2_SET_PATH_INFORMATION:
        return("TRANS2_SET_PATH_INFORMATION");
    case TRANS2_QUERY_FILE_INFORMATION:
        return("TRANS2_QUERY_FILE_INFORMATION");
    case TRANS2_SET_FILE_INFORMATION:
        return("TRANS2_SET_FILE_INFORMATION");
    case TRANS2_FSCTL:
        return("TRANS2_FSCTL");
    case TRANS2_IOCTL2:
        return("TRANS2_IOCTL2");
    case TRANS2_FIND_NOTIFY_FIRST:
        return("TRANS2_FIND_NOTIFY_FIRST");
    case TRANS2_FIND_NOTIFY_NEXT:
        return("TRANS2_FIND_NOTIFY_NEXT");
    case TRANS2_CREATE_DIRECTORY:
        return("TRANS2_CREATE_DIRECTORY");
    case TRANS2_SESSION_SETUP:
        return("TRANS2_SESSION_SETUP");
    case TRANS2_GET_DFS_REFERRAL:
        return("TRANS2_GET_DFS_REFERRAL");
    case TRANS2_REPORT_DFS_INCONSISTENCY:
        return("TRANS2_REPORT_DFS_INCONSISTENCY");
    default:
        return(0);
    }
#else
    return(0);
#endif /* RTSMB_DEBUG */
}

#endif /* INCLUDE_RTSMB_SERVER */
