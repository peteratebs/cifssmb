//
// CLISSN.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  [tbd]
//

#include "smbdefs.h"
#ifdef SUPPORT_SMB2
#include "com_smb2.h"
#endif

#if (INCLUDE_RTSMB_CLIENT)
#include "clissn.h"
#include "cliwire.h"
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
#include "smbconf.h"
#include "smbdebug.h"

#include "rtptime.h"
#include "rtpnet.h"
#include "rtpthrd.h"
#include "rtpwcs.h"
#include "rtpprint.h"

/* ********************************************************************     */
#define INCLUDE_ANON_AUTOMATIC 0   /* anonymous login done automatically after
                                      Negotiate */
#define INCLUDE_ANON_AUTOMATIC_CARE 0  /* DO NOT CHANGE - leave as 0 */
#define INCLUDE_NQ_NEG_AUTOMATIC 0 /* Negotiate done automatically after
                                      Name Query - with_name() -
                                      with_name() replaced by
                                      resolve_name and name_with_ip */
#define ENUM_SRV_ALL 0            /* have enum server do everything */
#define TRY_NAME 1  /* new implementation on new_name */

#define DEBUG_SID              1
#define DEBUG_ENUM_SERVER      0
#define DEBUG_SESSION_ON_WIRE  0
#define DEBUG_LOGON            0
#define DEBUG_LOGON_JOB_HELPER 0
#define DEBUG_AUTH_JOB         0
#define DEBUG_AUTH             0
#define DEBUG_JOB              0



#ifdef SUPPORT_SMB2
int           rtsmb_cli_wire_smb2_stream_flush(PRTSMB_CLI_WIRE_SESSION pSession, smb2_stream  *pStream);
smb2_stream  *rtsmb_cli_wire_smb2_stream_construct (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
smb2_stream  *rtsmb_cli_wire_smb2_stream_get(PRTSMB_CLI_WIRE_SESSION pSession, word mid);
#endif

/****************************************************************************  */
/* Macros
 *****************************************************************************/
#define RTSMB_CLI_MAX_FAILED_CONNECTIONS   1 /* maximum number of times a connection will be restarted to see if server will work */

/****************************************************************************  */
/* DIAGNOSTIC MACROS */
/****************************************************************************  */
/* Un-comment the next line to print state diagnostics. They are verbose but useful with careful study   */

#if (0)
#define STATE_DIAGNOSTICS
#define STATE_DIAGNOSTICS_SIMPLE
#endif

#ifdef STATE_DIAGNOSTICS

typedef struct s_RTSMB_STATE_DIAGNOSIS
{
    RTSMB_CLI_SESSION_STATE       sessionState;
    RTSMB_CLI_SESSION_USER_STATE  userState;
    RTSMB_CLI_SESSION_SHARE_STATE shareState;
    RTSMB_CLI_SESSION_JOB_STATE   jobState;
    RTSMB_CLI_WIRE_BUFFER_STATE   wireBufferState;
    RTSMB_CLI_WIRE_SESSION_STATE  wireSessionState;
    int                           srvSearchState;
    int                           rpcState;
}RTSMB_STATE_DIAGNOSIS;

RTSMB_STATE_DIAGNOSIS STATE_LOG = {0};
int  DIAGNOSTIC_INDEX = 1;

const char *SessionStateName[] = {"UNUSED", "DEAD  ", "QUERYING", "CONNECTING", "UNCONNECTED",
                                  "NEGOTIATED", "RECOVERY_QUERYING", "RECOVERY_NEGOTIATING",
                                  "RECOVERY_NEGOTIATED", "RECOVERY_LOGGING_ON",
                                  "RECOVERY_LOGGED_ON", "RECOVERY_TREE_CONNECTING",
                                  "RECOVERY_TREE_CONNECTED", "RECOVERY_FILE_OPENING",
                                  "RECOVERY_FILE_OPENED"};

const char *UserStateName[] = {"UNUSED", "LOGGING ON", "LOGGED ON", "DIRTY"};
const char *ShareStateName[] = {"UNUSED", "CONNECTING", "CONNECTED", "DIRTY"};
const char *JobStateName[] = {"UNUSED", "FAKE  ", "STALLED", "WAITING", "DIRTY"};
const char *ServerSearchStateName[] = {"UNUSED", "BACK UP", "LOGGING ON", "REQUESTING", "DATA READY",
                                       "BACKUP AGAIN", "DONE LOCAL", "FINISH"};
const char *WireBufferStateName[] = {"UNUSED", "BEING FILLED", "WAITING ON SERVER", "WAITING ON US", "TIMEOUT", "DONE"};
const char *WireSessionStateName[] = {"DEAD  ", "UNCONNECTED", "CONNECTED", "NBSCONNECTED"};
const char *RPCStateName[] = {"Error", "RD_Bind_Ack_Err", "WR_Bind_Ack_Err", "Create Pipe Err", "Tree Connect Err", "Init",
                                  "Tree Connect", "Create Pipe", "WR Bind", "Read Bind Ack", "Done"};
const char *StateMachineName[] = {"Session", "Search", "User  ", "Share  ", "Job  ",
                                  "WireBuffer", "WireSession", "RPC  "};

#define PRINT_STATE_CHANGE(a, b, c)  {rtp_printf("%.2d %5d  %s::%s -> %s\n" , DIAGNOSTIC_INDEX++, rtp_get_system_msec(), StateMachineName[a], b, c);}


#define PRINT_STATES()  {rtp_printf("\t\t\t\t\t\t\t| %s\t- %s,\t\t%s\t\t- %s,\n\t\t\t\t\t\t\t| %s\t- %s,\t\t%s\t\t- %s,\n\t\t\t\t\t\t\t| %s\t\t- %s,\t\t%s\t- %s,\n\t\t\t\t\t\t\t| %s\t- %s,\t\t%s\t\t- %s\n---------------------------------------------------------\n" ,\
                                    StateMachineName[0], SessionStateName[STATE_LOG.sessionState],\
                                    StateMachineName[1], ServerSearchStateName[STATE_LOG.srvSearchState],\
                                    StateMachineName[2], UserStateName[STATE_LOG.userState],\
                                    StateMachineName[3], ShareStateName[STATE_LOG.shareState],\
                                    StateMachineName[4], JobStateName[STATE_LOG.jobState],\
                                    StateMachineName[5], WireBufferStateName[STATE_LOG.wireBufferState],\
                                    StateMachineName[6], WireSessionStateName[STATE_LOG.wireSessionState],\
                                    StateMachineName[7], RPCStateName[(STATE_LOG.rpcState+5)]);}

/****************************************************************************  */
#ifdef STATE_DIAGNOSTICS_SIMPLE
#define RTSMB_GET_SESSION_STATE(a)        {PRINT_STATE_CHANGE(0, SessionStateName[STATE_LOG.sessionState], SessionStateName[a]); STATE_LOG.sessionState = a;}
#define RTSMB_GET_SESSION_SEARCH_STATE(a) {PRINT_STATE_CHANGE(1, ServerSearchStateName[STATE_LOG.srvSearchState], ServerSearchStateName[a]); STATE_LOG.srvSearchState = a;}
#define RTSMB_GET_SESSION_USER_STATE(a)   {PRINT_STATE_CHANGE(2, UserStateName[STATE_LOG.shareState], UserStateName[a]); STATE_LOG.userState = a;}
#define RTSMB_GET_SESSION_SHARE_STATE(a)  {PRINT_STATE_CHANGE(3, ShareStateName[STATE_LOG.jobState], ShareStateName[a]); STATE_LOG.shareState = a;}
#define RTSMB_GET_SESSION_JOB_STATE(a)    {PRINT_STATE_CHANGE(4, JobStateName[STATE_LOG.userState], JobStateName[a]); STATE_LOG.jobState = a;}
#define RTSMB_GET_WIRE_BUFFER_STATE(a)    {PRINT_STATE_CHANGE(5, WireBufferStateName[STATE_LOG.wireBufferState], WireBufferStateName[a]); STATE_LOG.wireBufferState = a;}
#define RTSMB_GET_WIRE_SESSION_STATE(a)   {PRINT_STATE_CHANGE(6, WireSessionStateName[STATE_LOG.wireSessionState], WireSessionStateName[a]); STATE_LOG.wireSessionState = a;}
#define RTSMB_GET_RPC_STATE(a)            {PRINT_STATE_CHANGE(7, RPCStateName[STATE_LOG.rpcState+5], RPCStateName[a+5]); STATE_LOG.rpcState = a;}
#define RTSMB_GET_ALL_STATES()            {PRINT_STATES();}
#else

#define RTSMB_GET_SESSION_STATE(a)        {PRINT_STATE_CHANGE(0, SessionStateName[STATE_LOG.sessionState], SessionStateName[a]); STATE_LOG.sessionState = a; PRINT_STATES();}
#define RTSMB_GET_SESSION_SEARCH_STATE(a) {PRINT_STATE_CHANGE(1, ServerSearchStateName[STATE_LOG.srvSearchState], ServerSearchStateName[a]); STATE_LOG.srvSearchState = a; PRINT_STATES();}
#define RTSMB_GET_SESSION_USER_STATE(a)   {PRINT_STATE_CHANGE(2, UserStateName[STATE_LOG.shareState], UserStateName[a]); STATE_LOG.userState = a; PRINT_STATES();}
#define RTSMB_GET_SESSION_SHARE_STATE(a)  {PRINT_STATE_CHANGE(3, ShareStateName[STATE_LOG.jobState], ShareStateName[a]); STATE_LOG.shareState = a; PRINT_STATES();}
#define RTSMB_GET_SESSION_JOB_STATE(a)    {PRINT_STATE_CHANGE(4, JobStateName[STATE_LOG.userState], JobStateName[a]); STATE_LOG.jobState = a; PRINT_STATES();}
#define RTSMB_GET_WIRE_BUFFER_STATE(a)    {PRINT_STATE_CHANGE(5, WireBufferStateName[STATE_LOG.wireBufferState], WireBufferStateName[a]); STATE_LOG.wireBufferState = a; PRINT_STATES();}
#define RTSMB_GET_WIRE_SESSION_STATE(a)   {PRINT_STATE_CHANGE(6, WireSessionStateName[STATE_LOG.wireSessionState], WireSessionStateName[a]); STATE_LOG.wireSessionState = a; PRINT_STATES();}
#define RTSMB_GET_RPC_STATE(a)            {PRINT_STATE_CHANGE(7, RPCStateName[STATE_LOG.rpcState+5], RPCStateName[a+5]); STATE_LOG.rpcState = a; PRINT_STATES();}
#define RTSMB_GET_ALL_STATES()            {PRINT_STATES();}
#endif

void Get_Wire_Buffer_State(int a)
{
    RTSMB_GET_WIRE_BUFFER_STATE(a)
}

void Get_Wire_Session_State(int a)
{
    RTSMB_GET_WIRE_SESSION_STATE(a)
}

#endif /* #ifdef STATE_DIAGNOSTICS */

/****************************************************************************  */
/* string constants   */
RTSMB_STATIC rtsmb_char dialect_lanman[]   = {'L', 'A', 'N', 'M', 'A', 'N', '1', '.', '0', '\0'};
RTSMB_STATIC rtsmb_char dialect_ntlm[]     = {'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', '\0'};

#ifdef SUPPORT_SMB2    /* Some branching to SMB2 from this file, no major processing */
RTSMB_STATIC rtsmb_char srv_dialect_smb2002[] = {'S', 'M', 'B', '2', '.', '0', '0', '2', '\0'};
/* RTSMB_STATIC rtsmb_char srv_dialect_smb2xxx[] = {'S', 'M', 'B', '2', '.', '?', '?', '?', '\0'};   */
#endif



RTSMB_STATIC char       ipc_name []        = {'I', 'P', 'C', '$', '\0'};
RTSMB_STATIC rtsmb_char name_pipe_lanman[] = {'\\', 'P', 'I', 'P', 'E', '\\', 'L', 'A', 'N', 'M', 'A', 'N', '\0'};
/* RTSMB_STATIC rtsmb_char disk_type[]        = {'A', ':', '\0'};   */
RTSMB_STATIC rtsmb_char wildcard_type[]        = {'?', '?', '?', '?', '?', '\0'};

RTSMB_STATIC
rtsmb_char *spoken_dialects[] =
{
    dialect_lanman,
    dialect_ntlm,
#ifdef SUPPORT_SMB2
    srv_dialect_smb2002,
#endif
};

/* should be same size as spoken_dialects above   */
RTSMB_STATIC
RTSMB_CLI_SESSION_DIALECT dialect_types[] =
{
    CSSN_DIALECT_PRE_NT,
    CSSN_DIALECT_NT,
#ifdef SUPPORT_SMB2
    CSSN_DIALECT_SMB2_2002
#endif
};
#define NUM_SPOKEN_DIALECTS (sizeof (spoken_dialects) / sizeof (rtsmb_char *))


#define RTSMB_BASE_FLAGS    0x08

#define RTSMB_BASE_FLAGS2   (SMB_FLG2_LONGNAME | SMB_FLG2_LONGNAME_REQ)


/* ********************************************************************     */
/* LOCAL FUNCTIONS */
/* ********************************************************************     */
RTSMB_STATIC int  rtsmb_cli_session_examine_wire (PRTSMB_CLI_SESSION pSession, int wire_response);
RTSMB_STATIC int  rtsmb_cli_session_process_smbs_on_wire (PRTSMB_CLI_SESSION pSession);
RTSMB_STATIC int  rtsmb_cli_session_handle_job (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int  rtsmb_cli_session_handle_job_timeout (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int  rtsmb_cli_session_handle_bad_connection (PRTSMB_CLI_SESSION pSession);
RTSMB_STATIC int rtsmb_cli_session_name_query (PRTSMB_CLI_SESSION pSession);

RTSMB_STATIC void rtsmb_cli_session_job_new (PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC void rtsmb_cli_session_job_close (PRTSMB_CLI_SESSION_JOB pJob);

RTSMB_STATIC void rtsmb_cli_session_share_new (PRTSMB_CLI_SESSION_SHARE pShare);
#if 0
RTSMB_STATIC PRTSMB_CLI_SESSION_SHARE rtsmb_cli_session_get_share_by_tid (PRTSMB_CLI_SESSION pSession, word tid);
#endif

RTSMB_STATIC PRTSMB_CLI_SESSION_FID rtsmb_cli_session_get_free_fid (PRTSMB_CLI_SESSION pSession);
RTSMB_STATIC void rtsmb_cli_session_fid_new (PRTSMB_CLI_SESSION_FID pFid, int fid);
RTSMB_STATIC void rtsmb_cli_session_fid_close (PRTSMB_CLI_SESSION_FID pFid);

RTSMB_STATIC PRTSMB_CLI_SESSION_SEARCH rtsmb_cli_session_get_free_search (PRTSMB_CLI_SESSION pSession);
RTSMB_STATIC void rtsmb_cli_session_search_new (PRTSMB_CLI_SESSION_SEARCH pSearch, int sid);
RTSMB_STATIC void rtsmb_cli_session_search_close (PRTSMB_CLI_SESSION_SEARCH pSearch);
RTSMB_STATIC PRTSMB_CLI_SESSION_SEARCH rtsmb_cli_session_get_search (PRTSMB_CLI_SESSION pSession, int sid);

RTSMB_STATIC PRTSMB_CLI_SESSION_SHARE_SEARCH rtsmb_cli_session_get_free_share_search (PRTSMB_CLI_SESSION pSession);
RTSMB_STATIC void rtsmb_cli_session_share_search_new (PRTSMB_CLI_SESSION_SHARE_SEARCH pSearch, int sid);
RTSMB_STATIC void rtsmb_cli_session_share_search_close (PRTSMB_CLI_SESSION_SHARE_SEARCH pSearch);
RTSMB_STATIC PRTSMB_CLI_SESSION_SHARE_SEARCH rtsmb_cli_session_get_share_search (PRTSMB_CLI_SESSION pSession, int sid);

RTSMB_STATIC void rtsmb_cli_session_user_new (PRTSMB_CLI_SESSION_USER pUser, word uid);
void rtsmb_cli_session_user_close (PRTSMB_CLI_SESSION_USER pUser);

RTSMB_STATIC int  rtsmb_cli_session_send_job (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int  rtsmb_cli_session_send_negotiate (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);

#ifdef SUPPORT_SMB2
extern int rtsmb2_cli_session_send_negotiate (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_negotiate (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_tree_connect (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_tree_connect_error_handler (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_tree_connect (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_session_setup_error_handler (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_session_setup (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_session_setup (smb2_stream  *psmb2stream);

extern int rtsmb2_cli_session_send_logoff (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_logoff (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_tree_disconnect (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_tree_disconnect (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_read (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_read (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_write (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_write (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_open (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_open (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_close (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_close (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_seek (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_seek (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_truncate (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_truncate (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_flush (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_rename (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_delete (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_mkdir (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_rmdir (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_find_first (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_find_first_error_handler (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_find_first (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_find_next (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_find_next (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_find_close (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_stat (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_stat (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_chmode (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_full_server_enum (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_full_server_enum (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_get_free (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_get_free (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_share_find_first (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_share_find_first (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_send_server_enum (smb2_stream  *psmb2stream);
extern int rtsmb2_cli_session_receive_server_enum (smb2_stream  *psmb2stream);
#endif

RTSMB_STATIC int rtsmb_cli_session_send_session_setup_error_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);
RTSMB_STATIC int rtsmb_cli_session_send_session_setup_pre_nt (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_send_session_setup_nt (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_session_setup (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int  rtsmb_cli_session_receive_negotiate (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);


RTSMB_STATIC int rtsmb_cli_session_send_tree_connect (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_send_tree_connect_error_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);
RTSMB_STATIC int rtsmb_cli_session_receive_tree_connect (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_tree_disconnect (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_tree_disconnect (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_logoff (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_logoff (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_read (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_read (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_open (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_open (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_close (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_close (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_write (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_write (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

#if 0
RTSMB_STATIC int rtsmb_cli_session_send_raw_write (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_raw_write (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);
#endif

RTSMB_STATIC int rtsmb_cli_session_send_seek (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_seek (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_truncate (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_truncate (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_flush (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);

RTSMB_STATIC int rtsmb_cli_session_send_rename (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);

RTSMB_STATIC int rtsmb_cli_session_send_delete (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);

RTSMB_STATIC int rtsmb_cli_session_send_mkdir (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);

RTSMB_STATIC int rtsmb_cli_session_send_rmdir (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);

RTSMB_STATIC int rtsmb_cli_session_send_chmode (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);

RTSMB_STATIC int rtsmb_cli_session_send_find_first (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_find_first (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);
RTSMB_STATIC int rtsmb_cli_session_send_find_first_error_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_find_next (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_find_next (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_find_close (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);

RTSMB_STATIC int rtsmb_cli_session_send_stat (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_stat (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_share_find_first (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_share_find_first (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_server_enum (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_server_enum (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_full_server_enum (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_full_server_enum (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_get_free (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_get_free  (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);


RTSMB_STATIC int rtsmb_cli_session_negotiate (PRTSMB_CLI_SESSION pSession);
RTSMB_STATIC int rtsmb_cli_session_connect_anon (PRTSMB_CLI_SESSION pSession);
RTSMB_STATIC int rtsmb_cli_session_connect_ipc (PRTSMB_CLI_SESSION pSession);

/* ********************************************************************     */
RTSMB_STATIC
int rtsmb_cli_session_get_free_session (void)
{
    int i;

    if (!rtsmb_client_config_initialized)
    {
        return -1;
    }

    RTSMB_CLAIM_MUTEX(prtsmb_cli_ctx->sessions_mutex);

    for (i = 0; i < prtsmb_cli_ctx->max_sessions; i++)
    {
        if (prtsmb_cli_ctx->sessions[i].state == CSSN_STATE_UNUSED)
        {
            prtsmb_cli_ctx->sessions[i].state = CSSN_STATE_DEAD;
            break;
        }
    }

    RTSMB_RELEASE_MUTEX(prtsmb_cli_ctx->sessions_mutex);

    if (i == prtsmb_cli_ctx->max_sessions)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_session_get_free_session: All sessions (%d) are in use. !!!!!!!!!!! \n",prtsmb_cli_ctx->max_sessions);
        return -1;
    }
    else
    {
#if (DEBUG_SID)
        rtp_printf("get free session returned %d\n", i);
#endif

        return i;
    }
}

PRTSMB_CLI_SESSION rtsmb_cli_session_get_session (int i)
{
    if (!prtsmb_cli_ctx->sessions)
    {
        /* sprsprspr */
        rtp_printf("rtsmb_cli_session_get_session: prtsmb_cli_cts->sessions not setup\n");
        rtp_printf("                               make sure rtsmb_cli_init has been called\n");
        return 0;
    }

    if (i < 0 || i >= prtsmb_cli_ctx->max_sessions ||
        prtsmb_cli_ctx->sessions[i].state == CSSN_STATE_UNUSED)
    {
        if (prtsmb_cli_ctx->sessions[i].state != CSSN_STATE_UNUSED)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_session_get_session: Invalid session Id (%d). !!!!!!!!!!! \n",i);
        }
        return 0;
    }
    else
    {
        return &prtsmb_cli_ctx->sessions[i];
    }
}


RTSMB_STATIC
void rtsmb_cli_session_memclear (PRTSMB_CLI_SESSION pSession)
{
    int i;

#if (DEBUG_SID)
    for (i = 0; i < prtsmb_cli_ctx->max_sessions; i++)
    {
        if (prtsmb_cli_ctx->sessions + i == pSession)
        {
            rtp_printf("session memclear for sid = %d\n", i);
            break;
        }
    }
#endif

    pSession->state = CSSN_STATE_UNCONNECTED;

#ifdef STATE_DIAGNOSTICS
    RTSMB_GET_SESSION_STATE (CSSN_STATE_UNCONNECTED);
#endif

    for (i = 0; i < prtsmb_cli_ctx->max_jobs_per_session; i++)
    {
        pSession->jobs[i].state = CSSN_JOB_STATE_UNUSED;
    }

    for (i = 0; i < prtsmb_cli_ctx->max_shares_per_session; i++)
    {
        pSession->shares[i].state = CSSN_SHARE_STATE_UNUSED;
    }

    for (i = 0; i < prtsmb_cli_ctx->max_fids_per_session; i++)
    {
        pSession->fids[i].real_fid = -1;
    }

    for (i = 0; i < prtsmb_cli_ctx->max_searches_per_session; i++)
    {
        pSession->searches[i].sid = -1;
    }

    pSession->share_search.sid = -1;
    /*
    for (i = 0; i < prtsmb_cli_ctx->max_share_searches_per_session; i++)
    {
        pSession->share_searches[i].sid = -1;
    }
    */

    pSession->user.state = CSSN_USER_STATE_UNUSED;
    pSession->anon.state = CSSN_USER_STATE_UNUSED;
#ifdef STATE_DIAGNOSTICS
    RTSMB_GET_SESSION_USER_STATE (CSSN_USER_STATE_UNUSED);
#endif
}


/* ********************************************************************     */
void rtsmb_cli_session_update_timestamp (PRTSMB_CLI_SESSION pSession)
{
    pSession->timestamp = rtp_get_system_msec ();
}

/* ********************************************************************     */
/* GET IP FOR NAME */
/* ********************************************************************     */
/* get ip address for Server name */
int rtsmb_cli_session_resolve_name (PFCHAR name, PFBYTE broadcast_ip, PFBYTE ip)
{
    int sid;
    PRTSMB_CLI_SESSION pSession;
    int r;

    ASSURE (name, RTSMB_CLI_SSN_RV_BAD_ARGS);

    sid = rtsmb_cli_session_get_free_session ();
    pSession = rtsmb_cli_session_get_session (sid);

    ASSURE (pSession, RTSMB_CLI_SSN_RV_NOT_ENOUGH_RESOURCES);
    rtsmb_cli_session_update_timestamp (pSession);

    rtsmb_cli_session_memclear (pSession);

    pSession->blocking_mode = TRUE;

    rtp_thread_handle((RTP_HANDLE *) &pSession->owning_thread);

    pSession->state = CSSN_STATE_QUERYING;

#ifdef STATE_DIAGNOSTICS
    RTSMB_GET_SESSION_STATE (CSSN_STATE_QUERYING);
#endif

    if (broadcast_ip)
    {
        tc_memcpy (pSession->broadcast_ip, broadcast_ip, 4);
    }
    else
    {
        tc_memcpy (pSession->broadcast_ip, rtsmb_net_get_broadcast_ip (),4);
    }

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        /* Hard wiring SNGEGO blob   */
        pSession->user.spnego_blob_size = sizeof("Hello from the blob");
        pSession->user.spnego_blob = (PFBYTE)"Hello from the blob";
        /* Attach an SMB2 session structure since that is our prefered dialect   */
        if (rtsmb_cli_smb2_session_init (pSession) < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_new_with_ip: Call to rtsmb_cli_smb2_session_init failed !!!!\n",0);
            return RTSMB_CLI_SSN_RV_NOT_ENOUGH_RESOURCES;
        }
    }
#endif

    /* -------------------------- */
    /* START NEGOTIATION */
    /* -------------------------- */
    tc_strncpy (pSession->server_name, name, RTSMB_NB_NAME_SIZE);
    pSession->server_name[RTSMB_NB_NAME_SIZE] = '\0';
    rtsmb_util_latin_string_toupper (pSession->server_name);

    /* start Negotiate - will block until negotiate complete*/
    r = rtsmb_cli_session_name_query (pSession);
    if (r < 0)
    {
        /* sprsprspr - 1 */
        rtsmb_cli_session_close_session (sid);
        return RTSMB_CLI_SSN_RV_DEAD;
    }

rtp_printf("with_name: IP is %d.%d.%d.%d\n",
    pSession->server_ip[0], pSession->server_ip[1],
    pSession->server_ip[2], pSession->server_ip[3]);

        tc_mv4(ip, pSession->server_ip, 4);

        /* free the session */
        rtsmb_cli_session_close_session (sid);


        return(r);

}

/* ********************************************************************     */
/* RESOLVE WITH IP */
/* ********************************************************************     */
/* called by rtsmb_cli_session_new_with_ip() */
RTSMB_STATIC
int rtsmb_cli_session_init (PRTSMB_CLI_SESSION pSession, PFCHAR name, PFBYTE ip)
{
    rtsmb_cli_wire_session_new (&pSession->wire, name, ip, 1);

    if (name)
    {
        tc_strncpy (pSession->server_name, name, RTSMB_NB_NAME_SIZE);
        pSession->server_name[RTSMB_NB_NAME_SIZE] = '\0';
    }
    else
    {
        tc_strcpy (pSession->server_name, "");
    }

    tc_memcpy (pSession->server_ip, ip, 4);

    return rtsmb_cli_session_negotiate (pSession);
}

RTSMB_STATIC
int rtsmb_cli_session_init_nonblock (PRTSMB_CLI_SESSION pSession, PFCHAR name, PFBYTE ip)
{
    if (name)
    {
        tc_strncpy (pSession->server_name, name, RTSMB_NB_NAME_SIZE);
        pSession->server_name[RTSMB_NB_NAME_SIZE] = '\0';
    }
    else
    {
        tc_strcpy (pSession->server_name, "");
    }

    tc_memcpy (pSession->server_ip, ip, 4);

    return rtsmb_cli_wire_session_new (&pSession->wire, name, ip, 0);
}


/* The use of this function is not reccomended for compatability with older SMB servers.  The functionality   */
/* it provides is outside of the SMB spec, however newer version of Windows client offer this functionality.  */
int rtsmb_cli_session_new_with_ip (PFBYTE ip, PFBYTE broadcast_ip, BBOOL blocking, PFINT psid, RTSMB_CLI_SESSION_DIALECT dialect)
{
    int sid;
    PRTSMB_CLI_SESSION pSession;
#if (INCLUDE_ANON_AUTOMATIC)
    PRTSMB_CLI_SESSION_JOB pFakeJob;
#endif
    int job_off;
    int r;

    sid = rtsmb_cli_session_get_free_session ();
    pSession = rtsmb_cli_session_get_session (sid);

    ASSURE (pSession, RTSMB_CLI_SSN_RV_NOT_ENOUGH_RESOURCES);

    rtsmb_cli_session_update_timestamp (pSession);

    rtsmb_cli_session_memclear (pSession);

    pSession->blocking_mode = blocking;

    /* Force speaking over this dialect   */
    pSession->server_info.dialect = dialect;

    rtp_thread_handle((RTP_HANDLE *) &pSession->owning_thread);

    if (broadcast_ip)
    {
        tc_memcpy (pSession->broadcast_ip, broadcast_ip, 4);
    }
    else
    {
        tc_memcpy (pSession->broadcast_ip, rtsmb_net_get_broadcast_ip (),4);
    }

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        /* Hard wiring SNGEGO blob   */
        pSession->user.spnego_blob_size = sizeof("Hello from the blob");
        pSession->user.spnego_blob = (PFBYTE)"Hello from the blob";
        /* Attach an SMB2 session structure since that is our prefered dialect   */
        if (rtsmb_cli_smb2_session_init (pSession) < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_new_with_ip: Call to rtsmb_cli_smb2_session_init failed !!!!\n",0);
            return RTSMB_CLI_SSN_RV_NOT_ENOUGH_RESOURCES;
        }
    }
#endif

    /* -------------------------- */
    /* start Negotiate Protocol - also setups callbacks for
       fake job to logon as anonymous */
    job_off = rtsmb_cli_session_init (pSession, 0, ip);
    if (job_off < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_new_with_ip: Call to rtsmb_cli_session_init failed !!!!\n",0);
        rtsmb_cli_session_close_session (sid);
        return RTSMB_CLI_SSN_RV_DEAD;
    }

#if (INCLUDE_ANON_AUTOMATIC)
    /* -------------------------- */
    /* We are going to set up a fake job that will be completed when
       all the various negotiate packets (anonymous login $ipc connect)
       are finished.
       The callbacks for this fake job were setup by
       rtsmb_cli_session_negotiate() which is called by
       rtsmb_cli_session_init()
    */
    /* Get free job and set to CSSN_JOB_STATE_STALLED */
    pFakeJob = rtsmb_cli_session_get_free_job (pSession);

    ASSURE (pFakeJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pFakeJob->state = CSSN_JOB_STATE_FAKE;
#ifdef STATE_DIAGNOSTICS
    RTSMB_GET_SESSION_JOB_STATE (CSSN_JOB_STATE_FAKE);
#endif
#endif


#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_new_with_ip: Connected to SMBV2 server\n",0);
        rtsmb_cli_smb2_session_release (pSession);  /* tbd - move this from below - sprspr */
    }
    else
#endif
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_new_with_ip: Connected to SMBV1 server\n",0);
    }

    /*IT WOULD BE COMPATIBLE WITH THE SPEC IF YOU COULD SOMEHOW FIND THE SERVER'S NAME   */
    /*HERE AND SET pSession->server_name, BUT THIS SEEMS IMPOSSIBLE.                     */


#if (INCLUDE_ANON_AUTOMATIC)
    /* -------------------------- */
    /* wait for Negotiate Protocol to complete */
    if (pSession->blocking_mode)
    {
        rtsmb_cli_session_send_stalled_jobs (pSession);
        rtp_printf("rtsmb_cli_session_new_with_ip() - call wait_for_job off = %d\n", job_off);
        r = rtsmb_cli_session_wait_for_job (pSession, job_off);
        rtp_printf("**** rtsmb_cli_session_new_with_ip() - return from wait_for_job with %d; state = %d\n",
            r, pSession->state);
        if (r < 0)
        {
            return(r);
        }
    }
#endif   /* INCLUDE_ANON_AUTOMATIC */

    /* -------------------------- */
    if (psid) *psid = sid;

    /* -------------------------- */
    if (pSession->blocking_mode)
    {
#if (INCLUDE_ANON_AUTOMATIC)
        /* anonymous login tried but only care how Negotiation went so
           ignore failure logon to anonymous and return result
           of Negotiation */
        pSession->state = CSSN_STATE_UNCONNECTED;
        return RTSMB_CLI_SSN_RV_OK;
#else
        /* anonymous login not tried */
        /* wait for Negotiate Protocol to complete */
        rtp_printf("rtsmb_cli_session_new_with_ip() - call wait_for_job for NEGOTIATION; job_off = %d\n", job_off);
        r = rtsmb_cli_session_wait_for_job (pSession, job_off);
        rtp_printf("rtsmb_cli_session_new_with_ip() - return from wait_for_job with r = %d; state = %d\n",
            r, pSession->state);

        return(r);
#endif
    }
    else
    {
#if (INCLUDE_ANON_AUTOMATIC)
        /* non-blocking mode */
        return INDEX_OF (pSession->jobs, pFakeJob);
#else
        return job_off;
#endif
    }

}

/* ********************************************************************     */
/* RESOLVE WITH NAME */
/* ********************************************************************     */
RTSMB_STATIC
int rtsmb_cli_session_send_name_query (PRTSMB_CLI_SESSION pSession)
{
    byte buffer [50];
    int r;
    word id;

    id = (word) (((RTP_ADDR) pSession) & 0xFFFF);
    r = rtsmb_nbns_fill_name_query (buffer, 50, id, pSession->server_name, RTSMB_NB_NAME_TYPE_SERVER);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_DEAD);

    ASSURE (rtp_net_sendto (pSession->broadcast_socket, buffer, r, pSession->broadcast_ip,
                            rtsmb_nbns_port, 4) == r, RTSMB_CLI_SSN_RV_DEAD);
    pSession->broadcast_timeout_base = rtp_get_system_msec ();
    pSession->broadcast_attempts += 1;

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC int rtsmb_cli_session_name_query (PRTSMB_CLI_SESSION pSession)
{
    int r;

    /* set up broadcast socket and then initiate query   */
    ASSURE( rtp_net_socket_datagram(&pSession->broadcast_socket) == 0, -1);

    if (rtp_net_setbroadcast(pSession->broadcast_socket, 1) < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR("Error occurred while trying to set broadcast on socket\n",RTSMB_DEBUG_TYPE_ASCII);
    }

    pSession->broadcast_attempts = 0;

    /* -------------------------- */
    /* start Name Query - will do Negotiate Protocol when done */
    /*   rtsmb_cli_session_cycle() will call rtsmb_cli_session_negotiate()
    /*   when rtsmb_cli_wire_connect_cycle() says ok */
    /* -------------------------- */
    r = rtsmb_cli_session_send_name_query (pSession);
    if (r < 0) return r;

    if (pSession->blocking_mode)
    {
        r = 0;

        /* we do a special wait loop here till we get the name answer   */
        while ((pSession->state == CSSN_STATE_QUERYING ||
                pSession->state == CSSN_STATE_RECOVERY_QUERYING) && r >= 0)
        {
#ifdef STATE_DIAGNOSTICS
            RTSMB_GET_ALL_STATES ();
#endif

            r = rtsmb_cli_session_cycle (INDEX_OF (prtsmb_cli_ctx->sessions, pSession), RTSMB_NB_BCAST_RETRY_TIMEOUT);
        }

        if (r < 0)
        {
            rtsmb_cli_session_close_session (INDEX_OF (prtsmb_cli_ctx->sessions, pSession));
            return RTSMB_CLI_SSN_RV_DEAD;
        }
    }

    return RTSMB_CLI_SSN_RV_OK;
}

#if (TRY_NAME)  /* new implementation on new_name */
int rtsmb_cli_session_new_with_name (PFCHAR name, BBOOL blocking, PFBYTE broadcast_ip, PFINT psid, RTSMB_CLI_SESSION_DIALECT dialect)
{
byte ip[4];
int  r;

    /* get ip address for Server name */
    r = rtsmb_cli_session_resolve_name (name, broadcast_ip, ip);
    if (r < 0)
    {
        SMB_ERROR("rtsmb_cli_session_new_with_name: call to resolve name failed with %d\n",
            r);
    }

    r = rtsmb_cli_session_new_with_ip (ip, broadcast_ip, blocking, psid, dialect);
    return r;

}

#else
int rtsmb_cli_session_new_with_name (PFCHAR name, BBOOL blocking, PFBYTE broadcast_ip, PFINT psid, RTSMB_CLI_SESSION_DIALECT dialect)
{
    int sid,r;
    PRTSMB_CLI_SESSION pSession;
#if (INCLUDE_ANON_AUTOMATIC || 1)
    PRTSMB_CLI_SESSION_JOB pFakeJob;
#endif

    ASSURE (name, RTSMB_CLI_SSN_RV_BAD_ARGS);

    sid = rtsmb_cli_session_get_free_session ();
    pSession = rtsmb_cli_session_get_session (sid);

    ASSURE (pSession, RTSMB_CLI_SSN_RV_NOT_ENOUGH_RESOURCES);
    rtsmb_cli_session_update_timestamp (pSession);

    rtsmb_cli_session_memclear (pSession);

    pSession->blocking_mode = blocking;

    /* Force speaking over this dialect   */
    pSession->server_info.dialect = dialect;

    rtp_thread_handle((RTP_HANDLE *) &pSession->owning_thread);

    pSession->state = CSSN_STATE_QUERYING;

#ifdef STATE_DIAGNOSTICS
    RTSMB_GET_SESSION_STATE (CSSN_STATE_QUERYING);
#endif

    if (broadcast_ip)
    {
        tc_memcpy (pSession->broadcast_ip, broadcast_ip, 4);
    }
    else
    {
        tc_memcpy (pSession->broadcast_ip, rtsmb_net_get_broadcast_ip (), 4);
    }

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        /* Hard wiring SNGEGO blob   */
        pSession->user.spnego_blob_size = sizeof("Hello from the blob");
        pSession->user.spnego_blob = (PFBYTE)"Hello from the blob";

        /* Attach an SMB2 session structure since that is our prefered dialect   */
        if (rtsmb_cli_smb2_session_init (pSession) < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_new_with_ip: Call to rtsmb_cli_smb2_session_init failed !!!!\n",0);
            return RTSMB_CLI_SSN_RV_NOT_ENOUGH_RESOURCES;
        }
    }
#endif

#if (INCLUDE_ANON_AUTOMATIC || 1)
    /* -------------------------- */
    /* We are going to set up a fake job that will be completed when
       all the various negotiate packets are finished. */
    pFakeJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pFakeJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);
#endif

#if (INCLUDE_ANON_AUTOMATIC)
    pFakeJob->state = CSSN_JOB_STATE_FAKE;
#ifdef STATE_DIAGNOSTICS
    RTSMB_GET_SESSION_JOB_STATE (CSSN_JOB_STATE_FAKE);
#endif
#endif

    /* -------------------------- */
    /* START NEGOTIATION */
    /* -------------------------- */
    tc_strncpy (pSession->server_name, name, RTSMB_NB_NAME_SIZE);
    pSession->server_name[RTSMB_NB_NAME_SIZE] = '\0';
    rtsmb_util_latin_string_toupper (pSession->server_name);

    /* start Negotiate - will block until negotiate complete*/
    r = rtsmb_cli_session_name_query (pSession);
    if (r < 0)
    {
        /* sprsprspr - 1 */
        rtsmb_cli_session_close_session (sid);
        return RTSMB_CLI_SSN_RV_DEAD;
    }

    /* -------------------------- */
    if (psid) *psid = sid;

    /* -------------------------- */
#if (INCLUDE_ANON_AUTOMATIC || 1)
    if (pSession->blocking_mode)
    {
        rtp_printf("***** with_name: WAIT\n");
        /* sprsprspr - 1 */
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pFakeJob));
        rtp_printf("***** with_name: RETURNED %d\n", r);
        if (r < 0)
        {
            rtsmb_cli_session_close_session (sid);
        }
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pFakeJob);
    }
#else
        return RTSMB_CLI_SSN_RV_OK;
#endif
}
#endif

/* ********************************************************************     */
/* CLOSE, RESTART SESSION */
/* ********************************************************************     */

void rtsmb_cli_session_close_session (int sid)
{
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);

    if (pSession)
    {
        rtsmb_cli_wire_session_close (&pSession->wire);
        pSession->state = CSSN_STATE_UNUSED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_UNUSED);
#endif
    }
}

int rtsmb_cli_session_restart (int sid)
{
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);

    /* We don't update the timestamp because there may not actually be
       any activity going on here.  This way, if there is not a
       reconnection, this session is a good candidate for being dropped. */
//  rtsmb_cli_session_update_timestamp (pSession);

    return rtsmb_cli_session_handle_bad_connection (pSession);
}

int rtsmb_cli_session_set_blocking (int sid, BBOOL blocking)
{
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    pSession->blocking_mode = blocking;

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_name_query_cycle (PRTSMB_CLI_SESSION pSession, long timeout)
{
    RTP_SOCKET sock = pSession->broadcast_socket;
    byte temp_buffer [RTSMB_NB_MAX_DATAGRAM_SIZE];
    byte ip [4];

    /* check if we need to end earlier than 'timeout' allows */
    if (timeout >= 0 &&
        IS_PAST_THIS (rtp_get_system_msec () + (dword)timeout, pSession->broadcast_timeout_base, RTSMB_NB_BCAST_RETRY_TIMEOUT))
    {
        timeout = (long) pSession->broadcast_timeout_base +
                  (long) RTSMB_NB_BCAST_RETRY_TIMEOUT -
                  (long) rtp_get_system_msec ();

        if (timeout < 0)
        {
            timeout = 0;
        }
    }

    if (rtsmb_netport_select_n_for_read (&sock, 1, timeout))
    {
        int r;
        int best_addr_score = -1;
        RTSMB_NBNS_NAME_INFO info[5];

        r = rtp_net_recv(sock, temp_buffer, RTSMB_NB_MAX_DATAGRAM_SIZE);

        if (r < 0)
        {
            return RTSMB_CLI_SSN_RV_DEAD;
        }

        r = rtsmb_nbns_read_name_query_response(temp_buffer, RTSMB_NB_MAX_DATAGRAM_SIZE, info, 5);

        if (r > 0)
        {
            int n, c;
            int current_score;
            PFBYTE my_addr = rtsmb_net_get_host_ip ();

            for (n = 0; n < r; n++)
            {
                if (info[n].ip_addr[0] == 169 && info[n].ip_addr[1] == 254)
                {
                    continue;
                }

                current_score = 0;
                for (c = 0; c < 4; c++)
                {
                    if (info[n].ip_addr[c] == my_addr[c])
                    {
                        current_score += 8;
                    }
                    else
                    {
                        int b = 0x80;
                        for (; b; b >>= 1)
                        {
                            if ((info[n].ip_addr[c] & b) == (my_addr[c] & b))
                            {
                                current_score++;
                            }
                            else
                            {
                                break;
                            }
                        }
                        break;
                    }
                }

                if (current_score > best_addr_score)
                {
                    best_addr_score = current_score;
                    rtp_memcpy(ip, info[n].ip_addr, 4);
                }
            }
        }

        if (best_addr_score > -1)
        {
            if (rtp_net_closesocket(pSession->broadcast_socket))
            {
                RTSMB_DEBUG_OUTPUT_STR("ERROR IN CLOSESOCKET\n",RTSMB_DEBUG_TYPE_ASCII);
            }

            pSession->state = (pSession->state == CSSN_STATE_QUERYING) ?
                CSSN_STATE_UNCONNECTED : CSSN_STATE_RECOVERY_NEGOTIATING;

#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (pSession->state);
#endif
#if (!INCLUDE_NQ_NEG_AUTOMATIC)
            tc_memcpy (pSession->server_ip, ip, 4);
#else
            //if (rtsmb_cli_session_init (pSession, pSession->server_name, ip) < 0)
            if (rtsmb_cli_session_init_nonblock (pSession, pSession->server_name, ip) < 0)
            {
                rtsmb_cli_session_close_session (INDEX_OF (prtsmb_cli_ctx->sessions, pSession));
                return RTSMB_CLI_SSN_RV_DEAD;
            }

            pSession->state = CSSN_STATE_CONNECTING;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_CONNECTING);
#endif
#endif
            return RTSMB_CLI_SSN_RV_OK;
        }
    }

    if (IS_PAST (pSession->broadcast_timeout_base, RTSMB_NB_BCAST_RETRY_TIMEOUT))
    {
        if (pSession->broadcast_attempts < RTSMB_NB_BCAST_RETRY_COUNT)
        {
            rtsmb_cli_session_send_name_query (pSession);
        }
        else
        {
            return RTSMB_CLI_SSN_RV_DEAD;
        }
    }

    return RTSMB_CLI_SSN_RV_OK;
}

int rtsmb_cli_session_cycle (int sid, long timeout)
{
    int r;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);


    if (pSession->state == CSSN_STATE_QUERYING ||
        pSession->state == CSSN_STATE_RECOVERY_QUERYING)
    {
        /* can't do normal stuff, we must wait for query response */
        return rtsmb_cli_session_name_query_cycle (pSession, timeout);
    }

    if (pSession->state == CSSN_STATE_CONNECTING)
    {
        switch (rtsmb_cli_wire_connect_cycle(&pSession->wire))
        {
            case RTSMB_CLI_SSN_RV_IN_PROGRESS:
                return RTSMB_CLI_SSN_RV_OK;

            case RTSMB_CLI_SSN_RV_OK:
                // we're connected!
                rtsmb_cli_session_negotiate (pSession);
                pSession->state = CSSN_STATE_UNCONNECTED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_UNCONNECTED);
#endif
                break;

            default:
                return RTSMB_CLI_SSN_RV_DEAD;
        }
    }

    /* check for recovery states: */
    /* log back on any users */
    /* reconnect to shares */
    /* reopen files */
    /* restart outstanding jobs */

    if (pSession->state == CSSN_STATE_RECOVERY_NEGOTIATED)
    {
        if (pSession->user.state == CSSN_USER_STATE_DIRTY)
        {
            int rv;

            pSession->state = CSSN_STATE_RECOVERY_LOGGING_ON;
            pSession->user.state = CSSN_USER_STATE_UNUSED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_USER_STATE (CSSN_USER_STATE_UNUSED);
#endif

            // TODO need to test this branch
            rv = rtsmb_cli_session_logon_user_rt (sid, pSession->user.name, pSession->user.password, pSession->user.domain_name);

            return rv < 0 ? rv : RTSMB_CLI_SSN_RV_OK;
        }
        else
        {
            pSession->state = CSSN_STATE_RECOVERY_LOGGED_ON;
            return RTSMB_CLI_SSN_RV_OK;
        }
    }

    if (pSession->state == CSSN_STATE_RECOVERY_LOGGED_ON ||
        pSession->state == CSSN_STATE_RECOVERY_TREE_CONNECTED)
    {
        int i;

        for (i = 0; i < prtsmb_cli_ctx->max_shares_per_session; i++)
        {
            if (pSession->shares[i].state == CSSN_SHARE_STATE_DIRTY)
            {
                int rv;

                pSession->state = CSSN_STATE_RECOVERY_TREE_CONNECTING;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_RECOVERY_TREE_CONNECTING);
#endif
                rv = rtsmb_cli_session_connect_share (sid, pSession->shares[i].share_name, pSession->shares[i].password);

                return rv < 0 ? rv : RTSMB_CLI_SSN_RV_OK;
            }
        }

        pSession->state = CSSN_STATE_RECOVERY_TREE_CONNECTED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_RECOVERY_TREE_CONNECTED);
#endif
    }

    if (pSession->state == CSSN_STATE_RECOVERY_TREE_CONNECTED ||
        pSession->state == CSSN_STATE_RECOVERY_FILE_OPENED)
    {
        int i;

        for (i = 0; i < prtsmb_cli_ctx->max_fids_per_session; i++)
        {
            if (pSession->fids[i].real_fid == CSSN_FID_STATE_DIRTY)
            {
                int rv, flags;

                pSession->state = CSSN_STATE_RECOVERY_FILE_OPENING;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_RECOVERY_FILE_OPENING);
#endif

                /* we only want some of the flags, so that we open it correctly */
                flags = pSession->fids[i].flags & 0x31F;

                rv = rtsmb_cli_session_open_rt (sid, pSession->fids[i].owning_share->share_name, pSession->fids[i].name, flags, 0, 0);

                return rv < 0 ? rv : RTSMB_CLI_SSN_RV_OK;
            }
        }

        /* no files left to reopen -- let's restart jobs */
        pSession->state = CSSN_STATE_NEGOTIATED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_NEGOTIATED);
#endif
        for (i = 0; i < prtsmb_cli_ctx->max_jobs_per_session; i++)
        {
            if (pSession->jobs[i].state == CSSN_JOB_STATE_DIRTY)
            {
                pSession->jobs[i].state = CSSN_JOB_STATE_STALLED;
                pSession->jobs[i].send_count = 0;
            }
        }
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);
    r = rtsmb_cli_wire_cycle (&pSession->wire, timeout);

    return rtsmb_cli_session_examine_wire (pSession, r);
}

int rtsmb_cli_session_set_job_callback (int sid, int job, RTSMB_JOB_CALLBACK callback, PFVOID data)
{
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    if (job < 0 || job >= prtsmb_cli_ctx->max_jobs_per_session ||
        pSession->jobs[job].state == CSSN_JOB_STATE_UNUSED)
    {
        return RTSMB_CLI_SSN_RV_BAD_JOB;
    }

    pSession->jobs[job].callback = callback;
    pSession->jobs[job].callback_data = data;

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
void rtsmb_cli_session_wait_for_job_helper (int job, int r, PFVOID data)
{
    PFINT prv = (PFINT) data;

#if (DEBUG_LOGON_JOB_HELPER)
    printf("rtsmb_cli_session_wait_for_job_helper for job %d called with rv == %d\n",job, r);
#endif

    *prv = r;
}

int rtsmb_cli_session_wait_for_job (PRTSMB_CLI_SESSION pSession, int job)
{
    int rv = RTSMB_CLI_SSN_RV_INVALID_RV;
    RTSMB_JOB_CALLBACK old_callback;
    PFVOID old_callback_data;

#if (DEBUG_JOB)
    rtp_printf("rtsmb_cli_session_wait_for_job: session = %x, job = %d\n",
        pSession, job);
#endif
    if (job < 0 || job >= prtsmb_cli_ctx->max_jobs_per_session ||
        pSession->jobs[job].state == CSSN_JOB_STATE_UNUSED)
    {
#if (DEBUG_JOB)
        rtp_printf("rtsmb_cli_session_wait_for_job: max jobs = %d; state = %d \n",
            prtsmb_cli_ctx->max_jobs_per_session, pSession->jobs[job].state);
#endif
        return RTSMB_CLI_SSN_RV_BAD_JOB;
    }

    /* back up callback info before we overwrite it */
    old_callback = pSession->jobs[job].callback;
    old_callback_data = pSession->jobs[job].callback_data;
    if (rtsmb_cli_session_set_job_callback (INDEX_OF (prtsmb_cli_ctx->sessions, pSession), job, rtsmb_cli_session_wait_for_job_helper, &rv))
    {
#if (DEBUG_JOB)
        rtp_printf("rtsmb_cli_session_wait_for_job: callback failed\n");
#endif
        return RTSMB_CLI_SSN_RV_BAD_JOB;
    }

    while (rv == RTSMB_CLI_SSN_RV_INVALID_RV)
    {
        int r = rtsmb_cli_session_cycle (INDEX_OF (prtsmb_cli_ctx->sessions, pSession), RTSMB_NB_UCAST_RETRY_TIMEOUT);

        if (r < 0)
        {
#if (DEBUG_JOB)
            rtp_printf("rtsmb_cli_session_wait_for_job: rtsmb_cli_session_cycle returned %d\n",
                r);
#endif
            return r;
        }
    }

    /* ok, we've broken out of the loop, meaning the job is over. Now, call old callback */
    if (old_callback)
    {
        (*old_callback) (job, rv, old_callback_data);
    }

#if (DEBUG_JOB)
    rtp_printf("rtsmb_cli_session_wait_for_job: returns %d\n",
        rv);
#endif
    return rv;
}

RTSMB_STATIC
word rtsmb_cli_session_get_uid (PRTSMB_CLI_SESSION pSession)
{
    if (pSession->server_info.user_mode)
    {
        if (pSession->user.state == CSSN_USER_STATE_LOGGED_ON)
        {
            return pSession->user.uid;
        }
        else if (pSession->anon.state == CSSN_USER_STATE_LOGGED_ON)
        {
            return pSession->anon.uid;
        }
        else
        {
            return INVALID_UID;
        }
    }
    else
    {
        return INVALID_UID;
    }
}

void rtsmb_cli_session_fill_header (PRTSMB_CLI_SESSION pSession, PRTSMB_HEADER pHeader)
{
    /* set up header */
    pHeader->command = SMB_COM_NONE;
    pHeader->flags = RTSMB_BASE_FLAGS;
    pHeader->flags2 = RTSMB_BASE_FLAGS2;

#if (INCLUDE_RTSMB_UNICODE)
    if (pSession->server_info.dialect >= CSSN_DIALECT_NT &&
        ON (pSession->server_info.capabilities, CAP_UNICODE))
    {
        pHeader->flags2 |= SMB_FLG2_UNICODESTR;
    }
#endif

    if (ON (pSession->server_info.capabilities, CAP_STATUS32))
    {
        pHeader->flags2 |= SMB_FLG2_32BITERROR;
    }

    pHeader->status = 0;
    pHeader->tid = INVALID_TID;
    pHeader->uid = rtsmb_cli_session_get_uid (pSession);

    rtp_thread_handle((RTP_HANDLE *) &pHeader->pid);
    tc_memset (pHeader->security_sig, 0, 8);
}


#if (INCLUDE_ANON_AUTOMATIC)   /* anonymous login done automatically */
RTSMB_STATIC
void rtsmb_cli_session_negotiate_helper (int job, int rv, PFVOID data)
{
#if (DEBUG_SESSION_ON_WIRE)
    rtp_printf("PVO rtsmb_cli_session_negotiate_helper was called \n");
#endif

    if (rtsmb_cli_session_connect_anon ((PRTSMB_CLI_SESSION) data) < 0)
    {
#if (!INCLUDE_ANON_AUTOMATIC_CARE)
        rtp_printf("PVO rtsmb_cli_session_negotiate_helper: connect_anon failed  would set dead \n");
        ((PRTSMB_CLI_SESSION) data)->state = CSSN_STATE_NEGOTIATED;
#ifdef STATE_DIAGNOSTICS
        RTSMB_GET_SESSION_STATE (CSSN_STATE_NEGOTIATED);
#endif
#else
#if (DEBUG_SESSION_ON_WIRE || DEBUG_JOB)
        rtp_printf("PVO rtsmb_cli_session_negotiate_helper: connect_anon failed  set dead \n");
#endif

        ((PRTSMB_CLI_SESSION) data)->state = CSSN_STATE_DEAD;

#ifdef STATE_DIAGNOSTICS
        RTSMB_GET_SESSION_STATE (CSSN_STATE_DEAD);
#endif
#endif
    }
}
#endif

RTSMB_STATIC
int rtsmb_cli_session_negotiate (PRTSMB_CLI_SESSION pSession)
{
    PRTSMB_CLI_SESSION_JOB pJob;

    pJob = rtsmb_cli_session_get_free_job (pSession);
#if (DEBUG_AUTH_JOB)
    rtp_printf("rtsmb_cli_session_negotiate: got free pJob = %x\n", pJob);
#endif
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2     = rtsmb2_cli_session_send_negotiate;
        pJob->receive_handler_smb2 =  rtsmb2_cli_session_receive_negotiate;
        HEREHERE;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_negotiate;
        pJob->receive_handler = rtsmb_cli_session_receive_negotiate;
    }

#if (INCLUDE_ANON_AUTOMATIC)
    /* We set up a chain of actions here.  First is negotiate, then
       we connect an anonymous user.  Then, we connect to the IPC. */
    pJob->callback = rtsmb_cli_session_negotiate_helper;
    pJob->callback_data = pSession;
#endif

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->jobs[0].state == CSSN_JOB_STATE_FAKE)
    {
        /* OK, we have a fake job.  That means we should pretend that we are
           that job. */
        pJob = &pSession->jobs[0];
        rtp_printf("rtsmb_cli_session_negotiate() : we are *** FAKE job ****\n");
    }

    return INDEX_OF (pSession->jobs, pJob);
}

#if (INCLUDE_ANON_AUTOMATIC)   /* anonymous login done automatically */
RTSMB_STATIC
void rtsmb_cli_session_connect_ipc_helper (int job, int rv, PFVOID data)
{
#if (DEBUG_SESSION_ON_WIRE)
    rtp_printf("PVO Inside to rtsmb_cli_session_connect_ipc_helper\n");
#endif

    if (((PRTSMB_CLI_SESSION) data)->state == CSSN_STATE_RECOVERY_NEGOTIATING)
    {
        ((PRTSMB_CLI_SESSION) data)->state = CSSN_STATE_RECOVERY_NEGOTIATED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_RECOVERY_NEGOTIATED);
#endif
    }
    else
    {
        ((PRTSMB_CLI_SESSION) data)->state = CSSN_STATE_NEGOTIATED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_NEGOTIATED);
#endif
    }
}
#endif

#if (INCLUDE_ANON_AUTOMATIC)   /* anonymous login done automatically */
RTSMB_STATIC
int rtsmb_cli_session_connect_ipc (PRTSMB_CLI_SESSION pSession)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION_SHARE pShare;
    static rtsmb_char ipc_type[] = {'I', 'P', 'C', '\0'};
    static char share[] = {'I', 'P', 'C', '$', '\0'};

    /* First, see if we alread are connected */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    if (pShare && pShare->state != CSSN_SHARE_STATE_DIRTY)
    {
        return RTSMB_CLI_SSN_RV_ALREADY_CONNECTED;
    }

    if (!pShare)
    {
        /* find free share */
        pShare = rtsmb_cli_session_get_free_share (pSession);
        ASSURE (pShare, RTSMB_CLI_SSN_RV_TOO_MANY_SHARES);
    }

    pJob = rtsmb_cli_session_get_free_job (pSession);
    if (!pJob)
        rtsmb_cli_session_share_close (pShare);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.tree_connect.share_type = ipc_type;
    pJob->data.tree_connect.share_struct = pShare;
    tc_strcpy (pJob->data.tree_connect.share_name, share);
    tc_memset (pJob->data.tree_connect.password, 0, 2);

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2         = rtsmb2_cli_session_send_tree_connect;
        pJob->error_handler_smb2        = rtsmb2_cli_session_send_tree_connect_error_handler;
        pJob->receive_handler_smb2      = rtsmb2_cli_session_receive_tree_connect;

#if (DEBUG_SESSION_ON_WIRE)
        rtp_printf("PVO set callback to rtsmb_cli_session_connect_ipc_helper == %X\n", (int) rtsmb_cli_session_connect_ipc_helper);
#endif
        pJob->callback                  = rtsmb_cli_session_connect_ipc_helper;
        pJob->callback_data             = pSession;

        HEREHERE;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_tree_connect;
        pJob->error_handler = rtsmb_cli_session_send_tree_connect_error_handler;
        pJob->receive_handler = rtsmb_cli_session_receive_tree_connect;
        pJob->callback = rtsmb_cli_session_connect_ipc_helper;
        pJob->callback_data = pSession;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}
#endif

#if (INCLUDE_ANON_AUTOMATIC)   /* anonymous login done automatically */
RTSMB_STATIC
void rtsmb_cli_session_connect_anon_helper (int job, int rv, PFVOID data)
{
#if (DEBUG_SESSION_ON_WIRE)
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_connect_anon_helper: Called \n",0);
#endif

    /* Try to connect if we didn't already get an error from the server */
    if (rv < 0 || rtsmb_cli_session_connect_ipc ((PRTSMB_CLI_SESSION) data) < 0)
    {
        if (rv < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_connect_anon_helper: Error: rv == %d !!!!!!!!!!!!!!\n",rv);
        }
        else
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_connect_anon_helper: rtsmb_cli_session_connect_ipc failed !!!!!!!! \n",0);
        }
#if (!INCLUDE_ANON_AUTOMATIC_CARE)
        rtp_printf("PVO rtsmb_cli_session_connect_anon_helper: connect_ipc failed  would set dead: rv = %d \n, rv");
        ((PRTSMB_CLI_SESSION) data)->state = CSSN_STATE_NEGOTIATED;
#ifdef STATE_DIAGNOSTICS
        RTSMB_GET_SESSION_STATE (CSSN_STATE_NEGOTIATED);
#endif
#else
#if (DEBUG_SESSION_ON_WIRE)
        rtp_printf("PVO rtsmb_cli_session_connect_anon_helper  set dead \n");
#endif
        ((PRTSMB_CLI_SESSION) data)->state = CSSN_STATE_DEAD;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_DEAD);
#endif
#endif  /* care */
    }
}
#endif

#if (INCLUDE_ANON_AUTOMATIC)   /* anonymous login done automatically */
RTSMB_STATIC
int rtsmb_cli_session_connect_anon (PRTSMB_CLI_SESSION pSession)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    rtsmb_char anon_name[] = {'\0'};

    if (pSession->anon.state == CSSN_USER_STATE_DIRTY)
    {
        /* nothing special need be done */
        pSession->anon.state = CSSN_USER_STATE_UNUSED;
    }
    ASSURE (pSession->anon.state == CSSN_USER_STATE_UNUSED, RTSMB_CLI_SSN_RV_TOO_MANY_USERS);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    rtsmb_cpy (pJob->data.session_setup.account_name, anon_name);
    tc_strcpy (pJob->data.session_setup.password, "");
    pSession->anon.uid = 1;
    pJob->data.session_setup.user_struct = &pSession->anon;


    pJob->error_handler = rtsmb_cli_session_send_session_setup_error_handler;
    pJob->receive_handler = rtsmb_cli_session_receive_session_setup;
    switch (pSession->server_info.dialect)
    {
    case CSSN_DIALECT_PRE_NT:
        pJob->send_handler = rtsmb_cli_session_send_session_setup_pre_nt;
        break;

    case CSSN_DIALECT_NT:
        if (ON (pSession->server_info.capabilities, CAP_EXTENDED_SECURITY))
        {
            SMB_ERROR("rtsmb_cli_session_connect_anon: extended security on -> DEAD");
            /* we currently don't do extended security */
            return RTSMB_CLI_SSN_RV_DEAD;
        }
        else
        {
            pJob->send_handler = rtsmb_cli_session_send_session_setup_nt;
        }
#ifdef SUPPORT_SMB2
    case CSSN_DIALECT_SMB2_2002:
        break;
#endif
    }

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2    = rtsmb2_cli_session_send_session_setup;
        pJob->error_handler_smb2   = rtsmb2_cli_session_send_session_setup_error_handler;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_session_setup;
    }
#endif

    /* We set up a chain of actions here.  First is negotiate, then
       we connect an anonymous user.  Then, we connect to the IPC. */
#if (DEBUG_SESSION_ON_WIRE)
    rtp_printf("PVO set callback to rtsmb_cli_session_connect_anon_helper == %X\n", (int) rtsmb_cli_session_connect_anon_helper);
#endif

    pJob->callback = rtsmb_cli_session_connect_anon_helper;
    pJob->callback_data = pSession;

    rtsmb_cli_session_user_new (&pSession->anon, 0);

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        SMB_ERROR("rtsmb_cli_session_connect_anon: wait for job returned %d\n", r);
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}
#endif

int rtsmb_cli_session_logon_user_rt (int sid, PFRTCHAR user, PFCHAR password, PFRTCHAR domain)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

#if (DEBUG_LOGON)
    rtp_printf("PVO - rtsmb_cli_session_logon_user_rt \n");
#endif

    if(rtsmb_len(user) > (CFG_RTSMB_MAX_USERNAME_SIZE - 1))
        return RTSMB_CLI_SSN_RV_BAD_ARGS;

    if(rtp_strlen(password) > (CFG_RTSMB_MAX_PASSWORD_SIZE - 1))
        return RTSMB_CLI_SSN_RV_BAD_ARGS;

    if(rtsmb_len(domain) > (CFG_RTSMB_MAX_DOMAIN_NAME_SIZE - 1))
        return RTSMB_CLI_SSN_RV_BAD_ARGS;

#if (DEBUG_LOGON)
    rtp_printf("PVO - rtsmb_cli_session_logon_user_rt 2\n");
#endif

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

#if (DEBUG_LOGON)
    rtp_printf("PVO - rtsmb_cli_session_logon_user_rt 3\n");
#endif

    ASSURE (pSession->user.state == CSSN_USER_STATE_UNUSED, RTSMB_CLI_SSN_RV_TOO_MANY_USERS);
    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pSession->user.uid = 0;
    pJob->data.session_setup.user_struct = &pSession->user;
    rtsmb_cpy (pJob->data.session_setup.account_name, user);
    tc_strcpy (pJob->data.session_setup.password, password);
    rtsmb_cpy (pJob->data.session_setup.domain_name, domain);

#if (DEBUG_LOGON)
    rtp_printf("PVO - rtsmb_cli_session_logon_user_rt 4 dialect == %d\n",pSession->server_info.dialect);
#endif

    pJob->error_handler = rtsmb_cli_session_send_session_setup_error_handler;
    pJob->receive_handler = rtsmb_cli_session_receive_session_setup;

    switch (pSession->server_info.dialect)
    {
    case CSSN_DIALECT_PRE_NT:
        pJob->send_handler = rtsmb_cli_session_send_session_setup_pre_nt;
        break;

    case CSSN_DIALECT_NT:
        if (ON (pSession->server_info.capabilities, CAP_EXTENDED_SECURITY))
        {
            /* we currently don't do extended security */
            return RTSMB_CLI_SSN_RV_DEAD;
        }
        else
        {
            pJob->send_handler = rtsmb_cli_session_send_session_setup_nt;
        }
        break;
#ifdef SUPPORT_SMB2
    case CSSN_DIALECT_SMB2_2002:
        break;
#endif
    }

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_session_setup;
        pJob->error_handler_smb2 = rtsmb2_cli_session_send_session_setup_error_handler;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_session_setup;
    }
#endif
    rtsmb_cli_session_user_new (&pSession->user, 1);

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
rtp_printf("USER LOGON: WAIT\n");
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
rtp_printf("USER LOGON: DONE WAIT returned %d\n", r);
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_logoff_user (int sid)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    if (!(RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect)))
    {
        ASSURE (pSession->user.state == CSSN_USER_STATE_LOGGED_ON, RTSMB_CLI_SSN_RV_NO_USER);
    }
    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_logoff;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_logoff;
        HEREHERE;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_logoff;
        pJob->receive_handler = rtsmb_cli_session_receive_logoff;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_connect_share (int sid, PFCHAR share, PFCHAR password)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION pSession;

#if (DEBUG_SESSION_ON_WIRE)
    rtp_printf("In rtsmb_cli_session_connect_share: share = %s\n", share);
#endif
    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    ASSURE (share, RTSMB_CLI_SSN_RV_BAD_SHARE);

    /* First, see if we alread are connected */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    if (pShare && pShare->state != CSSN_SHARE_STATE_DIRTY)
    {
        return RTSMB_CLI_SSN_RV_ALREADY_CONNECTED;
    }

    if (!pShare)
    {
        /* find free share */
        pShare = rtsmb_cli_session_get_free_share (pSession);
        ASSURE (pShare, RTSMB_CLI_SSN_RV_TOO_MANY_SHARES);
    }
    else
    {
        pShare->state = CSSN_SHARE_STATE_CONNECTING;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_SHARE_STATE_CONNECTING);
#endif
    }

    pJob = rtsmb_cli_session_get_free_job (pSession);
    if (!pJob)
        rtsmb_cli_session_share_close (pShare);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.tree_connect.share_type = wildcard_type; // disk_type;
    pJob->data.tree_connect.share_struct = pShare;
    tc_strcpy (pJob->data.tree_connect.share_name, share);
    if (password)
        tc_strcpy (pJob->data.tree_connect.password, password);
    else
        tc_memset (pJob->data.tree_connect.password, 0, 2);

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_tree_connect;
        pJob->error_handler_smb2 = rtsmb2_cli_session_send_tree_connect_error_handler;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_tree_connect;
        HEREHERE;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_tree_connect;
        pJob->error_handler = rtsmb_cli_session_send_tree_connect_error_handler;
        pJob->receive_handler = rtsmb_cli_session_receive_tree_connect;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}


int rtsmb_cli_session_disconnect_share (int sid, PFCHAR share)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find share */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    ASSURE (pShare->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->data.tree_disconnect.tid = pShare->tid;
        rtsmb_cli_session_share_close (pShare);
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_tree_disconnect;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_tree_disconnect;
    }
    else
#endif
    {
        pJob->data.tree_disconnect.tid = pShare->tid;
        rtsmb_cli_session_share_close (pShare);
        pJob->send_handler = rtsmb_cli_session_send_tree_disconnect;
        pJob->receive_handler = rtsmb_cli_session_receive_tree_disconnect;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_read (int sid, int fid, PFBYTE data, int count, PFINT count_read)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION_FID pFid;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find fid */
    pFid = rtsmb_cli_session_get_fid (pSession, fid);
    ASSURE (pFid, RTSMB_CLI_SSN_RV_BAD_FID);

    /* check share */
    ASSURE (pFid->owning_share->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    if (count > (int) RTSMB_CLI_SESSION_MAX_DATA_BYTES)
    {
        return RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    }

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.read.returned_data_size = count_read;
    pJob->data.read.max_data_size = count;
    pJob->data.read.data = data;
    pJob->data.read.fid_struct = pFid;

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_read;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_read;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_read;
        pJob->receive_handler = rtsmb_cli_session_receive_read;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        return rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_write (int sid, int fid, PFBYTE data, int count, PFINT written)
{
    PRTSMB_CLI_SESSION_FID pFid;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find fid */
    pFid = rtsmb_cli_session_get_fid (pSession, fid);
    ASSURE (pFid, RTSMB_CLI_SSN_RV_BAD_FID);

    /* check share */
    ASSURE (pFid->owning_share->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

  #ifndef INCLUDE_RTSMB_CLI_ZERO_COPY
    if (count > (int) RTSMB_CLI_SESSION_MAX_DATA_BYTES)
    {
        return RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    }
  #endif

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.writex.returned_data_size = written;
    pJob->data.writex.total_to_write = count;
    pJob->data.writex.written_so_far = 0;
    pJob->data.writex.bytes_acked = 0;
    pJob->data.writex.data = data;
    pJob->data.writex.fid_struct = pFid;
#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_write;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_write;
        HEREHERE;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_write;
        pJob->receive_handler = rtsmb_cli_session_receive_write;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}



int rtsmb_cli_session_open_rt (int sid, PFCHAR share, PFRTCHAR file, int flags, int mode, PFINT fid)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find share */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    ASSURE (pShare->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    ASSURE (rtsmb_len (file) <= SMBF_FILENAMESIZE, RTSMB_CLI_SSN_RV_BAD_FILENAME);
    rtsmb_cpy (pJob->data.open.filename, file);
    pJob->data.open.filename[SMBF_FILENAMESIZE] = '\0';
    pJob->data.open.flags = flags;
    pJob->data.open.mode = mode;
    pJob->data.open.returned_fid = fid;
    pJob->data.open.share_struct = pShare;
#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_open;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_open;
        HEREHERE;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_open;
        pJob->receive_handler = rtsmb_cli_session_receive_open;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_close (int sid, int fid)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION_FID pFid;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find fid */
    pFid = rtsmb_cli_session_get_fid (pSession, fid);
    ASSURE (pFid, RTSMB_CLI_SSN_RV_BAD_FID);

    /* check share */
    ASSURE (pFid->owning_share->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.close.fid_struct = pFid;

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_close;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_close;
        HEREHERE;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_close;
        pJob->receive_handler = rtsmb_cli_session_receive_close;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_seek (int sid, int fid, long offset, int location, PFLONG resulting_offset)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION_FID pFid;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find fid */
    pFid = rtsmb_cli_session_get_fid (pSession, fid);
    ASSURE (pFid, RTSMB_CLI_SSN_RV_BAD_FID);

    /* check share */
    ASSURE (pFid->owning_share->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.seek.fid_struct = pFid;
    pJob->data.seek.offset = offset;
    pJob->data.seek.resulting_offset = resulting_offset;

    switch (location)
    {
        case RTSMB_SEEK_SET:
            pJob->data.seek.mode = 0;
            break;
        default:
        case RTSMB_SEEK_CUR:
            pJob->data.seek.mode = 1;
            break;
        case RTSMB_SEEK_END:
            pJob->data.seek.mode = 2;
            break;
    }

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_seek;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_seek;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_seek;
        pJob->receive_handler = rtsmb_cli_session_receive_seek;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_truncate (int sid, int fid, long offset)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION_FID pFid;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find fid */
    pFid = rtsmb_cli_session_get_fid (pSession, fid);
    ASSURE (pFid, RTSMB_CLI_SSN_RV_BAD_FID);

    /* check share */
    ASSURE (pFid->owning_share->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.truncate.fid_struct = pFid;
    pJob->data.truncate.offset = offset;

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_truncate;
        pJob->receive_handler_smb2 = rtsmb2_cli_session_receive_truncate;
        HEREHERE;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_truncate;
        pJob->receive_handler = rtsmb_cli_session_receive_truncate;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_flush (int sid, int fid)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION_FID pFid;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find fid */
    pFid = rtsmb_cli_session_get_fid (pSession, fid);
    ASSURE (pFid, RTSMB_CLI_SSN_RV_BAD_FID);

    /* check share */
    ASSURE (pFid->owning_share->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.flush.fid_struct = pFid;
#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_flush;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_flush;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_rename_rt (int sid, PFCHAR share, PFRTCHAR old_filename, PFRTCHAR new_filename)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find share */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    ASSURE (pShare->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.rename.share_struct = pShare;
    rtsmb_cpy (pJob->data.rename.old_filename, old_filename);
    rtsmb_cpy (pJob->data.rename.new_filename, new_filename);

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_rename;
        HEREHERE;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_rename;
    }
    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_delete_rt (int sid, PFCHAR share, PFRTCHAR filename)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find share */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    ASSURE (pShare->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.delete.share_struct = pShare;
    rtsmb_cpy (pJob->data.delete.filename, filename);

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_delete;
        HEREHERE;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_delete;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_mkdir_rt (int sid, PFCHAR share, PFRTCHAR filename)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find share */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    ASSURE (pShare->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.mkdir.share_struct = pShare;
    rtsmb_cpy (pJob->data.mkdir.filename, filename);
#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_mkdir;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_mkdir;
    }
    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_rmdir_rt (int sid, PFCHAR share, PFRTCHAR filename)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find share */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    ASSURE (pShare->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.rmdir.share_struct = pShare;
    rtsmb_cpy (pJob->data.rmdir.filename, filename);

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_rmdir;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_rmdir;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_find_first_rt (int sid, PFCHAR share, PFRTCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION_SEARCH pSearch;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find share */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    ASSURE (pShare->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pSearch = rtsmb_cli_session_get_free_search (pSession);
    if (!pSearch)
    {
        rtsmb_cli_session_job_close (pJob);
        return RTSMB_CLI_SSN_RV_TOO_MANY_SEARCHES;
    }

    pSearch->share_struct = pShare;
    pJob->data.findfirst.search_struct = pSearch;
    pJob->data.findfirst.answering_dstat = pdstat;
    rtsmb_cpy (pJob->data.findfirst.pattern, pattern);

#if (DEBUG_LOGON_JOB_HELPER)
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_find_first_rt:pJob == %X\n",(int)pJob);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_find_first_rt:pJob->data.findfirst.search_struct == %X\n",(int)pJob->data.findfirst.search_struct);
#endif

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2     = rtsmb2_cli_session_send_find_first;
        pJob->error_handler_smb2    = rtsmb2_cli_session_send_find_first_error_handler;
        pJob->receive_handler_smb2  = rtsmb2_cli_session_receive_find_first;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_find_first;
        pJob->error_handler = rtsmb_cli_session_send_find_first_error_handler;
        pJob->receive_handler = rtsmb_cli_session_receive_find_first;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_find_next (int sid, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
    PRTSMB_CLI_SESSION_SEARCH pSearch;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    pSearch = rtsmb_cli_session_get_search (pSession, pdstat->sid);
    ASSURE (pSearch, RTSMB_CLI_SSN_RV_BAD_SEARCH);

    if (pSearch->index + 1 >= pSearch->num_stats)
    {
        PRTSMB_CLI_SESSION_JOB pJob;

        if (pSearch->end_of_search)
        {
            return RTSMB_CLI_SSN_RV_END_OF_SEARCH;
        }

        /* we have to get more results, so we send a find next job */
        pJob = rtsmb_cli_session_get_free_job (pSession);
        ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

        pJob->data.findnext.search_struct = pSearch;
        pJob->data.findnext.answering_dstat = pdstat;

#ifdef SUPPORT_SMB2
        if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
        {
            HEREHERE;
            pJob->send_handler_smb2     = rtsmb2_cli_session_send_find_next;
            pJob->receive_handler_smb2  = rtsmb2_cli_session_receive_find_next;
        }
        else
#endif
        {
            pJob->send_handler = rtsmb_cli_session_send_find_next;
            pJob->receive_handler = rtsmb_cli_session_receive_find_next;
        }

        rtsmb_cli_session_send_stalled_jobs (pSession);

        if (pSession->blocking_mode)
        {
        int r;
            r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
            return(r);
        }
        else
        {
            return INDEX_OF (pSession->jobs, pJob);
        }
    }
    else
    {
        /* we have the data right now, so let's fill stat object out */
        *pdstat = pSearch->dstats[++pSearch->index];
        return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
    }
}

int rtsmb_cli_session_find_close (int sid, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
    PRTSMB_CLI_SESSION_SEARCH pSearch;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    pSearch = rtsmb_cli_session_get_search (pSession, pdstat->sid);
    ASSURE (pSearch, RTSMB_CLI_SSN_RV_BAD_SEARCH);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.findclose.search_struct = pSearch;

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_find_close;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_find_close;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_stat_rt (int sid, PFCHAR share, PFRTCHAR file, PRTSMB_CLI_SESSION_FSTAT pfstat)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find share */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    ASSURE (pShare->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.stat.share_struct = pShare;
    pJob->data.stat.answering_stat = pfstat;
    rtsmb_cpy (pJob->data.stat.filename, file);
#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2      = rtsmb2_cli_session_send_stat;
        pJob->receive_handler_smb2   = rtsmb2_cli_session_receive_stat;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_stat;
        pJob->receive_handler = rtsmb_cli_session_receive_stat;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_chmode_rt (int sid, PFCHAR share, PFRTCHAR file, int attributes)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find share */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    ASSURE (pShare->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.chmode.share_struct = pShare;
    pJob->data.chmode.attributes = attributes;
    rtsmb_cpy (pJob->data.chmode.filename, file);

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2 = rtsmb2_cli_session_send_chmode;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_chmode;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}


int rtsmb_cli_session_full_server_enum (int sid, dword type, PFCHAR domain, PRTSMB_BROWSE_SERVER_INFO answering_infos, int answering_infos_size)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    if (domain)
    {
        pJob->data.full_server_enum.valid_domain = TRUE;
        rtsmb_util_ascii_to_rtsmb (domain, pJob->data.full_server_enum.domain, CFG_RTSMB_USER_CODEPAGE);
    }
    else
    {
        pJob->data.full_server_enum.valid_domain = FALSE;
    }
    pJob->data.full_server_enum.type = type;
    pJob->data.full_server_enum.answering_infos = answering_infos;
    pJob->data.full_server_enum.answering_infos_size = answering_infos_size;

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2     = rtsmb2_cli_session_send_full_server_enum;
        pJob->receive_handler_smb2  = rtsmb2_cli_session_receive_full_server_enum;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_full_server_enum;
        pJob->receive_handler = rtsmb_cli_session_receive_full_server_enum;
    }
    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_get_free (int sid, PFCHAR share, PFINT total_units, PFINT free_units, PFINT blocks_per_unit, PFINT block_size)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* find share */
    pShare = rtsmb_cli_session_get_share (pSession, share);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    ASSURE (pShare->state == CSSN_SHARE_STATE_CONNECTED, RTSMB_CLI_SSN_RV_BAD_SHARE);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.getfree.share_struct = pShare;
    pJob->data.getfree.answering_total_units = total_units;
    pJob->data.getfree.answering_free_units = free_units;
    pJob->data.getfree.answering_blocks_per_unit = blocks_per_unit;
    pJob->data.getfree.answering_block_size = block_size;

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2     = rtsmb2_cli_session_send_get_free;
        pJob->receive_handler_smb2  = rtsmb2_cli_session_receive_get_free;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_get_free;
        pJob->receive_handler = rtsmb_cli_session_receive_get_free;
    }

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_share_find_first (int sid, PRTSMB_CLI_SESSION_SSTAT pstat)
{
    PRTSMB_CLI_SESSION_SHARE_SEARCH pSearch;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pSearch = rtsmb_cli_session_get_free_share_search (pSession);
    if (!pSearch)
    {
        rtsmb_cli_session_job_close (pJob);
        return RTSMB_CLI_SSN_RV_TOO_MANY_SEARCHES;
    }

    pJob->data.sharefindfirst.search_struct = pSearch;
    pJob->data.sharefindfirst.answering_sstat = pstat;

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2      = rtsmb2_cli_session_send_share_find_first;
        pJob->receive_handler_smb2   = rtsmb2_cli_session_receive_share_find_first;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_share_find_first;
        pJob->receive_handler = rtsmb_cli_session_receive_share_find_first;
    }
    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_share_find_next (int sid, PRTSMB_CLI_SESSION_SSTAT pstat)
{
    PRTSMB_CLI_SESSION_SHARE_SEARCH pSearch;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    pSearch = rtsmb_cli_session_get_share_search (pSession, pstat->sid);
    ASSURE (pSearch, RTSMB_CLI_SSN_RV_BAD_SEARCH);

    if (pSearch->index + 1 >= pSearch->num_stats)
    {
        return RTSMB_CLI_SSN_RV_END_OF_SEARCH;
    }
    else
    {
        /* we have the data right now, so let's fill the stat object out */
        *pstat = pSearch->sstats[++pSearch->index];

        return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
    }
}

int rtsmb_cli_session_share_find_close (int sid, PRTSMB_CLI_SESSION_SSTAT pstat)
{
    PRTSMB_CLI_SESSION_SHARE_SEARCH pSearch;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    pSearch = rtsmb_cli_session_get_share_search (pSession, pstat->sid);
    ASSURE (pSearch, RTSMB_CLI_SSN_RV_BAD_SEARCH);

    rtsmb_cli_session_share_search_close (pSearch);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_get_free_server_search_server (void)
{
    int i;

    if (!rtsmb_client_config_initialized)
    {
        return -1;
    }

    RTSMB_CLAIM_MUTEX(prtsmb_cli_ctx->server_search_mutex);

    for (i = 0; i < prtsmb_cli_ctx->max_server_searches; i++)
    {
        if (!prtsmb_cli_ctx->server_search_in_use[i])
        {
            prtsmb_cli_ctx->server_search_in_use[i] = TRUE;
            break;
        }
    }

    RTSMB_RELEASE_MUTEX(prtsmb_cli_ctx->server_search_mutex);

    if (i == prtsmb_cli_ctx->max_server_searches)
    {
        return -1;
    }
    else
    {
        return i;
    }
}

RTSMB_STATIC
int rtsmb_cli_session_server_enum (int sid, PRTSMB_CLI_SESSION_SERVER_SEARCH pSearch)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pJob->data.serverfind.search_struct = pSearch;
#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        HEREHERE;
        pJob->send_handler_smb2      = rtsmb2_cli_session_send_server_enum;
        pJob->receive_handler_smb2   = rtsmb2_cli_session_receive_server_enum;
    }
    else
#endif
    {
        pJob->send_handler = rtsmb_cli_session_send_server_enum;
        pJob->receive_handler = rtsmb_cli_session_receive_server_enum;
    }
    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
    int r;
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}

int rtsmb_cli_session_server_enum_start (PRTSMB_CLI_SESSION_SRVSTAT pstat, PFBYTE ip, PFBYTE bip)
{
    char backup_server [RTSMB_NB_NAME_SIZE + 1];
    BBOOL other_workgroups;
    int i;

    i = rtsmb_cli_session_get_free_server_search_server ();
    ASSURE (i >= 0, RTSMB_CLI_SSN_RV_NOT_ENOUGH_RESOURCES);

    pstat->sid = i;
    pstat->domain = 0;

    /* if no one else is around to set ips, we'll start off with ours here */
    if (!rtsmb_net_are_valid_ips ())
    {
        rtsmb_net_set_ip (ip, 0);
    }

    if (ip)
    {
        tc_memcpy (pstat->ip, ip, 4);
    }
    else
    {
        tc_memcpy (pstat->ip, rtsmb_net_get_host_ip (), 4);
    }
    if (bip)
    {
        tc_memcpy (pstat->bip, bip, 4);
    }
    else
    {
        tc_memcpy (pstat->bip, rtsmb_net_get_broadcast_ip (), 4);
    }

    rtsmb_nbds_init ();


    /* We have here an optimization.  If we are running a server that knows the
       domains on the network, do not send a backup list request if there aren't
       any domains to get lists from. */
    other_workgroups = TRUE;

    RTSMB_CLAIM_MUTEX(prtsmb_browse_ctx->mutex);

    if (rtsmb_glue_are_other_workgroups)
    {
        other_workgroups = (*rtsmb_glue_are_other_workgroups) ();
    }

    RTSMB_RELEASE_MUTEX(prtsmb_browse_ctx->mutex);

    if (!other_workgroups)
    {
        pstat->state = CSSN_SRV_SEARCH_STATE_FINISH;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_FINISH);
#endif
        return RTSMB_CLI_SSN_RV_OK;
    }


    if (rtsmb_nbds_get_backup_server (pstat->domain, backup_server, 0) == 0)
    {
#if (ENUM_SRV_ALL)
        pstat->state = CSSN_SRV_SEARCH_STATE_LOGGING_ON;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_LOGGING_ON);
#endif
        pstat->backup_server_index = 0;
        r = rtsmb_cli_session_new_with_name (backup_server, FALSE, pstat->bip, &pstat->ssnid, CSSN_DIALECT_NT); // HEREHERE
        if (r != RTSMB_CLI_SSN_RV_OK)
        {
            // tbd - TONY: "why was this line commented out?"
//          rtsmb_cli_session_server_enum_close (pstat);
            return RTSMB_CLI_SSN_RV_DEAD;
        }
        else
        {
            return RTSMB_CLI_SSN_RV_OK;
        }
#else
        pstat->backup_server_index = 0;
        return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
#endif
    }
    else
    {
        prtsmb_cli_ctx->server_search_results[i].broadcast_timeout_base = rtp_get_system_msec ();
        pstat->state = CSSN_SRV_SEARCH_STATE_BACKUP;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_BACKUP);
#endif
        return RTSMB_CLI_SSN_RV_OK;
    }
}


RTSMB_STATIC
void rtsmb_cli_session_server_enum_cache_to_results (PRTSMB_CLI_SESSION_SRVSTAT pstat)
{
    /* grab all names from cache and put them into results. */
    int i, j;

    RTSMB_CLAIM_MUTEX(prtsmb_browse_ctx->mutex);

    if (rtsmb_glue_get_server_name_from_cache)
    {
        for (i = 0, j = 0; j < prtsmb_cli_ctx->max_servers_per_search; j++)
        {
            PFCHAR name = (*rtsmb_glue_get_server_name_from_cache) (&i);

            if (!name)
            {
                break;
            }

            //rtp_wcscpy (&prtsmb_cli_ctx->server_search_results[pstat->sid].srvstats[j * RTSMB_NB_NAME_SIZE], name);
            rtsmb_util_ascii_to_unicode (
                    name,
                    &prtsmb_cli_ctx->server_search_results[pstat->sid].srvstats[j * RTSMB_NB_NAME_SIZE],
                    CFG_RTSMB_USER_CODEPAGE);
        }
    }
    else
    {
        j = 0;
    }

    RTSMB_RELEASE_MUTEX(prtsmb_browse_ctx->mutex);

    prtsmb_cli_ctx->server_search_results[pstat->sid].index = 0;
    prtsmb_cli_ctx->server_search_results[pstat->sid].num_stats = j;
}


RTSMB_STATIC
void rtsmb_cli_session_server_enum_cycle_helper (int job, int rv, PFVOID data)
{
    PFINT i = (PFINT) data;

    *i = CSSN_SRV_SEARCH_STATE_DATA_READY;
}

int rtsmb_cli_session_server_enum_cycle (PRTSMB_CLI_SESSION_SRVSTAT pstat, int timeout)
{
    if (pstat->sid < 0 || pstat->sid >= prtsmb_cli_ctx->max_server_searches)
    {
        return RTSMB_CLI_SSN_RV_BAD_SEARCH;
    }

    if (pstat->state == CSSN_SRV_SEARCH_STATE_BACKUP)
    {
        char backup_server [RTSMB_NB_NAME_SIZE + 1];
        long newtimeout;
        long expire_time;

        if (IS_PAST (prtsmb_cli_ctx->server_search_results[pstat->sid].broadcast_timeout_base, RTSMB_NB_BCAST_RETRY_TIMEOUT))
        {
            /* no one is answering our broadcast calls.... */
#if (DEBUG_ENUM_SERVER)
            rtp_printf("enum_cycle: no response(1) - finished\n");
#endif
            pstat->state = CSSN_SRV_SEARCH_STATE_FINISH;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_FINISH);
#endif
            return RTSMB_CLI_SSN_RV_OK;
        }

        expire_time = (long) (prtsmb_cli_ctx->server_search_results[pstat->sid].broadcast_timeout_base +
                              RTSMB_NB_BCAST_RETRY_TIMEOUT - rtp_get_system_msec());
        if (expire_time < 0)
        {
            expire_time = 0;
        }
        newtimeout = (timeout == -1) ? expire_time : MIN (timeout, expire_time);
        rtsmb_nbds_cycle (newtimeout);
        if (rtsmb_nbds_get_backup_server (pstat->domain, backup_server, 0) == 0)
        {
#if (ENUM_SRV_ALL)
            pstat->state = CSSN_SRV_SEARCH_STATE_LOGGING_ON;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_LOGGING_ON);
#endif
            pstat->backup_server_index = 0;
            r = rtsmb_cli_session_new_with_name (backup_server, FALSE, pstat->bip, &pstat->ssnid, CSSN_DIALECT_NT); // HEREHERE
            if (r < 0)
            {
                rtsmb_cli_session_server_enum_close (pstat);
                return pstat    ->ssnid;
            }
            else
            {
                return RTSMB_CLI_SSN_RV_OK;
            }
#else
            pstat->backup_server_index = 0;
            return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
#endif
        }
        else
        {
            if (IS_PAST (prtsmb_cli_ctx->server_search_results[pstat->sid].broadcast_timeout_base, RTSMB_NB_BCAST_RETRY_TIMEOUT))
            {
#if (DEBUG_ENUM_SERVER)
                rtp_printf("enum_cycle: no response (2) - finished\n");
#endif
                /* no one is answering our broadcast calls.... */
                pstat->state = CSSN_SRV_SEARCH_STATE_FINISH;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_FINISH);
#endif
                return RTSMB_CLI_SSN_RV_OK;
            }
#if (DEBUG_ENUM_SERVER)
            else
            {
                rtp_printf("enum_cycle: no response but not timeout\n");
            }
#endif
        }
    }
    else if (pstat->state == CSSN_SRV_SEARCH_STATE_BACKUP_AGAIN)
    {
        char backup_server [RTSMB_NB_NAME_SIZE + 1];

#if (DEBUG_ENUM_SERVER)
        rtp_printf("enum_cycle: BACKUP again\n");
#endif
        if (rtsmb_nbds_get_backup_server (pstat->domain, backup_server, 0) == 0)
        {

#if (ENUM_SRV_ALL)
            pstat->state = CSSN_SRV_SEARCH_STATE_LOGGING_ON;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_LOGGING_ON);
#endif
            pstat->backup_server_index = 0;
            r = rtsmb_cli_session_new_with_name (backup_server, FALSE, pstat->bip, &pstat->ssnid, CSSN_DIALECT_NT); // HEREHERE
            if (r < 0)
            {
                pstat->state = CSSN_SRV_SEARCH_STATE_FINISH;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_FINISH);
#endif
                return RTSMB_CLI_SSN_RV_OK;
            }
            else
            {
                return RTSMB_CLI_SSN_RV_OK;
            }
#else
            pstat->backup_server_index = 0;
            return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
#endif
        }
        else
        {
            /* no more domains */
            pstat->state = CSSN_SRV_SEARCH_STATE_FINISH;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_FINISH);
#endif
            return RTSMB_CLI_SSN_RV_OK;
        }
    }
    else if (pstat->state == CSSN_SRV_SEARCH_STATE_LOGGING_ON)
    {
        PRTSMB_CLI_SESSION_SHARE pShare;

        /* find share */
        pShare = rtsmb_cli_session_get_share (&prtsmb_cli_ctx->sessions[pstat->ssnid], ipc_name);

        if (!pShare || pShare->state != CSSN_SHARE_STATE_CONNECTED)
        {
            int r;

            /* if session connect fails, then see if there is another backup server
               for this domain, and try to connect to that one */

            r = rtsmb_cli_session_cycle (pstat->ssnid, timeout);
            if (r == RTSMB_CLI_SSN_RV_DEAD || r == RTSMB_CLI_SSN_RV_BAD_SID)
            {
                char backup_server [RTSMB_NB_NAME_SIZE + 1];

                rtsmb_cli_session_close_session (pstat->ssnid);
                pstat->backup_server_index++;

#if (DEBUG_ENUM_SERVER)
                rtp_printf("enum_cycle: call backup server yet again\n");
#endif
                if (rtsmb_nbds_get_backup_server (pstat->domain, backup_server, pstat->backup_server_index) == 0)
                {
                    r = rtsmb_cli_session_new_with_name (backup_server, FALSE, pstat->bip, &pstat->ssnid, CSSN_DIALECT_NT); // HEREHERE
                    if (r < 0)
                    {
                        pstat->state = CSSN_SRV_SEARCH_STATE_FINISH;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_FINISH);
#endif
                        return RTSMB_CLI_SSN_RV_OK;
                    }
                    else
                    {
                        return RTSMB_CLI_SSN_RV_OK;
                    }
                }

#if (DEBUG_ENUM_SERVER)
                rtp_printf("enum_cycle: no response do try next domain\n");
#endif
                /* none of the backup servers for this domain are responding,
                    so move to the next one. */
                pstat->domain++;
                pstat->state = CSSN_SRV_SEARCH_STATE_BACKUP_AGAIN;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_BACKUP_AGAIN);
#endif
#if (DEBUG_ENUM_SERVER)
                rtp_printf("enum_cycle: move on to next domain (1) = %d\n", pstat->domain++);
#endif
                return RTSMB_CLI_SSN_RV_OK;
            }
        }
        else
        {
            int r;

#if (DEBUG_ENUM_SERVER)
            rtp_printf("enum_cycle: call server enum again\n");
#endif
            r = rtsmb_cli_session_server_enum (pstat->ssnid, &prtsmb_cli_ctx->server_search_results[pstat->sid]);

            pstat->state = CSSN_SRV_SEARCH_STATE_REQUESTING;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_REQUESTING);
#endif

            if (r >= 0)
            {
                rtsmb_cli_session_set_job_callback (pstat->ssnid, r, rtsmb_cli_session_server_enum_cycle_helper, &pstat->state);
            }
            else
            {
                rtsmb_cli_session_close_session (pstat->ssnid);
            }

            return r;
        }
    }
    else if (pstat->state == CSSN_SRV_SEARCH_STATE_REQUESTING)
    {
        return rtsmb_cli_session_cycle (pstat->ssnid, timeout);
    }
    else if (pstat->state == CSSN_SRV_SEARCH_STATE_DATA_READY)
    {
        rtsmb_cli_session_close_session (pstat->ssnid);

        return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
    }
    else if (pstat->state == CSSN_SRV_SEARCH_STATE_FINISH)
    {
        pstat->state = CSSN_SRV_SEARCH_STATE_DONE_LOCAL; /* so that the next time we are called, we will really die */
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_DONE_LOCAL);
#endif

        /* we are done enumerating domains.  But, if we are also a server,
           we should enumerate our own cache before we stop. */

        RTSMB_CLAIM_MUTEX(prtsmb_browse_ctx->mutex);

        if (rtsmb_glue_do_we_have_server_list)
        {
            if ((*rtsmb_glue_do_we_have_server_list) ())
            {
                RTSMB_RELEASE_MUTEX(prtsmb_browse_ctx->mutex);

                rtsmb_cli_session_server_enum_cache_to_results (pstat);
                return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
            }
        }

        RTSMB_RELEASE_MUTEX(prtsmb_browse_ctx->mutex);

        return RTSMB_CLI_SSN_RV_OK;
    }
    else if (pstat->state == CSSN_SRV_SEARCH_STATE_DONE_LOCAL)
    {
        /* this means we have already searched domains and our local cache
           nothing left to do but die */
        return RTSMB_CLI_SSN_RV_END_OF_SEARCH;
    }

    return RTSMB_CLI_SSN_RV_OK;
}

/* |name| must be 16 bytes large */
int _rtsmb_cli_session_server_enum_next_name (PRTSMB_CLI_SESSION_SRVSTAT pstat, PFVOID name, RTSMB_BOOL unicode)
{
    if (pstat->sid < 0 || pstat->sid >= prtsmb_cli_ctx->max_server_searches)
    {
        return RTSMB_CLI_SSN_RV_BAD_SEARCH;
    }

    if (prtsmb_cli_ctx->server_search_results[pstat->sid].index >= prtsmb_cli_ctx->server_search_results[pstat->sid].num_stats)
    {
        pstat->domain ++;

        /* change state to go back to the next domain, if we haven't already
           done our local cache (meaning we've done all domains) */
        if (pstat->state != CSSN_SRV_SEARCH_STATE_DONE_LOCAL)
        {
            pstat->state = CSSN_SRV_SEARCH_STATE_BACKUP_AGAIN;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SEARCH_STATE (CSSN_SRV_SEARCH_STATE_BACKUP_AGAIN);
#endif
#if (DEBUG_ENUM_SERVER)
            rtp_printf("enum_cycle: move on to next domain (2) = %d\n", pstat->domain++);
#endif
        }
        return RTSMB_CLI_SSN_RV_END_OF_SEARCH;
    }
    else
    {
        /* If the server is running, we want to exclude our own name */
#if 0 // tbd - TPA fix this in the server first
        RTSMB_CLAIM_MUTEX(prtsmb_browse_ctx->mutex);

        if (rtsmb_glue_get_our_server_name)
        {
            if (tc_strcmp (&prtsmb_cli_ctx->server_search_results[pstat->sid].srvstats[prtsmb_cli_ctx->server_search_results[pstat->sid].index * RTSMB_NB_NAME_SIZE],
                        (*rtsmb_glue_get_our_server_name) ()) == 0)
            {
                RTSMB_RELEASE_MUTEX(prtsmb_browse_ctx->mutex);
                prtsmb_cli_ctx->server_search_results[pstat->sid].index ++;
                return rtsmb_cli_session_server_enum_next_name (pstat, name);
            }
        }

        RTSMB_RELEASE_MUTEX(prtsmb_browse_ctx->mutex);
#endif

        if (unicode)
        {
            rtp_wcscpy (name, &prtsmb_cli_ctx->server_search_results[pstat->sid].srvstats[prtsmb_cli_ctx->server_search_results[pstat->sid].index * RTSMB_NB_NAME_SIZE]);
        }
        else
        {
            rtsmb_util_unicode_to_ascii (
                    &prtsmb_cli_ctx->server_search_results[pstat->sid].srvstats[prtsmb_cli_ctx->server_search_results[pstat->sid].index * RTSMB_NB_NAME_SIZE],
                    name,
                    CFG_RTSMB_USER_CODEPAGE);
        }

        prtsmb_cli_ctx->server_search_results[pstat->sid].index++;

        return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
    }
}

int rtsmb_cli_session_server_enum_next_name (PRTSMB_CLI_SESSION_SRVSTAT pstat, PFCHAR name)
{
    return _rtsmb_cli_session_server_enum_next_name(pstat, name, RTSMB_FALSE);
}

int rtsmb_cli_session_server_enum_next_name_uc (PRTSMB_CLI_SESSION_SRVSTAT pstat, PFWCS name)
{
    return _rtsmb_cli_session_server_enum_next_name(pstat, name, RTSMB_TRUE);
}

int rtsmb_cli_session_server_enum_close (PRTSMB_CLI_SESSION_SRVSTAT pstat)
{
    if (pstat->sid < 0 || pstat->sid >= prtsmb_cli_ctx->max_server_searches)
    {
        return RTSMB_CLI_SSN_RV_BAD_SEARCH;
    }

    prtsmb_cli_ctx->server_search_in_use[pstat->sid] = FALSE;
    rtsmb_nbds_shutdown ();

    return 0;
}


RTSMB_STATIC
int rtsmb_cli_session_examine_wire (PRTSMB_CLI_SESSION pSession, int wire_response)
{
    switch (wire_response)
    {
    case 1:     /* a job is done */
#if (DEBUG_AUTH_JOB)
        rtp_printf("rtsmb_cli_session_examine_wire: pSession = %x\n",
            pSession);
#endif
        return rtsmb_cli_session_process_smbs_on_wire (pSession);
    case 0:     /* nothing for us to do */
    case -1:    /* a select timeout */
        return RTSMB_CLI_SSN_RV_OK;
    case -3:    /* dead session */
//      pSession->state = CSSN_STATE_DEAD;
        return RTSMB_CLI_SSN_RV_DEAD;
    case RTSMB_CLI_WIRE_ERROR_BAD_STATE:
//      pSession->state = CSSN_STATE_DEAD;
        return RTSMB_CLI_SSN_RV_DEAD;
    case RTSMB_CLI_WIRE_TOO_MANY_REQUESTS:
        return RTSMB_CLI_SSN_RV_TOO_MANY_JOBS;
    case -2:    /* bad connection */
    default:    /* some misc. error */
        return rtsmb_cli_session_handle_bad_connection (pSession);
    }
}

void rtsmb_cli_session_job_cleanup (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, int r)
{
    rtsmb_cli_session_job_close (pJob);

    if (pJob->callback)
    {
        (*pJob->callback) (INDEX_OF (pSession->jobs, pJob), r, pJob->callback_data);
    }

}

RTSMB_STATIC
int rtsmb_cli_session_process_smbs_on_wire (PRTSMB_CLI_SESSION pSession)
{
    int i, r;

    /* first, find out which jobs are done */
    for (i = 0; i < prtsmb_cli_ctx->max_jobs_per_session; i++)
    {
        if (pSession->jobs[i].state == CSSN_JOB_STATE_WAITING)
        {
#if (DEBUG_SESSION_ON_WIRE)
            rtp_printf("PVO CHECK ON WAITING \n");
#endif
            switch (rtsmb_cli_wire_check_message (&pSession->wire, pSession->jobs[i].mid))
            {
                case NON_EXISTANT:  /* job is in wrong state */
#if (DEBUG_SESSION_ON_WIRE)
                    rtp_printf("PVO NON_EXISTANT \n");
#endif
                    rtsmb_cli_session_job_close (&pSession->jobs[i]);   /* fix it */
                    break;

                case WAITING:   /* not done yet */
#if (DEBUG_SESSION_ON_WIRE)
                    rtp_printf("PVO WAITING \n");
#endif
                    break;

                case TIMED_OUT: /* no response... */
#if (DEBUG_SESSION_ON_WIRE)
                    rtp_printf("PVO Timeout \n");
#endif
                    r = rtsmb_cli_session_handle_job_timeout (pSession, &pSession->jobs[i]);
                    if (r == RTSMB_CLI_SSN_RV_DEAD)
                    {
                        return r;
                    }
                    break;
                case FINISHED:  /* we can answer this */
                {
#if (DEBUG_AUTH_JOB)
                    rtp_printf("rtsmb_cli_session_process_smbs_on_wire: FINISHED: call handle job: session = %x\n",
                        pSession);
#endif
                    r = rtsmb_cli_session_handle_job (pSession, &pSession->jobs[i]);
                    if (pSession->jobs[i].state == CSSN_JOB_STATE_STALLED)
                    {
#if (DEBUG_SESSION_ON_WIRE)
                    rtp_printf("PVO Stalled \n");
#endif
                        /* this job apparently wants to send more data; let it */
                    }
                    else
                    {
                        rtsmb_cli_session_job_close (&pSession->jobs[i]);
#if (DEBUG_SESSION_ON_WIRE)
                        rtp_printf("PVO callback == %X\n",(unsigned int)pSession->jobs[i].callback);
#endif
                        if (pSession->jobs[i].callback)
                        {
#if (DEBUG_SESSION_ON_WIRE)
                            rtp_printf("PVO callback \n");
#endif
                            (*pSession->jobs[i].callback) (i, r, pSession->jobs[i].callback_data);
                        }
                    }

                    if (r == RTSMB_CLI_SSN_RV_DEAD)
                    {
                        return r;
                    }

                    break;
                }
            }
        }
    }

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_handle_bad_connection (PRTSMB_CLI_SESSION pSession)
{
    int i;
//  RTSMB_CLI_SESSION_STATE preRecoveryState = pSession->state;

    if (pSession->state >= CSSN_STATE_RECOVERY_QUERYING)
    {
        /* We are already recovering and we want to try again?  Just kill the session,
           this is going nowhere. */

        RTSMB_DEBUG_OUTPUT_STR ("Killing bad connection to ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (pSession->server_name, RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);

        pSession->state = CSSN_STATE_DEAD;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_DEAD);
#endif
        return RTSMB_CLI_SSN_RV_DEAD;
    }

    RTSMB_DEBUG_OUTPUT_STR ("Restarting bad connection to ",  RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (pSession->server_name,  RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);

    pSession->state = CSSN_STATE_RECOVERY_QUERYING;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_RECOVERY_QUERYING);
#endif
    pSession->anon.state = CSSN_USER_STATE_DIRTY;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_USER_STATE (CSSN_USER_STATE_DIRTY);
#endif
    if (pSession->user.state == CSSN_USER_STATE_LOGGED_ON)
    {
        pSession->user.state = CSSN_USER_STATE_DIRTY;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_USER_STATE (CSSN_USER_STATE_DIRTY);
#endif
    }

    for (i = 0; i < prtsmb_cli_ctx->max_shares_per_session; i++)
    {
        if (pSession->shares[i].state == CSSN_SHARE_STATE_CONNECTED)
        {
            pSession->shares[i].state = CSSN_SHARE_STATE_DIRTY;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_SHARE_STATE_DIRTY);
#endif
        }
    }

    for (i = 0; i < prtsmb_cli_ctx->max_fids_per_session; i++)
    {
        if (pSession->fids[i].real_fid >= 0)
        {
            pSession->fids[i].real_fid = CSSN_FID_STATE_DIRTY;
        }
    }

    for (i = 0; i < prtsmb_cli_ctx->max_jobs_per_session; i++)
    {
        if (pSession->jobs[i].state != CSSN_JOB_STATE_UNUSED)
        {
            pSession->jobs[i].state = CSSN_JOB_STATE_DIRTY;
        }
    }

    rtsmb_cli_wire_session_close (&pSession->wire);

    pSession->state = CSSN_STATE_DEAD;
    return RTSMB_CLI_SSN_RV_DEAD;
}

RTSMB_STATIC
int rtsmb_cli_session_handle_job_timeout (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_DEBUG_OUTPUT_STR("Job timed out.  We have sent job ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_INT(pJob->send_count);
    RTSMB_DEBUG_OUTPUT_STR(" times of ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_INT(RTSMB_NB_UCAST_RETRY_COUNT);
    RTSMB_DEBUG_OUTPUT_STR(".\n", RTSMB_DEBUG_TYPE_ASCII);

    if (pJob->send_count >= RTSMB_NB_UCAST_RETRY_COUNT)
    {
        /* no more chances */
        /* restart session, because server seems unresponsive */

        /* however, if we have already restarted for this job before, make sure
           that we aren't over our limit.  If so, quit session. */
        if (pJob->die_count >= RTSMB_CLI_MAX_FAILED_CONNECTIONS)
        {
            pSession->state = CSSN_STATE_DEAD;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_DEAD);
#endif
            return RTSMB_CLI_SSN_RV_DEAD;
        }

        pJob->die_count ++;
        return rtsmb_cli_session_handle_bad_connection (pSession);
    }
    else
    {
        rtsmb_cli_wire_smb_close (&pSession->wire, pJob->mid);
        return rtsmb_cli_session_send_job (pSession, pJob);
    }
}

int rtsmb_cli_session_translate_error32 (dword status)
{
    switch (status)
    {
        case SMB_NT_STATUS_OBJECT_NAME_NOT_FOUND:
        case SMB_NT_STATUS_NO_SUCH_FILE:
        case SMB_NT_STATUS_OBJECT_NAME_INVALID:
        case SMB_NT_STATUS_OBJECT_NAME_COLLISION:
        case SMB_NT_STATUS_OBJECT_PATH_INVALID:
        case SMB_NT_STATUS_OBJECT_PATH_NOT_FOUND:
        case SMB_NT_STATUS_OBJECT_PATH_SYNTAX_BAD:
            return RTSMB_CLI_SSN_RV_FILE_NOT_FOUND;

        case SMB_NT_STATUS_ACCESS_VIOLATION:
        case SMB_NT_STATUS_ACCESS_DENIED:
        case SMB_NT_STATUS_SHARING_VIOLATION:
        case SMB_NT_STATUS_WRONG_PASSWORD:
        case SMB_NT_STATUS_ILL_FORMED_PASSWORD:
        case SMB_NT_STATUS_PASSWORD_RESTRICTION:
        case SMB_NT_STATUS_LOGON_FAILURE:
        case SMB_NT_STATUS_ACCOUNT_RESTRICTION:
        case SMB_NT_STATUS_INVALID_LOGON_HOURS:
        case SMB_NT_STATUS_INVALID_WORKSTATION:
        case SMB_NT_STATUS_PASSWORD_EXPIRED:
        case SMB_NT_STATUS_ACCOUNT_DISABLED:
        case SMB_NT_STATUS_CANNOT_DELETE:
            return RTSMB_CLI_SSN_RV_BAD_PERMISSIONS;
    }
    return RTSMB_CLI_SSN_RV_SMB_ERROR;
}
RTSMB_STATIC
int rtsmb_cli_session_translate_error (PRTSMB_HEADER pheader)
{
    if (ON (pheader->flags2, SMB_FLG2_32BITERROR))
    {
        /* Ok, let's translate NT error codes. */
        return rtsmb_cli_session_translate_error32 (pheader->status);
    }
    else
    {
        byte type;
        word num;

        type = (byte) (pheader->status & 0xFF);
        num = (word) ((pheader->status & 0xFFFF0000) >> 16);

        /* Ok, let's translate DOS error codes. */
        switch (type)
        {
            case SMB_EC_ERRDOS:
                switch (num)
                {
                    case SMB_ERRDOS_BADFILE:
                    case SMB_ERRDOS_BADPATH:
                        return RTSMB_CLI_SSN_RV_FILE_NOT_FOUND;
                    case SMB_ERRDOS_NOACCESS:
                        return RTSMB_CLI_SSN_RV_BAD_PERMISSIONS;
                }
                break;
            case SMB_EC_ERRSRV:
                switch (num)
                {
                    case SMB_ERRSRV_BADPW:
                    case SMB_ERRSRV_ACCESS:
                        return RTSMB_CLI_SSN_RV_BAD_PERMISSIONS;
                }
        }
    }

    return RTSMB_CLI_SSN_RV_SMB_ERROR;
}

#ifdef SUPPORT_SMB2    // Some branching to SMB2 from this file, no major processing
RTSMB_STATIC
int rtsmb_cli_session_handle_job_smb2 (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    int rv;
    if (pJob->receive_handler_smb2)
    {
        smb2_stream *pStream;
        pStream = rtsmb_cli_wire_smb2_stream_get (&pSession->wire, pJob->mid);
        if (pStream)
        {
            rv = (*pJob->receive_handler_smb2) (pStream);

            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_handle_job_smb2: *pJob->receive_handler_smb2 returned rv == %d\n",rv);
            // HERERE - comparing ddword with word
            if (pStream->InHdr.MessageId != pJob->mid)
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_session_handle_job_smb2: Job and header message ID's do not match!!!!!!!!!!!!!!!!!\n",0);
                rv = RTSMB_CLI_SSN_RV_MALICE;
            }
            else if (pStream->InHdr.Status_ChannelSequenceReserved)
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_session_handle_job_smb2: error passed in header returned %X\n", (int)pStream->InHdr.Status_ChannelSequenceReserved);
                /* an error occurred */
                pJob->error = pStream->InHdr.Status_ChannelSequenceReserved;
                rv = RTSMB_CLI_SSN_RV_INVALID_RV;
                if (pJob->error_handler_smb2)
                {
                    /* We give the error handler a chance to override the
                       error value and do cleanup. */
                    rv = (*pJob->error_handler_smb2)(pStream);
                    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "*pJob->error_handler_smb2: return error == %X\n", rv);
                }
                /* if the error handler overrode it, we return new error */
                if (rv == RTSMB_CLI_SSN_RV_INVALID_RV)
                {
                    rv = rtsmb_cli_session_translate_error32 (pStream->InHdr.Status_ChannelSequenceReserved);
                    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_session_translate_error32: return error == %X\n", rv);
                }
            }
        }
        else
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_session_handle_job_smb2: No resource. LATER !!!!\n",0);
            rv = RTSMB_CLI_SSN_RV_LATER;
        }
    }
    else
    {
        rv = RTSMB_CLI_SSN_RV_OK;
    }
    /*  Release the buffer we used for this job */
    rtsmb_cli_wire_smb_read_end (&pSession->wire, pJob->mid);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_handle_job_smb2: Returnng %d\n", rv);
    return rv;
}
#endif

RTSMB_STATIC
int rtsmb_cli_session_handle_job (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    int rv;
    int r;

#ifdef SUPPORT_SMB2
    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        return rtsmb_cli_session_handle_job_smb2 (pSession, pJob);
    }
#endif

    /* grab header to see what we have */
    r = rtsmb_cli_wire_smb_read_start (&pSession->wire, pJob->mid);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_BAD_JOB);
    r = rtsmb_cli_wire_smb_read_header (&pSession->wire, pJob->mid, &h);
    if (r != 0)
    {
        rtsmb_cli_wire_smb_read_end (&pSession->wire, pJob->mid);
        return RTSMB_CLI_SSN_RV_MALFORMED;
    }

    if (h.mid != pJob->mid)
    {
        rtsmb_cli_wire_smb_read_end (&pSession->wire, pJob->mid);
        return RTSMB_CLI_SSN_RV_MALICE;
    }

    if (h.status)
    {
        /* an error occurred */
        pJob->error = h.status;

        rv = RTSMB_CLI_SSN_RV_INVALID_RV;
        if (pJob->error_handler)
        {
            /* We give the error handler a chance to override the
               error value and do cleanup. */
            rv = (*pJob->error_handler) (pSession, pJob, &h);
        }
        rtsmb_cli_wire_smb_read_end (&pSession->wire, pJob->mid);

        /* if the error handler overrode it, we return new error */
        if (rv != RTSMB_CLI_SSN_RV_INVALID_RV)
        {
            return rv;
        }
        else
        {
            return rtsmb_cli_session_translate_error (&h);
        }
    }

    if (pJob->receive_handler)
    {
#if (DEBUG_AUTH_JOB)
        rtp_printf("rtsmb_cli_session_handle_job: pJob = %x, pSession = %x\n",
            pJob, pSession);
#endif
        rv = (*pJob->receive_handler) (pSession, pJob, &h);
    }
    else
    {
        rv = RTSMB_CLI_SSN_RV_OK;
    }

    r = rtsmb_cli_wire_smb_read_end (&pSession->wire, pJob->mid);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_BAD_JOB);

    return rv;
}


RTSMB_STATIC
void rtsmb_cli_session_job_new (PRTSMB_CLI_SESSION_JOB pJob)
{
    pJob->state = CSSN_JOB_STATE_STALLED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_JOB_STATE (CSSN_JOB_STATE_STALLED);
#endif
    pJob->send_count = 0;
    pJob->die_count = 0;
    pJob->error = 0;
    pJob->error_handler = 0;
    pJob->send_handler = 0;
    pJob->receive_handler = 0;
#ifdef SUPPORT_SMB2
    pJob->send_handler_smb2    = 0;
    pJob->error_handler_smb2   = 0;
    pJob->receive_handler_smb2 = 0;
#endif
    pJob->callback = 0;
    pJob->callback_data = 0;
    pJob->mid = 0;
}

RTSMB_STATIC
void rtsmb_cli_session_job_close (PRTSMB_CLI_SESSION_JOB pJob)
{
    pJob->state = CSSN_JOB_STATE_UNUSED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_JOB_STATE (CSSN_JOB_STATE_UNUSED);
#endif
}


PRTSMB_CLI_SESSION_JOB rtsmb_cli_session_get_free_job (PRTSMB_CLI_SESSION pSession)
{
    int i;

    for (i = 0; i < prtsmb_cli_ctx->max_jobs_per_session; i++)
    {
        if (pSession->jobs[i].state == CSSN_JOB_STATE_UNUSED)
        {
            rtsmb_cli_session_job_new (&pSession->jobs[i]);
#if (DEBUG_JOB)
            rtp_printf("rtsmb_cli_session_get_free_job: session = %x, job index = %d\n",
                pSession, i);
#endif
            return &pSession->jobs[i];
        }
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_session_get_free_job: All jobs (%d) are in use. !!!!!!!!!!! \n",prtsmb_cli_ctx->max_jobs_per_session);
    return 0;
}

RTSMB_STATIC
void rtsmb_cli_session_search_new (PRTSMB_CLI_SESSION_SEARCH pSearch, int sid)
{
    pSearch->sid = sid;
    pSearch->index = 0;
}

RTSMB_STATIC
void rtsmb_cli_session_search_close (PRTSMB_CLI_SESSION_SEARCH pSearch)
{
    pSearch->sid = -1;
}


RTSMB_STATIC
PRTSMB_CLI_SESSION_SEARCH rtsmb_cli_session_get_free_search (PRTSMB_CLI_SESSION pSession)
{
    int i;

    for (i = 0; i < prtsmb_cli_ctx->max_searches_per_session; i++)
    {
        if (pSession->searches[i].sid == -1)
        {
            rtsmb_cli_session_search_new (&pSession->searches[i], i);
            return &pSession->searches[i];
        }
    }

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_session_get_free_search: All searches (%d) are in use. !!!!!!!!!!! \n",prtsmb_cli_ctx->max_searches_per_session);
    return 0;
}

RTSMB_STATIC
PRTSMB_CLI_SESSION_SEARCH rtsmb_cli_session_get_search (PRTSMB_CLI_SESSION pSession, int sid)
{
    int i;

    for (i = 0; i < prtsmb_cli_ctx->max_searches_per_session; i++)
    {
        if (pSession->searches[i].sid == sid)
        {
            return &pSession->searches[i];
        }
    }

    return 0;
}

RTSMB_STATIC
void rtsmb_cli_session_share_search_new (PRTSMB_CLI_SESSION_SHARE_SEARCH pSearch, int sid)
{
    pSearch->sid = sid;
    pSearch->index = 0;
}

RTSMB_STATIC
void rtsmb_cli_session_share_search_close (PRTSMB_CLI_SESSION_SHARE_SEARCH pSearch)
{
    pSearch->sid = -1;
}

PRTSMB_CLI_SESSION_SHARE_SEARCH rtsmb_cli_session_get_free_share_search (PRTSMB_CLI_SESSION pSession)
{
    if (pSession->share_search.sid == -1)
    {
        rtsmb_cli_session_share_search_new (&pSession->share_search, 0);
        return &pSession->share_search;
    }
    else
    {
        return 0;
    }
}

RTSMB_STATIC
PRTSMB_CLI_SESSION_SHARE_SEARCH rtsmb_cli_session_get_share_search (PRTSMB_CLI_SESSION pSession, int sid)
{
    if (pSession->share_search.sid == sid)
    {
        return &pSession->share_search;
    }
    else
    {
        return 0;
    }
}

RTSMB_STATIC
void rtsmb_cli_session_share_new (PRTSMB_CLI_SESSION_SHARE pShare)
{
    pShare->state = CSSN_SHARE_STATE_CONNECTING;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SHARE_STATE (CSSN_SHARE_STATE_CONNECTING);
#endif
    pShare->tid = INVALID_TID;
    pShare->connect_mid = 0;
}

void rtsmb_cli_session_share_close (PRTSMB_CLI_SESSION_SHARE pShare)
{
    pShare->state = CSSN_SHARE_STATE_UNUSED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SHARE_STATE (CSSN_SHARE_STATE_UNUSED);
#endif
}

PRTSMB_CLI_SESSION_SHARE rtsmb_cli_session_get_free_share (PRTSMB_CLI_SESSION pSession)
{
    int i;

    for (i = 0; i < prtsmb_cli_ctx->max_shares_per_session; i++)
    {
        if (pSession->shares[i].state == CSSN_SHARE_STATE_UNUSED)
        {
            rtsmb_cli_session_share_new (&pSession->shares[i]);
            return &pSession->shares[i];
        }
    }

    return 0;
}

PRTSMB_CLI_SESSION_SHARE rtsmb_cli_session_get_share (PRTSMB_CLI_SESSION pSession, PFCHAR share)
{
    int i;

    for (i = 0; i < prtsmb_cli_ctx->max_shares_per_session; i++)
    {
        if (pSession->shares[i].state != CSSN_SHARE_STATE_UNUSED &&
            tc_strcmp (pSession->shares[i].share_name, share) == 0)
        {
            return &pSession->shares[i];
        }
    }

    return 0;
}

#if 0
RTSMB_STATIC
PRTSMB_CLI_SESSION_SHARE rtsmb_cli_session_get_share_by_tid (PRTSMB_CLI_SESSION pSession, word tid)
{
    int i;

    for (i = 0; i < prtsmb_cli_ctx->max_shares_per_session; i++)
    {
        if (pSession->shares[i].tid == tid)
        {
            return &pSession->shares[i];
        }
    }

    return 0;
}
#endif

RTSMB_STATIC
void rtsmb_cli_session_fid_new (PRTSMB_CLI_SESSION_FID pFid, int fid)
{
    pFid->owning_share = 0;
    pFid->offset = 0;
    pFid->smb_fid = 0;
    pFid->real_fid = fid;
}

RTSMB_STATIC
void rtsmb_cli_session_fid_close (PRTSMB_CLI_SESSION_FID pFid)
{
    pFid->real_fid = -1;
}

RTSMB_STATIC
PRTSMB_CLI_SESSION_FID rtsmb_cli_session_get_free_fid (PRTSMB_CLI_SESSION pSession)
{
    int i;

    for (i = 0; i < prtsmb_cli_ctx->max_fids_per_session; i++)
    {
        if (pSession->fids[i].real_fid == -1)
        {
            rtsmb_cli_session_fid_new (&pSession->fids[i], i);
            return &pSession->fids[i];
        }
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_session_get_free_fid: All fids (%d) are in use. !!!!!!!!!!! \n",prtsmb_cli_ctx->max_fids_per_session);

    return 0;
}

PRTSMB_CLI_SESSION_FID rtsmb_cli_session_get_fid (PRTSMB_CLI_SESSION pSession, int fid)
{
    int i;

    if (fid < 0)
    {
        return 0;
    }

    for (i = 0; i < prtsmb_cli_ctx->max_fids_per_session; i++)
    {
        if (pSession->fids[i].real_fid == fid)
        {
            return &pSession->fids[i];
        }
    }

    return 0;
}

RTSMB_STATIC
void rtsmb_cli_session_user_new (PRTSMB_CLI_SESSION_USER pUser, word uid)
{
    pUser->state = CSSN_USER_STATE_LOGGING_ON;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_USER_STATE (CSSN_USER_STATE_LOGGING_ON);
#endif
    pUser->uid = uid;
}

void rtsmb_cli_session_user_close (PRTSMB_CLI_SESSION_USER pUser)
{
    pUser->state = CSSN_USER_STATE_UNUSED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_USER_STATE (CSSN_USER_STATE_UNUSED);
#endif
}

void rtsmb_cli_session_send_stalled_jobs (PRTSMB_CLI_SESSION pSession)
{
    int i;

    for (i = 0; i < prtsmb_cli_ctx->max_jobs_per_session; i++)
    {
        if (pSession->jobs[i].state == CSSN_JOB_STATE_STALLED)
        {
            int r;

            r = rtsmb_cli_session_send_job (pSession, &pSession->jobs[i]);

            if (r == RTSMB_CLI_SSN_RV_OK)
            {
                pSession->jobs[i].state = CSSN_JOB_STATE_WAITING;
            }
        }
    }
}

/* precondition: |pJob| has been initialized. */
RTSMB_STATIC
int rtsmb_cli_session_send_job (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    pJob->send_count += 1;

#ifdef SUPPORT_SMB2
    if (pJob->send_handler_smb2)
    {
    smb2_stream *pStream;

        RTSMB_DEBUG_OUTPUT_STR ("Create a send stream\n",  RTSMB_DEBUG_TYPE_ASCII);
        pStream = rtsmb_cli_wire_smb2_stream_construct (pSession, pJob);

        if (pStream)
        {
            int r;
            pJob->mid = (word) pStream->pBuffer->mid;
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_send_job: Call send handler\n",0);
            r = (*pJob->send_handler_smb2) (pStream);
            if (r == RTSMB_CLI_SSN_RV_OK)
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_send_job: Send handler success\n",0);
                r = rtsmb_cli_wire_smb2_stream_flush(&pSession->wire, pStream);
                if (r != 0)
                {
                    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_send_job: rtsmb_cli_wire_smb2_stream_flush failed\n",0);
                }
                ASSURE (r == 0, RTSMB_CLI_SSN_RV_DEAD);
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_send_job: rtsmb_cli_wire_smb2_stream_flush succeed\n",0);
            }
        }
        else
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_session_send_job: Send handler deferred, stream construct failed. !!!!!!!!!!! \n",0);
            return RTSMB_CLI_SSN_RV_LATER;

        }
    }
    else
#endif
    {
        if (pJob->send_handler)
        {
            return (*pJob->send_handler) (pSession, pJob);
        }
    }
    return RTSMB_CLI_SSN_RV_OK;
}



RTSMB_STATIC
int rtsmb_cli_session_send_negotiate (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_NEGOTIATE n;
    int r;

    /* set up header */
    h.command = SMB_COM_NEGOTIATE;
    h.flags = 0;
    h.flags2 = 0;
    h.status = 0;
    h.tid = INVALID_TID;
    h.uid = INVALID_UID;
    h.pid = 0;
    tc_memset (h.security_sig, 0, 8);

    /* set up negotiate */
    n.num_dialects = NUM_SPOKEN_DIALECTS;
    n.dialects = spoken_dialects;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_negotiate, &n, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_session_setup_error_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    rtsmb_cli_session_user_close (pJob->data.session_setup.user_struct);

    return RTSMB_CLI_SSN_RV_INVALID_RV;
}

RTSMB_STATIC
int rtsmb_cli_session_send_session_setup_pre_nt (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_SESSION_SETUP_AND_X_PRE_NT s;
#if (INCLUDE_RTSMB_ENCRYPTION)
    byte encrypted_password [24];
#endif
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_SESSION_SETUP_ANDX;
    h.uid = pJob->data.session_setup.user_struct->uid;

    /* set up session setup */
    s.next_command = SMB_COM_NONE;
    s.max_buffer_size = (word) RTSMB_CLI_WIRE_MAX_BUFFER_SIZE;
    s.max_mpx_count = pSession->server_info.mpx_count;
    s.vc_number = 1;
    s.session_id = pSession->server_info.session_id;

#if (INCLUDE_RTSMB_ENCRYPTION)
    if (pSession->server_info.encrypted && tc_strcmp (pJob->data.session_setup.password, ""))
    {
        s.password_size = 24;

        cli_util_encrypt_password_pre_nt (
            pJob->data.session_setup.password,
            pSession->server_info.challenge,
            encrypted_password);
        s.password = encrypted_password;
    }
    else
#endif
    {
        s.password_size = (word) rtp_strlen (pJob->data.session_setup.password);
        s.password = (PFBYTE) pJob->data.session_setup.password;
    }

    s.account_name = pJob->data.session_setup.account_name;
    s.primary_domain = (pJob->data.session_setup.domain_name[0] ? pJob->data.session_setup.domain_name : 0);
    s.native_os = 0;
    s.native_lan_man = 0;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    pJob->data.session_setup.user_struct->logon_mid = pJob->mid;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_session_setup_and_x_pre_nt, &s, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_session_setup_nt (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_SESSION_SETUP_AND_X_NT s;
#if (INCLUDE_RTSMB_ENCRYPTION)
    byte ansi_encrypted_password [24];
    byte unicode_encrypted_password [24];
#endif
    int r;

#if (DEBUG_AUTH)
    rtp_printf("rtsmb_cli_session_send_session_setup_nt called pSession = %x encrypt = %d pwd = %s\n",
        pSession, pSession->server_info.encrypted, pJob->data.session_setup.password);
#endif
    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_SESSION_SETUP_ANDX;
    h.uid = pJob->data.session_setup.user_struct->uid;

    /* set up session setup */
    s.next_command = SMB_COM_NONE;
    s.max_buffer_size = (word) RTSMB_CLI_WIRE_MAX_BUFFER_SIZE;
    s.max_mpx_count = pSession->server_info.mpx_count;
    s.vc_number = 1;
    s.session_id = pSession->server_info.session_id;
    s.capabilities = 0;
#if INCLUDE_RTSMB_UNICODE
    s.capabilities |= CAP_UNICODE;
#endif
    s.capabilities |= CAP_NT_SMBS;
    s.capabilities |= CAP_STATUS32;

#if (INCLUDE_RTSMB_ENCRYPTION)
    /* only do encrypted stuff if we negotiated it, or if this is an anonymous
       connect (checked by seeing if the password is empty) */
    if (pSession->server_info.encrypted && tc_strcmp (pJob->data.session_setup.password, ""))
    {
        s.ansi_password_size = 24;
        s.unicode_password_size = 24;

        cli_util_encrypt_password_pre_nt (
            pJob->data.session_setup.password,
            pSession->server_info.challenge,
            ansi_encrypted_password);
        cli_util_encrypt_password_nt (
            pJob->data.session_setup.password,
            pSession->server_info.challenge,
            unicode_encrypted_password);
#if (DEBUG_AUTH)
        {
        int i;
        rtp_printf("rtsmb_cli_session_send_session_setup_nt password %s\n",
            pJob->data.session_setup.password);
        for(i=0; i < s.ansi_password_size; i++)
        {
            rtp_printf("%x ", ansi_encrypted_password[i]);
        }
        rtp_printf("\n");
        for (i=0; i < s.unicode_password_size; i++)
        {
            rtp_printf("%x ", unicode_encrypted_password[i]);
        }
        rtp_printf("\n");
        }
#endif

        s.ansi_password = ansi_encrypted_password;
        s.unicode_password = unicode_encrypted_password;
    }
    else
#endif
    {
        s.ansi_password_size = (word) rtp_strlen (pJob->data.session_setup.password);
        s.ansi_password = (PFBYTE) pJob->data.session_setup.password;
        s.unicode_password_size = 0;
        s.unicode_password = 0;
    }

    s.account_name = pJob->data.session_setup.account_name;
    s.primary_domain = (pJob->data.session_setup.domain_name[0] ? pJob->data.session_setup.domain_name : 0);
    s.native_os = 0;
    s.native_lan_man = 0;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    pJob->data.session_setup.user_struct->logon_mid = pJob->mid;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_session_setup_and_x_nt, &s, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_logoff (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_LOGOFF_AND_X l;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_LOGOFF_ANDX;
    h.uid = pSession->user.uid;

    /* set up logoff */
    l.next_command = SMB_COM_NONE;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_logoff_and_x, &l, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_tree_connect_error_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    rtsmb_cli_session_share_close (pJob->data.tree_connect.share_struct);

    return RTSMB_CLI_SSN_RV_INVALID_RV;
}

RTSMB_STATIC
int rtsmb_cli_session_send_tree_connect (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    return rtsmb_cli_session_send_tree_connect_job(pSession, pJob, &pJob->data.tree_connect);
}

int rtsmb_cli_session_send_tree_connect_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_CLI_TREE_CONNECT_JOB_DATA info)
{
    RTSMB_HEADER h;
    RTSMB_TREE_CONNECT_AND_X t;
    int r;
    rtsmb_char share_name [RTSMB_NB_NAME_SIZE + RTSMB_MAX_SHARENAME_SIZE + 4]; /* 3 for '\\'s and 1 for null */
#if (INCLUDE_RTSMB_ENCRYPTION)
    byte encrypted_password [24];
#endif

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_TREE_CONNECT_ANDX;

    /* set up tree connect */
    t.next_command = SMB_COM_NONE;
    t.flags = 0;
    t.service = pJob->data.tree_connect.share_type;

    if (pSession->server_info.user_mode || tc_strcmp (pJob->data.tree_connect.password, "") == 0)
    {
        t.password_size = 1;
        t.password = (PFBYTE) "";
    }
#if (INCLUDE_RTSMB_ENCRYPTION)
    else if (pSession->server_info.encrypted)
    {
        t.password_size = 24;

        if (pSession->server_info.dialect < CSSN_DIALECT_NT)
        {
            cli_util_encrypt_password_pre_nt (
                pJob->data.tree_connect.password,
                pSession->server_info.challenge,
                encrypted_password);
        }
        else
        {
            cli_util_encrypt_password_nt (
                pJob->data.tree_connect.password,
                pSession->server_info.challenge,
                encrypted_password);
        }

        t.password = encrypted_password;
    }
#endif
    else
    {
        t.password_size = (word) rtp_strlen (pJob->data.tree_connect.password);
        t.password = (PFBYTE) pJob->data.tree_connect.password;
    }

    tc_memset (share_name, 0, sizeof (share_name));
    if (tc_strcmp (pSession->server_name, "") != 0)
    {
        share_name[0] = '\\';
        share_name[1] = '\\';
        rtsmb_util_ascii_to_rtsmb (pSession->server_name, &share_name[2], CFG_RTSMB_USER_CODEPAGE);
        share_name [rtsmb_len (share_name)] = '\\';
    }
    rtsmb_util_ascii_to_rtsmb (pJob->data.tree_connect.share_name, &share_name [rtsmb_len (share_name)], CFG_RTSMB_USER_CODEPAGE);
    t.share = share_name;

    rtsmb_util_string_to_upper (t.share, CFG_RTSMB_USER_CODEPAGE);

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    pJob->data.tree_connect.share_struct->connect_mid = pJob->mid;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_tree_connect_and_x, &t, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_read (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    return rtsmb_cli_session_send_read_job(pSession, pJob, &pJob->data.read);
}

int rtsmb_cli_session_send_read_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_CLI_READ_JOB_DATA info)
{
    RTSMB_HEADER h;
    RTSMB_READ_AND_X read;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_READ_ANDX;
    h.tid = info->fid_struct->owning_share->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    /* set up read */
    read.next_command = SMB_COM_NONE;
    read.fid = info->fid_struct->smb_fid;
    read.offset = info->fid_struct->offset;
    read.max_count = (dword)info->max_data_size;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_read_and_x_pre_nt, &read, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_write (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    return rtsmb_cli_session_send_write_job(pSession, pJob, &pJob->data.writex);
}

int rtsmb_cli_session_send_write_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_CLI_WRITEX_JOB_DATA info)
{
    RTSMB_HEADER h;
    RTSMB_WRITE_AND_X write;
    int r;
    long write_limit;
    long data_size;
  #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
    unsigned long first_buffer_payload_size;
  #endif

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_WRITE_ANDX;
    h.tid = info->fid_struct->owning_share->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    /* calculate data size */
    data_size = info->total_to_write - info->bytes_acked;

    /* if the server has specified a limit smaller than the size of the data
        we are trying to send, then we must send it in chunks */
    if (pSession->server_info.capabilities & CAP_LARGE_WRITEX)
    {
        write_limit = 0xefff;
    }
    else
    {
        write_limit = (long) (pSession->server_info.buffer_size - RTSMB_CLI_MESSAGE_OVERHEAD_BYTES);
        if (write_limit < 0)
            write_limit = 0;
    }

    if (data_size > write_limit)
    {
        data_size = write_limit;
    }

    /* set up write */
    write.next_command = SMB_COM_NONE;
    write.fid = info->fid_struct->smb_fid;
    write.offset = info->fid_struct->offset;
    write.offset_high = 0;
    write.write_mode = 0;
    write.data_size = (dword) data_size;
    write.data = info->data + info->bytes_acked;

    if (data_size > (long) (pSession->server_info.buffer_size - RTSMB_CLI_MESSAGE_OVERHEAD_BYTES))
    {
        write.is_large_write = 1;
    }

  #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
    first_buffer_payload_size = pSession->wire.physical_packet_size -
        (RTSMB_NBSS_HEADER_SIZE + 32 /* SMB header */ + 32 /* max WRITE_ANDX param header size */);

    if (write.data_size > first_buffer_payload_size)
    {
        write.limited_copy = 1;
        write.copy_data_size = first_buffer_payload_size;
    }
    else
    {
        write.limited_copy = 0;
        write.copy_data_size = 0;
    }
  #endif

    /* the total we have out on the wire; bytes_acked is the number of bytes
        that have been acknowledged by the server */
    info->written_so_far = info->bytes_acked + (long)write.data_size;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_write_and_x, &write, r);

  #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
    if (write.limited_copy)
    {
        rtsmb_cli_wire_smb_add_data (&pSession->wire,
                                     pJob->mid,
                                     write.data + write.copy_data_size,
                                     data_size - (long)write.copy_data_size);
    }
  #endif

    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

#if 0
RTSMB_STATIC
int rtsmb_cli_session_send_raw_write (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_WRITE_RAW write;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_WRITE_RAW;
    h.tid = pJob->data.writex.fid_struct->owning_share->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    /* set up write */
    write.fid = pJob->data.writex.fid_struct->smb_fid;
    write.count = pJob->data.writex.total_to_write;
    write.offset = pJob->data.writex.fid_struct->offset;
    write.timeout = 0;
    write.write_mode = 0;
    write.offset_high = 0;
    write.data_size = pJob->data.writex.total_to_write - pJob->data.writex.bytes_acked;
    write.data = pJob->data.writex.data + pJob->data.writex.bytes_acked;

    if (pJob->data.writex.bytes_acked == 0)
    {
        //write.write_mode = 0x01;

        /* if the server has specified a limit smaller than the size of the data
            we are trying to send, then we must send it in chunks */
        if (write.data_size > pSession->server_info.buffer_size - RTSMB_CLI_MESSAGE_OVERHEAD_BYTES)
        {
            write.data_size = pSession->server_info.buffer_size - RTSMB_CLI_MESSAGE_OVERHEAD_BYTES;
        }

        /* track how many bytes have been written so far */
        pJob->data.writex.written_so_far = write.data_size;

        r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
        ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
        pJob->mid = (word) r;
        rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
        rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_write_raw, &write, r);
        rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);
    }
    else
    {
#if 0
        PRTSMB_CLI_WIRE_BUFFER pBuffer;

        if (write.data_size > pSession->server_info.raw_size)
        {
            write.data_size = pSession->server_info.raw_size;
        }

        rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
        pBuffer = rtsmb_cli_wire_get_buffer (&pSession->wire, pJob->mid);
        if (pBuffer)
        {
            // we need to create a fake buffer here so the wire code will
            //  correctly process the final server response;
            pBuffer->state = WAITING_ON_SERVER;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_WIRE_BUFFER_STATE (WAITING_ON_SERVER);
#endif
            TURN_OFF (pBuffer->flags, INFO_CAN_TIMEOUT);
            pSession->wire.next_mid--;
        }

        rtsmb_net_write (pSession->wire.socket,
                         write.data + pJob->data.writex.bytes_acked,
                         write.data_size);

        /* track how many bytes have been written so far */
        pJob->data.writex.written_so_far = write.data_size;
#endif
    }

    return RTSMB_CLI_SSN_RV_OK;
}
#endif

RTSMB_STATIC
int rtsmb_cli_session_send_open (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_OPEN_AND_X open;
    int r;
    word w;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_OPEN_ANDX;
    h.tid = pJob->data.open.share_struct->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    /* set up open */
    open.next_command = SMB_COM_NONE;
    open.flags = 0;

    open.desired_access = 0;
    if (ON (pJob->data.open.flags, RTP_FILE_O_RDWR))
    {
        open.desired_access = 0x2;
    }
    else if (ON (pJob->data.open.flags, RTP_FILE_O_WRONLY))
    {
        open.desired_access = 0x1;
    }

    open.search_attributes = 0xFFFF;    /* search everything */
    open.file_attributes =  (pJob->data.open.mode & RTP_FILE_S_IWRITE)  ? 0x00 : 0x01;
    w  = (word)((pJob->data.open.mode & RTP_FILE_S_HIDDEN)  ? 0x02 : 0);
    open.file_attributes |= w;
    w = (word)((pJob->data.open.mode & RTP_FILE_S_SYSTEM)  ? 0x04 : 0);
    open.file_attributes |= w;
    w = (word)((pJob->data.open.mode & RTP_FILE_S_ARCHIVE) ? 0x20 : 0);
    open.file_attributes |= w;

    open.creation_time = 0;
    open.allocation_size = 0;

    open.open_function = 0;
    if (ON (pJob->data.open.flags, RTP_FILE_O_CREAT))
    {
        open.open_function |= 0x10;
    }

    if (ON (pJob->data.open.flags, RTP_FILE_O_TRUNC))
    {
        open.open_function |= 0x2;
    }
    else if ((ON (pJob->data.open.flags, RTP_FILE_O_CREAT) && OFF (pJob->data.open.flags, RTP_FILE_O_EXCL)) ||
             (OFF (pJob->data.open.flags, RTP_FILE_O_CREAT)))
    {
        open.open_function |= 0x1;
    }

    open.filename = pJob->data.open.filename;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_open_and_x, &open, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

int rtsmb_cli_session_send_create_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_CLI_CREATEX_JOB_DATA info)
{
    RTSMB_HEADER h;
    RTSMB_NT_CREATE_AND_X create;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_NT_CREATE_ANDX;
    h.tid = info->share_struct->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    /* set up open */
    create.next_command = SMB_COM_NONE; /* no other command */
    create.flags = 0;
    create.root_directory_fid = 0;

    create.desired_access  = (info->flags & RTP_FILE_O_RDWR)?   0x0002019B : 0;
    create.desired_access |= (info->flags & RTP_FILE_O_RDONLY)? 0x00000489 : 0;
    create.desired_access |= (info->flags & RTP_FILE_O_WRONLY)? 0x00000112 : 0;
    create.desired_access |= (info->flags & RTP_FILE_O_APPEND)? 0x00000004 : 0;

    create.allocation_size_high = 0;
    create.allocation_size_low = 0;

    create.ext_file_attributes =  (info->mode & RTP_FILE_S_IWRITE)  ? 0x00 : 0x01; // set readonly
    create.ext_file_attributes |= (info->mode & RTP_FILE_S_HIDDEN)  ? 0x02 : 0;    // set hidden
    create.ext_file_attributes |= (info->mode & RTP_FILE_S_SYSTEM)  ? 0x04 : 0;    // set system
    create.ext_file_attributes |= (info->mode & RTP_FILE_S_ARCHIVE) ? 0x20 : 0;
    if (create.ext_file_attributes == 0)
    {
        create.ext_file_attributes = 0x80; // normal bit
    }

    create.share_access = (dword)info->share_access;

    create.create_disposition = (info->flags & RTP_FILE_O_CREAT) ?
                                   ((info->flags & RTP_FILE_O_EXCL)?
                                       (2 /* CREATE_NEW */) :
                                       ((info->flags & RTP_FILE_O_TRUNC)?
                                           (5 /* CREATE_ALWAYS */) :  // correct
                                           (3 /* OPEN_ALWAYS */)))  : // correct
                                   ((info->flags & RTP_FILE_O_TRUNC)?
                                       (4 /* TRUNCATE_EXISTING */) :
                                       (1 /* OPEN_EXISTING */)); // correct

    create.create_options = 0x00400040;
    create.impersonation_level = 2;
    create.security_flags = 1;
    create.filename_size = (word) (rtsmb_len(info->filename) * sizeof(rtsmb_char));
    create.filename = info->filename;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_create_and_x, &create, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_create_local_fid (
        PRTSMB_CLI_SESSION pSession,
        word server_fid,
        PRTSMB_CLI_SESSION_SHARE share_struct,
        PFRTCHAR filename,
        int flags,
        int mode,
        PFINT returned_fid)
{
    PRTSMB_CLI_SESSION_FID pFid = 0;

    if (pSession->state == CSSN_STATE_RECOVERY_FILE_OPENING)
    {
        int i;

        /* find the file we are reopening */
        for (i = 0; i < prtsmb_cli_ctx->max_fids_per_session; i++)
        {
            if (pSession->fids[i].real_fid == CSSN_FID_STATE_DIRTY)
            {
                pSession->fids[i].real_fid = i;
                pSession->fids[i].smb_fid = server_fid;
                pFid = &pSession->fids[i];
                break;
            }
        }

        pSession->state = CSSN_STATE_RECOVERY_FILE_OPENED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_RECOVERY_FILE_OPENED);
#endif

        if (i == prtsmb_cli_ctx->max_fids_per_session)
        {
            /* THIS SHOULDN'T HAPPEN! */
            RTSMB_DEBUG_OUTPUT_STR("I TRIED TO FIND FID TO REOPEN, BUT THERE AREN'T ANY.\n",RTSMB_DEBUG_TYPE_ASCII);
            return RTSMB_CLI_SSN_RV_OK;
        }
    }
    else
    {
        pFid = rtsmb_cli_session_get_free_fid (pSession);
        ASSURE (pFid, RTSMB_CLI_SSN_RV_TOO_MANY_FIDS);

        pFid->smb_fid = server_fid;
        pFid->owning_share = share_struct;
        pFid->flags = flags;
        pFid->mode = mode;
        pFid->offset = 0;
        rtsmb_cpy (pFid->name, filename);
    }

    if (returned_fid)
    {
        (*returned_fid) = pFid->real_fid;
    }

    return RTSMB_CLI_SSN_RV_OK;
}

int rtsmb_cli_session_receive_create_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader,
        PRTSMB_CLI_CREATEX_JOB_DATA info)
{
    RTSMB_NT_CREATE_AND_X_R create;
    int r = 0;

    create.fid = 0;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_create_and_x, &create, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    r = rtsmb_cli_session_create_local_fid (
            pSession,
            create.fid,
            info->share_struct,
            info->filename,
            info->flags,
            info->mode,
            info->returned_fid);

    return r;
}

RTSMB_STATIC
int rtsmb_cli_session_send_close (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_CLOSE close;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_CLOSE;
    h.tid = pJob->data.close.fid_struct->owning_share->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    /* set up close */
    close.fid = pJob->data.close.fid_struct->smb_fid;
    close.last_write_time = 0;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_close, &close, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_tree_disconnect (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_TREE_DISCONNECT;
    h.tid = pJob->data.tree_disconnect.tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_tree_disconnect, 0, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_seek (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_SEEK seek;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_SEEK;
    h.tid = pJob->data.seek.fid_struct->owning_share->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    seek.offset = (dword) (pJob->data.seek.offset);
    seek.fid = pJob->data.seek.fid_struct->smb_fid;
    seek.mode = (word) pJob->data.seek.mode;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_seek, &seek, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_truncate (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_WRITE write;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_WRITE;
    h.tid = pJob->data.truncate.fid_struct->owning_share->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    write.offset = (dword) pJob->data.truncate.offset;
    write.count = 0;
    write.fid = pJob->data.truncate.fid_struct->smb_fid;
    write.data = 0;
    write.data_size = 0;
    write.remaining = 0;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_write, &write, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_flush (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_FLUSH flush;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_FLUSH;
    h.tid = pJob->data.flush.fid_struct->owning_share->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    flush.fid = pJob->data.truncate.fid_struct->smb_fid;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_flush, &flush, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_rename (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_RENAME rename;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_RENAME;
    h.tid = pJob->data.rename.share_struct->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    rename.search_attributes = 0xFFFF;
    rename.new_filename = pJob->data.rename.new_filename;
    rename.old_filename = pJob->data.rename.old_filename;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_rename, &rename, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_delete (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_DELETE delete;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_DELETE;
    h.tid = pJob->data.delete.share_struct->tid;
    h.uid = rtsmb_cli_session_get_uid (pSession);

    delete.search_attributes = 0x0026;  /* include most normal files */
    delete.filename = pJob->data.delete.filename;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_delete, &delete, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_mkdir (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_CREATE_DIRECTORY com;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_CREATE_DIRECTORY;
    h.tid = pJob->data.mkdir.share_struct->tid;

    com.directory = pJob->data.mkdir.filename;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_create_directory, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_rmdir (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_DELETE_DIRECTORY com;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_DELETE_DIRECTORY;
    h.tid = pJob->data.rmdir.share_struct->tid;

    com.directory = pJob->data.rmdir.filename;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_delete_directory, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_find_first_error_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    /* Here, we are concerned with only one thing: if a FILE_NOT_FOUND error occurred, we
       need to claim the search is over. */
    if (rtsmb_cli_session_translate_error (pHeader) == RTSMB_CLI_SSN_RV_FILE_NOT_FOUND)
    {
        return RTSMB_CLI_SSN_RV_END_OF_SEARCH;
    }

    return RTSMB_CLI_SSN_RV_INVALID_RV;
}

RTSMB_STATIC
int rtsmb_cli_session_send_find_first (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_TRANSACTION trans;
    RTSMB_TRANS2_FIND_FIRST2 com;
    word setup_words [1] = {TRANS2_FIND_FIRST2};
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_TRANSACTION2;
    h.tid = pJob->data.findfirst.search_struct->share_struct->tid;

    trans.max_data_count = 1028;
    trans.max_parameter_count = 1028;
    trans.max_setup_count = 20;
    trans.flags = 0;
    trans.name = 0;
    trans.name_size = 0;
    trans.timeout = 0;
    trans.setup = setup_words;
    trans.setup_size = 1;

    com.filename = pJob->data.findfirst.pattern;
    com.search_attributes = 0x0016;
    com.search_storage_type = 0;
    com.data = 0;
    com.data_size = 0;
    com.flags = 0;
    com.information_level = 1;  /* SMB_INFO_STANDARD */
    com.search_count = (word) prtsmb_cli_ctx->max_files_per_search;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_transaction, &trans, r);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_trans2_find_first2, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_find_next (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_TRANSACTION trans;
    RTSMB_TRANS2_FIND_NEXT2 com;
    word setup_words [1] = {TRANS2_FIND_NEXT2};
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_TRANSACTION2;
    h.tid = pJob->data.findnext.search_struct->share_struct->tid;

    trans.max_data_count = 2000;
    trans.max_parameter_count = 2000;
    trans.max_setup_count = 20;
    trans.flags = 0;
    trans.name = 0;
    trans.name_size = 0;
    trans.timeout = 0;
    trans.setup = setup_words;
    trans.setup_size = 1;

    com.sid = pJob->data.findnext.search_struct->server_sid;
    com.filename = 0;
    com.flags = 0x8;    /* continue from last place */
    com.resume_key = 0;
    com.information_level = 1;  /* SMB_INFO_STANDARD */
    com.search_count = (word) prtsmb_cli_ctx->max_files_per_search;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_transaction, &trans, r);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_trans2_find_next2, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_find_close (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_FIND_CLOSE2 com;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_FIND_CLOSE2;
    h.tid = pJob->data.findclose.search_struct->share_struct->tid;

    com.sid = pJob->data.findclose.search_struct->server_sid;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_find_close2, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);


    /* we also want to close everything up here -- useless to wait for response */
    rtsmb_cli_session_search_close (pJob->data.findclose.search_struct);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_stat (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_TRANSACTION trans;
    RTSMB_TRANS2_QUERY_PATH_INFORMATION com;
    word setup_words [1] = {TRANS2_QUERY_PATH_INFORMATION};
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_TRANSACTION2;
    h.tid = pJob->data.stat.share_struct->tid;

    trans.max_data_count = 2000;
    trans.max_parameter_count = 2000;
    trans.max_setup_count = 20;
    trans.flags = 0;
    trans.name = 0;
    trans.name_size = 0;
    trans.timeout = 0;
    trans.setup = setup_words;
    trans.setup_size = 1;

    com.filename = pJob->data.stat.filename;
    com.information_level = 1;  /* SMB_INFO_STANDARD */
    com.parent = &trans;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_transaction, &trans, r);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_trans2_query_path_information, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_chmode (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_SET_INFORMATION com;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_SET_INFORMATION;
    h.tid = pJob->data.chmode.share_struct->tid;

    com.filename = pJob->data.chmode.filename;
    com.last_write_time = 0;
    com.file_attributes = 0;

    if (ON (pJob->data.chmode.attributes, RTP_FILE_ATTRIB_RDONLY))
    {
        com.file_attributes |= SMB_FA_RO;
    }
    if (ON (pJob->data.chmode.attributes, RTP_FILE_ATTRIB_ISDIR))
    {
        com.file_attributes |= SMB_FA_D;
    }
    if (ON (pJob->data.chmode.attributes, RTP_FILE_ATTRIB_ISVOL))
    {
        com.file_attributes |= SMB_FA_V;
    }
    if (ON (pJob->data.chmode.attributes, RTP_FILE_ATTRIB_HIDDEN))
    {
        com.file_attributes |= SMB_FA_H;
    }
    if (ON (pJob->data.chmode.attributes, RTP_FILE_ATTRIB_SYSTEM))
    {
        com.file_attributes |= SMB_FA_S;
    }
    if (ON (pJob->data.chmode.attributes, RTP_FILE_ATTRIB_ARCHIVE))
    {
        com.file_attributes |= SMB_FA_A;
    }

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_set_information, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

#if 0
RTSMB_STATIC
int rtsmb_cli_session_send_setfiletime (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_SET_INFORMATION com;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_SET_INFORMATION;
    h.tid = pJob->data.setfiletime.share_struct->tid;

    com.filename = pJob->data.setfiletime.filename;
    com.last_write_time = 0;
    com.file_attributes = 0;

    //deal with times


    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_set_information, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}
#endif

RTSMB_STATIC
int rtsmb_cli_session_send_share_find_first (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    RTSMB_HEADER h;
    RTSMB_TRANSACTION trans;
    RTSMB_RAP_GET_INFO com;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_TRANSACTION;
    pShare = rtsmb_cli_session_get_share (pSession, ipc_name);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    h.tid = pShare->tid;

    trans.max_data_count = 2000;
    trans.max_parameter_count = 8;
    trans.max_setup_count = 0;
    trans.flags = 0;
    trans.name = name_pipe_lanman;
    trans.timeout = 0;
    trans.setup = 0;
    trans.setup_size = 0;

    com.information_level = 1;
    com.receive_size = (word) (RTSMB_CLI_WIRE_MAX_BUFFER_SIZE - 100);   /* should be about right */

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_transaction, &trans, r);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_share_enum, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_server_enum (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    RTSMB_HEADER h;
    RTSMB_TRANSACTION trans;
    RTSMB_RAP_SERVER_ENUM2 com;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_TRANSACTION;
    pShare = rtsmb_cli_session_get_share (pSession, ipc_name);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    h.tid = pShare->tid;

    trans.max_data_count = (word) (RTSMB_CLI_WIRE_MAX_BUFFER_SIZE - 100);
    trans.max_parameter_count = 8;
    trans.max_setup_count = 0;
    trans.flags = 0;
    trans.name = name_pipe_lanman;
    trans.timeout = 0;
    trans.setup = 0;
    trans.setup_size = 0;

    com.information_level = 0;
    com.receive_size = (word) (RTSMB_CLI_WIRE_MAX_BUFFER_SIZE - 100);   /* should be about right */
    com.domain = 0;
    com.server_type = 0x2;  /* only interested in smb servers */

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_transaction, &trans, r);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_rap_server_enum2, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_full_server_enum (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    RTSMB_HEADER h;
    RTSMB_TRANSACTION trans;
    RTSMB_RAP_SERVER_ENUM2 com;
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_TRANSACTION;
    pShare = rtsmb_cli_session_get_share (pSession, ipc_name);
    ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
    h.tid = pShare->tid;

    trans.max_data_count = (word) (RTSMB_CLI_WIRE_MAX_BUFFER_SIZE - 100);
    trans.max_parameter_count = 8;
    trans.max_setup_count = 0;
    trans.flags = 0;
    trans.name = name_pipe_lanman;
    trans.timeout = 0;
    trans.setup = 0;
    trans.setup_size = 0;

    com.information_level = 1;
    com.receive_size = (word) (RTSMB_CLI_WIRE_MAX_BUFFER_SIZE - 100);   /* should be about right */
    if (pJob->data.full_server_enum.valid_domain)
    {
        com.domain = pJob->data.full_server_enum.domain;
    }
    else
    {
        com.domain = 0;
    }
    com.server_type = pJob->data.full_server_enum.type;

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_transaction, &trans, r);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_rap_server_enum2, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_send_get_free (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    RTSMB_HEADER h;
    RTSMB_TRANSACTION trans;
    RTSMB_TRANS2_QUERY_FS_INFORMATION com;
    word setup_words [1] = {TRANS2_QUERY_FS_INFORMATION};
    int r;

    /* set up header */
    rtsmb_cli_session_fill_header (pSession, &h);
    h.command = SMB_COM_TRANSACTION2;
    h.tid = pJob->data.getfree.share_struct->tid;

    trans.max_data_count = 18;
    trans.max_parameter_count = 0;
    trans.max_setup_count = 0;
    trans.flags = 0;
    trans.name = 0;
    trans.name_size = 0;
    trans.timeout = 0;
    trans.setup = setup_words;
    trans.setup_size = 1;

    com.parent = &trans;
    com.information_level = 1;  /* SMB_INFO_ALLOCATION */

    r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
    ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
    pJob->mid = (word) r;
    rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_transaction, &trans, r);
    rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_query_fs_information, &com, r);
    rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_negotiate (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    RTSMB_NEGOTIATE_R nr;
    int r = 0;

#if (DEBUG_AUTH)
    rtp_printf("rtsmb_cli_session_receive_negotiate: pJob = %x\n", pJob);
#endif
    nr.challenge_size = 8;
    nr.challenge = pSession->server_info.challenge;
    nr.domain = 0;
    nr.dialect_index = 0;
    nr.security_mode = 0;
    nr.capabilities = 0;
    nr.max_buffer_size = 0;
    nr.max_raw_size = 0;
    nr.max_vcs = 0;
    nr.session_id = 0;
    nr.max_mpx_count = 0;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_negotiate, &nr, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    /* make sure we have a valid dialect */
    ASSURE (nr.dialect_index != 0xFF, RTSMB_CLI_SSN_RV_DEAD);
    ASSURE (nr.dialect_index < NUM_SPOKEN_DIALECTS, RTSMB_CLI_SSN_RV_MALICE);

    pSession->server_info.dialect = dialect_types[nr.dialect_index];
    pSession->server_info.user_mode = ON (nr.security_mode, 0x1);
    pSession->server_info.capabilities = nr.capabilities;
    pSession->server_info.encrypted = ON (nr.security_mode, 0x2);
#if (DEBUG_AUTH)
    rtp_printf("rtsmb_cli_session_receive_negotiate: pSession = %x, encrypt = %d\n",
        pSession, pSession->server_info.encrypted);
#endif
    pSession->server_info.buffer_size = nr.max_buffer_size;
    pSession->server_info.raw_size = nr.max_raw_size;
    pSession->server_info.vcs = nr.max_vcs;
    pSession->server_info.session_id = nr.session_id;
    pSession->server_info.mpx_count = (word) MIN (nr.max_mpx_count, prtsmb_cli_ctx->max_jobs_per_session);

    if (pSession->server_info.encrypted)
    {
        /* we currently only support 8-bytes */
        ASSURE (nr.challenge_size == 8, RTSMB_CLI_SSN_RV_DEAD);
    }

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_session_setup (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    RTSMB_SESSION_SETUP_AND_X_R s;
    int r = 0;

    s.srv_native_os = 0;
    s.srv_native_lan_man = 0;
    s.srv_primary_domain = 0;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_session_setup_and_x, &s, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    /* make sure we have a valid user */
    ASSURE (pJob->data.session_setup.user_struct->state == CSSN_USER_STATE_LOGGING_ON, RTSMB_CLI_SSN_RV_BAD_UID);

    pJob->data.session_setup.user_struct->uid = pHeader->uid;
    pJob->data.session_setup.user_struct->state = CSSN_USER_STATE_LOGGED_ON;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_USER_STATE (CSSN_USER_STATE_LOGGED_ON);
#endif
    rtsmb_cpy (pJob->data.session_setup.user_struct->name, pJob->data.session_setup.account_name);
    tc_strcpy (pJob->data.session_setup.user_struct->password, pJob->data.session_setup.password);
    rtsmb_cpy (pJob->data.session_setup.user_struct->domain_name, pJob->data.session_setup.domain_name);

    if (pSession->state == CSSN_STATE_RECOVERY_LOGGING_ON)
    {
        pSession->state = CSSN_STATE_RECOVERY_LOGGED_ON;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_STATE (CSSN_STATE_RECOVERY_LOGGED_ON);
#endif
    }

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_logoff (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    RTSMB_LOGOFF_AND_X_R l;
    int r = 0;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_logoff_and_x, &l, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    /* make sure we have a valid user */
    ASSURE (pSession->user.state == CSSN_USER_STATE_LOGGED_ON, RTSMB_CLI_SSN_RV_BAD_UID);
    ASSURE (pSession->user.uid == pHeader->uid, RTSMB_CLI_SSN_RV_BAD_UID);

    rtsmb_cli_session_user_close (&pSession->user);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_tree_connect (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    RTSMB_TREE_CONNECT_AND_X_R t;
    PRTSMB_CLI_SESSION_SHARE pShare;
    int r = 0;

    t.service = 0;
    t.native_fs = 0;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_tree_connect_and_x, &t, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    pShare = 0;
    for (r = 0; r < prtsmb_cli_ctx->max_shares_per_session; r++)
    {
        if (pSession->shares[r].state != CSSN_SHARE_STATE_UNUSED &&
            pSession->shares[r].connect_mid == pHeader->mid)
        {
            pShare = &pSession->shares[r];
            break;
        }
    }

    ASSURE (pShare, RTSMB_CLI_SSN_RV_MALFORMED);

    pShare->tid = pHeader->tid;
    pShare->state = CSSN_SHARE_STATE_CONNECTED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SHARE_STATE (CSSN_SHARE_STATE_CONNECTED);
#endif
    tc_strcpy (pShare->share_name, pJob->data.tree_connect.share_name);
    tc_strcpy (pShare->password, pJob->data.tree_connect.password);

    /* We special-case a situation where we have just connected to the IPC$ share.  This
       means that we are now a fully-negotiated session and should alert our consumer. */
    if (tc_strcmp (pShare->share_name, "IPC$") == 0)
    {
        /* To denote this, we find the pseudo-job that was waiting on this and finish it. */
        for (r = 0; r < prtsmb_cli_ctx->max_jobs_per_session; r++)
        {
            if (pSession->jobs[r].state == CSSN_JOB_STATE_FAKE)
            {
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

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_tree_disconnect (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_tree_disconnect, 0, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_read (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    return rtsmb_cli_session_receive_read_job(pSession, pJob, pHeader, &pJob->data.read);
}

int rtsmb_cli_session_receive_read_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader,
        PRTSMB_CLI_READ_JOB_DATA info)
{
    RTSMB_READ_AND_X_R read;
    int r = 0;

    read.data_size = (dword)info->max_data_size;
    read.data = info->data;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_read_and_x, &read, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    if (info->returned_data_size)
    {
        /* we only send a word's worth */
        (*info->returned_data_size) = (word) (read.data_size & 0xFFFF);
    }

    info->fid_struct->offset += read.data_size;

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_write (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    return rtsmb_cli_session_receive_write_job(pSession, pJob, pHeader, &pJob->data.writex);
}

int rtsmb_cli_session_receive_write_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader,
        PRTSMB_CLI_WRITEX_JOB_DATA info)
{
    RTSMB_WRITE_AND_X_R write;
    int r = 0;

    write.count = 0;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_write_and_x, &write, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    info->bytes_acked += write.count;
    info->fid_struct->offset += write.count;

    if (info->bytes_acked < info->total_to_write)
    {
        /* there is still more data to be written; reset our state to 'stalled'
            so the client state machine will let us send it */
        pJob->state = CSSN_JOB_STATE_STALLED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_JOB_STATE (CSSN_JOB_STATE_STALLED);
#endif
        pJob->send_count = 0;
    }
    else
    {
        if (info->returned_data_size)
        {
            (*info->returned_data_size) = info->bytes_acked;
        }
    }

    return RTSMB_CLI_SSN_RV_OK;
}

#if 0
RTSMB_STATIC
int rtsmb_cli_session_receive_raw_write (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0;

    if (pJob->data.writex.bytes_acked == 0)
    {
        RTSMB_WRITE_RAW_R1 write;
        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_write_raw_r1, &write, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

        pJob->data.writex.bytes_acked += pJob->data.writex.written_so_far;
        pJob->data.writex.fid_struct->offset += pJob->data.writex.written_so_far;

        if (pJob->data.writex.bytes_acked < pJob->data.writex.total_to_write)
        {
            rtsmb_net_write (pSession->wire.socket,
                             pJob->data.writex.data + pJob->data.writex.bytes_acked,
                             pJob->data.writex.total_to_write - pJob->data.writex.bytes_acked);

          #if 0
            /* there is still more data to be written; reset our state to 'stalled'
                so the client state machine will let us send it */
            pJob->state = CSSN_JOB_STATE_STALLED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_JOB_STATE (CSSN_JOB_STATE_STALLED);
#endif
            pJob->send_count = 0;
          #endif
        }
    }
  #if 0
    else
    {
        RTSMB_WRITE_RAW_R2 write;
        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_write_raw_r2, &write, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

        pJob->data.writex.bytes_acked += pJob->data.writex.written_so_far;
        pJob->data.writex.fid_struct->offset += pJob->data.writex.written_so_far;

        if (pJob->data.writex.returned_data_size)
        {
            (*pJob->data.writex.returned_data_size) = pJob->data.writex.bytes_acked;
        }
    }
  #endif

    return RTSMB_CLI_SSN_RV_OK;
}
#endif

RTSMB_STATIC
int rtsmb_cli_session_receive_open (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    RTSMB_OPEN_AND_X_R open;
    int r = 0;

    open.fid = 0;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_open_and_x, &open, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    r = rtsmb_cli_session_create_local_fid (
            pSession, open.fid,
            pJob->data.open.share_struct,
            pJob->data.open.filename,
            pJob->data.open.flags,
            pJob->data.open.mode,
            pJob->data.open.returned_fid);

    return r;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_close (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_close, 0, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    rtsmb_cli_session_fid_close (pJob->data.close.fid_struct);

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_seek (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0;
    RTSMB_SEEK_R seek;

    seek.offset = 0;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_seek, &seek, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    if (pJob->data.seek.resulting_offset)
    {
        (*pJob->data.seek.resulting_offset) = (long) seek.offset;
    }

    pJob->data.seek.fid_struct->offset = seek.offset;

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_truncate (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0;
    RTSMB_WRITE_R write;

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_write, &write, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    pJob->data.truncate.fid_struct->offset = (dword)pJob->data.truncate.offset;

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
void rtsmb_cli_session_find_to_dstat (PRTSMB_FIND_FILE_INFO_STANDARD pinfo, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
    DATE_STR adate, wdate, cdate;

    pdstat->fattributes = 0;
    if (ON (pinfo->attributes, SMB_FA_D))
        pdstat->fattributes |= RTP_FILE_ATTRIB_ISDIR;

    if (ON (pinfo->attributes, SMB_FA_RO))
        pdstat->fattributes |= RTP_FILE_ATTRIB_RDONLY;
    else
        pdstat->fattributes |= RTP_FILE_ATTRIB_RDWR;

    if (ON (pinfo->attributes, SMB_FA_H))
        pdstat->fattributes |= RTP_FILE_ATTRIB_HIDDEN;

    if (ON (pinfo->attributes, SMB_FA_S))
        pdstat->fattributes |= RTP_FILE_ATTRIB_SYSTEM;

    if (ON (pinfo->attributes, SMB_FA_V))
        pdstat->fattributes |= RTP_FILE_ATTRIB_ISVOL;

    if (ON (pinfo->attributes, SMB_FA_A))
        pdstat->fattributes |= RTP_FILE_ATTRIB_ARCHIVE;

    adate.time = pinfo->last_access_time;
    adate.date = pinfo->last_access_date;
    wdate.time = pinfo->last_write_time;
    wdate.date = pinfo->last_write_date;
    cdate.time = pinfo->creation_time;
    cdate.date = pinfo->creation_date;
    pdstat->fatime64 = rtsmb_util_time_date_to_ms (adate);
    pdstat->fwtime64 = rtsmb_util_time_date_to_ms (wdate);
    pdstat->fctime64 = rtsmb_util_time_date_to_ms (cdate);
    pdstat->fhtime64.low_time = 0;
    pdstat->fhtime64.high_time = 0;
    pdstat->fsize = pinfo->file_size;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_find_first (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0, i;
    RTSMB_TRANSACTION_R trans;
    RTSMB_TRANS2_FIND_FIRST_R find;
    RTSMB_FIND_FILE_INFO_STANDARD info;

    find.sid = 0;
    find.end_of_search = 0;
    find.search_count = 0;

    trans.setup = 0;
    trans.setup_size = 0;
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_transaction, &trans, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_find_first2, &find, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    /* let's fill out the search struct now, since we lose this info after this function */
    pJob->data.findfirst.search_struct->server_sid = find.sid;
    pJob->data.findfirst.search_struct->index = 0;
    pJob->data.findfirst.search_struct->end_of_search = find.end_of_search;
    for (i = 0; i < find.search_count && i < prtsmb_cli_ctx->max_files_per_search; i++)
    {
        rtsmb_char dot[2] = {'.', '\0'};
        rtsmb_char dotdot[3] = {'.', '.', '\0'};

        info.valid_resume_key = FALSE;
        info.filename = (PFRTCHAR) pJob->data.findfirst.search_struct->dstats[i].filename;
        info.filename_size = (byte) (rtsmb_len (info.filename) * sizeof (rtsmb_char));
        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_find_file_info_standard, &info, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

        /* returning the special files . and .. confuses things, so we skip them here */
        if (rtsmb_cmp (info.filename, dot) == 0 || rtsmb_cmp (info.filename, dotdot) == 0)
        {
            find.search_count--;
            i--;
            continue;
        }

        rtsmb_cli_session_find_to_dstat (&info, &pJob->data.findfirst.search_struct->dstats[i]);

        pJob->data.findfirst.search_struct->dstats[i].unicode = INCLUDE_RTSMB_UNICODE ? 1 : 0;
        pJob->data.findfirst.search_struct->dstats[i].sid = pJob->data.findfirst.search_struct->sid;
    }

    pJob->data.findfirst.search_struct->num_stats = MIN (find.search_count, prtsmb_cli_ctx->max_files_per_search);

    if (find.search_count)
    {
        *pJob->data.findfirst.answering_dstat = pJob->data.findfirst.search_struct->dstats[0];
    }
    else
    {
        pJob->data.findfirst.search_struct->end_of_search = 1;
        return RTSMB_CLI_SSN_RV_END_OF_SEARCH;
    }

    return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_find_next (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0, i;
    RTSMB_TRANSACTION_R trans;
    RTSMB_TRANS2_FIND_NEXT_R find;
    RTSMB_FIND_FILE_INFO_STANDARD info;

    find.end_of_search = 0;
    find.search_count = 0;

    trans.setup = 0;
    trans.setup_size = 0;
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_transaction, &trans, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_find_next2, &find, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    /* let's fill out the search struct now, since we lose this info after this function */
    pJob->data.findnext.search_struct->index = 0;
    pJob->data.findnext.search_struct->end_of_search = find.end_of_search;
    for (i = 0; i < find.search_count && i < prtsmb_cli_ctx->max_files_per_search; i++)
    {
        static rtsmb_char dot[2] = {'.', '\0'};
        static rtsmb_char dotdot[3] = {'.', '.', '\0'};

        info.valid_resume_key = FALSE;
        info.filename = (PFRTCHAR) pJob->data.findnext.search_struct->dstats[i].filename;
        info.filename_size = (byte) (rtsmb_len (info.filename) * sizeof (rtsmb_char));
        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_find_file_info_standard, &info, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

        /* returning the special files . and .. confuses things, so we skip them here */
        if (rtsmb_cmp (info.filename, dot) == 0 || rtsmb_cmp (info.filename, dotdot) == 0)
        {
            find.search_count--;
            i--;
            continue;
        }

        rtsmb_cli_session_find_to_dstat (&info, &pJob->data.findfirst.search_struct->dstats[i]);

        pJob->data.findnext.search_struct->dstats[i].unicode = INCLUDE_RTSMB_UNICODE ? 1 : 0;;
        pJob->data.findnext.search_struct->dstats[i].sid = pJob->data.findnext.search_struct->sid;
    }

    pJob->data.findnext.search_struct->num_stats = MIN (find.search_count, prtsmb_cli_ctx->max_files_per_search);

    if (find.search_count)
    {
        *pJob->data.findnext.answering_dstat = pJob->data.findnext.search_struct->dstats[0];
    }
    else
    {
        pJob->data.findfirst.search_struct->end_of_search = 1;
        return RTSMB_CLI_SSN_RV_END_OF_SEARCH;
    }

    return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_stat (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0;
    RTSMB_TRANSACTION_R trans;
    RTSMB_INFO_STANDARD info;
    DATE_STR adate, wdate, cdate;

    info.attributes = 0;

    trans.setup = 0;
    trans.setup_size = 0;
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_transaction, &trans, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_info_standard, &info, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    pJob->data.stat.answering_stat->fattributes = rtsmb_util_smb_to_rtsmb_attributes (info.attributes);

    adate.time = info.last_access_time;
    adate.date = info.last_access_date;
    wdate.time = info.last_write_time;
    wdate.date = info.last_write_date;
    cdate.time = info.creation_time;
    cdate.date = info.creation_date;
    pJob->data.stat.answering_stat->fatime64 = rtsmb_util_time_date_to_ms (adate);
    pJob->data.stat.answering_stat->fwtime64 = rtsmb_util_time_date_to_ms (wdate);
    pJob->data.stat.answering_stat->fctime64 = rtsmb_util_time_date_to_ms (cdate);
    pJob->data.stat.answering_stat->fhtime64.low_time = 0;
    pJob->data.stat.answering_stat->fhtime64.high_time = 0;
    pJob->data.stat.answering_stat->fsize = info.file_size;

    return RTSMB_CLI_SSN_RV_OK;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_share_find_first (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0, i, j;
    RTSMB_TRANSACTION_R trans;
    RTSMB_RAP_ENUM_HEADER_R enum_header;
    RTSMB_RAP_SHARE_ENUM_INFO_R info;

    trans.setup = 0;
    trans.setup_size = 0;
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_transaction, &trans, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_enum_header, &enum_header, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    for (i = 0, j = 0; i < enum_header.available_entries && j < prtsmb_cli_ctx->max_shares_per_search; i++)
    {
        info.share_num = i;
        info.total_shares = enum_header.available_entries;
        info.share_data.comment = 0;
        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_share_enum_info, &info, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

        /* We only support share types right now. */
        /* :::: Removed, pass all share names up if (info.share_data.type == RTSMB_SHARE_TYPE_DISK) */
        {
            rtsmb_util_rtsmb_to_ascii (info.share_data.name, pJob->data.sharefindfirst.search_struct->sstats[j].name, CFG_RTSMB_USER_CODEPAGE);
            //rtsmb_cpy (pJob->data.sharefindfirst.search_struct->sstats[j].name, info.share_data.name);
            pJob->data.sharefindfirst.search_struct->sstats[j].type = info.share_data.type;
            pJob->data.sharefindfirst.search_struct->sstats[j].sid = pJob->data.sharefindfirst.search_struct->sid;
            j++;
        }
    }

    pJob->data.sharefindfirst.search_struct->num_stats = j;

    if (j > 0)
    {
        *pJob->data.sharefindfirst.answering_sstat = pJob->data.sharefindfirst.search_struct->sstats[0];
    }
    else
    {
        return RTSMB_CLI_SSN_RV_END_OF_SEARCH;
    }

    return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
}

/* receives a server enum request */
RTSMB_STATIC
int rtsmb_cli_session_receive_server_enum (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0, i;
    RTSMB_TRANSACTION_R trans;
    RTSMB_RAP_ENUM_HEADER_R enum_header;
    RTSMB_RAP_SERVER_INFO_0 info;

    trans.setup = 0;
    trans.setup_size = 0;
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_transaction, &trans, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_enum_header, &enum_header, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    for (i = 0; i < enum_header.available_entries && i < prtsmb_cli_ctx->max_servers_per_search; i++)
    {
        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_server_info_0, &info, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

        rtsmb_util_rtsmb_to_unicode (info.name, &pJob->data.serverfind.search_struct->srvstats[i * RTSMB_NB_NAME_SIZE], CFG_RTSMB_USER_CODEPAGE);
    }

    pJob->data.serverfind.search_struct->index = 0;
    pJob->data.serverfind.search_struct->num_stats = MIN (enum_header.available_entries, prtsmb_cli_ctx->max_servers_per_search);

    return RTSMB_CLI_SSN_RV_OK;
}

/* receives a server enum request */
RTSMB_STATIC
int rtsmb_cli_session_receive_full_server_enum (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0, i, j;
    RTSMB_TRANSACTION_R trans;
    RTSMB_RAP_ENUM_HEADER_R enum_header;
    RTSMB_RAP_SERVER_INFO_1 info;

    trans.setup = 0;
    trans.setup_size = 0;
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_transaction, &trans, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_enum_header, &enum_header, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    if (enum_header.status != 0)
    {
        return RTSMB_CLI_SSN_RV_SMB_ERROR;
    }

    info.info_total = enum_header.available_entries;
    for (i = 0, j = 0; i < enum_header.available_entries && j < pJob->data.full_server_enum.answering_infos_size; i++)
    {
        rtsmb_char comment [RTSMB_MAX_COMMENT_SIZE + 1];

        info.info_num = i;
        info.comment = comment;
        info.comment_size = RTSMB_MAX_COMMENT_SIZE;
        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_server_info_1, &info, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

        rtsmb_util_rtsmb_to_ascii (info.name, pJob->data.full_server_enum.answering_infos[j].name, CFG_RTSMB_USER_CODEPAGE);
        pJob->data.full_server_enum.answering_infos[j].version_minor = info.version_minor;
        pJob->data.full_server_enum.answering_infos[j].version_major = info.version_major;
        pJob->data.full_server_enum.answering_infos[j].type = info.type;
        rtsmb_util_rtsmb_to_ascii (info.comment, pJob->data.full_server_enum.answering_infos[j].comment, CFG_RTSMB_USER_CODEPAGE);

        pJob->data.full_server_enum.answering_infos[j].time_received = rtp_get_system_msec ();

        /* zero out stuff we don't get from this smb */
        pJob->data.full_server_enum.answering_infos[j].browse_version_minor = 0;
        pJob->data.full_server_enum.answering_infos[j].browse_version_major = 0;
        pJob->data.full_server_enum.answering_infos[j].signature = 0;
        pJob->data.full_server_enum.answering_infos[j].update_count = 0;
        pJob->data.full_server_enum.answering_infos[j].periodicity = 0;
        j++;
    }

    return j;
}

RTSMB_STATIC
int rtsmb_cli_session_receive_get_free (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    int r = 0;
    RTSMB_TRANSACTION_R trans;
    RTSMB_INFO_ALLOCATION info;

    trans.setup = 0;
    trans.setup_size = 0;
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_transaction, &trans, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
    rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_info_allocation, &info, r);
    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);

    if (pJob->data.getfree.answering_free_units)
        *pJob->data.getfree.answering_free_units = (int)info.available_units;
    if (pJob->data.getfree.answering_block_size)
        *pJob->data.getfree.answering_block_size = (int)info.bytes_per_sector;
    if (pJob->data.getfree.answering_blocks_per_unit)
        *pJob->data.getfree.answering_blocks_per_unit = (int)info.sectors_per_unit;
    if (pJob->data.getfree.answering_total_units)
        *pJob->data.getfree.answering_total_units = (int)info.total_units;

    return RTSMB_CLI_SSN_RV_OK;
}

#endif /* INCLUDE_RTSMB_CLIENT */
