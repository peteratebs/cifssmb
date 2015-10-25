#ifndef __CLI_SSN_H__
#define __CLI_SSN_H__

#include "smbdefs.h"
#if (INCLUDE_RTSMB_CLIENT)

#ifdef SUPPORT_SMB2
#include "com_smb2.h"
#include "com_smb2_wiredefs.h"
#endif

#include "cliwire.h"
#include "smbnbds.h"
#include "clirpc.h"

/* This is how much we can take in one write or read */
/* it's the size of the wire buffer minus headers */
#define RTSMB_CLI_MESSAGE_OVERHEAD_BYTES      60
#define RTSMB_CLI_SESSION_MAX_DATA_BYTES      (RTSMB_CLI_WIRE_MAX_BUFFER_SIZE - RTSMB_CLI_MESSAGE_OVERHEAD_BYTES)

#define RTSMB_CLI_SSN_RV_OK                   0    /* everything is good */
#define RTSMB_CLI_SSN_RV_MALFORMED            -1   /* something was malformed on the wire */
#define RTSMB_CLI_SSN_RV_LATER                -2   /* try again later */
#define RTSMB_CLI_SSN_RV_DEAD                 -3   /* session is untenable and should be closed */
#define RTSMB_CLI_SSN_RV_MALICE               -4   /* server seems malicious */
#define RTSMB_CLI_SSN_RV_BAD_JOB              -5   /* job id is invalid */
#define RTSMB_CLI_SSN_RV_BAD_NAME             -19  /* invalid netbios name passed */
#define RTSMB_CLI_SSN_RV_BAD_ARGS             -6   /* argument to function is out of range */
#define RTSMB_CLI_SSN_RV_TOO_MANY_JOBS        -7   /* too many jobs waiting */
#define RTSMB_CLI_SSN_RV_TOO_MANY_USERS       -8   /* too many users logged on */
#define RTSMB_CLI_SSN_RV_TOO_MANY_SHARES      -11  /* too many shares already connected */
#define RTSMB_CLI_SSN_RV_TOO_MANY_FIDS        -13  /* too many fids already open */
#define RTSMB_CLI_SSN_RV_TOO_MANY_SEARCHES    -15  /* too many searches already open */
#define RTSMB_CLI_SSN_RV_BAD_SHARE            -12  /* bad share name */
#define RTSMB_CLI_SSN_RV_BAD_FILENAME         -21  /* bad file name */
#define RTSMB_CLI_SSN_RV_BAD_UID              -9   /* uid in packet was bad */
#define RTSMB_CLI_SSN_RV_BAD_FID              -14  /* bad fid */
#define RTSMB_CLI_SSN_RV_BAD_SID              -23  /* bad session id */
#define RTSMB_CLI_SSN_RV_BAD_SEARCH           -16  /* bad search struct passed in */
#define RTSMB_CLI_SSN_RV_SEARCH_DATA_READY    -17  /* data is available from a search struct */
#define RTSMB_CLI_SSN_RV_END_OF_SEARCH        -18  /* no more data from this search */
#define RTSMB_CLI_SSN_RV_ALREADY_CONNECTED    -20  /* already connected to a share */
#define RTSMB_CLI_SSN_RV_NOT_ENOUGH_RESOURCES -22  /* not enough search structs to hand out */
#define RTSMB_CLI_SSN_RV_TOO_MUCH_DATA        -24  /* write or read too large for buffers */
#define RTSMB_CLI_SSN_RV_NO_USER              -10  /* no user logged on */
#define RTSMB_CLI_SSN_RV_SMB_ERROR            -50  /* an error occurred on server for a particular smb */
#define RTSMB_CLI_SSN_RV_FILE_NOT_FOUND       -51  /* an error occurred on server for a particular smb */
#define RTSMB_CLI_SSN_RV_BAD_PERMISSIONS      -52  /* an error occurred on server for a particular smb */
#define RTSMB_CLI_SSN_RV_IN_PROGRESS          -101 /* the requested operation is still in progress */
#define RTSMB_CLI_SSN_RV_INVALID_RV           -100 /* this is guaranteed to never be used as an rv value */

typedef void  (RTSMB_FAR *RTSMB_JOB_CALLBACK)(int job, int r, PFVOID data);

typedef struct
{
    /* this whole structure is for internal use only */
    int sid;
    int ssnid;
    int state;
    int domain;
    int backup_server_index;
    byte ip[4];
    byte bip[4];

} RTSMB_CLI_SESSION_SRVSTAT;
typedef RTSMB_CLI_SESSION_SRVSTAT RTSMB_FAR *PRTSMB_CLI_SESSION_SRVSTAT;


/* this struct contains information about a share */
typedef struct
{
    //rtsmb_char name [RTSMB_MAX_SHARENAME_SIZE + 1];
    char name [RTSMB_MAX_SHARENAME_SIZE + 1];

    enum RTSMB_SHARE_TYPE type;

    /* the rest of this structure is for internal use only */
    int sid;

} RTSMB_CLI_SESSION_SSTAT;
typedef RTSMB_CLI_SESSION_SSTAT RTSMB_FAR *PRTSMB_CLI_SESSION_SSTAT;

typedef struct
{
    unsigned short fattributes;

    TIME           fatime64; /* last access time */
    TIME           fwtime64; /* last write time */
    TIME           fctime64; /* last create time */
    TIME           fhtime64; /* last change time */

    unsigned long  fsize;

} RTSMB_CLI_SESSION_FSTAT;
typedef RTSMB_CLI_SESSION_FSTAT RTSMB_FAR *PRTSMB_CLI_SESSION_FSTAT;

typedef struct
{
    char filename [SMBF_FILENAMESIZE * 2 + 2];  /* big enough for unicode */

    char unicode;   /* will be zero if filename is ascii, non-zero if unicode */

    unsigned short fattributes;

    TIME           fatime64; /* last access time */
    TIME           fwtime64; /* last write time */
    TIME           fctime64; /* last create time */
    TIME           fhtime64; /* last change time */

    unsigned long fsize;

    /* the rest of this structure is for internal use only */
    int sid;

} RTSMB_CLI_SESSION_DSTAT;
typedef RTSMB_CLI_SESSION_DSTAT RTSMB_FAR *PRTSMB_CLI_SESSION_DSTAT;


typedef enum
{
    CSSN_DIALECT_PRE_NT,
    CSSN_DIALECT_NT,
#ifdef SUPPORT_SMB2
    CSSN_DIALECT_SMB2_2002,
#endif
} RTSMB_CLI_SESSION_DIALECT;

#ifdef SUPPORT_SMB2
#define RTSMB_ISSMB2_DIALECT(DIALECT) ( (int)DIALECT >= (int)CSSN_DIALECT_SMB2_2002 )
#else
#define RTSMB_ISSMB2_DIALECT(DIALECT) (RTSMB_FALSE)
#endif

int rtsmb_cli_session_resolve_name (PFCHAR name, PFBYTE broadcast_ip, PFBYTE ip);


int rtsmb_cli_session_new_with_name (PFCHAR name, BBOOL blocking, PFBYTE broadcast_ip, PFINT sid, RTSMB_CLI_SESSION_DIALECT dialect);
//The use of this function is not reccomended for compatability with older SMB servers.  The functionality
//it provides is outside of the SMB spec, however newer version of Windows client offer this functionality.
int rtsmb_cli_session_new_with_ip (PFBYTE ip, PFBYTE broadcast_ip, BBOOL blocking, PFINT psid, RTSMB_CLI_SESSION_DIALECT dialect);

void rtsmb_cli_session_close_session (int sid);
int rtsmb_cli_session_restart (int sid);

int rtsmb_cli_session_set_blocking (int sid, BBOOL blocking);

/* These two are only used in non-blocking mode */
int rtsmb_cli_session_cycle (int sid, long timeout);
int rtsmb_cli_session_set_job_callback (int sid, int job, RTSMB_JOB_CALLBACK callback, PFVOID data);


/**
 * Functions to control our resource access on the server.
 */
int rtsmb_cli_session_logon_user_rt (int sid, PFRTCHAR user, PFCHAR password, PFRTCHAR domain);
int rtsmb_cli_session_logoff_user (int sid);
int rtsmb_cli_session_connect_share (int sid, PFCHAR share, PFCHAR password);
int rtsmb_cli_session_disconnect_share (int sid, PFCHAR share);


/**
 * Functions to interact with files on the server.  You will need to be logged in
 * and connected to a share.
 *
 * NOTE: file descriptors are guaranteed to not be larger than 255.
 */
int rtsmb_cli_session_open_rt (int sid, PFCHAR share, PFRTCHAR file, int flags, int mode, PFINT fid);
int rtsmb_cli_session_close (int sid, int fid);
int rtsmb_cli_session_read (int sid, int fid, PFBYTE data, int count, PFINT count_read);
int rtsmb_cli_session_write (int sid, int fid, PFBYTE data, int count, PFINT written);
int rtsmb_cli_session_seek (int sid, int fid, long offset, int location, PFLONG resulting_offset);
int rtsmb_cli_session_truncate (int sid, int fid, long offset);
int rtsmb_cli_session_flush (int sid, int fid);
int rtsmb_cli_session_rename_rt (int sid, PFCHAR share, PFRTCHAR old_filename, PFRTCHAR new_filename);
int rtsmb_cli_session_delete_rt (int sid, PFCHAR share, PFRTCHAR filename);
int rtsmb_cli_session_mkdir_rt (int sid, PFCHAR share, PFRTCHAR filename);
int rtsmb_cli_session_rmdir_rt (int sid, PFCHAR share, PFRTCHAR filename);
int rtsmb_cli_session_find_first_rt (int sid, PFCHAR share, PFRTCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);
int rtsmb_cli_session_find_next (int sid, PRTSMB_CLI_SESSION_DSTAT pdstat);
int rtsmb_cli_session_find_close (int sid, PRTSMB_CLI_SESSION_DSTAT pdstat);
int rtsmb_cli_session_stat_rt (int sid, PFCHAR share, PFRTCHAR file, PRTSMB_CLI_SESSION_FSTAT pstat);
int rtsmb_cli_session_chmode_rt (int sid, PFCHAR share, PFRTCHAR file, int attributes);
int rtsmb_cli_session_get_free (int sid, PFCHAR share, PFINT total_units, PFINT free_units, PFINT blocks_per_unit, PFINT block_size);

/**
 * Functions to get information about the shares available on a particular server.
 * You do not need to be logged in or connected to a share for these.
 */
int rtsmb_cli_session_share_find_first (int sid, PRTSMB_CLI_SESSION_SSTAT pstat);
int rtsmb_cli_session_share_find_next (int sid, PRTSMB_CLI_SESSION_SSTAT pstat);
int rtsmb_cli_session_share_find_close (int sid, PRTSMB_CLI_SESSION_SSTAT pstat);


/**
 * Functions to get information about the servers available on the network.
 * You do not need to be connected to a server for these.
 *
 * The calling semantics are a little weird for this group.  Start off a search with
 * enum_start.  Call enum_cycle until either RTSMB_CLI_SSN_RV_END_OF_SEARCH is returned, indicating
 * there are no more servers, RTSMB_CLI_SSN_RV_SEARCH_DATA_READY is returned, indicating you can
 * start getting names, or another negative number is returned, indicating some error,
 * On a zero, keep cycling.
 *
 * However, once you start getting names from next_name, do so until a RTSMB_CLI_SSN_RV_END_OF_SEARCH
 * is returned.  Once this happens, you need to repeat the cycling process.  Whenever a cycle
 * returns RTSMB_CLI_SSN_RV_END_OF_SEARCH, the search is truly over, and you should close it.  But, when
 * a next_name call returns RTSMB_CLI_SSN_RV_END_OF_SEARCH, it merely means that that group of names
 * is done.
 *
 * You may pass 0 for the ip and broadcast ip for enum_start.  It will then use the global
 * defaults set by rtsmb_net_set_ip.
 */
int rtsmb_cli_session_server_enum_start (PRTSMB_CLI_SESSION_SRVSTAT pstat, PFBYTE ip, PFBYTE bip);
int rtsmb_cli_session_server_enum_cycle (PRTSMB_CLI_SESSION_SRVSTAT pstat, int timeout);
int rtsmb_cli_session_server_enum_next_name (PRTSMB_CLI_SESSION_SRVSTAT pstat, PFCHAR name);
int rtsmb_cli_session_server_enum_next_name_uc (PRTSMB_CLI_SESSION_SRVSTAT pstat, PFWCS name);
int rtsmb_cli_session_server_enum_close (PRTSMB_CLI_SESSION_SRVSTAT pstat);




/**************************************************
 * The rest of this file is for internal use only.*
 * These are not part of the public API.          *
 **************************************************/














int rtsmb_cli_session_full_server_enum (int sid, dword type, PFCHAR domain, PRTSMB_BROWSE_SERVER_INFO answering_infos, int answering_infos_size);



typedef struct RTSMB_CLI_SESSION_T RTSMB_CLI_SESSION;
typedef RTSMB_CLI_SESSION RTSMB_FAR *PRTSMB_CLI_SESSION;

typedef struct RTSMB_CLI_SESSION_JOB_T RTSMB_CLI_SESSION_JOB;
typedef RTSMB_CLI_SESSION_JOB RTSMB_FAR *PRTSMB_CLI_SESSION_JOB;

typedef struct RTSMB_CLI_SESSION_FID_T RTSMB_CLI_SESSION_FID;
typedef RTSMB_CLI_SESSION_FID RTSMB_FAR *PRTSMB_CLI_SESSION_FID;


typedef struct
{
    /* if server is user mode, TRUE.  if server is share mode, FALSE. */
    BBOOL user_mode;

    BBOOL encrypted;

    RTSMB_CLI_SESSION_DIALECT dialect;

    dword capabilities;

    dword buffer_size;
    dword raw_size;
    word vcs;
    word mpx_count;
    dword session_id;

    byte challenge [8];

} RTSMB_CLI_SESSION_SERVER_INFO;
typedef RTSMB_CLI_SESSION_SERVER_INFO RTSMB_FAR *PRTSMB_CLI_SESSION_SERVER_INFO;

typedef enum
{
    CSSN_USER_STATE_UNUSED, /* no user */
    CSSN_USER_STATE_LOGGING_ON, /* user is trying to log on */
    CSSN_USER_STATE_LOGGED_ON,  /* user is logged on */
    CSSN_USER_STATE_DIRTY       /* user needs to be reconnected */
} RTSMB_CLI_SESSION_USER_STATE;

/* this struct contains information about a user */
typedef struct
{
    RTSMB_CLI_SESSION_USER_STATE state;

    word logon_mid;
    word uid;

    rtsmb_char name [CFG_RTSMB_MAX_USERNAME_SIZE + 1];
    char password [CFG_RTSMB_MAX_PASSWORD_SIZE + 1];
    rtsmb_char domain_name [CFG_RTSMB_MAX_DOMAIN_NAME_SIZE + 1];
#ifdef SUPPORT_SMB2
    byte spnego_blob_size;
    byte *spnego_blob;
#endif

} RTSMB_CLI_SESSION_USER;
typedef RTSMB_CLI_SESSION_USER RTSMB_FAR *PRTSMB_CLI_SESSION_USER;

typedef enum
{
    CSSN_SHARE_STATE_UNUSED,    /* no user */
    CSSN_SHARE_STATE_CONNECTING,    /* trying to connect */
    CSSN_SHARE_STATE_CONNECTED, /* share is connected */
    CSSN_SHARE_STATE_DIRTY      /* share needs to be reconnected */
} RTSMB_CLI_SESSION_SHARE_STATE;

/* this struct contains information about a share */
typedef struct
{
    RTSMB_CLI_SESSION_SHARE_STATE state;

    word connect_mid;
    word tid;
    char share_name [RTSMB_MAX_SHARENAME_SIZE + 1];
    char password [CFG_RTSMB_MAX_PASSWORD_SIZE + 1];

} RTSMB_CLI_SESSION_SHARE;
typedef RTSMB_CLI_SESSION_SHARE RTSMB_FAR *PRTSMB_CLI_SESSION_SHARE;

#define CSSN_SRV_SEARCH_STATE_UNUSED        0 /* not used for anything; available */
#define CSSN_SRV_SEARCH_STATE_BACKUP        1 /* need to grab first backup server to query it */
#define CSSN_SRV_SEARCH_STATE_LOGGING_ON    2 /* waiting on reply from our logon */
#define CSSN_SRV_SEARCH_STATE_REQUESTING    3 /* waiting on reply from our server enum request */
#define CSSN_SRV_SEARCH_STATE_DATA_READY    4 /* data is ready to be read */
#define CSSN_SRV_SEARCH_STATE_BACKUP_AGAIN  5 /* need to grab next backup server and query it */
#define CSSN_SRV_SEARCH_STATE_DONE_LOCAL    6 /* just finished reading local cache */
#define CSSN_SRV_SEARCH_STATE_FINISH        7 /* end the search */


typedef struct
{
    int sid;                /* search ID */
    word server_sid;        /* server's sid value */
    byte    SMB2FileId[16]; /* FileId provided by SMB2 Create Request */
    int num_stats;          /* number of dstats stored here */
    int end_of_search;      /* are we done with this search? */
    int index;              /* where we are along the array */
    PRTSMB_CLI_SESSION_DSTAT dstats;

    PRTSMB_CLI_SESSION_SHARE share_struct;  /* share that search is on */

} RTSMB_CLI_SESSION_SEARCH;
typedef RTSMB_CLI_SESSION_SEARCH RTSMB_FAR *PRTSMB_CLI_SESSION_SEARCH;

typedef struct
{
    int sid;    /* search ID */

    int num_stats;      /* number of sstats stored here */
    int index;          /* where we are along the array */
    PRTSMB_CLI_SESSION_SSTAT sstats;

} RTSMB_CLI_SESSION_SHARE_SEARCH;
typedef RTSMB_CLI_SESSION_SHARE_SEARCH RTSMB_FAR *PRTSMB_CLI_SESSION_SHARE_SEARCH;

typedef struct
{
    int session_id;

    int num_stats;      /* number of sstats stored here */
    int index;          /* where we are along the array */
    RTSMB_CHAR16 RTSMB_FAR * srvstats;

    /* some info for when we are finding out the master browsers */
    unsigned long broadcast_timeout_base;

} RTSMB_CLI_SESSION_SERVER_SEARCH;
typedef RTSMB_CLI_SESSION_SERVER_SEARCH RTSMB_FAR *PRTSMB_CLI_SESSION_SERVER_SEARCH;

typedef enum
{
    CSSN_JOB_STATE_UNUSED,  /* no job */
    CSSN_JOB_STATE_FAKE,    /* not a real job, just for internal use */
    CSSN_JOB_STATE_STALLED, /* job is waiting for wire to clear */
    CSSN_JOB_STATE_WAITING, /* job is waiting on SMB server response */
    CSSN_JOB_STATE_DIRTY    /* job is waiting to be restarted */
} RTSMB_CLI_SESSION_JOB_STATE;

typedef struct
{
    char share_name [RTSMB_MAX_SHARENAME_SIZE + 1];
    char password [CFG_RTSMB_MAX_PASSWORD_SIZE + 1];
    PRTSMB_CLI_SESSION_SHARE share_struct;
    PFRTCHAR share_type;
}
RTSMB_CLI_TREE_CONNECT_JOB_DATA;
typedef RTSMB_CLI_TREE_CONNECT_JOB_DATA RTSMB_FAR * PRTSMB_CLI_TREE_CONNECT_JOB_DATA;

#define RTSMB_SHARE_ACCESS_DELETE  0x04
#define RTSMB_SHARE_ACCESS_WRITE   0x02
#define RTSMB_SHARE_ACCESS_READ    0x01

typedef struct
{
    rtsmb_char filename [SMBF_FILENAMESIZE + 1];
    int flags;
    int mode;
    int share_access;
    PRTSMB_CLI_SESSION_SHARE share_struct;

    PFINT returned_fid;
}
RTSMB_CLI_CREATEX_JOB_DATA;
typedef RTSMB_CLI_CREATEX_JOB_DATA RTSMB_FAR * PRTSMB_CLI_CREATEX_JOB_DATA;

typedef struct
{
    long max_data_size;
    PFBYTE data;
    PRTSMB_CLI_SESSION_FID fid_struct;

    PFINT returned_data_size;
}
RTSMB_CLI_READ_JOB_DATA;
typedef RTSMB_CLI_READ_JOB_DATA RTSMB_FAR * PRTSMB_CLI_READ_JOB_DATA;

typedef struct
{
    long total_to_write;
    long written_so_far;
    long bytes_acked;
    PFBYTE data;
    PRTSMB_CLI_SESSION_FID fid_struct;

    PFINT returned_data_size;
}
RTSMB_CLI_WRITEX_JOB_DATA;
typedef RTSMB_CLI_WRITEX_JOB_DATA RTSMB_FAR * PRTSMB_CLI_WRITEX_JOB_DATA;

typedef struct
{
    int fid;
    int operation;
    long (RTSMB_FAR *write_request_params) (PFBYTE origin, PFBYTE buffer, long buf_size,
                                            PFVOID param_data, PFINT status);
    PFVOID request_params;
    long (RTSMB_FAR *read_response_params) (PFBYTE origin, PFBYTE buffer, long buf_size,
                                            PFVOID param_data, PFINT status);
    PFVOID response_params;
    int read_more;
}
RTSMB_CLI_RPC_INVOKE_JOB_DATA;
typedef RTSMB_CLI_RPC_INVOKE_JOB_DATA RTSMB_FAR * PRTSMB_CLI_RPC_INVOKE_JOB_DATA;

/* this struct contains enough information to restart a job */
struct RTSMB_CLI_SESSION_JOB_T
{
    RTSMB_CLI_SESSION_JOB_STATE state;

    word mid;
    int send_count; /* number of times we've tried to send this */
    int die_count; /* number of times we've restarted our connection while servicing this job */

    int response;   /* response to client of us */

    dword error;

    RTSMB_JOB_CALLBACK  callback;
    PFVOID callback_data;

    int (*error_handler) (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);
    int (*send_handler) (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
    int (*receive_handler) (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

#ifdef SUPPORT_SMB2    // Some branching to SMB2 from this file, no major processing
    int (*send_handler_smb2)    (smb2_stream  *psmb2stream);
    int (*error_handler_smb2)   (smb2_stream  *psmb2stream);
    int (*receive_handler_smb2) (smb2_stream  *psmb2stream);
#endif

    union {
        struct {
            PRTSMB_CLI_SESSION_USER user_struct;
            rtsmb_char account_name [CFG_RTSMB_MAX_USERNAME_SIZE + 1];
            char password [CFG_RTSMB_MAX_PASSWORD_SIZE + 1];
            rtsmb_char domain_name [CFG_RTSMB_MAX_DOMAIN_NAME_SIZE + 1];
        } session_setup;

        RTSMB_CLI_TREE_CONNECT_JOB_DATA tree_connect;

        struct {
            word tid;
        } tree_disconnect;

        RTSMB_CLI_READ_JOB_DATA read;

        RTSMB_CLI_WRITEX_JOB_DATA writex;

        struct {
            rtsmb_char filename [SMBF_FILENAMESIZE + 1];
            int flags;
            int mode;
            PRTSMB_CLI_SESSION_SHARE share_struct;

            PFINT returned_fid;
        } open;

        struct {

            PRTSMB_CLI_SESSION_FID fid_struct;

        } close;

        struct {

            PRTSMB_CLI_SESSION_FID fid_struct;
            long offset;
            int mode;

            PFLONG resulting_offset;

        } seek;

        struct {

            PRTSMB_CLI_SESSION_FID fid_struct;
            long offset;

        } truncate;

        struct {

            PRTSMB_CLI_SESSION_FID fid_struct;

        } flush;

        struct {

            PRTSMB_CLI_SESSION_SHARE share_struct;
            rtsmb_char old_filename [SMBF_FILENAMESIZE + 1];
            rtsmb_char new_filename [SMBF_FILENAMESIZE + 1];

        } rename;

        struct {

            PRTSMB_CLI_SESSION_SHARE share_struct;
            rtsmb_char filename [SMBF_FILENAMESIZE + 1];

        } delete;

        struct {

            PRTSMB_CLI_SESSION_SHARE share_struct;
            rtsmb_char filename [SMBF_FILENAMESIZE + 1];

        } mkdir;

        struct {

            PRTSMB_CLI_SESSION_SHARE share_struct;
            rtsmb_char filename [SMBF_FILENAMESIZE + 1];

        } rmdir;

        struct {

            PRTSMB_CLI_SESSION_SEARCH search_struct;
            rtsmb_char pattern [SMBF_FILENAMESIZE + 1];
            PRTSMB_CLI_SESSION_DSTAT answering_dstat;

        } findfirst;

        struct {

            PRTSMB_CLI_SESSION_SEARCH search_struct;
            PRTSMB_CLI_SESSION_DSTAT answering_dstat;

        } findnext;

        struct {

            PRTSMB_CLI_SESSION_SEARCH search_struct;

        } findclose;

        struct {

            PRTSMB_CLI_SESSION_SHARE share_struct;
            rtsmb_char filename [SMBF_FILENAMESIZE + 1];
            PRTSMB_CLI_SESSION_FSTAT answering_stat;

        } stat;

        struct {

            PRTSMB_CLI_SESSION_SHARE_SEARCH search_struct;
            PRTSMB_CLI_SESSION_SSTAT answering_sstat;

        } sharefindfirst;

        struct {

            PRTSMB_CLI_SESSION_SERVER_SEARCH search_struct;

        } serverfind;

        struct {

            PRTSMB_CLI_SESSION_SHARE share_struct;
            rtsmb_char filename [SMBF_FILENAMESIZE + 1];
            int attributes;

        } chmode;

        struct {
            PRTSMB_CLI_SESSION_SHARE share_struct;
            rtsmb_char filename [SMBF_FILENAMESIZE + 1];
            TIME atime;
            TIME wtime;
            TIME ctime;
            TIME htime;
        } setfiletime;

        struct {

            PRTSMB_CLI_SESSION_SHARE share_struct;
            PFINT answering_total_units;
            PFINT answering_free_units;
            PFINT answering_blocks_per_unit;
            PFINT answering_block_size;

        } getfree;

        struct {

            BBOOL valid_domain;
            rtsmb_char domain [RTSMB_NB_NAME_SIZE + 1];
            dword type;

            PRTSMB_BROWSE_SERVER_INFO answering_infos;
            long answering_infos_size;

        } full_server_enum;

        struct {

            int state;
            int fid;
            PFINT returned_fid;
            int bytes_processed;

#define RTSMB_RPC_OPEN_STATE_INIT                  0
#define RTSMB_RPC_OPEN_STATE_TREE_CONNECT          1
#define RTSMB_RPC_OPEN_STATE_TREE_CONNECT_ERROR   -1
#define RTSMB_RPC_OPEN_STATE_CREATE_PIPE           2
#define RTSMB_RPC_OPEN_STATE_CREATE_PIPE_ERROR    -2
#define RTSMB_RPC_OPEN_STATE_WRITE_BIND            3
#define RTSMB_RPC_OPEN_STATE_WRITE_BIND_ERROR     -3
#define RTSMB_RPC_OPEN_STATE_READ_BIND_ACK         4
#define RTSMB_RPC_OPEN_STATE_READ_BIND_ACK_ERROR  -4
#define RTSMB_RPC_OPEN_STATE_DONE                  5
#define RTSMB_RPC_OPEN_STATE_ERROR                -5

            rtsmb_char pipe_name [SMBF_FILENAMESIZE + 1];
            PRTSMB_RPC_IFACE_INFO iface_info;

            union {

                RTSMB_CLI_TREE_CONNECT_JOB_DATA  tree_connect;
                RTSMB_CLI_CREATEX_JOB_DATA       create;
                RTSMB_CLI_WRITEX_JOB_DATA        write;
                RTSMB_CLI_READ_JOB_DATA          read;

            } subjob;

            PFBYTE buffer;

        } rpc_open;

        RTSMB_CLI_RPC_INVOKE_JOB_DATA rpc_invoke;

    } data;

};

#define CSSN_FID_STATE_UNUSED -1
#define CSSN_FID_STATE_DIRTY  -2

/* this struct contains information about a fid */
struct RTSMB_CLI_SESSION_FID_T
{
    int real_fid;   /* -1 means not in use */
    word smb_fid;

    dword offset;   /* we keep our own count of where we are in the file */
    PRTSMB_CLI_SESSION_SHARE owning_share;

    int flags;
    int mode;
    rtsmb_char name [SMBF_FILENAMESIZE + 1];
};


typedef enum
{
    CSSN_STATE_UNUSED,                   /* absolutely free to be used by someone */
    CSSN_STATE_DEAD,                     /* untenable, but needs to be free'd */
    CSSN_STATE_QUERYING,                 /* in the process of finding server by name */
    CSSN_STATE_CONNECTING,               /* we know the name/address mapping, and are connecting */
    CSSN_STATE_UNCONNECTED,              /* haven't yet formed a session */
    CSSN_STATE_NEGOTIATED,               /* we've started a full session and are go */
    CSSN_STATE_RECOVERY_QUERYING,        /* we're trying to recover from a bad connection */
    CSSN_STATE_RECOVERY_NEGOTIATING,     /* we're trying to recover from a bad connection */
    CSSN_STATE_RECOVERY_NEGOTIATED,      /* we're trying to recover from a bad connection */
    CSSN_STATE_RECOVERY_LOGGING_ON,      /* we're trying to recover from a bad connection */
    CSSN_STATE_RECOVERY_LOGGED_ON,       /* we're trying to recover from a bad connection */
    CSSN_STATE_RECOVERY_TREE_CONNECTING, /* we're trying to recover from a bad connection */
    CSSN_STATE_RECOVERY_TREE_CONNECTED,  /* we're trying to recover from a bad connection */
    CSSN_STATE_RECOVERY_FILE_OPENING,    /* we're trying to recover from a bad connection */
    CSSN_STATE_RECOVERY_FILE_OPENED      /* we're trying to recover from a bad connection */
} RTSMB_CLI_SESSION_STATE;



struct RTSMB_CLI_SESSION_T
{
    RTP_SOCKET broadcast_socket;    /* used when finding a server by name */
    byte broadcast_ip [4];      /* used when finding a server by name */
    unsigned long broadcast_timeout_base; /* used when finding a server by name */
    int broadcast_attempts; /* used when finding a server by name */

    byte server_ip [4];
    char server_name [RTSMB_NB_NAME_SIZE + 1];
    BBOOL blocking_mode;

    unsigned int owning_thread; /* id for thread that started us */
    unsigned long timestamp; /* tells how long it's been since the session has been used */

    RTSMB_CLI_WIRE_SESSION wire;

    RTSMB_CLI_SESSION_STATE state;

    RTSMB_CLI_SESSION_SERVER_INFO server_info;

    RTSMB_CLI_SESSION_USER user;
    RTSMB_CLI_SESSION_USER anon;    /* an anonymous user we have as a fallback */

    PRTSMB_CLI_SESSION_JOB jobs;

    PRTSMB_CLI_SESSION_SHARE shares;

    PRTSMB_CLI_SESSION_FID fids;

    PRTSMB_CLI_SESSION_SEARCH searches;

    RTSMB_CLI_SESSION_SHARE_SEARCH share_search;

    struct Rtsmb2ClientSession_s   *psmb2Session;   // Points to the smb2 session structure. Initialized in rtsmb_cli_smb2_session_init()
};

/* session related */
void                     rtsmb_cli_session_update_timestamp (PRTSMB_CLI_SESSION pSession);
PRTSMB_CLI_SESSION       rtsmb_cli_session_get_session (int i);
void                     rtsmb_cli_session_fill_header (PRTSMB_CLI_SESSION pSession, PRTSMB_HEADER pHeader);

/* share related */
PRTSMB_CLI_SESSION_SHARE rtsmb_cli_session_get_share (PRTSMB_CLI_SESSION pSession, PFCHAR share);
PRTSMB_CLI_SESSION_SHARE rtsmb_cli_session_get_free_share (PRTSMB_CLI_SESSION pSession);
void                     rtsmb_cli_session_share_close (PRTSMB_CLI_SESSION_SHARE pShare);

/* job related */
PRTSMB_CLI_SESSION_JOB   rtsmb_cli_session_get_free_job (PRTSMB_CLI_SESSION pSession);
void                     rtsmb_cli_session_send_stalled_jobs (PRTSMB_CLI_SESSION pSession);
int                      rtsmb_cli_session_wait_for_job (PRTSMB_CLI_SESSION pSession, int job);

/* fid related */
PRTSMB_CLI_SESSION_FID   rtsmb_cli_session_get_fid (PRTSMB_CLI_SESSION pSession, int fid);

/* send/receive/error handlers for various job types */
int rtsmb_cli_session_send_tree_connect_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_CLI_TREE_CONNECT_JOB_DATA info);

int rtsmb_cli_session_send_tree_connect_job_error_handler (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader,
        PRTSMB_CLI_TREE_CONNECT_JOB_DATA info);

int rtsmb_cli_session_receive_tree_connect_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader,
        PRTSMB_CLI_TREE_CONNECT_JOB_DATA info);

int rtsmb_cli_session_send_create_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_CLI_CREATEX_JOB_DATA info);

int rtsmb_cli_session_receive_create_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader,
        PRTSMB_CLI_CREATEX_JOB_DATA info);

int rtsmb_cli_session_send_write_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_CLI_WRITEX_JOB_DATA info);

int rtsmb_cli_session_receive_write_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader,
        PRTSMB_CLI_WRITEX_JOB_DATA info);

int rtsmb_cli_session_send_read_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_CLI_READ_JOB_DATA info);

int rtsmb_cli_session_receive_read_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader,
        PRTSMB_CLI_READ_JOB_DATA info);

#endif /* INCLUDE_RTSMB_CLIENT */

#endif /* __CLI_SSN_H__ */
