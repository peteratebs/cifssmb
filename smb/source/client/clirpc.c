/*
|  CLIRPC.C -
|
|  EBSnet - RTSMB embedded SMB/CIFS client and server
|
|   $Author: vmalaiya $
|   $Date: 2006/06/02 19:53:12 $
|   $Name:  $
|   $Revision: 1.1 $
|
|  Copyright EBS Inc. , 2005
|  All rights reserved.
|  This code may not be redistributed in source or linkable object form
|  without the consent of its author.
*/

/*****************************************************************************/
/* Header files
 *****************************************************************************/

#include "smbdefs.h"
#include "clirpc.h"
#include "cliapi.h"
#include "smbutil.h"
#include "rtpwcs.h"
#include "clicfg.h"
#include "smbpack.h"

/*****************************************************************************/
/* Macros
 *****************************************************************************/

#define RTSMB_DCE_RPC_HEADER_LEN     16

#define RTSMB_DCE_RPC_TYPE_REQUEST   0
#define RTSMB_DCE_RPC_TYPE_RESPONSE  1
#define RTSMB_DCE_RPC_TYPE_BIND      11
#define RTSMB_DCE_RPC_TYPE_BIND_ACK  12

#define RTSMB_DCE_RPC_FLAG_OBJECT    0x80
#define RTSMB_DCE_RPC_FLAG_MAYBE     0x40
#define RTSMB_DCE_RPC_FLAG_NOEXECUTE 0x20
#define RTSMB_DCE_RPC_FLAG_MULTIPLEX 0x10
#define RTSMB_DCE_RPC_FLAG_RESERVED  0x08
#define RTSMB_DCE_RPC_FLAG_CANCEL    0x04
#define RTSMB_DCE_RPC_FLAG_LAST      0x02
#define RTSMB_DCE_RPC_FLAG_FIRST     0x01

#define RTSMB_DCE_RPC_ENDIAN_MASK    0xf0
#define RTSMB_DCE_RPC_BIG_ENDIAN     0x00
#define RTSMB_DCE_RPC_LITTLE_ENDIAN  0x10

#define RTSMB_DCE_RPC_CHARSET_MASK   0x0f
#define RTSMB_DCE_RPC_CHARSET_ASCII  0

#define RTSMB_DCE_RPC_FP_MASK        0
#define RTSMB_DCE_RPC_FP_IEEE        0

/*****************************************************************************/
/* Types
 *****************************************************************************/

/*****************************************************************************/
/* Function Prototypes
 *****************************************************************************/

RTSMB_STATIC long _rtsmb_cli_rpc_write_dce_header (PFBYTE buffer, int packet_type, int length);
RTSMB_STATIC long _rtsmb_cli_rpc_write_bind (PFBYTE buffer, PRTSMB_RPC_IFACE_INFO info);
RTSMB_STATIC long _rtsmb_cli_rpc_read_bind_ack (PFBYTE buffer, PRTSMB_RPC_IFACE_INFO info, PFINT result);
RTSMB_STATIC long _rtsmb_cli_rpc_read_dce_header (PFBYTE buffer, PFINT packet_type, PFINT data_rep, PFINT fp_rep, PFINT len, PFINT is_last);
RTSMB_STATIC int _rtsmb_cli_rpc_open_send_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int _rtsmb_cli_rpc_open_error_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);
RTSMB_STATIC int _rtsmb_cli_rpc_open_receive_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

RTSMB_STATIC int rtsmb_cli_session_send_rpc_request (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
RTSMB_STATIC int rtsmb_cli_session_receive_rpc_response (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);

int cli_cmd_fill_dce_rpc (PFVOID origin, PFVOID buf, rtsmb_size size,
    PRTSMB_HEADER pHeader, PRTSMB_CLI_RPC_INVOKE_JOB_DATA pRPC);

int cli_cmd_read_dce_rpc (PFVOID origin, PFVOID buf, rtsmb_size size,
    PRTSMB_HEADER pHeader, PRTSMB_CLI_RPC_INVOKE_JOB_DATA pRPC);

/*****************************************************************************/
/* Data
 *****************************************************************************/

rtsmb_char ipc_share_type [] = {'I', 'P', 'C', '\0'};
char       ipc_share_name [] = {'I', 'P', 'C', '$', '\0'};
rtsmb_char name_pipe      [] = {'\\', 'P', 'I', 'P', 'E', '\\', '\0'};

/*****************************************************************************/
/* Function Definitions
 *****************************************************************************/

/*---------------------------------------------------------------------------*/
int rtsmb_cli_rpc_open_interface (int session_id, PFRTCHAR pipe_name,
                                  PRTSMB_RPC_IFACE_INFO info, PFINT fid,
                                  PFBYTE buffer)
{
    /* This function must create a job that performs the following actions:
         1. Perform a tree connect to the IPC$ share
         2. Perform a create operation to open a new named pipe
         3. Write a DCE RPC bind packet to the newly created pipe
         4. Read the bind_ack packet from the pipe
     */
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION_SHARE pShare;
    PRTSMB_CLI_SESSION pSession;
    int initial_state = RTSMB_RPC_OPEN_STATE_INIT;

    pSession = rtsmb_cli_session_get_session (session_id);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    /* First, see if we alread are connected */
    pShare = rtsmb_cli_session_get_share (pSession, ipc_share_name);
    if (pShare && pShare->state != CSSN_SHARE_STATE_DIRTY)
    {
        initial_state = RTSMB_RPC_OPEN_STATE_CREATE_PIPE;
    }

    if (!pShare)
    {
        /* find free share */
        pShare = rtsmb_cli_session_get_free_share (pSession);
        ASSURE (pShare, RTSMB_CLI_SSN_RV_TOO_MANY_SHARES);
    }

    pJob = rtsmb_cli_session_get_free_job (pSession);
    if (!pJob)
    {
        rtsmb_cli_session_share_close (pShare);
        return RTSMB_CLI_SSN_RV_TOO_MANY_JOBS;
    }

    rtsmb_cpy(pJob->data.rpc_open.pipe_name, pipe_name);
    pJob->data.rpc_open.pipe_name[SMBF_FILENAMESIZE] = 0;
    pJob->data.rpc_open.state = initial_state;
    pJob->data.rpc_open.buffer = buffer;
    pJob->data.rpc_open.iface_info = info;
    pJob->data.rpc_open.returned_fid = fid;

    /* set up for the first sub-job, tree connect to IPC$ */
    pJob->data.rpc_open.subjob.tree_connect.share_type = ipc_share_type;
    pJob->data.rpc_open.subjob.tree_connect.share_struct = pShare;
    rtp_strcpy (pJob->data.rpc_open.subjob.tree_connect.share_name, ipc_share_name);
    rtp_memset (pJob->data.rpc_open.subjob.tree_connect.password, 0, sizeof(pJob->data.tree_connect.password));

    /* set event handlers - tbd consolidate these into a job class spec */
    pJob->send_handler = _rtsmb_cli_rpc_open_send_handler;
    pJob->error_handler = _rtsmb_cli_rpc_open_error_handler;
    pJob->receive_handler = _rtsmb_cli_rpc_open_receive_handler;

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        return rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
    }

    return INDEX_OF (pSession->jobs, pJob);
}

/*---------------------------------------------------------------------------*/
int rtsmb_cli_rpc_close_interface (int session_id, int fid)
{
    /* closing an RPC pipe is equivalent to closing a file */
    return rtsmb_cli_session_close (session_id, fid);
}

/*---------------------------------------------------------------------------*/
int rtsmb_cli_rpc_invoke (
        int session_id,
        int fid,
        int operation,
        long (RTSMB_FAR *write_request_params) (PFBYTE origin, PFBYTE buffer, long buf_size,
                                                PFVOID param_data, PFINT status),
        PFVOID request_params,
        long (RTSMB_FAR *read_response_params) (PFBYTE origin, PFBYTE buffer, long buf_size,
                                                PFVOID param_data, PFINT status),
        PFVOID response_params)
{
    PRTSMB_CLI_SESSION_FID pFid;
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    pSession = rtsmb_cli_session_get_session (session_id);
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

    pJob->data.rpc_invoke.fid = pFid->smb_fid;
    pJob->data.rpc_invoke.operation = operation;
    pJob->data.rpc_invoke.write_request_params = write_request_params;
    pJob->data.rpc_invoke.request_params = request_params;
    pJob->data.rpc_invoke.read_response_params = read_response_params;
    pJob->data.rpc_invoke.response_params = response_params;
    pJob->data.rpc_invoke.read_more = 0;
    //pJob->data.rpc_invoke.first_read_andx = 1;

    pJob->send_handler = rtsmb_cli_session_send_rpc_request;
    pJob->receive_handler = rtsmb_cli_session_receive_rpc_response;

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

/*---------------------------------------------------------------------------*/
RTSMB_STATIC
int _rtsmb_cli_rpc_open_send_handler (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob)
{
    int r;

    switch (pJob->data.rpc_open.state)
    {
        default:
        case RTSMB_RPC_OPEN_STATE_ERROR:
        case RTSMB_RPC_OPEN_STATE_READ_BIND_ACK_ERROR:
        case RTSMB_RPC_OPEN_STATE_WRITE_BIND_ERROR:
        case RTSMB_RPC_OPEN_STATE_CREATE_PIPE_ERROR:
        case RTSMB_RPC_OPEN_STATE_TREE_CONNECT_ERROR:
            break;

        case RTSMB_RPC_OPEN_STATE_INIT:
        case RTSMB_RPC_OPEN_STATE_TREE_CONNECT:
            // send tree connect command
            //  set state to tree connect

            r = rtsmb_cli_session_send_tree_connect_job (pSession, pJob,
                    &pJob->data.rpc_open.subjob.tree_connect);

            if (r == RTSMB_CLI_SSN_RV_OK)
            {
                pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_TREE_CONNECT;
            }
            else
            {
                pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_TREE_CONNECT_ERROR;
                return r;
            }

            break;

        case RTSMB_RPC_OPEN_STATE_CREATE_PIPE:
            // send create and x command to create the named pipe
            // must be first member set (since subjob is a union)
            pJob->data.rpc_open.subjob.create.share_struct = pJob->data.rpc_open.subjob.tree_connect.share_struct;
            rtsmb_cpy(pJob->data.rpc_open.subjob.create.filename, pJob->data.rpc_open.pipe_name);
            pJob->data.rpc_open.subjob.create.flags = RTP_FILE_O_APPEND|RTP_FILE_O_RDWR;
            pJob->data.rpc_open.subjob.create.mode = RTP_FILE_S_IWRITE|RTP_FILE_S_IREAD;
            pJob->data.rpc_open.subjob.create.share_access = RTSMB_SHARE_ACCESS_READ | RTSMB_SHARE_ACCESS_WRITE;
            pJob->data.rpc_open.subjob.create.returned_fid = &pJob->data.rpc_open.fid;

            r = rtsmb_cli_session_send_create_job (pSession, pJob,
                    &pJob->data.rpc_open.subjob.create);

            if (r != RTSMB_CLI_SSN_RV_OK)
            {
                pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_CREATE_PIPE_ERROR;
                return r;
            }

            break;

        case RTSMB_RPC_OPEN_STATE_WRITE_BIND:
            // send write and x command to bind the pipe to an interface
            pJob->data.rpc_open.subjob.write.fid_struct = rtsmb_cli_session_get_fid (pSession,
                    pJob->data.rpc_open.fid);

            if (!pJob->data.rpc_open.subjob.write.fid_struct)
            {
                pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_WRITE_BIND_ERROR;
                return RTSMB_CLI_SSN_RV_TOO_MANY_FIDS;
            }

            pJob->data.rpc_open.subjob.write.data = pJob->data.rpc_open.buffer;
            pJob->data.rpc_open.subjob.write.total_to_write = _rtsmb_cli_rpc_write_bind (
                    pJob->data.rpc_open.buffer,
                    pJob->data.rpc_open.iface_info);

            pJob->data.rpc_open.subjob.write.bytes_acked = 0;
            pJob->data.rpc_open.subjob.write.written_so_far = 0;
            pJob->data.rpc_open.subjob.write.returned_data_size = &pJob->data.rpc_open.bytes_processed;

            r = rtsmb_cli_session_send_write_job (pSession, pJob,
                    &pJob->data.rpc_open.subjob.write);

            if (r != RTSMB_CLI_SSN_RV_OK)
            {
                pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_WRITE_BIND_ERROR;
                return r;
            }

            break;

        case RTSMB_RPC_OPEN_STATE_READ_BIND_ACK:
            // send read and x command to read the bind_ack from the pipe
            // send write and x command to bind the pipe to an interface
            pJob->data.rpc_open.subjob.read.fid_struct = pJob->data.rpc_open.subjob.write.fid_struct;

            pJob->data.rpc_open.subjob.read.data = pJob->data.rpc_open.buffer;
            pJob->data.rpc_open.subjob.write.total_to_write = _rtsmb_cli_rpc_write_bind (
                    pJob->data.rpc_open.buffer,
                    pJob->data.rpc_open.iface_info);

            pJob->data.rpc_open.subjob.read.max_data_size = RTSMB_RPC_INIT_BUFFER_SIZE;
            pJob->data.rpc_open.subjob.read.returned_data_size = &pJob->data.rpc_open.bytes_processed;

            r = rtsmb_cli_session_send_read_job (pSession, pJob, &pJob->data.rpc_open.subjob.read);
            if (r != RTSMB_CLI_SSN_RV_OK)
            {
                pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_READ_BIND_ACK_ERROR;
                return r;
            }
            break;

        case RTSMB_RPC_OPEN_STATE_DONE:
            // nothing to send here!
            break;
    }

    return RTSMB_CLI_SSN_RV_OK;
}

/*---------------------------------------------------------------------------*/
RTSMB_STATIC
int _rtsmb_cli_rpc_open_error_handler (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader)
{
    switch (pJob->data.rpc_open.state)
    {
        default:
        case RTSMB_RPC_OPEN_STATE_ERROR:
        case RTSMB_RPC_OPEN_STATE_READ_BIND_ACK_ERROR:
        case RTSMB_RPC_OPEN_STATE_WRITE_BIND_ERROR:
        case RTSMB_RPC_OPEN_STATE_CREATE_PIPE_ERROR:
        case RTSMB_RPC_OPEN_STATE_TREE_CONNECT_ERROR:
            break;

        case RTSMB_RPC_OPEN_STATE_INIT:
            pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_ERROR;
            break;

        case RTSMB_RPC_OPEN_STATE_TREE_CONNECT:
            pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_TREE_CONNECT_ERROR;
            break;

        case RTSMB_RPC_OPEN_STATE_CREATE_PIPE:
            pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_CREATE_PIPE_ERROR;
            break;

        case RTSMB_RPC_OPEN_STATE_WRITE_BIND:
            pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_WRITE_BIND_ERROR;
            break;

        case RTSMB_RPC_OPEN_STATE_READ_BIND_ACK:
            pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_READ_BIND_ACK_ERROR;
            break;

        case RTSMB_RPC_OPEN_STATE_DONE:
            pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_ERROR;
            break;
    }

    return RTSMB_CLI_SSN_RV_OK;
}

/*---------------------------------------------------------------------------*/
RTSMB_STATIC
int _rtsmb_cli_rpc_open_receive_handler (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader)
{
    int r;

    switch (pJob->data.rpc_open.state)
    {
        default:
        case RTSMB_RPC_OPEN_STATE_ERROR:
        case RTSMB_RPC_OPEN_STATE_READ_BIND_ACK_ERROR:
        case RTSMB_RPC_OPEN_STATE_WRITE_BIND_ERROR:
        case RTSMB_RPC_OPEN_STATE_CREATE_PIPE_ERROR:
        case RTSMB_RPC_OPEN_STATE_TREE_CONNECT_ERROR:
            break;

        case RTSMB_RPC_OPEN_STATE_INIT:
            // if we are receiving, we should be in some other state!
            break;

        case RTSMB_RPC_OPEN_STATE_TREE_CONNECT:
            // tree connect completed; set state to create pipe and
            //  set job state to stalled
            break;

        case RTSMB_RPC_OPEN_STATE_CREATE_PIPE:
            // create and x completed; check the result... if ok,
            //  set rpc open state to RTSMB_RPC_OPEN_STATE_WRITE_BIND and
            //  set job state to stalled
            r =  rtsmb_cli_session_receive_create_job (pSession, pJob,  pHeader,
                    &pJob->data.rpc_open.subjob.create);

            if (r != RTSMB_CLI_SSN_RV_OK)
            {
                pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_CREATE_PIPE_ERROR;
                return r;
            }

            pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_WRITE_BIND;
            pJob->state = CSSN_JOB_STATE_STALLED;
            break;

        case RTSMB_RPC_OPEN_STATE_WRITE_BIND:
            // write and x completed; set state to read bind_ack and
            //  set job state to stalled
            r = rtsmb_cli_session_receive_write_job (pSession, pJob, pHeader,
                    &pJob->data.rpc_open.subjob.write);

            if (r != RTSMB_CLI_SSN_RV_OK ||
                pJob->data.rpc_open.bytes_processed < pJob->data.rpc_open.subjob.write.total_to_write)
            {
                pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_WRITE_BIND_ERROR;
                return r;
            }

            pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_READ_BIND_ACK;
            pJob->state = CSSN_JOB_STATE_STALLED;
            break;

        case RTSMB_RPC_OPEN_STATE_READ_BIND_ACK:
            // read response; if successful, then RPC pipe is open!
            //  set state to done
            r = rtsmb_cli_session_receive_read_job (pSession, pJob, pHeader,
                    &pJob->data.rpc_open.subjob.read);

            if (r != RTSMB_CLI_SSN_RV_OK || pJob->data.rpc_open.bytes_processed <= 0)
            {
                pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_READ_BIND_ACK_ERROR;
                return r;
            }

            if (_rtsmb_cli_rpc_read_bind_ack (pJob->data.rpc_open.buffer, pJob->data.rpc_open.iface_info, &r) <= 0 ||
                r != 0) // tbd - correct value for success?
            {
                pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_READ_BIND_ACK_ERROR;
                return RTSMB_CLI_SSN_RV_MALFORMED;
            }

            /* the pipe is open and bound to the desired interface! */
            pJob->data.rpc_open.state = RTSMB_RPC_OPEN_STATE_DONE;
            if (pJob->data.rpc_open.returned_fid)
            {
                *pJob->data.rpc_open.returned_fid = pJob->data.rpc_open.fid;
            }
            break;

        case RTSMB_RPC_OPEN_STATE_DONE:
            break;
    }

    return RTSMB_CLI_SSN_RV_OK;
}


/*---------------------------------------------------------------------------*/
RTSMB_STATIC
long _rtsmb_cli_rpc_write_bind (PFBYTE buffer, PRTSMB_RPC_IFACE_INFO info)
{
    PFBYTE start = buffer;

    buffer += _rtsmb_cli_rpc_write_dce_header(buffer, RTSMB_DCE_RPC_TYPE_BIND, 72);

    WRITE_UINT16_INTEL(buffer, RTSMB_CLI_SESSION_MAX_DATA_BYTES-96); // max xmit length
    WRITE_UINT16_INTEL(buffer, RTSMB_CLI_SESSION_MAX_DATA_BYTES-96); // max recv length
    WRITE_UINT32_INTEL(buffer, 0); // assoc group?
    WRITE_UINT8_INTEL(buffer, 1); // num ctx items
    WRITE_PADDING(buffer, 2, 0, start);  // pad with 0's up to the 2^2 byte boundary

    WRITE_UINT16_INTEL(buffer, 0); // context id
    WRITE_UINT16_INTEL(buffer, 1); // num trans items

    // write interface uuid (bytes need to be written in this strange order)
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[3]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[2]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[1]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[0]);

    WRITE_UINT8_INTEL(buffer, info->iface_uuid[5]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[4]);

    WRITE_UINT8_INTEL(buffer, info->iface_uuid[7]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[6]);

    WRITE_UINT8_INTEL(buffer, info->iface_uuid[8]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[9]);

    WRITE_UINT8_INTEL(buffer, info->iface_uuid[10]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[11]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[12]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[13]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[14]);
    WRITE_UINT8_INTEL(buffer, info->iface_uuid[15]);

    WRITE_UINT16_INTEL(buffer, info->iface_major_version);
    WRITE_UINT16_INTEL(buffer, info->iface_minor_version);

    // write transfer_syntax_uuid (bytes need to be written in this strange order)
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[3]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[2]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[1]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[0]);

    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[5]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[4]);

    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[7]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[6]);

    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[8]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[9]);

    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[10]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[11]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[12]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[13]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[14]);
    WRITE_UINT8_INTEL(buffer, info->transfer_syntax_uuid[15]);

    WRITE_UINT32_INTEL(buffer, info->transfer_syntax_version);

    return (long) PDIFF(buffer, start);
}

/*---------------------------------------------------------------------------*/
RTSMB_STATIC
long _rtsmb_cli_rpc_write_dce_header (PFBYTE buffer, int packet_type, int length)
{
    PFBYTE start = buffer;

    WRITE_UINT8_INTEL(buffer, 5);           // major version
    WRITE_UINT8_INTEL(buffer, 0);           // minor version
    WRITE_UINT8_INTEL(buffer, packet_type); // packet type
    WRITE_UINT8_INTEL(buffer, RTSMB_DCE_RPC_FLAG_FIRST|RTSMB_DCE_RPC_FLAG_LAST); // flags
    WRITE_UINT8_INTEL(buffer, RTSMB_DCE_RPC_LITTLE_ENDIAN|RTSMB_DCE_RPC_CHARSET_ASCII); // data representation
    WRITE_UINT8_INTEL(buffer, RTSMB_DCE_RPC_FP_IEEE); // floating point format
    WRITE_UINT16_INTEL(buffer, 0); // reserved?
    WRITE_UINT16_INTEL(buffer, length);
    WRITE_UINT16_INTEL(buffer, 0); // auth length
    WRITE_UINT32_INTEL(buffer, 1); // call id

    return (long) PDIFF(buffer, start);
}

/*---------------------------------------------------------------------------*/
RTSMB_STATIC
long _rtsmb_cli_rpc_read_bind_ack (PFBYTE buffer, PRTSMB_RPC_IFACE_INFO info, PFINT result)
{
    int type;
    int i;
    int last;
    long r;
    PFBYTE start = buffer;

    r = _rtsmb_cli_rpc_read_dce_header(buffer, &type, 0, 0, 0, &last);
    if (r < 0 || type != RTSMB_DCE_RPC_TYPE_BIND_ACK || !last)
    {
        return -1;
    }

    buffer += r;

    SKIP_UINT16(buffer); // max xmit length
    SKIP_UINT16(buffer); // max recv length
    SKIP_UINT32(buffer); // assoc group?
    i = READ_UINT16_INTEL(buffer); // secondary address length

    i = (i + 1) & ~1;
    while (i > 0)
    {
        SKIP_UINT8(buffer);
        i--;
    }

    i = READ_UINT8(buffer);
    if (i != 1)
    {
        return -1;
    }

    READ_PADDING(buffer, 2, start);

    if (result)
    {
        *result = READ_UINT16_INTEL(buffer);
    }
    else
    {
        SKIP_UINT16(buffer);
    }

    READ_PADDING(buffer, 2, start);

    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[3], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[2], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[1], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[0], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[5], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[4], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[7], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[6], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[8], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[9], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[10], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[11], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[12], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[13], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[14], -1);
    ASSURE(READ_UINT8(buffer)==info->transfer_syntax_uuid[15], -1);
    ASSURE(READ_UINT32_INTEL(buffer)==info->transfer_syntax_version, -1);

    return (long) PDIFF(buffer, start);
}

/*---------------------------------------------------------------------------*/
RTSMB_STATIC
long _rtsmb_cli_rpc_read_dce_header (PFBYTE buffer, PFINT packet_type, PFINT data_rep, PFINT fp_rep, PFINT len, PFINT is_last)
{
    PFBYTE start = buffer;
    RTSMB_UINT8 flags;

    if (READ_UINT8(buffer) < 5) // major version
    {
        return -1;
    }

    SKIP_UINT8(buffer); // minor version
    if (packet_type)
    {
        *packet_type = READ_UINT8(buffer);
    }
    else
    {
        SKIP_UINT8(buffer);
    }

    flags = (byte)READ_UINT8(buffer);
    if (is_last)
    {
        *is_last = (flags & RTSMB_DCE_RPC_FLAG_LAST)? 1 : 0;
    }

    if (data_rep)
    {
        *data_rep = READ_UINT8(buffer);
    }
    else
    {
        SKIP_UINT8(buffer);
    }

    if (fp_rep)
    {
        *fp_rep = READ_UINT8(buffer);
    }
    else
    {
        SKIP_UINT8(buffer);
    }

    SKIP_UINT16(buffer);

    if (len)
    {
        *len = READ_UINT16_INTEL(buffer);
    }
    else
    {
        SKIP_UINT16(buffer);
    }

    SKIP_UINT16(buffer); // auth length
    SKIP_UINT32(buffer); // call ID

    return (long) PDIFF(buffer, start);
}

/*---------------------------------------------------------------------------*/
RTSMB_STATIC
int rtsmb_cli_session_send_rpc_request_job (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_CLI_RPC_INVOKE_JOB_DATA job_data)
{
    PRTSMB_CLI_SESSION_SHARE pShare;
    RTSMB_HEADER h;
    //PRTSMB_CLI_WIRE_BUFFER pBuffer;
    int r;
    //int data_start, data_end;

    RTSMB_UINT16 setup_params [2] = { 0x0026 /* Function: TransactNmPipe */, (RTSMB_UINT16) job_data->fid };

    /* set up header */
    if (!pJob->data.rpc_invoke.read_more)
    {
        RTSMB_TRANSACTION trans;

        /* we are sending the RPC request for the first time */
        rtsmb_cli_session_fill_header (pSession, &h);
        h.command = SMB_COM_TRANSACTION;
        pShare = rtsmb_cli_session_get_share (pSession, ipc_share_name);
        ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
        h.tid = pShare->tid;

        trans.max_data_count = (word)(RTSMB_CLI_WIRE_MAX_BUFFER_SIZE - 100);
        trans.max_parameter_count = 0;
        trans.max_setup_count = 0;
        trans.flags = 0;
        trans.name = name_pipe;
        trans.name_size = 5;
        trans.timeout = 0;
        trans.setup = setup_params;
        trans.setup_size = 2;

        r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
        ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
        pJob->mid = (word) r;
        rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
        rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_transaction, &trans, r);
        rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_dce_rpc, job_data, r);
        rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);
    }
    else
    {
        RTSMB_READ_AND_X read;

        /* we are reading the next chunk of RPC response data */
        /* set up header */
        rtsmb_cli_session_fill_header (pSession, &h);
        h.command = SMB_COM_READ_ANDX;
        pShare = rtsmb_cli_session_get_share (pSession, ipc_share_name);
        ASSURE (pShare, RTSMB_CLI_SSN_RV_BAD_SHARE);
        h.tid = pShare->tid;

        /* set up read */
        read.next_command = SMB_COM_NONE;
        read.fid = (word) job_data->fid;
        read.offset = 0;
        read.max_count = RTSMB_CLI_SESSION_MAX_DATA_BYTES - 96;

        r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
        ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
        pJob->mid = (word) r;
        rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
        rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_read_and_x_pre_nt, &read, r);
        rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);
    }

    return RTSMB_CLI_SSN_RV_OK;
}

/*---------------------------------------------------------------------------*/
RTSMB_STATIC
int rtsmb_cli_session_send_rpc_request (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob)
{
    return rtsmb_cli_session_send_rpc_request_job(pSession, pJob, &pJob->data.rpc_invoke);
}

/*---------------------------------------------------------------------------*/
int cli_cmd_fill_dce_rpc (PFVOID origin, PFVOID buf, rtsmb_size size,
    PRTSMB_HEADER pHeader, PRTSMB_CLI_RPC_INVOKE_JOB_DATA pRPC)
{
    PFVOID pfraglength;
    long header_len;
    long params_len;
    int status;

    PFVOID pres, s, e, p;

    pres = buf;

    RTSMB_PACK_PAD_TO (4);

    s = buf;

    pfraglength = PADD(buf, 8);

    header_len =  _rtsmb_cli_rpc_write_dce_header(buf, RTSMB_DCE_RPC_TYPE_REQUEST, 0);
    ASSURE((long)size > header_len, -1);
    buf = PADD(buf, header_len);
    size = size - (rtsmb_size) header_len;

    RTSMB_PACK_DWORD (64);  /* alloc hint? */
    RTSMB_PACK_WORD (0);    /* context id? */
    RTSMB_PACK_WORD ((word) pRPC->operation);

    params_len = pRPC->write_request_params(origin, buf, (long)size - header_len, pRPC->request_params, &status);
    ASSURE(params_len > 0, -1);
    ASSURE(size >= (rtsmb_size) params_len, -1);
    buf = PADD(buf, params_len);
    size = size-(rtsmb_size)params_len;

    e = buf;

    /* now go back and fill in all the values we didn't know before */

    rtsmb_pack_add_word_unsafe (pfraglength, (word) PDIFF(e, s), FALSE); /* DCE fragment length */

    p = PADD (origin, 35);  /* total data count */
    rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);

    p = PADD (origin, 51);  /* param count */
    rtsmb_pack_add_word_unsafe (p, (word) 0, FALSE);

    p = PADD (origin, 53);  /* param offset */
    rtsmb_pack_add_word_unsafe (p, (word) PDIFF (s, origin), FALSE);

    p = PADD (origin, 55);  /* data count */
    rtsmb_pack_add_word_unsafe (p, (word) PDIFF (e, s), FALSE);

    p = PADD (origin, 57);  /* data offset */
    rtsmb_pack_add_word_unsafe (p, (word) PDIFF (s, origin), FALSE);

    p = PADD (origin, 65);  /* byte count */
    rtsmb_pack_add_word_unsafe (p, (word)(PDIFF (e, p)-2), FALSE);

    return (int) PDIFF(e,pres);
}

/*---------------------------------------------------------------------------*/
int cli_cmd_read_dce_rpc (PFVOID origin, PFVOID buf, rtsmb_size size,
    PRTSMB_HEADER pHeader, PRTSMB_CLI_RPC_INVOKE_JOB_DATA pRPC)
{
    PFVOID s, e;
    int packet_type, data_rep, fp_rep, status, last;
    long r;

    s = buf;

    if (size < RTSMB_DCE_RPC_HEADER_LEN + 8)
    {
        return -1;
    }

    /* make sure we are 4 byte-aligned */
    if (PDIFF(buf, origin) & 3)
    {
        RTP_ADDR offset = (4-PDIFF(buf, origin)) & 3;
        buf = PADD(buf, offset);
        size -= (rtsmb_size) offset;
    }

    r = _rtsmb_cli_rpc_read_dce_header (buf, &packet_type, &data_rep, &fp_rep, 0, &last);
    if (r < 0)
    {
        return -1;
    }

    pRPC->read_more = !last;

    buf = PADD(buf, r);
    size = size - (rtsmb_size) r;

    /* skip the next 8 bytes */
    buf = PADD(buf, 8);
    size -= 8;

    r = pRPC->read_response_params(origin, buf, (long)size, pRPC->response_params, &status);
    if (r < 0)
    {
        return -1;
    }
    buf = PADD(buf, r);
    size -= (rtsmb_size)r;

    RTSMB_ASSERT((pRPC->read_more == 0) == (status == RTSMB_RPC_RESPONSE_STATUS_DONE));

    e = buf;

    return (int) PDIFF (e, s);
}

/*---------------------------------------------------------------------------*/
RTSMB_STATIC int rtsmb_cli_session_receive_rpc_response (
        PRTSMB_CLI_SESSION pSession,
        PRTSMB_CLI_SESSION_JOB pJob,
        PRTSMB_HEADER pHeader)
{
    int r = 0;

    if (!pJob->data.rpc_invoke.read_more)
    {
        RTSMB_TRANSACTION_R trans;

        trans.setup = 0;
        trans.setup_size = 0;
        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_transaction, &trans, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_dce_rpc, &pJob->data.rpc_invoke, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
    }
    else
    {
        RTSMB_READ_AND_X_R read;

        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_read_and_x_up_to_data, &read, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
        rtsmb_cli_wire_smb_read (&pSession->wire, pHeader->mid, cli_cmd_read_dce_rpc, &pJob->data.rpc_invoke, r);
        ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
    }

    if (pJob->data.rpc_invoke.read_more)
    {
        pJob->state = CSSN_JOB_STATE_STALLED;
    }

    return 0;
}



/*---------------------------------------------------------------------------*/
int rtsmb_rpc_dce_unistr_reader_init (
        PRTSMB_RPC_DCE_UNISTR_READER reader,
        PFWORD unistr,
        RTSMB_UINT32 size,
        RTSMB_UINT32 offset_from_origin)
{
    reader->unistr = unistr;
    reader->size = size;
    reader->last_chunk_size = 0;
    reader->current_offset_from_origin = offset_from_origin;
    reader->chars_read = 0;
    reader->read_padding = RTSMB_FALSE;
    reader->read_header = RTSMB_FALSE;

    return 0;
}

/*---------------------------------------------------------------------------*/
RTSMB_BOOL rtsmb_rpc_dce_unistr_reader_is_done (
        PRTSMB_RPC_DCE_UNISTR_READER reader)
{
    return (reader->read_padding && reader->read_header && reader->chars_left == 0);
}

/*---------------------------------------------------------------------------*/
long rtsmb_rpc_dce_unistr_reader_process_data (
        PRTSMB_RPC_DCE_UNISTR_READER reader,
        PFBYTE data,
        long size)
{
    long bytes_read = 0;

    if (size < 0)
    {
        return -1;
    }

    if (!reader->read_padding)
    {
        while ((reader->current_offset_from_origin & 0x3) != 0 && size > 0)
        {
            size--;
            data++;
            bytes_read++;
            reader->current_offset_from_origin++;
        }

        if ((reader->current_offset_from_origin & 0x3) != 0)
        {
            return bytes_read;
        }

        reader->read_padding = RTSMB_TRUE;
    }

    if (!reader->read_header)
    {
        PFBYTE p = reader->last_chunk_data + 8;
        RTSMB_UINT32 to_copy = RTSMB_MIN((RTSMB_UINT32) size, 12 - reader->last_chunk_size);
        rtp_memcpy (reader->last_chunk_data + reader->last_chunk_size,
                    data,
                    to_copy);

        reader->last_chunk_size += to_copy;
        bytes_read += (long)to_copy;

        if (reader->last_chunk_size < 12)
        {
            return bytes_read;
        }

        data += (long)to_copy;
        size -= (long)to_copy;

        /* skip max_count (32bit) and offset (32bit) */
        reader->chars_left = (READ_UINT32_INTEL(p) + 1) & ~((unsigned long)1);
        reader->read_header = RTSMB_TRUE;
        reader->last_chunk_size = 0;
    }

    if (reader->last_chunk_size == 1 && size > 0)
    {
        PFBYTE p = reader->last_chunk_data;
        reader->last_chunk_data[1] = *data;
        data++;
        size--;
        if (reader->chars_read < reader->size)
        {
            reader->unistr[reader->chars_read] = (word)READ_UINT16_INTEL(p);
        }
    }

    while (reader->chars_left > 0 && size > 1)
    {
        if (reader->chars_read < reader->size)
        {
            reader->unistr[reader->chars_read] = (word)READ_UINT16_INTEL(data);
        }
        else
        {
            SKIP_UINT16(data);
        }
        reader->chars_read++;
        reader->chars_left--;
        size -= 2;
        bytes_read += 2;
    }

    if (size == 1)
    {
        reader->last_chunk_data[0] = *data;
        reader->last_chunk_size = 1;
    }

    return bytes_read;
}
