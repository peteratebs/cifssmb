//
// SRVRAP.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles enumeration and getting info on network shares
//

//============================================================================
//    IMPLEMENTATION HEADERS
//============================================================================
#include "smbdefs.h"
#include "rtpwcs.h" /* _YI_ 9/24/2004 */

#if (INCLUDE_RTSMB_SERVER)

#include "srvrap.h"
#include "srvnet.h"
#include "smbnb.h"
#include "srvrsrcs.h"
#include "srvshare.h"
#include "srvfio.h"
#include "smbobjs.h"
#include "srvans.h"
#include "srvcmds.h"
#include "smbutil.h"
#include "srvnbns.h"
#include "smbnb.h"
#include "smbnbds.h"
#include "smbbrcfg.h"
#include "srvbrbak.h"
#include "srvbrws.h"


#include "rtpsignl.h"
#include "smbdebug.h"
//============================================================================
//    IMPLEMENTATION PRIVATE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
#define RAP_NERR_SUCCESS            0       // No errors encountered
#define RAP_ERROR_ACCESS_DENIED     6       // User has insufficient privilege
#define RAP_ERROR_MORE_DATA         234     // additional data is availiable
#define RAP_NERR_BUFTOOSMALL        2123    // The supplied buffer is too small
#define RAP_NERR_BADTRANSACTCONFIG  2141    // The server is not configured for
                                            //  transactions, IPC$ is not shared
#define RAP_NERR_QNOTFOUND          2150    // printer queue name is not valid
#define RAP_NERR_SPOOLERNOTLOADED   2161    // spooler is not started on server
#define RAP_NERR_USERNOTFOUND       2221    // The user name was not found
#define RAP_NERR_INVALID_DOMAIN     2320    // The domain does not exist

#define PRQ_ACTIVE      0   // active
#define PRQ_PAUSE       1   // paused
#define PRQ_ERROR       2   // error occured
#define PRQ_PENDING     3   // deletion pending

#define LM20_QNLEN  12

#define PRJ_QS_QUEUED       0 // Print job is queued
#define PRJ_QS_PAUSED       1 // Print job is paused
#define PRJ_QS_SPOOLING     2 // Print job is spooling
#define PRJ_QS_PRINTING     3 // Print job is printing, bits 2-11 are valid

#define PRJ_COMPLETE        0x0004 // Print job is complete
#define PRJ_INTERV          0x0008 // an error occurred
#define PRJ_ERROR           0x0010 // Print job is spooling (?)
#define PRJ_DESTOFFLINE     0x0020 // The print destination is offline
#define PRJ_DESTPAUSED      0x0040 // The print destination is paused
#define PRJ_NOTIFY          0x0080 // An alert is raised
#define PRJ_DESTNOPAPER     0x0100 // Out of paper
#define PRJ_DESTFORMCHG     0x0200 // Waiting for a form change
#define PRJ_DESTCRTCHG      0x0400 // Waiting for a cartridge change
#define PRJ_DESTENCHG       0x0800 // Waiting for a pen change
#define PRJ_PRINTING        0x8000 // An alert indicates the job was deleted

//============================================================================
//    IMPLEMENTATION PRIVATE STRUCTURES
//============================================================================
//============================================================================
//    IMPLEMENTATION REQUIRED EXTERNAL REFERENCES (AVOID)
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE DATA
//============================================================================
//============================================================================
//    INTERFACE DATA
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTION PROTOTYPES
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTIONS
//============================================================================

/*
================
    int length - x
    PFBYTE pOutBuf - x
    PSMB_TRANSACTIONRS pOutTran - x
================
*/
int NetShareEnum (PSMB_SESSIONCTX pCtx, PRTSMB_RAP_REQUEST pFunc,
    PRTSMB_HEADER pInHdr, PFVOID pInBuf,
    PRTSMB_HEADER pOutHdr,
    rtsmb_size size_left, PFWORD param_size)
{
    PSR_RESOURCE pOutRes;
    RTSMB_RAP_GET_INFO command;
    RTSMB_RAP_ENUM_HEADER_R header;
    RTSMB_RAP_SHARE_ENUM_INFO_R info;
    PFVOID data_section;
    PFVOID pOutBuf = pCtx->tmpBuffer;
    int r, i;

    r = srv_cmd_read_rap_get_info (pCtx->write_origin, pInBuf,
        pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin)), pInHdr,
        &command);
    if (r == -1)
        return -1;

    size_left = MIN (command.receive_size, size_left);

    // Fill out parameters
    header.status = RAP_ERROR_ACCESS_DENIED;
    header.converter = 0;
    header.entry_count = 0;
    header.available_entries = 0;

    r = srv_cmd_fill_rap_share_enum_header (pCtx->tmpBuffer, pCtx->tmpBuffer,
        size_left, pOutHdr, &header);
    if (r == -1)
        return r;
    size_left -=  (rtsmb_size)r;
    *param_size = (word) r;

    pOutBuf = PADD (pCtx->tmpBuffer, r);
    data_section = pOutBuf;

    CLAIM_SHARE ();
    header.entry_count = 0;
    header.available_entries = 0;
    info.total_shares = 0;

    // find out how many shares there are.
    for(pOutRes = SR_FirstResource(); pOutRes != (PSR_RESOURCE)0; pOutRes = SR_NextResource(pOutRes))
    {
        info.total_shares++;
    }

    // pack each share into the buffer.
    i = 0;
    r = 0;
    for(pOutRes = SR_FirstResource(); pOutRes != (PSR_RESOURCE)0; pOutRes = SR_NextResource(pOutRes))
    {
        int this_r;

        info.share_num = info.total_shares - (i++) - 1;

        rtsmb_cpy (info.share_data.name, pOutRes->name);
        info.share_data.type = pOutRes->stype;
        info.share_data.comment = pOutRes->comment;

        header.entry_count++;
        header.available_entries++;

        this_r = srv_cmd_fill_rap_share_enum_info (pCtx->tmpBuffer, pOutBuf,
            size_left, pOutHdr, &info);

        if (this_r == -1)
            break;

        r += this_r;
    }

    RELEASE_SHARE ();

    if (r == -1)
    {
        header.status = RAP_NERR_BUFTOOSMALL;
        header.converter = 0;
        r = 0;
    }
    else
    {
        header.status = RAP_NERR_SUCCESS;
        header.converter = (word)(((int) data_section) & 0xFFFF);
    }

    srv_cmd_fill_rap_share_enum_header (pCtx->tmpBuffer, pCtx->tmpBuffer,
        size_left, pOutHdr, &header);

    return r;
} // End NetShareEnum


/*
================

================
*/
int NetServerEnum2 (PSMB_SESSIONCTX pCtx, PRTSMB_RAP_REQUEST pFunc,
    PRTSMB_HEADER pInHdr, PFVOID pInBuf,
    PRTSMB_HEADER pOutHdr,
    rtsmb_size size_left, PFWORD param_size)
{
    RTSMB_RAP_SERVER_ENUM2 command;
    RTSMB_RAP_ENUM_HEADER_R header;
    RTSMB_RAP_SERVER_INFO_1 info;
    PRTSMB_BROWSE_SERVER_INFO plist;
    PFVOID data_section;
    PFVOID pOutBuf = pCtx->tmpBuffer;
    int r, i, j, max_possible;
    rtsmb_char domain [RTSMB_NB_NAME_SIZE + 1];

    command.domain = domain;
    command.domain_size = RTSMB_NB_NAME_SIZE;
    r = srv_cmd_read_rap_server_enum2 (pCtx->write_origin, pInBuf,
        pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin)), pInHdr,
        &command);
    if (r == -1)
        return -1;

    size_left = MIN (command.receive_size, size_left);

    // Fill out parameters
    header.status = RAP_ERROR_ACCESS_DENIED;
    header.converter = 0;
    header.entry_count = 0;
    header.available_entries = 0;

    r = srv_cmd_fill_rap_share_enum_header (pCtx->tmpBuffer, pCtx->tmpBuffer,
        size_left, pOutHdr, &header);
    if (r == -1)
        return r;
    size_left -= (rtsmb_size)r;
    *param_size = (word)r;

    pOutBuf = PADD (pCtx->tmpBuffer, r);
    data_section = pOutBuf;

    rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    header.entry_count = 0;
    header.available_entries = 0;
    info.info_total = 0;

    if (pCtx->state == BROWSE_FAIL)
    {
        /* domain is invalid.   tell client */
        header.status = RAP_NERR_INVALID_DOMAIN;
        srv_cmd_fill_rap_share_enum_header (pCtx->tmpBuffer, pCtx->tmpBuffer,
            size_left, pOutHdr, &header);
        return r;
    }
    else if (pCtx->state == BROWSE_FINISH)
    {
        /* we have previously been here and punted our netenum2 to another
           server.  here, we have the data now and we want to ship it out. */
        plist = prtsmb_srv_ctx->enum_results;
        max_possible = prtsmb_srv_ctx->enum_results_size;
    }
    /* is this a domain enum or server enum? */
    else if (command.server_type == SV_TYPE_DOMAIN_ENUM)
    {
        plist = prtsmb_srv_ctx->domain_table;
        max_possible = prtsmb_srv_ctx->domain_table_size;
    }
    else
    {
        char group_name [RTSMB_NB_NAME_SIZE + 1];

        plist = prtsmb_srv_ctx->server_table;
        max_possible = prtsmb_srv_ctx->server_table_size;

        rtsmb_util_rtsmb_to_ascii (command.domain, group_name, CFG_RTSMB_USER_CODEPAGE);

        /* if the group name is null or the same as our group, we just get it from
           our own list.  else, we need to outsource the netenum2 */
        if (group_name[0] && rtsmb_strcasecmp (group_name, rtsmb_srv_nbns_get_our_group (), CFG_RTSMB_USER_CODEPAGE) != 0)
        {
            rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);

            /* we have a server enum request outside of our own workgroup. */
            /* punt it off to the browse layer, which will come up with something to hand over */
            pCtx->state = BROWSE_MUTEX;
            pCtx->server_enum_type = command.server_type;
            tc_strcpy (pCtx->server_enum_domain, group_name);

            rtsmb_srv_browse_finish_server_enum (pCtx);

            return -2; /* tell upper layers to not send response yet */
        }
    }

    // find out how many servers there are.
    for (i = 0; i < max_possible; i++)
    {
        if (plist[i].type & command.server_type)
        {
            info.info_total++;
        }
    }

    // pack each server into the buffer.
    for (i = 0, j = 0, r = 0; i < max_possible; i++)
    {
        int this_r;
        rtsmb_char comment [RTSMB_MAX_COMMENT_SIZE + 1];

        /* take care of non-used types (0-value 'type') and
           servers we aren't interested in */
        if ((plist[i].type & command.server_type) == 0)
        {
            continue;
        }

        info.info_num = info.info_total - (j++) - 1;

        rtsmb_util_ascii_to_rtsmb (plist[i].name, info.name, CFG_RTSMB_USER_CODEPAGE);
        info.type = plist[i].type;
        rtsmb_util_ascii_to_rtsmb (plist[i].comment, comment, CFG_RTSMB_USER_CODEPAGE);
        info.comment = comment;
        info.version_minor = plist[i].version_minor;
        info.version_major = plist[i].version_major;

        header.entry_count++;
        header.available_entries++;

        if (command.information_level == 0)
        {
            this_r = srv_cmd_fill_rap_server_enum_info_0 (pCtx->tmpBuffer, pOutBuf,
                size_left, pOutHdr, &info);
        }
        else /* must be one... */
        {
            this_r = srv_cmd_fill_rap_server_enum_info_1 (pCtx->tmpBuffer, pOutBuf,
                size_left, pOutHdr, &info);
        }

        if (this_r == -1)
            break;

        r += this_r;
    }

    rtp_sig_mutex_release((RTP_MUTEX) prtsmb_browse_ctx->mutex);

    if (r == -1)
    {
        header.status = RAP_NERR_BUFTOOSMALL;
        header.converter = 0;
        r = 0;
    }
    else
    {
        header.status = RAP_NERR_SUCCESS;
        header.converter = (word)(((int) data_section) & 0xFFFF);
    }

    srv_cmd_fill_rap_share_enum_header (pCtx->tmpBuffer, pCtx->tmpBuffer,
        size_left, pOutHdr, &header);

    return r;
}

/*
================
    int level - x
    int length - x
    PFBYTE pOutBuf - x
    PSMB_TRANSACTIONRS pOutTran - x
================
*/
int NetServerGetInfo(PSMB_SESSIONCTX pCtx, PRTSMB_RAP_REQUEST pFunc,
    PRTSMB_HEADER pInHdr, PFVOID pInBuf,
    PRTSMB_HEADER pOutHdr,
    rtsmb_size size_left, PFWORD param_size)
{
    RTSMB_RAP_GET_INFO command;
    RTSMB_RAP_RESPONSE response;
    RTSMB_RAP_SERVER_INFO_1 info;
    rtsmb_char comment [RTSMB_MAX_COMMENT_SIZE + 1];
    PFVOID data_section;
    PFVOID pOutBuf = pCtx->tmpBuffer;
    int r;

    r = srv_cmd_read_rap_get_info (pCtx->write_origin, pInBuf,
        pCtx->current_body_size - (rtsmb_size)PDIFF (pInBuf, pCtx->read_origin), pInHdr,
        &command);
    if (r == -1)
        return -1;

    size_left = MIN (command.receive_size, size_left);

    // Fill out parameters
    response.status = RAP_ERROR_ACCESS_DENIED;
    response.converter = 0;
    response.available_bytes = 0;

    r = srv_cmd_fill_rap_response (pCtx->tmpBuffer, pCtx->tmpBuffer,
        size_left, pOutHdr, &response);
    if (r == -1)
        return r;
    size_left -= (rtsmb_size)r;
    *param_size = (word)r;

    pOutBuf = PADD (pCtx->tmpBuffer, r);
    data_section = pOutBuf;

    rtsmb_util_ascii_to_rtsmb (rtsmb_srv_nbns_get_our_name (), info.name, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_rtsmb (CFG_RTSMB_DEFAULT_COMMENT, comment, CFG_RTSMB_USER_CODEPAGE);

    info.version_major = 4;
    info.version_minor = 0;
    info.type = rtsmb_srv_browse_get_server_type ();
    info.comment = comment;

    switch (command.information_level)
    {
    case 0:
    {
        r = srv_cmd_fill_rap_server_info_0 (pCtx->write_origin, pOutBuf,
            size_left, pOutHdr, &info);
    }
    break;
    case 1:
    {
        r = srv_cmd_fill_rap_server_info_1 (pCtx->write_origin, pOutBuf,
            size_left, pOutHdr, &info);
    }
    break;
    }

    if (r == -1)
    {
        response.status = RAP_NERR_BUFTOOSMALL;
        response.converter = 0;
        r = 0;
    }
    else
    {
        response.status = RAP_NERR_SUCCESS;
        response.converter = (word)(((int) data_section) & 0xFFFF);
    }

    response.available_bytes = (word) r;
    srv_cmd_fill_rap_response (pCtx->tmpBuffer, pCtx->tmpBuffer,
        size_left, pOutHdr, &response);

    return r;
}

/*
================

    int level - x
    int length - x
    PFBYTE pOutBuf - x
    PSMB_TRANSACTIONRS pOutTran - x
================
*/
int NetWkstaGetInfo (PSMB_SESSIONCTX pCtx, PRTSMB_RAP_REQUEST pFunc,
    PRTSMB_HEADER pInHdr, PFVOID pInBuf,
    PRTSMB_HEADER pOutHdr,
    rtsmb_size size_left, PFWORD param_size)
{
    RTSMB_RAP_GET_INFO command;
    RTSMB_RAP_WKSTA_INFO info;
    RTSMB_RAP_RESPONSE response;
    PFVOID pOutBuf = pCtx->tmpBuffer;
    PFVOID data_section;
    rtsmb_char group_name [RTSMB_NB_NAME_SIZE + 1];
    rtsmb_char comp_name [RTSMB_NB_NAME_SIZE + 1];
    int r;

    r = srv_cmd_read_rap_get_info (pCtx->write_origin, pInBuf,
        pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin)), pInHdr,
        &command);
    if (r == -1)
        return -1;

    size_left = MIN (command.receive_size, size_left);

    // Fill out parameters
    response.status = RAP_ERROR_ACCESS_DENIED;
    response.converter = 0;
    response.available_bytes = 0;

    r = srv_cmd_fill_rap_response (pCtx->tmpBuffer, pCtx->tmpBuffer,
        size_left, pOutHdr, &response);
    if (r == -1)
        return r;
    size_left -= (rtsmb_size)r;
    *param_size = (word)r;

    pOutBuf = PADD (pCtx->tmpBuffer, r);
    data_section = pOutBuf;

    rtsmb_util_ascii_to_rtsmb (rtsmb_srv_nbns_get_our_group (), group_name, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_rtsmb (rtsmb_srv_nbns_get_our_name (), comp_name, CFG_RTSMB_USER_CODEPAGE);

    info.version_minor = 0;
    info.version_major = 4;
    info.computer_name = comp_name;
    info.username = (PFRTCHAR)0;
    info.lan_group = group_name;
    info.logon_domain = group_name;
    info.other_domains = (PFRTCHAR)0;

    r = srv_cmd_fill_rap_wksta_info (pCtx->tmpBuffer, pOutBuf,
        size_left, pOutHdr, &info);
    if (r == -1)
    {
        response.status = RAP_NERR_BUFTOOSMALL;
        response.converter = 0;
        response.available_bytes = (word) srv_cmd_sizeof_rap_wksta_info (pOutHdr, &info);
        r = 0;
    }
    else
    {
        response.status = RAP_NERR_SUCCESS;
        response.converter = (word)(((int) data_section) & 0xFFFF);
        response.available_bytes = (word)r;
    }

    response.available_bytes = (word)r;
    srv_cmd_fill_rap_response (pCtx->tmpBuffer, pCtx->tmpBuffer,
        size_left, pOutHdr, &response);

    return r;
} // End NetWkstaGetInfo

#if 0
/**
 * This function should look at the enclosed file path, and return some value for status
 * that makes sense.
 *
 * Instead, it always returns 50 for status.
 */
void NetAccessGetInfo( PFBYTE pOutBuf, PSMB_TRANSACTIONRS pOutTran )
{
    PSMB_HEADER1 pOutHdr1;
    PSMB_HEADER2 pOutHdr2;
    PACCESS_INFO pOutParam;

    pOutHdr1 = (PSMB_HEADER1) pOutBuf;
    pOutHdr2 = (PSMB_HEADER2) pOutTran->setup;
    pOutParam = (PACCESS_INFO) pOutHdr2->buffer;

    // Fill out the data
    pOutParam->status = 50; // i have observed win98 sending this to winnt for a particular directory
                            // I don't know what it means

    // Fill out header 2
    pOutHdr2->byteCount = sizeof (ACCESS_INFO_T);

    // Fill out pOutTran
    pOutTran->totalParameterCount = sizeof (ACCESS_INFO_T);
    pOutTran->totalDataCount = 0;
    pOutTran->reserved = 0;
    pOutTran->parameterCount = pOutTran->totalParameterCount;
    pOutTran->parameterOffset = (dword) pOutParam - (dword) pOutHdr1;
    pOutTran->parameterDisplacement = 0;
    pOutTran->dataCount = pOutTran->totalDataCount;
    pOutTran->dataOffset = pOutTran->parameterOffset + pOutTran->totalParameterCount;
    pOutTran->dataDisplacement = 0;
    pOutTran->setupCount = 0;

    pOutHdr1->wordCount = 10;
} // End NetWkstaGetInfo
#endif
/*
================
Returns some info about the named printer.  This packet's
                        documentation is nigh-non-existant.  I have pieced this together from
                        sniffing live transmissions.  Mileage may vary.
    PFCHAR printer - the printer to get info on
    PFBYTE pOutBuf - x
    PSMB_TRANSACTIONRS pOutTran - x
================
*/

int WPrintQGetInfo (PSMB_SESSIONCTX pCtx, PRTSMB_RAP_REQUEST pFunc,
    PRTSMB_HEADER pInHdr, PFVOID pInBuf,
    PRTSMB_HEADER pOutHdr,
    rtsmb_size size_left, PFWORD param_size)
{
    PSR_RESOURCE pOutRes;
    RTSMB_RAP_SHARE_GET_INFO command;
    RTSMB_RAP_RESPONSE response;
    PFVOID data_section;
    PFVOID pOutBuf = pCtx->tmpBuffer;
    rtsmb_char share[RTSMB_MAX_SHARENAME_SIZE + 1];
    word status = RAP_NERR_SUCCESS;
    int r;
    rtsmb_size desired_size;
    rtsmb_size original_size_left = size_left;

    command.share = share;
    command.share_size = RTSMB_MAX_SHARENAME_SIZE;
    r = srv_cmd_read_rap_share_get_info (pCtx->write_origin, pInBuf,
        pCtx->current_body_size - (rtsmb_size)PDIFF (pInBuf, pCtx->read_origin), pInHdr,
        &command);
    if (r == -1)
        return -1;

    size_left = MIN (command.receive_size, original_size_left);

    // Fill out parameters
    response.status = RAP_ERROR_ACCESS_DENIED;
    response.converter = 0;
    response.available_bytes = 0;

    r = srv_cmd_fill_rap_response (pCtx->tmpBuffer, pCtx->tmpBuffer,
        original_size_left, pOutHdr, &response);
    if (r == -1)
    {
        return 0;
    }

    *param_size = (word)r;

    pOutBuf = PADD (pCtx->tmpBuffer, r);
    data_section = pOutBuf;

    CLAIM_SHARE ();
    // find printer share
    for(pOutRes = SR_FirstResource(); pOutRes != (PSR_RESOURCE)0; pOutRes = SR_NextResource(pOutRes))
    {
        if (rtsmb_casecmp (pOutRes->name, command.share, CFG_RTSMB_USER_CODEPAGE) == 0)
        {
            break;
        }
    }

    if (!pOutRes)
    {
        status = RAP_ERROR_ACCESS_DENIED;
    }
    else
    {
        switch (command.information_level)
        {
        case 0:
        {
            RTSMB_RAP_PRINTER_QUEUE_INFO_0 info;

            rtsmb_ncpy (info.name, pOutRes->name, 12);
            info.name[12] = '\0';

            desired_size = srv_cmd_sizeof_rap_printer_queue_info_0 (pOutHdr, &info);
            r = srv_cmd_fill_rap_printer_queue_info_0 (pCtx->tmpBuffer, pOutBuf,
                size_left, pOutHdr, &info);
        }
            break;
        case 1:
        case 2:
        {
            RTSMB_RAP_PRINTER_QUEUE_INFO_1 info;
            rtsmb_char preproc[] = {'W', 'i', 'n', 'P', 'r', 'i', 'n', 't', '\0'};

            info.priority = 1;
            info.start_time = 0;
            info.until_time = 0;
            info.status = PRQ_ACTIVE;
            info.num_jobs = 0;

            rtsmb_ncpy (info.name, pOutRes->name, 12);
            info.name[12] = '\0';

            info.preprocessor = preproc;
            info.comment = pOutRes->comment;
            info.sep_file = (PFRTCHAR)0;
            info.parameters = (PFRTCHAR)0;
            info.destinations = (PFRTCHAR)0;

            desired_size = srv_cmd_sizeof_rap_printer_queue_info_1 (pOutHdr, &info);
            r = srv_cmd_fill_rap_printer_queue_info_1 (pCtx->tmpBuffer, pOutBuf,
                size_left, pOutHdr, &info);
        }
            break;
        case 3:
        case 4:
        {
            RTSMB_RAP_PRINTER_QUEUE_INFO_3 info;
            rtsmb_char preproc[] = {'W', 'i', 'n', 'P', 'r', 'i', 'n', 't', '\0'};

            info.priority = 1;
            info.start_time = 0;
            info.until_time = 0;
            info.status = PRQ_ACTIVE;
            info.num_jobs = 0;

            info.name = pOutRes->name;
            info.comment = pOutRes->comment;
            info.driver_name = pOutRes->u.printer.printerfile;
            info.preprocessor = preproc;
            info.sep_file = (PFRTCHAR)0;
            info.parameters = (PFRTCHAR)0;
            info.printers = (PFRTCHAR)0;
            info.driver_data = (PFRTCHAR)0;

            desired_size = srv_cmd_sizeof_rap_printer_queue_info_3 (pOutHdr, &info);
            r = srv_cmd_fill_rap_printer_queue_info_3 (pCtx->tmpBuffer, pOutBuf,
                size_left, pOutHdr, &info);
        }
            break;
        case 5:
        {
            RTSMB_RAP_PRINTER_QUEUE_INFO_5 info;

            info.name = pOutRes->name;

            desired_size = srv_cmd_sizeof_rap_printer_queue_info_5 (pOutHdr, &info);
            r = srv_cmd_fill_rap_printer_queue_info_5 (pCtx->tmpBuffer, pOutBuf,
                size_left, pOutHdr, &info);
        }
            break;
        }
    }

    RELEASE_SHARE ();

    if (r == -1)
    {
        response.status = RAP_NERR_BUFTOOSMALL;
        response.converter = 0;

        response.available_bytes = (word)desired_size;
        r = 0;
    }
    else
    {
        response.status = status;
        response.converter = (word)(((int) data_section) & 0xFFFF);

        response.available_bytes = (word)r;
    }

    srv_cmd_fill_rap_response (pCtx->tmpBuffer, pCtx->tmpBuffer,
        original_size_left, pOutHdr, &response);

    return r;
}


int NetShareGetInfo (PSMB_SESSIONCTX pCtx, PRTSMB_RAP_REQUEST pFunc,
    PRTSMB_HEADER pInHdr, PFVOID pInBuf,
    PRTSMB_HEADER pOutHdr,
    rtsmb_size size_left, PFWORD param_size)
{
    PSR_RESOURCE pResource;
    RTSMB_RAP_SHARE_GET_INFO command;
    RTSMB_RAP_RESPONSE response;
    PFVOID data_section;
    PFVOID pOutBuf = pCtx->tmpBuffer;
    rtsmb_char share[RTSMB_MAX_SHARENAME_SIZE + 1];
    int r, id;

    command.share = share;
    command.share_size = RTSMB_MAX_SHARENAME_SIZE;
    r = srv_cmd_read_rap_share_get_info (pCtx->write_origin, pInBuf,
        pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin)), pInHdr,
        &command);
    if (r == -1)
        return -1;

    size_left = MIN (command.receive_size, size_left);

    // Fill out parameters
    response.status = RAP_ERROR_ACCESS_DENIED;
    response.converter = 0;
    response.available_bytes = 0;

    r = srv_cmd_fill_rap_response (pCtx->tmpBuffer, pCtx->tmpBuffer,
        size_left, pOutHdr, &response);
    if (r == -1)
        return r;
    size_left -= (rtsmb_size) r;
    *param_size = (word) r;

    pOutBuf = PADD (pCtx->tmpBuffer, r);
    data_section = pOutBuf;

    id = SR_GetTreeIdFromName (command.share);

    CLAIM_SHARE ();

    if (id > -1)
    {
        pResource = SR_ResourceById ((word) id);

        switch (command.information_level)
        {
        case 0:
        {
            RTSMB_RAP_SHARE_INFO_0 info;

            rtsmb_ncpy (info.name, pResource->name, 12);
            info.name[12] = '\0';

            r = srv_cmd_fill_rap_share_info_0 (pCtx->write_origin, pOutBuf,
                size_left, pOutHdr, &info);
        }
        break;
        case 1:
        {
            RTSMB_RAP_SHARE_INFO_1 info;

            rtsmb_ncpy (info.name, pResource->name, 12);
            info.name[12] = '\0';

            info.type = pResource->stype;
            info.comment = pResource->comment;

            r = srv_cmd_fill_rap_share_info_1 (pCtx->write_origin, pOutBuf,
                size_left, pOutHdr, &info);
        }
        break;
        default:
            r = 0;
            break;
        }
    }
    else
        r = 0;

    RELEASE_SHARE ();

    if (r == -1)
    {
        response.status = RAP_NERR_BUFTOOSMALL;
        response.converter = 0;
        r = 0;
    }
    else
    {
        response.status = RAP_NERR_SUCCESS;
        response.converter = (word)((int) data_section) & 0xFFFF;
    }

    response.available_bytes = (word) r;
    srv_cmd_fill_rap_response (pCtx->tmpBuffer, pCtx->tmpBuffer,
        size_left, pOutHdr, &response);

    return r;
} // End NetShareGetInfo



//============================================================================
//    INTERFACE FUNCTIONS
//============================================================================
/*
================

    PFBYTE inBuf - The start of the incoming buffer (needed for offset calculations)
    PSMB_TRANSACTIONRQ pInReq - the incoming request
    PFBYTE outBuf - the outgoing buffer (needed for offset calculations)
    PSMB_TRANSACTIONRS pOutRes - The out going transaction response
================
*/
int RAP_Proc (PSMB_SESSIONCTX pCtx,
    PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
    PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left)
{
    RTSMB_RAP_REQUEST func;
    rtsmb_char param [50];
    rtsmb_char answer [50];
    int size, data_size = 0;
    word param_size;

    func.parent = pTransaction;
    func.parameter = param;
    func.parameter_size = 49;
    func.answer = answer;
    func.answer_size = 49;
    size = srv_cmd_read_rap_request (pCtx->read_origin, pInBuf,
         pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &func);
    if (size == -1) return 0;
    pInBuf = PADD (pInBuf, size);

    param_size = 0;
    switch (func.opcode)
    {
    case RAP_COM_NET_SHARE_ENUM:
        data_size = NetShareEnum (pCtx, &func, pInHdr, pInBuf, pOutHdr,
            size_left, &param_size);
        break;
    case RAP_COM_NET_SERVER_GETINFO:
        data_size = NetServerGetInfo (pCtx, &func, pInHdr, pInBuf, pOutHdr,
            size_left, &param_size);
        break;
    case RAP_COM_NET_WKSTA_GETINFO:
        data_size = NetWkstaGetInfo (pCtx, &func, pInHdr, pInBuf, pOutHdr,
            size_left, &param_size);
        break;
    case RAP_COM_NET_SHARE_GETINFO:
        data_size = NetShareGetInfo (pCtx, &func, pInHdr, pInBuf, pOutHdr,
            size_left, &param_size);
        break;
    case RAP_COM_WPRINTQ_GETINFO:
        data_size = WPrintQGetInfo (pCtx, &func, pInHdr, pInBuf, pOutHdr,
            size_left, &param_size);
        break;
    case RAP_COM_NET_SERVER_ENUM2:
        data_size = NetServerEnum2 (pCtx, &func, pInHdr, pInBuf, pOutHdr,
            size_left, &param_size);
        break;
        /*
    case RAP_COM_NET_ACCESS_GETINFO:
        NetAccessGetInfo (pCtx, &func, pInHdr, pInBuf, pOutHdr, size_left);
        break;*/
    default:
        RTSMB_DEBUG_OUTPUT_STR ("RAP_Proc: function unhandled: ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_INT (func.opcode);
        RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);
    }

    if (data_size == -2) /* special error case where we don't want to answer */
        return -1;

    pTransactionR->setup_size = 0;
    pTransactionR->setup = (PFWORD)0;
    pTransactionR->parameter = pCtx->tmpBuffer;
    pTransactionR->parameter_count = param_size;
    if (data_size == -1)
    {
        pTransactionR->data = (PFBYTE)0;
        pTransactionR->data_count = 0;
    }
    else
    {
        pTransactionR->data = PADD (pCtx->tmpBuffer, param_size);
        pTransactionR->data_count = (word) data_size;
    }

    return 0;
} // End RAP_Proc


//****************************************************************************
//**
//**    END MODULE SRVRAP.C
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */
