/*
|  CLSRVSVC.C - Support for RPC interface SRVSVC (Microsoft Server Services),
|               including NetrShareEnum
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

#include "clsrvsvc.h"
#include "rtpwcs.h"
#include "smbutil.h"

/*****************************************************************************/
/* Macros
 *****************************************************************************/

/*****************************************************************************/
/* Types
 *****************************************************************************/

/*****************************************************************************/
/* Function Prototypes
 *****************************************************************************/

int rtsmb_rpc_dce_share_info_1_reader_init (
        PRTSMB_RPC_DCE_SHARE_INFO_1_READER reader,
        PRTSMB_RPC_SHARE_INFO_LEVEL_1 share_info,
        RTSMB_UINT32 offset_from_origin);

RTSMB_BOOL rtsmb_rpc_dce_share_info_1_reader_is_done (
        PRTSMB_RPC_DCE_SHARE_INFO_1_READER reader);

long rtsmb_rpc_dce_share_info_1_reader_process_data (
        PRTSMB_RPC_DCE_SHARE_INFO_1_READER reader,
        PFBYTE data,
        long size);

/*****************************************************************************/
/* Data
 *****************************************************************************/
rtsmb_char _rtsmb_srvsvc_pipe_name [] = {'\\','s','r','v','s','v','c',0};
PFRTCHAR prtsmb_srvsvc_pipe_name = _rtsmb_srvsvc_pipe_name;
RTSMB_RPC_IFACE_INFO _rtsmb_srvsvc_info =
{
    {0x4B, 0x32, 0x4F, 0xC8, 0x16, 0x70, 0x01, 0xD3,
     0x12, 0x78, 0x5A, 0x47, 0xBF, 0x6E, 0xE1, 0x88},
    3, 0,
    {0x8A, 0x88, 0x5D, 0x04, 0x1C, 0xEB, 0x11, 0xC9,
     0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60},
    2
};
PRTSMB_RPC_IFACE_INFO prtsmb_srvsvc_info = &_rtsmb_srvsvc_info;

/*****************************************************************************/
/* Function Definitions
 *****************************************************************************/

/*---------------------------------------------------------------------------*/
void rtsmb_cli_rpc_NetrShareEnum_init     (PFVOID request_data, PFVOID response_data)
{
    PRTSMB_RPC_NETR_SHARE_ENUM_RESPONSE response = (PRTSMB_RPC_NETR_SHARE_ENUM_RESPONSE) response_data;

    response->state = NETR_SHARE_ENUM_STATE_READING_HEADER;
}

/*---------------------------------------------------------------------------*/
long rtsmb_cli_rpc_NetrShareEnum_request  (PFBYTE origin, PFBYTE buffer, long bufferSize,
                                           PFVOID param_data, PFINT status)
{
    RTSMB_UINT16* serverNameUC = ((PRTSMB_RPC_NETR_SHARE_ENUM_REQUEST)param_data)->server_name_uc;
    RTSMB_UINT8* writePtr = buffer;
    RTSMB_UINT32 i;

    i = rtp_wcslen(serverNameUC) + 1;

    if ((unsigned long) bufferSize < 44 + ((i + 1) & ~((dword)(0x1)) * 2))
    {
        /* error: buffer too small */
        return -1;
    }

    WRITE_UINT32_INTEL(writePtr, (RTSMB_UINT32) serverNameUC);
    WRITE_UINT32_INTEL(writePtr, i); // maxCount
    WRITE_UINT32_INTEL(writePtr, 0); // offset
    WRITE_UINT32_INTEL(writePtr, i); // actualCount
    WRITE_UNISTR_INTEL(writePtr, serverNameUC, i); // string data
    if (i & 0x1) // if unicode string was odd length, add an extra uint16 to pad to 32-bits
    {
        WRITE_UINT16_INTEL(writePtr, 0);
    }

    WRITE_UINT32_INTEL(writePtr, 1); // info level
    WRITE_UINT32_INTEL(writePtr, 1); // share info level
    WRITE_UINT32_INTEL(writePtr, (RTSMB_UINT32) &writePtr); // shareInfoContainer ptr
    WRITE_UINT32_INTEL(writePtr, 0); // numEntries
    WRITE_UINT32_INTEL(writePtr, 0); // null ptr (shareInfoArray)

    WRITE_UINT32_INTEL(writePtr, 0xFFFFFFFF); // preferred length
    WRITE_UINT32_INTEL(writePtr, 0);          // null ptr (resume handle)

    RTSMB_ASSERT(PDIFF(writePtr, buffer) <= bufferSize);

    return (int) PDIFF(writePtr, buffer);
}

/*---------------------------------------------------------------------------*/
long rtsmb_cli_rpc_NetrShareEnum_response (PFBYTE origin, PFBYTE buffer, long buf_size,
                                           PFVOID param_data, PFINT status)
{
    PRTSMB_RPC_NETR_SHARE_ENUM_RESPONSE response = (PRTSMB_RPC_NETR_SHARE_ENUM_RESPONSE) param_data;
    PFBYTE readPtr = buffer;
    RTSMB_UINT32 infoLevel;
    RTSMB_UINT32 enumHandle;
    RTSMB_UINT32 returnCode;
    long r;
    RTSMB_UINT32 totalEntries;
    static RTSMB_RPC_SHARE_INFO_LEVEL_1 nil_info;

    *status = RTSMB_RPC_RESPONSE_STATUS_INCOMPLETE;

    switch (response->state)
    {
        case NETR_SHARE_ENUM_STATE_READING_HEADER:
            ASSURE(buf_size >= 24, -1);

            infoLevel = READ_UINT32_INTEL(readPtr);
            buf_size -= 4;

            ASSURE(infoLevel == 1, -1);
            ASSURE(READ_UINT32_INTEL(readPtr) == infoLevel, -1);

            SKIP_UINT32(readPtr); /* referent ID; useless to us */
            response->total_shares = READ_UINT32_INTEL(readPtr);
            response->num_shares = response->total_shares;
            if (response->num_shares > response->max_shares)
            {
                response->num_shares = response->max_shares;
            }

            SKIP_UINT32(readPtr); /* referent ID; useless to us */
            SKIP_UINT32(readPtr); /* max count */
            buf_size -= 20;

            response->current_offset_from_start = (RTSMB_UINT32) PDIFF(readPtr, origin);

            response->state = NETR_SHARE_ENUM_STATE_READING_SHARE_INFO;
            response->current_share_index = 0;
            rtsmb_rpc_dce_share_info_1_reader_init (
                    &response->context.share_info_reader,
                    &response->share_info[0],
                    response->current_offset_from_start);

            /* fall through */

        case NETR_SHARE_ENUM_STATE_READING_SHARE_INFO:

            for (; response->current_share_index < response->total_shares; response->current_share_index++)
            {
                r = rtsmb_rpc_dce_share_info_1_reader_process_data (
                            &response->context.share_info_reader,
                            readPtr,
                            (long)buf_size);

                if (r < 0)
                {
                    *status = RTSMB_RPC_RESPONSE_STATUS_ERROR;
                    return -1;
                }

                readPtr += r;
                buf_size -= r;
                response->current_offset_from_start += (dword)r;

                if (!rtsmb_rpc_dce_share_info_1_reader_is_done(&response->context.share_info_reader))
                {
                    return (long) PDIFF(readPtr, buffer);
                }

                if (response->current_share_index + 1 < response->num_shares)
                {
                    rtsmb_rpc_dce_share_info_1_reader_init (
                            &response->context.share_info_reader,
                            &response->share_info[response->current_share_index + 1],
                            response->current_offset_from_start);
                }
                else
                {
                    rtsmb_rpc_dce_share_info_1_reader_init (
                            &response->context.share_info_reader,
                            &nil_info,
                            response->current_offset_from_start);
                }
            }

            response->state = NETR_SHARE_ENUM_STATE_READING_SHARE_NAME;
            response->current_share_index = 0;
            rtsmb_rpc_dce_unistr_reader_init (
                    &response->context.unistr_reader,
                    response->share_info[0].share_name_uc,
                    SMBF_FILENAMESIZE,
                    response->current_offset_from_start);

            /* fall through */

        case NETR_SHARE_ENUM_STATE_READING_SHARE_NAME:
        case NETR_SHARE_ENUM_STATE_READING_SHARE_COMMENT:

            for (; response->current_share_index < response->total_shares; response->current_share_index++)
            {
                switch (response->state)
                {
                    case NETR_SHARE_ENUM_STATE_READING_SHARE_NAME:
                        r = rtsmb_rpc_dce_unistr_reader_process_data (
                                    &response->context.unistr_reader,
                                    readPtr,
                                    buf_size);

                        if (r < 0)
                        {
                            *status = RTSMB_RPC_RESPONSE_STATUS_ERROR;
                            return -1;
                        }

                        readPtr += r;
                        buf_size -= r;
                        response->current_offset_from_start += (dword)r;

                        if (!rtsmb_rpc_dce_unistr_reader_is_done(&response->context.unistr_reader))
                        {
                            return (long) PDIFF(readPtr, buffer);
                        }

                        if (response->current_share_index < response->num_shares)
                        {
                            rtsmb_rpc_dce_unistr_reader_init (
                                    &response->context.unistr_reader,
                                    response->share_info[response->current_share_index].share_comment_uc,
                                    SMBF_FILENAMESIZE,
                                    response->current_offset_from_start);
                        }
                        else
                        {
                            rtsmb_rpc_dce_unistr_reader_init (
                                    &response->context.unistr_reader,
                                    nil_info.share_comment_uc,
                                    SMBF_FILENAMESIZE,
                                    response->current_offset_from_start);
                        }

                        response->state = NETR_SHARE_ENUM_STATE_READING_SHARE_COMMENT;

                        /* fall through */

                    case NETR_SHARE_ENUM_STATE_READING_SHARE_COMMENT:

                        r = rtsmb_rpc_dce_unistr_reader_process_data (
                                    &response->context.unistr_reader,
                                    readPtr,
                                    buf_size);

                        if (r < 0)
                        {
                            *status = RTSMB_RPC_RESPONSE_STATUS_ERROR;
                            return -1;
                        }

                        readPtr += r;
                        buf_size -= r;
                        response->current_offset_from_start += (dword)r;

                        if (!rtsmb_rpc_dce_unistr_reader_is_done(&response->context.unistr_reader))
                        {
                            return (long) PDIFF(readPtr, buffer);
                        }

                        if (response->current_share_index + 1 < response->total_shares)
                        {
                            response->state = NETR_SHARE_ENUM_STATE_READING_SHARE_NAME;
                        }

                        if (response->current_share_index + 1 < response->num_shares)
                        {
                            rtsmb_rpc_dce_unistr_reader_init (
                                    &response->context.unistr_reader,
                                    response->share_info[response->current_share_index + 1].share_name_uc,
                                    SMBF_FILENAMESIZE,
                                    response->current_offset_from_start);
                        }
                        else
                        {
                            rtsmb_rpc_dce_unistr_reader_init (
                                    &response->context.unistr_reader,
                                    nil_info.share_name_uc,
                                    SMBF_FILENAMESIZE,
                                    response->current_offset_from_start);
                        }
                        break;

                    default:
                        break;
                }
            }

            break;

        default:
            /* unknown state? */
            break;
    }

    ASSURE(buf_size >= 12, -1);
    totalEntries = READ_UINT32_INTEL(readPtr);
    enumHandle = READ_UINT32_INTEL(readPtr);
    returnCode = READ_UINT32_INTEL(readPtr);

    totalEntries = totalEntries;
    enumHandle   = enumHandle  ;
    returnCode   = returnCode  ;

    buf_size -= 12;

    *status = RTSMB_RPC_RESPONSE_STATUS_DONE;

    return (long) PDIFF(readPtr, buffer);
}

/*---------------------------------------------------------------------------*/
int rtsmb_rpc_dce_share_info_1_reader_init (
        PRTSMB_RPC_DCE_SHARE_INFO_1_READER reader,
        PRTSMB_RPC_SHARE_INFO_LEVEL_1 share_info,
        RTSMB_UINT32 offset_from_origin)
{
    reader->share_info = share_info;
    reader->last_chunk_size = 0;
    reader->done = RTSMB_FALSE;

    return 0;
}

/*---------------------------------------------------------------------------*/
RTSMB_BOOL rtsmb_rpc_dce_share_info_1_reader_is_done (
        PRTSMB_RPC_DCE_SHARE_INFO_1_READER reader)
{
    return reader->done;
}

/*---------------------------------------------------------------------------*/
long rtsmb_rpc_dce_share_info_1_reader_process_data (
        PRTSMB_RPC_DCE_SHARE_INFO_1_READER reader,
        PFBYTE data,
        long size)
{
    if (!reader->done)
    {
        RTSMB_UINT32 to_copy = RTSMB_MIN((RTSMB_UINT32) size, 12 - reader->last_chunk_size);

        RTSMB_ASSERT(reader->last_chunk_size < 12);

        rtp_memcpy(reader->last_chunk_data + reader->last_chunk_size, data, to_copy);
        reader->last_chunk_size += to_copy;
        if (reader->last_chunk_size == 12)
        {
            PFBYTE buffer = reader->last_chunk_data + 4;
            reader->share_info->share_type = READ_UINT32_INTEL(buffer);
            reader->share_info->share_name_uc[0] = 0;
            reader->share_info->share_comment_uc[0] = 0;
            reader->done = RTSMB_TRUE;
        }

        return (long)to_copy;
    }

    return 0;
}