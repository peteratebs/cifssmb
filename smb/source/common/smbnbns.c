//
// SMBNBNS.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Process NETBIOS Naming Service requests
//

#include "smbnbns.h"
#include "smbpack.h"
#include "smbread.h"
#include "smbnb.h"
#include "smbutil.h"
#include "smbnet.h"
#include "rtptime.h"
#include "smbdebug.h"

/**
 * These rtsmb_nbns_fill_* and rtsmb_nbns_read_* functions operate on buffers,
 * reading or filling them out as required into structs.
 */

/**
 * returns size of header
 */
int rtsmb_nbns_fill_header (PFVOID buf, rtsmb_size size,
    PFVOID origin, PRTSMB_NBNS_HEADER pHeader)
{
    PFVOID e, s;

    s = buf;

    PACK_WORD (buf, &size, pHeader->id, TRUE, -1);
    PACK_WORD (buf, &size, pHeader->flags, TRUE, -1);
    PACK_WORD (buf, &size, pHeader->question_count, TRUE, -1);
    PACK_WORD (buf, &size, pHeader->answer_count, TRUE, -1);
    PACK_WORD (buf, &size, pHeader->authority_count, TRUE, -1);
    PACK_WORD (buf, &size, pHeader->additional_count, TRUE, -1);

    e = buf;

    return (int) PDIFF (e, s);
}


/**
 * returns size of header
 */
int rtsmb_nbns_read_header (PFVOID buf, rtsmb_size size,
    PFVOID origin, PRTSMB_NBNS_HEADER pHeader)
{
    PFVOID e, s;

    s = buf;

    READ_WORD (buf, &size, &pHeader->id, TRUE, -1);
    READ_WORD (buf, &size, &pHeader->flags, TRUE, -1);
    READ_WORD (buf, &size, &pHeader->question_count, TRUE, -1);
    READ_WORD (buf, &size, &pHeader->answer_count, TRUE, -1);
    READ_WORD (buf, &size, &pHeader->authority_count, TRUE, -1);
    READ_WORD (buf, &size, &pHeader->additional_count, TRUE, -1);

    e = buf;

    return (int) PDIFF (e, s);
}


/**
 * returns size of question
 */
int rtsmb_nbns_fill_question (PFVOID buf, rtsmb_size size,
    PFVOID origin, PRTSMB_NBNS_QUESTION pQuestion)
{
    PFVOID e, s;
    char decompressed_name [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];

    rtsmb_nb_fill_name (decompressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pQuestion->name);

    s = buf;

    PACK_ITEM (buf, &size, decompressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);
    PACK_WORD (buf, &size, pQuestion->type, TRUE, -1);
    PACK_WORD (buf, &size, pQuestion->class, TRUE, -1);

    e = buf;

    return (int) PDIFF (e, s);
}


/**
 * returns size of question
 */
int rtsmb_nbns_read_question (PFVOID buf, rtsmb_size size,
    PFVOID origin, PRTSMB_NBNS_QUESTION pQuestion)
{
    PFVOID e, s;
    char decompressed_name [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];

    s = buf;

    READ_ITEM (buf, &size, decompressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);
    READ_WORD (buf, &size, &pQuestion->type, TRUE, -1);
    READ_WORD (buf, &size, &pQuestion->class, TRUE, -1);

    e = buf;

    ASSURE (rtsmb_nb_read_name (decompressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pQuestion->name) >= 0, -1);

    return (int) PDIFF (e, s);
}


/**
 * returns size of resource
 */
int rtsmb_nbns_fill_resource (PFVOID buf, rtsmb_size size,
    PFVOID origin, PRTSMB_NBNS_RESOURCE pResource)
{
    PFVOID e, s;

    s = buf;

    if (pResource->pointer)
    {
        /* name is a pointer to a previous name instead of full name */
        PACK_WORD (buf, &size, 0xc00c, TRUE, -1);
    }
    else
    {
        char decompressed_name [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];

        rtsmb_nb_fill_name (decompressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pResource->name);

        PACK_ITEM (buf, &size, decompressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);
    }
    PACK_WORD (buf, &size, pResource->type, TRUE, -1);
    PACK_WORD (buf, &size, pResource->class, TRUE, -1);
    PACK_DWORD (buf, &size, pResource->time_to_live, TRUE, -1);
    PACK_WORD (buf, &size, pResource->data_size, TRUE, -1);
    PACK_ITEM (buf, &size, pResource->data, pResource->data_size, -1);

    e = buf;

    return (int) PDIFF (e, s);
}


/**
 * returns size of resource
 */
int rtsmb_nbns_read_resource (PFVOID buf, rtsmb_size size,
    PFVOID origin, PRTSMB_NBNS_RESOURCE pResource)
{
    PFVOID e, s;
    char compressed_name [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];
    word data_size, w;

    s = buf;

    READ_WORD (buf, &size, &w, TRUE, -1);

    if (w == 0xc00c)    /* it is a pointer to previous name */
    {
        PFVOID tmp = buf;
        rtsmb_size tmp_size;

        /* if we aren't past 0xc00c yet, bail because this is malformed */
        ASSURE (PDIFF (buf, origin) >= 0xc00c + RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);

        tmp_size = RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE;
        READ_ITEM (tmp, &tmp_size, compressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);
    }
    else
    {
        /* reset our pointer in the buf to before the word we read */
        buf = PADD (buf, -2);
        size += 2;
        READ_ITEM (buf, &size, compressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);
    }
    READ_WORD (buf, &size, &pResource->type, TRUE, -1);
    READ_WORD (buf, &size, &pResource->class, TRUE, -1);
    READ_DWORD (buf, &size, &pResource->time_to_live, TRUE, -1);
    READ_WORD (buf, &size, &data_size, TRUE, -1);

    ASSURE (data_size <= pResource->data_size, -1);

    READ_ITEM (buf, &size, pResource->data, data_size, -1);
    pResource->data_size = data_size;

    e = buf;

    ASSURE (rtsmb_nb_read_name (compressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pResource->name) >= 0, -1);

    return (int) PDIFF (e, s);
}


int rtsmb_nbns_fill_name_query (PFVOID buf, rtsmb_size size, word id, PFCHAR name, byte name_type)
{
    RTSMB_NBNS_HEADER header;
    RTSMB_NBNS_QUESTION question;
    PFVOID tmp = buf;
    int r;

    header.id = id;
    header.flags = 0x0110;
    header.question_count = 1;
    header.answer_count = 0;
    header.authority_count = 0;
    header.additional_count = 0;

    rtsmb_util_make_netbios_name (question.name, name, name_type);
    question.type = RTSMB_NBNS_TYPE_NB;
    question.class = RTSMB_NBNS_CLASS_IN;

    r = rtsmb_nbns_fill_header (tmp, size, buf, &header);
    ASSURE (r >= 0, -1);
    tmp = PADD (tmp, r);
    size -= (rtsmb_size)r;

    r = rtsmb_nbns_fill_question (tmp, size, buf, &question);
    ASSURE (r >= 0, -1);
    tmp = PADD (tmp, r);

    return (int) PDIFF (tmp, buf);
}


/* returns 0 if response is negative and no data was written to ip */
/* returns n if response is positive and [n] entries were written to info */
/* returns -1 if there was a problem reading response */

int rtsmb_nbns_read_name_query_response (
        PFVOID buf,
        rtsmb_size size,
        PRTSMB_NBNS_NAME_INFO info,
        int max_entries)
{
    RTSMB_NBNS_HEADER header;
    RTSMB_NBNS_RESOURCE resource;
    PFVOID tmp = buf;
    int r;
    int n, i;
    rtsmb_size data_size = 50;
    byte data[50];

    resource.data = data;
    resource.data_size = 50;

    r = rtsmb_nbns_read_header (tmp, size, buf, &header);
    ASSURE (r >= 0, -1);
    tmp = PADD (tmp, r);
    size -= (rtsmb_size) r;

    r = rtsmb_nbns_read_resource (tmp, size, buf, &resource);
    ASSURE (r >= 0, -1);
    tmp = PADD (tmp, r);
    size -= (rtsmb_size) r;

    if (resource.data_size == 0)
    {
        return 0;   /* negative response */
    }

    n = resource.data_size;
    if (n % 6 != 0)
    {
        /* malformed; each entry should be exactly 6 bytes long */
        return -1;
    }

    tmp = data;
    for (i = 0; i < (n/6); i++)
    {
        READ_WORD (tmp, &data_size, &info[i].flags, TRUE, -1);
        READ_ITEM (tmp, &data_size, &info[i].ip_addr, 4, -1);
    }

    return (n/6);
}

static RTSMB_BOOL _send_query (PRTSMB_NBNS_NAME_QUERY query)
{
    byte buffer [50];
    int r;
    word id;

    id = (word) (((RTP_ADDR) query) & 0xFFFF);
    r = rtsmb_nbns_fill_name_query (buffer, 50, id, query->name, RTSMB_NB_NAME_TYPE_SERVER);

    if (r > 0)
    {
        if (rtp_net_sendto (query->sock,
                            buffer,
                            r,
                            rtsmb_net_get_broadcast_ip(),
                            rtsmb_nbns_port,
                            4) == r)
        {
            query->start_time_msec = (long)rtp_get_system_msec();
            return 1;
        }
    }

    return 0;
}

int  rtsmb_nbns_query_name (PRTSMB_NBNS_NAME_QUERY query, PFCHAR name)
{
    query->status = RTSMB_NBNS_QUERY_STATUS_CLOSED;

    if (rtp_net_socket_datagram(&query->sock) >= 0)
    {
        if (rtp_net_setbroadcast(query->sock, 1) >= 0)
        {
            query->name = name;
            if (_send_query(query))
            {
                query->timeout_msec = RTSMB_NB_BCAST_RETRY_TIMEOUT;
                query->retries_left = RTSMB_NB_BCAST_RETRY_COUNT;
                query->status = RTSMB_NBNS_QUERY_STATUS_PENDING;
                return 0;
            }
        }
        rtp_net_closesocket(query->sock);
    }

    return -1;
}

void rtsmb_nbns_query_cycle (PRTSMB_NBNS_NAME_QUERY queryList, int listSize, long msecTimeout)
{
    int n;
    long queryMsecRemaining;
    long currentTimeMsec;
    RTP_FD_SET readList;
    RTP_FD_SET errList;
    int result;
    int do_select = 0;

    rtp_fd_zero(&readList);
    rtp_fd_zero(&errList);

    currentTimeMsec = (long)rtp_get_system_msec();

    for (n = 0; n < listSize; n++)
    {
        if (queryList[n].status == RTSMB_NBNS_QUERY_STATUS_PENDING)
        {
            queryMsecRemaining = queryList[n].timeout_msec - (currentTimeMsec - queryList[n].start_time_msec);
            if (msecTimeout > queryMsecRemaining)
            {
                msecTimeout = queryMsecRemaining;
            }

            rtp_fd_set(&readList, queryList[n].sock);
            rtp_fd_set(&errList, queryList[n].sock);
            do_select = 1;
        }
    }

    if (do_select)
    {
        if (msecTimeout < 0)
        {
            msecTimeout = 0;
        }

        result = rtp_net_select(&readList, 0, &errList, msecTimeout);
        if (result < 0)
        {
            RTSMB_DEBUG_OUTPUT_STR ("rtp_net_select: Error in rtsmb_nbns_query_cycle", RTSMB_DEBUG_TYPE_ASCII);
        }


        for (n = 0; n < listSize; n++)
        {
            if (rtp_fd_isset(&errList, queryList[n].sock))
            {
                queryList[n].status = RTSMB_NBNS_QUERY_STATUS_ERROR;
                continue;
            }

            if (rtp_fd_isset(&readList, queryList[n].sock))
            {
                queryList[n].status = RTSMB_NBNS_QUERY_STATUS_RESOLVED;
                continue;
            }

            if (IS_PAST(queryList[n].start_time_msec, queryList[n].timeout_msec))
            {
                if (queryList[n].retries_left > 0)
                {
                    queryList[n].retries_left--;
                    if (!_send_query(&queryList[n]))
                    {
                        queryList[n].status = RTSMB_NBNS_QUERY_STATUS_ERROR;
                    }
                }
                else
                {
                    queryList[n].status = RTSMB_NBNS_QUERY_STATUS_TIMEOUT;
                }
            }
        }
    }
}

int  rtsmb_nbns_get_name_query_response (PRTSMB_NBNS_NAME_QUERY query, PRTSMB_NBNS_NAME_INFO info, int max_entries)
{
    byte temp_buffer [RTSMB_NB_MAX_DATAGRAM_SIZE];
    long r;

    if (query->status != RTSMB_NBNS_QUERY_STATUS_RESOLVED)
    {
        return -1;
    }

    r = rtp_net_recv(query->sock, temp_buffer, RTSMB_NB_MAX_DATAGRAM_SIZE);

    if (r < 0)
    {
        query->status = RTSMB_NBNS_QUERY_STATUS_ERROR;
        return -1;
    }

    return rtsmb_nbns_read_name_query_response(temp_buffer, RTSMB_NB_MAX_DATAGRAM_SIZE, info, max_entries);
}

void rtsmb_nbns_close_query (PRTSMB_NBNS_NAME_QUERY query)
{
    if (query->status != RTSMB_NBNS_QUERY_STATUS_CLOSED)
    {
        rtp_net_closesocket(query->sock);
        query->status = RTSMB_NBNS_QUERY_STATUS_CLOSED;
    }
}
