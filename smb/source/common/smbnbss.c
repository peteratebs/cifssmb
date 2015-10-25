//
// SMBNBSS.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Process NETBIOS Session Service requests
//

#include "smbnbss.h"
#include "smbpack.h"
#include "smbread.h"
#include "smbnb.h"
#include "smbutil.h"
#if (0)
#include "smbnet.h"  /* for global port variables */
#endif

#if (0)
void rtsmb_nbss_init_port_alt (void)
{
    rtsmb_nbss_port        = RTSMB_NBSS_PORT_ALT;
    rtsmb_nbss_direct_port = RTSMB_NBSS_DIRECT_PORT_ALT;
}

void rtsmb_nbss_init_port_well_know (void)
{
    rtsmb_nbss_port        = RTSMB_NBSS_PORT;
    rtsmb_nbss_direct_port = RTSMB_NBSS_DIRECT_PORT;

}
#endif

/**
 * returns size of packet
 */
int rtsmb_nbss_fill_request (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_REQUEST pRequest)
{
    char decompressed_called [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];
    char decompressed_calling [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];
    word packet_size = RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE * 2;

    rtsmb_nb_fill_name (decompressed_called, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pRequest->called);
    rtsmb_nb_fill_name (decompressed_calling, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pRequest->calling);

    PACK_ITEM (buf, &size, decompressed_called, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);
    PACK_ITEM (buf, &size, decompressed_calling, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);

    return packet_size + RTSMB_NBSS_HEADER_SIZE;
}

/**
 * returns size of packet
 */
int rtsmb_nbss_read_request (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_REQUEST pRequest)
{
    PFVOID e, s;
    char to_compressed_name [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];
    char from_compressed_name [RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE];

    s = buf;

    READ_ITEM (buf, &size, to_compressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);
    READ_ITEM (buf, &size, from_compressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, -1);

    e = buf;

    ASSURE (rtsmb_nb_read_name (to_compressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pRequest->called) >= 0, -1);
    ASSURE (rtsmb_nb_read_name (from_compressed_name, RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE, pRequest->calling) >= 0, -1);

    return (int) PDIFF (e, s);
}


/**
 * returns size of header
 */
int rtsmb_nbss_fill_header (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_HEADER pStruct)
{
    PACK_BYTE (buf, &size, pStruct->type, -1);
    PACK_BYTE (buf, &size, (byte) ((size > 0xFFFF) ? 0x1 : 0), -1);
    PACK_WORD (buf, &size, (word) (pStruct->size & 0xFFFF), TRUE, -1);

    return RTSMB_NBSS_HEADER_SIZE;
}


/**
 * returns size of header
 */
int rtsmb_nbss_read_header (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_HEADER pStruct)
{
    byte command, flags;
    word datasize;

    READ_BYTE (buf, &size, &command, -1);
    READ_BYTE (buf, &size, &flags, -1);
    READ_WORD (buf, &size, &datasize, TRUE, -1);

    pStruct->type = command;
    pStruct->size = (dword) (datasize + (word)((flags & 0x1) ? 0xFFFF : 0));

    return RTSMB_NBSS_HEADER_SIZE;
}
