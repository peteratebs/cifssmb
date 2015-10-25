#ifndef __SMB_NB_H__
#define __SMB_NB_H__

/* these are the defaults recommended by rfc's 1001 and 1002 */
#define RTSMB_NB_BCAST_RETRY_TIMEOUT              250L  /* in milliseconds */
#define RTSMB_NB_BCAST_RETRY_COUNT                3
#define RTSMB_NB_UCAST_RETRY_TIMEOUT              5000L /* in milliseconds */
#define RTSMB_NB_UCAST_RETRY_COUNT                3

#define RTSMB_NB_MAX_DATAGRAM_SIZE                576  /* in bytes */

#define RTSMB_NB_NAME_SIZE                        16
#define RTSMB_NB_DECOMPRESSED_NAME_BUFFER_SIZE    (RTSMB_NB_NAME_SIZE * 2 + 2)

#define RTSMB_NB_DEFAULT_NAME                     "*SMBSERVER"
#define RTSMB_NB_MASTER_BROWSER_NAME              "\1\2__MSBROWSE__\2\1"

#define RTSMB_NB_NAME_TYPE_WORKSTATION            0x00
#define RTSMB_NB_NAME_TYPE_MESSENGER              0x03
#define RTSMB_NB_NAME_TYPE_SERVER                 0x20
#define RTSMB_NB_NAME_TYPE_MASTER_BROWSER         0x1D
#define RTSMB_NB_NAME_TYPE_ELECTION_SERVICE       0x1E



int rtsmb_nb_fill_name (PFVOID buf, rtsmb_size size, PFCHAR name);
int rtsmb_nb_read_name (PFVOID buf, rtsmb_size size, PFCHAR dest);


#endif /* __SMB_NB_H__ */
