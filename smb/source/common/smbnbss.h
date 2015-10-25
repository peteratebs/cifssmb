
#ifndef __SMB_NBSS_H__
#define __SMB_NBSS_H__

#include "smbdefs.h"
#include "smbnb.h"

#define RTSMB_NBSS_COM_MESSAGE            0x00
#define RTSMB_NBSS_COM_REQUEST            0x81
#define RTSMB_NBSS_COM_POSITIVE_RESPONSE  0x82
#define RTSMB_NBSS_COM_NEGATIVE_RESPONSE  0x83

#define RTSMB_NBSS_DIRECT_PORT_ALT        9445 
#define RTSMB_NBSS_PORT_ALT               9139 
#define RTSMB_NBSS_DIRECT_PORT            445  // well-known port number
#define RTSMB_NBSS_PORT                   139  // well-known port number

#define RTSMB_NBSS_HEADER_SIZE            4

#define RTSMB_NBNS_CLOSE_TIMEOUT          30000  /* in milliseconds */
//#define RTSMB_NBNS_KEEP_ALIVE_TIMEOUT     60000  /* in milliseconds */
#define RTSMB_NBNS_KEEP_ALIVE_TIMEOUT     30000  /* in milliseconds */
#define RTSMB_NBNS_RETRY_COUNT            4


typedef struct
{
	byte type;
	dword size;
} RTSMB_NBSS_HEADER;
typedef RTSMB_NBSS_HEADER RTSMB_FAR *PRTSMB_NBSS_HEADER;

typedef struct
{
	char calling [RTSMB_NB_NAME_SIZE + 1];
	char called [RTSMB_NB_NAME_SIZE + 1];
} RTSMB_NBSS_REQUEST;
typedef RTSMB_NBSS_REQUEST RTSMB_FAR *PRTSMB_NBSS_REQUEST;

void rtsmb_nbss_init_port_alt (void);
void rtsmb_nbss_init_port_well_know (void);

int rtsmb_nbss_fill_request (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_REQUEST pRequest);
int rtsmb_nbss_read_request (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_REQUEST pRequest);

int rtsmb_nbss_fill_header (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_HEADER pStruct);
int rtsmb_nbss_read_header (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_HEADER pStruct);


#endif /* __SMB_NBSS_H__ */
