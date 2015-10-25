#ifndef __CLI_WIRE_H__
#define __CLI_WIRE_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_CLIENT)

#include "smbobjs.h"
#include "clicmds.h"
#include "clians.h"
#include "smbnbss.h"
#include "smbnbns.h"
#include "rtpnet.h"
#include "smbconf.h"


/* error codes */
#define RTSMB_CLI_WIRE_ERROR_BAD_STATE	-50
#define RTSMB_CLI_WIRE_TOO_MANY_REQUESTS	-51
#define RTSMB_CLI_WIRE_BAD_MID			-52


#define RTSMB_CLI_WIRE_MAX_BUFFER_SIZE	(prtsmb_cli_ctx->buffer_size - RTSMB_NBSS_HEADER_SIZE)


typedef enum
{
	DEAD,
	UNCONNECTED,
	CONNECTED,
	NBS_CONNECTED
} RTSMB_CLI_WIRE_SESSION_STATE;

typedef enum
{
	UNUSED,
	BEING_FILLED,
	WAITING_ON_SERVER,
	WAITING_ON_US,
	TIMEOUT,
	DONE
} RTSMB_CLI_WIRE_BUFFER_STATE;

#define INFO_CAN_TIMEOUT	     0x0001  /* can this request time out? */
#define INFO_CHAINED_ZERO_COPY   0x0002  /* this buffer includes a second section
                                            marked as 'zero-copy' for inclusion when
                                            sent on the wire */
typedef struct RTSMB_CLI_WIRE_BUFFER_s
{
	word flags;	/* flags about this buffer */

	RTSMB_CLI_WIRE_BUFFER_STATE state;

	word mid;

	unsigned long end_time_base;	/* time when this will be considered timed out */

	PFVOID last_section;	/* used for andx requests */
	PFVOID buffer_end;

	PFBYTE     attached_data;
	rtsmb_size attached_size;

	rtsmb_size buffer_size;
	PFBYTE buffer;

    rtsmb_size allocated_buffer_size; /* Added for SMB2 */
#ifdef SUPPORT_SMB2
    smb2_stream smb2stream;
#endif

} RTSMB_CLI_WIRE_BUFFER;
typedef RTSMB_CLI_WIRE_BUFFER RTSMB_FAR *PRTSMB_CLI_WIRE_BUFFER;


typedef struct RTSMB_CLI_WIRE_SESSION_s
{
	RTP_SOCKET socket;	/* socket into which all data is sent */

	byte server_ip [4];	/* ip of server */
	char server_name [RTSMB_NB_NAME_SIZE + 1]; /* name of server */

	word next_mid;

	RTSMB_CLI_WIRE_SESSION_STATE state;	/* the state that we are in */

	int num_nbss_sent;
	unsigned long temp_end_time_base;	/* timeout for personal things, like netbios layer */

	PFBYTE temp_buffer;

	BBOOL reading; /* TRUE if we are in the middle of reading a packet */
	rtsmb_size total_to_read; /* how big the currently being read packet is */
	rtsmb_size total_read; /* how much we have read so far */

	/* our buffers */
	PRTSMB_CLI_WIRE_BUFFER buffers;

	/* boolean - set to non-zero if NOT using NetBIOS session service as transport layer */
	int usingSmbOverTcp;

	/* data related to connect state machine */
	int nbssStatus;
	int tcpStatus;
	unsigned long startMsec;
	RTP_SOCKET nbssAttempt;
	RTP_SOCKET tcpAttempt;
	int tryingSmbOverTcp;

	unsigned long physical_packet_size;

} RTSMB_CLI_WIRE_SESSION;
typedef RTSMB_CLI_WIRE_SESSION RTSMB_FAR *PRTSMB_CLI_WIRE_SESSION;


typedef enum
{
	NON_EXISTANT,
	WAITING,
	TIMED_OUT,
	FINISHED
} RTSMB_CLI_MESSAGE_STATE;


int rtsmb_cli_wire_session_new (PRTSMB_CLI_WIRE_SESSION pSession, PFCHAR name, PFBYTE ip, int blocking);
int rtsmb_cli_wire_session_close (PRTSMB_CLI_WIRE_SESSION pSession);
int rtsmb_cli_wire_connect_cycle (PRTSMB_CLI_WIRE_SESSION pSession);

RTSMB_CLI_MESSAGE_STATE rtsmb_cli_wire_check_message (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

int rtsmb_cli_wire_cycle (PRTSMB_CLI_WIRE_SESSION pSession, long timeout);

/* adding stuff to a session sends data to the server */
int rtsmb_cli_wire_smb_add_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

int rtsmb_cli_wire_smb_add_header (PRTSMB_CLI_WIRE_SESSION pSession, word mid,
	PRTSMB_HEADER pHeader);
#ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
int rtsmb_cli_wire_smb_add_data (PRTSMB_CLI_WIRE_SESSION pSession, word mid, PFBYTE data, long size);
#endif
int rtsmb_cli_wire_smb_add_end (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

/* reading stuff from a session reads data from the server */
int rtsmb_cli_wire_smb_read_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid);
int rtsmb_cli_wire_smb_read_header (PRTSMB_CLI_WIRE_SESSION pSession, word mid,
	PRTSMB_HEADER pHeader);
int rtsmb_cli_wire_smb_read_end (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

int rtsmb_cli_wire_smb_close (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

/* DON'T USE THIS FUNCTION -- internal use only */
PRTSMB_CLI_WIRE_BUFFER rtsmb_cli_wire_get_buffer (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

/* would like to make these not defined globally */
#define rtsmb_cli_wire_smb_add(pSession, mid, pFunction, pStruct, rv)\
{\
	PRTSMB_CLI_WIRE_BUFFER pBuffer;\
	RTSMB_HEADER header;\
	int r;\
	rv = 0;\
	\
	pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);\
	\
	if (!pBuffer)\
		rv = RTSMB_CLI_WIRE_BAD_MID;\
	\
	if (rv == 0)\
	{\
		r = cli_cmd_read_header (PADD (pBuffer->buffer, RTSMB_NBSS_HEADER_SIZE),\
		                         PADD (pBuffer->buffer, RTSMB_NBSS_HEADER_SIZE),\
		                         prtsmb_cli_ctx->buffer_size - RTSMB_NBSS_HEADER_SIZE, &header);\
		\
		if (r >= 0)\
		{\
			r = pFunction (PADD (pBuffer->buffer, RTSMB_NBSS_HEADER_SIZE), pBuffer->buffer_end,\
			               prtsmb_cli_ctx->buffer_size - (rtsmb_size) PDIFF (pBuffer->buffer_end, pBuffer->buffer),\
			               &header, pStruct);\
			\
			if (r < 0)\
				rv = -3;\
			else\
			{\
				pBuffer->last_section = pBuffer->buffer_end;\
				pBuffer->buffer_end = PADD (pBuffer->buffer_end, r);\
				pBuffer->buffer_size = (rtsmb_size) PDIFF (pBuffer->buffer_end, pBuffer->buffer);\
			}\
		}\
		else\
		{\
			rv = -3;\
		}\
	}\
}

#define rtsmb_cli_wire_smb_read(pSession, mid, pFunction, pStruct, rv)\
{\
	PRTSMB_CLI_WIRE_BUFFER pBuffer;\
	RTSMB_HEADER header;\
	int r;\
	rv = 0;\
	\
	pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);\
	\
	if (!pBuffer)\
		rv = RTSMB_CLI_WIRE_BAD_MID;\
	\
	if (rv == 0)\
	{\
		r = cli_cmd_read_header (pBuffer->buffer, pBuffer->buffer,\
			prtsmb_cli_ctx->buffer_size, &header);\
		\
		if (r >= 0)\
		{\
			r = pFunction (pBuffer->buffer, pBuffer->buffer_end,\
				pBuffer->buffer_size,\
				&header, pStruct);\
			\
			if (r < 0)\
				rv = -3;\
			else\
			{\
				pBuffer->last_section = pBuffer->buffer_end;\
				pBuffer->buffer_end = PADD (pBuffer->buffer_end, r);\
				pBuffer->buffer_size -= (dword)r;\
			}\
		}\
		else\
		{\
			rv = -3;\
		}\
	}\
}

#endif /* INCLUDE_RTSMB_CLIENT */

#endif /* __CLI_WIRE_H__ */
