/*
|  CLSRVSVC.H - Support for RPC interface SRVSVC (Microsoft Server Services),
|               including NetrShareEnum
| 
|  EBSnet - RTSMB embedded SMB/CIFS client and server
| 
|  Copyright EBS Inc. , 2005
|  All rights reserved.
|  This code may not be redistributed in source or linkable object form
|  without the consent of its author.
*/ 

#ifndef __CLSRVSVC_H__
#define __CLSRVSVC_H__

#include "smbdefs.h"
#include "smbnb.h"
#include "clirpc.h"

/* Operation numbers for all functions available on SRVSVC interface */

#define RTSMB_RPC_SRVSVC_NETR_CHAR_DEV_ENUM                0x00
#define RTSMB_RPC_SRVSVC_NETR_CHAR_DEV_GET_INFO            0x01
#define RTSMB_RPC_SRVSVC_NETR_CHAR_DEV_CONTROL             0x02
#define RTSMB_RPC_SRVSVC_NETR_CHAR_DEV_QENUM               0x03
#define RTSMB_RPC_SRVSVC_NETR_CHAR_DEV_QGET_INFO           0x04
#define RTSMB_RPC_SRVSVC_NETR_CHAR_DEV_QSET_INFO           0x05
#define RTSMB_RPC_SRVSVC_NETR_CHAR_DEV_QPURGE              0x06
#define RTSMB_RPC_SRVSVC_NETR_CHAR_DEV_QPURGE_SELF         0x07
#define RTSMB_RPC_SRVSVC_NETR_CONNECTION_ENUM              0x08
#define RTSMB_RPC_SRVSVC_NETR_FILE_ENUM                    0x09
#define RTSMB_RPC_SRVSVC_NETR_FILE_GET_INFO                0x0a
#define RTSMB_RPC_SRVSVC_NETR_FILE_CLOSE                   0x0b
#define RTSMB_RPC_SRVSVC_NETR_SESSION_ENUM                 0x0c
#define RTSMB_RPC_SRVSVC_NETR_SESSION_DEL                  0x0d
#define RTSMB_RPC_SRVSVC_NETR_SHARE_ADD                    0x0e
#define RTSMB_RPC_SRVSVC_NETR_SHARE_ENUM                   0x0f
#define RTSMB_RPC_SRVSVC_NETR_SHARE_GET_INFO               0x10
#define RTSMB_RPC_SRVSVC_NETR_SHARE_SET_INFO               0x11
#define RTSMB_RPC_SRVSVC_NETR_SHARE_DEL                    0x12
#define RTSMB_RPC_SRVSVC_NETR_SHARE_DEL_STICKY             0x13
#define RTSMB_RPC_SRVSVC_NETR_SHARE_CHECK                  0x14
#define RTSMB_RPC_SRVSVC_NETR_SERVER_GET_INFO              0x15
#define RTSMB_RPC_SRVSVC_NETR_SERVER_SET_INFO              0x16
#define RTSMB_RPC_SRVSVC_NETR_SERVER_DISK_ENUM             0x17
#define RTSMB_RPC_SRVSVC_NETR_SERVER_STATISTICS_GET        0x18
#define RTSMB_RPC_SRVSVC_NETR_SERVER_TRANSPORT_ADD         0x19
#define RTSMB_RPC_SRVSVC_NETR_SERVER_TRANSPORT_ENUM        0x1a
#define RTSMB_RPC_SRVSVC_NETR_SERVER_TRANSPORT_DEL         0x1b
#define RTSMB_RPC_SRVSVC_NETR_REMOTE_TOD                   0x1c
#define RTSMB_RPC_SRVSVC_NETR_SERVER_SET_SERVICE_BITS      0x1d
#define RTSMB_RPC_SRVSVC_NETPR_PATH_TYPE                   0x1e
#define RTSMB_RPC_SRVSVC_NETPR_PATH_CANONICALIZE           0x1f
#define RTSMB_RPC_SRVSVC_NETPR_PATH_COMPARE                0x20
#define RTSMB_RPC_SRVSVC_NETPR_NAME_VALIDATE               0x21
#define RTSMB_RPC_SRVSVC_NETPR_NAME_CANONICALIZE           0x22
#define RTSMB_RPC_SRVSVC_NETPR_NAME_COMPARE                0x23
#define RTSMB_RPC_SRVSVC_NETR_SHARE_ENUM_STICKY            0x24
#define RTSMB_RPC_SRVSVC_NETR_SHARE_DEL_START              0x25
#define RTSMB_RPC_SRVSVC_NETR_SHARE_DEL_COMMIT             0x26
#define RTSMB_RPC_SRVSVC_NETRP_GET_FILE_SECURITY           0x27
#define RTSMB_RPC_SRVSVC_NETRP_SET_FILE_SECURITY           0x28
#define RTSMB_RPC_SRVSVC_NETR_SERVER_TRANSPORT_ADD_EX      0x29
#define RTSMB_RPC_SRVSVC_NETR_SERVER_SET_SERVICE_BITS_EX   0x2a
#define RTSMB_RPC_SRVSVC_NETR_DFS_GET_VERSION              0x2b
#define RTSMB_RPC_SRVSVC_NETR_DFS_CREATE_LOCAL_PARTITION   0x2c   /* > Windows 2000	*/
#define RTSMB_RPC_SRVSVC_NETR_DFS_DELETE_LOCAL_PARTITION   0x2d
#define RTSMB_RPC_SRVSVC_NETR_DFS_SET_LOCAL_VOLUME_STATE   0x2e
#define RTSMB_RPC_SRVSVC_NETR_DFS_SET_SERVER_INFO          0x2f
#define RTSMB_RPC_SRVSVC_NETR_DFS_CREATE_EXIT_POINT        0x30
#define RTSMB_RPC_SRVSVC_NETR_DFS_DELETE_EXIT_POINT        0x31
#define RTSMB_RPC_SRVSVC_NETR_DFS_MODIFY_PREFIX            0x32
#define RTSMB_RPC_SRVSVC_NETR_DFS_FIX_LOCAL_VOLUME         0x33
#define RTSMB_RPC_SRVSVC_NETR_DFS_MANAGER_REPORT_SITE_INFO 0x34
#define RTSMB_RPC_SRVSVC_NETR_SERVER_TRANSPORT_DEL_EX      0x35   /* > Windows XP and Windows Server 2003 */

typedef struct
{
	RTSMB_UINT16 server_name_uc[RTSMB_NB_NAME_SIZE+1];
}
RTSMB_RPC_NETR_SHARE_ENUM_REQUEST;
typedef RTSMB_RPC_NETR_SHARE_ENUM_REQUEST RTSMB_FAR * PRTSMB_RPC_NETR_SHARE_ENUM_REQUEST;

typedef struct
{
	RTSMB_UINT16 share_name_uc[SMBF_FILENAMESIZE+1];
	RTSMB_UINT32 share_type;
	RTSMB_UINT16 share_comment_uc[SMBF_FILENAMESIZE+1];
}
RTSMB_RPC_SHARE_INFO_LEVEL_1;
typedef RTSMB_RPC_SHARE_INFO_LEVEL_1 RTSMB_FAR * PRTSMB_RPC_SHARE_INFO_LEVEL_1;

typedef enum
{
	NETR_SHARE_ENUM_STATE_READING_HEADER,
	NETR_SHARE_ENUM_STATE_READING_SHARE_INFO,
	NETR_SHARE_ENUM_STATE_READING_SHARE_NAME,
	NETR_SHARE_ENUM_STATE_READING_SHARE_COMMENT,
	NETR_SHARE_ENUM_NUM_STATES
}
RTSMB_RPC_NETR_SHARE_ENUM_STATE;

typedef struct 
{
	PRTSMB_RPC_SHARE_INFO_LEVEL_1 share_info;
	RTSMB_UINT8  last_chunk_data[12];
	RTSMB_UINT32 last_chunk_size;
	RTSMB_BOOL   done;
}
RTSMB_RPC_DCE_SHARE_INFO_1_READER;
typedef RTSMB_RPC_DCE_SHARE_INFO_1_READER RTSMB_FAR * PRTSMB_RPC_DCE_SHARE_INFO_1_READER;

typedef struct
{
	RTSMB_UINT32                    max_shares;   /* input: size of share_info array */
	RTSMB_UINT32                    num_shares;   /* output: number of shares returned */
	RTSMB_UINT32                    total_shares; /* output: number of shares present on 
	                                                  the server; may be larger than 
	                                                  maxShares (this indicates there 
	                                                  was not enough space to hold all
	                                                  share info) */
	PRTSMB_RPC_SHARE_INFO_LEVEL_1   share_info;   /* pointer to array of share info structs
	                                                  (receives output of NetrShareEnum) */
	                                              
	/* fields below this line are used internally and should not
	    be modified or read by outside code */
	
	/* we'll make it a requirement that the standard level 1 share info header
	    has to fit in the default size buffer, so we just need to store our state 
	    inside the loops where the share list is read. */
	    
	RTSMB_RPC_NETR_SHARE_ENUM_STATE state;
	RTSMB_UINT32                    current_offset_from_start;
	RTSMB_UINT32                    current_share_index;
	union
	{
		RTSMB_RPC_DCE_SHARE_INFO_1_READER share_info_reader;
		RTSMB_RPC_DCE_UNISTR_READER       unistr_reader;
	}
	context;
}
RTSMB_RPC_NETR_SHARE_ENUM_RESPONSE;
typedef RTSMB_RPC_NETR_SHARE_ENUM_RESPONSE RTSMB_FAR * PRTSMB_RPC_NETR_SHARE_ENUM_RESPONSE;


#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------
	prtsmb_srvsvc_pipe_name, prtsmb_srvsvc_info - 
		
		Data pointers used to initialize a named pipe for invoking RPCs to the 
		Microsoft Server Service (SRVSVC) interface.  
	
	Example: 
		
		(this example assumes that a session has already been established with 
		 the server, and that that session's identifier is stored in sid; for
		 the definition of wait_on_job, see the RTSMB client test application)
		
		int fid, jid;
		
		jid = rtsmb_cli_rpc_open_interface (sid, prtsmb_srvsvc_pipe_name, 
		                                    prtsmb_srvsvc_info, &fid);
		if (wait_on_job(sid, jid) >= 0)
		{			
			// invoke one or more RPC's here
			
			rtsmb_cli_rpc_close_interface (sid, fid);
		}				
		
 ---------------------------------------------------------------------------- */
extern PFRTCHAR              prtsmb_srvsvc_pipe_name;
extern PRTSMB_RPC_IFACE_INFO prtsmb_srvsvc_info;

/* ----------------------------------------------------------------------------
	rtsmb_cli_rpc_NetrShareEnum_init,
	rtsmb_cli_rpc_NetrShareEnum_request,
	rtsmb_cli_rpc_NetrShareEnum_response - 
		
		Utility data/functions passed into rtsmb_cli_rpc_invoke to invoke the
		NetrShareEnum function to enumerate the shares on a server.
	
	Example: 
		
		(this example assumes that a session has been established with the 
		 server, and that a named pipe has been opened and bound to the 
		 SRVSVC interface for RPC use; see above for an example of how
		 to perform the necessary initialization)
		
		RTSMB_RPC_SHARE_INFO_LEVEL_1 shareInfoArray[16];
		RTSMB_RPC_NETR_SHARE_ENUM_REQUEST request;
		RTSMB_RPC_NETR_SHARE_ENUM_RESPONSE response;
		
		// initialize the request parameters
		wcscpy(request.server_name_uc, L"\\my_server");
		
		// initialize the response parameters
		response.max_shares = 16;
		response.share_info = shareInfoArray;
		
		// initialize private data for request and response
		rtsmb_cli_rpc_NetrShareEnum_init(&request, &response);
		
		jid = rtsmb_cli_rpc_invoke(sid, fid, RTSMB_RPC_SRVSVC_NETR_SHARE_ENUM,
		                     rtsmb_cli_rpc_NetrShareEnum_request, &request,
		                     rtsmb_cli_rpc_NetrShareEnum_response, &response);
		                     
		if (wait_on_job(sid, jid) < 0)
		{
			// handle error case here
		}
		else
		{
			// the operation was successful; read the collected share data

			int i;
			
			for (i = 0; i < response.num_shares; i++)
			{
				printf("Share found; name%S, type=%08x, comment=%S\n", 
						shareInfoArray[i].share_name_uc,
						shareInfoArray[i].share_type,
						shareInfoArray[i].share_comment_uc);
			}
		}		
		
 ---------------------------------------------------------------------------- */
void rtsmb_cli_rpc_NetrShareEnum_init     (PFVOID request_data, PFVOID response_data);

long rtsmb_cli_rpc_NetrShareEnum_request  (PFBYTE origin, PFBYTE buffer, long buf_size, 
		                                   PFVOID param_data, PFINT status);

long rtsmb_cli_rpc_NetrShareEnum_response (PFBYTE origin, PFBYTE buffer, long buf_size, 
		                                   PFVOID param_data, PFINT status);

#ifdef __cplusplus
}
#endif

#endif /* __CLSRVSVC_H__ */
