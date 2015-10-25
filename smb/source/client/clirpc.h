/*
|  CLIRPC.H - 
| 
|  EBSnet - RTSMB embedded SMB/CIFS client and server
| 
|  Copyright EBS Inc. , 2005
|  All rights reserved.
|  This code may not be redistributed in source or linkable object form
|  without the consent of its author.
*/ 

#ifndef __CLIRPC_H__
#define __CLIRPC_H__

#define RTSMB_RPC_INIT_BUFFER_SIZE  72

#define WRITE_UINT8(BYTEPTR, VALUE)         *(BYTEPTR) = (unsigned char) ((VALUE) & 0xFF); (BYTEPTR)++;

#define WRITE_UINT8_INTEL(BYTEPTR, VALUE)   WRITE_UINT8(BYTEPTR, VALUE)
#define WRITE_UINT16_INTEL(BYTEPTR, VALUE)  WRITE_UINT8_INTEL(BYTEPTR, VALUE); \
                                            WRITE_UINT8_INTEL(BYTEPTR, ((VALUE)>>8));
#define WRITE_UINT32_INTEL(BYTEPTR, VALUE)  WRITE_UINT16_INTEL(BYTEPTR, VALUE); \
                                            WRITE_UINT16_INTEL(BYTEPTR, ((VALUE)>>16));

#define WRITE_UINT8_NET(BYTEPTR, VALUE)     WRITE_UINT8(BYTEPTR, VALUE)
#define WRITE_UINT16_NET(BYTEPTR, VALUE)    WRITE_UINT8_INTEL(BYTEPTR, ((VALUE)>>8)); \
                                            WRITE_UINT8_INTEL(BYTEPTR, VALUE);
#define WRITE_UINT32_NET(BYTEPTR, VALUE)    WRITE_UINT16_INTEL(BYTEPTR, ((VALUE)>>16)); \
                                            WRITE_UINT16_INTEL(BYTEPTR, VALUE);
                                            
#define WRITE_UNISTR_INTEL(BYTEPTR, STR, L) {                                               \
                                                RTSMB_UINT32 n;                             \
                                                for (n = 0; n < (L); n++)                   \
                                                {                                           \
                                                    WRITE_UINT16_INTEL(BYTEPTR, (STR)[n]);  \
                                                }                                           \
                                            }

#define WRITE_PADDING(BYTEPTR, BITS, V, S)  {                                              \
                                                while (PDIFF(BYTEPTR,S) & ((1<<(BITS))-1)) \
                                                {                                          \
                                                	WRITE_UINT8(BYTEPTR, V);               \
                                                }                                          \
                                            }

#define READ_UINT8(BYTEPTR)                 ((BYTEPTR)++, (BYTEPTR)[-1] & 0xFF)

#define READ_UINT16_INTEL(BYTEPTR)          ((BYTEPTR)+=2, \
                                             ((RTSMB_UINT16) ((BYTEPTR)[-2])) | \
                                             ((RTSMB_UINT16) ((BYTEPTR)[-1]) << 8) )

#define READ_UINT32_INTEL(BYTEPTR)          ((BYTEPTR)+=4, \
                                             ((RTSMB_UINT32) ((BYTEPTR)[-4]))       | \
                                             ((RTSMB_UINT32) ((BYTEPTR)[-3]) << 8)  | \
                                             ((RTSMB_UINT32) ((BYTEPTR)[-2]) << 16) | \
                                             ((RTSMB_UINT32) ((BYTEPTR)[-1]) << 24) )

#define SKIP_UINT8(BYTEPTR)                 (BYTEPTR)+=1
#define SKIP_UINT16(BYTEPTR)                (BYTEPTR)+=2
#define SKIP_UINT32(BYTEPTR)                (BYTEPTR)+=4

#define READ_PADDING(BYTEPTR, BITS, S)      {                                              \
                                                while (PDIFF(BYTEPTR,S) & ((1<<(BITS))-1)) \
                                                {                                          \
                                                	(BYTEPTR)++;                           \
                                                }                                          \
                                            }
                                                                   

typedef struct
{
	RTSMB_UINT8  iface_uuid[16];
	RTSMB_UINT16 iface_major_version;
	RTSMB_UINT16 iface_minor_version;
	RTSMB_UINT8  transfer_syntax_uuid[16];
	RTSMB_UINT32 transfer_syntax_version;	
}
RTSMB_RPC_IFACE_INFO;
typedef RTSMB_RPC_IFACE_INFO RTSMB_FAR * PRTSMB_RPC_IFACE_INFO;

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************

 rtsmb_cli_rpc_open_interface - create a named pipe and bind to an RPC interface
 
    sid       - client session id to use
    pipe_name - name of pipe to create on the IPC$ share; should conform to 
                RPC interface conventions (for example, for Server Services
                interface, this should be: "\srvsvc")
	info      - specific information about the RPC interface to which the new
	            pipe is to be bound
	fid       - pointer to int that receives the file identifier that serves
	            as a handle to this pipe
	buffer    - pointer to a buffer of size RTSMB_RPC_INIT_BUFFER_SIZE
	            
 Description
	This function is the first step to invoke remote procedure calls over SMB.
	It establishes a context in which the RPCs are to be invoked by creating a
	named pipe that will act as a transport for RPCs, and binding that pipe
	to a specific interface.  An RPC interface is a set of functions which can
	be invoked remotely.  
	 
 See Code
    
 
 See Also
    

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating 
	the job id or a negative value on failure.
 
******************************************************************************/
int rtsmb_cli_rpc_open_interface (int sid, PFRTCHAR pipe_name, 
                                  PRTSMB_RPC_IFACE_INFO info,
                                  PFINT fid, PFBYTE buffer);

/******************************************************************************

 rtsmb_cli_rpc_close_interface - close a named pipe
 
    sid       - client session id to use
	fid       - the file identifier returned by rtsmb_cli_rpc_open_interface
	            
 Description
	Use this function to end an RPC session.  There can be no more RPC invocations
	on the given pipe after this function is called.
	 
 See Code
    
 
 See Also
    

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating 
	the job id or a negative value on failure.
 
******************************************************************************/
int rtsmb_cli_rpc_close_interface (int sid, int fid);

/******************************************************************************

 rtsmb_cli_rpc_invoke - invoke a remote procedure call
 
    sid                  - client session id to use
	fid                  - the file identifier returned by rtsmb_cli_rpc_open_interface,
	                       identifying the bound pipe to use
	operation            - integer indicating what function on the bound interface 
	                       to invoke (defined in the header file for the relevant
	                       service, for example in slsrvsvc.h, 
	                       RTSMB_RPC_SRVSVC_NETR_SHARE_ENUM)
	write_request_params - function used to write any input parameters 
	                       associated with the function to a buffer for sending
	request_params       - opaque data pointer passed into write_request_params
	read_response_params - function used to read any out parameters 
	                       associated with the function from the response message
	response_params      - opaque data pointer passed into read_response_params
	            
 Description
	
	 
 See Code
    
 
 See Also
    

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating 
	the job id or a negative value on failure.
 
******************************************************************************/
int rtsmb_cli_rpc_invoke (
		int sid, 
		int fid, 
		int operation,
		long (RTSMB_FAR *write_request_params) (PFBYTE origin, PFBYTE buffer, long buf_size, 
		                                        PFVOID param_data, PFINT status),
		PFVOID request_params,
		long (RTSMB_FAR *read_response_params) (PFBYTE origin, PFBYTE buffer, long buf_size, 
		                                        PFVOID param_data, PFINT status),
		PFVOID response_params);

#define RTSMB_RPC_RESPONSE_STATUS_DONE       0
#define RTSMB_RPC_RESPONSE_STATUS_INCOMPLETE 1
#define RTSMB_RPC_RESPONSE_STATUS_ERROR      2

/* ------------------------------------------------------------------------- */
/* The following functions are for internal use only                         */


typedef struct 
{
	PFWORD       unistr;
	RTSMB_UINT32 size;
	RTSMB_UINT8  last_chunk_data[12];
	RTSMB_UINT32 last_chunk_size;
	RTSMB_UINT32 current_offset_from_origin; /* the offset from the origin where the next data buffer starts */
	RTSMB_UINT32 chars_read;
	RTSMB_UINT32 chars_left;
	RTSMB_BOOL   read_padding;
	RTSMB_BOOL   read_header;
}
RTSMB_RPC_DCE_UNISTR_READER;
typedef RTSMB_RPC_DCE_UNISTR_READER RTSMB_FAR * PRTSMB_RPC_DCE_UNISTR_READER;

int rtsmb_rpc_dce_unistr_reader_init (
		PRTSMB_RPC_DCE_UNISTR_READER reader, 
		PFWORD unistr, 
		RTSMB_UINT32 size,
		RTSMB_UINT32 offset_from_origin);

RTSMB_BOOL rtsmb_rpc_dce_unistr_reader_is_done (
		PRTSMB_RPC_DCE_UNISTR_READER reader);

long rtsmb_rpc_dce_unistr_reader_process_data (
		PRTSMB_RPC_DCE_UNISTR_READER reader,
		PFBYTE data,
		long size);

#ifdef __cplusplus
}
#endif

#endif /* __CLIRPC_H__ */
