#ifndef __CLI_ANS_H__
#define __CLI_ANS_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_CLIENT)

#include "smbobjs.h"

#define CLI_CMD_MALFORMED		-1

int cli_cmd_read_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader);

int cli_cmd_read_negotiate (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE_R pNegotiateR);

int cli_cmd_read_session_setup_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_R pSetupR);
int cli_cmd_read_session_setup_and_x_ext_sec (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_EXT_SEC_R pSetupR);

int cli_cmd_read_logoff_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOGOFF_AND_X_R pLogoffR);

int cli_cmd_read_echo (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_ECHO_R pEchoR);

int cli_cmd_read_tree_connect_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_AND_X_R pSetupR);
int cli_cmd_read_tree_disconnect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int cli_cmd_read_read_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X_R pReadR);

int cli_cmd_read_read_and_x_up_to_data (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X_R pReadR);

int cli_cmd_read_write_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_X_R pWriteR);

int cli_cmd_read_write_raw_r1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW_R1 pWriteR);

int cli_cmd_read_write_raw_r2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW_R2 pWriteR);

int cli_cmd_read_open_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_AND_X_R pOpenR);

int cli_cmd_read_create_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NT_CREATE_AND_X_R pCreateR);

int cli_cmd_read_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int cli_cmd_read_seek (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEEK_R pSeekR);

int cli_cmd_read_write (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_R pWriteR);

int cli_cmd_read_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION_R pTransactionR);
int cli_cmd_read_find_first2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_FIRST_R pFindR);
int cli_cmd_read_find_next2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_NEXT_R pFindR);

int cli_cmd_read_find_file_info_standard (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_INFO_STANDARD pInfo);

int cli_cmd_read_enum_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_ENUM_HEADER_R pEnumR);
int cli_cmd_read_share_enum_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SHARE_ENUM_INFO_R pInfo);

int cli_cmd_read_backup_list (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_BROWSE_GET_BACKUP_LIST_R pList);

int cli_cmd_read_server_info_0 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_0 pInfo);
int cli_cmd_read_server_info_1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo);

int cli_cmd_read_info_allocation (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_ALLOCATION pInfo);

int cli_cmd_read_info_standard (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_STANDARD pInfo);
int cli_cmd_read_query_file_all_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_ALL_INFO pInfo);

#endif /* INCLUDE_RTSMB_CLIENT */

#endif /* __CLI_ANS_H__ */
