#ifndef __SRV_CMDS_H__
#define __SRV_CMDS_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "smbobjs.h"

#define RTSMB_CMD_MALFORMED		-1


int srv_cmd_read_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader);

int srv_cmd_read_negotiate (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE pNegotiate);

int srv_cmd_read_session_setup_and_x_pre_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_PRE_NT pSession);
int srv_cmd_read_session_setup_and_x_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_NT pSession);

int srv_cmd_read_logoff_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOGOFF_AND_X pLogoff);

int srv_cmd_read_tree_connect_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_AND_X pTree);

int srv_cmd_read_read_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X pRead);

int srv_cmd_read_write_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_X pWrite);

int srv_cmd_read_open_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_AND_X pOpen);

int srv_cmd_read_locking_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOCKING_AND_X pLocking);

int srv_cmd_read_tree_disconnect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_read_create_temporary (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE_TEMPORARY pTemp);

int srv_cmd_read_seek (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEEK pSeek);

int srv_cmd_read_flush (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FLUSH pFlush);

int srv_cmd_read_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CLOSE pClose);
int srv_cmd_read_close_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CLOSE_PRINT_FILE pClose);

int srv_cmd_read_delete (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_DELETE pDelete);

int srv_cmd_read_rename (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RENAME pRename);

int srv_cmd_read_move (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_MOVE pMove);

int srv_cmd_read_copy (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_COPY pCopy);

int srv_cmd_read_delete_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_DELETE_DIRECTORY pDelete);

int srv_cmd_read_check_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CHECK_DIRECTORY pCheck);

int srv_cmd_read_create_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE_DIRECTORY pCreate);

int srv_cmd_read_find_close2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_CLOSE2 pClose);

int srv_cmd_read_open_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_PRINT_FILE pOpen);

int srv_cmd_read_create (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE pCreate);

int srv_cmd_read_open (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN pOpen);

int srv_cmd_read_echo (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_ECHO pEcho);

int srv_cmd_read_query_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_INFORMATION pQuery);

int srv_cmd_read_query_information2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_INFORMATION2 pQuery);

int srv_cmd_read_read (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ pRead);

int srv_cmd_read_read_raw (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_RAW pRead);

int srv_cmd_read_search (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEARCH pSearch);

int srv_cmd_read_set_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SET_INFORMATION pSet);
int srv_cmd_read_set_information2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SET_INFORMATION2 pSet);

int srv_cmd_read_query_information_disk (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_read_tree_connect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT pTree);

int srv_cmd_read_write (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE pWrite);

int srv_cmd_read_write_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_PRINT_FILE pWrite);

int srv_cmd_read_write_raw (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW pWrite);

int srv_cmd_read_write_and_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_CLOSE pWrite);

int srv_cmd_read_process_exit (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_read_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION pTransaction);

int srv_cmd_read_query_fs_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_QUERY_FS_INFORMATION pQuery);

int srv_cmd_read_find_first2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_FIRST2 pFind);
int srv_cmd_read_find_next2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_NEXT2 pFind);

int srv_cmd_read_query_file_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_QUERY_FILE_INFORMATION pQuery);
int srv_cmd_read_query_path_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_QUERY_PATH_INFORMATION pQuery);

int srv_cmd_read_trans2_set_file_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_SET_FILE_INFORMATION pSet);
int srv_cmd_read_trans2_set_path_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_SET_PATH_INFORMATION pSet);

int srv_cmd_read_rap_request (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_REQUEST pRAP);
int srv_cmd_read_rap_get_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_GET_INFO pInfo);

int srv_cmd_read_rap_share_get_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SHARE_GET_INFO pInfo);

int srv_cmd_read_nt_create_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NT_CREATE_AND_X pCreate);

int srv_cmd_read_info_standard (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_STANDARD pInfo);
int srv_cmd_read_basic_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_BASIC_INFO pInfo);

int srv_cmd_read_rap_server_enum2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_ENUM2 penum);

int srv_cmd_read_end_of_file_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FILE_END_OF_FILE_INFO pInfo);

int srv_cmd_read_allocation_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FILE_ALLOCATION_INFO pInfo);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_CMDS_H__ */
