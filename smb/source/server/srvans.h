#ifndef __SRV_ANS_H__
#define __SRV_ANS_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "smbobjs.h"


int srv_cmd_fill_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader);

int srv_cmd_fill_negotiate_bad (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE_BAD_R pNegotiateR);
int srv_cmd_fill_negotiate_pre_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE_R pNegotiateR);
int srv_cmd_fill_negotiate_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE_R pNegotiateR);


int srv_cmd_fill_session_setup_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_R pSessionR);

int srv_cmd_fill_logoff_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOGOFF_AND_X_R pLogoffR);

int srv_cmd_fill_tree_connect_and_x_pre_lanman (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_AND_X_R pTreeR);
int srv_cmd_fill_tree_connect_and_x_lanman (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_AND_X_R pTreeR);

int srv_cmd_fill_read_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X_R pReadR);

int srv_cmd_fill_write_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_X_R pWriteR);

int srv_cmd_fill_locking_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOCKING_AND_X_R pLockingR);

int srv_cmd_fill_open_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_AND_X_R pOpenR);

int srv_cmd_fill_tree_disconnect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_create_temporary (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE_TEMPORARY_R pTempR);

int srv_cmd_fill_seek (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEEK_R pSeekR);

int srv_cmd_fill_flush (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);
int srv_cmd_fill_close_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_delete (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_rename (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_move (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_MOVE_R pMoveR);

int srv_cmd_fill_copy (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_COPY_R pCopyR);

int srv_cmd_fill_delete_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_check_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_create_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_find_close2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_open_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_PRINT_FILE_R pOpenR);

int srv_cmd_fill_create (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE_R pCreateR);

int srv_cmd_fill_open (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_R pOpenR);

int srv_cmd_fill_echo (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_ECHO_R pEcho);

int srv_cmd_fill_query_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_INFORMATION_R pQueryR);

int srv_cmd_fill_query_information2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_INFORMATION2_R pQueryR);

int srv_cmd_fill_read (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_R pReadR);

int srv_cmd_fill_search (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEARCH_R pSearchR);

int srv_cmd_fill_directory_information_data (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_DIRECTORY_INFORMATION_DATA pData);

int srv_cmd_fill_set_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);
int srv_cmd_fill_set_information2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_query_information_disk (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_INFORMATION_DISK_R pQueryR);

int srv_cmd_fill_tree_connect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_R pTreeR);

int srv_cmd_fill_write (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_R pWriteR);

int srv_cmd_fill_write_and_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_CLOSE_R pWriteR);

int srv_cmd_fill_write_print_file (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_write_raw1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW_R1 pWriteR);
int srv_cmd_fill_write_raw2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW_R2 pWriteR);

int srv_cmd_fill_process_exit (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int srv_cmd_fill_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION_R pTransactionR);
int srv_cmd_fill_info_allocation (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_ALLOCATION pInfo);
int srv_cmd_fill_info_volume (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_VOLUME pInfo);
int srv_cmd_fill_query_fs_volume_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FS_VOLUME_INFO pInfo);
int srv_cmd_fill_query_fs_size_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FS_SIZE_INFO pInfo);
int srv_cmd_fill_query_fs_device_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FS_DEVICE_INFO pInfo);
int srv_cmd_fill_query_fs_attribute_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FS_ATTRIBUTE_INFO pInfo);

int srv_cmd_fill_find_first (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_FIRST_R pFindR);
int srv_cmd_fill_find_next (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_NEXT_R pFindR);
int srv_cmd_fill_find_file_info_standard (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_INFO_STANDARD pInfo);
int srv_cmd_fill_find_file_info_query_ea_size (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_INFO_QUERY_EA_SIZE pInfo);
int srv_cmd_fill_find_file_directory_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_DIRECTORY_INFO pInfo);
int srv_cmd_fill_find_file_full_directory_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_FULL_DIRECTORY_INFO pInfo);
int srv_cmd_fill_find_file_both_directory_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_BOTH_DIRECTORY_INFO pInfo);
int srv_cmd_fill_find_file_names_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_FILE_NAMES_INFO pInfo);


int srv_cmd_fill_info_standard (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_STANDARD pInfo);
int srv_cmd_fill_info_query_ea_size (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_QUERY_EA_SIZE pInfo);
int srv_cmd_fill_query_ea_size_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_INFO_QUERY_EA_SIZE pInfo);
int srv_cmd_fill_query_file_basic_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_BASIC_INFO pInfo);
int srv_cmd_fill_query_file_standard_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_STANDARD_INFO pInfo);
int srv_cmd_fill_query_file_ea_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_EA_INFO pInfo);
int srv_cmd_fill_query_file_name_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_NAME_INFO pInfo);
int srv_cmd_fill_query_file_stream_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_STREAM_INFO pInfo);
int srv_cmd_fill_query_file_compression_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_QUERY_FILE_COMPRESSION_INFO pInfo);


int srv_cmd_fill_rap_response (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_RESPONSE pRAP);

rtsmb_size srv_cmd_sizeof_rap_wksta_info (PRTSMB_HEADER pHeader, PRTSMB_RAP_WKSTA_INFO pInfo);
int srv_cmd_fill_rap_wksta_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_WKSTA_INFO pInfo);

int srv_cmd_fill_rap_share_enum_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SHARE_ENUM_INFO_R pInfo);
int srv_cmd_fill_rap_share_enum_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_ENUM_HEADER_R pRAP);

int srv_cmd_fill_rap_share_info_0 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SHARE_INFO_0 pInfo);
int srv_cmd_fill_rap_share_info_1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SHARE_INFO_1 pInfo);

int srv_cmd_fill_rap_server_info_0 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo);
int srv_cmd_fill_rap_server_info_1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo);

int srv_cmd_fill_rap_server_enum_info_0 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo);
int srv_cmd_fill_rap_server_enum_info_1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_INFO_1 pInfo);


rtsmb_size srv_cmd_sizeof_rap_printer_queue_info_0 (PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_0 pInfo);
rtsmb_size srv_cmd_sizeof_rap_printer_queue_info_1 (PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_1 pInfo);
rtsmb_size srv_cmd_sizeof_rap_printer_queue_info_3 (PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_3 pInfo);
rtsmb_size srv_cmd_sizeof_rap_printer_queue_info_5 (PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_5 pInfo);

int srv_cmd_fill_rap_printer_queue_info_0 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_0 pInfo);
int srv_cmd_fill_rap_printer_queue_info_1 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_1 pInfo);
int srv_cmd_fill_rap_printer_queue_info_3 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_3 pInfo);
int srv_cmd_fill_rap_printer_queue_info_5 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_PRINTER_QUEUE_INFO_5 pInfo);

int srv_cmd_fill_mailslot_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_MAILSLOT_HEADER pMailslot);

int srv_cmd_fill_transaction_cmd (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION pTransaction);

int srv_cmd_fill_nt_create_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NT_CREATE_AND_X_R pCreateR);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_ANS_H__ */
