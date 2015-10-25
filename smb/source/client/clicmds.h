#ifndef __CLI_CMDS_H__
#define __CLI_CMDS_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_CLIENT)

#include "smbobjs.h"

int cli_cmd_fill_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader);

int cli_cmd_fill_negotiate (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NEGOTIATE pNegotiate);

int cli_cmd_fill_session_setup_and_x_pre_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_PRE_NT pSetup);
int cli_cmd_fill_session_setup_and_x_nt_ext_sec (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_EXT_SEC pSetup);
int cli_cmd_fill_session_setup_and_x_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SESSION_SETUP_AND_X_NT pSetup);

int cli_cmd_fill_logoff_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_LOGOFF_AND_X pLogoff);

int cli_cmd_fill_tree_connect_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TREE_CONNECT_AND_X pTree);

int cli_cmd_fill_tree_disconnect (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PFVOID none);

int cli_cmd_fill_read_and_x_pre_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X pRead);
int cli_cmd_fill_read_and_x_nt (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_READ_AND_X pRead);

int cli_cmd_fill_open_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_OPEN_AND_X pOpen);

int cli_cmd_fill_create_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_NT_CREATE_AND_X pCreate);

int cli_cmd_fill_close (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CLOSE pClose);

int cli_cmd_fill_write_and_x (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_AND_X pWrite);

int cli_cmd_fill_write_raw (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE_RAW pWrite);

int cli_cmd_fill_seek (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SEEK pSeek);

int cli_cmd_fill_write (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_WRITE pWrite);

int cli_cmd_fill_flush (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FLUSH pFlush);

int cli_cmd_fill_rename (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RENAME pRename);

int cli_cmd_fill_delete (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_DELETE pDelete);

int cli_cmd_fill_create_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_CREATE_DIRECTORY pCreate);

int cli_cmd_fill_delete_directory (PFVOID origin, PFVOID buf, rtsmb_size size,
    PRTSMB_HEADER pHeader, PRTSMB_DELETE_DIRECTORY pDelete);

int cli_cmd_fill_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION pTransaction);
int cli_cmd_fill_trans2_find_first2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_FIRST2 pFind);
int cli_cmd_fill_trans2_find_next2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_FIND_NEXT2 pFind);

int cli_cmd_fill_find_close2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_FIND_CLOSE2 pFind);

int cli_cmd_fill_share_enum (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_GET_INFO pInfo);
int cli_cmd_fill_get_server_info (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_GET_INFO pInfo);

int cli_cmd_fill_get_backup_list (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_BROWSE_GET_BACKUP_LIST pGet);

int cli_cmd_fill_rap_server_enum2 (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_RAP_SERVER_ENUM2 pEnum);

int cli_cmd_fill_set_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_SET_INFORMATION pSet);

int cli_cmd_fill_query_fs_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_QUERY_FS_INFORMATION pQuery);

int cli_cmd_fill_trans2_query_path_information (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANS2_QUERY_PATH_INFORMATION pQuery);

#endif /* INCLUDE_RTSMB_CLIENT */

#endif
