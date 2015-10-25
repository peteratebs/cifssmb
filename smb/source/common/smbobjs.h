#ifndef __SMB_OBJS_H__
#define __SMB_OBJS_H__

#include "smbdefs.h"




/* A list of structs for considering SMBs logically follows.
   If a struct represents a server->client SMB, its name is suffixed by
   a "_R". */

typedef struct
{
	byte command;
	byte flags;
	word flags2;
	dword status;
	word tid;
	word uid;
	dword pid;
	word mid;
	byte security_sig [8];
} RTSMB_HEADER;
typedef RTSMB_HEADER RTSMB_FAR *PRTSMB_HEADER;


typedef struct
{
	int num_dialects;
	int string_size;
	PFRTCHAR RTSMB_FAR *dialects;
} RTSMB_NEGOTIATE;
typedef RTSMB_NEGOTIATE RTSMB_FAR *PRTSMB_NEGOTIATE;

typedef struct
{
	word dialect_index;
} RTSMB_NEGOTIATE_BAD_R;
typedef RTSMB_NEGOTIATE_BAD_R RTSMB_FAR *PRTSMB_NEGOTIATE_BAD_R;

/* there are several versions of the negotiate response.  but, we can't
   tell which is sent until we get it, so we have one universal struct
   for the response */
typedef struct
{
	word dialect_index;
	byte security_mode;
	word max_mpx_count;
	word max_vcs;
	dword max_buffer_size;
	dword max_raw_size;
	dword session_id;
	dword capabilities;
	dword time_low;
	dword time_high;
	word time_zone;

	BBOOL valid_guid;	/* true if |guid| has useful data */
	byte guid [16];
	byte challenge_size;
	PFBYTE challenge;

	BBOOL valid_domain;	/* true if |domain| has useful data */
	dword domain_size;
	PFRTCHAR domain;	/* in unicode */

	BBOOL valid_server; /* true if |server| has useful data */
	rtsmb_char server;

} RTSMB_NEGOTIATE_R;
typedef RTSMB_NEGOTIATE_R RTSMB_FAR *PRTSMB_NEGOTIATE_R;


typedef struct
{
	byte next_command;
	word max_buffer_size;
	word max_mpx_count;
	word vc_number;
	dword session_id;

	word password_size;
	PFBYTE password;
	dword account_name_size;
	PFRTCHAR account_name;
	dword primary_domain_size;
	PFRTCHAR primary_domain;
	dword native_os_size;
	PFRTCHAR native_os;
	dword native_lan_man_size;
	PFRTCHAR native_lan_man;
} RTSMB_SESSION_SETUP_AND_X_PRE_NT;
typedef RTSMB_SESSION_SETUP_AND_X_PRE_NT RTSMB_FAR *PRTSMB_SESSION_SETUP_AND_X_PRE_NT;

typedef struct
{
	byte next_command;
	word max_buffer_size;
	word max_mpx_count;
	word vc_number;
	dword session_id;
	dword capabilities;

	word ansi_password_size;
	word unicode_password_size;
	PFBYTE ansi_password;
	PFBYTE unicode_password;
	dword account_name_size;
	PFRTCHAR account_name;	/* in unicode */
	dword primary_domain_size;
	PFRTCHAR primary_domain;	/* in unicode */
	dword native_os_size;
	PFRTCHAR native_os;	/* in unicode */
	dword native_lan_man_size;
	PFRTCHAR native_lan_man;	/* in unicode */
} RTSMB_SESSION_SETUP_AND_X_NT;
typedef RTSMB_SESSION_SETUP_AND_X_NT RTSMB_FAR *PRTSMB_SESSION_SETUP_AND_X_NT;

typedef struct
{
	byte next_command;
	BBOOL guest_logon;	/* were we logged on as a guest? */

	dword srv_native_os_size;
	PFRTCHAR srv_native_os;
	dword srv_native_lan_man_size;
	PFRTCHAR srv_native_lan_man;
	dword srv_primary_domain_size;
	PFRTCHAR srv_primary_domain;
} RTSMB_SESSION_SETUP_AND_X_R;
typedef RTSMB_SESSION_SETUP_AND_X_R RTSMB_FAR *PRTSMB_SESSION_SETUP_AND_X_R;

typedef struct
{
	byte next_command;
	word max_buffer_size;
	word max_mpx_count;
	word vc_number;
	dword session_id;
	dword capabilities;

	dword blob_size;
	PFBYTE blob;
	dword native_os_size;
	PFRTCHAR native_os;	/* in unicode */
	dword native_lan_man_size;
	PFRTCHAR native_lan_man;	/* in unicode */
} RTSMB_SESSION_SETUP_AND_X_EXT_SEC;
typedef RTSMB_SESSION_SETUP_AND_X_EXT_SEC RTSMB_FAR *PRTSMB_SESSION_SETUP_AND_X_EXT_SEC;

typedef struct
{
	byte next_command;
	BBOOL guest_logon;	/* were we logged on as a guest? */

	dword blob_size;
	PFBYTE blob;
	dword srv_native_os_size;
	PFRTCHAR srv_native_os;
	dword srv_native_lan_man_size;
	PFRTCHAR srv_native_lan_man;
	dword srv_primary_domain_size;
	PFRTCHAR srv_primary_domain;
} RTSMB_SESSION_SETUP_AND_X_EXT_SEC_R;
typedef RTSMB_SESSION_SETUP_AND_X_EXT_SEC_R RTSMB_FAR *PRTSMB_SESSION_SETUP_AND_X_EXT_SEC_R;

typedef struct
{
	byte next_command;
} RTSMB_LOGOFF_AND_X;
typedef RTSMB_LOGOFF_AND_X RTSMB_FAR *PRTSMB_LOGOFF_AND_X;

typedef struct
{
	byte next_command;
} RTSMB_LOGOFF_AND_X_R;
typedef RTSMB_LOGOFF_AND_X_R RTSMB_FAR *PRTSMB_LOGOFF_AND_X_R;

typedef struct
{
	byte next_command;
	word flags;

	word password_size;		/* needs to be filled in on read/write */
	PFBYTE password;		/* needs to be filled in on read/write */
	dword share_size;		/* needs to be filled in on read */
	PFRTCHAR share;			/* needs to be filled in on read/write */
	dword service_size;		/* needs to be filled in on read */
	PFRTCHAR service;			/* needs to be filled in on read/write */
} RTSMB_TREE_CONNECT_AND_X;
typedef RTSMB_TREE_CONNECT_AND_X RTSMB_FAR *PRTSMB_TREE_CONNECT_AND_X;

/* there are two forms of this response, but since a server that
 has negotiated a later dialect can still send lower form, it's better to
 let us auto-detect type and use one struct */
typedef struct
{
	byte next_command;
	word optional_support;

	dword service_size;			/* needs to be filled in on read */
	PFRTCHAR service;				/* needs to be filled in on read */
	dword native_fs_size;		/* needs to be filled in on read */
	PFRTCHAR native_fs;			/* needs to be filled in on read */
} RTSMB_TREE_CONNECT_AND_X_R;
typedef RTSMB_TREE_CONNECT_AND_X_R RTSMB_FAR *PRTSMB_TREE_CONNECT_AND_X_R;

typedef struct
{
	byte next_command;

	dword flags;
	dword root_directory_fid;
	dword desired_access;

	dword allocation_size_high;
	dword allocation_size_low;

	dword ext_file_attributes;
	dword share_access;
	dword create_disposition;
	dword create_options;
	dword impersonation_level;
	byte security_flags;

	word filename_size;
	PFRTCHAR filename;

} RTSMB_NT_CREATE_AND_X;
typedef RTSMB_NT_CREATE_AND_X RTSMB_FAR *PRTSMB_NT_CREATE_AND_X;

typedef struct
{
	byte next_command;

	byte oplock_level;
	word fid;
	dword create_action;

	dword creation_time_high;
	dword creation_time_low;
	dword last_access_time_high;
	dword last_access_time_low;
	dword last_write_time_high;
	dword last_write_time_low;
	dword change_time_high;
	dword change_time_low;

	dword ext_file_attributes;
	dword allocation_size_high;
	dword allocation_size_low;
	dword end_of_file_high;
	dword end_of_file_low;

	word file_type;
	word device_state;
	BBOOL directory;

} RTSMB_NT_CREATE_AND_X_R;
typedef RTSMB_NT_CREATE_AND_X_R RTSMB_FAR *PRTSMB_NT_CREATE_AND_X_R;

typedef struct
{
	word count;

	word data_size;			/* needs to be filled in on read */
	PFBYTE data;			/* needs to be filled in on read */
} RTSMB_ECHO;
typedef RTSMB_ECHO RTSMB_FAR *PRTSMB_ECHO;

typedef struct
{
	word sequence_number;

	word data_size;			/* needs to be filled in on read */
	PFBYTE data;			/* needs to be filled in on read */
} RTSMB_ECHO_R;
typedef RTSMB_ECHO_R RTSMB_FAR *PRTSMB_ECHO_R;

typedef struct
{
	byte next_command;

	word fid;
	dword offset;
	dword offset_high;	/* upper 32 bits of offset */
	dword max_count;

} RTSMB_READ_AND_X;
typedef RTSMB_READ_AND_X RTSMB_FAR *PRTSMB_READ_AND_X;

typedef struct
{
	byte next_command;

	word  offset;
	word  real_data_length;
	dword data_size;
	PFBYTE data;

} RTSMB_READ_AND_X_R;
typedef RTSMB_READ_AND_X_R RTSMB_FAR *PRTSMB_READ_AND_X_R;

typedef struct
{
	byte next_command;

	word fid;
	word write_mode;
	dword offset;
	dword offset_high;	/* upper 32 bits of offset */

	dword data_size;
	dword copy_data_size;
	PFBYTE data;

	int is_large_write; /* boolean; non-zero if this write is over the
						   server-negotiated SMB message size limit
						   (this is allowed if the server supports
						   large writes) */

	int limited_copy;   /* boolean; copy size specified by copy_data_size rather than data_size */

} RTSMB_WRITE_AND_X;
typedef RTSMB_WRITE_AND_X RTSMB_FAR *PRTSMB_WRITE_AND_X;

typedef struct
{
	byte next_command;

	word count;

} RTSMB_WRITE_AND_X_R;
typedef RTSMB_WRITE_AND_X_R RTSMB_FAR *PRTSMB_WRITE_AND_X_R;

typedef struct
{
	byte next_command;

	word flags;
	word desired_access;
	word search_attributes;
	word file_attributes;
	dword creation_time;
	dword allocation_size;

	word open_function;

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_OPEN_AND_X;
typedef RTSMB_OPEN_AND_X RTSMB_FAR *PRTSMB_OPEN_AND_X;

typedef struct
{
	byte next_command;

	word fid;
	dword server_fid;

	word file_attributes;
	dword last_write_time;
	dword file_size;
	word file_type;
	word device_state;

	word granted_access;
	word action;

} RTSMB_OPEN_AND_X_R;
typedef RTSMB_OPEN_AND_X_R RTSMB_FAR *PRTSMB_OPEN_AND_X_R;

typedef struct
{
	dword creation_time;

	dword directory_size;
	PFRTCHAR directory;

} RTSMB_CREATE_TEMPORARY;
typedef RTSMB_CREATE_TEMPORARY RTSMB_FAR *PRTSMB_CREATE_TEMPORARY;

typedef struct
{
	word fid;

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_CREATE_TEMPORARY_R;
typedef RTSMB_CREATE_TEMPORARY_R RTSMB_FAR *PRTSMB_CREATE_TEMPORARY_R;

typedef struct
{
	word fid;
	word mode;
	dword offset;

} RTSMB_SEEK;
typedef RTSMB_SEEK RTSMB_FAR *PRTSMB_SEEK;

typedef struct
{
	dword offset;

} RTSMB_SEEK_R;
typedef RTSMB_SEEK_R RTSMB_FAR *PRTSMB_SEEK_R;

typedef struct
{
	word fid;

} RTSMB_FLUSH;
typedef RTSMB_FLUSH RTSMB_FAR *PRTSMB_FLUSH;

typedef struct
{
	word fid;
	dword last_write_time;

} RTSMB_CLOSE;
typedef RTSMB_CLOSE RTSMB_FAR *PRTSMB_CLOSE;

typedef struct
{
	word fid;

} RTSMB_CLOSE_PRINT_FILE;
typedef RTSMB_CLOSE_PRINT_FILE RTSMB_FAR *PRTSMB_CLOSE_PRINT_FILE;

typedef struct
{
	word search_attributes;

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_DELETE;
typedef RTSMB_DELETE RTSMB_FAR *PRTSMB_DELETE;

typedef struct
{
	word search_attributes;

	dword old_filename_size;
	PFRTCHAR old_filename;

	dword new_filename_size;
	PFRTCHAR new_filename;

} RTSMB_RENAME;
typedef RTSMB_RENAME RTSMB_FAR *PRTSMB_RENAME;

typedef struct
{
	word tid2;
	word open_function;
	word flags;

	dword old_filename_size;
	PFRTCHAR old_filename;
	dword new_filename_size;
	PFRTCHAR new_filename;

} RTSMB_MOVE;
typedef RTSMB_MOVE RTSMB_FAR *PRTSMB_MOVE;

typedef struct
{
	word count;

	dword error_filename_size;
	PFRTCHAR error_filename;

} RTSMB_MOVE_R;
typedef RTSMB_MOVE_R RTSMB_FAR *PRTSMB_MOVE_R;

typedef struct
{
	word tid2;
	word open_function;
	word flags;

	dword old_filename_size;
	PFRTCHAR old_filename;
	dword new_filename_size;
	PFRTCHAR new_filename;

} RTSMB_COPY;
typedef RTSMB_COPY RTSMB_FAR *PRTSMB_COPY;

typedef struct
{
	word count;

	dword error_filename_size;
	PFRTCHAR error_filename;

} RTSMB_COPY_R;
typedef RTSMB_COPY_R RTSMB_FAR *PRTSMB_COPY_R;

typedef struct
{
	dword directory_size;
	PFRTCHAR directory;

} RTSMB_DELETE_DIRECTORY;
typedef RTSMB_DELETE_DIRECTORY RTSMB_FAR *PRTSMB_DELETE_DIRECTORY;

typedef struct
{
	dword directory_size;
	PFRTCHAR directory;

} RTSMB_CHECK_DIRECTORY;
typedef RTSMB_CHECK_DIRECTORY RTSMB_FAR *PRTSMB_CHECK_DIRECTORY;

typedef struct
{
	dword directory_size;
	PFRTCHAR directory;

} RTSMB_CREATE_DIRECTORY;
typedef RTSMB_CREATE_DIRECTORY RTSMB_FAR *PRTSMB_CREATE_DIRECTORY;

typedef struct
{
	word setup_length;
	word mode;

	dword identifier_size;
	PFRTCHAR identifier;

} RTSMB_OPEN_PRINT_FILE;
typedef RTSMB_OPEN_PRINT_FILE RTSMB_FAR *PRTSMB_OPEN_PRINT_FILE;

typedef struct
{
	word fid;

} RTSMB_OPEN_PRINT_FILE_R;
typedef RTSMB_OPEN_PRINT_FILE_R RTSMB_FAR *PRTSMB_OPEN_PRINT_FILE_R;

typedef struct
{
	word file_attributes;
	dword creation_time;

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_CREATE;
typedef RTSMB_CREATE RTSMB_FAR *PRTSMB_CREATE;

typedef struct
{
	word fid;

} RTSMB_CREATE_R;
typedef RTSMB_CREATE_R RTSMB_FAR *PRTSMB_CREATE_R;

typedef struct
{
	word desired_access;
	word search_attributes;

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_OPEN;
typedef RTSMB_OPEN RTSMB_FAR *PRTSMB_OPEN;

typedef struct
{
	word fid;
	word file_attributes;
	dword last_write_time;
	dword file_size;
	word granted_access;

} RTSMB_OPEN_R;
typedef RTSMB_OPEN_R RTSMB_FAR *PRTSMB_OPEN_R;

typedef struct
{
	dword filename_size;
	PFRTCHAR filename;

} RTSMB_QUERY_INFORMATION;
typedef RTSMB_QUERY_INFORMATION RTSMB_FAR *PRTSMB_QUERY_INFORMATION;

typedef struct
{
	word file_attributes;
	dword last_write_time;
	dword file_size;

} RTSMB_QUERY_INFORMATION_R;
typedef RTSMB_QUERY_INFORMATION_R RTSMB_FAR *PRTSMB_QUERY_INFORMATION_R;

typedef struct
{
	word fid;

} RTSMB_QUERY_INFORMATION2;
typedef RTSMB_QUERY_INFORMATION2 RTSMB_FAR *PRTSMB_QUERY_INFORMATION2;

typedef struct
{
	word creation_date;
	word creation_time;
	word last_access_date;
	word last_access_time;
	word last_write_date;
	word last_write_time;

	dword file_size;
	dword file_allocation_size;

	word file_attributes;

} RTSMB_QUERY_INFORMATION2_R;
typedef RTSMB_QUERY_INFORMATION2_R RTSMB_FAR *PRTSMB_QUERY_INFORMATION2_R;

typedef struct
{
	word fid;
	word count;
	dword offset;
	word remaining;

} RTSMB_READ;
typedef RTSMB_READ RTSMB_FAR *PRTSMB_READ;

typedef struct
{
	word data_size;
	PFBYTE data;

} RTSMB_READ_R;
typedef RTSMB_READ_R RTSMB_FAR *PRTSMB_READ_R;

typedef struct
{
	word fid;
	dword offset;
	word max_count;
	word min_count;
	dword timeout;

	BBOOL valid_offset_high;
	dword offset_high;

} RTSMB_READ_RAW;
typedef RTSMB_READ_RAW RTSMB_FAR *PRTSMB_READ_RAW;

typedef struct
{
	char filename[11];

	byte reserved;	/* for server's and client's private use */

	byte server_data[5];
	byte client_data[4];

} RTSMB_RESUME_KEY;
typedef RTSMB_RESUME_KEY RTSMB_FAR *PRTSMB_RESUME_KEY;

typedef struct
{
	word max_count;
	word search_attributes;

	dword filename_size;
	PFRTCHAR filename;

	BBOOL valid_resume_key;
	RTSMB_RESUME_KEY resume_key;

} RTSMB_SEARCH;
typedef RTSMB_SEARCH RTSMB_FAR *PRTSMB_SEARCH;

typedef struct
{
	RTSMB_RESUME_KEY resume_key;
	byte file_attributes;
	word last_write_time;
	word last_write_date;
	dword file_size;
	rtsmb_char filename[13];

} RTSMB_DIRECTORY_INFORMATION_DATA;
typedef RTSMB_DIRECTORY_INFORMATION_DATA RTSMB_FAR *PRTSMB_DIRECTORY_INFORMATION_DATA;
#define RTSMB_DIRECTORY_INFORMATION_DATA_SIZE	43	/* the size in bytes that this structure takes up in buffer */

typedef struct
{
	word count;

} RTSMB_SEARCH_R;
typedef RTSMB_SEARCH_R RTSMB_FAR *PRTSMB_SEARCH_R;

typedef struct
{
	word file_attributes;
	dword last_write_time;

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_SET_INFORMATION;
typedef RTSMB_SET_INFORMATION RTSMB_FAR *PRTSMB_SET_INFORMATION;

typedef struct
{
	word fid;
	word creation_date;
	word creation_time;
	word last_access_date;
	word last_access_time;
	word last_write_date;
	word last_write_time;

} RTSMB_SET_INFORMATION2;
typedef RTSMB_SET_INFORMATION2 RTSMB_FAR *PRTSMB_SET_INFORMATION2;

typedef struct
{
	word total_units;
	word blocks_per_unit;
	word block_size;
	word free_units;

} RTSMB_QUERY_INFORMATION_DISK_R;
typedef RTSMB_QUERY_INFORMATION_DISK_R RTSMB_FAR *PRTSMB_QUERY_INFORMATION_DISK_R;

typedef struct
{
	dword share_size;
	PFRTCHAR share;

	dword password_size;
	PFRTCHAR password;	/* this is an RTCHAR type, but only byte values will be here */

	dword service_size;
	PFRTCHAR service;

} RTSMB_TREE_CONNECT;
typedef RTSMB_TREE_CONNECT RTSMB_FAR *PRTSMB_TREE_CONNECT;

typedef struct
{
	word max_buffer_size;
	word tid;

} RTSMB_TREE_CONNECT_R;
typedef RTSMB_TREE_CONNECT_R RTSMB_FAR *PRTSMB_TREE_CONNECT_R;

typedef struct
{
	word fid;
	word count;
	dword offset;
	word remaining;

	word data_size;
	PFBYTE data;

} RTSMB_WRITE;
typedef RTSMB_WRITE RTSMB_FAR *PRTSMB_WRITE;

typedef struct
{
	word count;

} RTSMB_WRITE_R;
typedef RTSMB_WRITE_R RTSMB_FAR *PRTSMB_WRITE_R;

typedef struct
{
	word fid;
	word count;
	dword offset;
	dword last_write_time;

	word data_size;
	PFBYTE data;

} RTSMB_WRITE_AND_CLOSE;
typedef RTSMB_WRITE_AND_CLOSE RTSMB_FAR *PRTSMB_WRITE_AND_CLOSE;

typedef struct
{
	word count;

} RTSMB_WRITE_AND_CLOSE_R;
typedef RTSMB_WRITE_AND_CLOSE_R RTSMB_FAR *PRTSMB_WRITE_AND_CLOSE_R;

typedef struct
{
	word fid;

	word data_size;
	PFBYTE data;

} RTSMB_WRITE_PRINT_FILE;
typedef RTSMB_WRITE_PRINT_FILE RTSMB_FAR *PRTSMB_WRITE_PRINT_FILE;

typedef struct
{
	word fid;
	word count;
	dword offset;
	dword timeout;
	word write_mode;

	BBOOL valid_offset_high;
	dword offset_high;

	dword data_size;
	PFBYTE data;

} RTSMB_WRITE_RAW;
typedef RTSMB_WRITE_RAW RTSMB_FAR *PRTSMB_WRITE_RAW;

typedef struct
{
	word remaining;

} RTSMB_WRITE_RAW_R1;
typedef RTSMB_WRITE_RAW_R1 RTSMB_FAR *PRTSMB_WRITE_RAW_R1;

typedef struct
{
	word count;

} RTSMB_WRITE_RAW_R2;
typedef RTSMB_WRITE_RAW_R2 RTSMB_FAR *PRTSMB_WRITE_RAW_R2;


typedef struct
{
	word flags;
	dword timeout;

	word max_parameter_count;
	word max_data_count;
	byte max_setup_count;

	word parameter_count;	/* not used in cli */
	word parameter_offset;	/* not used in cli */
	word data_count;		/* not used in cli */
	word data_offset;		/* not used in cli */

	byte setup_size;
	PFWORD setup;

	dword name_size;
	PFRTCHAR name;

	/* temporary variable until this struct get cleaned up
	   from client work */
	word byte_count;	/* not used in cli */

} RTSMB_TRANSACTION;
typedef RTSMB_TRANSACTION RTSMB_FAR *PRTSMB_TRANSACTION;


typedef struct
{
	word parameter_count;	/* not used in cli */
	PFBYTE parameter;		/* not used in cli */

	word data_count;		/* not used in cli */
	PFBYTE data;			/* not used in cli */

	byte setup_size;
	PFWORD setup;

} RTSMB_TRANSACTION_R;
typedef RTSMB_TRANSACTION_R RTSMB_FAR *PRTSMB_TRANSACTION_R;

typedef struct
{
	PRTSMB_TRANSACTION parent;

	word information_level;

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_TRANS2_QUERY_PATH_INFORMATION;
typedef RTSMB_TRANS2_QUERY_PATH_INFORMATION RTSMB_FAR *PRTSMB_TRANS2_QUERY_PATH_INFORMATION;

typedef struct
{
	PRTSMB_TRANSACTION parent;

	word information_level;
	word fid;

} RTSMB_TRANS2_QUERY_FILE_INFORMATION;
typedef RTSMB_TRANS2_QUERY_FILE_INFORMATION RTSMB_FAR *PRTSMB_TRANS2_QUERY_FILE_INFORMATION;

typedef struct
{
	word creation_date;
	word creation_time;
	word last_access_date;
	word last_access_time;
	word last_write_date;
	word last_write_time;

	dword file_size;
	dword allocation_size;
	word attributes;

} RTSMB_INFO_STANDARD;
typedef RTSMB_INFO_STANDARD RTSMB_FAR *PRTSMB_INFO_STANDARD;

typedef struct
{
	word creation_date;
	word creation_time;
	word last_access_date;
	word last_access_time;
	word last_write_date;
	word last_write_time;

	dword file_size;
	dword allocation_size;
	word attributes;

	dword ea_size;

} RTSMB_INFO_QUERY_EA_SIZE;
typedef RTSMB_INFO_QUERY_EA_SIZE RTSMB_FAR *PRTSMB_INFO_QUERY_EA_SIZE;

typedef struct
{
	dword low_creation_time;
	dword high_creation_time;
	dword low_last_access_time;
	dword high_last_access_time;
	dword low_last_write_time;
	dword high_last_write_time;
	dword low_change_time;
	dword high_change_time;

	word attributes;

} RTSMB_QUERY_FILE_BASIC_INFO;
typedef RTSMB_QUERY_FILE_BASIC_INFO RTSMB_FAR *PRTSMB_QUERY_FILE_BASIC_INFO;

typedef struct
{
	dword low_allocation_size;
	dword high_allocation_size;
	dword low_end_of_file;
	dword high_end_of_file;

	dword number_of_links;

	BBOOL delete_pending;
	BBOOL is_directory;

} RTSMB_QUERY_FILE_STANDARD_INFO;
typedef RTSMB_QUERY_FILE_STANDARD_INFO RTSMB_FAR *PRTSMB_QUERY_FILE_STANDARD_INFO;

typedef struct
{
	dword ea_size;

} RTSMB_QUERY_FILE_EA_INFO;
typedef RTSMB_QUERY_FILE_EA_INFO RTSMB_FAR *PRTSMB_QUERY_FILE_EA_INFO;

typedef struct
{
	dword filename_size;
	PFRTCHAR filename;

} RTSMB_QUERY_FILE_NAME_INFO;
typedef RTSMB_QUERY_FILE_NAME_INFO RTSMB_FAR *PRTSMB_QUERY_FILE_NAME_INFO;

typedef struct
{
	dword low_creation_time;
	dword high_creation_time;
	dword low_last_access_time;
	dword high_last_access_time;
	dword low_last_write_time;
	dword high_last_write_time;
	dword low_change_time;
	dword high_change_time;

	word attributes;

	dword low_allocation_size;
	dword high_allocation_size;
	dword low_end_of_file;
	dword high_end_of_file;

	dword number_of_links;

	BBOOL delete_pending;
	BBOOL is_directory;

	dword low_index_number;
	dword high_index_number;

	dword ea_size;
	dword access_flags;

	/* why two of them? */
	dword low_index_number2;
	dword high_index_number2;

	dword low_current_offset;
	dword high_current_offset;

	dword mode;
	dword alignment_requirement;

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_QUERY_FILE_ALL_INFO;
typedef RTSMB_QUERY_FILE_ALL_INFO RTSMB_FAR *PRTSMB_QUERY_FILE_ALL_INFO;

typedef struct
{
	dword filename_size;
	PFRTCHAR filename;

} RTSMB_QUERY_FILE_ALT_NAME_INFO;
typedef RTSMB_QUERY_FILE_ALT_NAME_INFO RTSMB_FAR *PRTSMB_QUERY_FILE_ALT_NAME_INFO;

typedef struct
{
	dword low_stream_size;
	dword high_stream_size;

	dword low_allocation_size;
	dword high_allocation_size;

	dword stream_name_size;
	PFRTCHAR stream_name;

} RTSMB_QUERY_FILE_STREAM_INFO;
typedef RTSMB_QUERY_FILE_STREAM_INFO RTSMB_FAR *PRTSMB_QUERY_FILE_STREAM_INFO;

typedef struct
{
	dword low_compressed_file_size;
	dword high_compressed_file_size;

	word compression_format;
	byte compression_unit_shift;
	byte chunk_shift;
	byte cluster_shift;

} RTSMB_QUERY_FILE_COMPRESSION_INFO;
typedef RTSMB_QUERY_FILE_COMPRESSION_INFO RTSMB_FAR *PRTSMB_QUERY_FILE_COMPRESSION_INFO;

typedef struct
{
	PRTSMB_TRANSACTION parent;

	word information_level;

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_TRANS2_SET_PATH_INFORMATION;
typedef RTSMB_TRANS2_SET_PATH_INFORMATION RTSMB_FAR *PRTSMB_TRANS2_SET_PATH_INFORMATION;

typedef struct
{
	PRTSMB_TRANSACTION parent;

	word information_level;
	word fid;

} RTSMB_TRANS2_SET_FILE_INFORMATION;
typedef RTSMB_TRANS2_SET_FILE_INFORMATION RTSMB_FAR *PRTSMB_TRANS2_SET_FILE_INFORMATION;

typedef struct
{
	BBOOL file_is_deleted;

} RTSMB_FILE_DISPOSITION_INFO;
typedef RTSMB_FILE_DISPOSITION_INFO RTSMB_FAR *PRTSMB_FILE_DISPOSITION_INFO;

typedef struct
{
	dword low_allocation_size;
	dword high_allocation_size;

} RTSMB_FILE_ALLOCATION_INFO;
typedef RTSMB_FILE_ALLOCATION_INFO RTSMB_FAR *PRTSMB_FILE_ALLOCATION_INFO;

typedef struct
{
	dword low_end_of_file;
	dword high_end_of_file;

} RTSMB_FILE_END_OF_FILE_INFO;
typedef RTSMB_FILE_END_OF_FILE_INFO RTSMB_FAR *PRTSMB_FILE_END_OF_FILE_INFO;

typedef struct
{
	PRTSMB_TRANSACTION parent;

	word search_attributes;
	word search_count;
	word flags;
	word information_level;
	dword search_storage_type;

	dword filename_size;
	PFRTCHAR filename;

	dword data_size;
	PFBYTE data;

} RTSMB_TRANS2_FIND_FIRST2;
typedef RTSMB_TRANS2_FIND_FIRST2 RTSMB_FAR *PRTSMB_TRANS2_FIND_FIRST2;

typedef struct
{
	PRTSMB_TRANSACTION parent;

	word sid;
	word search_count;
	word flags;
	word information_level;
	dword resume_key;

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_TRANS2_FIND_NEXT2;
typedef RTSMB_TRANS2_FIND_NEXT2 RTSMB_FAR *PRTSMB_TRANS2_FIND_NEXT2;

typedef struct
{
	word sid;
	word search_count;
	word end_of_search;

	word ea_error_offset;
	word last_name_offset;

} RTSMB_TRANS2_FIND_FIRST_R;
typedef RTSMB_TRANS2_FIND_FIRST_R RTSMB_FAR *PRTSMB_TRANS2_FIND_FIRST_R;

typedef struct
{
	word search_count;
	word end_of_search;

	word ea_error_offset;
	word last_name_offset;

} RTSMB_TRANS2_FIND_NEXT_R;
typedef RTSMB_TRANS2_FIND_NEXT_R RTSMB_FAR *PRTSMB_TRANS2_FIND_NEXT_R;

typedef struct
{
	word sid;

} RTSMB_FIND_CLOSE2;
typedef RTSMB_FIND_CLOSE2 RTSMB_FAR *PRTSMB_FIND_CLOSE2;

typedef struct
{
	BBOOL valid_resume_key;
	dword resume_key;

	word creation_date;
	word creation_time;
	word last_access_date;
	word last_access_time;
	word last_write_date;
	word last_write_time;

	dword file_size;
	dword allocation_size;
	word attributes;

	/* These work a little differently than most of the _size
	   variables in these structs.
	   Here, it means the exact length of information in |filename|.
	   The packing methods will not try and figure it out for you.
	   Do not include the NULL byte or bytes in this size.
	*/
	byte filename_size;
	PFRTCHAR filename;

} RTSMB_FIND_FILE_INFO_STANDARD;
typedef RTSMB_FIND_FILE_INFO_STANDARD RTSMB_FAR *PRTSMB_FIND_FILE_INFO_STANDARD;

typedef struct
{
	/* is set to true when writing if you want to write resume keys.
	   is set to true when reading if you want to read resume keys. */
	BBOOL valid_resume_key;
	dword resume_key;

	word creation_date;
	word creation_time;
	word last_access_date;
	word last_access_time;
	word last_write_date;
	word last_write_time;

	dword file_size;
	dword allocation_size;
	word attributes;
	dword ea_size;

	/* These work a little differently than most of the _size
	   variables in these structs.
	   Here, it means the exact length of information in |filename|.
	   The packing methods will not try and figure it out for you.
	   Do not include the NULL byte or bytes in this size.
	*/
	byte filename_size;
	PFRTCHAR filename;

} RTSMB_FIND_FILE_INFO_QUERY_EA_SIZE;
typedef RTSMB_FIND_FILE_INFO_QUERY_EA_SIZE RTSMB_FAR *PRTSMB_FIND_FILE_INFO_QUERY_EA_SIZE;

typedef struct
{
	dword file_index;

	dword low_creation_time;
	dword high_creation_time;
	dword low_last_access_time;
	dword high_last_access_time;
	dword low_last_write_time;
	dword high_last_write_time;
	dword low_change_time;
	dword high_change_time;
	dword low_end_of_file;
	dword high_end_of_file;
	dword low_allocation_size;
	dword high_allocation_size;

	dword extended_file_attributes;

	/* These work a little differently than most of the _size
	   variables in these structs.
	   Here, it means the exact length of information in |filename|.
	   The packing methods will not try and figure it out for you.
	   Do not include the NULL byte or bytes in this size.
	*/
	dword filename_size;
	PFRTCHAR filename;

} RTSMB_FIND_FILE_DIRECTORY_INFO;
typedef RTSMB_FIND_FILE_DIRECTORY_INFO RTSMB_FAR *PRTSMB_FIND_FILE_DIRECTORY_INFO;

typedef struct
{
	dword file_index;

	dword low_creation_time;
	dword high_creation_time;
	dword low_last_access_time;
	dword high_last_access_time;
	dword low_last_write_time;
	dword high_last_write_time;
	dword low_change_time;
	dword high_change_time;
	dword low_end_of_file;
	dword high_end_of_file;
	dword low_allocation_size;
	dword high_allocation_size;

	dword extended_file_attributes;
	dword ea_size;

	/* These work a little differently than most of the _size
	   variables in these structs.
	   Here, it means the exact length of information in |filename|.
	   The packing methods will not try and figure it out for you.
	   Do not include the NULL byte or bytes in this size.
	*/
	dword filename_size;
	PFRTCHAR filename;

} RTSMB_FIND_FILE_FULL_DIRECTORY_INFO;
typedef RTSMB_FIND_FILE_FULL_DIRECTORY_INFO RTSMB_FAR *PRTSMB_FIND_FILE_FULL_DIRECTORY_INFO;

typedef struct
{
	dword file_index;

	dword low_creation_time;
	dword high_creation_time;
	dword low_last_access_time;
	dword high_last_access_time;
	dword low_last_write_time;
	dword high_last_write_time;
	dword low_change_time;
	dword high_change_time;
	dword low_end_of_file;
	dword high_end_of_file;
	dword low_allocation_size;
	dword high_allocation_size;

	dword extended_file_attributes;
	dword ea_size;

	byte short_name_size;	/* size in characters */
	rtsmb_char short_name[13];	/* 8.3 name */

	dword filename_size;
	PFRTCHAR filename;

} RTSMB_FIND_FILE_BOTH_DIRECTORY_INFO;
typedef RTSMB_FIND_FILE_BOTH_DIRECTORY_INFO RTSMB_FAR *PRTSMB_FIND_FILE_BOTH_DIRECTORY_INFO;

typedef struct
{
	dword file_index;

	/* These work a little differently than most of the _size
	   variables in these structs.
	   Here, it means the exact length of information in |filename|.
	   The packing methods will not try and figure it out for you.
	   Do not include the NULL byte or bytes in this size.
	*/
	dword filename_size;
	PFRTCHAR filename;

} RTSMB_FIND_FILE_NAMES_INFO;
typedef RTSMB_FIND_FILE_NAMES_INFO RTSMB_FAR *PRTSMB_FIND_FILE_NAMES_INFO;

typedef struct
{
	PRTSMB_TRANSACTION parent;

	word information_level;

} RTSMB_TRANS2_QUERY_FS_INFORMATION;
typedef RTSMB_TRANS2_QUERY_FS_INFORMATION RTSMB_FAR *PRTSMB_TRANS2_QUERY_FS_INFORMATION;

typedef struct
{
	dword file_system_id;
	dword sectors_per_unit;
	dword total_units;
	dword available_units;
	word bytes_per_sector;

} RTSMB_INFO_ALLOCATION;
typedef RTSMB_INFO_ALLOCATION RTSMB_FAR *PRTSMB_INFO_ALLOCATION;

typedef struct
{
	dword serial_number;

	byte label_size;
	PFRTCHAR label;

} RTSMB_INFO_VOLUME;
typedef RTSMB_INFO_VOLUME RTSMB_FAR *PRTSMB_INFO_VOLUME;

typedef struct
{
	dword low_creation_time;
	dword high_creation_time;

	dword serial_number;

	dword label_size;
	PFRTCHAR label;

} RTSMB_QUERY_FS_VOLUME_INFO;
typedef RTSMB_QUERY_FS_VOLUME_INFO RTSMB_FAR *PRTSMB_QUERY_FS_VOLUME_INFO;

typedef struct
{
	dword low_total_units;
	dword high_total_units;
	dword low_free_units;
	dword high_free_units;

	dword sectors_per_unit;
	dword bytes_per_sector;

} RTSMB_QUERY_FS_SIZE_INFO;
typedef RTSMB_QUERY_FS_SIZE_INFO RTSMB_FAR *PRTSMB_QUERY_FS_SIZE_INFO;

typedef struct
{
	dword device_type;
	dword characteristics;

} RTSMB_QUERY_FS_DEVICE_INFO;
typedef RTSMB_QUERY_FS_DEVICE_INFO RTSMB_FAR *PRTSMB_QUERY_FS_DEVICE_INFO;

typedef struct
{
	dword attributes;
	dword max_filename_size;

	dword fs_name_size;
	PFRTCHAR fs_name;

} RTSMB_QUERY_FS_ATTRIBUTE_INFO;
typedef RTSMB_QUERY_FS_ATTRIBUTE_INFO RTSMB_FAR *PRTSMB_QUERY_FS_ATTRIBUTE_INFO;

typedef struct
{
	PRTSMB_TRANSACTION parent;

	word opcode;

	dword parameter_size;
	PFRTCHAR parameter;

	dword answer_size;
	PFRTCHAR answer;

} RTSMB_RAP_REQUEST;
typedef RTSMB_RAP_REQUEST RTSMB_FAR *PRTSMB_RAP_REQUEST;

typedef struct
{
	word status;
	word converter;
	word available_bytes;

} RTSMB_RAP_RESPONSE;
typedef RTSMB_RAP_RESPONSE RTSMB_FAR *PRTSMB_RAP_RESPONSE;

typedef struct
{
	word information_level;
	word receive_size;

} RTSMB_RAP_GET_INFO;
typedef RTSMB_RAP_GET_INFO RTSMB_FAR *PRTSMB_RAP_GET_INFO;

typedef struct
{
	dword share_size;
	PFRTCHAR share;

	word information_level;
	word receive_size;

} RTSMB_RAP_SHARE_GET_INFO;
typedef RTSMB_RAP_SHARE_GET_INFO RTSMB_FAR *PRTSMB_RAP_SHARE_GET_INFO;

typedef struct
{
	rtsmb_char name[13];

} RTSMB_RAP_SHARE_INFO_0;
typedef RTSMB_RAP_SHARE_INFO_0 RTSMB_FAR *PRTSMB_RAP_SHARE_INFO_0;

typedef struct
{
	rtsmb_char name[13];
	word type;

	dword comment_size;
	PFRTCHAR comment;

} RTSMB_RAP_SHARE_INFO_1;
typedef RTSMB_RAP_SHARE_INFO_1 RTSMB_FAR *PRTSMB_RAP_SHARE_INFO_1;

typedef struct
{
	word status;
	word converter;
	word entry_count;
	word available_entries;

} RTSMB_RAP_ENUM_HEADER_R;
typedef RTSMB_RAP_ENUM_HEADER_R RTSMB_FAR *PRTSMB_RAP_ENUM_HEADER_R;

typedef struct
{
	int share_num;	/* 0-based */
	int total_shares;

	RTSMB_RAP_SHARE_INFO_1 share_data;

} RTSMB_RAP_SHARE_ENUM_INFO_R;
typedef RTSMB_RAP_SHARE_ENUM_INFO_R RTSMB_FAR *PRTSMB_RAP_SHARE_ENUM_INFO_R;

typedef struct
{
	rtsmb_char name[16];

} RTSMB_RAP_SERVER_INFO_0;
typedef RTSMB_RAP_SERVER_INFO_0 RTSMB_FAR *PRTSMB_RAP_SERVER_INFO_0;

typedef struct
{
	rtsmb_char name[16];

	byte version_major;
	byte version_minor;

	dword type;

	dword comment_size;
	PFRTCHAR comment;

	/* which number it is among the total */
	int info_num;

	/* how many total info structs are in this packet */
	int info_total;

} RTSMB_RAP_SERVER_INFO_1;
typedef RTSMB_RAP_SERVER_INFO_1 RTSMB_FAR *PRTSMB_RAP_SERVER_INFO_1;

typedef struct
{
	word status;

} RTSMB_RAP_ACCESS_INFO;
typedef RTSMB_RAP_ACCESS_INFO RTSMB_FAR *PRTSMB_RAP_ACCESS_INFO;

typedef struct
{
	byte version_major;
	byte version_minor;

	dword computer_name_size;
	PFRTCHAR computer_name;

	dword username_size;
	PFRTCHAR username;

	dword lan_group_size;
	PFRTCHAR lan_group;

	dword logon_domain_size;
	PFRTCHAR logon_domain;

	dword other_domains_size;
	PFRTCHAR other_domains;

} RTSMB_RAP_WKSTA_INFO;
typedef RTSMB_RAP_WKSTA_INFO RTSMB_FAR *PRTSMB_RAP_WKSTA_INFO;

typedef struct
{
	rtsmb_char name[13];

} RTSMB_RAP_PRINTER_QUEUE_INFO_0;
typedef RTSMB_RAP_PRINTER_QUEUE_INFO_0 RTSMB_FAR *PRTSMB_RAP_PRINTER_QUEUE_INFO_0;

typedef struct
{
	word priority;
	word start_time;
	word until_time;
	word status;
	word num_jobs;

	rtsmb_char name[13];
	dword sep_file_size;
	PFRTCHAR sep_file;
	dword preprocessor_size;
	PFRTCHAR preprocessor;
	dword parameters_size;
	PFRTCHAR parameters;
	dword comment_size;
	PFRTCHAR comment;
	dword destinations_size;
	PFRTCHAR destinations;

} RTSMB_RAP_PRINTER_QUEUE_INFO_1;
typedef RTSMB_RAP_PRINTER_QUEUE_INFO_1 RTSMB_FAR *PRTSMB_RAP_PRINTER_QUEUE_INFO_1;

typedef struct
{
	word priority;
	word start_time;
	word until_time;
	word status;
	word num_jobs;

	dword name_size;
	PFRTCHAR name;
	dword sep_file_size;
	PFRTCHAR sep_file;
	dword preprocessor_size;
	PFRTCHAR preprocessor;
	dword parameters_size;
	PFRTCHAR parameters;
	dword comment_size;
	PFRTCHAR comment;
	dword printers_size;
	PFRTCHAR printers;
	dword driver_name_size;
	PFRTCHAR driver_name;
	dword driver_data_size;
	PFRTCHAR driver_data;

} RTSMB_RAP_PRINTER_QUEUE_INFO_3;
typedef RTSMB_RAP_PRINTER_QUEUE_INFO_3 RTSMB_FAR *PRTSMB_RAP_PRINTER_QUEUE_INFO_3;

typedef struct
{
	dword name_size;
	PFRTCHAR name;

} RTSMB_RAP_PRINTER_QUEUE_INFO_5;
typedef RTSMB_RAP_PRINTER_QUEUE_INFO_5 RTSMB_FAR *PRTSMB_RAP_PRINTER_QUEUE_INFO_5;

typedef struct
{
	byte command;
	byte flags;

	dword name_size;
	PFRTCHAR name;

} RTSMB_BROWSE_HEADER;
typedef RTSMB_BROWSE_HEADER RTSMB_FAR *PRTSMB_BROWSE_HEADER;

typedef struct
{
	word opcode;
	word priority;
	word type;

} RTSMB_MAILSLOT_HEADER;
typedef RTSMB_MAILSLOT_HEADER RTSMB_FAR *PRTSMB_MAILSLOT_HEADER;

typedef struct
{
	word information_level;
	word receive_size;
	dword server_type;

	dword domain_size;
	PFRTCHAR domain;

} RTSMB_RAP_SERVER_ENUM2;
typedef RTSMB_RAP_SERVER_ENUM2 RTSMB_FAR *PRTSMB_RAP_SERVER_ENUM2;

typedef struct
{
	/* spec says just a word token, but truth is a byte count and a dword token */
	byte count;
	dword token;

} RTSMB_BROWSE_GET_BACKUP_LIST;
typedef RTSMB_BROWSE_GET_BACKUP_LIST RTSMB_FAR *PRTSMB_BROWSE_GET_BACKUP_LIST;

typedef struct
{
	dword token;

	byte count;
	PFRTCHAR RTSMB_FAR *servers;

} RTSMB_BROWSE_GET_BACKUP_LIST_R;
typedef RTSMB_BROWSE_GET_BACKUP_LIST_R RTSMB_FAR *PRTSMB_BROWSE_GET_BACKUP_LIST_R;

typedef struct
{
	byte next_command;

	word fid;
	byte lock_type;
	byte oplock_level;
	dword timeout;
	word num_unlocks;
	word num_locks;

} RTSMB_LOCKING_AND_X;
typedef RTSMB_LOCKING_AND_X RTSMB_FAR *PRTSMB_LOCKING_AND_X;

typedef struct
{
	byte next_command;

} RTSMB_LOCKING_AND_X_R;
typedef RTSMB_LOCKING_AND_X_R RTSMB_FAR *PRTSMB_LOCKING_AND_X_R;


#endif /* __SMB_OBJS_H__ */
