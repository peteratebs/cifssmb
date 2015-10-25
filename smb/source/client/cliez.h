#ifndef __CLI_EZ_H__
#define __CLI_EZ_H__

#include "smbdefs.h"
#include "clissn.h"

#if (INCLUDE_RTSMB_CLIENT_EZ)

/* This is returned if the filename passed in could not be parsed. */
#define RTSMB_CLI_EZ_INVALID_PATH          -2

/* This is returned if we have problems connecting to a server. */
#define RTSMB_CLI_EZ_COULD_NOT_CONNECT     -3

/* This is returned if we have too many shares */
#define RTSMB_CLI_EZ_TOO_MANY_SHARES       -4

/* This is returned if there was some generic error on the server side. */
#define RTSMB_CLI_EZ_SESSION_ERROR         -5

/* This is returned if we did not recognize the file descriptor. */
#define RTSMB_CLI_EZ_BAD_FD                -6

/* This is returned if there was not a server specified in the filename, and the function requires one. */
#define RTSMB_CLI_EZ_NO_SERVER_SPECIFIED   -7

/* This is returned if there was not a share specified in the filename, and the function requires one. */
#define RTSMB_CLI_EZ_NO_SHARE_SPECIFIED    -8

/* This is returned if there was not a filename path specified in the filename, and the function requires one. */
#define RTSMB_CLI_EZ_NO_FILENAME_SPECIFIED -9

/* This is returned if a buffer is not big enough or too many searches are trying to be run at once. */
#define RTSMB_CLI_EZ_NOT_ENOUGH_RESOURCES  -10

/* This is returned if you are trying to rename across sessions/shares. */
#define RTSMB_CLI_EZ_NOT_SAME_SESSION      -11

/* This is returned if the file you were trying to use did not exist on the server. */
#define RTSMB_CLI_EZ_FILE_NOT_FOUND        -12

/* This is returned if you do not have the permissions to attempt some file operation (like write to a read only file). */
#define RTSMB_CLI_EZ_BAD_PERMISSIONS       -13 

/* This is returned if too many files are open and we can't do the requested operation until they are closed */
#define RTSMB_CLI_EZ_TOO_MANY_FIDS         -14


void rtsmb_cli_ez_set_user_rt (PFRTCHAR username, PFCHAR password, PFRTCHAR domain);
int  rtsmb_cli_ez_open_rt (PFRTCHAR name, int flags, int mode);
int  rtsmb_cli_ez_read (int fd, PFBYTE buffer, unsigned int count);
int  rtsmb_cli_ez_write (int fd, PFBYTE buffer, unsigned int count);
long rtsmb_cli_ez_seek (int fd, long offset, int origin);
int  rtsmb_cli_ez_close (int fd);
int  rtsmb_cli_ez_truncate (int fd, long offset);
int  rtsmb_cli_ez_flush (int fd);
int  rtsmb_cli_ez_rename_rt (PFRTCHAR old_filename, PFRTCHAR new_filename);
int  rtsmb_cli_ez_delete_rt (PFRTCHAR filename);
int  rtsmb_cli_ez_mkdir_rt (PFRTCHAR filename);
int  rtsmb_cli_ez_rmdir_rt (PFRTCHAR filename);
int  rtsmb_cli_ez_find_first_rt (PFRTCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);
int  rtsmb_cli_ez_find_next (PRTSMB_CLI_SESSION_DSTAT pdstat);
void rtsmb_cli_ez_find_close (PRTSMB_CLI_SESSION_DSTAT pdstat);
int  rtsmb_cli_ez_stat_rt (PFRTCHAR filename, PRTSMB_CLI_SESSION_FSTAT pfstat);
int  rtsmb_cli_ez_chmode_rt (PFRTCHAR filename, int attributes);
int  rtsmb_cli_ez_get_free_rt (PFRTCHAR filename, PFINT total_blocks, PFINT free_blocks, PFINT sectors_per_block, PFINT bytes_per_sector);
int  rtsmb_cli_ez_get_cwd_rt (PFRTCHAR filename, rtsmb_size size);
int  rtsmb_cli_ez_set_cwd_rt (PFRTCHAR filename);


/* Stuff below this line is not for public use -- not part of the API */
typedef struct
{
	rtsmb_char pattern [SMBF_FILENAMESIZE + 1];
	BBOOL unicode;
	int sid;	/* ez sid */

} RTSMB_CLI_EZ_SEARCH;
typedef RTSMB_CLI_EZ_SEARCH RTSMB_FAR *PRTSMB_CLI_EZ_SEARCH;

typedef struct
{
	BBOOL in_use;
	dword thread_id;
	dword timestamp;
	rtsmb_char working_dir [SMBF_FILENAMESIZE + 1];

} RTSMB_CLI_EZ_THREAD;
typedef RTSMB_CLI_EZ_THREAD RTSMB_FAR *PRTSMB_CLI_EZ_THREAD;

typedef struct
	{
		BBOOL valid_server;
		char server [RTSMB_NB_NAME_SIZE + 1];

		BBOOL valid_share;
		char share [RTSMB_MAX_SHARENAME_SIZE + 1];

		BBOOL valid_filename;
		/* This size is chosen so that a full absolute path to EZ will be at most SMBF_FILENAMESIZE */
		rtsmb_char filename [SMBF_FILENAMESIZE - RTSMB_MAX_SHARENAME_SIZE - RTSMB_NB_NAME_SIZE - 2];

	} RTSMB_URI;
typedef RTSMB_URI RTSMB_FAR *PRTSMB_URI;
int rtsmb_cli_ez_setup_char (PFCHAR name, PRTSMB_URI uri, PFINT session);
int rtsmb_cli_ez_open_uri (PRTSMB_URI uri, int flags, int mode, int sid);

#endif /* INCLUDE_RTMSB_CLIENT_EZ */

#endif
