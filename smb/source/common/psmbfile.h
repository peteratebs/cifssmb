#ifndef __PSMBFILE_H__
#define __PSMBFILE_H__

#include "smbdefs.h"

/* DO NOT CHANGE ANY CONSTANTS */

#define SMBF_FILENAMESIZE  180

/************************************************************************
 * File System API abstraction layer constants                          *
 ************************************************************************/


/* for the origin argument to fs_lseek */
#define RTSMB_SEEK_SET  0       /* Seek from beginning of file */
#define RTSMB_SEEK_CUR  1       /* Seek from file pointer */
#define RTSMB_SEEK_END  2       /* Seek from end of file */


/************************************************************************
 * Type definitions
 ************************************************************************/

typedef struct smbdstat SMBDSTAT;
typedef SMBDSTAT RTSMB_FAR *PSMBDSTAT;
typedef struct smbfstat SMBFSTAT;
typedef SMBFSTAT RTSMB_FAR *PSMBFSTAT;

typedef int  (RTSMB_FAR *RTSMB_FS_OPENFN)(char RTSMB_FAR * name, unsigned short flag, unsigned short mode);
typedef int  (RTSMB_FAR *RTSMB_FS_READFN)(int fd,  unsigned char RTSMB_FAR * buf, unsigned int count);
typedef int  (RTSMB_FAR *RTSMB_FS_WRITEFN)(int fd, unsigned char RTSMB_FAR * buf, unsigned int count);
typedef long (RTSMB_FAR *RTSMB_FS_LSEEKFN)(int fd, long offset, int origin);
typedef int  (RTSMB_FAR *RTSMB_FS_CLOSEFN)(int fd);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_TRUNCATEFN)(int fd, dword offset);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_FLUSHFN)(int fd);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_RENAMEFN)(char RTSMB_FAR * name, char RTSMB_FAR * newname);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_DELETEFN)(char RTSMB_FAR * name);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_MKDIRFN)(char RTSMB_FAR * name);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_RMDIRFN)(char RTSMB_FAR * name);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_SETCWDFN)(char RTSMB_FAR * name);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_PWDFN)(char RTSMB_FAR * name, long size);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_GFIRSTFN)(PSMBDSTAT dirobj, char RTSMB_FAR * name);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_GNEXTFN)(PSMBDSTAT dirobj);
typedef void (RTSMB_FAR *RTSMB_FS_GDONEFN)(PSMBDSTAT dirobj);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_STATFN)(char RTSMB_FAR * name, PSMBFSTAT stat);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_CHMODEFN)(char RTSMB_FAR * name, unsigned char attributes);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_GET_FREEFN)(char RTSMB_FAR * name, unsigned long *total, unsigned long *free, unsigned long *sectors_per_unit, unsigned short *bytes_per_sector);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_SET_TIMEFN) (int fid, TIME atime, TIME wtime, TIME ctime, TIME htime);

typedef int  (RTSMB_FAR *RTSMB_FS_WOPENFN)(unsigned short RTSMB_FAR * name, unsigned short flag, unsigned short mode);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WRENAMEFN)(unsigned short RTSMB_FAR * name, unsigned short RTSMB_FAR * newname);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WDELETEFN)(unsigned short RTSMB_FAR * name);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WMKDIRFN)(unsigned short RTSMB_FAR * name);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WRMDIRFN)(unsigned short RTSMB_FAR * name);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WSETCWDFN)(unsigned short RTSMB_FAR * name);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WPWDFN)(unsigned short RTSMB_FAR * name, long size);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WGFIRSTFN)(PSMBDSTAT dirobj, unsigned short RTSMB_FAR * name);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WGNEXTFN)(PSMBDSTAT dirobj);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WSTATFN)(unsigned short RTSMB_FAR * name, PSMBFSTAT stat);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WCHMODEFN)(unsigned short RTSMB_FAR * name, unsigned char attributes);
typedef BBOOL (RTSMB_FAR *RTSMB_FS_WGET_FREEFN)(unsigned short RTSMB_FAR * name, unsigned long *total, unsigned long *free, unsigned long *sectors_per_unit, unsigned short *bytes_per_sector);


/************************************************************************
 * SMBFILEAPI - File system interface
 ************************************************************************/

typedef struct smbfileapi
{
	RTSMB_FS_OPENFN        fs_open;
	RTSMB_FS_READFN        fs_read;
	RTSMB_FS_WRITEFN       fs_write;
	RTSMB_FS_LSEEKFN       fs_lseek;
	RTSMB_FS_TRUNCATEFN    fs_truncate;
	RTSMB_FS_FLUSHFN       fs_flush;
	RTSMB_FS_CLOSEFN       fs_close;
	RTSMB_FS_RENAMEFN      fs_rename;
	RTSMB_FS_DELETEFN      fs_delete;
	RTSMB_FS_MKDIRFN       fs_mkdir;
	RTSMB_FS_RMDIRFN       fs_rmdir;
	RTSMB_FS_SETCWDFN      fs_set_cwd;
	RTSMB_FS_PWDFN         fs_pwd;
	RTSMB_FS_GFIRSTFN      fs_gfirst;
	RTSMB_FS_GNEXTFN       fs_gnext;
	RTSMB_FS_GDONEFN       fs_gdone;
	RTSMB_FS_STATFN        fs_stat;
	RTSMB_FS_CHMODEFN      fs_chmode;
	RTSMB_FS_GET_FREEFN    fs_get_free;
	RTSMB_FS_SET_TIMEFN    fs_set_time;

	/* The following function pointers may be null
	   if the file system does not support unicode. */
	RTSMB_FS_WOPENFN	   fs_wopen;
	RTSMB_FS_WRENAMEFN	   fs_wrename;
	RTSMB_FS_WDELETEFN	   fs_wdelete;
	RTSMB_FS_WMKDIRFN	   fs_wmkdir;
	RTSMB_FS_WRMDIRFN	   fs_wrmdir;
	RTSMB_FS_WSETCWDFN	   fs_wset_cwd;
	RTSMB_FS_WPWDFN		   fs_wpwd;
	RTSMB_FS_WGFIRSTFN	   fs_wgfirst;
	RTSMB_FS_WGNEXTFN	   fs_wgnext;
	RTSMB_FS_WSTATFN	   fs_wstat;
	RTSMB_FS_WCHMODEFN	   fs_wchmode;
	RTSMB_FS_WGET_FREEFN   fs_wget_free;

} SMBFILEAPI;

typedef SMBFILEAPI RTSMB_FAR *PSMBFILEAPI;


/************************************************************************
 * SMBFSTAT - File Status                                                 *
 ************************************************************************/

struct smbfstat
{
	unsigned char  f_attributes;
	unsigned long  f_size;    /* file size, in bytes */
	TIME           f_atime64; /* last access time */
	TIME           f_wtime64; /* last write time */
	TIME           f_ctime64; /* last create time */
	TIME           f_htime64; /* last change time */
};



/************************************************************************
 * SMBDSTAT - Directory Iterator; used for directory scans               *
 ************************************************************************/

struct smbdstat
{
	PSMBFILEAPI    fs_api;

#if (INCLUDE_RTSMB_UNICODE)
	char           filename[SMBF_FILENAMESIZE * 2 + 2];
	char           short_filename[26];
#else
	char           filename[SMBF_FILENAMESIZE + 1];
	char           short_filename[13];
#endif

	char           unicode;                  /* set it to zero if filename is ascii,
	                                            or non-zero when it is unicode */
	unsigned char  fattributes;
	unsigned long  fsize;

	TIME           fatime64; /* last access time */
	TIME           fwtime64; /* last write time */
	TIME           fctime64; /* last create time */
	TIME           fhtime64; /* last change time */

	void * 		   rtp_dirobj;  /* pointer to rtplatform's dirobj */
};


/************************************************************************
 * Porting functions
 ************************************************************************/

/* set up the prtsmb_filesys structure */
int rtsmb_fileport_init (void);

extern PSMBFILEAPI prtsmb_filesys;

#endif /*__PSMBFILE_H__*/
