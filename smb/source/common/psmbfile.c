//
// PSMBFILE.C - RTSMB File System Interface Layer to RTPlatform
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//
// NOTE:The module no longer needs to be ported.  RTSMB now sits on top of
// RTPlatform, which will need to be ported to your filesystem.  In other
// words, this is ported to RTPlatform.
// However, you may modify this file if you do not want to use RTPlatform interface
// for FILE porting layer.
//

#include "rtpfile.h"
#include "rtpwfile.h"
#include "rtpdutil.h"
#include "rtpdobj.h"  /* _YI_ 9/24/2004 */
#include "rtpwcs.h"   /* _YI_ 9/24/2004 */
#include "smbdebug.h" /* _VM_ 12/27/2004 */

#include "psmbfile.h"
#include "smbutil.h"

#if (INCLUDE_RTSMB_SERVER)

// ********************************************************************
int  rtplatform_open(char RTSMB_FAR * name, unsigned short flag, unsigned short mode);
long rtplatform_read(int fd,  unsigned char RTSMB_FAR * buf, long count);
long rtplatform_write(int fd,  unsigned char RTSMB_FAR * buf, long count);
int  rtplatform_close(int fd);
long rtplatform_lseek(int fd, long offset, int origin);
BBOOL rtplatform_truncate(int fd, long offset);
BBOOL rtplatform_flush(int fd);
BBOOL rtplatform_pwd(char RTSMB_FAR * to, long size);
BBOOL rtplatform_rename(char RTSMB_FAR * from, char RTSMB_FAR * to);
BBOOL rtplatform_delete(char RTSMB_FAR * to);
BBOOL rtplatform_mkdir(char RTSMB_FAR * to);
BBOOL rtplatform_setcwd(char RTSMB_FAR * to);
BBOOL rtplatform_rmdir(char RTSMB_FAR * to);
BBOOL rtplatform_gfirst(PSMBDSTAT dirobj, char RTSMB_FAR * name);
BBOOL rtplatform_gnext(PSMBDSTAT dirobj);
void rtplatform_gdone(PSMBDSTAT dirobj);
BBOOL rtplatform_stat(char RTSMB_FAR * name, PSMBFSTAT vstat);
BBOOL rtplatform_chmode(char RTSMB_FAR * name, unsigned char attributes);
BBOOL rtplatform_get_free(char RTSMB_FAR * name, unsigned long *total, unsigned long *free, unsigned long *sectors_per_unit, unsigned short *bytes_per_sector);
BBOOL rtplatform_set_time(int fd, TIME atime, TIME wtime, TIME ctime, TIME htime);

int  rtplatform_wopen(unsigned short RTSMB_FAR * name, unsigned short flag, unsigned short mode);
BBOOL rtplatform_wrename(unsigned short RTSMB_FAR * from, unsigned short RTSMB_FAR * to);
BBOOL rtplatform_wdelete(unsigned short RTSMB_FAR * to);
BBOOL rtplatform_wmkdir(unsigned short RTSMB_FAR * to);
BBOOL rtplatform_wrmdir(unsigned short RTSMB_FAR * to);
BBOOL rtplatform_wsetcwd(unsigned short RTSMB_FAR * to);
BBOOL rtplatform_wpwd(unsigned short RTSMB_FAR * to, long size);
BBOOL rtplatform_wgfirst(PSMBDSTAT dirobj, unsigned short RTSMB_FAR * name);
BBOOL rtplatform_wgnext (PSMBDSTAT dirobj);
BBOOL rtplatform_wstat(unsigned short RTSMB_FAR * name, PSMBFSTAT vstat);
BBOOL rtplatform_wchmode(unsigned short RTSMB_FAR * name, unsigned char attributes);
BBOOL rtplatform_wget_free(unsigned short RTSMB_FAR * name, unsigned long *total, unsigned long *free, unsigned long *sectors_per_unit, unsigned short *bytes_per_sector);

void rtplatform_translate_dstat (PSMBDSTAT dstat, void * rtp_dirobj);
void rtplatform_translate_fstat (PSMBFSTAT fstat, void * rtp_dirobj);

static SMBFILEAPI _rtsmb_filesys_rtplatform;
PSMBFILEAPI prtsmb_filesys = 0;


/******************************************************************************

 rtsmb_fileport_init - Initialize the default file system

 Description

    The interface between RTSMB and underlying file system routines is the
    SMBFILEAPI struct, which contains a set of function pointers to the various
    file system routines needed by RTSMB.  There is always one such struct,
    pointed to by the global variable prtsmb_filesys, that provides RTSMB
    with access to the default file system.  It is possible to mount SMB/CIFS
    shares using many different SMBFILEAPI structures (only one per share), to
    provide access to several file systems on a device.  However, if the
    SMBFILEAPI specified in the call to mount a share is NULL (i.e. no file
    system is explicitly specified), then prtsmb_filesys will be used.

 See Also

 Returns

    0 on success, negative on failure

******************************************************************************/

int rtsmb_fileport_init(void)
{

    /* Return if already initialized */
    if (prtsmb_filesys)
    {
        return (0);
    }

    prtsmb_filesys = &_rtsmb_filesys_rtplatform;

    prtsmb_filesys->fs_open         =   (RTSMB_FS_OPENFN)        rtplatform_open;
    prtsmb_filesys->fs_read         =   (RTSMB_FS_READFN)        rtplatform_read;
    prtsmb_filesys->fs_write        =   (RTSMB_FS_WRITEFN)       rtplatform_write;
    prtsmb_filesys->fs_lseek        =   (RTSMB_FS_LSEEKFN)       rtplatform_lseek;
    prtsmb_filesys->fs_truncate     =   (RTSMB_FS_TRUNCATEFN)    rtplatform_truncate;
    prtsmb_filesys->fs_flush        =   (RTSMB_FS_FLUSHFN)       rtplatform_flush;
    prtsmb_filesys->fs_close        =   (RTSMB_FS_CLOSEFN)       rtplatform_close;
    prtsmb_filesys->fs_rename       =   (RTSMB_FS_RENAMEFN)      rtplatform_rename;
    prtsmb_filesys->fs_delete       =   (RTSMB_FS_DELETEFN)      rtplatform_delete;
    prtsmb_filesys->fs_mkdir        =   (RTSMB_FS_MKDIRFN)       rtplatform_mkdir;
    prtsmb_filesys->fs_rmdir        =   (RTSMB_FS_RMDIRFN)       rtplatform_rmdir;
    prtsmb_filesys->fs_set_cwd       =  (RTSMB_FS_SETCWDFN)      rtplatform_setcwd;
    prtsmb_filesys->fs_pwd          =   (RTSMB_FS_PWDFN)         rtplatform_pwd;
    prtsmb_filesys->fs_gfirst       =   (RTSMB_FS_GFIRSTFN)      rtplatform_gfirst;
    prtsmb_filesys->fs_gnext        =   (RTSMB_FS_GNEXTFN)       rtplatform_gnext;
    prtsmb_filesys->fs_gdone        =   (RTSMB_FS_GDONEFN)       rtplatform_gdone;
    prtsmb_filesys->fs_stat         =   (RTSMB_FS_STATFN)        rtplatform_stat;
    prtsmb_filesys->fs_chmode       =   (RTSMB_FS_CHMODEFN)      rtplatform_chmode;
    prtsmb_filesys->fs_get_free     =   (RTSMB_FS_GET_FREEFN)    rtplatform_get_free;
    prtsmb_filesys->fs_set_time     =   (RTSMB_FS_SET_TIMEFN)    rtplatform_set_time;

    prtsmb_filesys->fs_wopen        =   (RTSMB_FS_WOPENFN)       rtplatform_wopen;
    prtsmb_filesys->fs_wrename      =   (RTSMB_FS_WRENAMEFN)     rtplatform_wrename;
    prtsmb_filesys->fs_wdelete      =   (RTSMB_FS_WDELETEFN)     rtplatform_wdelete;
    prtsmb_filesys->fs_wmkdir       =   (RTSMB_FS_WMKDIRFN)      rtplatform_wmkdir;
    prtsmb_filesys->fs_wrmdir       =   (RTSMB_FS_WRMDIRFN)      rtplatform_wrmdir;
    prtsmb_filesys->fs_wset_cwd     =   (RTSMB_FS_WSETCWDFN)     rtplatform_wsetcwd;
    prtsmb_filesys->fs_wpwd         =   (RTSMB_FS_WPWDFN)        rtplatform_wpwd;
    prtsmb_filesys->fs_wgfirst      =   (RTSMB_FS_WGFIRSTFN)     rtplatform_wgfirst;
    prtsmb_filesys->fs_wgnext       =   (RTSMB_FS_WGNEXTFN)      rtplatform_wgnext;
    prtsmb_filesys->fs_wstat        =   (RTSMB_FS_WSTATFN)       rtplatform_wstat;
    prtsmb_filesys->fs_wchmode      =   (RTSMB_FS_WCHMODEFN)     rtplatform_wchmode;
    prtsmb_filesys->fs_wget_free    =   (RTSMB_FS_WGET_FREEFN)   rtplatform_wget_free;


    return (0);
}


int rtplatform_open(char RTSMB_FAR * name, unsigned short flag, unsigned short mode)
{
    int fd, rv;

    rv = rtp_file_open ((RTP_FILE *) &fd, name, flag, mode);
    if (rv < 0)
    {
        RTSMB_DEBUG_OUTPUT_STR ("rtplatform_open: Error on open is ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_INT (rv);
        RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);
        return -1;
    }

    return fd;
}

int rtplatform_wopen(unsigned short RTSMB_FAR * name, unsigned short flag, unsigned short mode)
{
    int fd, rv;

    rv = rtp_wfile_open ((RTP_FILE *) &fd, name, flag, mode);
    if (rv < 0)
    {
        return -1;
    }
    return fd;
}


long rtplatform_read(int fd,  unsigned char RTSMB_FAR * buf, long count)
{
    long rv;

    rv = rtp_file_read ((RTP_HANDLE) fd, buf, count);
    if (rv < 0)
    {
        return -1;
    }
    return rv;

}


long rtplatform_write(int fd,  unsigned char RTSMB_FAR * buf, long count)
{
    long rv;


    rv = rtp_file_write ((RTP_HANDLE) fd, buf, count);

    if (rv < 0)
    {
        return -1;
    }
    return rv;
}


int rtplatform_close(int fd)
{
    int rv;

    rv = rtp_file_close ((RTP_FILE) fd);
    if (rv < 0)
    {
        return -1;
    }
    return rv;
}

long rtplatform_lseek(int fd, long offset, int origin)
{
    long rv;

    rv = rtp_file_lseek ((RTP_HANDLE) fd, offset, origin);
    if (rv < 0)
    {
        return -1;
    }
    return rv;

}


BBOOL rtplatform_truncate(int fd, long offset)
{
    int rv;

    rv = rtp_file_truncate ((RTP_HANDLE) fd, offset);
    if (rv < 0)
    {
        return (char) 0;
    }
    return (char) 1;
}


BBOOL rtplatform_flush(int fd)
{
    return (BBOOL) rtp_file_flush((RTP_HANDLE) fd);
}


BBOOL rtplatform_rename(char RTSMB_FAR * from, char RTSMB_FAR * to)
{
    if (rtp_file_rename (from, to) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_wrename(unsigned short RTSMB_FAR * from, unsigned short RTSMB_FAR * to)
{
    if (rtp_wfile_rename (from, to) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_delete(char RTSMB_FAR * d)
{
    if (rtp_file_delete(d) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_wdelete(unsigned short RTSMB_FAR * d)
{
    if (rtp_wfile_delete(d) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_mkdir(char RTSMB_FAR * d)
{
    if (rtp_file_mkdir(d) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_wmkdir(unsigned short RTSMB_FAR * d)
{
    if (rtp_wfile_mkdir(d) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_rmdir(char RTSMB_FAR * d)
{
    if (rtp_file_rmdir(d) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_wrmdir(unsigned short RTSMB_FAR * d)
{
    if (rtp_wfile_rmdir(d) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_setcwd(char RTSMB_FAR * to)
{
    if (rtp_file_setcwd(to) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_wsetcwd(unsigned short RTSMB_FAR * to)
{
    if (rtp_wfile_setcwd(to) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_pwd(char RTSMB_FAR * to, long size)
{
    if (rtp_file_pwd(to, size) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_wpwd(unsigned short RTSMB_FAR * to, long size)
{
    if (rtp_wfile_pwd(to, size) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

BBOOL rtplatform_gfirst(PSMBDSTAT dirobj, char RTSMB_FAR * name_in)
{
char slashstar [] = {'\\', '*', '\0'};
char dotstar [] = {'.', '*', '\0'};
char name [SMBF_FILENAMESIZE + 1];
rtsmb_size len;
int rv;
void * rtp_dirobj;

    /* translate "*" to "*.*" becaues some file systems don't like "*" */
    len = (rtsmb_size) tc_strlen (name_in);
    tc_strcpy (name, name_in);
    if (len > 1 && len < SMBF_FILENAMESIZE - 2 && tc_strcmp (&name[len - 2], slashstar) == 0)
    {
       tc_strcat  (name, dotstar);
    }

    rv = rtp_file_gfirst(&rtp_dirobj, name);
    if (rv < 0)
    {
        dirobj->rtp_dirobj = (void*)0;
        return FALSE;
    }

    rtp_file_get_name(rtp_dirobj, dirobj->filename, SMBF_FILENAMESIZE);
    dirobj->filename[SMBF_FILENAMESIZE] = '\0';

    /*translate rtplatform dstat to smb dstat */
    rtplatform_translate_dstat (dirobj, rtp_dirobj);
    dirobj->unicode = 0;

    return TRUE;
}

BBOOL rtplatform_wgfirst(PSMBDSTAT dirobj, unsigned short RTSMB_FAR * name_in)
{
unsigned short slashstar [] = {'\\', '*', '\0'};
unsigned short dotstar [] = {'.', '*', '\0'};
unsigned short name [SMBF_FILENAMESIZE + 1];
rtsmb_size len;
void * rtp_dirobj;
int rv;

    /* translate "*" to "*.*" becaues some file systems don't like "*" */
    len = tc_wcslen (name_in);
    tc_wcscpy (name, name_in);
    if (len > 1 && len < SMBF_FILENAMESIZE - 2 && tc_wcscmp (&name[len - 2], slashstar) == 0)
    {
       tc_wcscat  (name, dotstar);
    }

    rv = rtp_wfile_gfirst(&rtp_dirobj, name);
    if (rv < 0)
    {
        dirobj->rtp_dirobj = rtp_dirobj;
        return FALSE;
    }

    rtp_wfile_get_name(rtp_dirobj, (unsigned short *) dirobj->filename, SMBF_FILENAMESIZE);
    dirobj->filename[SMBF_FILENAMESIZE] = '\0';

    /* translate rtplatform dstat to smb dstat */
    rtplatform_translate_dstat (dirobj, rtp_dirobj);
    dirobj->unicode = 1;
    return TRUE;
}

BBOOL rtplatform_gnext(PSMBDSTAT dirobj)
{
int rv;

    rv = rtp_file_gnext(dirobj->rtp_dirobj);
    if (rv < 0)
    {
        return (0);
    }

    rtp_file_get_name(dirobj->rtp_dirobj, dirobj->filename, SMBF_FILENAMESIZE);
    dirobj->filename[SMBF_FILENAMESIZE] = '\0';

    /* translate rtplatform dstat to smb dstat  */
    rtplatform_translate_dstat(dirobj, dirobj->rtp_dirobj);
    dirobj->unicode = 0;

    return TRUE;
}

BBOOL rtplatform_wgnext(PSMBDSTAT dirobj)
{
int rv;

    rv = rtp_wfile_gnext(dirobj->rtp_dirobj);
    if (rv < 0)
    {
        return (0);
    }

    rtp_wfile_get_name(dirobj->rtp_dirobj, (unsigned short *) dirobj->filename, SMBF_FILENAMESIZE);
    dirobj->filename[SMBF_FILENAMESIZE] = '\0';

    /* translate rtplatform dstat to smb dstat  */
    rtplatform_translate_dstat(dirobj, dirobj->rtp_dirobj);
    dirobj->unicode = 1;
    return TRUE;
}



void rtplatform_gdone(PSMBDSTAT dirobj)
{
    /* make sure it hasn't already been freed */
    if (dirobj->rtp_dirobj != (void*)0)
    {
        rtp_file_gdone(dirobj->rtp_dirobj);
    }
}


BBOOL rtplatform_stat(char RTSMB_FAR * name, PSMBFSTAT vstat)
{
void * rtp_dirobj;

    if (rtp_file_gfirst(&rtp_dirobj, name) < 0)
    {
        rtp_dirobj = (void *)0;
        return FALSE;
    }

    rtplatform_translate_fstat(vstat, rtp_dirobj);
    rtp_file_gdone(rtp_dirobj);
    return TRUE;
}

BBOOL rtplatform_wstat(unsigned short RTSMB_FAR * name, PSMBFSTAT vstat)
{
void * rtp_dirobj;

    if (rtp_wfile_gfirst(&rtp_dirobj, name) < 0)
    {
        rtp_dirobj = (void *)0;
        return FALSE;
    }

    rtplatform_translate_fstat(vstat, rtp_dirobj);
    rtp_file_gdone(rtp_dirobj);
    return TRUE;
}

BBOOL rtplatform_chmode(char RTSMB_FAR * name, unsigned char attributes)
{
    if (rtp_file_chmode (name, attributes) < 0)
    {
        return FALSE;
    }

    return TRUE;
}

BBOOL rtplatform_wchmode(unsigned short RTSMB_FAR * name, unsigned char attributes)
{
    if (rtp_wfile_chmode (name, attributes) < 0)
    {
        return FALSE;
    }

    return TRUE;
}

#define FAKE_BYTES_PER_SECTOR 512
#define FAKE_SECTORS_PER_UNIT 64
BBOOL rtplatform_get_free (char RTSMB_FAR * name, unsigned long *total, unsigned long *free, unsigned long *sectors_per_unit, unsigned short *bytes_per_sector)
{
    if (rtp_file_get_free (name, total, free, sectors_per_unit, bytes_per_sector) < 0)
    {
        return FALSE;
    }
    return TRUE;

}

BBOOL rtplatform_wget_free (unsigned short RTSMB_FAR * name, unsigned long *total, unsigned long *free, unsigned long *sectors_per_unit, unsigned short *bytes_per_sector)
{
    if (rtp_wfile_get_free (name, total, free, sectors_per_unit, bytes_per_sector) < 0)
    {
        return FALSE;
    }
    return TRUE;

}


BBOOL rtplatform_set_time(int fd, TIME atime, TIME wtime, TIME ctime, TIME htime)
{
    RTP_DATE adate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE wdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE cdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE hdate = {0,0,0,0,0,0,0,0,0};

    adate = rtsmb_util_time_ms_to_rtp_date(atime);
    wdate = rtsmb_util_time_ms_to_rtp_date(wtime);
    cdate = rtsmb_util_time_ms_to_rtp_date(ctime);
    hdate = rtsmb_util_time_ms_to_rtp_date(htime);

    if (rtp_file_set_time (fd, &adate, &wdate, &cdate, &hdate) < 0)
    {
        return FALSE;
    }
    return TRUE;
}

void rtplatform_translate_dstat (PSMBDSTAT dstat, void * rtp_dirobj)
{
    RTP_DATE adate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE wdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE cdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE hdate = {0,0,0,0,0,0,0,0,0};
    TIME atime = {0,0};
    TIME wtime = {0,0};
    TIME ctime = {0,0};
    TIME htime = {0,0};

    dstat->fs_api = prtsmb_filesys;

    rtp_file_get_attrib(rtp_dirobj, &dstat->fattributes);

    rtp_file_get_time(rtp_dirobj, &adate, &wdate, &cdate, &hdate );

    if (adate.year != 0) atime = rtsmb_util_time_rtp_date_to_ms(adate);
    if (wdate.year != 0) wtime = rtsmb_util_time_rtp_date_to_ms(wdate);
    if (cdate.year != 0) ctime = rtsmb_util_time_rtp_date_to_ms(cdate);
    if (hdate.year != 0) htime = rtsmb_util_time_rtp_date_to_ms(hdate);

    dstat->fctime64.low_time = ctime.low_time;
    dstat->fctime64.high_time = ctime.high_time;
    dstat->fwtime64.low_time = wtime.low_time;
    dstat->fwtime64.high_time = wtime.high_time;
    dstat->fatime64.low_time = atime.low_time;
    dstat->fatime64.high_time = atime.high_time;
    dstat->fhtime64.low_time = htime.low_time;
    dstat->fhtime64.high_time = htime.high_time;

    rtp_file_get_size(rtp_dirobj, &dstat->fsize);

    dstat->rtp_dirobj = rtp_dirobj;

}

void rtplatform_translate_fstat (PSMBFSTAT fstat, void * rtp_dirobj)
{
    RTP_DATE adate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE wdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE cdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE hdate = {0,0,0,0,0,0,0,0,0};
    TIME atime = {0,0};
    TIME wtime = {0,0};
    TIME ctime = {0,0};
    TIME htime = {0,0};

    rtp_file_get_time(rtp_dirobj, &adate, &wdate, &cdate, &hdate);

    if (adate.year != 0) atime = rtsmb_util_time_rtp_date_to_ms(adate);
    if (wdate.year != 0) wtime = rtsmb_util_time_rtp_date_to_ms(wdate);
    if (cdate.year != 0) ctime = rtsmb_util_time_rtp_date_to_ms(cdate);
    if (hdate.year != 0) htime = rtsmb_util_time_rtp_date_to_ms(hdate);

    rtp_file_get_size(rtp_dirobj, &fstat->f_size);   /* file size, in bytes */

    fstat->f_atime64 = atime;
    fstat->f_ctime64 = ctime;
    fstat->f_wtime64 = wtime;
    fstat->f_htime64 = htime;

    rtp_file_get_attrib(rtp_dirobj, &fstat->f_attributes);

}
  
#endif
