#ifndef __SRV_FIO_H__
#define __SRV_FIO_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "psmbfile.h"
#include "srvssn.h"

// All the following functions are the public API for our shares
PFRTCHAR SMBFIO_ExpandName (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name, PFRTCHAR dest, dword size);
int SMBFIO_Open (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name, word flags, word mode);
long SMBFIO_Read (PSMB_SESSIONCTX pCtx, word tid, int fd, PFBYTE buf, dword count);
long SMBFIO_Write (PSMB_SESSIONCTX pCtx, word tid, int fd, PFBYTE buf, dword count);
long SMBFIO_Seek (PSMB_SESSIONCTX pCtx, word tid, int fd, long offset, int origin);
dword SMBFIO_Seeku32 (PSMB_SESSIONCTX pCtx, word tid, int fd, dword offset);
BBOOL SMBFIO_Truncate (PSMB_SESSIONCTX pCtx, word tid, int fd, dword offset);
BBOOL SMBFIO_Flush (PSMB_SESSIONCTX pCtx, word tid, int fd);
int SMBFIO_Close (PSMB_SESSIONCTX pCtx, word tid, int fd);
BBOOL SMBFIO_Rename (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR oldname, PFRTCHAR newname);
BBOOL SMBFIO_Delete (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name);
BBOOL SMBFIO_Mkdir (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name);
BBOOL SMBFIO_Rmdir (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name);
BBOOL SMBFIO_SetCwd (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name);
BBOOL SMBFIO_SetCwdToRootAt (PSMB_SESSIONCTX pCtx, word tid);
BBOOL SMBFIO_Pwd (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name);
BBOOL SMBFIO_GFirst (PSMB_SESSIONCTX pCtx, word tid, PSMBDSTAT dirobj, PFRTCHAR name);
BBOOL SMBFIO_GNext (PSMB_SESSIONCTX pCtx, word tid, PSMBDSTAT dirobj);
void SMBFIO_GDone (PSMB_SESSIONCTX pCtx, word tid, PSMBDSTAT dirobj);
BBOOL SMBFIO_Stat (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name, PSMBFSTAT stat);
BBOOL SMBFIO_Chmode (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name, byte attributes);
BBOOL SMBFIO_GetFree (PSMB_SESSIONCTX pCtx, word tid, PFDWORD blocks, PFDWORD bfree, PFDWORD sectors, PFWORD bytes);
BBOOL SMBFIO_SetTime (PSMB_SESSIONCTX pCtx, word tid, int fd, const TIME * atime, const TIME * wtime, const TIME * ctime, const TIME * htime);



// here are some functions for file IO without needing to
// be connected to a share already -- try and keep away from these
PFRTCHAR SMBFIO_ExpandNameInternal (word tid, PFRTCHAR name, PFRTCHAR dest, dword size);
int SMBFIO_OpenInternal (word tid, PFRTCHAR name, word flags, word mode);
long SMBFIO_ReadInternal (word tid, int fd, PFBYTE buf, dword count);
long SMBFIO_WriteInternal (word tid, int fd, PFBYTE buf, dword count);
long SMBFIO_SeekInternal (word tid, int fd, long offset, int origin);
BBOOL SMBFIO_TruncateInternal (word tid, int fd, dword offset);
BBOOL SMBFIO_FlushInternal (word tid, int fd);
int SMBFIO_CloseInternal (word tid, int fd);
BBOOL SMBFIO_RenameInternal (word tid, PFRTCHAR oldname, PFRTCHAR newname);
BBOOL SMBFIO_DeleteInternal (word tid, PFRTCHAR name);
BBOOL SMBFIO_MkdirInternal (word tid, PFRTCHAR name);
BBOOL SMBFIO_RmdirInternal (word tid, PFRTCHAR name);
BBOOL SMBFIO_GFirstInternal (word tid, PSMBDSTAT dirobj, PFRTCHAR name);
BBOOL SMBFIO_GNextInternal (word tid, PSMBDSTAT dirobj);
void SMBFIO_GDoneInternal (word tid, PSMBDSTAT dirobj);
BBOOL SMBFIO_StatInternal (word tid, PFRTCHAR name, PSMBFSTAT stat);
BBOOL SMBFIO_ChmodeInternal (word tid, PFRTCHAR name, byte attributes);
BBOOL SMBFIO_GetFreeInternal (word tid, PFDWORD blocks, PFDWORD bfree, PFDWORD sectors, PFWORD bytes);
BBOOL SMBFIO_SetTimeInternal (word tid, int fd, const TIME * atime, const TIME * wtime, const TIME * ctime, const TIME * htime);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_FIO_H__ */
