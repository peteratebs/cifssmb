//
// SRVFIO.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles all File Input/Output for the Server.  All map to RTPlatform
//

#include "smbdefs.h"
#include "rtpwcs.h" /* _YI_ 9/24/2004 */
#if (INCLUDE_RTSMB_SERVER)

#include "srvfio.h"
#include "srvshare.h"
#include "srvrsrcs.h"
#include "srvutil.h"
#include "smbutil.h"

/* 'name' is an SMB-encoded full name.  Thus, it looks like "\path\to\something\a.txt".
   This function determines if we dip outside of our share space.  The previous example
   does not.  A path like "\yo\..\a.txt" does not, but a path like "\..\..\a.txt" does.

   We also catch things like "\../a.txt", because if we pass that into the file system
   layer, it could reach outside root.
 */
RTSMB_STATIC BBOOL rtsmb_srv_fio_points_past_root (PFRTCHAR name)
{
	int depth = 0, dotdot_match = 1;
	rtsmb_size i, len;
	len = rtsmb_len (name);

	for (i = name[0] == '\\' ? 1 : 0; i <= len; i++)
	{
		if (name[i] == '\\' || name[i] == '/' || name[i] == '\0')
		{
			if (dotdot_match == 3) /* a previous \ and two dots */
			{
				depth--;

				if (depth < 0)
				{
					return TRUE;
				}
			}
			else
			{
				depth++;
			}
			dotdot_match = 1;
		}
		else if (name[i] == '.' && dotdot_match)
		{
			dotdot_match += 1;
		}
		else
		{
			dotdot_match = 0;
		}
	}

	return FALSE;
}


// returns the full path name of 'name', adding
// the correct prefix from share table
// puts the content in dest with max size of 'size'
// returns NULL if dest will be too long
// also dosify's
RTSMB_STATIC PFRTCHAR expandName (PSR_RESOURCE resource, PFRTCHAR name, PFRTCHAR dest, dword size)
{
	dword nameSize;
	dword pathSize;
	PFRTCHAR start;
	PFRTCHAR tmp;
    rtsmb_char *DEVICE_path;
    rtsmb_char DEVICE_separator;
    int DEVICE_flags;

	rtsmb_char qsdotqs[] = {'?', '?', '?', '?', '?', '?', '?', '?', '.', '?', '?', '?', '\0'};
	rtsmb_char stardotstar[] = {'*', '.', '*', '\0'};

	if (resource->stype != ST_DISKTREE &&
		resource->stype != ST_PRINTQ)
		return (PFRTCHAR)0;

	if (resource->stype == ST_PRINTQ)
	{
        DEVICE_path         = resource->u.printer.path;
        DEVICE_separator    = resource->u.printer.separator;
        DEVICE_flags        = resource->u.printer.flags;
	}
	else
	{
        DEVICE_path         = resource->u.disktree.path;
        DEVICE_separator    = resource->u.disktree.separator;
        DEVICE_flags        = resource->u.disktree.flags;
	}

	nameSize = rtsmb_len (name);
	pathSize = rtsmb_len (DEVICE_path);

	if (pathSize >= size - 1)
		return (PFRTCHAR)0;

	/* We should make sure that the client isn't being malicous and
	   trying to reach above the server's share folder. */
	if (rtsmb_srv_fio_points_past_root (name))
	{
		return (PFRTCHAR)0;
	}

	tc_memset (dest, '\0', size);
	rtsmb_ncpy (dest, DEVICE_path, size);

	if (nameSize == 0 || (nameSize == 1 && name[0] == '\\')) return dest;

	// add separator if needed
	if (dest[pathSize - 1] != DEVICE_separator)
	{
		dest[pathSize] = DEVICE_separator;
		pathSize ++;
	}

	// ignore leading slash
	if (name[0] == '\\')
	{
		name ++;
		nameSize --;
	}

	//for(start=dest; start!='\0';start++);
	//start--;

	start = dest + pathSize;

	// dosify if we need to
	if (DEVICE_flags & SHARE_FLAGS_8_3)
	{
		if (!SMBU_DOSifyPath (name, start, (rtsmb_size) (size - pathSize)))
			return (PFRTCHAR)0;
	}
	else if (rtsmb_len (dest) + nameSize < size)
	{
		rtsmb_cpy (start, name);
	}
	else
	{
		return (PFRTCHAR)0;
	}

	if (ON (DEVICE_flags, SHARE_FLAGS_CASE_SENSITIVE))
	{
		rtsmb_util_string_to_upper ((PFRTCHAR) start, CFG_RTSMB_USER_CODEPAGE);
	}

	// scan through, replacing '\\' with correct separator
	if (DEVICE_separator != '\\')
	{
		for (tmp = start; tmp[0]; tmp++)
			if (tmp[0] == '\\')
				tmp[0] = DEVICE_separator;
	}

	// remove trailing seperator
	if (dest[rtsmb_len (dest) - 1] == DEVICE_separator)
	{
		dest[rtsmb_len (dest) - 1] = '\0';
	}

	/* replace weird smb wildcards (<, ", and >) with ours */
	/* this algorithm is from the smb draft spec */
	for (tmp = start; tmp[0]; tmp++)
	{
		if (tmp[0] == '>')
		{
			tmp[0] = '?';
		}
		else if (tmp[0] == '"' && tmp[1] && (tmp[1] == '<' || tmp[1] == '>'))
		{
			tmp[0] = '.';
		}
		else if (tmp[0] == '<' && tmp[1] && tmp[1] == '"')
		{
			tmp[0] = '*';
		}
	}

	/* map ????????.??? or *.* to * -- this is what they really mean,
	   according to the spec */
	if (rtsmb_cmp (start, qsdotqs) == 0 || rtsmb_cmp (start, stardotstar) == 0)
	{
		start[0] = '*';
		start[1] = '\0';
	}

	return dest;
}


RTSMB_STATIC void dstat_to_rtsmb (PSMBDSTAT dirobj)
{
	if (dirobj->unicode)
	{
		/* the fs supports unicode */
		rtsmb_util_unicode_to_rtsmb ((PFWCS) dirobj->filename, (PFRTCHAR) dirobj->filename, CFG_RTSMB_USER_CODEPAGE);
		rtsmb_util_unicode_to_rtsmb ((PFWCS) dirobj->short_filename, (PFRTCHAR) dirobj->short_filename, CFG_RTSMB_USER_CODEPAGE);
	}
	else
	{
		/* the fs does not support unicode */
		rtsmb_util_ascii_to_rtsmb ((PFCHAR) dirobj->filename, (PFRTCHAR) dirobj->filename, CFG_RTSMB_USER_CODEPAGE);
		rtsmb_util_ascii_to_rtsmb ((PFCHAR) dirobj->short_filename, (PFRTCHAR) dirobj->short_filename, CFG_RTSMB_USER_CODEPAGE);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////       API FUNCTIONS       //////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////

// this is public version, taking a shareHandle;
PFRTCHAR SMBFIO_ExpandName (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name, PFRTCHAR dest, dword size)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return (PFRTCHAR)0;
	}
	return SMBFIO_ExpandNameInternal ((word) tree->internal, name, dest, size);
}

int SMBFIO_Open (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name, word flags, word mode)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return -1;
	}
	return SMBFIO_OpenInternal ((word) tree->internal, name, flags, mode);
}

long SMBFIO_Read (PSMB_SESSIONCTX pCtx, word tid, int fd, PFBYTE buf, dword count)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return -1;
	}
	return SMBFIO_ReadInternal ((word) tree->internal, fd, buf, count);
}

long SMBFIO_Write (PSMB_SESSIONCTX pCtx, word tid, int fd, PFBYTE buf, dword count)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return -1;
	}
	return SMBFIO_WriteInternal ((word) tree->internal, fd, buf, count);
}

dword SMBFIO_Seeku32 (PSMB_SESSIONCTX pCtx, word tid, int fd, dword offset)
{
	PTREE tree;

	tree = SMBU_GetTree (pCtx, tid);
	if (tree)
	{
        long loffset,r;
        /* Unsigned 32 bit version of seek set */
        if ((offset & 0x8000000)==0)
            r=SMBFIO_SeekInternal ((word) tree->internal, fd, (long)offset, RTSMB_SEEK_SET);
        else
        {
            loffset = (long)(offset/2);
            r=SMBFIO_SeekInternal ((word) tree->internal, fd, (long)offset, RTSMB_SEEK_SET);
            if (r != -1)
            {
                loffset = (long)(offset-(offset/2));
                r=SMBFIO_SeekInternal ((word) tree->internal, fd, loffset, RTSMB_SEEK_CUR);
            }
        }
        if (r != -1)
		    return offset;
	}

	return 0xffffffff;
}
long SMBFIO_Seek (PSMB_SESSIONCTX pCtx, word tid, int fd, long offset, int origin)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return -1;
	}
	return SMBFIO_SeekInternal ((word) tree->internal, fd, offset, origin);
}

BBOOL SMBFIO_SetTime (PSMB_SESSIONCTX pCtx, word tid, int fd, const TIME * atime, const TIME * wtime, const TIME * ctime, const TIME * htime)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_SetTimeInternal ((word) tree->internal, fd, atime, wtime, ctime, htime);
}

BBOOL SMBFIO_Truncate (PSMB_SESSIONCTX pCtx, word tid, int fd, dword offset)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_TruncateInternal ((word) tree->internal, fd, offset);
}

BBOOL SMBFIO_Flush (PSMB_SESSIONCTX pCtx, word tid, int fd)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_FlushInternal ((word) tree->internal, fd);
}

int SMBFIO_Close (PSMB_SESSIONCTX pCtx, word tid, int fd)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return -1;
	}

	return SMBFIO_CloseInternal ((word) tree->internal, fd);
}

BBOOL SMBFIO_Rename (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR oldname, PFRTCHAR newname)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_RenameInternal ((word) tree->internal, oldname, newname);
}

BBOOL SMBFIO_Delete (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_DeleteInternal ((word) tree->internal, name);
}

BBOOL SMBFIO_Mkdir (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_MkdirInternal ((word) tree->internal, name);
}

BBOOL SMBFIO_Rmdir (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_RmdirInternal ((word) tree->internal, name);
}


/**
 * TODO: add a parameter for search attributes, and skip those that aren't allowed.
 */
BBOOL SMBFIO_GFirst (PSMB_SESSIONCTX pCtx, word tid, PSMBDSTAT dirobj, PFRTCHAR name)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);
	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_GFirstInternal ((word) tree->internal, dirobj, name);
}

BBOOL SMBFIO_GNext (PSMB_SESSIONCTX pCtx, word tid, PSMBDSTAT dirobj)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);
	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_GNextInternal ((word) tree->internal, dirobj);
}

void SMBFIO_GDone (PSMB_SESSIONCTX pCtx, word tid, PSMBDSTAT dirobj)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return;
	}
	SMBFIO_GDoneInternal ((word) tree->internal, dirobj);
}

BBOOL SMBFIO_Stat (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name, PSMBFSTAT stat)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);
	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_StatInternal ((word) tree->internal, name, stat);
}

BBOOL SMBFIO_Chmode (PSMB_SESSIONCTX pCtx, word tid, PFRTCHAR name, byte attributes)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);
	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_ChmodeInternal ((word) tree->internal, name, attributes);
}

BBOOL SMBFIO_GetFree (PSMB_SESSIONCTX pCtx, word tid, PFDWORD blocks, PFDWORD bfree, PFDWORD sectors, PFWORD bytes)
{
	PTREE tree;
	tree = SMBU_GetTree (pCtx, tid);

	if (!tree)
	{
		return FALSE;
	}
	return SMBFIO_GetFreeInternal ((word) tree->internal, blocks, bfree, sectors, bytes);
}








PFRTCHAR SMBFIO_ExpandNameInternal (word tid, PFRTCHAR name, PFRTCHAR dest, dword size)
{
	PFRTCHAR rv;
	PSR_RESOURCE pResource;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);
	rv = expandName (pResource, name, dest, size);
	RELEASE_SHARE ();

	return rv;
}

int SMBFIO_OpenInternal (word tid, PFRTCHAR name, word flags, word mode)
{
	rtsmb_char fullName [SMBF_FILENAMESIZE + 1];
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	int rv = 0;
	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		name = pResource->u.printer.printerfileBuf; //Overriding name to printerfile value.
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = -1;
		break;
	}

	if (!rv && !expandName (pResource, name, fullName, SMBF_FILENAMESIZE + 1))	rv = -1;
	RELEASE_SHARE ();

	if (rv)	return rv;

	flags |= RTP_FILE_O_BINARY; /* _YI_ */

#if (INCLUDE_RTSMB_UNICODE)
		/* the fs supports unicode */
		rtsmb_util_rtsmb_to_unicode (fullName, (PFWCS) fullName, CFG_RTSMB_USER_CODEPAGE);
		rv = api->fs_wopen((PFWCS) fullName, flags, mode);
		if (rv < 0)
#endif
		{
			/* the fs does not support unicode */
			rtsmb_util_rtsmb_to_ascii (fullName, (PFCHAR) fullName, CFG_RTSMB_USER_CODEPAGE);
			rv = api->fs_open((PFCHAR) fullName, flags, mode);
		}

	return rv;
}

long SMBFIO_ReadInternal (word tid, int fd, PFBYTE buf, dword count)
{
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	long rv = 0;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = -1;
		break;
	}
	RELEASE_SHARE ();

	if (rv)	return rv;

	rv =  api->fs_read(fd, buf, count);

	return rv;
}

long SMBFIO_WriteInternal (word tid, int fd, PFBYTE buf, dword count)
{
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	long rv = 0;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = -1;
		break;
	}
	RELEASE_SHARE ();

	if (rv)	return rv;

	rv = api->fs_write(fd, buf, count);

	return rv;
}

long SMBFIO_SeekInternal (word tid, int fd, long offset, int origin)
{
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	long rv = 0;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = -1;
		break;
	}
	RELEASE_SHARE ();

	if (rv)	return rv;

	rv = api->fs_lseek (fd, offset, origin);

	return rv;
}

BBOOL SMBFIO_SetTimeInternal (word tid, int fd, const TIME * atime, const TIME * wtime, const TIME * ctime, const TIME * htime)
{
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;
    TIME at = *atime;
    TIME wt = *wtime;
    TIME ct = *ctime;
    TIME ht = *htime;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}
	RELEASE_SHARE ();

	if (rv)
	    rv = api->fs_set_time(fd, at, wt, ct, ht);

	return rv;
}

BBOOL SMBFIO_TruncateInternal (word tid, int fd, dword offset)
{
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}
	RELEASE_SHARE ();

	if (!rv) return rv;

	return api->fs_truncate (fd, offset);
}

BBOOL SMBFIO_FlushInternal (word tid, int fd)
{
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}
	RELEASE_SHARE ();
	if (!rv)
	    return rv;

    return api->fs_flush(fd);
}

int SMBFIO_CloseInternal (word tid, int fd)
{
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	int rv = 0;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	case ST_IPC:
		rv = -2;
		break;
	default:
		rv = -1;
		break;
	}
	RELEASE_SHARE ();

	// always return safely for ipc file closes
	if (rv == -2)
		return 0;

	if (rv) return rv;

	rv = api->fs_close(fd);

	return rv;
}

BBOOL SMBFIO_RenameInternal (word tid, PFRTCHAR oldname, PFRTCHAR newname)
{
	rtsmb_char fullNewName [SMBF_FILENAMESIZE + 1];
	rtsmb_char fullOldName [SMBF_FILENAMESIZE + 1];
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}

	if (rv && !expandName (pResource, oldname, fullOldName, SMBF_FILENAMESIZE + 1))	rv = FALSE;
	if (rv && !expandName (pResource, newname, fullNewName, SMBF_FILENAMESIZE + 1))	rv = FALSE;
	RELEASE_SHARE ();

	if (!rv) return rv;

#if (INCLUDE_RTSMB_UNICODE)

		rtsmb_util_rtsmb_to_unicode (fullOldName, (PFWCS) fullOldName, CFG_RTSMB_USER_CODEPAGE);
		rtsmb_util_rtsmb_to_unicode (fullNewName, (PFWCS) fullNewName, CFG_RTSMB_USER_CODEPAGE);
		rv = api->fs_wrename((PFWCS) fullOldName, (PFWCS) fullNewName);
		if (!rv)
#endif
		{
			/* the fs does not support unicode */
			rtsmb_util_rtsmb_to_ascii (fullOldName, (PFCHAR) fullOldName, CFG_RTSMB_USER_CODEPAGE);
			rtsmb_util_rtsmb_to_ascii (fullNewName, (PFCHAR) fullNewName, CFG_RTSMB_USER_CODEPAGE);
			rv = api->fs_rename((PFCHAR) fullOldName, (PFCHAR) fullNewName);
		}

	return rv;
}

BBOOL SMBFIO_DeleteInternal (word tid, PFRTCHAR name)
{
	rtsmb_char fullName [SMBF_FILENAMESIZE + 1];
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		name = pResource->u.printer.printerfileBuf; //Overriding name value to printerfile value.
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}

	if (rv && !expandName (pResource, name, fullName, SMBF_FILENAMESIZE + 1))	rv = FALSE;
	RELEASE_SHARE ();

	if (!rv) return rv;

#if (INCLUDE_RTSMB_UNICODE)
		rtsmb_util_rtsmb_to_unicode (fullName, (PFWCS) fullName, CFG_RTSMB_USER_CODEPAGE);
		rv = api->fs_wdelete((PFWCS) fullName);
		if (!rv)
#endif
		{
			rtsmb_util_rtsmb_to_ascii (fullName, (PFCHAR) fullName, CFG_RTSMB_USER_CODEPAGE);
			rv = api->fs_delete((PFCHAR) fullName);
		}

	return rv;
}

BBOOL SMBFIO_MkdirInternal (word tid, PFRTCHAR name)
{
	rtsmb_char fullName [SMBF_FILENAMESIZE + 1];
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}

	if (rv && !expandName (pResource, name, fullName, SMBF_FILENAMESIZE + 1)) rv = FALSE;
	RELEASE_SHARE ();

	if (!rv) return rv;

#if (INCLUDE_RTSMB_UNICODE)
		rtsmb_util_rtsmb_to_unicode (fullName, (PFWCS) fullName, CFG_RTSMB_USER_CODEPAGE);
		rv = api->fs_wmkdir((PFWCS) fullName);
		if (!rv)
#endif
		{
			rtsmb_util_rtsmb_to_ascii (fullName, (PFCHAR) fullName, CFG_RTSMB_USER_CODEPAGE);
			rv = api->fs_mkdir((PFCHAR) fullName);
		}

	return rv;
}

BBOOL SMBFIO_RmdirInternal (word tid, PFRTCHAR name)
{
	rtsmb_char fullName [SMBF_FILENAMESIZE + 1];
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}

	if (rv && !expandName (pResource, name, fullName, SMBF_FILENAMESIZE + 1)) rv = FALSE;
	RELEASE_SHARE ();

	if (!rv) return rv;

#if (INCLUDE_RTSMB_UNICODE)
		rtsmb_util_rtsmb_to_unicode (fullName, (PFWCS) fullName, CFG_RTSMB_USER_CODEPAGE);
		rv = api->fs_wrmdir((PFWCS) fullName);
		if (!rv)
#endif
		{
			rtsmb_util_rtsmb_to_ascii (fullName, (PFCHAR) fullName, CFG_RTSMB_USER_CODEPAGE);
			rv = api->fs_rmdir((PFCHAR) fullName);
		}

	return rv;
}

BBOOL SMBFIO_GFirstInternal (word tid, PSMBDSTAT dirobj, PFRTCHAR name)
{
	rtsmb_char fullName [SMBF_FILENAMESIZE + 1];
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		name = pResource->u.printer.printerfileBuf; //Overriding name value to printerfile value.
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}

	if (rv && !expandName (pResource, name, fullName, SMBF_FILENAMESIZE + 1)) rv = FALSE;
	RELEASE_SHARE ();

	if (!rv) return rv;

#if (INCLUDE_RTSMB_UNICODE)
	rtsmb_util_rtsmb_to_unicode (fullName, (PFWCS) fullName, CFG_RTSMB_USER_CODEPAGE);
	rv = api->fs_wgfirst(dirobj, (PFWCS) fullName);
	if (rv)
	{
		dstat_to_rtsmb (dirobj);
	}
	else
#endif

	{
		rtsmb_util_rtsmb_to_ascii (fullName, (PFCHAR) fullName, CFG_RTSMB_USER_CODEPAGE);
		rv = api->fs_gfirst(dirobj, (PFCHAR) fullName);
		if (rv)
		{
			dstat_to_rtsmb (dirobj);
		}
	}

	return rv;
}

BBOOL SMBFIO_GNextInternal (word tid, PSMBDSTAT dirobj)
{
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}
	RELEASE_SHARE ();

		if (!rv) return rv;

#if (INCLUDE_RTSMB_UNICODE)

	rv = api->fs_wgnext(dirobj);

	if (rv)
	{
		dstat_to_rtsmb (dirobj);
	}
	else

#endif
	{
		rv = api->fs_gnext(dirobj);
		if (rv)
		{
			dstat_to_rtsmb (dirobj);
		}
	}

	return rv;
}

void SMBFIO_GDoneInternal (word tid, PSMBDSTAT dirobj)
{
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL valid = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		valid = FALSE;
		break;
	}
	RELEASE_SHARE ();

	if (!valid) return;

	api->fs_gdone(dirobj);
}

BBOOL SMBFIO_StatInternal (word tid, PFRTCHAR name, PSMBFSTAT stat)
{
	rtsmb_char fullName [SMBF_FILENAMESIZE + 1];
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		api = pResource->u.printer.api;
		name = pResource->u.printer.printerfileBuf; //Overriding name value to printerfile value.
		break;
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}

	if (rv && !expandName (pResource, name, fullName, SMBF_FILENAMESIZE + 1)) rv = FALSE;
	RELEASE_SHARE ();

	if (!rv) return rv;

#if (INCLUDE_RTSMB_UNICODE)

		rtsmb_util_rtsmb_to_unicode (fullName, (PFWCS) fullName, CFG_RTSMB_USER_CODEPAGE);
		rv = api->fs_wstat((PFWCS) fullName, stat);
		if (!rv)
#endif
		{
			rtsmb_util_rtsmb_to_ascii (fullName, (PFCHAR) fullName, CFG_RTSMB_USER_CODEPAGE);
			rv = api->fs_stat((PFCHAR) fullName, stat);
		}

	return rv;
}

BBOOL SMBFIO_ChmodeInternal (word tid, PFRTCHAR name, byte attributes)
{
	rtsmb_char fullName [SMBF_FILENAMESIZE + 1];
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}

	if (rv && !expandName (pResource, name, fullName, SMBF_FILENAMESIZE + 1)) rv = FALSE;
	RELEASE_SHARE ();

	if (!rv) return rv;

#if (INCLUDE_RTSMB_UNICODE)

		rtsmb_util_rtsmb_to_unicode (fullName, (PFWCS) fullName, CFG_RTSMB_USER_CODEPAGE);
		rv = api->fs_wchmode((PFWCS) fullName, attributes);
		if (!rv)
#endif
		{
			rtsmb_util_rtsmb_to_ascii (fullName, (PFCHAR) fullName, CFG_RTSMB_USER_CODEPAGE);
			rv = api->fs_chmode((PFCHAR) fullName, attributes);
		}

	return rv;
}

BBOOL SMBFIO_GetFreeInternal (word tid, PFDWORD blocks, PFDWORD bfree, PFDWORD sectors, PFWORD bytes)
{
	rtsmb_char path [SMBF_FILENAMESIZE + 1];
	PSR_RESOURCE pResource;
	PSMBFILEAPI api;
	BBOOL rv = TRUE;

	CLAIM_SHARE ();
	pResource = SR_ResourceById (tid);

	switch (pResource->stype)
	{
	case ST_DISKTREE:
		api = pResource->u.disktree.api;
		break;
	default:
		rv = FALSE;
		break;
	}

	if (rv) rtsmb_cpy (path, pResource->u.disktree.path);
	RELEASE_SHARE ();

	if (!rv) return rv;

#if (INCLUDE_RTSMB_UNICODE)

		rtsmb_util_rtsmb_to_unicode (path, (PFWCS) path, CFG_RTSMB_USER_CODEPAGE);
		rv = api->fs_wget_free((PFWCS) path, blocks, bfree, sectors, bytes);
		if (!rv)
#endif
		{
			rtsmb_util_rtsmb_to_ascii (path, (PFCHAR) path, CFG_RTSMB_USER_CODEPAGE);
			rv =
			api->fs_get_free(
			(PFCHAR) path,
			blocks,
			bfree,
			sectors,
			bytes);
		}

	return rv;
}

//BBOOL SMBFIO_ChsizeInternal (word tid, int fd, long size);

#endif /* INCLUDE_RTSMB_SERVER */
