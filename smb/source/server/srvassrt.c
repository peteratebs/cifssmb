//
// SRVASSRT.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Assertions used throughout the code
//

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvassrt.h"
#include "srvshare.h"
#include "srvauth.h"
#include "srvfio.h"
#include "srvrsrcs.h"
#include "smbdebug.h"

BBOOL assertUid (PSMB_SESSIONCTX pCtx)
{
	PUSER user;
	
	// no need to authenticate when in share mode
	if (pCtx->accessMode == AUTH_SHARE_MODE)
	{
		return FALSE;
	}
	user = SMBU_GetUser (pCtx, pCtx->uid);
	
	if (user == (PUSER)0)
	{
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_BADUID);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

// undefined behavior if uid doesn't exist
BBOOL assertTid (PSMB_SESSIONCTX pCtx)
{
	return assertThisTid (pCtx, pCtx->tid);
}

// undefined behavior if uid doesn't exist
BBOOL assertThisTid (PSMB_SESSIONCTX pCtx, word tid)
{
	if (SMBU_GetTree (pCtx, tid))
	{
		return FALSE;
	}

	SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_INVNID);
	return TRUE;
}

// undefined behavior if uid or tid isn't valid
BBOOL assertPermission (PSMB_SESSIONCTX pCtx, byte permission)
{
	return assertPermissionForTid (pCtx, permission, pCtx->tid);
}

// undefined behavior if uid or tid isn't valid
BBOOL assertPermissionForTid (PSMB_SESSIONCTX pCtx, byte permission, word tid)
{
	PTREE tree;

	tree = SMBU_GetTree (pCtx, pCtx->tid);

	if (tree->access == SECURITY_NONE ||
		(tree->access != SECURITY_READWRITE && tree->access != permission))
	{
		RTSMB_DEBUG_OUTPUT_STR ("failed permissions check with permission of ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_INT (permission);
		RTSMB_DEBUG_OUTPUT_STR (" against permission of ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_INT (tree->access);
		RTSMB_DEBUG_OUTPUT_STR (" on tid ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_INT (tid);
		RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_ACCESS);
		return TRUE;
	}

	return FALSE;
}

// undefined behavior if uid or tid isn't valid
// or if user doesn't have access permissions
// this also checks for old errors on this fid
BBOOL assertFid (PSMB_SESSIONCTX pCtx, word external, word flag)
{
	int fid;
	byte ec = 0;
	word error = 0;

	if ((fid = SMBU_GetInternalFid (pCtx, external, flag,0)) == -2)
	{
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_ACCESS);
		return TRUE;
	}
	else if (fid < 0)
	{
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRDOS, SMB_ERRDOS_BADFID);
		return TRUE;
	}

	// check if an error is waiting for us
	SMBU_GetFidError (pCtx, external, &ec, &error);

	if (error > 0)
	{
		SMBU_SetFidError (pCtx, external, SMB_EC_SUCCESS, 0);
		SMBU_FillError (pCtx, pCtx->pOutHeader, ec, error);
		return TRUE;
	}

	return FALSE;
}

// undefined behavior if uid or tid isn't valid
BBOOL assertDisk (PSMB_SESSIONCTX pCtx)
{
	if (SMBU_GetTree (pCtx, pCtx->tid)->type != ST_DISKTREE)
	{
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_INVDEVICE);
		return TRUE;
	}

	return FALSE;
}

// undefined behavior if uid or tid isn't valid
BBOOL assertSid (PSMB_SESSIONCTX pCtx, word sid)
{
	if (sid >= prtsmb_srv_ctx->max_searches_per_uid ||
		!SMBU_GetUser (pCtx, pCtx->uid)->searches[sid].inUse)
	{
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRDOS, SMB_ERRDOS_BADFID); // apparently, BADFID is used for sids too
		return TRUE;
	}

	return FALSE;
}

// undefined behavior if uid or tid isn't valid
BBOOL assertPath (PSMB_SESSIONCTX pCtx, PFRTCHAR filename)
{
	rtsmb_char path [SMBF_FILENAMESIZE + 1];
	SMBFSTAT stat;

	SMBU_GetPath (filename, path);

	if (!SMBFIO_Stat (pCtx, pCtx->tid, path, &stat))
	{
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRDOS, SMB_ERRDOS_BADPATH);
		return TRUE;
	}

	return FALSE;
}

#endif /* INCLUDE_RTSMB_SERVER */
