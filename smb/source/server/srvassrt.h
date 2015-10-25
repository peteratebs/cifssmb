#ifndef __SRV_ASSERT_H__
#define __SRV_ASSERT_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvutil.h"

/**
 * A is SMB Header
 * B is SMB Context
 *
 * assert* functions return TRUE for error, FALSE for ok
 */

#define ASSERT_UID(A)						if (assertUid (A) == TRUE)						return TRUE;
#define ASSERT_TID(A)						if (assertTid (A) == TRUE)						return TRUE;
#define ASSERT_THIS_TID(A, B)				if (assertThisTid (A, B) == TRUE)				return TRUE;
#define ASSERT_PERMISSION(A, B)				if (assertPermission (A, B) == TRUE)			return TRUE;
#define ASSERT_PERMISSION_FOR_TID(A, B, C)	if (assertPermissionForTid (A, B, C) == TRUE)	return TRUE;
#define ASSERT_FID(A, B, C)					if (assertFid (A, B, C) == TRUE)				return TRUE;
#define ASSERT_DISK(A)						if (assertDisk (A) == TRUE)						return TRUE;
#define ASSERT_SID(A, B)					if (assertSid (A, B) == TRUE)					return TRUE;
#define ASSERT_PATH(A, B)					if (assertPath (A, B) == TRUE)					return TRUE;

BBOOL assertUid (PSMB_SESSIONCTX pCtx);
BBOOL assertTid (PSMB_SESSIONCTX pCtx);
BBOOL assertThisTid (PSMB_SESSIONCTX pCtx, word tid);
BBOOL assertPermission (PSMB_SESSIONCTX pCtx, byte permission);
BBOOL assertPermissionForTid (PSMB_SESSIONCTX pCtx, byte permission, word tid);
BBOOL assertFid (PSMB_SESSIONCTX pCtx, word external, word flag);
BBOOL assertDisk (PSMB_SESSIONCTX pCtx);
BBOOL assertSid (PSMB_SESSIONCTX pCtx, word sid);
BBOOL assertPath (PSMB_SESSIONCTX pCtx, PFRTCHAR filename);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_ASSERT_H__ */
