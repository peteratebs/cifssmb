//
// SRVSHARE.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles all of the functions related to SMB shares, including adding,
// removing, and maintaining
//
//============================================================================
//    IMPLEMENTATION HEADERS
//============================================================================
#include "smbdefs.h"
#include "rtpwcs.h"   /* _YI_ 9/24/2004 */
#include "smbdebug.h" /* _VM_ 12/23/2004 */

#if (INCLUDE_RTSMB_SERVER)

#include "srvshare.h"
#include "srvauth.h"
#include "srvrsrcs.h"
#include "smbutil.h"

//============================================================================
//    IMPLEMENTATION PRIVATE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE STRUCTURES
//============================================================================
//============================================================================
//    IMPLEMENTATION REQUIRED EXTERNAL REFERENCES (AVOID)
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE DATA
//============================================================================

RTSMB_STATIC rtsmb_char serviceStr[5][6] =
{
	{'A', ':', '\0'},
	{'L', 'P', 'T', '1', ':', '\0'},
	{'C', 'O', 'M', 'M', '\0'},
	{'I', 'P', 'C', '\0'},
	{'?', '?', '?', '?', '?', '\0'}
};
//============================================================================
//    INTERFACE DATA
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTION PROTOTYPES
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTIONS
//============================================================================
//============================================================================
//    INTERFACE FUNCTIONS
//============================================================================

void SR_Init (void)
{
	word i;

	RTSMB_DEBUG_OUTPUT_STR("SR_Init:  Initializing share data.\n", RTSMB_DEBUG_TYPE_ASCII);

	CLAIM_SHARE ();

	for (i = 0; i < prtsmb_srv_ctx->max_shares; i++)
		prtsmb_srv_ctx->shareTable[i].inUse = FALSE;

	RELEASE_SHARE ();
}

/*
================

	SHARE_T stype - the share type of resource
================
*/
PFRTCHAR SR_ServiceToStr( SHARE_T stype )
{
	return(serviceStr[stype % NUM_SHARE_TYPES]);
} // End SR_ServiceToStr

/*
================

	int id - x
================
*/
PSR_RESOURCE SR_ResourceById( word id )
{
	PSR_RESOURCE rv;

	rv = &prtsmb_srv_ctx->shareTable[id];

	return rv;
} // End SR_ResourceById

/*
================
 Returns the first free shared resource

  ret( PSR_RESOURCE ) - a pointer to a structure that describes a shared
	resource.
================
*/
PSR_RESOURCE SR_FirstResource( void )
{
	PSR_RESOURCE rv;
	word i;

	for (i = 0; i < prtsmb_srv_ctx->max_shares; i++)
	{
		if (prtsmb_srv_ctx->shareTable[i].inUse == TRUE)
		{
			break;
		}
	}

	rv = i < prtsmb_srv_ctx->max_shares ? &prtsmb_srv_ctx->shareTable[i] : (void*)0;

	return rv;
} // End SR_FirstResource

/*
================

================
*/
PSR_RESOURCE SR_NextResource( PSR_RESOURCE pPrev )
{
	PSR_RESOURCE rv;
	int i;

	i = INDEX_OF (prtsmb_srv_ctx->shareTable, pPrev);

	for (i = i + 1; i < prtsmb_srv_ctx->max_shares; i++)
		if (prtsmb_srv_ctx->shareTable[i].inUse == TRUE)
			break;

	rv = i < prtsmb_srv_ctx->max_shares ? &prtsmb_srv_ctx->shareTable[i] : (void*)0;

	return rv;
} // End SR_NextResource

/*
================
	PFCHAR path - x
	PFCHAR service - x
================
*/
int SR_GetTreeId( PFRTCHAR name, PFRTCHAR service )
{
	int i;

    // PVO - Don't do this unless leading slashes
    if(name[0] == '\\')
    {
	    // get past obligatory slashes
	    for(i=0; i < 3; name++)
	    {
		    if(name[0] == '\0')
		    {
			    return -1;
		    }
		    if(name[0] == '\\')
		    {
			    i++;
		    }
	    }
    }

	CLAIM_SHARE ();
	for(i=0; i < prtsmb_srv_ctx->max_shares; i++)
	{
		if( prtsmb_srv_ctx->shareTable[i].inUse == TRUE &&
			(rtsmb_casecmp(prtsmb_srv_ctx->shareTable[i].name, name, CFG_RTSMB_USER_CODEPAGE) == 0) &&
			((rtsmb_casecmp(SR_ServiceToStr(prtsmb_srv_ctx->shareTable[i].stype), service, CFG_RTSMB_USER_CODEPAGE)==0)
				|| (rtsmb_casecmp(SR_ServiceToStr(ANY_SHARE_TYPE), service, CFG_RTSMB_USER_CODEPAGE)==0)))
			break;
	}
	RELEASE_SHARE ();

	if (i == prtsmb_srv_ctx->max_shares)
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_GetTreeId: resource ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR (service, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR (" not found, unhandled case\n", RTSMB_DEBUG_TYPE_ASCII);
		return -1;
	}

	return i;
} // End SR_GetTreeId

/*
================

	PFCHAR path - x
	PFCHAR service - x
================
*/
int SR_GetTreeIdFromName ( PFRTCHAR name )
{
	int i;

	CLAIM_SHARE ();
	for (i = 0; i < prtsmb_srv_ctx->max_shares; i++)
	{
		if (prtsmb_srv_ctx->shareTable[i].inUse == TRUE && rtsmb_casecmp(prtsmb_srv_ctx->shareTable[i].name, name, CFG_RTSMB_USER_CODEPAGE) == 0)
		{
			break;
		}
	}
	RELEASE_SHARE ();

	if (i == prtsmb_srv_ctx->max_shares)
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_GetTreeIdFromName: resource ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR (" not found, unhandled case\n", RTSMB_DEBUG_TYPE_ASCII);
		return -1;
	}

	return i;
} // End SR_GetTreeIdFromName

int SR_AddDiskTree (PFRTCHAR name, PFRTCHAR comment, PSMBFILEAPI api, PFRTCHAR path, int flags, byte permissions, PFCHAR password)
{
	word i;
	int useable = -1;
	int rv = 0;
	rtsmb_char empty[] = {'\0'};

	CLAIM_SHARE ();
	for (i = 0; i < prtsmb_srv_ctx->max_shares; i++)
	{
		if (!prtsmb_srv_ctx->shareTable[i].inUse)
		{
			if (useable == -1)
			{
				useable = i;
			}
		}
		else if (!rtsmb_casecmp (prtsmb_srv_ctx->shareTable[i].name, name, CFG_RTSMB_USER_CODEPAGE))	// name conflict
		{
			useable = -2;
			break;
		}
	}

	if (useable >= 0)
	{
		i = (word)useable;

		prtsmb_srv_ctx->shareTable[i].inUse = TRUE;
		rtsmb_ncpy (prtsmb_srv_ctx->shareTable[i].name, name, RTSMB_MAX_SHARENAME_SIZE);
		prtsmb_srv_ctx->shareTable[i].name[RTSMB_MAX_SHARENAME_SIZE] = '\0';
		prtsmb_srv_ctx->shareTable[i].stype = ST_DISKTREE;

		if (comment != (PFRTCHAR)0)
		{
			rtsmb_ncpy (prtsmb_srv_ctx->shareTable[i].comment, comment, RTSMB_MAX_COMMENT_SIZE);
			prtsmb_srv_ctx->shareTable[i].comment[RTSMB_MAX_COMMENT_SIZE] = '\0';
		}
		else
		{
			rtsmb_cpy (prtsmb_srv_ctx->shareTable[i].comment, empty);
		}

		if (api)
		{
			prtsmb_srv_ctx->shareTable[i].u.disktree.api = api;
		}
		else
		{
			/* Use the globally-defined default api */
			prtsmb_srv_ctx->shareTable[i].u.disktree.api = prtsmb_filesys;
		}

		prtsmb_srv_ctx->shareTable[i].u.disktree.flags = flags;
		prtsmb_srv_ctx->shareTable[i].permission = permissions;

		if (password != (PFCHAR)0)
		{
			tc_strncpy (prtsmb_srv_ctx->shareTable[i].passwordBuf, password, CFG_RTSMB_MAX_PASSWORD_SIZE);
			prtsmb_srv_ctx->shareTable[i].passwordBuf[CFG_RTSMB_MAX_PASSWORD_SIZE] = '\0';
			prtsmb_srv_ctx->shareTable[i].password = prtsmb_srv_ctx->shareTable[i].passwordBuf;
		}
		else
		{
			prtsmb_srv_ctx->shareTable[i].password = (PFCHAR)0;
		}

		if (path != (PFRTCHAR)0)
		{
			if (rtsmb_chr (path, '/') != (unsigned short*)0)
			{
				prtsmb_srv_ctx->shareTable[i].u.disktree.separator = '/';
			}
			else	// assume that it is dos-style if no forward slashes
			{
				prtsmb_srv_ctx->shareTable[i].u.disktree.separator = '\\';
			}

			rtsmb_ncpy (prtsmb_srv_ctx->shareTable[i].u.disktree.path, path, MAX_PATH_PREFIX_SIZE);
			prtsmb_srv_ctx->shareTable[i].u.disktree.path[MAX_PATH_PREFIX_SIZE] = '\0';

			if (ON (flags, SHARE_FLAGS_CREATE))
			{
				PFRTCHAR curdir = path;
				rtsmb_char path_tmp[SMBF_FILENAMESIZE + 1];

				curdir = rtsmb_chr (curdir, prtsmb_srv_ctx->shareTable[i].u.disktree.separator);

				while (curdir)
				{
					curdir[0] = '\0';

					rtsmb_cpy (path_tmp, path);

#if (INCLUDE_RTSMB_UNICODE)
					if (prtsmb_srv_ctx->shareTable[i].u.disktree.api->fs_wmkdir)
					{
						/* the fs supports unicode */
						rtsmb_util_rtsmb_to_unicode (path_tmp, (PFWCS) path_tmp, CFG_RTSMB_USER_CODEPAGE);

						rv = prtsmb_srv_ctx->shareTable[i].u.disktree.api->fs_wmkdir((PFWCS) path_tmp);
					}
					else
#endif
					{
						/* the fs does not support unicode */
						rtsmb_util_rtsmb_to_ascii (path_tmp, (PFCHAR) path_tmp, CFG_RTSMB_USER_CODEPAGE);

						rv = prtsmb_srv_ctx->shareTable[i].u.disktree.api->fs_mkdir((PFCHAR) path_tmp);
					}

					curdir[0] = prtsmb_srv_ctx->shareTable[i].u.disktree.separator;

					curdir ++;

					curdir = rtsmb_chr (curdir, prtsmb_srv_ctx->shareTable[i].u.disktree.separator);
				}

				rtsmb_cpy (path_tmp, path);
#if (INCLUDE_RTSMB_UNICODE)
				if (prtsmb_srv_ctx->shareTable[i].u.disktree.api->fs_wmkdir)
				{
					/* the fs supports unicode */
					rtsmb_util_rtsmb_to_unicode (path_tmp, (PFWCS) path_tmp, CFG_RTSMB_USER_CODEPAGE);

					rv = prtsmb_srv_ctx->shareTable[i].u.disktree.api->fs_wmkdir((PFWCS) path_tmp);
				}
				else
#endif
				{
					/* the fs does not support unicode */
					rtsmb_util_rtsmb_to_ascii (path_tmp, (PFCHAR) path_tmp, CFG_RTSMB_USER_CODEPAGE);

					rv = prtsmb_srv_ctx->shareTable[i].u.disktree.api->fs_mkdir((PFCHAR) path_tmp);
				}
			}
			else
			{
				// check for path existence
			}
		}
		else
		{
			rv = -1;	// we need a path
		}
	}
	else
	{
		rv = -1;
	}
	RELEASE_SHARE ();

	if (rv == -1)
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_AddDiskTree:  Failed to add share ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
	}
	else
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_AddDiskTree:  Successfully added share ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
	}

	return rv;
}

int SR_AddIPC (PFCHAR password)
{
	word i;
	int useable = -1;
	int rv = 0;
	rtsmb_char name[] = {'I', 'P', 'C', '$', '\0'};
	rtsmb_char empty[] = {'\0'};

	CLAIM_SHARE ();
	for (i = 0; i < prtsmb_srv_ctx->max_shares; i++)
	{
		if (prtsmb_srv_ctx->shareTable[i].inUse == FALSE)
		{
			if (useable == -1)
				useable = i;
		}
		else if (prtsmb_srv_ctx->shareTable[i].stype == ST_IPC)	// there can be only one IPC$
		{
			useable = -2;
			break;
		}
	}

	if (useable >= 0)
	{
		i = (word)useable;

		prtsmb_srv_ctx->shareTable[i].inUse = TRUE;
		prtsmb_srv_ctx->shareTable[i].stype = ST_IPC;
		rtsmb_cpy (prtsmb_srv_ctx->shareTable[i].name, name);
		rtsmb_cpy (prtsmb_srv_ctx->shareTable[i].comment, empty);
		prtsmb_srv_ctx->shareTable[i].permission = SECURITY_READWRITE;

		if (password != (PFCHAR)0)
		{
			tc_strncpy (prtsmb_srv_ctx->shareTable[i].passwordBuf, password, CFG_RTSMB_MAX_PASSWORD_SIZE);
			prtsmb_srv_ctx->shareTable[i].passwordBuf[CFG_RTSMB_MAX_PASSWORD_SIZE] = '\0';
			prtsmb_srv_ctx->shareTable[i].password = prtsmb_srv_ctx->shareTable[i].passwordBuf;
		}
		else
		{
			prtsmb_srv_ctx->shareTable[i].password = (PFCHAR)0;
		}
	}
	else
		rv = -1;
	RELEASE_SHARE ();

	if (rv == -1)
	{
		RTSMB_DEBUG_OUTPUT_STR("SR_AddIPC:  Failed to add IPC share.\n", RTSMB_DEBUG_TYPE_ASCII);
	}
	else
	{
		RTSMB_DEBUG_OUTPUT_STR("SR_AddIPC:  Successfully added IPC share.\n", RTSMB_DEBUG_TYPE_ASCII);
	}

	return rv;
}

int SR_AddPrinter (PFRTCHAR name, PFRTCHAR comment, int n, PSMBFILEAPI api, PFRTCHAR path, int flags, PFCHAR password, PFRTCHAR printerfile)
{
	word i;
	int useable = -1;
	int rv = 0;
	rtsmb_char empty[] = {'\0'};

	RTSMB_DEBUG_OUTPUT_STR(" ********* SR_AddPrinter: called.\n", RTSMB_DEBUG_TYPE_ASCII);


	CLAIM_SHARE ();
	for (i = 0; i < prtsmb_srv_ctx->max_shares; i++)
	{
		if (!prtsmb_srv_ctx->shareTable[i].inUse)
		{
			if (useable == -1)
				useable = i;
		}
		else if (!rtsmb_casecmp (prtsmb_srv_ctx->shareTable[i].name, name, CFG_RTSMB_USER_CODEPAGE))	// name conflict
		{
			useable = -2;
			break;
		}
	}

	if (useable >= 0)
	{
		i = (word)useable;

		prtsmb_srv_ctx->shareTable[i].inUse = TRUE;
		rtsmb_ncpy (prtsmb_srv_ctx->shareTable[i].name, name, RTSMB_MAX_SHARENAME_SIZE);
		prtsmb_srv_ctx->shareTable[i].name[RTSMB_MAX_SHARENAME_SIZE] = '\0';
		prtsmb_srv_ctx->shareTable[i].stype = ST_PRINTQ;

		if (comment != (PFRTCHAR)0)
		{
			rtsmb_ncpy (prtsmb_srv_ctx->shareTable[i].comment, comment, RTSMB_MAX_COMMENT_SIZE);
			prtsmb_srv_ctx->shareTable[i].comment[RTSMB_MAX_COMMENT_SIZE] = '\0';
		}
		else
		{
			rtsmb_cpy (prtsmb_srv_ctx->shareTable[i].comment, empty);
		}

		if (printerfile != (PFRTCHAR)0)
		{
			rtsmb_ncpy (prtsmb_srv_ctx->shareTable[i].u.printer.printerfileBuf, printerfile, SMBF_FILENAMESIZE);
			prtsmb_srv_ctx->shareTable[i].u.printer.printerfileBuf[SMBF_FILENAMESIZE] = '\0';
			prtsmb_srv_ctx->shareTable[i].u.printer.printerfile = prtsmb_srv_ctx->shareTable[i].u.printer.printerfileBuf;
		}
		else
		{
			prtsmb_srv_ctx->shareTable[i].u.printer.printerfile = (PFRTCHAR)0;
			RTSMB_DEBUG_OUTPUT_STR(" ********* SR_AddPrinter: we need a printer driver.\n", RTSMB_DEBUG_TYPE_ASCII);
			rv = -1;	/* we need a printer driver */
			goto addprintcleanup;
		}

		if (api)
		{
			prtsmb_srv_ctx->shareTable[i].u.printer.api = api;
		}
		else
		{
			/* Use the globally-defined default api */
			prtsmb_srv_ctx->shareTable[i].u.printer.api = prtsmb_filesys;
		}

		prtsmb_srv_ctx->shareTable[i].u.printer.flags = flags;
		prtsmb_srv_ctx->shareTable[i].u.printer.num = n;
		prtsmb_srv_ctx->shareTable[i].permission = SECURITY_READWRITE;

		if (password != (PFCHAR)0)
		{
			tc_strncpy (prtsmb_srv_ctx->shareTable[i].passwordBuf, password, CFG_RTSMB_MAX_PASSWORD_SIZE);
			prtsmb_srv_ctx->shareTable[i].passwordBuf[CFG_RTSMB_MAX_PASSWORD_SIZE] = '\0';
			prtsmb_srv_ctx->shareTable[i].password = prtsmb_srv_ctx->shareTable[i].passwordBuf;
		}
		else
		{
			prtsmb_srv_ctx->shareTable[i].password = (PFCHAR)0;
		}

		if (path != (PFRTCHAR)0)
		{
			if (rtsmb_chr (path, '/') != (unsigned short*)0)
			{
				prtsmb_srv_ctx->shareTable[i].u.printer.separator = '/';
			}
			else	// assume that it is dos-style if no forward slashes
			{
				prtsmb_srv_ctx->shareTable[i].u.printer.separator = '\\';
			}

			rtsmb_ncpy (prtsmb_srv_ctx->shareTable[i].u.printer.path, path, MAX_PATH_PREFIX_SIZE);
			prtsmb_srv_ctx->shareTable[i].u.printer.path[MAX_PATH_PREFIX_SIZE] = '\0';

			if (ON (flags, SHARE_FLAGS_CREATE))
			{
				PFRTCHAR curdir = path;
				rtsmb_char path_tmp[SMBF_FILENAMESIZE + 1];

				curdir = rtsmb_chr (curdir, prtsmb_srv_ctx->shareTable[i].u.printer.separator);

				while (curdir)
				{
					curdir[0] = '\0';

					rtsmb_cpy (path_tmp, path);
#if (INCLUDE_RTSMB_UNICODE)
					if (prtsmb_srv_ctx->shareTable[i].u.printer.api->fs_wmkdir)
					{
						/* the fs supports unicode */
						rtsmb_util_rtsmb_to_unicode (path_tmp, (PFWCS) path_tmp, CFG_RTSMB_USER_CODEPAGE);

						rv = prtsmb_srv_ctx->shareTable[i].u.printer.api->fs_wmkdir((PFWCS) path_tmp);
					}
					else
#endif
					{
						/* the fs does not support unicode */
						rtsmb_util_rtsmb_to_ascii (path_tmp, (PFCHAR) path_tmp, CFG_RTSMB_USER_CODEPAGE);

						rv = prtsmb_srv_ctx->shareTable[i].u.printer.api->fs_mkdir((PFCHAR) path_tmp);
					}

					curdir[0] = prtsmb_srv_ctx->shareTable[i].u.printer.separator;

					curdir ++;

					curdir = rtsmb_chr (curdir, prtsmb_srv_ctx->shareTable[i].u.printer.separator);
				}

				rtsmb_cpy (path_tmp, path);
#if (INCLUDE_RTSMB_UNICODE)
				if (prtsmb_srv_ctx->shareTable[i].u.printer.api->fs_wmkdir)
				{
					/* the fs supports unicode */
					rtsmb_util_rtsmb_to_unicode (path_tmp, (PFWCS) path_tmp, CFG_RTSMB_USER_CODEPAGE);

					rv = prtsmb_srv_ctx->shareTable[i].u.printer.api->fs_wmkdir((PFWCS) path_tmp);
				}
				else
#endif
				{
					/* the fs does not support unicode */
					rtsmb_util_rtsmb_to_ascii (path_tmp, (PFCHAR) path_tmp, CFG_RTSMB_USER_CODEPAGE);

					rv = prtsmb_srv_ctx->shareTable[i].u.printer.api->fs_mkdir((PFCHAR) path_tmp);
				}
			}
			else
			{
				// check for path existence
			}
		}
		else
		{
			rv = -1;	// we need a path
		}
	}
	else
	{
		rv = -1;
	}

	if (!rv)
	{
		if (rtsmb_osport_printer_init (n))
		{
			rv = -1;
			prtsmb_srv_ctx->shareTable[i].inUse = FALSE;
			RTSMB_DEBUG_OUTPUT_STR("SR_AddPrinter: Printer initialization failed.\n", RTSMB_DEBUG_TYPE_ASCII);
		}
	}

addprintcleanup:
	RELEASE_SHARE ();

	if (rv == -1)
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_AddPrinter:  Failed to add printer \" ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR ("\".\n", RTSMB_DEBUG_TYPE_ASCII);
	}
	else
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_AddPrinter:  successfully added printer \" ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR ("\".\n", RTSMB_DEBUG_TYPE_ASCII);
	}

	return rv;
}

// returns 0 on success, non-zero else
int SR_ModifyShare (PFRTCHAR currentname, PFRTCHAR newname, byte newpermissions)
{
	PSR_RESOURCE pResource;
	int rv = -1;
	int found = 0;

	CLAIM_SHARE ();

	for (pResource = SR_FirstResource (); pResource; pResource = SR_NextResource (pResource))
	{
		if (!rtsmb_casecmp(pResource->name, currentname, CFG_RTSMB_USER_CODEPAGE))
		{
			found = 1;
			if(rtp_strcmp((const char*)newname,"") != 0)
			{
                rtsmb_cpy (pResource->name, newname);
			}

			if(newpermissions <=4)
			    pResource->permission = newpermissions;

			rv = 0;
			break;
		}
	}

	RELEASE_SHARE ();

	if(found == 0)
	{
		RTSMB_DEBUG_OUTPUT_STR ("Share not found", RTSMB_DEBUG_TYPE_ASCII);
	    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
	}

	if (rv == -1)
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_ModifyShare:  Failed to modify share \" ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (currentname, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR ("\".\n", RTSMB_DEBUG_TYPE_ASCII);
	}
	else
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_ModifyShare:  Successfully modified share \" ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (currentname, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR ("\".\n", RTSMB_DEBUG_TYPE_ASCII);
	}

	return rv;
}//SR_ModifyShare

int SR_ModifyPrinter (PFRTCHAR currentname, PFRTCHAR newname)
{
	PSR_RESOURCE pResource;
	int rv = -1;
	int found = 0;

	CLAIM_SHARE ();

	for (pResource = SR_FirstResource (); pResource; pResource = SR_NextResource (pResource))
	{
		if (!rtsmb_casecmp(pResource->name, currentname, CFG_RTSMB_USER_CODEPAGE))
		{
			found = 1;
			if(rtp_strcmp((const char*)newname,"") != 0)
			{
                rtsmb_cpy (pResource->name, newname);
			}
			rv = 0;
			break;
		}
	}

	RELEASE_SHARE ();

	if(found == 0)
	{
		RTSMB_DEBUG_OUTPUT_STR ("Printer or print share not found", RTSMB_DEBUG_TYPE_ASCII);
	    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
	}

	if (rv == -1)
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_ModifyPrinter:  Failed to modify print share \" ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (currentname, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR ("\".\n", RTSMB_DEBUG_TYPE_ASCII);
	}
	else
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_ModifyPrinter:  Successfully modified print share \" ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (currentname, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR ("\".\n", RTSMB_DEBUG_TYPE_ASCII);
	}

	return rv;

}//SR_ModifyPrinter

// returns 0 on success, non-zero else
int SR_RemoveShare (PFRTCHAR name)
{
	PSR_RESOURCE pResource;
	PNET_SESSIONCTX pCtx;
	int rv = -1;

	CLAIM_SHARE ();

	for (pResource = SR_FirstResource (); pResource; pResource = SR_NextResource (pResource))
	{
		if (!rtsmb_casecmp (pResource->name, name, CFG_RTSMB_USER_CODEPAGE))
		{
			pResource->inUse = FALSE;
			rv = 0;
			break;
		}
	}

	RELEASE_SHARE ();

	if (!rv)	// if found...
	{
		for (pCtx = firstSession (); pCtx; pCtx = nextSession (pCtx))
		{
			claimSession (pCtx);

			/**
			 * We have the session right where we want it.  It is not doing anything,
			 * so we can close the tree itself and all the files it has open on this session.
			 */
			SMBS_CloseShare (&pCtx->smbCtx, (word) INDEX_OF (prtsmb_srv_ctx->shareTable, pResource));

			releaseSession (pCtx);
		}
	}

	if (rv == -1)
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_RemoveShare:  Failed to remove share \" ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR ("\".\n", RTSMB_DEBUG_TYPE_ASCII);
	}
	else
	{
		RTSMB_DEBUG_OUTPUT_STR ("SR_RemoveShare:  Successfully removed share \" ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
		RTSMB_DEBUG_OUTPUT_STR ("\".\n", RTSMB_DEBUG_TYPE_ASCII);
	}

	return rv;
}

//****************************************************************************
//**
//**    END MODULE SMBSHARE.C
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */
