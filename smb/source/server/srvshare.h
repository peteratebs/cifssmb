#ifndef __SRV_SHARE_H__
#define __SRV_SHARE_H__
//****************************************************************************
//**
//**    SRV_SHARE.H
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "psmbfile.h"

//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
typedef enum
{
	ST_DISKTREE = 0,
	ST_PRINTQ,
	ST_DEVICE,
	ST_IPC,

	ANY_SHARE_TYPE,

	NUM_SHARE_TYPES
} SHARE_T;	// RAP compliant

/**
 * SHARE_FLAGS_8_3 means that the file system can only handle DOS-style 8.3 formatted
 * file names.  All incoming names will be mangled and passed to the file system.
 * This has problems, however, since both longname.txt and longnames.txt will be
 * mangled to longna~1.txt.  There is no way to avoid this, without the file system
 * mangling the names itself, in which case, this flag should not be specified.
 */
#define SHARE_FLAGS_8_3				0x01

/**
 * SHARE_FLAGS_CASE_SENSITIVE means that the file system is case sensitive.  This
 * causes no end of problems, because typical Windows clients assume that the 
 * file system is not case sensitive.  So, this flags means that we uppercase all
 * incoming filenames.  This gives the illusion of being case insensitive, but the
 * problem is, of course, that any existing filenames on the file system that aren't in
 * all-caps will be inaccessible to SMB clients.
 */
#define SHARE_FLAGS_CASE_SENSITIVE	0x02

/**
 * SHARE_FLAGS_CREATE means that the shared directory will be created if it doesn't
 * exist.  So, you could share "c:\long\path\that\does\not\exist\" and each directory
 * would be made if it did not already exist.
 */
#define SHARE_FLAGS_CREATE			0x04


#define MAX_PATH_PREFIX_SIZE	230

//============================================================================
//    INTERFACE STRUCTURES / UTILITY CLASSES
//============================================================================

typedef struct sr_resource_s
{
	BBOOL inUse;		// does this resource contain valid data?
	
	SHARE_T stype;		// the type of shared resource
	rtsmb_char name[RTSMB_MAX_SHARENAME_SIZE + 1];	// the name of the shared resources
	rtsmb_char comment[RTSMB_MAX_COMMENT_SIZE + 1];	// comment about shared resource
	byte permission;	// what permissions the password for this share gives
	PFCHAR password;	// pointer to passwordBuf or NULL if we don't need it
	char passwordBuf[CFG_RTSMB_MAX_PASSWORD_SIZE + 1];
	
	// FIXME: code in expandName (in smbfio.c) requires that 
	// disktree and printer share their similar info both at the
	// beginning of structs (it refers to u.disktree even for a printer)
	union {
		struct {
			rtsmb_char path[MAX_PATH_PREFIX_SIZE + 1];	// path to local resource
			PSMBFILEAPI api;	// API for accessing files on this share 
			int flags;
			rtsmb_char separator;
			
		} disktree;
		
		struct {
			rtsmb_char path[MAX_PATH_PREFIX_SIZE + 1];	// path to local resource
			PSMBFILEAPI api;	// API for accessing files on this share 
			int flags;
			rtsmb_char separator;
			int num;
			
			/* printer file is used right now to store the driver name for the printer */
			PFRTCHAR printerfile;
			rtsmb_char printerfileBuf [SMBF_FILENAMESIZE + 1];
			
		} printer;
	} u;
	
} SR_RESOURCE_T;
typedef SR_RESOURCE_T RTSMB_FAR *PSR_RESOURCE;
//============================================================================
//    INTERFACE DATA DECLARATIONS
//============================================================================
//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================
void SR_Init (void);
PFRTCHAR SR_ServiceToStr( SHARE_T stype );
PSR_RESOURCE SR_ResourceById( word id );
PSR_RESOURCE SR_FirstResource( void );
PSR_RESOURCE SR_NextResource( PSR_RESOURCE pPrev );
int SR_GetTreeId( PFRTCHAR name, PFRTCHAR service );
int SR_GetTreeIdFromName ( PFRTCHAR name );
int SR_AddDiskTree (PFRTCHAR name, PFRTCHAR comment, PSMBFILEAPI api, PFRTCHAR path, int flags, byte permissions, PFCHAR password);
int SR_AddIPC (PFCHAR password);
int SR_AddPrinter (PFRTCHAR name, PFRTCHAR comment, int n, PSMBFILEAPI api, PFRTCHAR path, int flags, PFCHAR password, PFRTCHAR printerfile);
int SR_RemoveShare (PFRTCHAR name);
int SR_ModifyShare (PFRTCHAR currentname, PFRTCHAR newname, byte newpermissions);
int SR_ModifyPrinter (PFRTCHAR currentname, PFRTCHAR newname);

//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================

//****************************************************************************
//**
//**    END HEADER SRV_SHARE.H
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_SHARE_H__ */
