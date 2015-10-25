#ifndef __SMB_H__
#define __SMB_H__
//****************************************************************************
//**
//**    smb.h
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================



typedef enum		//Possible SMB Dialects
{
	DIALECT_NONE=-1,
	PC_NETWORK=0,	// PC NETWORK PROGRAM 1.0
	LANMAN_1_0,		// LANMAN 1.0
	LM1_2X002,		// LM1.2X002
	LANMAN_2_1,		// LANMAN 2.1
	NT_LM,			// NT LM 0.12
#ifdef SUPPORT_SMB2
    SMB_SMB2_2002,       // "SMB 2.002"
    SMB_SMB2_2xxx,       //  "SMB 2.???"
#endif
	NUM_DIALECTS
} SMB_DIALECT_T;

#ifdef SUPPORT_SMB2
typedef enum		//Possible SMB Dialects
{
	SMB2_NONE=-1,
    SMB2_2002,       // "SMB 2.002"
    SMB2_2xxx,
	SMB2_NUM_DIALECTS
} SMB2_DIALECT_T;
#endif



enum CodePageType
{
	RTSMB_CODEPAGE_LATIN1 = 0,
	RTSMB_CODEPAGE_SHIFTJIS
	//add any additional codepages here
};

//------------
// File Attribute Encoding for SMB Protocol
#define SMB_FA_RO	0x01 //Read only file
#define SMB_FA_H	0x02 //Hidden file
#define SMB_FA_S	0x04 //System file
#define SMB_FA_V	0x08 //Volume
#define SMB_FA_D	0x10 //Directory
#define SMB_FA_A	0x20 //Archive file
#define SMB_FA_N    0x80 //Normal file (no other attribs set)

//------------
// Buffer Formats
#define SMB_BF_DATA		0x01
#define SMB_BF_DIALECT	0x02
#define SMB_BF_PATHNAME	0x03
#define SMB_BF_ASCII	0x04
#define SMB_BF_VARIABLE	0x05

//------------
// SMB File Types
#define SMB_FILE_TYPE_DISK				0
#define SMB_FILE_TYPE_BYTE_MODE_PIPE	1
#define SMB_FILE_TYPE_MESSAGE_MODE_PIPE	2
#define SMB_FILE_TYPE_PRINTER			3
#define SMB_FILE_TYPE_UNKNOWN			0xFFFF

//------------
// SMB Commands
#define SMB_COM_CREATE_DIRECTORY 0x00
#define SMB_COM_DELETE_DIRECTORY 0x01
#define SMB_COM_OPEN 0x02
#define SMB_COM_CREATE 0x03
#define SMB_COM_CLOSE 0x04
#define SMB_COM_FLUSH 0x05
#define SMB_COM_DELETE 0x06
#define SMB_COM_RENAME 0x07
#define SMB_COM_QUERY_INFORMATION 0x08
#define SMB_COM_SET_INFORMATION 0x09
#define SMB_COM_READ 0x0A
#define SMB_COM_WRITE 0x0B
#define SMB_COM_LOCK_BYTE_RANGE 0x0C
#define SMB_COM_UNLOCK_BYTE_RANGE 0x0D
#define SMB_COM_CREATE_TEMPORARY 0x0E
#define SMB_COM_CREATE_NEW 0x0F
#define SMB_COM_CHECK_DIRECTORY 0x10
#define SMB_COM_PROCESS_EXIT 0x11
#define SMB_COM_SEEK 0x12
#define SMB_COM_LOCK_AND_READ 0x13
#define SMB_COM_WRITE_AND_UNLOCK 0x14
#define SMB_COM_READ_RAW 0x1A
#define SMB_COM_READ_MPX 0x1B
#define SMB_COM_READ_MPX_SECONDARY 0x1C
#define SMB_COM_WRITE_RAW 0x1D
#define SMB_COM_WRITE_MPX 0x1E
#define SMB_COM_WRITE_COMPLETE 0x20

#define SMB_COM_QUERY_SERVER 0x21

#define SMB_COM_SET_INFORMATION2 0x22
#define SMB_COM_QUERY_INFORMATION2 0x23
#define SMB_COM_LOCKING_ANDX 0x24
#define SMB_COM_TRANSACTION 0x25
#define SMB_COM_TRANSACTION_SECONDARY 0x26
#define SMB_COM_IOCTL 0x27
#define SMB_COM_IOCTL_SECONDARY 0x28
#define SMB_COM_COPY 0x29
#define SMB_COM_MOVE 0x2A
#define SMB_COM_ECHO 0x2B
#define SMB_COM_WRITE_AND_CLOSE 0x2C
#define SMB_COM_OPEN_ANDX 0x2D
#define SMB_COM_READ_ANDX 0x2E
#define SMB_COM_WRITE_ANDX 0x2F

#define SMB_COM_NEW_FILE_SIZE 0x30

#define SMB_COM_CLOSE_AND_TREE_DISC 0x31
#define SMB_COM_TRANSACTION2 0x32
#define SMB_COM_TRANSACTION2_SECONDARY 0x33
#define SMB_COM_FIND_CLOSE2 0x34
#define SMB_COM_FIND_NOTIFY_CLOSE 0x35
#define SMB_COM_TREE_CONNECT 0x70
#define SMB_COM_TREE_DISCONNECT 0x71
#define SMB_COM_NEGOTIATE 0x72
#define SMB_COM_SESSION_SETUP_ANDX 0x73
#define SMB_COM_LOGOFF_ANDX 0x74
#define SMB_COM_TREE_CONNECT_ANDX 0x75
#define SMB_COM_QUERY_INFORMATION_DISK 0x80
#define SMB_COM_SEARCH 0x81
#define SMB_COM_FIND 0x82
#define SMB_COM_FIND_UNIQUE 0x83
#define SMB_COM_NT_TRANSACT 0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY 0xA1
#define SMB_COM_NT_CREATE_ANDX 0xA2
#define SMB_COM_NT_CANCEL 0xA4
#define SMB_COM_OPEN_PRINT_FILE 0xC0
#define SMB_COM_WRITE_PRINT_FILE 0xC1
#define SMB_COM_CLOSE_PRINT_FILE 0xC2
#define SMB_COM_GET_PRINT_QUEUE 0xC3

#define SMB_COM_READ_BULK 0xD8
#define SMB_COM_WRITE_BULK 0xD9
#define SMB_COM_WRITE_BULK_DATA 0xDA

#define SMB_COM_NONE 0xFF



//------------------
// Flags
#define SMB_FLG_SUBDIALECTSUPPORT (1<<0)
#define SMB_FLG_CLIENTBUFFER (1<<1)
#define SMB_FLG_ZERO (0<<2) //reserved
#define SMB_FLG_CASELESSPATH (1<<3)
#define SMB_FLG_CANONICALIZED (1<<4)
#define SMB_FLG_OPLOCK (1<<5)
#define SMB_FLG_NOTIFY (1<<6)
#define SMB_FLG_RESPONSE (1<<7)

//------------------
// Flags2
#define SMB_FLG2_LONGNAME		0x0001
#define SMB_FLG2_EXATTRIB		0x0002
#define SMB_FLG2_LONGNAME_REQ	0x0040
#define SMB_FLG2_DFSPATH		0x1000
#define SMB_FLG2_EXEREADABLE	0x2000
#define SMB_FLG2_32BITERROR		0x4000
#define SMB_FLG2_UNICODESTR		0x8000

/* NT Error codes */
#define SMB_NT_STATUS_SUCCESS                0x00000000
#define SMB_NT_STATUS_ACCESS_VIOLATION       0xC0000005
#define SMB_NT_STATUS_NO_SUCH_FILE           0xC000000F
#define SMB_NT_STATUS_ACCESS_DENIED          0xC0000022
#define SMB_NT_STATUS_OBJECT_NAME_INVALID    0xC0000033
#define SMB_NT_STATUS_OBJECT_NAME_NOT_FOUND  0xC0000034
#define SMB_NT_STATUS_OBJECT_NAME_COLLISION  0xC0000035
#define SMB_NT_STATUS_OBJECT_PATH_INVALID    0xC0000039
#define SMB_NT_STATUS_OBJECT_PATH_NOT_FOUND  0xC000003A
#define SMB_NT_STATUS_OBJECT_PATH_SYNTAX_BAD 0xC000003B
#define SMB_NT_STATUS_SHARING_VIOLATION      0xC0000043
#define SMB_NT_STATUS_WRONG_PASSWORD         0xC000006A
#define SMB_NT_STATUS_ILL_FORMED_PASSWORD    0xC000006B
#define SMB_NT_STATUS_PASSWORD_RESTRICTION   0xC000006C
#define SMB_NT_STATUS_LOGON_FAILURE          0xC000006D
#define SMB_NT_STATUS_ACCOUNT_RESTRICTION    0xC000006E
#define SMB_NT_STATUS_INVALID_LOGON_HOURS    0xC000006F
#define SMB_NT_STATUS_INVALID_WORKSTATION    0xC0000070
#define SMB_NT_STATUS_PASSWORD_EXPIRED       0xC0000071
#define SMB_NT_STATUS_ACCOUNT_DISABLED       0xC0000072
#define SMB_NT_STATUS_CANNOT_DELETE          0xC0000121

//--------------
// Error Class
#define SMB_EC_SUCCESS 0
#define SMB_EC_ERRDOS 0x01
#define SMB_EC_ERRSRV 0x02
#define SMB_EC_ERRHRD 0x03
#define SMB_EC_ERRCMD 0xFF

//---------------
// DOS Error Codes
#define SMB_ERRDOS_BADFUNC 1
#define SMB_ERRDOS_BADFILE 2
#define SMB_ERRDOS_BADPATH 3
#define SMB_ERRDOS_NOFIDS 4
#define SMB_ERRDOS_NOACCESS 5
#define SMB_ERRDOS_BADFID 6
#define SMB_ERRDOS_BADMCD 7
#define SMB_ERRDOS_NOMEM 8
#define SMB_ERRDOS_BADMEN 9
#define SMB_ERRDOS_BADENV 10
#define SMB_ERRDOS_BADFORMAT 11
#define SMB_ERRDOS_BADACCESS 12
#define SMB_ERRDOS_BADDATA 13
#define SMB_ERRDOS_BADDRIVE 15
#define SMB_ERRDOS_REMCD 16
#define SMB_ERRDOS_DIFFDEVICE 17
#define SMB_ERRDOS_NOFILES 18
#define SMB_ERRDOS_BADSHARE 32
#define SMB_ERRDOS_LOCK 33
#define SMB_ERRDOS_FILEEXISTS 80

//---------------
// Server Error Codes
#define SMB_ERRSRV_ERROR		1
#define SMB_ERRSRV_BADPW		2
#define SMB_ERRSRV_ACCESS		4
#define SMB_ERRSRV_INVNID		5
#define SMB_ERRSRV_INVNETNAME	6
#define SMB_ERRSRV_INVDEVICE	7
#define SMB_ERRSRV_QFULL		49
#define SMB_ERRSRV_QTOOBIG		50
#define SMB_ERRSRV_QEOF			51
#define SMB_ERRSRV_INVPFID		52
#define SMB_ERRSRV_SMBCMD		64
#define SMB_ERRSRV_SRVERROR		65
#define SMB_ERRSRV_TOOMANYUIDS	90
#define SMB_ERRSRV_BADUID		91
#define SMB_ERRSRV_USEMPX		250
#define SMB_ERRSRV_USESTD		251
#define SMB_ERRSRV_CONTMPX		252
#define SMB_ERRSRV_NOSUPPORT	65535

//---------------
// Hardware Error Codes
#define SMB_ERRHRD_NOWRITE 19
#define SMB_ERRHRD_BADUNIT 20
#define SMB_ERRHRD_NOTREADY 21
#define SMB_ERRHRD_BADCMD 22
#define SMB_ERRHRD_DATA 23
#define SMB_ERRHRD_BADREQ 24
#define SMB_ERRHRD_SEEK 25
#define SMB_ERRHRD_BADMEDIA 26
#define SMB_ERRHRD_BADSECTOR 27
#define SMB_ERRHRD_NOPAPER 28
#define SMB_ERRHRD_WRITE 29
#define SMB_ERRHRD_READ 30
#define SMB_ERRHRD_GENERAL 31
#define SMB_ERRHRD_BADSHARE 32
#define SMB_ERRHRD_LOCK 33
#define SMB_ERRHRD_WRONGDISK 34
#define SMB_ERRHRD_FCBUNAVAIL 35
#define SMB_ERRHRD_SHAREBUFEXC 36
#define SMB_ERRHRD_DISKFULL 39

#ifdef SUPPORT_SMB2
/* Not sur if error scheme is the same, distigbuish for now  */
#define SMB2_EC_ERRSRV SMB_EC_ERRSRV
#define SMB2_ERRSRV_ERROR SMB_ERRSRV_ERROR
#define SMB2_ERRSRV_SRVERROR SMB_ERRSRV_SRVERROR
#endif

/* the following CAP_* defines are flags of the capabilities dword in
 the negotiate response */
#define CAP_RAW_MODE			0x0001	/* The server supports
                                   SMB_COM_READ_RAW and
                                   SMB_COM_WRITE_RAW */
#define CAP_MPX_MODE			0x0002	/* The server supports
                                   SMB_COM_READ_MPX and
                                   SMB_COM_WRITE_MPX */
#define CAP_UNICODE				0x0004	/* The server supports Unicode
                                   strings */
#define CAP_LARGE_FILES			0x0008	/* The server supports large files
                                   with 64 bit offsets */
#define CAP_NT_SMBS				0x0010	/* The server supports the SMBs
                                   particular to the NT LM 0.12
                                   dialect. Implies CAP_NT_FIND. */
#define CAP_RPC_REMOTE_APIS		0x0020	/* The server supports remote admin
                                   API requests via DCE RPC */
#define CAP_STATUS32			0x0040	/* The server can respond with 32 bit
                                   status codes in Status.Status */
#define CAP_LEVEL_II_OPLOCKS	0x0080	/* The server supports level 2
                                   oplocks */
#define CAP_LOCK_AND_READ		0x0100	/* The server supports the
                                   SMB_COM_LOCK_AND_READ SMB */
#define CAP_NT_FIND				0x0200
#define CAP_DFS					0x1000	/* The server is DFS aware */
#define CAP_LARGE_READX			0x4000	/* The server supports large
                                   SMB_COM_READ_ANDX */
#define CAP_LARGE_WRITEX		0x8000	/* The server supports large
                                   SMB_COM_READ_ANDX */
#define CAP_UNIX                0x00800000  /* The server supports UNIX
								   extensions */
#define CAP_EXTENDED_SECURITY	0x80000000	/* The server supports extended
                                   security exchanges. */

#define NT_OPEN_EXISTING		1
#define NT_CREATE_NEW			2
#define NT_OPEN_ALWAYS			3
#define NT_TRUNCATE				4
#define NT_CREATE_ALWAYS		5


/* these take a short (representing an access mode value),
 returns the value of the field specified */
#define SMB_ACCESS_MODE_WRITE_THROUGH(A)	((A & 0x8000) >> 14)
#define SMB_ACCESS_MODE_SHARING(A)			((A & 0x0070) >> 4)
#define SMB_ACCESS_MODE_ACCESS(A)			(A & 0x0007)
#define SMB_ACCESS_MODE_CACHE(A)			((A & 0x1000) >> 12)
#define SMB_ACCESS_MODE_LOCALITY(A)			((A & 0x0700) >> 8)


/* these take a short (representing an access mode value), and a
 value for the field and then sets the field. */
#define SMB_ACCESS_MODE_SET_WRITE_THROUGH(A, B)	{A = (word)(A|((B & 0x1) << 14));}
#define SMB_ACCESS_MODE_SET_SHARING(A, B)		{A = (word)(A|((B & 0x7) << 4));}
#define SMB_ACCESS_MODE_SET_ACCESS(A, B)		{A = (word)(A|(B & 0x7));}
#define SMB_ACCESS_MODE_SET_CACHE(A, B)			{A = (word)(A|((B & 0x1) << 12)(;}
#define SMB_ACCESS_MODE_SET_LOCALITY(A, B)		{A = (word)(A|((B & 0x7) << 8));}


/* these take a short (representing an open function value),
 returns the value of the field specified */
#define SMB_OPEN_FUNCTION_CREATE(A)			((A & 0x0010) >> 4)
#define SMB_OPEN_FUNCTION_OPEN(A)			(A & 0x0003)


#define INVALID_TID	0xFFFF
#define INVALID_UID	0

#define TRANS2_OPEN2					0x00
#define TRANS2_FIND_FIRST2				0x01
#define TRANS2_FIND_NEXT2				0x02
#define TRANS2_FIND_CLOSE2				0x02
#define TRANS2_QUERY_FS_INFORMATION		0x03
#define TRANS2_QUERY_PATH_INFORMATION	0x05
#define TRANS2_SET_PATH_INFORMATION		0x06
#define TRANS2_QUERY_FILE_INFORMATION	0x07
#define TRANS2_SET_FILE_INFORMATION		0x08
#define TRANS2_FSCTL					0x09
#define TRANS2_IOCTL2					0x0A
#define TRANS2_FIND_NOTIFY_FIRST		0x0B
#define TRANS2_FIND_NOTIFY_NEXT			0x0C
#define TRANS2_CREATE_DIRECTORY			0x0D
#define TRANS2_SESSION_SETUP			0x0E
#define TRANS2_GET_DFS_REFERRAL			0x10
#define TRANS2_REPORT_DFS_INCONSISTENCY	0x11


/* This is dictated by the protocol.  A share name can
   be at most 12 ASCII characters. */
#define RTSMB_MAX_SHARENAME_SIZE        12

/* This is dictated by the protocol.  A server comment
   can be at most 42 ASCII characters. */
#define RTSMB_MAX_COMMENT_SIZE          42



enum RTSMB_SHARE_TYPE {
RTSMB_SHARE_TYPE_DISK = 0,
RTSMB_SHARE_TYPE_PRINTER,
RTSMB_SHARE_TYPE_DEVICE,
RTSMB_SHARE_TYPE_IPC
};

//============================================================================
//    INTERFACE DATA DECLARATIONS
//============================================================================
//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================
//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================
//****************************************************************************
//**
//**    END HEADER smb.h
//**
//****************************************************************************
#endif // __SMB_H__
