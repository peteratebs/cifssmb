#ifndef __SMB2_WIREDEFS_H__
#define __SMB2_WIREDEFS_H__


/* If compiler requires #pragma pack(1), replace all PACK_PRAGMA_ONE with #pragma pack(1) */
#define PACK_PRAGMA_ONE
/* If compiler requires #pragma pack(), replace all PACK_PRAGMA_POP with #pragma pack() */
#define PACK_PRAGMA_POP
/* If compiler supports __attribute__((packed)) set PACK_ATTRIBUTE to attribute__((packed)) */
#define PACK_ATTRIBUTE  __attribute__((packed))
#include <assert.h>
#define PACK_STRUCT_TO_WIRE(PSTRUCT,STYPE,SFIXED) \
    if (size<SFIXED)return -1;\
    tc_memcpy(buf,PSTRUCT,SFIXED);\
    buf=PADD(buf,SFIXED);\
    size-=SFIXED;

#define UNPACK_STRUCT_FR_WIRE(PSTRUCT,STYPE,SFIXED) \
    if (size<SFIXED)return -1;\
    tc_memcpy(PSTRUCT, buf, SFIXED);\
    buf=PADD(buf,SFIXED);\
    size-=SFIXED;


//****************************************************************************
//**
//**    smb2_wiredefs.h
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



#define SMB2_NEGOTIATE_SIGNING_ENABLED  0x0001   // When set, indicates that security signatures are enabled on the server.
#define SMB2_NEGOTIATE_SIGNING_REQUIRED 0x0002   // When set, indicates that security signatures are required by the server.
#define SMB2_SESSION_FLAG_BINDING 0x01           //  When set, indicates that the request is to bind an existing session to a new connection.

#define SMB2_DIALECT_2002  0x0202
#define SMB2_DIALECT_2100  0x0210
#define SMB2_DIALECT_3000  0x0300
#define SMB2_DIALECT_3002  0x0302
#define SMB2_DIALECT_WILD  0x02FF

#define SMB2IS3XXDIALECT(D) (D >= SMB2_DIALECT_3000)

/* EncryptionAlgorithm field in SMB2 TRANSFORM_HEADER */
#define SMB2_ENCRYPTION_AES128_CCM 0x0001


/* SMB2 Header structure command values and flag vlues. See  2.2.1.2, page 30 */
#define SMB2_NEGOTIATE          0x0000
#define SMB2_SESSION_SETUP      0x0001
#define SMB2_LOGOFF             0x0002
#define SMB2_TREE_CONNECT       0x0003
#define SMB2_TREE_DISCONNECT    0x0004
#define SMB2_CREATE             0x0005
#define SMB2_CLOSE              0x0006
#define SMB2_FLUSH              0x0007
#define SMB2_READ               0x0008
#define SMB2_WRITE              0x0009
#define SMB2_LOCK               0x000A
#define SMB2_IOCTL              0x000B
#define SMB2_CANCEL             0x000C
#define SMB2_ECHO               0x000D
#define SMB2_QUERY_DIRECTORY    0x000E
#define SMB2_CHANGE_NOTIFY      0x000F
#define SMB2_QUERY_INFO         0x0010
#define SMB2_SET_INFO           0x0011
#define SMB2_OPLOCK_BREAK       0x0012

#define SMB2_FLAGS_SERVER_TO_REDIR      0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND        0x00000002
#define SMB2_FLAGS_RELATED_OPERATIONS   0x00000004
#define SMB2_FLAGS_SIGNED               0x00000008
#define SMB2_FLAGS_DFS_OPERATIONS       0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION     0x20000000



/* Not sure if error scheme is the same, distinguish for now  */
// TBD
#define SMB2_EC_ERRSRV SMB_EC_ERRSRV
#define SMB2_ERRSRV_ERROR SMB_ERRSRV_ERROR
#define SMB2_ERRSRV_SRVERROR SMB_ERRSRV_SRVERROR

#define SMB2_STATUS_SUCCESS                     0x00000000 /* The client request is successful. */
#define SMB2_STATUS_INVALID_SMB                 0x00010002 /* An invalid SMB client request is received by the server. */
#define SMB2_STATUS_SMB_BAD_TID                 0x00050002 /* The client request received by the server contains an invalid TID value. */
#define SMB2_STATUS_SMB_BAD_COMMAND             0x00160002 /* The client request received by the server contains an unknown SMB command code. */
#define SMB2_STATUS_SMB_BAD_UID                 0x005B0002 /* The client request to the server contains an invalid UID value. */
#define SMB2_STATUS_SMB_USE_STANDARD            0x00FB0002 /* The client request received by the server is for a non-standard SMB operation (for example, an SMB_COM_READ_MPX request on a non-disk share ). The client SHOULD send another request with a different SMB command to perform this operation. */
#define SMB2_STATUS_BUFFER_OVERFLOW             0x80000005 /* The data was too large to fit into the specified buffer. */
#define SMB2_STATUS_NO_MORE_FILES               0x80000006 /* No more files were found that match the file specification. */
#define SMB2_STATUS_STOPPED_ON_SYMLINK          0x8000002D /* The create operation stopped after reaching a symbolic link. */
#define SMB2_STATUS_NOT_IMPLEMENTED             0xC0000002 /* The requested operation is not implemented. */
#define SMB2_STATUS_INVALID_PARAMETER           0xC000000D /* The parameter specified in the request is not valid. */
#define SMB2_STATUS_NO_SUCH_DEVICE              0xC000000E /* A device that does not exist was specified. */
#define SMB2_STATUS_INVALID_DEVICE_REQUEST      0xC0000010 /* The specified request is not a valid operation for the target device. */
#define SMB2_STATUS_MORE_PROCESSING_REQUIRED    0xC0000016 /* If extended security has been negotiated, then this error code can be returned in the SMB_COM_SESSION_SETUP_ANDX response from the server to indicate that additional authentication information is to be exchanged. See section 2.2.4.6 for details. */
#define SMB2_STATUS_ACCESS_DENIED               0xC0000022 /* The client did not have the required permission needed for the operation. */
#define SMB2_STATUS_BUFFER_TOO_SMALL            0xC0000023 /* The buffer is too small to contain the entry. No information has been written to the buffer. */
#define SMB2_STATUS_OBJECT_NAME_NOT_FOUND       0xC0000034 /* The object name is not found. */
#define SMB2_STATUS_OBJECT_NAME_COLLISION       0xC0000035 /* The object name already exists. */
#define SMB2_STATUS_OBJECT_PATH_NOT_FOUND       0xC000003A /* The path to the directory specified was not found. This error is also returned on a create request if the operation requires the creation of more than one new directory level for the path specified. */
#define SMB2_STATUS_BAD_IMPERSONATION_LEVEL     0xC00000A5 /* A specified impersonation level is invalid. This error is also used to indicate that a required impersonation level was not provided. */
#define SMB2_STATUS_IO_TIMEOUT                  0xC00000B5 /* The specified I/O operation was not completed before the time-out period expired. */
#define SMB2_STATUS_FILE_IS_A_DIRECTORY         0xC00000BA /* The file that was specified as a target is a directory and the caller specified that it could be anything but a directory. */
#define SMB2_STATUS_NOT_SUPPORTED               0xC00000BB /* The client request is not supported. */
#define SMB2_STATUS_NETWORK_NAME_DELETED        0xC00000C9 /* The network name specified by the client has been deleted on the server. This error is returned if the client specifies an incorrect TID or the share on the server represented by the TID was deleted. */
#define SMB2_STATUS_BAD_NETWORK_NAME            0xC00000CC /* The network or file name in a tree connect request was not found.  */
#define SMB2_STATUS_USER_SESSION_DELETED        0xC0000203 /* The user session specified by the client has been deleted on the server. This error is returned by the server if the client sends an incorrect UID. */
#define SMB2_STATUS_NETWORK_SESSION_EXPIRED     0xC000035C /* The client's session has expired; therefore, the client MUST re-authenticate to continue accessing remote resources. */
#define SMB2_STATUS_SMB_TOO_MANY_UIDS           0xC000205A /*  */


#define SMB2_STATUS_INSUFFICIENT_RESOURCES      0xC000009A
#define SMB2_STATUS_REQUEST_NOT_ACCEPTED        0xC00000D0
/* Session flags - see section 2.2.6 only one at a time */
#define SMB2_SESSION_FLAG_IS_GUEST      0x0001
#define SMB2_SESSION_FLAG_IS_NULL       0x0002
#define SMB2_SESSION_FLAG_ENCRYPT_DATA  0x0004


#define SMB2_GLOBAL_CAP_DFS 0x00000001                  /* When set, indicates that the server supports the Distributed File System (DFS). */
#define SMB2_GLOBAL_CAP_LEASING 0x00000002              /* When set, indicates that the server supports leasing. This flag is not valid for the SMB 2.002 dialect. */
#define SMB2_GLOBAL_CAP_LARGE_MTU 0x00000004            /* ** When set, indicates that the server supports multi-credit operations. This flag is not valid for the SMB 2.002 dialect. */
#define SMB2_GLOBAL_CAP_MULTI_CHANNEL 0x00000008        /* ** When set, indicates that the server supports establishing multiple channels for a single session. This flag is not valid for the SMB 2.002 and SMB 2.1 dialects. . */
#define SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010   /* ** When set, indicates that the server supports persistent handles. This flag is not valid for the SMB 2.002 and SMB 2.1 dialects. */
#define SMB2_GLOBAL_CAP_DIRECTORY_LEASING 0x00000020    /* ** When set, indicates that the server supports directory leasing. This flag is not valid for the SMB 2.002 and SMB 2.1 dialects. */
#define SMB2_GLOBAL_CAP_ENCRYPTION 0x00000040           /* ** When set, indicates that the server supports encryption. This flag is not valid for the SMB 2.002 and SMB 2.1 dialects. */




/*  File_pipe_printer access mask, section 2.2.13.1.1 */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_DATA         0x00000001   /* ** This value indicates the right to read data from the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_DATA        0x00000002   /* ** This value indicates the right to write data into the file or named pipe beyond the end of the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_APPEND_DATA       0x00000004   /* ** This value indicates the right to append data into the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_EA           0x00000008   /* ** This value indicates the right to read the extended attributes of the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_EA          0x00000010   /* ** This value indicates the right to write or change the extended attributes to the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_DELETE_CHILD      0x00000040   /* ** This value indicates the right to delete entries within a directory. */
#define SMB2_FPP_ACCESS_MASK_FILE_EXECUTE           0x00000020   /* ** This value indicates the right to execute the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_ATTRIBUTES   0x00000080   /* ** This value indicates the right to read the attributes of the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_ATTRIBUTES  0x00000100   /* ** This value indicates the right to change the attributes of the file. */
#define SMB2_FPP_ACCESS_MASK_DELETE                 0x00010000   /* ** This value indicates the right to delete the file. */
#define SMB2_FPP_ACCESS_MASK_READ_CONTROL           0x00020000   /* ** This value indicates the right to read the security descriptor for the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_WRITE_DAC              0x00040000   /* ** This value indicates the right to change the discretionary access control list (DACL) in the security descriptor for the file or named pipe. For the DACL data structure, see ACL in [MS-DTYP]. */
#define SMB2_FPP_ACCESS_MASK_WRITE_OWNER            0x00080000   /* ** This value indicates the right to change the owner in the security descriptor for the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_SYNCHRONIZE            0x00100000   /* ** SMB2 clients set this flag to any value. SMB2 servers SHOULD ignore this flag. */
#define SMB2_FPP_ACCESS_MASK_ACCESS_SYSTEM_SECURITY 0x01000000   /* ** This value indicates the right to read or change the system access control list (SACL) in the security descriptor for the file or named pipe. For the SACL data structure, see ACL in [MS-DTYP].<42> */
#define SMB2_FPP_ACCESS_MASK_MAXIMUM_ALLOWED        0x02000000   /* ** This value indicates that the client is requesting an open to the file with the highest level of access the client has on this file. If no access is granted for the client on this file, the server MUST fail the open with STATUS_ACCESS_DENIED. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_ALL            0x10000000   /* ** This value indicates a request for all the access flags that are previously listed except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_EXECUTE        0x20000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_READ_ATTRIBUTES| FILE_EXECUTE| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_WRITE          0x40000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_WRITE_DATA| FILE_APPEND_DATA| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_READ           0x80000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_READ_DATA| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL. */


/*  directory access mask, section 2.2.13.1.1 */
#define SMB2_DIR_ACCESS_MASK_FILE_LIST_DIRECTORY    0x00000001   /* ** This value indicates the right to enumerate the contents of the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_ADD_FILE          0x00000002   /* ** This value indicates the right to create a file under the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_ADD_SUBDIRECTORY  0x00000004   /* ** This value indicates the right to add a sub-directory under the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_READ_EA           0x00000008   /* ** This value indicates the right to read the extended attributes of the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_WRITE_EA          0x00000010   /* ** This value indicates the right to write or change the extended attributes of the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_TRAVERSE          0x00000020   /* ** This value indicates the right to traverse this directory if the server enforces traversal checking */
#define SMB2_DIR_ACCESS_MASK_FILE_DELETE_CHILD      0x00000040   /* ** This value indicates the right to delete the files and directories within this directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_READ_ATTRIBUTES   0x00000080   /* ** This value indicates the right to read the attributes of the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_WRITE_ATTRIBUTES  0x00000100   /* ** This value indicates the right to change the attributes of the directory. */
#define SMB2_DIR_ACCESS_MASK_DELETE                 0x00010000   /* ** This value indicates the right to delete the directory. */
#define SMB2_DIR_ACCESS_MASK_READ_CONTROL           0x00020000   /* ** This value indicates the right to read the security descriptor for the directory. */
#define SMB2_DIR_ACCESS_MASK_WRITE_DAC              0x00040000   /* ** This value indicates the right to change the DACL in the security descriptor for the directory. For the DACL data structure, see ACL in [MS-DTYP]. */
#define SMB2_DIR_ACCESS_MASK_WRITE_OWNER            0x00080000   /* ** This value indicates the right to change the owner in the security descriptor for the directory. */
#define SMB2_DIR_ACCESS_MASK_SYNCHRONIZE            0x00100000   /* ** SMB2 clients set this flag to any value.<43> SMB2 servers SHOULD<44> ignore this flag. */
#define SMB2_DIR_ACCESS_MASK_ACCESS_SYSTEM_SECURITY 0x01000000   /* ** This value indicates the right to read or change the SACL in the security descriptor for the directory. For the SACL data structure, see ACL in [MS-DTYP].<45> */
#define SMB2_DIR_ACCESS_MASK_MAXIMUM_ALLOWED        0x02000000   /* ** This value indicates that the client is requesting an open to the directory with the highest level of access the client has on this directory. If no access is granted for the client on this directory, the server MUST fail the open with STATUS_ACCESS_DENIED. */
#define SMB2_DIR_ACCESS_MASK_GENERIC_ALL            0x10000000   /* ** This value indicates a request for all the access flags that are listed above except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY. */
#define SMB2_DIR_ACCESS_MASK_GENERIC_EXECUTE        0x20000000   /* ** This value indicates a request for the following access flags listed above: FILE_READ_ATTRIBUTES| FILE_TRAVERSE| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_DIR_ACCESS_MASK_GENERIC_WRITE          0x40000000   /* ** This value indicates a request for the following access flags listed above: FILE_ADD_FILE| FILE_ADD_SUBDIRECTORY| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_DIR_ACCESS_MASK_GENERIC_READ           0x80000000   /* ** This value indicates a request for the following access flags listed above: FILE_LIST_DIRECTORY| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL. */




//============================================================================
//    INTERFACE DATA DECLARATIONS
//============================================================================
#define PACK_CLIENT_MID(TO,F) *((unsigned short *)(TO)) = F
#define UNPACK_CLIENT_MID(F)  (unsigned short) *((unsigned short *)(F))

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_HEADER
{
    byte ProtocolId[4];
    word StructureSize; // 64
    word CreditCharge; /* (2 bytes): In the SMB 2.002 dialect, this field MUST NOT be used and MUST be reserved. */
    dword Status_ChannelSequenceReserved; /*  (4 bytes): */
    word Command;
    word CreditRequest_CreditResponse;
    dword Flags;
    dword NextCommand;
    ddword MessageId;
    dword Reserved;
    dword TreeId;
    ddword SessionId;
    byte Signature[16];

} PACK_ATTRIBUTE RTSMB2_HEADER;
PACK_PRAGMA_POP
typedef RTSMB2_HEADER RTSMB_FAR *PRTSMB2_HEADER;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_NEGOTIATE_C
{
    word StructureSize; // 36
    word DialectCount;
    word SecurityMode;
    word Reserved;
    dword Capabilities;
    byte  guid[16];
    FILETIME_T ClientStartTime;
    word Dialects[4];
} PACK_ATTRIBUTE RTSMB2_NEGOTIATE_C;
PACK_PRAGMA_POP
typedef RTSMB2_NEGOTIATE_C RTSMB_FAR *PRTSMB2_NEGOTIATE_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_NEGOTIATE_R
{
    word StructureSize; // 65
    word SecurityMode;
    word DialectRevision;
    word Reserved;
    byte  ServerGuid[16];
    dword Capabilities;
    dword MaxTransactSize;
    dword MaxReadSize;
    dword MaxWriteSize;
    ddword SystemTime;
    ddword ServerStartTime;
    word SecurityBufferOffset;
    word SecurityBufferLength;
    dword Reserved2;
    byte  SecurityBuffer;
} PACK_ATTRIBUTE RTSMB2_NEGOTIATE_R;
PACK_PRAGMA_POP
typedef RTSMB2_NEGOTIATE_R RTSMB_FAR *PRTSMB2_NEGOTIATE_R;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_SESSION_SETUP_C
{
    word  StructureSize; // 25
	byte  Flags;
	byte  SecurityMode;
	dword Capabilities;
	dword Channel;
	word  SecurityBufferOffset;
	word  SecurityBufferLength;
    ddword PreviousSessionId;
    byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_SESSION_SETUP_C;
PACK_PRAGMA_POP
typedef RTSMB2_SESSION_SETUP_C RTSMB_FAR *PRTSMB2_SESSION_SETUP_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_SESSION_SETUP_R
{
    word  StructureSize; // 9
	word  SessionFlags;
	word  SecurityBufferOffset;
	word  SecurityBufferLength;
    byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_SESSION_SETUP_R;
PACK_PRAGMA_POP
typedef RTSMB2_SESSION_SETUP_R RTSMB_FAR *PRTSMB2_SESSION_SETUP_R;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LOGOFF_C
{
    word  StructureSize; // 4
    word  Reserved;
} PACK_ATTRIBUTE RTSMB2_LOGOFF_C;
PACK_PRAGMA_POP
typedef RTSMB2_LOGOFF_C RTSMB_FAR *PRTSMB2_LOGOFF_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LOGOFF_R
{
    word  StructureSize; // 16
    word  Reserved;
} PACK_ATTRIBUTE RTSMB2_LOGOFF_R;
PACK_PRAGMA_POP
typedef RTSMB2_LOGOFF_R RTSMB_FAR *PRTSMB2_LOGOFF_R;

#define SMB2_SHARE_TYPE_DISK 0x01
#define SMB2_SHARE_TYPE_PIPE 0x02
#define SMB2_SHARE_TYPE_PRINT 0x03

#define SMB2_SHAREFLAG_MANUAL_CACHING 0x00000000
#define SMB2_SHAREFLAG_AUTO_CACHING 0x00000010
#define SMB2_SHAREFLAG_VDO_CACHING 0x00000020
#define SMB2_SHAREFLAG_NO_CACHING 0x00000030
#define SMB2_SHAREFLAG_DFS 0x00000001
#define SMB2_SHAREFLAG_DFS_ROOT 0x00000002
#define SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS 0x00000100
#define SMB2_SHAREFLAG_FORCE_SHARED_DELETE 0x00000200
#define SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING 0x00000400
#define SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM 0x00000800
#define SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK 0x00001000
#define SMB2_SHAREFLAG_ENABLE_HASH_V1 0x00002000
#define SMB2_SHAREFLAG_ENABLE_HASH_V2 0x00004000
#define SMB2_SHAREFLAG_ENCRYPT_DATA 0x00008000
#define SMB2_SHARE_CAP_DFS 0x00000008
#define SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY 0x00000010
#define SMB2_SHARE_CAP_SCALEOUT 0x00000020
#define SMB2_SHARE_CAP_CLUSTER 0x00000040
#define SMB2_SHARE_CAP_ASYMMETRIC 0x00000080

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_TREE_CONNECT_C
{
    word  StructureSize; // 9
    word  Reserved;
    word  PathOffset;
    word  PathLength;
    byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_TREE_CONNECT_C;
PACK_PRAGMA_POP
typedef RTSMB2_TREE_CONNECT_C RTSMB_FAR *PRTSMB2_TREE_CONNECT_C;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_TREE_CONNECT_R
{
    word  StructureSize; // 16
    byte  ShareType;
    byte  Reserved;
    dword ShareFlags;
    dword Capabilities;
    dword MaximalAccess;
} PACK_ATTRIBUTE RTSMB2_TREE_CONNECT_R;
PACK_PRAGMA_POP
typedef RTSMB2_TREE_CONNECT_R RTSMB_FAR *PRTSMB2_TREE_CONNECT_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_TREE_DISCONNECT_C
{
    word  StructureSize; // 4
    word  Reserved;
} PACK_ATTRIBUTE RTSMB2_TREE_DISCONNECT_C;
PACK_PRAGMA_POP
typedef RTSMB2_TREE_DISCONNECT_C RTSMB_FAR *PRTSMB2_TREE_DISCONNECT_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_TREE_DISCONNECT_R
{
    word  StructureSize; // 4
    word  Reserved;
} PACK_ATTRIBUTE RTSMB2_TREE_DISCONNECT_R;
PACK_PRAGMA_POP
typedef RTSMB2_TREE_DISCONNECT_R RTSMB_FAR *PRTSMB2_TREE_DISCONNECT_R;


#define SMB2_OPLOCK_LEVEL_NONE 0x00
#define SMB2_OPLOCK_LEVEL_II 0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE 0x08
#define SMB2_OPLOCK_LEVEL_BATCH 0x09
#define SMB2_OPLOCK_LEVEL_LEASE 0xFF

#define SMB2_ImpersonationLevel_Anonymous           0x00000000
#define SMB2_ImpersonationLevel_Identification      0x00000001
#define SMB2_ImpersonationLevel_Impersonation       0x00000002
#define SMB2_ImpersonationLevel_Delegate            0x00000003

/* RTSMB2_CREATE_C::ShareAccess */
#define SMB2_FILE_SHARE_READ                        0x00000001
#define SMB2_FILE_SHARE_WRITE                       0x00000002
#define SMB2_FILE_SHARE_DELETE                      0x00000004

/* RTSMB2_CREATE_C::CreateDisposition */
#define SMB2_FILE_SUPERSEDE                         0x00000000
#define SMB2_FILE_OPEN                              0x00000001
#define SMB2_FILE_CREATE                            0x00000002
#define SMB2_FILE_OPEN_IF                           0x00000003
#define SMB2_FILE_OVERWRITE                         0x00000004
#define SMB2_FILE_OVERWRITE_IF                      0x00000005

/* RTSMB2_CREATE_C::CreateOptions */
#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_WRITE_THROUGH 0x00000002
#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_COMPLETE_IF_OPLOCKED 0x00000100
#define FILE_NO_EA_KNOWLEDGE 0x00000200
#define FILE_RANDOM_ACCESS 0x00000800
#define FILE_DELETE_ON_CLOSE 0x00001000
#define FILE_OPEN_BY_FILE_ID 0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_NO_COMPRESSION 0x00008000
#define FILE_OPEN_REMOTE_INSTANCE 0x00000400
#define FILE_OPEN_REQUIRING_OPLOCK 0x00010000
#define FILE_DISALLOW_EXCLUSIVE 0x00020000
#define FILE_RESERVE_OPFILTER 0x00100000
#define FILE_OPEN_REPARSE_POINT 0x00200000
#define FILE_OPEN_NO_RECALL 0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000

/* Note sections 2.2.13.2 contains several create contexts taht extend create
    Create contexts are defined in another file
*/

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CREATE_C
{
    word  StructureSize; // 57
	byte  SecurityFlags;
	byte  RequestedOplockLevel;
	dword ImpersonationLevel;
	byte  SmbCreateFlags[8];
	byte  Reserved[8];
	dword DesiredAccess;
	dword FileAttributes;
	dword ShareAccess;
	dword CreateDisposition;
	dword CreateOptions;
    word  NameOffset;
    word  NameLength;
	dword CreateContextsOffset;
	dword CreateContextsLength;
    byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_CREATE_C;
PACK_PRAGMA_POP
typedef RTSMB2_CREATE_C RTSMB_FAR *PRTSMB2_CREATE_C;

/* Note sections 2.2.14.2 contains several create contexts that extend create response
    Create contexts are defined in another file
*/
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CREATE_R
{
    word  StructureSize; // 89
	byte  OplockLevel;
	byte  Flags;
	dword CreateAction;
	FILETIME_T CreationTime;
	FILETIME_T LastAccessTime;
	FILETIME_T LastWriteTime;
	FILETIME_T ChangeTime;
	ddword AllocationSize;
	ddword EndofFile;
	dword  FileAttributes;
	dword  Reserved2;
    byte   FileId[16];
	dword CreateContextsOffset;
	dword CreateContextsLength;
    byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_CREATE_R;
PACK_PRAGMA_POP
typedef RTSMB2_CREATE_R RTSMB_FAR *PRTSMB2_CREATE_R;

#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB 0x0001
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CLOSE_C
{
    word  StructureSize; // 24
	word  Flags;
	dword Reserved;
	byte  FileId[16];
} PACK_ATTRIBUTE RTSMB2_CLOSE_C;
PACK_PRAGMA_POP
typedef RTSMB2_CLOSE_C RTSMB_FAR *PRTSMB2_CLOSE_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CLOSE_R
{
    word  StructureSize; // 60
	word  Flags;
	dword Reserved;
	FILETIME_T CreationTime;
	FILETIME_T LastAccessTime;
	FILETIME_T LastWriteTime;
	FILETIME_T ChangeTime;
	ddword AllocationSize;
	ddword EndofFile;
	dword  FileAttributes;
} PACK_ATTRIBUTE RTSMB2_CLOSE_R;
PACK_PRAGMA_POP
typedef RTSMB2_CLOSE_R RTSMB_FAR *PRTSMB2_CLOSE_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_FLUSH_C
{
    word  StructureSize; // 24
	word  Reserved1;
	dword Reserved2;
	byte  FileId[16];
} PACK_ATTRIBUTE RTSMB2_FLUSH_C;
PACK_PRAGMA_POP
typedef RTSMB2_FLUSH_C RTSMB_FAR *PRTSMB2_FLUSH_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_FLUSH_R
{
    word  StructureSize; // 4
	word  Reserved;
} PACK_ATTRIBUTE RTSMB2_FLUSH_R;
PACK_PRAGMA_POP
typedef RTSMB2_FLUSH_R RTSMB_FAR *PRTSMB2_FLUSH_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_READ_C
{
    word    StructureSize; // 49
	byte    Padding;
	byte    Flags;
	dword   Length;
	ddword  Offset;
	byte    FileId[16];
	dword   MinimumCount;
	dword   Channel;
	dword   RemainingBytes;
	word    ReadChannelInfoOffset;
	word    ReadChannelInfoLength;
	byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_READ_C;
PACK_PRAGMA_POP
typedef RTSMB2_READ_C RTSMB_FAR *PRTSMB2_READ_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_READ_R
{
    word  StructureSize; // 17
	byte  DataOffset;
	byte  Reserved;
	dword DataLength;
	dword DataRemaining;
	dword Reserved2;
	byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_READ_R;
PACK_PRAGMA_POP
typedef RTSMB2_READ_R RTSMB_FAR *PRTSMB2_READ_R;

#define SMB2_WRITEFLAG_WRITE_THROUGH 0x00000001
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED 0x00000002

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_WRITE_C
{
    word    StructureSize; // 49
	dword   DataOffset;
	dword   Length;
	ddword  Offset;
	byte    FileId[16];
	dword   Channel;
	dword   RemainingBytes;
	word    WriteChannelInfoOffset;
	word    WriteChannelInfoLength;
	dword   Flags;
	byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_WRITE_C;
PACK_PRAGMA_POP
typedef RTSMB2_WRITE_C RTSMB_FAR *PRTSMB2_WRITE_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_WRITE_R
{
    word  StructureSize; // 17
	word  Reserved;
	dword Count;
	dword Remaining;
	word  WriteChannelInfoOffset;
	word  WriteChannelInfoLength;
} PACK_ATTRIBUTE RTSMB2_WRITE_R;
PACK_PRAGMA_POP
typedef RTSMB2_WRITE_R RTSMB_FAR *PRTSMB2_WRITE_R;

/* Server -> Client */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_OPLOCK_BREAK_C
{
    word    StructureSize; // 24
	byte    OplockLevel;
	byte    Reserved;
	dword   Reserved2;
	byte    FileId[16];
} PACK_ATTRIBUTE RTSMB2_OPLOCK_BREAK_C;
PACK_PRAGMA_POP
typedef RTSMB2_OPLOCK_BREAK_C RTSMB_FAR *PRTSMB2_OPLOCK_BREAK_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_OPLOCK_BREAK_R
{
    word    StructureSize; // 24
	byte    OplockLevel;
	byte    Reserved;
	dword   Reserved2;
	byte    FileId[16];
} PACK_ATTRIBUTE RTSMB2_OPLOCK_BREAK_R;  /* Acnowledgement */
PACK_PRAGMA_POP
typedef RTSMB2_OPLOCK_BREAK_R RTSMB_FAR *PRTSMB2_OPLOCK_BREAK_R;


#define SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED 0x01

#define SMB2_LEASE_READ_CACHING 0x01
#define SMB2_LEASE_HANDLE_CACHING 0x02
#define SMB2_LEASE_WRITE_CACHING 0x04

/* Server -> Client */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LEASE_BREAK_C
{
    word    StructureSize; // 44
    word    NewEpoch;
	dword   Flags;
	byte    LeaseKey[16];
	dword   CurrentLeaseState;
	dword   NewLeaseState;
	dword   BreakReason;
	dword   AccessMaskHint;
	dword   ShareMaskHint;
} PACK_ATTRIBUTE RTSMB2_LEASE_BREAK_C;
PACK_PRAGMA_POP
typedef RTSMB2_LEASE_BREAK_C RTSMB_FAR *PRTSMB2_LEASE_BREAK_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LEASE_BREAK_R
{
    word    StructureSize; // 36
    word    Reserved;
	dword   Flags;
	byte    LeaseKey[16];
	dword   LeaseState;
	ddword  LeaseDuration;
} PACK_ATTRIBUTE RTSMB2_LEASE_BREAK_R;
PACK_PRAGMA_POP
typedef RTSMB2_LEASE_BREAK_R RTSMB_FAR *PRTSMB2_LEASE_BREAK_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LOCK_ELEMENT
{
	ddword   Offset;
	ddword   Length;
	dword    Flags;
	dword    Reserved;
} PACK_ATTRIBUTE RTSMB2_LOCK_ELEMENT;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LOCK_REQUEST_C
{
    word    StructureSize; // 48
	word    LockCount;
	dword   LockSequence;
	byte    FileId[16];
    RTSMB2_LOCK_ELEMENT Locks;
} PACK_ATTRIBUTE RTSMB2_LOCK_REQUEST_C;
PACK_PRAGMA_POP
typedef RTSMB2_LOCK_REQUEST_C RTSMB_FAR *PRTSMB2_LOCK_REQUEST_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LOCK_REQUEST_R
{
    word    StructureSize; // 4
	word    Reserved;
} PACK_ATTRIBUTE RTSMB2_LOCK_REQUEST_R;
PACK_PRAGMA_POP
typedef RTSMB2_LOCK_REQUEST_R RTSMB_FAR *PRTSMB2_LOCK_REQUEST_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_ECHO_C
{
    word    StructureSize; // 4
	word    Reserved;
} PACK_ATTRIBUTE RTSMB2_ECHO_C;
PACK_PRAGMA_POP
typedef RTSMB2_ECHO_C RTSMB_FAR *PRTSMB2_ECHO_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_ECHO_R
{
    word    StructureSize; // 4
	word    Reserved;
} PACK_ATTRIBUTE RTSMB2_ECHO_R;
PACK_PRAGMA_POP
typedef RTSMB2_ECHO_R RTSMB_FAR *PRTSMB2_ECHO_R;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CANCEL_C
{
    word    StructureSize; // 4
	word    Reserved;
} PACK_ATTRIBUTE RTSMB2_CANCEL_C;
PACK_PRAGMA_POP
typedef RTSMB2_CANCEL_C RTSMB_FAR *PRTSMB2_CANCEL_C;


/* Note: 2.2.31.1 contains formats for IOCTL requests */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_IOCTL_C
{
    word    StructureSize; // 57
	word    Reserved;
	dword   CtlCode;
	byte    FileId[16];
	dword   InputOffset;
	dword   InputCount;
	dword   MaxInputResponse;
	dword   OutputOffset;
	dword   OutputCount;
	dword   MaxOutputResponse;
	dword   Flags;
    dword   Reserved2;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_IOCTL_C;
PACK_PRAGMA_POP
typedef RTSMB2_IOCTL_C RTSMB_FAR *PRTSMB2_IOCTL_C;

/* Note: 2.2.32.1 contains formats for IOCTL replies */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_IOCTL_R
{
    word    StructureSize; // 49
	word    Reserved;
	dword   CtlCode;
	byte    FileId[16];
	dword   InputOffset;
	dword   InputCount;
	dword   OutputOffset;
	dword   OutputCount;
	dword   Flags;
    dword   Reserved2;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_IOCTL_R;
PACK_PRAGMA_POP
typedef RTSMB2_IOCTL_R RTSMB_FAR *PRTSMB2_IOCTL_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_QUERY_DIRECTORY_C
{
    word    StructureSize; // 33
	byte    FileInformationClass;
	byte    Flags;
	dword   FileIndex;
	byte    FileId[16];
	word    FileNameOffset;
	word    FileNameLength;
	dword   OutputBufferLength;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_QUERY_DIRECTORY_C;
PACK_PRAGMA_POP
typedef RTSMB2_QUERY_DIRECTORY_C RTSMB_FAR *PRTSMB2_QUERY_DIRECTORY_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_QUERY_DIRECTORY_R
{
    word    StructureSize; // 9
	word    OutputBufferOffset;
	dword   OutputBufferLength;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_QUERY_DIRECTORY_R;
PACK_PRAGMA_POP
typedef RTSMB2_QUERY_DIRECTORY_R RTSMB_FAR *PRTSMB2_QUERY_DIRECTORY_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CHANGE_NOTIFY_C
{
    word    StructureSize; // 33
	word    Flags;
	dword   OutputBufferLength;
	byte    FileId[16];
    dword   CompletionFilter;
    dword   Reserved;
} PACK_ATTRIBUTE RTSMB2_CHANGE_NOTIFY_C;
PACK_PRAGMA_POP
typedef RTSMB2_CHANGE_NOTIFY_C RTSMB_FAR *PRTSMB2_CHANGE_NOTIFY_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CHANGE_NOTIFY_R
{
    word    StructureSize; // 9
	word    OutputBufferOffset;
	dword   OutputBufferLength;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_CHANGE_NOTIFY_R;
PACK_PRAGMA_POP
typedef RTSMB2_CHANGE_NOTIFY_R RTSMB_FAR *PRTSMB2_CHANGE_NOTIFY_R;

/* Section 2.2.37.1 contains info request decriptions */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_QUERY_INFO_C
{
    word    StructureSize; // 41
	byte    InfoType;
	byte    FileInfoClass;
	dword   OutputBufferLength;
	word    InputBufferOffset;
	word    Reserved;
	dword   InputBufferLength;
	dword   AdditionalInformation;
	dword   Flags;
	byte    FileId[16];
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_QUERY_INFO_C;
PACK_PRAGMA_POP
typedef RTSMB2_QUERY_INFO_C RTSMB_FAR *PRTSMB2_QUERY_INFO_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_QUERY_INFO_R
{
    word    StructureSize; // 9
	word    OutputBufferOffset;
	dword   OutputBufferLength;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_QUERY_INFO_R;
PACK_PRAGMA_POP
typedef RTSMB2_QUERY_INFO_R RTSMB_FAR *PRTSMB2_QUERY_INFO_R;

/* Section 2.2.39.1 contains set info request decriptions */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_SET_INFO_C
{
    word    StructureSize; // 33
	byte    InfoType;
	byte    FileInfoClass;
	dword   BufferLength;
	word    BufferOffset;
	word    Reserved;
	dword   AdditionalInformation;
	byte    FileId[16];
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_SET_INFO_C;
PACK_PRAGMA_POP
typedef RTSMB2_SET_INFO_C RTSMB_FAR *PRTSMB2_SET_INFO_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_SET_INFO_R
{
    word    StructureSize; // 2
} PACK_ATTRIBUTE RTSMB2_SET_INFO_R;
PACK_PRAGMA_POP
typedef RTSMB2_SET_INFO_R RTSMB_FAR *PRTSMB2_SET_INFO_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_TRANSFORM_HEADER
{
	byte    ProtocolId[4];
	byte    Signature[16];
	byte    Nonce[16];
    dword   OriginalMessageSize;
    word    Reserved;
    word    EncryptionAlgorithm;
	ddword  SessionId;
} PACK_ATTRIBUTE RTSMB2_TRANSFORM_HEADER;
PACK_PRAGMA_POP
typedef RTSMB2_TRANSFORM_HEADER RTSMB_FAR *PRTSMB2_TRANSFORM_HEADER;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_ERROR_R
{
    word    StructureSize; // 9
	word    Reserved;
	dword   ByteCount;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_ERROR_R;
PACK_PRAGMA_POP
typedef RTSMB2_ERROR_R RTSMB_FAR *PRTSMB2_ERROR_R;


//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================
//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================
//****************************************************************************
//**
//**    END HEADER smb2.h
//**
//****************************************************************************
#endif // SMB2_WIREDEFS_H__
