#ifndef __SMB2_SRV_MODEL__
#define __SMB2_SRV_MODEL__
//****************************************************************************
//**
//**    SRVSSN_SMB2.H
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================



#if (INCLUDE_RTSMB_SERVER)

#include "srvshare.h"

//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================

/* Configs, none well thought out yet */
#define RTSMB2_CFG_MAX_SESSIONS                         1
#define RTSMB2_CFG_MAX_CONNECTIONS                      1
#define RTSMB2_CFG_MAX_LOCK_SEQUENCES                 128
#define RTSMB2_CFG_MAX_SHARES                          32
#define RTSMB2_CFG_MAX_OPENS                           32
#define RTSMB2_CFG_COPY_MAX_CHUNKS                      1
#define RTSMB2_CFG_COPY_MAX_CHUNK_SIZE               1024
#define RTSMB2_CFG_COPY_MAX_DATA_SIZE                1024
#define RTSMB2_CFG_SERVER_HASH_LEVEL                    0
#define RTSMB2_CFG_MAX_RESILIENCY_TIMEOUT           32000
#define RTSMB2_CFG_ENCRYPT_DATA                     FALSE
#define RTSMB2_CFG_REJECT_UNENCRYPTED_ACCESS        FALSE
#define RTSMB2_CFG_REQUIRE_MESSAGE_SIGNING          FALSE
#define RTSMB2_CFG_MULTI_CHANNEL_CAPABLE            FALSE
#define RTSMB2_CFG_LEASE_CAPABLE                    FALSE
#define RTSMB2_CFG_PERSISTENT_HANDLE_CAPABLE        FALSE
#define RTSMB2_CFG_LEASE_DIRECTORIES_CAPABLE        FALSE
#define RTSMB2_CFG_ENCRYPTION_CAPABLE               FALSE

#define RTSMB2_CFG_MAX_CHANNELS_PER_SESSION         4

/* share name | ipv4 address | ip v6 address */
#define RTSMB2_MAX_QUALIFIED_SHARENAME_SIZE    66 // ??
#define RTSMB2_MAX_COMMENT_SIZE                42 // ??
/* Client name or IP4/IPV6 string address string */
#define RTSMB2_MAX_QUALIFIED_CLIENTNAME_SIZE   66 // ??

/* Transport name and bit flags stored in connect Connect.TransportName */
#define RTSMB2_TRANSPORT_SMB_OVER_NBSS 1
#define RTSMB2_TRANSPORT_SMB_OVER_TCP  2
#define RTSMB2_TRANSPORT_SMB_OVER_RDMA 4


//============================================================================
//    INTERFACE STRUCTURES / UTILITY CLASSES
//============================================================================

#define pSmb2SrvModel_Global struct s_Smb2SrvModel_Global RTSMB_FAR *
#define pSmb2SrvModel_Share struct s_Smb2SrvModel_Share RTSMB_FAR *
#define pSmb2SrvModel_Connection struct s_Smb2SrvModel_Connection RTSMB_FAR *
#define pSmb2SrvModel_Session struct s_Smb2SrvModel_Session RTSMB_FAR *
#define pSmb2SrvModel_TreeConnect struct s_Smb2SrvModel_TreeConnect RTSMB_FAR *
#define pSmb2SrvModel_Open struct s_Smb2SrvModel_Open RTSMB_FAR *
#define pSmb2SrvModel_LeaseTable struct s_Smb2SrvModel_LeaseTable RTSMB_FAR *
#define pSmb2SrvModel_Channel struct s_Smb2SrvModel_Channel RTSMB_FAR *
#define pSmb2SrvModel_Request struct s_Smb2SrvModel_Request RTSMB_FAR *
#define pSmb2SrvModel_Lease struct s_Smb2SrvModel_Lease RTSMB_FAR *

struct smb2_dialect_entry_s {word dialect;	PFRTCHAR name;	int priority;};

/* MS-SRVS 2.2.4.39 .................................................................. 56*/
typedef struct _STAT_SERVER_0 {
    dword sts0_start;
    dword sts0_fopens;
    dword sts0_devopens;
    dword sts0_jobsqueued;
    dword sts0_sopens;
    dword sts0_stimedout;
    dword sts0_serrorout;
    dword sts0_pwerrors;
    dword sts0_permerrors;
    dword sts0_syserrors;
    dword sts0_bytessent_low;
    dword sts0_bytessent_high;
    dword sts0_bytesrcvd_low;
    dword sts0_bytesrcvd_high;
    dword sts0_avresponse;
    dword sts0_reqbufneed;
    dword sts0_bigbufneed;
} STAT_SERVER_0;

/* 3.3.1.5 Global .................................................................................................... 223 */
typedef struct s_Smb2SrvModel_Global {
    ddword     RTSMBNetSessionId;           /*  Session ID, increased by one every time a session is created */
    BBOOL RequireMessageSigning;            /*  A Boolean that, if set, indicates that this node requires that messages MUST be signed if the message is sent
                                                with a user security context that is neither anonymous nor guest. If not set, this node does not require that
                                                any messages be signed, but can still choose to do so if the other node requires it. */
    STAT_SERVER_0 ServerStatistics;         /*  Server statistical information. This contains all the members of STAT_SRV_0 structure as specified
                                                in [MS-SRVS] section 2.2.4.39. */
    BBOOL ServerEnabled;                    /*  Indicates whether the SMB2 server is accepting incoming connections or requests. */
        /*  A list of available shares for the system. The structure of a share is as specified in
            section 3.3.1.6 and is uniquely indexed by the tuple <Share.ServerName, Share.Name>. */
    pSmb2SrvModel_Share ShareList[RTSMB2_CFG_MAX_SHARES];
        /*  A table containing all the files opened by remote clients on the server, indexed by Open.DurableFileId. The structure of
            an open is as specified in section 3.3.1.10. The table MUST support enumeration of all entries in the table. */
    pSmb2SrvModel_Open OpenTable[RTSMB2_CFG_MAX_OPENS];
        /*  A list of all the active sessions established to this server, indexed by the Session.SessionId. */
    pSmb2SrvModel_Session  SessionTable[RTSMB2_CFG_MAX_SESSIONS];
        /*  A list of all open connections on the server, indexed by the connection endpoint addresses. */
    pSmb2SrvModel_Connection ConnectionList[RTSMB2_CFG_MAX_CONNECTIONS];
    /* Examle uuid value {f81d4fae-7dec-11d0-a765-00a0c91e6bf6} - RFC4122*/
    byte ServerGuid[16];                    /*  A global identifier for this server. [MS-DTYP] section 2.3.4 */
    FILETIME_T ServerStartTime;             /*  The start time of the SMB2 server, in FILETIME format as specified in [MS-DTYP] section 2.3.3. */
    BBOOL IsDfsCapable;                     /*  Indicates that the server supports the Distributed File System. */
    BBOOL RTSMBIsLeaseCapable;              /*  Indicates that the server supports leasing. */
    BBOOL RTSMBIsPersistentHandlesCapable;  /*  Indicates that the server supports persistent handles. */
    BBOOL RTSMBIsLeaseDirectoriesCapable;   /*  Indicates that the server supports leasing directories. */
    BBOOL RTSMBIsEncryptionCapable;         /*  Indicates that the server supports encryption. */

    dword ServerSideCopyMaxNumberofChunks;  /*  The maximum number of chunks the server will accept in a server side copy operation. */
    dword ServerSideCopyMaxChunkSize;       /*  The maximum number of bytes the server will accept in a single chunk for a server side copy operation. */
    dword ServerSideCopyMaxDataSize;        /*  The maximum total number of bytes the server will accept for a server side copy operation. */
    /* If the server implements the SMB 2.1 or SMB 3.x dialect family, it MUST implement the following; */
#define HashEnableAll   1       /*  Indicates that caching is enabled for all shares on the server. */
#define HashDisableAll  2       /*  Indicates that caching is disabled for all shares on the server. */
#define HashEnableShare 3       /*  Indicates that caching is enabled or disabled on a per-share basis */
    byte ServerHashLevel;       /*  A state that indicates the caching level configured on the server. It takes any of the following three values: */
    pSmb2SrvModel_LeaseTable GlobalLeaseTableList[RTSMB2_CFG_MAX_CONNECTIONS]; /*  A list of all the lease tables as described in 3.3.1.11, indexed by the ClientGuid. */
    dword MaxResiliencyTimeout;             /*  The maximum resiliency time-out in milliseconds, for the TimeOut field of NETWORK_RESILIENCY_REQUEST Request as specified in section 2.2.31.3. */
    ddword ResilientOpenScavengerExpiryTime;/*  The time at which the Resilient Open Scavenger Timer, as specified in section 3.3.2.4, is currently set to expire. */
    /* If the server implements the SMB 3.x dialect family, it MUST implement the following; */
    byte  **EncryptionAlgorithmList;        /*  A list of strings containing the encryption algorithms supported by the server. */
    BBOOL EncryptData;                      /*  Indicates that the server requires messages to be encrypted after session establishment, per the conditions specified in section 3.3.5.2.9. */
    BBOOL RejectUnencryptedAccess;          /*  Indicates that the server will reject any unencrypted messages. This flag is applicable only if EncryptData is TRUE or if Share.EncryptData (as defined in section 3.3.1.6) is TRUE. */
    BBOOL IsMultiChannelCapable;            /*  Indicates that the server supports the multichannel capability. */
/* If the server implements the SMB 3.02 dialect, it MUST implement the following; */
    BBOOL IsSharedVHDSupported;             /*  Indicates that the server supports shared virtual disks. */
} Smb2SrvModel_Global;


/* 3.3.1.6 Per Share ............................................................................................... 224 */


typedef struct s_Smb2SrvModel_Share
{
            /* A name for the shared resource on this server. */
    rtsmb_char Name[RTSMB_MAX_SHARENAME_SIZE + 1];
           /* The NetBIOS, fully qualified domain name (FQDN), or textual IPv4 or IPv6 address that the share is associated with.
              For more information, see [MS-SRVS] section 3.1.1.7. */
    rtsmb_char ServerName[RTSMB2_MAX_QUALIFIED_SHARENAME_SIZE];
    /* A path that describes the local resource that is being shared. This MUST be a store that either provides
      named pipe functionality, or that offers storage and/or retrieval of files. In the case of the latter,
      it MAYbe a device that accepts a file and then processes it in some format, such as a printer. */
    TYPELESS LocalPath;
    TYPELESS ConnectSecurity;             /* An authorization policy such as an access control list that describes which users are allowed to connect to this share. */
    TYPELESS FileSecurity;                /* An authorization policy such as an access control list that describes what actions users that connect to this share are allowed to perform on the shared resource.<165> */

    /* The configured offline caching policy for this share. This value MUST be manual caching, automatic caching of files,
       automatic caching of files and programs, or no offline caching. For more information, see section 2.2.10.
       For more information about offline caching, see [OFFLINE]. */
#define manual_caching                              1
#define automatic_caching_of_files                  2
#define automatic_caching_of_files_and_programs     3
#define no_offline_caching                          0
    byte CscFlags;
    BBOOL IsDfs;                         /* If set, indicates that this share is configured for DFS. */
        /* If set, indicates that the results of directory enumerations on this share MUST be trimmed to include only the
           files and directories that the calling  user has the right to access. */
    BBOOL DoAccessBasedDirectoryEnumeration;
    BBOOL AllowNamespaceCaching;         /* Indicates that clients are allowed to cache directory enumeration results
                                            for better performance.<166> */
    BBOOL ForceSharedDelete;             /* Indicates that all opens on this share MUST include FILE_SHARE_DELETE in
                                            the sharing access. */
    BBOOL RestrictExclusiveOpens;        /* Indicates that users who request read-only access to a file are not allowed
                                            to deny other readers. */
    SHARE_T Type;                        /* The value indicates the type of share. It MUST be one of the values that
                                            are listed in [MS-SRVS] section 2.2.2.4. */
    rtsmb_char  Remark[RTSMB2_MAX_COMMENT_SIZE]; /* A pointer to a null-terminated Unicode UTF-16 string that specifies an optional
                                             comment about the shared resource. */
    int   MaxUses;                       /* Indicates the maximum number of concurrent connections that the shared
                                            resource can accommodate. */
    int   CurrentUses;                   /* Indicates the number of current trees connected to the shared resource. */
    BBOOL ForceLevel2Oplock;             /* Indicates that the server does not issue exclusive caching rights on this share. */
    BBOOL HashEnabled;                  /* A Boolean that, if set, indicates that the share supports hash generation for branch cache retrieval of data. */
            /* If the server implements the SMB 3.x dialect family, it MUST implement the following: */
    dword CATimeout;                     /* The minimum time, in milliseconds, before closing an unreclaimed persistent
                                            handle on a continuously available share. */
    BBOOL IsCA;                          /* Indicates that the share is continuously available. */
    BBOOL EncryptData;                   /* Indicates that the server requires messages for accessing this share to be encrypted,
                                            per the conditions specified in section 3.3.5.2.11. */
} Smb2SrvModel_Share;


/* 3.3.1.7 Per Transport Connection ......................................................................... 225 */
typedef struct s_Smb2SrvModel_Connection
{
    ddword CommandSequenceWindow[2];    /*  A list of the sequence numbers that is valid to receive from the client at this time.
                                            For more information, see section 3.3.1.1. */
    pSmb2SrvModel_Request RequestList;     /*  A list of requests, as specified in section 3.3.1.13, that are currently
                                            being processed by the server. This list is indexed by the MessageId field. */
    dword   ClientCapabilities;        /*  The capabilities of the client of this connection in a form that MUST
                                             follow the syntax as specified in section 2.2.3. */
    word    NegotiateDialect;          /*  A numeric value representing the current state of dialect negotiation
                                            between the client and server on this transport connection. */
    word Dialect;                      /*    The dialect of SMB2 negotiated with the client. This value MUST be either
                                            "2002", "2.100", "3.000", "3.002" or "Unknown". For the purpose of
                                            These are defined symbolically in SMB2_DIALECT_2002 et al in smb2_wiredefs.h
                                            generalization in the server processing rules, the condition that
                                            Connection.Dialect is equal to "3.000" or "3.002" is referred to as
                                            Connection.Dialect belongs to the SMB 3.x dialect family¡¨. */
    pSmb2SrvModel_Request AsyncCommandList;/*  A list of client requests being handled asynchronously. Each request MUST
                                            have been assigned an AsyncId. */
    BBOOL ShouldSign;                   /*  Indicates that all sessions on this connection (with the exception of
                                            anonymous and guest sessions) MUST have signing enabled. */
                            /*  A null-terminated Unicode UTF-16 IP address string, or NetBIOS host name of the client machine. */
    byte ClientName[RTSMB2_MAX_QUALIFIED_CLIENTNAME_SIZE];
    dword MaxTransactSize;              /*  The maximum buffer size, in bytes, that the server allows on the transport
                                            that established this connection for QUERY_INFO, QUERY_DIRECTORY, SET_INFO
                                            and CHANGE_NOTIFY operations. This field is applicable only for buffers sent
                                            by the client in SET_INFO requests, or returned from the server in QUERY_INFO,
                                            QUERY_DIRECTORY, and CHANGE_NOTIFY responses. */
    dword MaxWriteSize;                 /*  The maximum buffer size, in bytes, that the server allows to be written on
                                            the connection using the SMB2 WRITE Request. */
    dword MaxReadSize;                  /*  The maximum buffer size, in bytes, that the server allows to be read on the
                                            connection using the SMB2 READ Request. */

    BBOOL SupportsMultiCredit;          /*  Indicates whether the connection supports multi-credit operations. */

    byte TransportName;                   /*  An implementation-specific name of the transport used by this connection. */
                                        /*  A table of authenticated sessions, as specified in section 3.3.1.8,
                                            established on this SMB2 transport connection. The table MUST allow lookup
                                            by both Session.SessionId and by the security context of the user that
                                            established the connection. */
    pSmb2SrvModel_Session SessionTable[RTSMB2_CFG_MAX_SESSIONS];
    FILETIME_T CreationTime;            /*  The time when the connection was established. */
       /* If the server implements the SMB 2.1 or 3.x dialect family, it MUST implement the following;  */
    byte ClientGuid[16];                /*  An identifier for the client machine. */
       /* If the server implements the SMB 3.x dialect family, it MUST implement the following;  */
    dword ServerCapabilities;           /*  The capabilities sent by the server in the SMB2 NEGOTIATE Response on this
                                            connection, in a form that MUST follow the syntax as specified in section 2.2.4. */
    word ClientSecurityMode;            /*  The security mode sent by the client in the SMB2 NEGOTIATE request on this
                                            connection, in a form that MUST follow the syntax as specified in section 2.2.3. */
    word ServerSecurityMode;            /*  The security mode received from the server in the SMB2 NEGOTIATE response
                                            on this connection, in a form that MUST follow the syntax as specified in
                                            section 2.2.4. */
} Smb2SrvModel_Connection;

/* 3.3.1.8 Per Session ............................................................................................. 226 */
typedef struct s_Smb2SrvModel_Session
{
    ddword  SessionId;                  /* A numeric value that is used as an index in GlobalSessionTable, and (transformed into a 64-bit number)
                                           is sent to clients as the SessionId in the SMB2 header. */
    BBOOL   RTSMBisAllocated;
    struct smb_sessionCtx_s *pSmbCtx;   /* Temporary - Point back to the SMB1 session that links to this session */


#define Smb2SrvModel_Session_State_InProgress  1
#define Smb2SrvModel_Session_State_Valid       2
#define Smb2SrvModel_Session_State_Expired     3
        /* The current activity state of this session. This value MUST be either InProgress, Valid, or Expired. */
    byte     State;
    TYPELESS SecurityContext;           /* The security context of the user that authenticated this session. This value MUST be in
                                           a form that allows for evaluating security descriptors within the server, as well as
                                           being passed to the underlying object store to handle security evaluation that may
                                           happen there. */
    BBOOL IsAnonymous;                  /* Indicates that the session is for an anonymous user. */
    BBOOL IsGuest;                      /* Indicates that the session is for a guest user. */
    byte SessionKey[16];                /* The first 16 bytes of the cryptographic key for this authenticated context. If the cryptographic key is less than
                                           16 bytes, it is right-padded with zero bytes. */
    BBOOL SigningRequired;              /* Indicates that all of the messages for this session MUST be signed. */
    pSmb2SrvModel_Open OpenTable;          /* A table of opens of files or named pipes, as specified in section 3.3.1.10, that have been opened by this
                                           authenticated session and indexed by Open.FileId. The server MUST support enumeration of all entries in the table. */
    pSmb2SrvModel_TreeConnect TreeConnectTable; /* A table of tree connects that have been established by this authenticated session to
                                                shares on this server, indexed by TreeConnect.TreeId. The server MUST allow enumeration of all entries in the table. */
    ddword   ExpirationTime;            /* A value that specifies the time after which the client must reauthenticate with the server.*/
    pSmb2SrvModel_Connection Connection;   /* The connection on which this session was established (see also section 3.3.5.5.1). */
    dword    SessionGlobalId;           /* A numeric 32-bit value obtained via registration with [MS-SRVS], as specified in [MS-SRVS] section 3.1.6.2. */
    FILETIME_T CreationTime;            /* The time the session was established. */
    ddword   IdleTime;                  /* The time the session processed its most recent request. */
    byte    *UserName;                  /* The name of the user who established the session. */
        /* If the server implements the SMB 3.x dialect family, it MUST implement the following  */
    pSmb2SrvModel_Channel ChannelList[RTSMB2_CFG_MAX_CHANNELS_PER_SESSION];/* A list of channels that have been established on this authenticated session, as specified in section 3.3.1.14. */
    BBOOL EncryptData;                  /* Indicates that the messages on this session SHOULD be encrypted. */
    byte EncryptionKey[16];             /* A 128-bit key used for encrypting the messages sent by the server. */
    byte DecryptionKey[16];             /* A 128-bit key used for decrypting the messages received from the client. */
    byte SigningKey[16];                /* A 128 bit key used for signing the SMB2 messages. */
    byte ApplicationKey[16];            /* A 128-bit key, for the authenticated context, that is queried by the higher-layer applications. */
} Smb2SrvModel_Session;



/* 3.3.1.9 Per Tree Connect ..................................................................................... 228 */
typedef struct s_Smb2SrvModel_TreeConnect
{
    dword    TreeId;                    /* A numeric value that uniquely identifies a tree connect within the scope of
                                           the session over which it was established. This value is represented as a 32-bit TreeId in the SMB2 header. */
    pSmb2SrvModel_Session Session;         /* A pointer to the authenticated session that established this tree connect. */
    pSmb2SrvModel_Share Share;             /* A pointer to the share that this tree connect was established for. */
    int OpenCount;                      /* A numeric value that indicates the number of files that are currently opened on TreeConnect. */
    TYPELESS TreeGlobalId;              /* A numeric value obtained via registration with [MS-SRVS], as specified in [MS-SRVS] section 3.1.6.6. */
    FILETIME_T CreationTime;            /* The time tree connect was established. */
} Smb2SrvModel_TreeConnect;


/* 3.3.1.10 Per Open .............................................................................................. 228 */
typedef struct s_Smb2SrvModel_Open
{
    ddword   FileId;                   /* A numeric value that uniquely identifies the open handle to a file or a pipe within the scope
                                          of a session over which the handle was opened. This value is the volatile portion of the
                                          identifier. A 64-bit representation of this value, combined with Open.DurableFileId as
                                          described below, combine to form the SMB2_FILEID described in section 2.2.14.1. */
    TYPELESS FileGlobalId;             /* A numeric value obtained via registration with [MS-SRVS], as specified in [MS-SRVS] section 3.1.6.4. */
    dword    DurableFileId;            /* A numeric value that uniquely identifies the open handle to a file or a pipe within the scope
                                          of all opens granted by the server, as described by the GlobalOpenTable. A 64-bit representation
                                          of this value combined with Open.FileId, as described above,
                                          form the SMB2_FILEID described in section 2.2.14.1. This value is the persistent portion of the identifier. */
    pSmb2SrvModel_Session Session;         /* A reference to the authenticated session, as specified in section 3.3.1.8, over which this open was
                                          performed. If the open is not attached to a session at this time, this value MUST be NULL. */
    pSmb2SrvModel_TreeConnect TreeConnect; /* A reference to the TreeConnect, as specified in section 3.3.1.9, over which the open was performed.
                                          If the open is not attached to a TreeConnect at this time, this value MUST be NULL. */
    pSmb2SrvModel_Connection Connection;   /* A reference to the connection, as specified in section 3.3.1.7, that created this open.
                                          If the open is not attached to a connection at this time, this value MUST be NULL. */
    TYPELESS LocalOpen;                /* An open of a file or named pipe in the underlying local resource that is used to perform the local operations,
                                          such as reading or writing, to the underlying object. For named pipes, Open.LocalOpen is shared between
                                          the SMB server and RPC server applications which serve RPC requests on a given named pipe.
                                          The higher level interfaces described in sections 3.3.4.5 and 3.3.4.11 require this shared element. */
    TYPELESS GrantedAccess;            /* The access granted on this open, as defined in section 2.2.13.1. */
    byte     OplockLevel;              /* The current oplock level for this open. This value MUST be one of the OplockLevel values
                                          defined in section 2.2.14 SMB2_OPLOCK_LEVEL_NONE, SMB2_OPLOCK_LEVEL_II,
                                          SMB2_OPLOCK_LEVEL_EXCLUSIVE, SMB2_OPLOCK_LEVEL_BATCH, or OPLOCK_LEVEL_LEASE. */
#define Smb2SrvModel_Open_OplockState_None     0
#define Smb2SrvModel_Open_OplockState_Held     1
#define Smb2SrvModel_Open_OplockState_Breaking 2
         /* The current oplock state of the file. This value MUST be Held, Breaking, or None. */
    TYPELESS OplockState;
    ddword   OplockTimeout;            /* The time value that indicates when an oplock that is breaking and has not received an
                                          acknowledgment from the client will be acknowledged by the server. */
    BBOOL   IsDurable;                 /* A Boolean that indicates whether this open has requested durable operation. */
    ddword  DurableOpenTimeout;        /* A time value that indicates when a handle that has been preserved for durability will be closed by the
                                          system if a client has not reclaimed it. */
    TYPELESS DurableOwner;             /* A security descriptor that holds the original opener of the open. This allows the server to determine
                                          if a caller that is trying to reestablish a durable open is allowed to do so.
                                          If the server implements SMB 2.1 or SMB 3.x and supports resiliency, this value is also used to enforce
                                          security during resilient open reestablishment. */
    TYPELESS EnumerationLocation;      /* For directories, this value indicates the current location in a directory enumeration and allows for
                                          the continuing of an enumeration across multiple requests. For files, this value is unused. */
    TYPELESS EnumerationSearchPattern; /* For directories, this value holds the search pattern that is used in directory enumeration and allows
                                          for the continuing of an enumeration across multiple requests. For files, this value is unused. */
    int CurrentEaIndex;                /* For extended attribute information, this value indicates the current location in an extended attribute
                                          information list and allows for the continuing of an enumeration across multiple requests. */
    int CurrentQuotaIndex;             /* For quota queries, this value indicates the current index in the quota information list and allows for
                                          the continuation of an enumeration across multiple requests. */
    int      LockCount;                /* A numeric value that indicates the number of locks that are held by current open. */
    TYPELESS PathName;                 /* A variable-length Unicode string that contains the local path name on the server that the open is performed on. */
    byte     ResumeKey[24];            /* A 24-byte key that identifies a source file in a server-side data copy operation. */
        /* If the server implements the SMB 2.1 or SMB 3.x dialect family and supports leasing, it MUST implement the following */
    byte     ClientGuid[16];           /* An identifier for the client machine that created this open. */
    pSmb2SrvModel_Lease Lease;            /* The lease associated with this open, as defined in 3.3.1.12. This value MUST point to a valid lease, or be set to NULL. */
    BBOOL    IsResilient;              /* A Boolean that indicates whether this open has requested resilient operation. */
    ddword   ResiliencyTimeout;        /* A time-out value that indicates how long the server will hold the file open after a disconnect
                                          before releasing the open. */
    ddword   ResilientOpenTimeout;     /* A time value that indicates when a handle that has been preserved for resiliency will be closed by the
                                          system if a client has not reclaimed it. */
        /* An array of lock sequence entries (each of size 1 byte) that have been successfully processed
           by the server for resilient opens. The size of this array is implementation-dependent.<167> */
    TYPELESS LockSequenceArray[RTSMB2_CFG_MAX_LOCK_SEQUENCES];
        /* If the server implements the SMB 3.x dialect family, it MUST implement the following */
    byte     CreateGuid[16];            /* A 16-byte value that associates this open to a create request. */
    byte     AppInstanceId[16];         /* A 16-byte value that associates this open with a calling application. */
    BBOOL    IsPersistent;              /* A Boolean that indicates whether this open is persistent. */
    byte     ChannelSequence[16];       /* A 16-bit identifier indicating the client's Channel change. */
    int      OutstandingRequestCount;   /* A numerical value that indicates the number of outstanding requests issued with ChannelSequence equal to Open.ChannelSequence. */
    int      OutstandingPreRequestCount;/* A numerical value that indicates the number of outstanding requests issued with ChannelSequence less than Open.ChannelSequence. */
    TYPELESS FileName;                  /* A variable length string that contains the Unicode file name supplied by the client for opening the file. */
    TYPELESS DesiredAccess;             /* The access mode requested by the client while opening the file, in the format specified in section 2.2.13.1. */
    TYPELESS ShareMode;                 /* The sharing mode requested by the client while opening the file, in the format specified in section 2.2.13. */
    TYPELESS CreateOptions;             /* The create options requested by the client while opening the file, in the format specified in section 2.2.13. */
    TYPELESS FileAttributes;            /* The file attributes used by the client for opening the fle, in the format specified in section 2.2.13. */
    TYPELESS CreateDisposition;         /* The create disposition requested by the client for opening the file, in the format specified in section 2.2.13. */
        /* If the server implements the SMB 3.02 dialect, it MUST implement the following */
    BBOOL   IsSharedVHDX;               /* A Boolean that indicates whether this open is a shared virtual disk operation. */
} Smb2SrvModel_Open;

/* 3.3.1.11 Per Lease Table ..................................................................................... 230 */
typedef struct s_Smb2SrvModel_LeaseTable
{
    /* If the server implements the SMB 2.1 or SMB 3.x dialect family and supports leasing, it implements the following */
    byte     ClientGuid[16];           /* A global identifier to associate which connections MUST use this LeaseTable. */
    pSmb2SrvModel_Lease LeaseList;         /* A list of lease structures, as defined in section 3.3.1.12, indexed by LeaseKey */
} Smb2SrvModel_LeaseTable;

/* 3.3.1.12 Per Lease .............................................................................................. 231 */
typedef struct s_Smb2SrvModel_Lease
{
    TYPELESS LeaseKey;                  /* A global identifier for this lease. */
    TYPELESS Filename;                  /* The name of the file backing this lease. */
    TYPELESS LeaseState;                /* The current state of the lease as indicated by the underlying object store. This value
                                           MUST be a combination of the flags described in section 2.2.13.2.8 for "LeaseState".
                                           For the remainder of section 3.3, these will be referred to as follows */
    TYPELESS BreakToLeaseState;         /* The state to which the lease is breaking. This value MUST be a combination of the flags
                                           described in section 2.2.13.2.8 for "LeaseState". For the remainder of section 3.3,
                                           these will be referred to as described in the table above. */
    TYPELESS LeaseBreakTimeout;         /* The time value that indicates when a lease that is breaking and has not received a Lease
                                           Break Acknowledgment from the client will be acknowledged by the server to the underlying
                                           object store. */
    TYPELESS LeaseOpens;                /* The list of opens associated with this lease. */
    BBOOL    Breaking;                  /* A Boolean that indicates if a lease break is in progress. */
        /* If the server implements the SMB 3.x dialect family and supports leasing, it implements the following */
    int      Epoch;                     /* A sequence number incremented by the server on every lease state change. */
    TYPELESS Version;                   /* A number indicating the lease version. */
} Smb2SrvModel_Lease;

/* 3.3.1.13 Per Request .......................................................................................... 231 */
typedef struct s_Smb2SrvModel_Request
{
    ddword   MessageId;                /* The value of the MessageId field from the SMB2 Header of the client request. */
    TYPELESS AsyncId;                  /* An asynchronous identifier generated for an Asynchronous Operation, as specified in section 3.3.4.2. The identifier
                                          MUST uniquely identify this Request among all requests currently being processed asynchronously on a specified SMB2 transport
                                          connection. If the request is not being processed asynchronously, this value MUST be set to zero. */
    TYPELESS CancelRequestId;          /* An implementation-dependent identifier generated by the server to support cancellation of pending requests
                                          that are sent to the object store. The identifier MUST be unique among all requests currently being processed
                                          by the server and all object store operations being performed by other server applications.<168> */
    TYPELESS Open;                     /* A reference to an Open of a file or named pipe, as specified in section 3.3.1.10.
                                          If the request is not associated with an Open at this time, this value MUST be NULL. */
        /* If the server implements the SMB 3.x dialect family, it MUST implement the following: */
    BBOOL   IsEncrypted;                 /* Indicates that the request has been encrypted. */
    ddword  TransformSessionId;      /* The SessionId sent by the client in the SMB2 TRANSFORM_HEADER, if the request is encrypted. */
} Smb2SrvModel_Request;

/* 3.3.1.14 Per Channel .......................................................................................... 232 */
typedef struct s_Smb2SrvModel_Channel
{
    /* If the server implements the SMB 3.x dialect family, the server implements the following: */
    byte SigningKey[16];               /* A 128-bit key used for signing the SMB2 messages on this channel. */
    pSmb2SrvModel_Connection Connection;  /* The connection on which this channel was established. */
} Smb2SrvModel_Channel;



//============================================================================
//    INTERFACE DATA DECLARATIONS
//============================================================================

//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================

void Smb2SrvModel_Global_Init(void);
pSmb2SrvModel_Session Smb2SrvModel_Global_Get_SessionById(ddword SessionId);
BBOOL Smb2SrvModel_Global_Set_SessionInSessionList(pSmb2SrvModel_Session pSession);
void Smb2SrvModel_Global_Remove_SessionFromSessionList(pSmb2SrvModel_Session pSession);
pSmb2SrvModel_Session Smb2SrvModel_Global_Get_SessionByConnectionAndId(pSmb2SrvModel_Connection Connection,ddword SessionId);
dword Smb2_util_get_global_caps(pSmb2SrvModel_Connection pConnection,PRTSMB2_NEGOTIATE_C pRequest);
BBOOL Smb2SrvModel_Connection_Set_SessionInSessionList(pSmb2SrvModel_Connection Connection, pSmb2SrvModel_Session pSession);
pSmb2SrvModel_Channel Smb2SrvModel_Session_Get_ChannelInChannelList(pSmb2SrvModel_Session pSession, pSmb2SrvModel_Connection Connection);
BBOOL Smb2SrvModel_Session_Set_ChannelInChannelList(pSmb2SrvModel_Session pSession, pSmb2SrvModel_Channel pChannel);
void Smb2SrvModel_Global_Stats_Send_Update(dword body_size);
void Smb2SrvModel_Global_Stats_Open_Update(int change);
void Smb2SrvModel_Global_Stats_Error_Update(void);
pSmb2SrvModel_Session Smb2SrvModel_New_Session(struct smb_sessionCtx_s *pSmbCtx);
void Smb2SrvModel_Free_Session(pSmb2SrvModel_Session pSession);
pSmb2SrvModel_Connection Smb2SrvModel_New_Connection(void);
pSmb2SrvModel_Channel Smb2SrvModel_New_Channel(pSmb2SrvModel_Connection Connection);



extern void Smb2SrvControl_Init(pSmb2SrvModel_Global pGlobal);

//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================


//****************************************************************************
//**
//**    END HEADER __SRV_SSN_SMB2.H
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* ___SMB2_SRV_MODEL___ */
