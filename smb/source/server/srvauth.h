#ifndef __SRV_AUTH_H__
#define __SRV_AUTH_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvssn.h"

/**
 * You must not register anyone with the name of
 * GUESTNAME.  Change this to something you know will not be used.
 */
#define SMB_GUESTNAME		"guest"
#define SMB_GUESTPASSWORD   "guest"

#define SECURITY_READ		0
#define SECURITY_WRITE		1
#define SECURITY_READWRITE	2
#define SECURITY_NONE		3
#define SECURITY_ANY		4

#define AUTH_GUEST			1
#define AUTH_NOACCESS		2

#define AUTH_USER_MODE		0
#define AUTH_SHARE_MODE		1

#define BITS_PER_TABLE_ENTRY	2 // must be a factor of 8 please


typedef struct access_table_s
{
	rtsmb_char name [CFG_RTSMB_MAX_GROUPNAME_SIZE + 1];
	byte *table;

} ACCESS_TABLE_T;
typedef ACCESS_TABLE_T RTSMB_FAR *PACCESS_TABLE;

typedef struct groups_s
{
	byte numGroups;
	
	ACCESS_TABLE_T *groups;
	
} GROUPS_T;
typedef GROUPS_T RTSMB_FAR *PGROUPS;

typedef struct user_data_s
{
	BBOOL inUse;
	rtsmb_char name[CFG_RTSMB_MAX_USERNAME_SIZE + 1];		// username
	PFCHAR password;
	char password_buf[CFG_RTSMB_MAX_PASSWORD_SIZE + 1];	// password for user
	BBOOL *groups; 	// whether this user is in each group
					// using a whole byte for each group is a little wasteful, 
					// but there shouldn't be many groups, and overhead for groups is large
					// This way we don't want to require a multiple of 4 number of groups

} USERDATA_T;
typedef USERDATA_T RTSMB_FAR *PUSERDATA;

typedef struct users_s
{
	USERDATA_T *users;
} USERLIST_T;


/**
 * Here are various functions to control access to the server.
 *
 * USERS
 *
 * If the smb server is in user-mode, each client machine will have to provide
 * a username and encrypted password pair which will be used to authenticate 
 * their session.  To register a user and assign access rights to them, use 
 * the functions Auth_RegisterUser and Auth_AddUserToGroup.  See below for 
 * a discussion on how to use groups.
 *
 * If a user tries to log in and cannot, due to not having a username or not 
 * knowing the password, you can optionally enable guest privileges and define
 * access rights for guests.
 *
 *
 * GROUPS
 *
 * Groups are merely a convenience to the server operator.  They are completely
 * transparent to the client machine.  Groups are a way to specify access
 * rights to a set of people conveniently.  When you register a user to be
 * allowed to the server, you can add them to one or more of these groups.  This
 * user gains the sum of all permissions of the groups he belongs to.  The user
 * can never lose privileges from belonging to a group.
 *
 * For example, say you set up the 'a' and the 'b' groups.  The
 * 'a' group has write only permission to share '1', the 'b' group has read only
 * permission to share '1'.  User 'sally', who belongs to both 'a' and 'b' groups,
 * has read and write permission to share '1'; but 'bob' who is only in group 'a',
 * can only write to share '1'
 *
 * To register groups and assign permissions, use the functions Auth_RegisterGroup
 * and Auth_AssignGroupPermission.
 *
 *
 * PERMISSION
 *
 * Permission is a concept used to selectively allow access to shares based on a 
 * username.  If a user has a certain access right to a share, they have that access
 * right to all files and directories in the share.
 *
 * The permissions available are read only; write only; read and write; and none.  If
 * a user has any permission but 'none', they can browse the files in the share (even if
 * they have only write permission -- they can just not read what the files contain).
 */
 
 
BBOOL Auth_RegisterGroup (PFRTCHAR name);
BBOOL Auth_AssignGroupPermission (PFRTCHAR group, PFRTCHAR share, byte mode);

BBOOL Auth_RegisterUser (PFRTCHAR name, PFCHAR password);
BBOOL Auth_DeleteUser (PFRTCHAR name);

BBOOL Auth_AddUserToGroup (PFRTCHAR user, PFRTCHAR group);
BBOOL Auth_RemoveUserFromGroup (PFRTCHAR user, PFRTCHAR group);

word Auth_AuthenticateUser (PSMB_SESSIONCTX pCtx, PFRTCHAR name, PFRTCHAR domainname, 
							PFCHAR ansi_password, PFCHAR uni_password, word *authId); //

byte Auth_BestAccess (PSMB_SESSIONCTX pCtx, word tid);
BBOOL Auth_DoPasswordsMatch (PSMB_SESSIONCTX pCtx, PFRTCHAR name, PFRTCHAR domainname, 
							 PFCHAR password, PFBYTE ansi_password, PFBYTE uni_password); //

void Auth_SetMode (byte mode);
byte Auth_GetMode (void);

void Auth_Init (void);
//void Auth_Shutdown (void);

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_AUTH_H__ */
