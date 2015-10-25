//
// SRVAPI.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Application Application Programmer Interface for using RTSMB Server.
// For RTSMB Client see cliapi.c
//

#include "smbdefs.h"
#include "smbdefs.h"
#ifdef SUPPORT_SMB2
#include "com_smb2.h"
#endif

#if (INCLUDE_RTSMB_SERVER)

#include "srvapi.h"
#include "srvauth.h"
#include "srvshare.h"
#include "srvarg.h"
#include "srvnet.h"
#include "srvcfg.h"
#include "srvnbns.h"
#include "srvbrws.h"
#include "srvglue.h"
#include "smbdebug.h"

#include "smbutil.h"
#include "smbnbds.h"


/******************************************************************************

 rtsmb_srv_read_config - set up the server from a configuration file

    filename - filename of configuration file

 Description
    It is possible to control how the server is set up from a file somewhere
    on the filesystem.  Pass the filename to this function to have it parsed
    and acted upon.  Look at the sample config file included with RTSMB for
    examples and documentation.

 See Code
    srvarg.c

 Returns
    0 on success or a negative value on failure

******************************************************************************/
int rtsmb_srv_read_config (PFCHAR filename)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short filename_uc [SMBF_FILENAMESIZE + 1];

    if (tc_strlen (filename) > SMBF_FILENAMESIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameter to rtsmb_srv_read_config.\n", RTSMB_DEBUG_TYPE_ASCII);
        return -2;
    }

    rtsmb_util_ascii_to_unicode (filename, filename_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR filename_uc = filename;
#endif

    return RTSMB_ReadArgsFrom (filename_uc);
}

#if (INCLUDE_RTSMB_UNICODE)
int rtsmb_srv_read_config_uc (PFWCS filename)
{
    return RTSMB_ReadArgsFrom (filename);
}
#endif



/******************************************************************************

 rtsmb_srv_share_add_tree - initialize a disk share

    name - name to use for share
    comment - comment to use for share
    api - the API struct to use for share
    path - directory name to share
    flags - flags to control treatment of this share
    permissions - permissions to grant when using share mode
    password - password to require when using share mode

 Description
    This sets up a directory to be shared as a disk share.  'Name' must be no
    more than 12 characters.  'Api' may be NULL to use the compiled-in default.
    'Flags' may be SHARE_FLAGS_CASE_SENSITIVE to indicate that the file system
    is case sensitive, SHARE_FLAGS_CREATE to indicate that the directory should
    be made if it does not already exist, or SHARE_FLAGS_8_3 to indicate that
    the file system can only handle MSDOS 8.3-formatted names.  'Permissions'
    is one of SECURITY_READ, SECURITY_WRITE, SECURITY_READWRITE, or
    SECURITY_NONE.  'Password' may be NULL, in which case no password is
    required in share mode.

 See Code
    srvshare.c

 See Also
    rtsmb_srv_share_add_ipc, rtsmb_srv_share_add_printer, rtsmb_srv_share_remove

 Returns
    0 on success or a negative value on failure

******************************************************************************/
int rtsmb_srv_share_add_tree (PFCHAR name, PFCHAR comment, PSMBFILEAPI api, PFCHAR path, byte flags, byte permissions, PFCHAR password)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short path_uc [MAX_PATH_PREFIX_SIZE + 1];
    unsigned short name_uc [RTSMB_MAX_SHARENAME_SIZE + 1];
    unsigned short comment_uc [RTSMB_MAX_COMMENT_SIZE + 1];

    if (tc_strlen (name) > RTSMB_MAX_SHARENAME_SIZE ||
        tc_strlen (comment) > RTSMB_MAX_COMMENT_SIZE ||
        tc_strlen (path) > MAX_PATH_PREFIX_SIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameters to rtsmb_srv_share_add_tree.\n", RTSMB_DEBUG_TYPE_ASCII);
        return -2;
    }

    rtsmb_util_ascii_to_unicode (name, name_uc, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_unicode (comment, comment_uc, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_unicode (path, path_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR name_uc = name, comment_uc = comment, path_uc = path;
#endif

    return SR_AddDiskTree (name_uc, comment_uc, api, path_uc, flags, permissions, password);
}

#if (INCLUDE_RTSMB_UNICODE)
int rtsmb_srv_share_add_tree_uc (PFWCS name, PFWCS comment, PSMBFILEAPI api, PFWCS path, byte flags, byte permissions, PFCHAR password)
{
    return SR_AddDiskTree (name, comment, api, path, flags, permissions, password);
}
#endif



/******************************************************************************

 rtsmb_srv_share_add_ipc - initialize the IPC$ share

    password - password to require when using share mode

 Description
    This sets up the IPC$ control share.  This must be done so that clients can
    browse the server's list of shares.  'Password' may be NULL, in which case
    no password is required in share mode.

 See Code
    srvshare.c

 See Also
    rtsmb_srv_share_add_tree, rtsmb_srv_share_add_printer, rtsmb_srv_share_remove

 Returns
    0 on success or a negative value on failure

******************************************************************************/
int rtsmb_srv_share_add_ipc (PFCHAR password)
{
    return SR_AddIPC (password);
}



/******************************************************************************

 rtsmb_srv_share_add_printer - initialize a printer for sharing

    name - name to use for share
    comment - comment to use for share
    n - an implementation-specific number indicating which printer to share
    api - the filesystem api to use for temporary files
    path - directory name of place to store temporary files
    flags - flags to control treatment of this directory
    password - password to require when using share mode
    printerfile - the Windows name of the printer driver (e.g. "HP LaserJet 1000")

 Description
    This sets up a printer to be shared.  'Name' must be no more than 12
    characters.  'Api' may be NULL to use the compiled-in default.
    'Flags' may be SHARE_FLAGS_CASE_SENSITIVE to indicate that the file system
    is case sensitive, SHARE_FLAGS_CREATE to indicate that the directory should
    be made if it does not already exist, or SHARE_FLAGS_8_3 to indicate that
    the file system can only handle MSDOS 8.3-formatted names.  'Password' may
    be NULL, in which case no password is required in share mode.  'N' is a
    1-based number to determine which printer to share.  For example, passing
    n as 1 on a Windows server would indicate to use the first COM port.

 See Code
    srvshare.c

 See Also
    rtsmb_srv_share_add_ipc, rtsmb_srv_share_add_tree, rtsmb_srv_share_remove

 Returns
    0 on success or a negative value on failure

******************************************************************************/
int rtsmb_srv_share_add_printer (PFCHAR name, PFCHAR comment, int n, PSMBFILEAPI api, PFCHAR path, byte flags, PFCHAR password, PFCHAR printerfile)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short path_uc [MAX_PATH_PREFIX_SIZE + 1];
    unsigned short file_uc [SMBF_FILENAMESIZE + 1];
    unsigned short name_uc [RTSMB_MAX_SHARENAME_SIZE + 1];
    unsigned short comment_uc [RTSMB_MAX_COMMENT_SIZE + 1];

    if (tc_strlen (name) > RTSMB_MAX_SHARENAME_SIZE ||
        tc_strlen (comment) > RTSMB_MAX_COMMENT_SIZE ||
        tc_strlen (printerfile) > SMBF_FILENAMESIZE ||
        tc_strlen (path) > MAX_PATH_PREFIX_SIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameters to rtsmb_srv_share_add_printer.\n", RTSMB_DEBUG_TYPE_ASCII);
        return -2;
    }

    rtsmb_util_ascii_to_unicode (name, name_uc, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_unicode (comment, comment_uc, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_unicode (path, path_uc, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_unicode (printerfile, file_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR name_uc = name, comment_uc = comment, path_uc = path, file_uc = printerfile;
#endif


    return SR_AddPrinter (name_uc, comment_uc, n, api, path_uc, flags, password, file_uc);
}

#if (INCLUDE_RTSMB_UNICODE)
int rtsmb_srv_share_add_printer_uc (PFWCS name, PFWCS comment, int n, PSMBFILEAPI api, PFWCS path, byte flags, PFCHAR password, PFWCS printerfile)
{
    return SR_AddPrinter (name, comment, n, api, path, flags, password, printerfile);
}
#endif

/******************************************************************************

 rtsmb_srv_share_modify - modify share properties

    currentname - current name of share to modify

 Description
    The "currentname" will be changed to "newname" if provided or current permission
    will be changed to "newpermission".

 See Code
    srvshare.c

 See Also
    rtsmb_srv_share_add_ipc, rtsmb_srv_share_add_tree, rtsmb_srv_share_add_printer

 Returns
    0 on success or a negative value on failure

******************************************************************************/
int rtsmb_srv_share_modify (PFCHAR currentname, PFCHAR newname, byte newpermissions)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short newname_uc [RTSMB_MAX_SHARENAME_SIZE + 1];
    unsigned short currentname_uc [RTSMB_MAX_SHARENAME_SIZE + 1];

    rtsmb_util_ascii_to_unicode (newname, newname_uc, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_unicode (currentname, currentname_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR newname_uc = newname;
    PFCHAR currentname_uc = currentname;
#endif

    return SR_ModifyShare (currentname_uc, newname_uc, newpermissions);
}

#if (INCLUDE_RTSMB_UNICODE)
int rtsmb_srv_share_modify_uc (PFWCS currentname, PFWCS newname, byte newpermissions)
{
    return SR_ModifyShare (currentname, newname, newpermissions);
}
#endif

/*************************************************************************
rtsmb_srv_printer_modify - modify printer properties

    currentname - current name of printer to modify

 Description
    The "currentname" will be changed to "newname" if provided or current permission
    will be changed to "newpermission" if provided.

 See Code
    srvshare.c

 See Also
     rtsmb_srv_share_add_printer, rtsmb_srv_share_add_tree, rtsmb_srv_share_add_ipc.

 Returns
    0 on success or a negative value on failure
**************************************************************************/
int rtsmb_srv_printer_modify (PFCHAR currentname, PFCHAR newname)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short currentname_uc [RTSMB_MAX_SHARENAME_SIZE + 1];
    unsigned short newname_uc [RTSMB_MAX_COMMENT_SIZE + 1];

    if (tc_strlen (currentname) > RTSMB_MAX_SHARENAME_SIZE ||
        tc_strlen (newname) > RTSMB_MAX_SHARENAME_SIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameters to rtsmb_srv_printer_modify.\n", RTSMB_DEBUG_TYPE_ASCII);
        return -2;
    }

    rtsmb_util_ascii_to_unicode (currentname, currentname_uc, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_unicode (newname, newname_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR currentname_uc = currentname, newname_uc = newname;
#endif

    return SR_ModifyPrinter (currentname_uc, newname_uc);
}

#if (INCLUDE_RTSMB_UNICODE)
int rtsmb_srv_printer_modify_uc (PFWCS currentname, PFWCS newname)
{
    return SR_ModifyPrinter (currentname, newname);
}
#endif

/******************************************************************************

 rtsmb_srv_share_remove - stop a share from being available

    name - name of share to remove

 Description
    The share named by 'name' will be shut down, not available for client
    connections anymore.  Any current activity on it will be halted.  May
    block if using multiple threads.

 See Code
    srvshare.c

 See Also
    rtsmb_srv_share_add_ipc, rtsmb_srv_share_add_tree, rtsmb_srv_share_add_printer

 Returns
    0 on success or a negative value on failure

******************************************************************************/
int rtsmb_srv_share_remove (PFCHAR name)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short name_uc [RTSMB_MAX_SHARENAME_SIZE + 1];

    if (tc_strlen (name) > RTSMB_MAX_SHARENAME_SIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameter to rtsmb_srv_share_remove.\n", RTSMB_DEBUG_TYPE_ASCII);
        return -2;
    }

    rtsmb_util_ascii_to_unicode (name, name_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR name_uc = name;
#endif

    return SR_RemoveShare (name_uc);
}

#if (INCLUDE_RTSMB_UNICODE)
int rtsmb_srv_share_remove_uc (PFWCS name)
{
    return SR_RemoveShare (name);
}
#endif



/******************************************************************************

 rtsmb_srv_set_mode - change the authentication mode of the server

    mode - mode type

 Description
    'Mode' can be either AUTH_USER_MODE or AUTH_SHARE_MODE.  In user mode,
    each user provides a username and password pair and then can access the
    shares at a certain security level.  In share mode, users provide
    a password for each share.

    This can be changed in the middle of server operation.  All currently
    connected users will continue to use the previous mode.  All further
    connections are made using the new mode.

    The default mode is share mode.

 See Code
    srvauth.c

 See Also
    rtsmb_srv_get_mode

******************************************************************************/
void rtsmb_srv_set_mode (byte mode)
{
    Auth_SetMode (mode);
}


/******************************************************************************

 rtsmb_srv_get_mode - get the authentication mode of the server

 Description
    Returns the authentication mode the server is currently using.  This mode
    can be either AUTH_USER_MODE or AUTH_SHARE_MODE.  In user mode,
    each user provides a username and password pair and then can access the
    shares at a certain security level.  In share mode, users provide
    a password for each share.

    The default mode is share mode.

 See Code
    srvauth.c

 See Also
    rtsmb_srv_set_mode

 Returns
    current authentication mode

******************************************************************************/
byte rtsmb_srv_get_mode (void)
{
    return Auth_GetMode ();
}



/******************************************************************************

 rtsmb_srv_register_group - set up a group for user accounts

    name - the name of the group to set up

 Description
    Groups are a way to manage collections of users.  They define what access
    rights a user has to which shares.  For example, if you register a group
    with the name 'colors' and user 'red' and 'blue' which belong to 'colors,'
    you can say that all members of 'colors' have read and write access to
    share 'crayon.'  After this call, a group with the specified name will
    be created.

    Groups are only used when the server is in user mode.

 See Code
    srvauth.c

 See Also
    rtsmb_srv_add_user_to_group, rtsmb_srv_remove_user_from_group,
    rtsmb_srv_set_group_permissions, rtsmb_srv_set_mode

 Returns
    non-zero on success or zero on failure

******************************************************************************/
BBOOL rtsmb_srv_register_group (PFCHAR name)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short name_uc [CFG_RTSMB_MAX_GROUPNAME_SIZE + 1];

    if (tc_strlen (name) > CFG_RTSMB_MAX_GROUPNAME_SIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameter to rtsmb_srv_register_group.\n", RTSMB_DEBUG_TYPE_ASCII);
        return FALSE;
    }

    rtsmb_util_ascii_to_unicode (name, name_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR name_uc = name;
#endif

    return Auth_RegisterGroup (name_uc);
}

#if (INCLUDE_RTSMB_UNICODE)
BBOOL rtsmb_srv_register_group_uc (PFWCS name)
{
    return Auth_RegisterGroup (name);
}
#endif


/******************************************************************************

 rtsmb_srv_register_user - set up a user account

    name - the name of the user to set up
    password - the user's required password

 Description
    Before RTSMB Server will allow a user to logon, that user must first
    be registered.  After this call, a user logging on with the username
    'name' and correct password hash of 'password' will be granted access.

    If you call this function with the special name SMB_GUESTNAME, you will
    define a guest account that any users who do not successfully log in will
    be logged in as instead.  In this case, the password parameter is ignored.
    Use the name SMB_GUESTNAME in rtsmb_srv_add_user_to_group to add the guest
    account to an appropriate group.

    Users are only used when the server is in user mode.

 See Code
    srvauth.c

 See Also
    rtsmb_srv_add_user_to_group, rtsmb_srv_remove_user_from_group,
    rtsmb_srv_set_group_permissions, rtsmb_srv_set_mode

 Returns
    non-zero on success or zero on failure

******************************************************************************/
BBOOL rtsmb_srv_register_user (PFCHAR name, PFCHAR password)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short name_uc [CFG_RTSMB_MAX_USERNAME_SIZE + 1];

    if (tc_strlen (name) > CFG_RTSMB_MAX_USERNAME_SIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameter to rtsmb_srv_register_user.\n", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR("User name exceeded the CFG_RTSMB_MAX_USERNAME_SIZE\n", RTSMB_DEBUG_TYPE_ASCII);
        return FALSE;
    }

    rtsmb_util_ascii_to_unicode (name, name_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR name_uc = name;
#endif

    return Auth_RegisterUser (name_uc, password);
}

#if (INCLUDE_RTSMB_UNICODE)
BBOOL rtsmb_srv_register_user_uc (PFWCS name, PFCHAR password)
{
    return Auth_RegisterUser (name, password);
}
#endif

/******************************************************************************

 rtsmb_srv_delete_user - delete a user account

    name - the name of the user to delete

 Description
    The user account associated with the username 'name' will be deleted.
    All further logons by that user will be denied.  All current logons by
    that user will continue.

    Users are only used when the server is in user mode.

 See Code
    srvauth.c

 See Also
    rtsmb_srv_add_user_to_group, rtsmb_srv_remove_user_from_group,
    rtsmb_srv_set_group_permissions, rtsmb_srv_set_mode

 Returns
    non-zero on success or zero on failure

******************************************************************************/
BBOOL rtsmb_srv_delete_user (PFCHAR name)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short name_uc [CFG_RTSMB_MAX_USERNAME_SIZE + 1];

    if (tc_strlen (name) > CFG_RTSMB_MAX_USERNAME_SIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameter to rtsmb_srv_delete_user.\n", RTSMB_DEBUG_TYPE_ASCII);
        return FALSE;
    }

    rtsmb_util_ascii_to_unicode (name, name_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR name_uc = name;
#endif

    return Auth_DeleteUser (name_uc);
}

#if (INCLUDE_RTSMB_UNICODE)
BBOOL rtsmb_delete_user_uc (PFWCS name)
{
    return Auth_DeleteUser (name);
}
#endif


/******************************************************************************

 rtsmb_srv_add_user_to_group - adds a user account into a permission group

    user - the name of the user to add
    group - the name of the group to add the user to

 Description
    Before a user can have permissions for any share, it must be added to a
    group.  Once in a group, the permissions of that group for certain shares
    can be set by rtsmb_srv_set_group_permissions.

    Users are only used when the server is in user mode.

 See Code
    srvauth.c

 See Also
    rtsmb_srv_add_user_to_group, rtsmb_srv_remove_user_from_group,
    rtsmb_srv_set_group_permissions, rtsmb_srv_set_mode

 Returns
    non-zero on success or zero on failure

******************************************************************************/
BBOOL rtsmb_srv_add_user_to_group (PFCHAR user, PFCHAR group)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short user_uc [CFG_RTSMB_MAX_USERNAME_SIZE + 1];
    unsigned short group_uc [CFG_RTSMB_MAX_GROUPNAME_SIZE + 1];

    if (tc_strlen (user) > CFG_RTSMB_MAX_USERNAME_SIZE ||
        tc_strlen (group) > CFG_RTSMB_MAX_GROUPNAME_SIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameters to rtsmb_srv_add_user_to_group.\n", RTSMB_DEBUG_TYPE_ASCII);
        return FALSE;
    }

    rtsmb_util_ascii_to_unicode (user, user_uc, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_unicode (group, group_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR user_uc = user, group_uc = group;
#endif

    return Auth_AddUserToGroup (user_uc, group_uc);
}

#if (INCLUDE_RTSMB_UNICODE)
BBOOL rtsmb_srv_add_user_to_group_uc (PFWCS user, PFWCS group)
{
    return Auth_AddUserToGroup (user, group);
}
#endif



/******************************************************************************

 rtsmb_srv_remove_user_from_group - removes a user account from a permission group

    user - the name of the user to add
    group - the name of the group to add the user to

 Description
    The user account associated with the username 'user' is removed from the
    group 'group.'

    Users are only used when the server is in user mode.

 See Code
    srvauth.c

 See Also
    rtsmb_srv_add_user_to_group, rtsmb_srv_remove_user_from_group,
    rtsmb_srv_set_group_permissions, rtsmb_srv_set_mode

 Returns
    non-zero on success or zero on failure

******************************************************************************/
BBOOL rtsmb_srv_remove_user_from_group (PFCHAR user, PFCHAR group)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short user_uc [CFG_RTSMB_MAX_USERNAME_SIZE + 1];
    unsigned short group_uc [CFG_RTSMB_MAX_GROUPNAME_SIZE + 1];

    if (tc_strlen (user) > CFG_RTSMB_MAX_USERNAME_SIZE ||
        tc_strlen (group) > CFG_RTSMB_MAX_GROUPNAME_SIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameters to rtsmb_srv_remove_user_from_group.\n", RTSMB_DEBUG_TYPE_ASCII);
        return FALSE;
    }

    rtsmb_util_ascii_to_unicode (user, user_uc, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_unicode (group, group_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR user_uc = user, group_uc = group;
#endif

    return Auth_RemoveUserFromGroup (user_uc, group_uc);
}

#if (INCLUDE_RTSMB_UNICODE)
BBOOL rtsmb_srv_remove_user_from_group_uc (PFWCS user, PFWCS group)
{
    return Auth_RemoveUserFromGroup (user, group);
}
#endif



/******************************************************************************

 rtsmb_srv_set_group_permissions - sets what access rights a group has

    group - the name of the group whose permissions are to be set
    share - the name of the share on which permissions for 'group' are set
    permissions - the set of permissions the group is allowed on 'share'

 Description
    Before a user can read or write on a share, it must belong to a group,
    which must have permissions set for the share in question.  'Permissions'
    is one of SECURITY_READ, SECURITY_WRITE, SECURITY_READWRITE, or
    SECURITY_NONE.  SECURITY_READ means that the users in the group can read
    and browse any files on it.  SECURITY_WRITE means that the users in the
    group can write to and browse any files on it.  SECURITY_READWRITe means
    the user can read and write and browse.  SECURITY_NONE means that user
    cannot even browse and is denied access to the share.

    The default for any share is SECURITY_NONE.  Thus, if you do not call this
    function, a user will have no access.

    Users are only used when the server is in user mode.

 See Code
    srvauth.c

 See Also
    rtsmb_srv_add_user_to_group, rtsmb_srv_remove_user_from_group,
    rtsmb_srv_set_group_permissions, rtsmb_srv_set_mode

 Returns
    non-zero on success or zero on failure

******************************************************************************/
BBOOL rtsmb_srv_set_group_permissions (PFCHAR group, PFCHAR share, byte permissions)
{
#if (INCLUDE_RTSMB_UNICODE)
    unsigned short share_uc [RTSMB_MAX_SHARENAME_SIZE + 1];
    unsigned short group_uc [CFG_RTSMB_MAX_GROUPNAME_SIZE + 1];

    if (tc_strlen (share) > RTSMB_MAX_SHARENAME_SIZE ||
        tc_strlen (group) > CFG_RTSMB_MAX_GROUPNAME_SIZE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Bad parameters to rtsmb_srv_set_group_permissions.\n", RTSMB_DEBUG_TYPE_ASCII);
        return FALSE;
    }

    rtsmb_util_ascii_to_unicode (share, share_uc, CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_ascii_to_unicode (group, group_uc, CFG_RTSMB_USER_CODEPAGE);
#else
    PFCHAR share_uc = share, group_uc = group;
#endif

    return Auth_AssignGroupPermission (group_uc, share_uc, permissions);
}

#if (INCLUDE_RTSMB_UNICODE)
BBOOL rtsmb_srv_set_group_permissions_uc (PFWCS group, PFWCS share, byte permissions)
{
    return Auth_AssignGroupPermission (group, share, permissions);
}
#endif



/******************************************************************************

 rtsmb_srv_init - initializes the RTSMB Server

    ip - a four-byte array representing the host machine's ip address
    mask_ip - a four-byte array representing the host machine's subnet mask
    net_name - the netbios name to announce ourselves as
    group_name - the netbios workgroup to join

 Description
    Any parameter can be NULL, and the compiled-in default will be used, with
    varying appropriateness.  The default ip is '127.0.0.1,' the default mask
    is '255.255.255.0,' the default network name is CFG_RTSMB_DEFAULT_NET_NAME,
    and the default workgroup name is CFG_RTSMB_DEFAULT_GROUP_NAME.

    CFG_RTSMB_DEFAULT_NET_NAME and CFG_RTSMB_DEFAULT_GROUP_NAME are set in
    smbconf.h.  The defaults when shipped are 'RTSMBSRV' and 'EBS.'

    The server starts in share mode.  Call rtsmb_srv_set_mode to change it.

    This function must be called before any other.

 See Also
    rtsmb_srv_set_mode, rtsmb_srv_set_ip, rtsmb_srv_shutdown

******************************************************************************/
void rtsmb_srv_init (PFBYTE ip, PFBYTE mask_ip, PFCHAR net_name, PFCHAR group_name)
{
    RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_init:  Initializing all server modules.\n", RTSMB_DEBUG_TYPE_ASCII);

    rtsmb_server_config ();
    rtsmb_fileport_init ();
    rtsmb_srv_nbns_init (net_name, group_name); /* srv_net uses this info */
    rtsmb_srv_net_init ();
    rtsmb_srv_net_set_ip (ip, mask_ip);
#ifdef SUPPORT_SMB2
    Smb2SrvModel_Global_Init();
#endif
    rtsmb_srv_browse_init ();
    Auth_Init ();
    SR_Init ();
    rtsmb_srv_glue_init ();

}


/******************************************************************************

 rtsmb_srv_set_ip - sets the ip and subnet to use

    ip - a four-byte array representing the host machine's ip address
    mask_ip - a four-byte array representing the host machine's subnet mask

 Description
    Either parameter can be NULL, and the compiled-in default will be used, with
    varying appropriateness.  The default ip is '127.0.0.1' and the default mask
    is '255.255.255.0.'  The ip can be changed mid-operation, and the server
    will just start operating on that ip and mask instead of the previous one.

 See Code
    srvnet.c, smbnet.c

 See Also
    rtsmb_srv_init

******************************************************************************/
void rtsmb_srv_set_ip (PFBYTE ip, PFBYTE mask_ip)
{
    rtsmb_srv_net_set_ip (ip, mask_ip);
}


/******************************************************************************

 rtsmb_srv_cycle - lets the RTSMB Server work

    timeout - a count of the maximum time to block, in milliseconds

 Description
    RTSMB Server needs to be able to process incoming requests.  To let it do
    so, rtsmb_srv_cycle needs to be called periodically.  'Timeout' may be
    negative, in which case no maximum timeout is specified -- the server
    will block until a request comes in.

 See Code
    srvnet.c, srvnbns.c, srvssn.c

******************************************************************************/
long rtsmb_srv_cycle (long timeout)
{
    long wake_timeout;

    wake_timeout = rtsmb_srv_browse_get_next_wake_timeout ();
    if (wake_timeout >= 0 && (timeout < 0 || wake_timeout < timeout))
    {
        timeout = wake_timeout;
    }

    wake_timeout = rtsmb_srv_nbns_get_next_wake_timeout ();
    if (wake_timeout >= 0 && (timeout < 0 || wake_timeout < timeout))
    {
        timeout = wake_timeout;
    }

    rtsmb_srv_net_cycle (timeout);
    rtsmb_nbds_cycle (0);
    rtsmb_srv_nbns_cycle ();
    rtsmb_srv_browse_cycle ();

    return timeout;
}



/******************************************************************************

 rtsmb_srv_shutdown - stops the RTSMB Server

 Description
    This stops the RTSMB Server gracefully.

 See Code
    srvnet.c, srvnbns.c, srvssn.c

 See Also
    rtsmb_srv_init

******************************************************************************/
void rtsmb_srv_shutdown (void)
{
    RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_shutdown:  Shutting down all modules.\n", RTSMB_DEBUG_TYPE_ASCII);

    rtsmb_srv_glue_shutdown ();
    //Auth_Shutdown ();
    rtsmb_srv_browse_shutdown ();
    /* we are intentionally shutting nbds down first because we want it to
       send dying announcement if we are closing (we don't want to turn off
       announcements first) */
    rtsmb_nbds_shutdown ();
    rtsmb_srv_nbns_shutdown ();
    rtsmb_srv_net_shutdown();
}



/******************************************************************************

 rtsmb_srv_disable - stops the RTSMB Server

 Description
    This disables the RTSMB Server.

 See Code
    srvnet.c, srvnbns.c, srvssn.c

 See Also
    rtsmb_srv_enable

******************************************************************************/
void rtsmb_srv_disable (void)
{
    RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_disable:  Disabling server.\n", RTSMB_DEBUG_TYPE_ASCII);

    rtsmb_srv_browse_shutdown ();
    /* we are intentionally shutting nbds down first because we want it to
       send dying announcement if we are closing (we don't want to turn off
       announcements first) */
    rtsmb_nbds_shutdown ();
    rtsmb_srv_nbns_shutdown ();
    rtsmb_srv_net_shutdown();
}





/******************************************************************************

 rtsmb_srv_enable - enables the RTSMB Server

 Description
    This enables the RTSMB Server.

 See Code
    srvnet.c, srvnbns.c, srvssn.c

 See Also
    rtsmb_srv_disable

******************************************************************************/
void rtsmb_srv_enable (PFCHAR net_name, PFCHAR group_name)
{
    RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_enable:  Enabling server.\n", RTSMB_DEBUG_TYPE_ASCII);

    rtsmb_srv_nbns_init (net_name, group_name); /* srv_net uses this info */
    rtsmb_nbds_init ();
    rtsmb_srv_net_init ();
    rtsmb_srv_browse_init ();

}

#endif /* INCLUDE_RTSMB_SERVER */
