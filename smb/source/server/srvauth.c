/*                                                                         */
/* EBSnet - RTSMB                                                          */
/*                                                                         */
/* Copyright EBSnet Inc. , 2003                                            */
/* All rights reserved.                                                    */
/* This code may not be redistributed in source or linkable object form    */
/* without the consent of its author.                                      */
/*                                                                         */
/* Module description:                                                     */
/* Handles authentication, including groups, users, passwords              */
/*                                                                         */

#include "smbdefs.h"
#include "rtpwcs.h"
#include "rtpprint.h"
#include "smbdebug.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvauth.h"
#include "srvshare.h"
#include "srvutil.h"
#include "srvrsrcs.h"

#include "srvcfg.h"
#include "smbutil.h"

#define DISPLAY_USERS 1

RTSMB_STATIC short getUserIdFromName (PFRTCHAR name);

#if (DISPLAY_USERS)
void smbs_display_users(void)
{
int i, j;
char rtsmb_user[CFG_RTSMB_MAX_USERNAME_SIZE + 1];  /* ascii user name */
int uid;

    rtp_printf("************** USERS ****************\n");
    for (i = 0; i < prtsmb_srv_ctx->max_users; i++)
    {
        if (prtsmb_srv_ctx->userList.users[i].inUse)
        {
            rtsmb_util_rtsmb_to_ascii(prtsmb_srv_ctx->userList.users[i].name, 
                                      rtsmb_user, CFG_RTSMB_USER_CODEPAGE);

            rtp_printf("USER TABLE ENTRY: %d USER: %s; PASSWORD: %s\n",
                i,
                rtsmb_user,
                prtsmb_srv_ctx->userList.users[i].password);

            uid = getUserIdFromName (prtsmb_srv_ctx->userList.users[i].name);
            rtp_printf("USER TABLE ENTRY: UID %d\n", uid);

            for (j = 0; j < prtsmb_srv_ctx->groupList.numGroups; j++)
            {
                if (prtsmb_srv_ctx->userList.users[uid].groups[j])
                {
                    rtp_printf("USER TABLE ENTRY: in GROUP %d\n", j);
                }
            }
        }
    }
}
#endif

/**
 *
 * These functions are used to authenticate users
 * for access to shares.
 */

RTSMB_STATIC
short getGroupIdFromName (PFRTCHAR name)
{
    byte i;

    for (i = 0; i < prtsmb_srv_ctx->groupList.numGroups; i++)
    {
        if (rtsmb_casencmp (name, prtsmb_srv_ctx->groupList.groups[i].name, CFG_RTSMB_MAX_GROUPNAME_SIZE, CFG_RTSMB_USER_CODEPAGE) == 0)
        {
            return i;
        }
    }

    return -1;
}

RTSMB_STATIC
short getUserIdFromName (PFRTCHAR name)
{
    byte i;

    for (i = 0; i < prtsmb_srv_ctx->max_users; i++)
    {
        if (prtsmb_srv_ctx->userList.users[i].inUse &&
            !rtsmb_casencmp (name, prtsmb_srv_ctx->userList.users[i].name, CFG_RTSMB_MAX_USERNAME_SIZE, CFG_RTSMB_USER_CODEPAGE))
        {
            return i;
        }
    }

    return -1;
}

word Auth_AuthenticateUser (PSMB_SESSIONCTX pCtx, PFRTCHAR name, PFRTCHAR domainname, PFCHAR ansi_password, PFCHAR uni_password, word *authId)
{
    short uid;
    PUSERDATA user;
    word rv = AUTH_NOACCESS;

    CLAIM_AUTH ();
    uid = getUserIdFromName (name);

    RTSMB_DEBUG_OUTPUT_STR ("\nUser \" ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
    RTSMB_DEBUG_OUTPUT_STR (" \" with domainname \" ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (domainname, RTSMB_DEBUG_TYPE_SYS_DEFINED);
    RTSMB_DEBUG_OUTPUT_STR (" \" is trying to access the share created on this server\n", RTSMB_DEBUG_TYPE_ASCII);

    if (uid >= 0)
    {
        user = &prtsmb_srv_ctx->userList.users[uid];

        if (Auth_DoPasswordsMatch (pCtx, name, domainname, user->password,
                                (PFBYTE) ansi_password, (PFBYTE) uni_password))
        {
            (*authId) = (word)uid;
            rv = 0;
        }
    }

    /* Commenting below code to allow guest login with only username "guest" and password "guest" */
    /*if (rv == AUTH_NOACCESS && prtsmb_srv_ctx->guestAccount != -1)
    {
        (*authId) = prtsmb_srv_ctx->guestAccount;
        rv = AUTH_GUEST;
    }*/

    RELEASE_AUTH ();

    if (rv == 0)
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_AuthenticateUser:  User \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \" granted access.\n", RTSMB_DEBUG_TYPE_ASCII);
    }
    else if (rv == AUTH_GUEST)
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_AuthenticateUser:  User \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \" granted guest access.\n", RTSMB_DEBUG_TYPE_ASCII);
    }
    else
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_AuthenticateUser:  User \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \" not granted access.\n", RTSMB_DEBUG_TYPE_ASCII);
    }

    return rv;
}

BBOOL isInGroup (word authId, word groupId)
{
    return prtsmb_srv_ctx->userList.users[authId].groups[groupId];
}


void setMode (PACCESS_TABLE table, word tid, byte mode)
{
    byte byteNum;
    byte bitNum;    /* first of two bits */
    byte *actualByte;

    byteNum = (byte)(tid / 4);
    bitNum =  (byte)((tid % 4)*2);  /* first of two bits */
    actualByte = &table->table [byteNum];

    (*actualByte) |= (byte)(0xc0 >> bitNum);
    (*actualByte) ^= (byte)(0xc0 >> bitNum);
    (*actualByte) |= (byte) (mode << (6 - bitNum));
}

byte getMode (PACCESS_TABLE table, word tid)
{
    byte byteNum;
    byte bitNum;
    byte actualByte;

    byteNum = (byte) (tid / 4);
    bitNum = (byte) ((tid % 4) * 2);  /* first of two bits */
    actualByte = table->table [byteNum];

    return
        (byte)((actualByte & (byte)(0xc0 >> bitNum))>>(6 - (int)bitNum));
}

byte mergeAccessRights (byte one, byte two)
{
    if (one == two)
    {
         return one;
    }
    else if (one == SECURITY_READWRITE)
    {
         return one;
    }
    else if (two == SECURITY_READWRITE)
    {
         return two;
    }
    else if (one == SECURITY_NONE)
    {
         return two;
    }
    else if (two == SECURITY_NONE)
    {
         return one;
    }
    else
    {
         return SECURITY_READWRITE;
    }
}

BBOOL Auth_DoPasswordsMatch (PSMB_SESSIONCTX pCtx, PFRTCHAR name, PFRTCHAR domainname,
                             PFCHAR  plaintext, PFBYTE ansi_password, PFBYTE uni_password) /*_YI_ */
{
    BBOOL ret_val;
#if (INCLUDE_RTSMB_ENCRYPTION)
    byte passbuf [24];
#endif

    if(plaintext) /* if there is no need to check passwords, don't */
    {
        ret_val = FALSE;
#if (INCLUDE_RTSMB_ENCRYPTION)
        if (pCtx->dialect >= NT_LM)
        {
        int i;
            rtp_printf("Auth_DoPasswordsMatch: ansi_password = %s\n", plaintext);
            for (i=0; i<24; i++)
                rtp_printf("%x ", ansi_password[i]);
        }
        
        if (pCtx->dialect >= NT_LM &&
            tc_memcmp (cli_util_encrypt_password_nt (plaintext, pCtx->encryptionKey, passbuf), ansi_password, 24)==0)
        {
            ret_val = TRUE;
        }
        else if (tc_memcmp (cli_util_encrypt_password_pre_nt (plaintext, pCtx->encryptionKey, passbuf), ansi_password, 24)==0)
        {
            ret_val = TRUE;
        }
        else if (name && domainname && uni_password && 
                 (tc_memcmp(cli_util_encrypt_password_lmv2 (plaintext, pCtx->encryptionKey, (PFCHAR)passbuf,uni_password, name, domainname), ansi_password, 24)==0))
        {
            ret_val = TRUE;
        }
#else
        if (tc_strcmp (plaintext, ansi_password) == 0)
        {
            ret_val = TRUE;
        }
#endif
    }
    else
        ret_val = TRUE;
    return (ret_val);
}

/* returns the accumulated access rights due to group membership     */
byte Auth_BestAccess (PSMB_SESSIONCTX pCtx, word tid)
{
    word i;
    PUSER user;
    byte best = SECURITY_NONE;

    user = SMBU_GetUser (pCtx, pCtx->uid);

    CLAIM_AUTH ();
    for (i = 0; i < prtsmb_srv_ctx->groupList.numGroups; i ++)
    {
        if (isInGroup (user->authId, i) == TRUE)
        {
            byte actualMode = getMode (&prtsmb_srv_ctx->groupList.groups[i], tid);

            best = mergeAccessRights (best, actualMode);

/*          PRINTF (("user %s in group " RTSMB_STR_TOK " gets permissions %i\n",                                     */
/*              prtsmb_srv_ctx->userList.users[user->authId].name, prtsmb_srv_ctx->groupList.groups[i].name, best));    */

            /* early exit, since can't get better than this */
            if (best == SECURITY_READWRITE)
                break;
        }
    }
    RELEASE_AUTH ();

    return best;
}

/* assume valid tid */
BBOOL Auth_HasAccess (PSMB_SESSIONCTX pCtx, word tid, byte mode) /* mode is either 0, 1, or 2 (read, write, or both) */
{
    word access;

    if (mode == SECURITY_NONE)
    {
        return TRUE; /* if for some reason, they ask for no access */
    }
    access = Auth_BestAccess (pCtx, tid);

    return  (access != SECURITY_NONE &&
            (access == SECURITY_READWRITE ||
             mode == access));
}

BBOOL Auth_RegisterGroup (PFRTCHAR name)
{
    byte b = 0;
    int i;
    BBOOL rv = TRUE;

    CLAIM_AUTH ();
    if (prtsmb_srv_ctx->groupList.numGroups == prtsmb_srv_ctx->max_groups)
    {
        rv = FALSE;
    }
    else
    {
        for (i = 0; i < 8; i += 2)
        {
            b = b | (byte)(SECURITY_NONE << i);
        }

        rtsmb_ncpy (prtsmb_srv_ctx->groupList.groups[prtsmb_srv_ctx->groupList.numGroups].name, name, CFG_RTSMB_MAX_GROUPNAME_SIZE);
        tc_memset (prtsmb_srv_ctx->groupList.groups[prtsmb_srv_ctx->groupList.numGroups].table, b, sizeof (prtsmb_srv_ctx->groupList.groups[prtsmb_srv_ctx->groupList.numGroups].table));

        prtsmb_srv_ctx->groupList.numGroups++;
    }
    RELEASE_AUTH ();

    if (rv)
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_RegisterGroup:  Successfully registered group \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \".\n", RTSMB_DEBUG_TYPE_ASCII);
    }
    else
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_RegisterGroup:  Failed to register group \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \".\n", RTSMB_DEBUG_TYPE_ASCII);
    }

    return rv;
}

BBOOL Auth_AssignGroupPermission (PFRTCHAR group, PFRTCHAR share, byte mode)
{
    short gid;
    int tid;
    BBOOL rv = TRUE;

    CLAIM_AUTH ();
    if ((gid = getGroupIdFromName (group)) < 0)
        rv = FALSE;

    if ((tid = SR_GetTreeIdFromName (share)) < 0)
        rv = FALSE;

    if (rv)
        setMode (&prtsmb_srv_ctx->groupList.groups[gid], (word)tid, mode);
    RELEASE_AUTH ();

    if (rv)
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_AssignGroupPermission:  Successfully assigned group \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (group, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \" permissions ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_INT (mode);
        RTSMB_DEBUG_OUTPUT_STR (" for share \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (share, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \".\n", RTSMB_DEBUG_TYPE_ASCII);
    }
    else
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_AssignGroupPermission:  Failed to assign group \" " , RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (group, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \" permissions ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_INT (mode);
        RTSMB_DEBUG_OUTPUT_STR (" for share \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (share, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \".\n", RTSMB_DEBUG_TYPE_ASCII);
    }

    return rv;
}

BBOOL Auth_RegisterUser (PFRTCHAR name, PFCHAR password)
{
    byte i;
    PUSERDATA user;
    BBOOL rv = TRUE;

    CLAIM_AUTH ();
    for (i = 0; i < prtsmb_srv_ctx->max_users; i++)
    {
        if (prtsmb_srv_ctx->userList.users[i].inUse == FALSE)
        {
            user = &prtsmb_srv_ctx->userList.users[i];
            break;
        }
    }

    if (i == prtsmb_srv_ctx->max_users)
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_RegisterUser exceeded max_users\n", RTSMB_DEBUG_TYPE_ASCII);
        rv = FALSE;
    }

    if (rv)
    {
        rtsmb_char rtsmb_guest [CFG_RTSMB_MAX_USERNAME_SIZE + 1];

        rtsmb_util_ascii_to_rtsmb (SMB_GUESTNAME, rtsmb_guest, CFG_RTSMB_USER_CODEPAGE);

        if (!rtsmb_casecmp (name, rtsmb_guest, CFG_RTSMB_USER_CODEPAGE))
        {
            prtsmb_srv_ctx->guestAccount = i;
        }

        user->inUse = TRUE;
        rtsmb_ncpy (user->name, name, CFG_RTSMB_MAX_USERNAME_SIZE);

        if (password)
        {
            user->password = user->password_buf;
            tc_memset (user->password, '\0', sizeof (user->password));  /* we want to pad it with nulls for encryption */
            tc_strncpy (user->password, password, CFG_RTSMB_MAX_PASSWORD_SIZE);
        }
        else
        {
            user->password = (PFCHAR)0;
        }

        tc_memset (user->groups, FALSE, prtsmb_srv_ctx->max_groups);
    }
    RELEASE_AUTH ();

    if (rv)
    {
        if (name)
        {
            RTSMB_DEBUG_OUTPUT_STR ("Auth_RegisterUser:  Successfully registered user \" ", RTSMB_DEBUG_TYPE_ASCII);
            RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
            if (password)
            {
                RTSMB_DEBUG_OUTPUT_STR (" \" with password ", RTSMB_DEBUG_TYPE_ASCII);
                RTSMB_DEBUG_OUTPUT_STR (password, RTSMB_DEBUG_TYPE_ASCII);
            }
            RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
        }
    }
    else
    {
        if (name)
        {
            RTSMB_DEBUG_OUTPUT_STR ("Auth_RegisterUser:  Failed to register user \" ", RTSMB_DEBUG_TYPE_ASCII);
            RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
            if (password)
            {
                RTSMB_DEBUG_OUTPUT_STR (" \" with password ", RTSMB_DEBUG_TYPE_ASCII);
                RTSMB_DEBUG_OUTPUT_STR (password, RTSMB_DEBUG_TYPE_ASCII);
            }
            RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
        }
    }
#if (DISPLAY_USERS)
    if (rv == RTP_TRUE)
    {
        smbs_display_users();
    }
#endif
    return rv;
}

BBOOL Auth_DeleteUser (PFRTCHAR name)
{
    short uid;
    BBOOL rv = TRUE;
    rtsmb_char rtsmb_guest [CFG_RTSMB_MAX_USERNAME_SIZE + 1];

    rtsmb_util_ascii_to_rtsmb (SMB_GUESTNAME, rtsmb_guest, CFG_RTSMB_USER_CODEPAGE);

    CLAIM_AUTH ();
    uid = getUserIdFromName (name);

    if (uid < 0)
        rv = FALSE;
    else
        prtsmb_srv_ctx->userList.users[uid].inUse = FALSE;

    if (rv && !rtsmb_casecmp (name, rtsmb_guest, CFG_RTSMB_USER_CODEPAGE))
        prtsmb_srv_ctx->guestAccount = -1;
    RELEASE_AUTH ();

    if (rv)
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_DeleteUser:  Successfully deleted user \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \".\n", RTSMB_DEBUG_TYPE_ASCII);
    }
    else
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_DeleteUser:  Failed to delete user \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \".\n", RTSMB_DEBUG_TYPE_ASCII);
    }

    return rv;
}

BBOOL Auth_AddUserToGroup (PFRTCHAR user, PFRTCHAR group)
{
    short uid;
    short gid;
    BBOOL rv = TRUE;

    CLAIM_AUTH ();
    uid = getUserIdFromName (user);
    gid = getGroupIdFromName (group);

    if (uid < 0 || gid < 0)
        rv = FALSE;
    else
        prtsmb_srv_ctx->userList.users[uid].groups[gid] = TRUE;
    RELEASE_AUTH ();

    if (rv)
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_AddUserToGroup:  Successfully added user \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (user, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \" to group \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (group, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \".\n", RTSMB_DEBUG_TYPE_ASCII);
    }
    else
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_AddUserToGroup:  Failed to add user \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (user, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \" to group \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (group, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \".\n", RTSMB_DEBUG_TYPE_ASCII);
    }

    return rv;
}

BBOOL Auth_RemoveUserFromGroup (PFRTCHAR user, PFRTCHAR group)
{
    short uid;
    short gid;
    BBOOL rv = TRUE;

    CLAIM_AUTH ();
    uid = getUserIdFromName (user);
    gid = getGroupIdFromName (group);

    if (uid < 0 || gid < 0)
        rv = FALSE;
    else
        prtsmb_srv_ctx->userList.users[uid].groups[gid] = FALSE;
    RELEASE_AUTH ();

    if (rv)
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_RemoveUserFromGroup:  Successfully removed user \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (user, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \" to group \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (group, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \".\n", RTSMB_DEBUG_TYPE_ASCII);
    }
    else
    {
        RTSMB_DEBUG_OUTPUT_STR ("Auth_RemoveUserFromGroup:  Failed to remove user \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (user, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \" to group \" ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (group, RTSMB_DEBUG_TYPE_SYS_DEFINED);
        RTSMB_DEBUG_OUTPUT_STR (" \".\n", RTSMB_DEBUG_TYPE_ASCII);

    }

    return rv;
}

void Auth_SetMode (byte mode)
{
    if (mode == AUTH_USER_MODE || mode == AUTH_SHARE_MODE)
    {
        CLAIM_AUTH ();
        prtsmb_srv_ctx->shareMode = mode;
        RELEASE_AUTH ();
    }

    if (mode == AUTH_USER_MODE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Auth_SetMode:  Set server mode to user mode.\n", RTSMB_DEBUG_TYPE_ASCII);
    }
    else if (mode == AUTH_SHARE_MODE)
    {
        RTSMB_DEBUG_OUTPUT_STR("Auth_SetMode:  Set server mode to share mode.\n", RTSMB_DEBUG_TYPE_ASCII);
    }
    else
    {
        RTSMB_DEBUG_OUTPUT_STR("Auth_SetMode:  Ignoring unrecognized mode.\n", RTSMB_DEBUG_TYPE_ASCII);
    }
}

byte Auth_GetMode (void)
{
    byte temp;

    CLAIM_AUTH ();
    temp = prtsmb_srv_ctx->shareMode;
    RELEASE_AUTH ();

    return temp;
}

void Auth_Init (void)
{
#if (CFG_RTSMB_PRINT_SIZES)
    char buffer[128];

    rtp_sprintf (buffer, "access table: %i\n", sizeof (ACCESS_TABLE_T));
    tm_puts (buffer);
    rtp_sprintf (buffer, "groups: %i\n", sizeof (GROUPS_T));
    tm_puts (buffer);
    rtp_sprintf (buffer, "user data: %i\n", sizeof (USERDATA_T));
    tm_puts (buffer);
#endif
    CLAIM_AUTH ();
    prtsmb_srv_ctx->shareMode = AUTH_SHARE_MODE;
    prtsmb_srv_ctx->guestAccount = -1;
    RELEASE_AUTH ();

    RTSMB_DEBUG_OUTPUT_STR("Auth_Init:  Initializing authorization data.\n", RTSMB_DEBUG_TYPE_ASCII);
}

#endif /* INCLUDE_RTSMB_SERVER */
