//
// SRVARG.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Parsing functions for SMB share names
//
#include "smbdefs.h"
#include "rtpchar.h" 
#include "rtpprint.h"
#include "smbdebug.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvarg.h"
#include "srvauth.h"
#include "smbutil.h"
#include "psmbfile.h"
#include "srvapi.h"


#define RTSMB_ARG_MAX_SECTION_SIZE  500
#define RTSMB_ARG_KEY_SIZE          20

// types of args
typedef enum
{
    ARG_NONE,
    ARG_GLOBAL,
    ARG_USER,
    ARG_GROUP,
    ARG_SHARE,
    ARG_IPC,
    ARG_PRINTER
}
ARG_SECTION_TYPE;

RTSMB_STATIC ARG_SECTION_TYPE RTSMB_GetNextArgSectionType (int f)
{
#define ARG_SECTION_TITLE_SIZE  50
#define ARG_SECTION_TITLE_USER      "user"
#define ARG_SECTION_TITLE_GROUP     "group"
#define ARG_SECTION_TITLE_GLOBAL    "global"
#define ARG_SECTION_TITLE_SHARE     "share"
#define ARG_SECTION_TITLE_IPC       "ipc"
#define ARG_SECTION_TITLE_PRINTER   "printer"

    int i, r;
    char title [ARG_SECTION_TITLE_SIZE + 1];
    BBOOL start, end, reading = TRUE;
    char c;

    start = end = FALSE;
    i = 0;

    do
    {
        r = prtsmb_filesys->fs_read (f, (unsigned char *)&c, 1);
        if (r <= 0)
            return ARG_NONE;

        // check to make sure we don't read comments
        if (!reading)
        {
            if (c == '\n')
            {
                reading = TRUE;
            }

            continue;
        }

        switch (c)
        {
        case '#':   // start of a comment
            reading = FALSE;
            break;
        case '[':   // start of section type we want
            start = TRUE;
            break;
        case ']':   // end of section type we want
            end = TRUE;
            break;
        default:
            if (start)
            {
                title[i++] = (char) c;

                if (i == ARG_SECTION_TITLE_SIZE)
                    end = TRUE;
            }
            break;
        }

        if (end)
            break;
    }
    while (1);

    title[i] = '\0';

    // do a quick check to make sure we don't use [end] markers if
    // they are in wrong places
    if (!rtsmb_strcasecmp (title, "end", CFG_RTSMB_USER_CODEPAGE))
        return RTSMB_GetNextArgSectionType (f);

    if (!rtsmb_strcasecmp (title, ARG_SECTION_TITLE_USER, CFG_RTSMB_USER_CODEPAGE))     return ARG_USER;
    else if (!rtsmb_strcasecmp (title, ARG_SECTION_TITLE_GROUP, CFG_RTSMB_USER_CODEPAGE))   return ARG_GROUP;
    else if (!rtsmb_strcasecmp (title, ARG_SECTION_TITLE_GLOBAL, CFG_RTSMB_USER_CODEPAGE))  return ARG_GLOBAL;
    else if (!rtsmb_strcasecmp (title, ARG_SECTION_TITLE_SHARE, CFG_RTSMB_USER_CODEPAGE))   return ARG_SHARE;
    else if (!rtsmb_strcasecmp (title, ARG_SECTION_TITLE_IPC, CFG_RTSMB_USER_CODEPAGE)) return ARG_IPC;
    else if (!rtsmb_strcasecmp (title, ARG_SECTION_TITLE_PRINTER, CFG_RTSMB_USER_CODEPAGE)) return ARG_PRINTER;
    else
        return ARG_NONE;
}

RTSMB_STATIC PFCHAR RTSMB_SectionToString (int f, PFCHAR dest, rtsmb_size size)
{
    int i = 0, left, r;
    BBOOL reading = TRUE;
    PFCHAR rv;
#define ARG_SECTION_ENDING_TOKEN_SIZE   5
    RTSMB_CONST char endingToken [ARG_SECTION_ENDING_TOKEN_SIZE + 1] =
        {'[', 'e', 'n', 'd', ']', '\0'};
    char c;
    rv = dest;
    left = (int)size - 1;

    do
    {
        r = prtsmb_filesys->fs_read (f, (unsigned char *)&c, 1);
        if (r <= 0)
            break;

        if (c == '#')   // a comment starter
        {
            reading = FALSE;
        }
        else if (c == '\n') // end of comment
        {
            reading = TRUE;
        }

        if (reading)
        {
            if (c == endingToken[i])
            {
                i++;

                if (i == ARG_SECTION_ENDING_TOKEN_SIZE)
                {
                    *dest = '\0';
                    return rv;
                }

                continue;
            }

            if (i > 0)
            {
                int oldi = i;

                for ( ; i > 0; i--)
                {
                    *dest = endingToken[oldi - i];
                    dest++;
                    left--;

                    if (!left)
                    {
                        *dest = '\0';
                        return rv;
                    }
                }
            }

            *dest = (char) c;
            dest++;
            left--;

            if (!left)
            {
                *dest = '\0';
                return rv;
            }
        }
    }
    while (1);

    *dest = '\0';

    return rv;
}

RTSMB_STATIC BBOOL RTSMB_GetStringValue (PFCHAR section, PFCHAR key, PFCHAR dest, rtsmb_size size)
{
    char keybuf [RTSMB_ARG_KEY_SIZE];
    char scanner [20];
    PFCHAR place, equals;
    int matched;
    BBOOL done = FALSE;

    place = section;
    while (1)
    {
        equals = (PFCHAR)0;

        // find equals character
        while (!equals && *place != '\0')
        {
            if (*place == '=')
                equals = place;

            place++;
        }

        // go to next line
        while (*place != '\n' && *place != '\0')
        {
            place++;
        }

        if (*place == '\0')
            done = TRUE;

        rtp_sprintf (scanner, " %%%is = %%*s \\n", RTSMB_ARG_KEY_SIZE);

        matched = rtp_sscanf (section, scanner, keybuf);

        if (*place == '\n')
            place++;
        section = place;

        if (matched == 1 && !rtsmb_strcasecmp (keybuf, key, CFG_RTSMB_USER_CODEPAGE))
        {
            int i = 0;
            int len;

            if (!done)
            {
                place--;
                *place = '\0';
            }

            // find beginning of word (move past leading whitespace)
            for (i = 1; tc_isspace (equals[i]); i++);

            // find end of word (skip trailing whitespace)
            len = (int)tc_strlen (&equals[i]);

            while (len > 0 && tc_isspace (equals[i + len - 1]))
            {
                len--;
            }

            len = MIN (len, (int)(size - 1));
            tc_strncpy (dest, &equals[i], (rtsmb_size)len);
            dest[len] = '\0';

            if (!done)
                *place = '\n';

            break;
        }

        if (done)
        {
            if (size) tc_strcpy (dest, "");
            return FALSE;
        }
    }

    return TRUE;
}

RTSMB_STATIC BBOOL RTSMB_GetIntegerValue (PFCHAR section, PFCHAR key, int *i)
{
    char keybuf [RTSMB_ARG_KEY_SIZE];
    char scanner [20];
    PFCHAR place;
    int matched;
    BBOOL done = FALSE;

    place = section;
    while (1)
    {
        while (*place != '\n' && *place != '\0')
        {
            place++;
        }

        if (*place == '\n')
            place++;
        else
            done = TRUE;

        rtp_sprintf (scanner, " %%%is = %%i \\n", RTSMB_ARG_KEY_SIZE);

        matched = rtp_sscanf (section, scanner, keybuf, i);

        section = place;

        if (matched < 2)
            continue;

        if (!rtsmb_strcasecmp (keybuf, key, CFG_RTSMB_USER_CODEPAGE))
            break;

        if (done)
            return FALSE;
    }

    return TRUE;
}

RTSMB_STATIC BBOOL RTSMB_ParseUserSection (PFCHAR section)
{
    char name [CFG_RTSMB_MAX_USERNAME_SIZE + 1];                    // name of user
    char passbuf [CFG_RTSMB_MAX_PASSWORD_SIZE + 1];
    char groups [RTSMB_ARG_MAX_SECTION_SIZE];
    char g[RTSMB_ARG_MAX_SECTION_SIZE];
    PFCHAR password;
    int gIndex;
    int index;

    /* First, grab name and password */
    if (!RTSMB_GetStringValue (section, "name", name,
            CFG_RTSMB_MAX_USERNAME_SIZE + 1))
        return FALSE;

    if (RTSMB_GetStringValue (section, "password", passbuf,
            CFG_RTSMB_MAX_PASSWORD_SIZE + 1))
        password = passbuf;
    else
        password = (PFCHAR)0;

    /* Now we register the user */
    RTSMB_DEBUG_OUTPUT_STR ("RTSMB_ParseUserSection: Registering user ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
    rtsmb_srv_register_user (name, password);

    /* Now get the user's groups */
    RTSMB_GetStringValue (section, "groups", groups, RTSMB_ARG_MAX_SECTION_SIZE);

    index = 0;
    gIndex = 0;
    *g = '\0';

    while (tc_isspace(groups[index]))  //skip white space in beginning
    {
        index++;
    }
    while (!(tc_isspace(groups[index]) || groups[index] == '\0'))
    {
        g[gIndex] = groups[index];
        index++;
        gIndex++;
    }  //now we have the first token

    do
    {
        RTSMB_DEBUG_OUTPUT_STR ("RTSMB_ParseUserSection: Adding user ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (" to group ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (g, RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);

        rtsmb_srv_add_user_to_group (name, g);

        *g = '\0';
        gIndex = 0;

        while (tc_isspace(groups[index]))  //skip white space
        {
            index++;
        }

        while (!(tc_isspace(groups[index]) || groups[index] == '\0'))
        {
            g[gIndex] = groups[index];
            index++;
            gIndex++;
        }  //now we have the next token
    }
    while (*g);

    return TRUE;
}

RTSMB_STATIC BBOOL RTSMB_ParseGroupSection (PFCHAR section)
{
    char name [CFG_RTSMB_MAX_GROUPNAME_SIZE + 1];
    char shares [RTSMB_ARG_MAX_SECTION_SIZE];
    char s [RTSMB_ARG_MAX_SECTION_SIZE];
    int permissions;
    int sIndex;
    int index;

    if (!RTSMB_GetStringValue (section, "name", name,
            CFG_RTSMB_MAX_GROUPNAME_SIZE + 1))
        return FALSE;

    RTSMB_DEBUG_OUTPUT_STR ("RTSMB_ParseGroupSection: Registering group ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
    rtsmb_srv_register_group (name);

    RTSMB_GetStringValue (section, "shares", shares, RTSMB_ARG_MAX_SECTION_SIZE);

    index = 0;
    sIndex = 0;
    s[0] = '\0';

    while (tc_isspace(shares[index]))  //skip white space in beginning
    {
        index++;
    }
    while (!(tc_isspace(shares[index]) || shares[index] == '\0'))
    {
        s[sIndex] = shares[index];
        index++;
        sIndex++;
    }  //now we have the first token

    do
    {
        PFCHAR tmp = tc_strchr (s, ':');

        if (tmp)
        {
            char rw_perm[4];
            *tmp++ = 0; /* Null terminate sharename */
            rw_perm[0] = *tmp++;
            rw_perm[1] = *tmp;
            rw_perm[2] = 0;

            if (!rtsmb_strcasecmp (rw_perm, "ro", CFG_RTSMB_USER_CODEPAGE))
                permissions = SECURITY_READ;
            else if (!rtsmb_strcasecmp (rw_perm, "wo", CFG_RTSMB_USER_CODEPAGE))
                permissions = SECURITY_WRITE;
            else if (!rtsmb_strcasecmp (rw_perm, "rw", CFG_RTSMB_USER_CODEPAGE))
                permissions = SECURITY_READWRITE;
            else
                permissions = SECURITY_NONE;
        }
        else
        {
            permissions = SECURITY_NONE;
        }

        RTSMB_DEBUG_OUTPUT_STR ("RTSMB_ParseGroupSection: Setting group ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (" permission's for share ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (s, RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_STR (" to ", RTSMB_DEBUG_TYPE_ASCII);
        RTSMB_DEBUG_OUTPUT_INT (permissions);
        RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
        rtsmb_srv_set_group_permissions (name, s, (byte) (permissions & 0xFF));


        while (tc_isspace(shares[index]))  //skip white space between shares
        {
            index++;
        }
        s[0] = '\0';
        sIndex = 0;
        while (!(tc_isspace(shares[index]) || shares[index] == '\0'))
        {
            s[sIndex] = shares[index];
            index++;
            sIndex++;
        }  //now we have the next token

    }
    while (s[0]);

    return TRUE;
}

RTSMB_STATIC BBOOL RTSMB_ParseShareSection (PFCHAR section)
{
    char name [RTSMB_MAX_SHARENAME_SIZE + 1];
    char comment [RTSMB_MAX_COMMENT_SIZE + 1];
    char path [MAX_PATH_PREFIX_SIZE + 1];
    char passbuf [CFG_RTSMB_MAX_PASSWORD_SIZE + 1];
    PFCHAR password;
    int flags;
    int permissions;

    char permission_str [5];
    char flags_str [100];

    if (!RTSMB_GetStringValue (section, "name", name,
            RTSMB_MAX_SHARENAME_SIZE + 1))
        return FALSE;

    if (!RTSMB_GetStringValue (section, "comment", comment,
            RTSMB_MAX_COMMENT_SIZE + 1))
        return FALSE;

    if (!RTSMB_GetStringValue (section, "path", path,
            MAX_PATH_PREFIX_SIZE + 1))
        return FALSE;

    if (RTSMB_GetStringValue (section, "password", passbuf,
            CFG_RTSMB_MAX_PASSWORD_SIZE + 1))
        password = passbuf;
    else
        password = (PFCHAR)0;

    if (!RTSMB_GetStringValue (section, "permission", permission_str, 5))
        return FALSE;

    if (!RTSMB_GetStringValue (section, "flags", flags_str, 100))
        return FALSE;

    if (!rtsmb_strcasecmp (permission_str, "ro", CFG_RTSMB_USER_CODEPAGE))
        permissions = SECURITY_READ;
    else if (!rtsmb_strcasecmp (permission_str, "wo", CFG_RTSMB_USER_CODEPAGE))
        permissions = SECURITY_WRITE;
    else if (!rtsmb_strcasecmp (permission_str, "rw", CFG_RTSMB_USER_CODEPAGE))
        permissions = SECURITY_READWRITE;
    else
        permissions = SECURITY_NONE;

    flags = 0;
    if (tc_strstr (flags_str, "create"))
        flags |= SHARE_FLAGS_CREATE;
    if (tc_strstr (flags_str, "case_sensitive"))
        flags |= SHARE_FLAGS_CASE_SENSITIVE;
    if (tc_strstr (flags_str, "dos_names"))
        flags |= SHARE_FLAGS_8_3;

    RTSMB_DEBUG_OUTPUT_STR ("RTSMB_ParseShareSection:  Adding share ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
    rtsmb_srv_share_add_tree (name, comment, prtsmb_filesys, path, (byte) flags,
        (byte) permissions, password);

    return TRUE;
}

RTSMB_STATIC BBOOL RTSMB_ParsePrinterSection (PFCHAR section)
{
    char name [RTSMB_MAX_SHARENAME_SIZE + 1];
    char comment [RTSMB_MAX_COMMENT_SIZE + 1];
    char path [MAX_PATH_PREFIX_SIZE + 1];
    char passbuf [CFG_RTSMB_MAX_PASSWORD_SIZE + 1];
    PFCHAR password;
    int flags;
    char flags_str [100];
    int number;
    char drivername [SMBF_FILENAMESIZE + 1];

    if (!RTSMB_GetStringValue (section, "name", name,
            RTSMB_MAX_SHARENAME_SIZE + 1))
        return FALSE;

    if (!RTSMB_GetStringValue (section, "comment", comment,
            RTSMB_MAX_COMMENT_SIZE + 1))
        return FALSE;

    if (!RTSMB_GetStringValue (section, "path", path,
            MAX_PATH_PREFIX_SIZE + 1))
        return FALSE;

    if (RTSMB_GetStringValue (section, "password", passbuf,
            CFG_RTSMB_MAX_PASSWORD_SIZE + 1))
        password = passbuf;
    else
        password = (PFCHAR)0;

    if (!RTSMB_GetStringValue (section, "drivername", drivername,
            SMBF_FILENAMESIZE + 1))
        return FALSE;

    if (!RTSMB_GetIntegerValue (section, "number", &number))
        return FALSE;

    if (!RTSMB_GetStringValue (section, "flags", flags_str, 100))
        return FALSE;

    flags = 0;
    if (tc_strstr (flags_str, "create"))
        flags |= SHARE_FLAGS_CREATE;
    if (tc_strstr (flags_str, "case_sensitive"))
        flags |= SHARE_FLAGS_CASE_SENSITIVE;
    if (tc_strstr (flags_str, "dos_names"))
        flags |= SHARE_FLAGS_8_3;

    RTSMB_DEBUG_OUTPUT_STR ("RTSMB_ParsePrinterSection:  Adding printer ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (name, RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
    rtsmb_srv_share_add_printer (name, comment,
        number, prtsmb_filesys, path,
        (byte) flags, password, drivername);

    return TRUE;
}

RTSMB_STATIC BBOOL RTSMB_ParseIPCSection (PFCHAR section)
{
    char passbuf [CFG_RTSMB_MAX_PASSWORD_SIZE + 1];
    PFCHAR password;

    if (RTSMB_GetStringValue (section, "password", passbuf,
            CFG_RTSMB_MAX_PASSWORD_SIZE + 1))
        password = passbuf;
    else
        password = (PFCHAR)0;

    RTSMB_DEBUG_OUTPUT_STR("RTSMB_ReadArgsFrom:  Adding IPC.\n", RTSMB_DEBUG_TYPE_ASCII);
    rtsmb_srv_share_add_ipc (password);

    return TRUE;
}

RTSMB_STATIC BBOOL RTSMB_ParseGlobalSection (PFCHAR section)
{
    char mode_str [10];
    char guest_str [10];
    int index;
    int gIndex;

    if (!RTSMB_GetStringValue (section, "mode", mode_str, 10))
    {
        tc_strcpy (mode_str, "share");
    }

    if (!RTSMB_GetStringValue (section, "guest", guest_str, 10))
    {
        tc_strcpy (guest_str, "no");
    }

    if (!rtsmb_strcasecmp (mode_str, "user", CFG_RTSMB_USER_CODEPAGE))
    {
        rtsmb_srv_set_mode (AUTH_USER_MODE);
    }
    else
    {
        rtsmb_srv_set_mode (AUTH_SHARE_MODE);
    }

    if (!rtsmb_strcasecmp (guest_str, "yes", CFG_RTSMB_USER_CODEPAGE))
    {
        char groups [RTSMB_ARG_MAX_SECTION_SIZE];
        char g [RTSMB_ARG_MAX_SECTION_SIZE];

        RTSMB_DEBUG_OUTPUT_STR("RTSMB_ParseGlobalSection:  Adding guest.\n", RTSMB_DEBUG_TYPE_ASCII);
        rtsmb_srv_register_user (SMB_GUESTNAME, (PFCHAR)0);

        /* Now get the guest's groups */
        RTSMB_GetStringValue (section, "guestgroups", groups, RTSMB_ARG_MAX_SECTION_SIZE);

        index = 0;
        gIndex = 0;
        *g = '\0';

        while (tc_isspace(groups[index]))  //skip white space in beginning
        {
            index++;
        }
        while (!(tc_isspace(groups[index]) || groups[index] == '\0'))
        {
            g[gIndex] = groups[index];
            index++;
            gIndex++;
        }  //now we have the first token

        do
        {
            RTSMB_DEBUG_OUTPUT_STR ("RTSMB_ParseGlobalSection: Adding guest to group ", RTSMB_DEBUG_TYPE_ASCII);
            RTSMB_DEBUG_OUTPUT_STR (g, RTSMB_DEBUG_TYPE_ASCII);
            RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
            rtsmb_srv_add_user_to_group (SMB_GUESTNAME, g);

            *g = '\0';
            gIndex = 0;
            while (!(tc_isspace(groups[index]) || groups[index] == '\0'))
            {
                g[gIndex] = groups[index];
                index++;
                gIndex++;
            }  //now we have the next token
        }
        while (*g);
    }

    return TRUE;
}

/* --------------------------------------------------- /
 * Parses arguments from SMB configuration file.  This /
 * function is looped on until it returns FALSE        /
 *                                                     /
 * Returns: TRUE if more to do, FALSE if not           /
 * -------------------------------------------------- */
RTSMB_STATIC BBOOL RTSMB_ParseNextArgSection (int f)
{
    ARG_SECTION_TYPE type;
    char buf [RTSMB_ARG_MAX_SECTION_SIZE];
    PFCHAR string;

    tc_memset (buf, '\0', RTSMB_ARG_MAX_SECTION_SIZE);

    type = RTSMB_GetNextArgSectionType (f);

    if (type == ARG_NONE)
    {
        return FALSE;
    }

    string = RTSMB_SectionToString (f, buf, RTSMB_ARG_MAX_SECTION_SIZE);

    switch (type)
    {
    case ARG_USER:
        if (!RTSMB_ParseUserSection (string))
            return RTSMB_ParseNextArgSection (f);

        break;
    case ARG_SHARE:
        if (!RTSMB_ParseShareSection (string))
            return RTSMB_ParseNextArgSection (f);

        break;
    case ARG_IPC:
        if (!RTSMB_ParseIPCSection (string))
            return RTSMB_ParseNextArgSection (f);

        break;
    case ARG_GROUP:
        if (!RTSMB_ParseGroupSection (string))
            return RTSMB_ParseNextArgSection (f);

        break;
    case ARG_GLOBAL:
        if (!RTSMB_ParseGlobalSection (string))
            return RTSMB_ParseNextArgSection (f);

        break;
    case ARG_PRINTER:
        if (!RTSMB_ParsePrinterSection (string))
            return RTSMB_ParseNextArgSection (f);

        break;
    default:
        return RTSMB_ParseNextArgSection (f);
    }

    return TRUE;
}

/* --------------------------------------------------- /
 * Reads arguments from RTSMB configuration file       /
 * (specified by filename)                             /
 *                                                     /
 * Returns: 0 on success, -1 on failure                /
 * -------------------------------------------------- */
int RTSMB_ReadArgsFrom (PFRTCHAR filename)
{
    int f;

#if (CFG_RTSMB_PRINT_SIZES)
    char buffer[128];

    rtp_sprintf (buffer, "share permission: %i\n", sizeof (SHARE_PERMISSION_T));
    tm_puts (buffer);
    rtp_sprintf (buffer, "arg section: %i\n", sizeof (ARG_SECTION_T));
    tm_puts (buffer);
#endif

#if (INCLUDE_RTSMB_UNICODE)
    if (prtsmb_filesys->fs_wopen)
    {
        /* good -- they support unicode */
        f = prtsmb_filesys->fs_wopen (filename, RTP_FILE_O_RDONLY, 0);
    }
    else
#endif
    {
        char filename_ascii [SMBF_FILENAMESIZE + 1];

        rtsmb_util_rtsmb_to_ascii (filename, filename_ascii, CFG_RTSMB_USER_CODEPAGE);

        f = prtsmb_filesys->fs_open (filename_ascii, RTP_FILE_O_RDONLY, 0);
    }

    if (f == -1)
    {
        return -1;
    }

    while (RTSMB_ParseNextArgSection (f));

    prtsmb_filesys->fs_close (f);

    return 0;
}

#endif /* INCLUDE_RTSMB_SERVER */

