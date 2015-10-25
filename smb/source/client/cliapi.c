//
// CLIAPI.C - 
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  [tbd]
//

#include "smbdefs.h"
#include "cliapi.h"
#include "clissn.h"
#include "cliez.h"
#include "smbutil.h"
#include "smbnet.h"
#include "smbnbds.h"
#include "clicfg.h"

#if (INCLUDE_RTSMB_CLIENT)

/**
 * Here, we define some of the API calls that don't live elsewhere.  These are mostly
 * unicode and ascii fudging routines.  The actual work is done in either clissn.c or
 * cliez.c.
 */


int rtsmb_cli_init (PFBYTE ip, PFBYTE mask)
{
    if (rtsmb_client_config())
    {
        rtsmb_net_set_ip (ip, mask);
        rtsmb_nbds_init ();

        return 0;
    }

    return -1;
}

void rtsmb_cli_shutdown (void)
{
    int i;

    RTSMB_CLAIM_MUTEX(prtsmb_cli_ctx->sessions_mutex);

    for (i = 0; i < prtsmb_cli_ctx->max_sessions; i++)
    {
        rtsmb_cli_session_close_session (i);
    }

    RTSMB_RELEASE_MUTEX(prtsmb_cli_ctx->sessions_mutex);

    rtsmb_nbds_shutdown ();
}


#if (INCLUDE_RTSMB_UNICODE)

int  rtsmb_cli_session_logon_user (int sid, PFCHAR user, PFCHAR password, PFCHAR domain)
{
    word user_uc [SMBF_FILENAMESIZE + 1], domain_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) user_uc, user, SMBF_FILENAMESIZE);
    ((PFCHAR) user_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) user_uc, user_uc, CFG_RTSMB_USER_CODEPAGE);

    tc_strncpy ((PFCHAR) domain_uc, domain, SMBF_FILENAMESIZE);
    ((PFCHAR) domain_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) domain_uc, domain_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_session_logon_user_rt (sid, user_uc, password, domain_uc);
}

int  rtsmb_cli_session_open (int sid, PFCHAR share, PFCHAR filename, int flags, int mode, PFINT fid)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_session_open_rt (sid, share, filename_uc, flags, mode, fid);
}

int  rtsmb_cli_session_rename (int sid, PFCHAR share, PFCHAR old_filename, PFCHAR new_filename)
{
    word old_filename_uc [SMBF_FILENAMESIZE + 1];
    word new_filename_uc [SMBF_FILENAMESIZE + 1];

    tc_strncpy ((PFCHAR) old_filename_uc, old_filename, SMBF_FILENAMESIZE);
    ((PFCHAR) old_filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) old_filename_uc, old_filename_uc, CFG_RTSMB_USER_CODEPAGE);

    tc_strncpy ((PFCHAR) new_filename_uc, new_filename, SMBF_FILENAMESIZE);
    ((PFCHAR) new_filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) new_filename_uc, new_filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_session_rename_rt (sid, share, old_filename_uc, new_filename_uc);
}

int  rtsmb_cli_session_delete (int sid, PFCHAR share, PFCHAR filename)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_session_delete_rt (sid, share, filename_uc);
}

int  rtsmb_cli_session_mkdir (int sid, PFCHAR share, PFCHAR filename)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_session_mkdir_rt (sid, share, filename_uc);
}

int  rtsmb_cli_session_rmdir (int sid, PFCHAR share, PFCHAR filename)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_session_rmdir_rt (sid, share, filename_uc);
}

int  rtsmb_cli_session_find_first (int sid, PFCHAR share, PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
    word pattern_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) pattern_uc, pattern, SMBF_FILENAMESIZE);
    ((PFCHAR) pattern_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) pattern_uc, pattern_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_session_find_first_rt (sid, share, pattern_uc, pdstat);
}

int  rtsmb_cli_session_stat (int sid, PFCHAR share, PFCHAR filename, PRTSMB_CLI_SESSION_FSTAT pstat)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_session_stat_rt (sid, share, filename_uc, pstat);
}

int  rtsmb_cli_session_chmode (int sid, PFCHAR share, PFCHAR filename, int attributes)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_session_chmode_rt (sid, share, filename_uc, attributes);
}

#if (INCLUDE_RTSMB_CLIENT_EZ)
void rtsmb_cli_ez_set_user (PFCHAR username, PFCHAR password, PFCHAR domain)
{
    word username_uc [SMBF_FILENAMESIZE + 1], domain_name_uc [SMBF_FILENAMESIZE + 1];

    tc_strncpy ((PFCHAR) username_uc, username, SMBF_FILENAMESIZE);
    ((PFCHAR) username_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) username_uc, username_uc, CFG_RTSMB_USER_CODEPAGE);

    tc_strncpy ((PFCHAR) domain_name_uc, domain, SMBF_FILENAMESIZE);
    ((PFCHAR) domain_name_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) domain_name_uc, domain_name_uc, CFG_RTSMB_USER_CODEPAGE);

    rtsmb_cli_ez_set_user_rt (username_uc, password, domain_name_uc);
}

int  rtsmb_cli_ez_open (PFCHAR filename, int flags, int mode)
{
    RTSMB_URI uri;
    int sid;
    int r;

    r = rtsmb_cli_ez_setup_char(filename, &uri, &sid);
    if (r)
    {
        return r;
    }
    return (rtsmb_cli_ez_open_uri(&uri, flags, mode, sid));
}

int  rtsmb_cli_ez_rename (PFCHAR old_filename, PFCHAR new_filename)
{
    word old_filename_uc [SMBF_FILENAMESIZE + 1];
    word new_filename_uc [SMBF_FILENAMESIZE + 1];

    tc_strncpy ((PFCHAR) old_filename_uc, old_filename, SMBF_FILENAMESIZE);
    ((PFCHAR) old_filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) old_filename_uc, old_filename_uc, CFG_RTSMB_USER_CODEPAGE);

    tc_strncpy ((PFCHAR) new_filename_uc, new_filename, SMBF_FILENAMESIZE);
    ((PFCHAR) new_filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) new_filename_uc, new_filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_ez_rename_rt (old_filename_uc, new_filename_uc);
}

int  rtsmb_cli_ez_delete (PFCHAR filename)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_ez_delete_rt (filename_uc);
}

int  rtsmb_cli_ez_mkdir (PFCHAR filename)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_ez_mkdir_rt (filename_uc);
}

int  rtsmb_cli_ez_rmdir (PFCHAR filename)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_ez_rmdir_rt (filename_uc);
}

int  rtsmb_cli_ez_find_first (PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
    word pattern_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) pattern_uc, pattern, SMBF_FILENAMESIZE);
    ((PFCHAR) pattern_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) pattern_uc, pattern_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_ez_find_first_rt (pattern_uc, pdstat);
}

int  rtsmb_cli_ez_stat (PFCHAR filename, PRTSMB_CLI_SESSION_FSTAT pfstat)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_ez_stat_rt (filename_uc, pfstat);
}

int  rtsmb_cli_ez_chmode (PFCHAR filename, int attributes)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_ez_chmode_rt (filename_uc, attributes);
}

int  rtsmb_cli_ez_get_free (PFCHAR filename, PFINT total_units, PFINT free_units, PFINT blocks_per_unit, PFINT block_size)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_ez_get_free_rt (filename_uc, total_units, free_units, blocks_per_unit, block_size);
}

int  rtsmb_cli_ez_get_cwd (PFCHAR filename, rtsmb_size size)
{
    int r;
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    r = rtsmb_cli_ez_get_cwd_rt (filename_uc, size);

    if (r)
    {
        return r;
    }

    rtsmb_util_rtsmb_to_ascii (filename_uc, filename, CFG_RTSMB_USER_CODEPAGE);

    return 0;
}

int  rtsmb_cli_ez_set_cwd (PFCHAR filename)
{
    word filename_uc [SMBF_FILENAMESIZE + 1];
    tc_strncpy ((PFCHAR) filename_uc, filename, SMBF_FILENAMESIZE);
    ((PFCHAR) filename_uc)[SMBF_FILENAMESIZE] = '\0';
    rtsmb_util_ascii_to_rtsmb ((PFCHAR) filename_uc, filename_uc, CFG_RTSMB_USER_CODEPAGE);

    return rtsmb_cli_ez_set_cwd_rt (filename_uc);
}

#endif /* INCLUDE_RTSMB_CLIENT_EZ */

int  rtsmb_cli_session_logon_user_uc (int sid, PFWCS user, PFCHAR password, PFWCS domain)
{
    return rtsmb_cli_session_logon_user_rt (sid, user, password, domain);
}

int  rtsmb_cli_session_open_uc (int sid, PFCHAR share, PFWCS file, int flags, int mode, PFINT fid)
{
    return rtsmb_cli_session_open_rt (sid, share, file, flags, mode, fid);
}

int  rtsmb_cli_session_rename_uc (int sid, PFCHAR share, PFWCS old_filename, PFWCS new_filename)
{
    return rtsmb_cli_session_rename_rt (sid, share, old_filename, new_filename);
}

int  rtsmb_cli_session_delete_uc (int sid, PFCHAR share, PFWCS filename)
{
    return rtsmb_cli_session_delete_rt (sid, share, filename);
}

int  rtsmb_cli_session_mkdir_uc (int sid, PFCHAR share, PFWCS filename)
{
    return rtsmb_cli_session_mkdir_rt (sid, share, filename);
}

int  rtsmb_cli_session_rmdir_uc (int sid, PFCHAR share, PFWCS filename)
{
    return rtsmb_cli_session_rmdir_rt (sid, share, filename);
}

int  rtsmb_cli_session_find_first_uc (int sid, PFCHAR share, PFWCS pattern, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
    return rtsmb_cli_session_find_first_rt (sid, share, pattern, pdstat);
}

int  rtsmb_cli_session_stat_uc (int sid, PFCHAR share, PFWCS file, PRTSMB_CLI_SESSION_FSTAT pstat)
{
    return rtsmb_cli_session_stat_rt (sid, share, file, pstat);
}

int  rtsmb_cli_session_chmode_uc (int sid, PFCHAR share, PFWCS file, int attributes)
{
    return rtsmb_cli_session_chmode_rt (sid, share, file, attributes);
}

#if (INCLUDE_RTSMB_CLIENT_EZ)

void rtsmb_cli_ez_set_user_uc (PFWCS username, PFCHAR password, PFWCS domain )
{
    rtsmb_cli_ez_set_user_rt (username, password, domain);
}

int  rtsmb_cli_ez_open_uc (PFWCS name, int flags, int mode)
{
    return rtsmb_cli_ez_open_rt (name, flags, mode);
}

int  rtsmb_cli_ez_rename_uc (PFWCS old_filename, PFWCS new_filename)
{
    return rtsmb_cli_ez_rename_rt (old_filename, new_filename);
}

int  rtsmb_cli_ez_delete_uc (PFWCS filename)
{
    return rtsmb_cli_ez_delete_rt (filename);
}

int  rtsmb_cli_ez_mkdir_uc (PFWCS filename)
{
    return rtsmb_cli_ez_mkdir_rt (filename);
}

int  rtsmb_cli_ez_rmdir_uc (PFWCS filename)
{
    return rtsmb_cli_ez_rmdir_rt (filename);
}

int  rtsmb_cli_ez_find_first_uc (PFWCS pattern, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
    return rtsmb_cli_ez_find_first_rt (pattern, pdstat);
}

int  rtsmb_cli_ez_stat_uc (PFWCS filename, PRTSMB_CLI_SESSION_FSTAT pfstat)
{
    return rtsmb_cli_ez_stat_rt (filename, pfstat);
}

int  rtsmb_cli_ez_chmode_uc (PFWCS filename, int attributes)
{
    return rtsmb_cli_ez_chmode_rt (filename, attributes);
}

int  rtsmb_cli_ez_get_free_uc (PFWCS filename, PFINT total_units, PFINT free_units, PFINT blocks_per_unit, PFINT block_size)
{
    return rtsmb_cli_ez_get_free_rt (filename, total_units, free_units, blocks_per_unit, block_size);
}

int  rtsmb_cli_ez_get_cwd_uc (PFWCS filename, rtsmb_size size)
{
    return rtsmb_cli_ez_get_cwd_rt (filename, size);
}

int  rtsmb_cli_ez_set_cwd_uc (PFWCS filename)
{
    return rtsmb_cli_ez_set_cwd_rt (filename);
}

#endif /* INCLUDE_RTMSB_CLIENT_EZ */


#else


int  rtsmb_cli_session_logon_user (int sid, PFCHAR user, PFCHAR password, PFCHAR domain)
{
    return rtsmb_cli_session_logon_user_rt (sid, user, password, domain);
}

int  rtsmb_cli_session_open (int sid, PFCHAR share, PFCHAR file, int flags, int mode, PFINT fid)
{
    return rtsmb_cli_session_open_rt (sid, share, file, flags, mode, fid);
}

int  rtsmb_cli_session_rename (int sid, PFCHAR share, PFCHAR old_filename, PFCHAR new_filename)
{
    return rtsmb_cli_session_rename_rt (sid, share, old_filename, new_filename);
}

int  rtsmb_cli_session_delete (int sid, PFCHAR share, PFCHAR filename)
{
    return rtsmb_cli_session_delete_rt (sid, share, filename);
}

int  rtsmb_cli_session_mkdir (int sid, PFCHAR share, PFCHAR filename)
{
    return rtsmb_cli_session_mkdir_rt (sid, share, filename);
}

int  rtsmb_cli_session_rmdir (int sid, PFCHAR share, PFCHAR filename)
{
    return rtsmb_cli_session_rmdir_rt (sid, share, filename);
}

int  rtsmb_cli_session_find_first (int sid, PFCHAR share, PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
    return rtsmb_cli_session_find_first_rt (sid, share, pattern, pdstat);
}

int  rtsmb_cli_session_stat (int sid, PFCHAR share, PFCHAR file, PRTSMB_CLI_SESSION_FSTAT pstat)
{
    return rtsmb_cli_session_stat_rt (sid, share, file, pstat);
}

int  rtsmb_cli_session_chmode (int sid, PFCHAR share, PFCHAR file, int attributes)
{
    return rtsmb_cli_session_chmode (sid, share, file, attributes);
}

#if (INCLUDE_RTSMB_CLIENT_EZ)

void rtsmb_cli_ez_set_user (PFCHAR username, PFCHAR password, PFCHAR domain)
{
    rtsmb_cli_ez_set_user_rt (username, password, domain);
}

int  rtsmb_cli_ez_open (PFCHAR name, int flags, int mode)
{
    return rtsmb_cli_ez_open_rt (name, flags, mode);
}

int  rtsmb_cli_ez_rename (PFCHAR old_filename, PFCHAR new_filename)
{
    return rtsmb_cli_ez_rename_rt (old_filename, new_filename);
}

int  rtsmb_cli_ez_delete (PFCHAR filename)
{
    return rtsmb_cli_ez_delete_rt (filename);
}

int  rtsmb_cli_ez_mkdir (PFCHAR filename)
{
    return rtsmb_cli_ez_mkdir_rt (filename);
}

int  rtsmb_cli_ez_rmdir (PFCHAR filename)
{
    return rtsmb_cli_ez_rmdir_rt (filename);
}

int  rtsmb_cli_ez_find_first (PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
    return rtsmb_cli_ez_find_first_rt (pattern, pdstat);
}

int  rtsmb_cli_ez_stat (PFCHAR filename, PRTSMB_CLI_SESSION_FSTAT pfstat)
{
    return rtsmb_cli_ez_stat_rt (filename, pfstat);
}

int  rtsmb_cli_ez_chmode (PFCHAR filename, int attributes)
{
    return rtsmb_cli_ez_chmode_rt (filename, attributes);
}

int  rtsmb_cli_ez_get_free (PFCHAR filename, PFINT total_units, PFINT free_units, PFINT blocks_per_unit, PFINT block_size)
{
    return rtsmb_cli_ez_get_free_rt (filename, total_units, free_units, blocks_per_unit, block_size);
}

int  rtsmb_cli_ez_get_cwd (PFCHAR filename, rtsmb_size size)
{
    return rtsmb_cli_ez_get_cwd_rt (filename, size);
}

int  rtsmb_cli_ez_set_cwd (PFCHAR filename)
{
    return rtsmb_cli_ez_set_cwd_rt (filename);
}

#endif /* INCLUDE_RTMSB_CLIENT_EZ */

#endif /* INCLUDE_RTSMB_UNICODE */

#endif /* INCLUDE_RTSMB_CLIENT */
