//
// CLIEZ.C -
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
#include "cliez.h"
#include "smbutil.h"
#include "clissn.h"
#include "clicfg.h"
#include "smbnet.h"
#include "rtpwcs.h"
#include "rtptime.h"
#include "rtpnet.h"
#include "rtpthrd.h"
#include "smbdebug.h"

#if (INCLUDE_RTSMB_CLIENT_EZ)


/**
 * Some convenience macros.
 */
#define REQUIRE_SERVER(URI)   {if (!(URI)->valid_server) return RTSMB_CLI_EZ_NO_SERVER_SPECIFIED;}
#define REQUIRE_SHARE(URI)    {if (!(URI)->valid_share) return RTSMB_CLI_EZ_NO_SHARE_SPECIFIED;}
#define REQUIRE_FILENAME(URI) {if (!(URI)->valid_filename) return RTSMB_CLI_EZ_NO_FILENAME_SPECIFIED;}

RTSMB_STATIC rtsmb_char rtsmb_cli_ez_default_username [CFG_RTSMB_MAX_USERNAME_SIZE + 1] =
	{'a', 'n', 'o', 'n', 'y', 'm', 'o', 'u', 's', '\0'};
RTSMB_STATIC char rtsmb_cli_ez_default_password [CFG_RTSMB_MAX_PASSWORD_SIZE + 1] = {'\0'};

RTSMB_STATIC rtsmb_char rtsmb_cli_ez_username [CFG_RTSMB_MAX_USERNAME_SIZE + 1] =
	{'a', 'n', 'o', 'n', 'y', 'm', 'o', 'u', 's', '\0'};
RTSMB_STATIC char rtsmb_cli_ez_password [CFG_RTSMB_MAX_PASSWORD_SIZE + 1] = {'\0'};
RTSMB_STATIC rtsmb_char rtsmb_cli_ez_domain_name [CFG_RTSMB_MAX_DOMAIN_NAME_SIZE + 1] = {'\0'};



void rtsmb_cli_ez_set_user_rt (PFRTCHAR username, PFCHAR password, PFRTCHAR domain)
{
	if (username)
	{
		rtsmb_ncpy (rtsmb_cli_ez_username, username, CFG_RTSMB_MAX_USERNAME_SIZE);
		rtsmb_cli_ez_username[CFG_RTSMB_MAX_USERNAME_SIZE] = '\0';
	}
	else
	{

		rtsmb_cpy (rtsmb_cli_ez_username, rtsmb_cli_ez_default_username);
	}

	if (password)
	{
		tc_strncpy (rtsmb_cli_ez_password, password, CFG_RTSMB_MAX_PASSWORD_SIZE);
		rtsmb_cli_ez_password[CFG_RTSMB_MAX_PASSWORD_SIZE] = '\0';
	}
	else
	{
		tc_strcpy (rtsmb_cli_ez_password, rtsmb_cli_ez_default_password);
	}

	if (domain)
	{
		rtsmb_ncpy (rtsmb_cli_ez_domain_name, domain, CFG_RTSMB_MAX_USERNAME_SIZE);
		rtsmb_cli_ez_domain_name[CFG_RTSMB_MAX_USERNAME_SIZE] = '\0';
	}
	else
	{
        rtsmb_char d[2];
        d[0]=0;
		rtsmb_cpy (rtsmb_cli_ez_domain_name, d);
	}
}


RTSMB_STATIC
PRTSMB_CLI_EZ_THREAD rtsmb_cli_ez_get_current_thread (void)
{
	dword id;
	int oldest = 0, free = -1;
	int i;

	rtp_thread_handle((RTP_HANDLE *) &id);

	RTSMB_CLAIM_MUTEX(prtsmb_cli_ctx->ez_threads_mutex);

	for (i = 0; i < prtsmb_cli_ctx->max_supported_threads; i++)
	{
		if (prtsmb_cli_ctx->ez_threads[i].in_use)
		{
			if (prtsmb_cli_ctx->ez_threads[oldest].timestamp > prtsmb_cli_ctx->ez_threads[i].timestamp)
			{
				oldest = i;
			}

			if (prtsmb_cli_ctx->ez_threads[i].thread_id == id)
			{
				break;
			}
		}
		else
		{
			free = i;
		}
	}

	if (i == prtsmb_cli_ctx->max_supported_threads) /* we didn't find it */
	{
		/* we have to make a new entry.  can we fill an unused hole? */
		if (free >= 0)
		{
			prtsmb_cli_ctx->ez_threads[free].in_use = TRUE;
			prtsmb_cli_ctx->ez_threads[free].thread_id = id;
			prtsmb_cli_ctx->ez_threads[free].working_dir[0] = '\0';
			i = free;
		}
		else
		{
			/* we have to overwrite an old thread's data */
			prtsmb_cli_ctx->ez_threads[oldest].thread_id = id;
			prtsmb_cli_ctx->ez_threads[oldest].working_dir[0] = '\0';
			i = oldest;
		}
	}

	prtsmb_cli_ctx->ez_threads[i].timestamp = rtp_get_system_msec ();

	RTSMB_RELEASE_MUTEX(prtsmb_cli_ctx->ez_threads_mutex);

	return &prtsmb_cli_ctx->ez_threads[i];
}

RTSMB_STATIC
int rtsmb_cli_ez_recognize_uri (PFRTCHAR uri)
{
	int rv = 0;
	rtsmb_char smb_prefix[] = {'s', 'm', 'b', ':', '\0'};
	rtsmb_char forward_prefix[] = {'/', '/', '\0'};
	rtsmb_char backward_prefix[] = {'\\', '\\', '\0'};

	if (rtsmb_ncmp (uri, smb_prefix, 4) == 0)
	{
		uri = uri + 4;
		rv += 4;
	}

	if (rtsmb_ncmp (uri, backward_prefix, 2) == 0)
	{
		rv += 2;
	}
	else if (rtsmb_ncmp (uri, forward_prefix, 2) == 0)
	{
		rv += 2;
	}
	else
	{
		rv = -1;
	}

	return rv;
}

RTSMB_STATIC
int rtsmb_cli_ez_recognize_uri_char (PFCHAR uri)
{
	int rv = 0;
	char smb_prefix[] = {'s', 'm', 'b', ':', '\0'};
	char forward_prefix[] = {'/', '/', '\0'};
	char backward_prefix[] = {'\\', '\\', '\0'};

	if (tc_strncmp (uri, smb_prefix, 4) == 0)
	{
		uri = uri + 4;
		rv += 4;
	}

	if (tc_strncmp (uri, backward_prefix, 2) == 0)
	{
		rv += 2;
	}
	else if (tc_strncmp (uri, forward_prefix, 2) == 0)
	{
		rv += 2;
	}
	else
	{
		rv = -1;
	}

	return rv;
}

/**
 * uri_string is a unicode string describing an SMB resource.
 * uri_struct is a structure describing an SMB resource
 *
 * When this call completes successfully, uri_struct will be filled out
 * with individual fields of the uri.
 *
 * Returns:
 *    a negative value on error
 *    0 on success
 */
RTSMB_STATIC
int rtsmb_cli_ez_parse_uri (PFRTCHAR uri_string_in, PRTSMB_URI uri_struct)
{
	rtsmb_size whole_size, next_size;
	PFRTCHAR next;
	rtsmb_char server_in_rtsmb [RTSMB_NB_NAME_SIZE + 1];
	rtsmb_char share_in_rtsmb [RTSMB_MAX_SHARENAME_SIZE + 1];
	rtsmb_char uri_string_buf[SMBF_FILENAMESIZE + 1];
	PFRTCHAR uri_string = uri_string_in;
	int r;

	if (!uri_string_in)
	{
		return RTSMB_CLI_EZ_INVALID_PATH;
	}

	r = rtsmb_cli_ez_recognize_uri (uri_string);

	if (r < 0)
	{
		/* Not a known smb path style */
		/* So, let's prefix our current working directory */
		PRTSMB_CLI_EZ_THREAD pthread;
		rtsmb_size dirlen;

		pthread = rtsmb_cli_ez_get_current_thread ();
		rtsmb_cpy (uri_string_buf, pthread->working_dir);
		dirlen = rtsmb_len (pthread->working_dir);

		if (uri_string_buf[dirlen - 1] != '/' && uri_string_buf[dirlen - 1] != '\\' &&
			uri_string_in[0] != '/' && uri_string_in[0] != '\\')
		{
			uri_string_buf[dirlen] = '\\';
			dirlen ++;
		}

		rtsmb_ncpy (&uri_string_buf[dirlen], uri_string_in, SMBF_FILENAMESIZE - dirlen);
		uri_string_buf[SMBF_FILENAMESIZE] = '\0';

		uri_string = uri_string_buf;

		r = rtsmb_cli_ez_recognize_uri (uri_string);

		if (r < 0)
		{
			RTSMB_DEBUG_OUTPUT_STR("Don't recognize ",RTSMB_DEBUG_TYPE_ASCII);
			/*RTSMB_DEBUG_OUTPUT_STR(uri_string,RTSMB_DEBUG_TYPE_UNICODE);*/
			RTSMB_DEBUG_OUTPUT_STR("as a valid SMB URL\n",RTSMB_DEBUG_TYPE_ASCII);
			return (-1);	/* we still couldn't recognize it */
		}
	}
	else
	{
		rtsmb_ncpy (uri_string_buf, uri_string_in, SMBF_FILENAMESIZE);
		uri_string_buf[SMBF_FILENAMESIZE] = '\0';
	}

	/* now get rid of all wrong slashes */
	uri_string = uri_string_buf;
	do
	{
		next = uri_string;
		uri_string = rtsmb_chr (uri_string, '/');
		if (uri_string)
		{
			uri_string[0] = '\\';
		}
	}
	while (uri_string);

	/* get rid of trailing slashes */
	whole_size = rtsmb_len (uri_string_buf);
	if (uri_string_buf[whole_size - 1] == '\\')
	{
		uri_string_buf[whole_size - 1] = '\0';
	}

	uri_string = &uri_string_buf[r];

	/* Grab the server part */
	next = rtsmb_chr (uri_string, '\\');
	if (next)
	{
		rtsmb_size to_grab;

		whole_size = rtsmb_len (uri_string);
		next_size = rtsmb_len (next);
		to_grab = MIN (whole_size - next_size, RTSMB_NB_NAME_SIZE);
		rtsmb_ncpy (server_in_rtsmb, uri_string, to_grab);
		server_in_rtsmb[to_grab] = '\0';
		rtsmb_util_rtsmb_to_ascii (server_in_rtsmb, uri_struct->server, CFG_RTSMB_USER_CODEPAGE);
		rtsmb_util_latin_string_toupper (uri_struct->server);
		uri_struct->valid_server = TRUE;
		uri_string = next + 1;
	}
	else
	{
		whole_size = rtsmb_len (uri_string);
		rtsmb_ncpy (server_in_rtsmb, uri_string, RTSMB_NB_NAME_SIZE);
		server_in_rtsmb[RTSMB_NB_NAME_SIZE] = '\0';
		rtsmb_util_rtsmb_to_ascii (server_in_rtsmb, uri_struct->server, CFG_RTSMB_USER_CODEPAGE);
		rtsmb_util_latin_string_toupper (uri_struct->server);
		uri_struct->valid_server = TRUE;
		uri_struct->valid_share = FALSE;
		uri_struct->valid_filename = FALSE;

		return (0);
	}

	/* Get the share part */
	next = rtsmb_chr (uri_string, '\\');
	if (next)
	{
		rtsmb_size to_grab;

		whole_size = next_size;
		next_size = rtsmb_len (next);
		to_grab = MIN (whole_size - next_size - 1, RTSMB_MAX_SHARENAME_SIZE);
		rtsmb_ncpy (share_in_rtsmb, uri_string, to_grab);
		share_in_rtsmb[to_grab] = '\0';
		rtsmb_util_rtsmb_to_ascii (share_in_rtsmb, uri_struct->share, CFG_RTSMB_USER_CODEPAGE);
		rtsmb_util_latin_string_toupper (uri_struct->share);
		uri_struct->valid_share = TRUE;
		uri_string = next + 1;
	}
	else
	{
		whole_size = next_size;
		rtsmb_ncpy (share_in_rtsmb, uri_string, RTSMB_MAX_SHARENAME_SIZE);
		share_in_rtsmb[RTSMB_MAX_SHARENAME_SIZE] = '\0';
		rtsmb_util_rtsmb_to_ascii (share_in_rtsmb, uri_struct->share, CFG_RTSMB_USER_CODEPAGE);
		rtsmb_util_latin_string_toupper (uri_struct->share);
		uri_struct->valid_share = TRUE;
		uri_struct->valid_filename = FALSE;

		return (0);
	}

	/* Get the filename part (the rest of the string) */
	uri_struct->valid_filename = TRUE;
	uri_struct->filename[0] = '\\';

	rtsmb_ncpy (uri_struct->filename + 1, uri_string, (sizeof(uri_struct->filename) - 2) / 2);
	uri_struct->filename[sizeof(uri_struct->filename)-1] = 0;


	return (0);
}

int rtsmb_cli_ez_parse_uri_char (PFCHAR uri_string_in, PRTSMB_URI uri_struct)
{
	rtsmb_size whole_size, next_size;
	PFCHAR next;
	char server_in_rtsmb [RTSMB_NB_NAME_SIZE + 1];
	char share_in_rtsmb [RTSMB_MAX_SHARENAME_SIZE + 1];
	char uri_string_buf[SMBF_FILENAMESIZE + 1];
	PFCHAR uri_string = uri_string_in;
	int r;

	if (!uri_string_in)
	{
		return RTSMB_CLI_EZ_INVALID_PATH;
	}

	r = rtsmb_cli_ez_recognize_uri_char (uri_string);

	if (r < 0)
	{
		/* Not a known smb path style */
		/* So, let's prefix our current working directory */
		PRTSMB_CLI_EZ_THREAD pthread;
		rtsmb_size dirlen;

		pthread = rtsmb_cli_ez_get_current_thread ();
		tc_strcpy (uri_string_buf, (char *) pthread->working_dir);
		dirlen = (rtsmb_size) tc_strlen ((char *) pthread->working_dir);

		if (uri_string_buf[dirlen - 1] != '/' && uri_string_buf[dirlen - 1] != '\\' &&
			uri_string_in[0] != '/' && uri_string_in[0] != '\\')
		{
			uri_string_buf[dirlen] = '\\';
			dirlen ++;
		}

		tc_strncpy (&uri_string_buf[dirlen], uri_string_in, SMBF_FILENAMESIZE - dirlen);
		uri_string_buf[SMBF_FILENAMESIZE] = '\0';

		uri_string = uri_string_buf;

		r = rtsmb_cli_ez_recognize_uri_char (uri_string);

		if (r < 0)
		{
			RTSMB_DEBUG_OUTPUT_STR("Don't recognize ",RTSMB_DEBUG_TYPE_ASCII);
			RTSMB_DEBUG_OUTPUT_STR(uri_string, RTSMB_DEBUG_TYPE_UNICODE);
			RTSMB_DEBUG_OUTPUT_STR(" as a valid SMB URL\n",RTSMB_DEBUG_TYPE_ASCII);
			return (-1);	/* we still couldn't recognize it */
		}
	}
	else
	{
		tc_strncpy (uri_string_buf, uri_string_in, SMBF_FILENAMESIZE);
		uri_string_buf[SMBF_FILENAMESIZE] = '\0';
	}

	/* now get rid of all wrong slashes */
	uri_string = uri_string_buf;
	do
	{
		next = uri_string;
		uri_string = tc_strchr (uri_string, '/');
		if (uri_string)
		{
			uri_string[0] = '\\';
		}
	}
	while (uri_string);

	/* get rid of trailing slashes */
	whole_size = (rtsmb_size) tc_strlen (uri_string_buf);
	if (uri_string_buf[whole_size - 1] == '\\')
	{
		uri_string_buf[whole_size - 1] = '\0';
	}

	uri_string = &uri_string_buf[r];

	/* Grab the server part */
	next = tc_strchr (uri_string, '\\');
	if (next)
	{
		rtsmb_size to_grab;

		whole_size = (rtsmb_size) tc_strlen (uri_string);
		next_size = (rtsmb_size) tc_strlen (next);
		to_grab = MIN (whole_size - next_size, RTSMB_NB_NAME_SIZE);
		tc_strncpy (server_in_rtsmb, uri_string, to_grab);
		server_in_rtsmb[to_grab] = '\0';
//		rtsmb_util_rtsmb_to_ascii (server_in_rtsmb, uri_struct->server);
		tc_strcpy (uri_struct->server, server_in_rtsmb);
		rtsmb_util_latin_string_toupper (uri_struct->server);
		uri_struct->valid_server = TRUE;
		uri_string = next + 1;
	}
	else
	{
		whole_size = (rtsmb_size) tc_strlen (uri_string);
		tc_strncpy (server_in_rtsmb, uri_string, RTSMB_NB_NAME_SIZE);
		server_in_rtsmb[RTSMB_NB_NAME_SIZE] = '\0';
		//rtsmb_util_rtsmb_to_ascii (server_in_rtsmb, uri_struct->server);
		tc_strcpy (uri_struct->server, server_in_rtsmb);
		rtsmb_util_latin_string_toupper (uri_struct->server);
		uri_struct->valid_server = TRUE;
		uri_struct->valid_share = FALSE;
		uri_struct->valid_filename = FALSE;

		return (0);
	}

	/* Get the share part */
	next = tc_strchr (uri_string, '\\');
	if (next)
	{
		rtsmb_size to_grab;

		whole_size = next_size;
		next_size = (rtsmb_size) tc_strlen (next);
		to_grab = MIN (whole_size - next_size - 1, RTSMB_MAX_SHARENAME_SIZE);
		tc_strncpy (share_in_rtsmb, uri_string, to_grab);
		share_in_rtsmb[to_grab] = '\0';
//		rtsmb_util_rtsmb_to_ascii (share_in_rtsmb, uri_struct->share);
		tc_strcpy (uri_struct->share, share_in_rtsmb);
		rtsmb_util_latin_string_toupper (uri_struct->share);
		uri_struct->valid_share = TRUE;
		uri_string = next + 1;
	}
	else
	{
		whole_size = next_size;
		tc_strncpy (share_in_rtsmb, uri_string, RTSMB_MAX_SHARENAME_SIZE);
		share_in_rtsmb[RTSMB_MAX_SHARENAME_SIZE] = '\0';
	//	rtsmb_util_rtsmb_to_ascii (share_in_rtsmb, uri_struct->share);
		tc_strcpy (uri_struct->share, share_in_rtsmb);
		rtsmb_util_latin_string_toupper (uri_struct->share);
		uri_struct->valid_share = TRUE;
		uri_struct->valid_filename = FALSE;

		return (0);
	}

	/* Get the filename part (the rest of the string) */
	uri_struct->valid_filename = TRUE;
	uri_struct->filename[0] = '\\';

	rtsmb_util_ascii_to_rtsmb(uri_string, uri_struct->filename, CFG_RTSMB_USER_CODEPAGE);
	uri_struct->filename[sizeof(uri_struct->filename)-1] = '\0';

	return (0);
}


RTSMB_STATIC
int rtsmb_cli_ez_translate_error (int error)
{
	switch (error)
	{
		case RTSMB_CLI_SSN_RV_FILE_NOT_FOUND:
			return RTSMB_CLI_EZ_FILE_NOT_FOUND;

		case RTSMB_CLI_SSN_RV_BAD_PERMISSIONS:
			return RTSMB_CLI_EZ_BAD_PERMISSIONS;
	}

	return RTSMB_CLI_EZ_SESSION_ERROR;
}

RTSMB_STATIC
PRTSMB_CLI_SESSION rtsmb_cli_ez_close_session (int sid)
{
	rtsmb_cli_session_close_session (sid);

	return 0;
}


RTSMB_STATIC
int rtsmb_cli_ez_make_session (PRTSMB_URI uri)
{
   int sid;
   int ipVer = 4;
   int rv, rv2;
   RTP_ADDR IP;
   unsigned char * ServerIP;
   unsigned char new_return_ip[4];

   ServerIP = (unsigned char*) &IP;

   rv = rtsmb_net_str_to_ip (uri->server, ServerIP);

   if (rv < 0)
   {
      // try NETBIOS
	   if (rtsmb_cli_session_new_with_name (uri->server, TRUE, rtsmb_net_get_broadcast_ip (), &sid, CSSN_DIALECT_NT) < 0)
	   {
         // try DNS
		 rv2 = rtp_net_gethostbyname(new_return_ip, &ipVer, uri->server);
		 IP = (RTP_ADDR) new_return_ip;

         if (rv2 >= 0)
         {
	         if (rtsmb_cli_session_new_with_ip (ServerIP, rtsmb_net_get_broadcast_ip (), TRUE, &sid, CSSN_DIALECT_NT) < 0)
	         {
		         return RTSMB_CLI_EZ_COULD_NOT_CONNECT;
	         }
         }
         else
         {
		      return RTSMB_CLI_EZ_COULD_NOT_CONNECT;
         }
      }
   }
   else
   {
	   if (rtsmb_cli_session_new_with_ip (ServerIP, rtsmb_net_get_broadcast_ip (), TRUE, &sid, CSSN_DIALECT_NT) < 0)
	   {
		   return RTSMB_CLI_EZ_COULD_NOT_CONNECT;
	   }
   }
	if (rtsmb_cli_session_logon_user_rt (sid, rtsmb_cli_ez_username, rtsmb_cli_ez_password, rtsmb_cli_ez_domain_name))
	{
		return RTSMB_CLI_EZ_COULD_NOT_CONNECT;
	}

	return sid;
}

/* makes it if there is room.  if there is an error from this, we can't use the uri */
RTSMB_STATIC
int rtsmb_cli_ez_get_session (PRTSMB_URI uri)
{
	int i, rv = 0;
	BBOOL all_used = TRUE;
	unsigned int current_thread;
	rtp_thread_handle((RTP_HANDLE *) &current_thread);
	/**
	 * Here we search through the sessions list looking for the first session
	 * connected to the server specified in |uri|.
	 *
	 * If we can't find it, we shut down the least recently used session.
	 */

	RTSMB_CLAIM_MUTEX(prtsmb_cli_ctx->sessions_mutex);

	for (i = 0; i < prtsmb_cli_ctx->max_sessions; i++)
	{
		if (prtsmb_cli_ctx->sessions[i].state == CSSN_STATE_DEAD)
		{
			rtsmb_cli_session_close_session (i);
		}

		if (prtsmb_cli_ctx->sessions[i].state == CSSN_STATE_UNUSED)
		{
			all_used = FALSE;
		}

		if (prtsmb_cli_ctx->sessions[i].state != CSSN_STATE_UNUSED &&
			rtsmb_strcasecmp (prtsmb_cli_ctx->sessions[i].server_name, uri->server, CFG_RTSMB_USER_CODEPAGE) == 0 &&
			prtsmb_cli_ctx->sessions[i].owning_thread == current_thread)
		{
			rv = i;
			break;
		}
	}

	if (i == prtsmb_cli_ctx->max_sessions)
	{
		if (all_used)
		{
			int oldest = -1;

			/* we have to find one to bump */
			for (i = 0; i < prtsmb_cli_ctx->max_sessions; i++)
			{
				BBOOL using_session = FALSE;

				/* pick the oldest, if it does not have any open files or searches */
				if (prtsmb_cli_ctx->sessions[i].owning_thread == current_thread && (oldest == -1 ||
					prtsmb_cli_ctx->sessions[i].timestamp < prtsmb_cli_ctx->sessions[oldest].timestamp))
				{
					int j;

					for (j = 0; j < prtsmb_cli_ctx->max_fids_per_session; j++)
					{
						if (prtsmb_cli_ctx->sessions[i].fids[j].real_fid >= 0)
						{
							/* they are using this fid.  we can't close session */
							using_session = TRUE;
						}
					}

					for (j = 0; j < prtsmb_cli_ctx->max_searches_per_session; j++)
					{
						if (prtsmb_cli_ctx->sessions[i].searches[j].sid >= 0)
						{
							/* they are using this search.  we can't close session */
							using_session = TRUE;
						}
					}

					if (prtsmb_cli_ctx->sessions[i].share_search.sid >= 0)
					{
						/* they are using this search.  we can't close session */
						using_session = TRUE;
					}

					if (!using_session)
					{
						oldest = i;
					}
				}
			}

			if (oldest >= 0)
			{
				rtsmb_cli_ez_close_session (oldest);
				rv = rtsmb_cli_ez_make_session (uri);
			}
			else
			{
				rv = RTSMB_CLI_EZ_NOT_ENOUGH_RESOURCES;
			}
		}
		else
		{
			rv = rtsmb_cli_ez_make_session (uri);
		}
	}

	RTSMB_RELEASE_MUTEX(prtsmb_cli_ctx->sessions_mutex);

	return rv;
}


RTSMB_STATIC
int rtsmb_cli_ez_ensure_session_share (PRTSMB_URI uri, int sid)
{
	int i;
	BBOOL all_used = TRUE;

	if (!uri->valid_share)
	{
		return 0;
	}

	/* see if we already have it */
	for (i = 0; i < prtsmb_cli_ctx->max_shares_per_session; i++)
	{
		if (prtsmb_cli_ctx->sessions[sid].shares[i].state == CSSN_SHARE_STATE_UNUSED)
		{
			all_used = FALSE;
		}

		if (prtsmb_cli_ctx->sessions[sid].shares[i].state != CSSN_SHARE_STATE_UNUSED &&
			tc_strcmp (prtsmb_cli_ctx->sessions[sid].shares[i].share_name, uri->share) == 0)
		{
			/* already here, so let's stop. */
			return 0;
		}
	}

	if (all_used)
	{
		/* Hmm...  we have to disconnect a share.  Let's find one with no files on it. */
		for (i = 0; i < prtsmb_cli_ctx->max_shares_per_session; i++)
		{
			int j;
			BBOOL using_files = FALSE;

			if (tc_strcmp (prtsmb_cli_ctx->sessions[sid].shares[i].share_name, "IPC$") == 0)
			{
				continue;
			}

			for (j = 0; j < prtsmb_cli_ctx->max_fids_per_session; j++)
			{
				if (prtsmb_cli_ctx->sessions[sid].fids[j].real_fid >= 0 &&
					prtsmb_cli_ctx->sessions[sid].fids[j].owning_share == &prtsmb_cli_ctx->sessions[sid].shares[i])
				{
					using_files = TRUE;
					break;
				}
			}

			if (!using_files)
			{
				rtsmb_cli_session_disconnect_share (sid, prtsmb_cli_ctx->sessions[sid].shares[i].share_name);
				break;
			}
		}

		if (i == prtsmb_cli_ctx->max_shares_per_session) /* we didn't find *any* shares to get rid of */
		{
			return RTSMB_CLI_EZ_TOO_MANY_FIDS;
		}
	}

	i = rtsmb_cli_session_connect_share (sid, uri->share, rtsmb_cli_ez_password);

	return (i == RTSMB_CLI_SSN_RV_ALREADY_CONNECTED || i == 0) ? 0 : RTSMB_CLI_EZ_TOO_MANY_SHARES;
}

/**
 * EZ fds are encoded thusly:
 * The lowest 8 bits are reserved for the lower layer -- RTSMB_CLI_SESSION.
 * The lowest 9th and 10th bits are reserved for us, as flags.
 * The rest is treated as our session id (at a minimum, therefore, we can hold 2^6 sessions).
 *
 * The flags indicate what kind of search is being done.  A 0 means a normal search.  A 1 means a share search.
 * A 2 means a server search, and we need to cycle.  A 3 means a server search and we don't need to cycle.
 */

RTSMB_STATIC
int rtsmb_cli_ez_fd_session_to_ez (int fd, int i, byte flag)
{
	return (fd & 0xFF) | (i << 10) | ((flag & 0x03) << 8);
}

RTSMB_STATIC
int rtsmb_cli_ez_fd_ez_to_session (int fd, PFINT index, PFBYTE flag)
{
	int i, session_fd;

	session_fd = fd & 0xFF;
	i = fd >> 10;

	*index = i;
	if (flag)
	{
		*flag = (byte) ((fd & 0x0300) >> 8);
	}

	return session_fd;
}

RTSMB_STATIC
void rtsmb_cli_ez_init (void)
{
	if (!rtsmb_client_config_initialized)
	{
		rtsmb_client_config ();
	}
}

RTSMB_STATIC
int rtsmb_cli_ez_setup (PFRTCHAR name, PRTSMB_URI uri, PFINT session)
{
	int tmp = -1;
	int r;

	rtsmb_cli_ez_init ();

	if (rtsmb_cli_ez_parse_uri (name, uri) < 0)
	{
		return RTSMB_CLI_EZ_INVALID_PATH;
	}

	if (uri->valid_server && uri->valid_share) /* user wants to do something *on* the server, so we need to connect to it */
	{
		tmp = rtsmb_cli_ez_get_session (uri);
		if (tmp < 0)
		{
			return tmp;
		}

		if (uri->valid_filename) /* user wants to do something *on* the share, so we need to connect to it */
		{
			r = rtsmb_cli_ez_ensure_session_share (uri, tmp);
			if (r)
			{
				return r;
			}
		}
	}

	if (session)
	{
		*session = tmp;
	}

	return 0;
}

int rtsmb_cli_ez_setup_char (PFCHAR name, PRTSMB_URI uri, PFINT session)
{
	int tmp = -1;
	int r;

	rtsmb_cli_ez_init ();

	if (rtsmb_cli_ez_parse_uri_char (name, uri) < 0)
	{
		return RTSMB_CLI_EZ_INVALID_PATH;
	}

	if (uri->valid_server && uri->valid_share) /* user wants to do something *on* the server, so we need to connect to it */
	{
		tmp = rtsmb_cli_ez_get_session (uri);
		if (tmp < 0)
		{
			return tmp;
		}

		if (uri->valid_filename) /* user wants to do something *on* the share, so we need to connect to it */
		{
			r = rtsmb_cli_ez_ensure_session_share (uri, tmp);
			if (r)
			{
				return r;
			}
		}
	}

	if (session)
	{
		*session = tmp;
	}

	return 0;
}



RTSMB_STATIC
int rtsmb_cli_ez_setup_by_fd (int fid, PFINT session_fid, PFINT i, PFBYTE pbool)
{
	int tmpi;
	byte tmp_bool;

	rtsmb_cli_ez_init ();

	*session_fid = rtsmb_cli_ez_fd_ez_to_session (fid, &tmpi, &tmp_bool);

	if (*session_fid < 0)
	{
		return RTSMB_CLI_EZ_BAD_FD;
	}

	*i = tmpi;
	if (pbool)
	{
		*pbool = tmp_bool;
	}

	return 0;
}

int rtsmb_cli_ez_open_rt (PFRTCHAR filename, int flags, int mode)
{
	RTSMB_URI uri;
	int sid;
	int r;

	r = rtsmb_cli_ez_setup (filename, &uri, &sid);
	if (r)
	{
		return r;
	}

	return (rtsmb_cli_ez_open_uri(&uri, flags, mode, sid));
}

int rtsmb_cli_ez_open_uri (PRTSMB_URI uri, int flags, int mode, int sid)
{
	int r;
	int fid;

	REQUIRE_SERVER (uri);
	REQUIRE_SHARE (uri);
	REQUIRE_FILENAME (uri);

	r = rtsmb_cli_session_open_rt (sid, uri->share, uri->filename, flags, mode, &fid);
	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	fid = rtsmb_cli_ez_fd_session_to_ez (fid, sid, FALSE);

	return fid;
}

int rtsmb_cli_ez_read (int fd, PFBYTE buffer, unsigned int count)
{
	int r, session_fd, i;
	int bytes_read;
	int bytes_returned = 0;

	r = rtsmb_cli_ez_setup_by_fd (fd, &session_fd, &i, 0);
	if (r)
	{
		return r;
	}

	/* cli_session can only handle so much data.  Here, we loop until we've got all
	   of 'count' */
	do
	{
		int to_read;

		to_read = (int) (count > RTSMB_CLI_SESSION_MAX_DATA_BYTES ? RTSMB_CLI_SESSION_MAX_DATA_BYTES : count);
		r = rtsmb_cli_session_read (i, session_fd, buffer, to_read, &bytes_read);
		if (r)
		{
			return rtsmb_cli_ez_translate_error (r);
		}

		bytes_returned += bytes_read;
		buffer += bytes_read;

		/* are we short on bytes?  If so, end loop */
		if (bytes_read < to_read)
		{
			break;
		}

		count = count - (unsigned int)to_read;
	}
	while (count != 0);

	return bytes_returned;
}

int rtsmb_cli_ez_write (int fd, PFBYTE buffer, unsigned int count)
{
	int r, session_fd, i;
	int bytes_written;
	int bytes_returned = 0;

	r = rtsmb_cli_ez_setup_by_fd (fd, &session_fd, &i, 0);
	if (r)
	{
		return r;
	}

	/* cli_session can only handle so much data.  Here, we loop until we've got all
	   of 'count' */
	do
	{
		int to_write;

		to_write = (int) (count > RTSMB_CLI_SESSION_MAX_DATA_BYTES ? RTSMB_CLI_SESSION_MAX_DATA_BYTES : count);
		r = rtsmb_cli_session_write (i, session_fd, buffer, to_write, &bytes_written);
		if (r)
		{
			return rtsmb_cli_ez_translate_error (r);
		}

		bytes_returned += bytes_written;
		buffer += bytes_written;

		/* are we short on bytes?  If so, end loop */
		if (bytes_written < to_write)
		{
			break;
		}

		count = count - (unsigned int)to_write;
	}
	while (count != 0);

	return bytes_returned;
}

long rtsmb_cli_ez_seek (int fd, long offset, int origin)
{
	int r, session_fd, i;
	long new_offset;

	r = rtsmb_cli_ez_setup_by_fd (fd, &session_fd, &i, 0);
	if (r)
	{
		return r;
	}

	r = rtsmb_cli_session_seek (i, session_fd, offset, origin, &new_offset);
	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	return new_offset;
}

int rtsmb_cli_ez_close (int fd)
{
	int r, session_fd, i;

	r = rtsmb_cli_ez_setup_by_fd (fd, &session_fd, &i, 0);
	if (r)
	{
		return r;
	}

	r = rtsmb_cli_session_close (i, session_fd);
	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	return 0;
}

/* returns 0 on success */
int rtsmb_cli_ez_truncate (int fd, long offset)
{
	int r, session_fd, i;

	r = rtsmb_cli_ez_setup_by_fd (fd, &session_fd, &i, 0);
	if (r)
	{
		return r;
	}

	r = rtsmb_cli_session_truncate (i, session_fd, offset);
	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	return 0;
}

/* returns 0 on success */
int rtsmb_cli_ez_flush (int fd)
{
	int r, session_fd, i;

	r = rtsmb_cli_ez_setup_by_fd (fd, &session_fd, &i, 0);
	if (r)
	{
		return r;
	}

	r = rtsmb_cli_session_flush (i, session_fd);
	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	return 0;
}

/* returns 0 on success */
/* old_filename and new_filename must be on the same server and share */
int rtsmb_cli_ez_rename_rt (PFRTCHAR old_filename, PFRTCHAR new_filename)
{
	RTSMB_URI old_uri, new_uri;
	int sid, sid2;
	int r;

	r = rtsmb_cli_ez_setup (old_filename, &old_uri, &sid);
	if (r)
	{
		return r;
	}
	REQUIRE_SERVER (&old_uri);
	REQUIRE_SHARE (&old_uri);
	REQUIRE_FILENAME (&old_uri);

	r = rtsmb_cli_ez_setup (new_filename, &new_uri, &sid2);
	if (r)
	{
		return r;
	}
	REQUIRE_SERVER (&new_uri);
	REQUIRE_SHARE (&new_uri);
	REQUIRE_FILENAME (&new_uri);

	if (sid != sid2)
	{
		return RTSMB_CLI_EZ_NOT_SAME_SESSION;
	}

	r = rtsmb_cli_session_rename_rt (sid, new_uri.share, old_uri.filename, new_uri.filename);
	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	return 0;
}

/* returns 0 on success */
int rtsmb_cli_ez_delete_rt (PFRTCHAR filename)
{
	RTSMB_URI uri;
	int sid;
	int r;

	r = rtsmb_cli_ez_setup (filename, &uri, &sid);
	if (r)
	{
		return r;
	}
	REQUIRE_SERVER (&uri);
	REQUIRE_SHARE (&uri);
	REQUIRE_FILENAME (&uri);

	r = rtsmb_cli_session_delete_rt (sid, uri.share, uri.filename);
	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	return 0;
}

/* returns 0 on success */
int rtsmb_cli_ez_mkdir_rt (PFRTCHAR filename)
{
	RTSMB_URI uri;
	int sid;
	int r;

	r = rtsmb_cli_ez_setup (filename, &uri, &sid);
	if (r)
	{
		return r;
	}
	REQUIRE_SERVER (&uri);
	REQUIRE_SHARE (&uri);
	REQUIRE_FILENAME (&uri);

	r = rtsmb_cli_session_mkdir_rt (sid, uri.share, uri.filename);
	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	return 0;
}

/* returns 0 on success */
int rtsmb_cli_ez_rmdir_rt (PFRTCHAR filename)
{
	RTSMB_URI uri;
	int sid;
	int r;

	r = rtsmb_cli_ez_setup (filename, &uri, &sid);
	if (r)
	{
		return r;
	}
	REQUIRE_SERVER (&uri);
	REQUIRE_SHARE (&uri);
	REQUIRE_FILENAME (&uri);

	r = rtsmb_cli_session_rmdir_rt (sid, uri.share, uri.filename);
	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	return 0;
}

/* returns 0 if no result, 1 if something */
int rtsmb_cli_ez_find_first_rt (PFRTCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
	RTSMB_URI uri;
	int sid;
	int r;

	r = rtsmb_cli_ez_setup (pattern, &uri, &sid);
	if (r)
	{
		return r;
	}

	/**
	 * There are three cases.  One is that a share is specified, in which
	 * case we do a normal find_first.  Another is that a share is not,
	 * and we then do a share_find_first.  The last is that no server is
	 * specified, so we do a server_enum_start call.
	 */
	if (uri.valid_filename)
	{
		r = rtsmb_cli_session_find_first_rt (sid, uri.share, uri.filename, pdstat);
		pdstat->sid = rtsmb_cli_ez_fd_session_to_ez (pdstat->sid, sid, 0);

		if (!r || r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
		{
			return 1;
		}
		else if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
		{
			return 0;
		}
		else if (r)
		{
			r = rtsmb_cli_ez_translate_error (r);
			return r;
		}
	}
	else if (uri.valid_share)
	{
		RTSMB_CLI_SESSION_SSTAT sstat;
		PRTSMB_CLI_EZ_SEARCH psearch;

		r = rtsmb_cli_session_share_find_first (sid, &sstat);
		pdstat->sid = rtsmb_cli_ez_fd_session_to_ez (sstat.sid, sid, TRUE);

		/* we need to save the pattern so that find_next can grab it */
		psearch = &prtsmb_cli_ctx->ez_share_searches[sid];
		psearch->unicode = INCLUDE_RTSMB_UNICODE ? TRUE : FALSE;
		rtsmb_util_ascii_to_rtsmb (uri.share, psearch->pattern, CFG_RTSMB_USER_CODEPAGE);
		psearch->sid = pdstat->sid;

		if (!r || r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
		{
			/* make sure it is a disk share */
			if (sstat.type != RTSMB_SHARE_TYPE_DISK)
			{
				return rtsmb_cli_ez_find_next (pdstat);
			}

			rtsmb_util_ascii_to_rtsmb (sstat.name, (PFRTCHAR) pdstat->filename, CFG_RTSMB_USER_CODEPAGE);
			pdstat->unicode = INCLUDE_RTSMB_UNICODE ? TRUE : FALSE;

			/* we have to make sure it matches the pattern */
#if (INCLUDE_RTSMB_UNICODE)
			if (rtsmb_util_unicode_patcmp ((PFWCS) psearch->pattern, (PFWCS) pdstat->filename, 1))
#else
			if (rtsmb_util_ascii_patcmp (psearch->pattern, pdstat->filename, 1))
#endif
			{
				pdstat->unicode = INCLUDE_RTSMB_UNICODE ? TRUE : FALSE;
				pdstat->fattributes = RTP_FILE_ATTRIB_ISDIR | RTP_FILE_ATTRIB_RDONLY;
				pdstat->fatime64.low_time = 0;
				pdstat->fatime64.high_time = 0;
				pdstat->fwtime64.low_time = 0;
				pdstat->fwtime64.high_time = 0;
				pdstat->fctime64.low_time = 0;
				pdstat->fctime64.high_time = 0;
				pdstat->fhtime64.low_time = 0;
				pdstat->fhtime64.high_time = 0;
				pdstat->fsize = 0;
				return 1;
			}
			else
			{
				return rtsmb_cli_ez_find_next (pdstat);
			}
		}
		else if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
		{
			return 0;
		}
		else if (r)
		{
			return rtsmb_cli_ez_translate_error (r);
		}
	}
	else	/* server enum */
	{
		int i;
		PRTSMB_CLI_EZ_SEARCH psearch;

		/* find a free pointer */
		for (i = 0; i < prtsmb_cli_ctx->max_server_searches; i++)
		{
			if (prtsmb_cli_ctx->ez_server_stats[i].sid == -1)
			{
				break;
			}
		}

		if (i == prtsmb_cli_ctx->max_server_searches)
		{
			/* no free pointers... */
			return RTSMB_CLI_EZ_NOT_ENOUGH_RESOURCES;
		}

		pdstat->sid = rtsmb_cli_ez_fd_session_to_ez (prtsmb_cli_ctx->ez_server_stats[i].sid, i, 2);

		r = rtsmb_cli_session_server_enum_start (&prtsmb_cli_ctx->ez_server_stats[i], 0, 0);

		if (r != RTSMB_CLI_SSN_RV_OK)
		{
			return rtsmb_cli_ez_translate_error (r);
		}

		do
		{
            r = rtsmb_cli_session_server_enum_cycle (&prtsmb_cli_ctx->ez_server_stats[i], 10); /* changed from -1 to 10 - sprspr */
		} while (r == 0);

		if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
		{
			return 0;
		}
		else if (r != RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
		{
			return rtsmb_cli_ez_translate_error (r);
		}

		/* ok.  now we can start grabbing names and setting up */
		pdstat->sid = rtsmb_cli_ez_fd_session_to_ez (prtsmb_cli_ctx->ez_server_stats[i].sid, i, 3);

		/* we need to save the pattern so that find_next can grab it */
		psearch = &prtsmb_cli_ctx->ez_server_searches[i];
		psearch->unicode = INCLUDE_RTSMB_UNICODE ? TRUE : FALSE;
		rtsmb_util_ascii_to_rtsmb (uri.server, psearch->pattern, CFG_RTSMB_USER_CODEPAGE);
		psearch->sid = pdstat->sid;

		r = rtsmb_cli_session_server_enum_next_name (&prtsmb_cli_ctx->ez_server_stats[i], pdstat->filename);

		if (r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
		{
			rtsmb_util_ascii_to_rtsmb (pdstat->filename, (PFRTCHAR) pdstat->filename, CFG_RTSMB_USER_CODEPAGE);

			/* we have to make sure it matches the pattern */
#if (INCLUDE_RTSMB_UNICODE)
			if (rtsmb_util_unicode_patcmp ((PFWCS) psearch->pattern, (PFWCS) pdstat->filename, TRUE))
#else
			if (rtsmb_util_ascii_patcmp (psearch->pattern, pdstat->filename, TRUE))
#endif
			{
				pdstat->unicode = INCLUDE_RTSMB_UNICODE ? TRUE : FALSE;
				pdstat->fattributes = RTP_FILE_ATTRIB_ISDIR | RTP_FILE_ATTRIB_RDONLY;
				pdstat->fatime64.low_time = 0;
				pdstat->fatime64.high_time = 0;
				pdstat->fwtime64.low_time = 0;
				pdstat->fwtime64.high_time = 0;
				pdstat->fctime64.low_time = 0;
				pdstat->fctime64.high_time = 0;
				pdstat->fhtime64.low_time = 0;
				pdstat->fhtime64.high_time = 0;
				pdstat->fsize = 0;
				return 1;
			}
			else
			{
				return rtsmb_cli_ez_find_next (pdstat);
			}
		}
		else if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
		{
			/* because now we need to cycle again */
			pdstat->sid = rtsmb_cli_ez_fd_session_to_ez (prtsmb_cli_ctx->ez_server_stats[i].sid, i, 2);
			return rtsmb_cli_ez_find_next (pdstat);
		}
		else if (r)
		{
			return rtsmb_cli_ez_translate_error (r);
		}
	}

	return 0;
}

/* returns 0 if no result, 1 if something */
int rtsmb_cli_ez_find_next (PRTSMB_CLI_SESSION_DSTAT pdstat)
{
	int r, session_fd, ez_fd, i;
	byte flag;

	r = rtsmb_cli_ez_setup_by_fd (pdstat->sid, &session_fd, &i, &flag);
	if (r)
	{
		return r;
	}

	if (flag == 0)
	{
		ez_fd = pdstat->sid;
		pdstat->sid = session_fd;
		r = rtsmb_cli_session_find_next (i, pdstat);
		pdstat->sid = ez_fd;
		if (!r || r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
		{
			return 1;
		}
		else if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
		{
			return 0;
		}
		else if (r)
		{
			return rtsmb_cli_ez_translate_error (r);
		}
	}
	else if (flag == 1)
	{
		RTSMB_CLI_SESSION_SSTAT sstat;

		sstat.sid = session_fd;
		r = rtsmb_cli_session_share_find_next (i, &sstat);

		if (!r || r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
		{
			PRTSMB_CLI_EZ_SEARCH psearch;

			/* make sure it is a disk share */
			if (sstat.type != RTSMB_SHARE_TYPE_DISK)
			{
				return rtsmb_cli_ez_find_next (pdstat);
			}

			psearch = &prtsmb_cli_ctx->ez_share_searches[i];

			if (psearch->unicode)
			{
				rtsmb_util_ascii_to_unicode (sstat.name, (PFWCS) pdstat->filename, CFG_RTSMB_USER_CODEPAGE);

				/* we have to make sure it matches the pattern */
				if (rtsmb_util_unicode_patcmp ((PFWCS) psearch->pattern, (PFWCS) pdstat->filename, TRUE))
				{
					pdstat->unicode = TRUE;
					pdstat->fattributes = RTP_FILE_ATTRIB_ISDIR | RTP_FILE_ATTRIB_RDONLY;
					pdstat->fatime64.low_time = 0;
					pdstat->fatime64.high_time = 0;
					pdstat->fwtime64.low_time = 0;
					pdstat->fwtime64.high_time = 0;
					pdstat->fctime64.low_time = 0;
					pdstat->fctime64.high_time = 0;
					pdstat->fhtime64.low_time = 0;
					pdstat->fhtime64.high_time = 0;
					pdstat->fsize = 0;
					return 1;
				}
				else
				{
					return rtsmb_cli_ez_find_next (pdstat);
				}
			}
			else
			{
				/* we have to make sure it matches the pattern */
				if (rtsmb_util_ascii_patcmp ((PFCHAR) psearch->pattern, sstat.name, TRUE))
				{
					tc_strcpy (pdstat->filename, sstat.name);
					pdstat->unicode = FALSE;
					pdstat->fattributes = RTP_FILE_ATTRIB_ISDIR | RTP_FILE_ATTRIB_RDONLY;
					pdstat->fatime64.low_time = 0;
					pdstat->fatime64.high_time = 0;
					pdstat->fwtime64.low_time = 0;
					pdstat->fwtime64.high_time = 0;
					pdstat->fctime64.low_time = 0;
					pdstat->fctime64.high_time = 0;
					pdstat->fhtime64.low_time = 0;
					pdstat->fhtime64.high_time = 0;
					pdstat->fsize = 0;
					return 1;
				}
				else
				{
					return rtsmb_cli_ez_find_next (pdstat);
				}
			}
		}
		else if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
		{
			return 0;
		}
		else if (r)
		{
			return rtsmb_cli_ez_translate_error (r);
		}
	}
	else if (flag == 2)
	{
		prtsmb_cli_ctx->ez_server_stats[i].sid = session_fd;

		do
		{
            r = rtsmb_cli_session_server_enum_cycle (&prtsmb_cli_ctx->ez_server_stats[i], 10);  /* changed from -1 to 10 - sprspr */
		} while (r == 0);

		if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
		{
			return 0;
		}
		else if (r != RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
		{
			return rtsmb_cli_ez_translate_error (r);
		}
	}

	if (flag == 2 || flag == 3)
	{
		prtsmb_cli_ctx->ez_server_stats[i].sid = session_fd;

		pdstat->sid = rtsmb_cli_ez_fd_session_to_ez (prtsmb_cli_ctx->ez_server_stats[i].sid, i, 3);
		r = rtsmb_cli_session_server_enum_next_name (&prtsmb_cli_ctx->ez_server_stats[i], pdstat->filename);

		if (r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
		{
			PRTSMB_CLI_EZ_SEARCH psearch;

			psearch = &prtsmb_cli_ctx->ez_server_searches[i];

			if (psearch->unicode)
			{
				rtsmb_util_ascii_to_unicode (pdstat->filename, (PFWCS) pdstat->filename, CFG_RTSMB_USER_CODEPAGE);

				/* we have to make sure it matches the pattern */
				if (rtsmb_util_unicode_patcmp ((PFWCS) psearch->pattern, (PFWCS) pdstat->filename, TRUE))
				{
					pdstat->unicode = TRUE;
					pdstat->fattributes = RTP_FILE_ATTRIB_ISDIR | RTP_FILE_ATTRIB_RDONLY;
					pdstat->fatime64.low_time = 0;
					pdstat->fatime64.high_time = 0;
					pdstat->fwtime64.low_time = 0;
					pdstat->fwtime64.high_time = 0;
					pdstat->fctime64.low_time = 0;
					pdstat->fctime64.high_time = 0;
					pdstat->fhtime64.low_time = 0;
					pdstat->fhtime64.high_time = 0;
					pdstat->fsize = 0;
					return 1;
				}
				else
				{
					return rtsmb_cli_ez_find_next (pdstat);
				}
			}
			else
			{
				/* we have to make sure it matches the pattern */
				if (rtsmb_util_ascii_patcmp ((PFCHAR) psearch->pattern, pdstat->filename, TRUE))
				{
					pdstat->unicode = FALSE;
					pdstat->fattributes = RTP_FILE_ATTRIB_ISDIR | RTP_FILE_ATTRIB_RDONLY;
					pdstat->fatime64.low_time = 0;
					pdstat->fatime64.high_time = 0;
					pdstat->fwtime64.low_time = 0;
					pdstat->fwtime64.high_time = 0;
					pdstat->fctime64.low_time = 0;
					pdstat->fctime64.high_time = 0;
					pdstat->fhtime64.low_time = 0;
					pdstat->fhtime64.high_time = 0;
					pdstat->fsize = 0;
					return 1;
				}
				else
				{
					return rtsmb_cli_ez_find_next (pdstat);
				}
			}
		}
		else if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
		{
			/* we need to cycle */
			pdstat->sid = rtsmb_cli_ez_fd_session_to_ez (prtsmb_cli_ctx->ez_server_stats[i].sid, i, 2);
			return rtsmb_cli_ez_find_next (pdstat);
		}
		else if (r)
		{
			return rtsmb_cli_ez_translate_error (r);
		}
	}

	return 0;
}

void rtsmb_cli_ez_find_close (PRTSMB_CLI_SESSION_DSTAT pdstat)
{
	int session_fd, ez_fd, i;
	BBOOL flag;
	int r;

	r = rtsmb_cli_ez_setup_by_fd (pdstat->sid, &session_fd, &i, &flag);
	if (r)
	{
		return;
	}

	if (flag == 0)
	{
		ez_fd = pdstat->sid;
		pdstat->sid = session_fd;
		rtsmb_cli_session_find_close (i, pdstat);
		pdstat->sid = ez_fd;
	}
	else if (flag == 1)
	{
		RTSMB_CLI_SESSION_SSTAT sstat;

		sstat.sid = session_fd;
		rtsmb_cli_session_share_find_close (i, &sstat);
	}
	else if (flag == 2 || flag == 3)
	{
		rtsmb_cli_session_server_enum_close (&prtsmb_cli_ctx->ez_server_stats[i]);
		prtsmb_cli_ctx->ez_server_stats[i].sid = -1;
	}
}

int rtsmb_cli_ez_stat_rt (PFRTCHAR filename, PRTSMB_CLI_SESSION_FSTAT pfstat)
{
	RTSMB_URI uri;
	int sid;
	int r;

	r = rtsmb_cli_ez_setup (filename, &uri, &sid);
	if (r)
	{
		return r;
	}
	REQUIRE_SERVER (&uri);
	REQUIRE_SHARE (&uri);

	if (uri.valid_filename)
	{
		r = rtsmb_cli_session_stat_rt (sid, uri.share, uri.filename, pfstat);
		if (r)
		{
			return rtsmb_cli_ez_translate_error (r);
		}
	}
	else
	{
		/* make up stuff for the share */
		pfstat->fsize = 0;
		pfstat->fatime64.low_time = 0;
		pfstat->fatime64.high_time = 0;
		pfstat->fwtime64.low_time = 0;
		pfstat->fwtime64.high_time = 0;
		pfstat->fctime64.low_time = 0;
		pfstat->fctime64.high_time = 0;
		pfstat->fhtime64.low_time = 0;
		pfstat->fhtime64.high_time = 0;
		pfstat->fattributes = RTP_FILE_ATTRIB_ISDIR | RTP_FILE_ATTRIB_RDONLY;
	}

	return 0;
}

int rtsmb_cli_ez_chmode_rt (PFRTCHAR filename, int attributes)
{
	RTSMB_URI uri;
	int sid;
	int r;

	r = rtsmb_cli_ez_setup (filename, &uri, &sid);
	if (r)
	{
		return r;
	}
	REQUIRE_SERVER (&uri);
	REQUIRE_SHARE (&uri);
	REQUIRE_FILENAME (&uri);

	r = rtsmb_cli_session_chmode_rt (sid, uri.share, uri.filename, attributes);
	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	return 0;
}


int rtsmb_cli_ez_get_free_rt (PFRTCHAR filename, PFINT total_blocks, PFINT free_blocks, PFINT sectors_per_block, PFINT bytes_per_sector)
{
	RTSMB_URI uri;
	int sid;
	int r;

	r = rtsmb_cli_ez_setup (filename, &uri, &sid);
	if (r)
	{
		return r;
	}
	REQUIRE_SERVER (&uri);
	REQUIRE_SHARE (&uri);

	r = rtsmb_cli_session_get_free (sid, uri.share, total_blocks, free_blocks, sectors_per_block, bytes_per_sector);

	if (r)
	{
		return rtsmb_cli_ez_translate_error (r);
	}

	return 0;
}

int rtsmb_cli_ez_set_cwd_rt (PFRTCHAR filename)
{
	RTSMB_URI uri;
	PRTSMB_CLI_EZ_THREAD pthread;
	int r;

	r = rtsmb_cli_ez_setup (filename, &uri, 0);
	if (r)
	{
		return r;
	}

	pthread = rtsmb_cli_ez_get_current_thread ();

	if (SMBF_FILENAMESIZE < rtsmb_len (filename))
	{
		return RTSMB_CLI_EZ_NOT_ENOUGH_RESOURCES;
	}
	else
	{
		rtsmb_char empty[] = {'\0'};
		rtsmb_char slash[] = {'\\', '\0'};
		rtsmb_char slashslash[] = {'\\', '\\', '\0'};

		rtsmb_cpy (pthread->working_dir, empty);
		if (uri.valid_server)
		{
			rtsmb_cat (pthread->working_dir, slashslash);
			rtsmb_util_ascii_to_rtsmb (uri.server, &pthread->working_dir[rtsmb_len (pthread->working_dir)], CFG_RTSMB_USER_CODEPAGE);

			if (uri.valid_share)
			{
				rtsmb_cat (pthread->working_dir, slash);
				rtsmb_util_ascii_to_rtsmb (uri.share, &pthread->working_dir[rtsmb_len (pthread->working_dir)], CFG_RTSMB_USER_CODEPAGE);

				if (uri.valid_filename)
				{
					rtsmb_cat (pthread->working_dir, uri.filename);
				}
			}
		}
	}

	return 0;
}

int rtsmb_cli_ez_get_cwd_rt (PFRTCHAR dest, rtsmb_size size)
{
	PRTSMB_CLI_EZ_THREAD pthread;

	pthread = rtsmb_cli_ez_get_current_thread ();

	if (size < rtsmb_len (pthread->working_dir) + 1)
	{
		return RTSMB_CLI_EZ_NOT_ENOUGH_RESOURCES;
	}
	else
	{
		rtsmb_cpy (dest, pthread->working_dir);
		return 0;
	}
}

#endif /* INCLUDE_RTMSB_CLIENT_EZ */
