#ifndef __CLI_API_H__
#define __CLI_API_H__

#include "smbdefs.h" /* for all of the typedefs used here */
#include "clissn.h"  /* for all of the structs used here */
#include "cliez.h"   /* for all of the error codes there */


#if (INCLUDE_RTSMB_CLIENT)

/**
 * NOTE:  Before using any of these API calls, it is recommended that you call
 *       rtsmb_cli_init (IP, MASK).  This initializes client data.
 */

/**
 * Here is the basic API.  Look further below to learn about an easier-to-use
 * API.  Here, you initialize a session with a call to rtsmb_cli_session_new_with_name
 * or rtsmb_cli_session_new_with_ip.  These will return either an error code or a
 * non-negative number which is the session id and must be passed to the other
 * API calls.
 *
 * A session can either be blocking or non-blocking.  If it is blocking, each
 * API call blocks until it completes its task.  No cycling need be done in this
 * case.  If it is non-blocking, each API call returns a job number that you
 * may attach one callback to.  When that job is complete, the callback will
 * be called with the specified data.  See clissn.h for the definition of
 * RTSMB_JOB_CALLBACK.  When in non-blocking mode, you need to call
 * rtsmb_cli_session_cycle periodically to let the session conduct its business.
 * This lets you do asynchronous I/O.
 *
 * You should always connect a user of some sort.  You are allowed only one
 * user at a time on a session.  If you don't anticipate the need for one,
 * or are connecting to a share-level server (where logons aren't necessary),
 * connect with the username "anonymous" and an empty-string password.
 * Some servers won't let you do anything before you do this.  A user should
 * be logged on before you do anything else with a session.
 *
 * You must pass each I/O-oriented API call a session identifier and a share
 * name.  You must first have connected to the share with a
 * rtsmb_cli_session_connect_share call.
 *
 * If a call returns RTSMB_CLI_SSN_RV_DEAD, then it has become untenable.  You should
 * then call rtsmb_cli_session_close_session (sid) on it.  Look in clissn.h
 * for a complete list of error codes.
 */


/******************************************************************************

 rtsmb_cli_init - initialize global client data

    ip - the host ip
    mask_ip - our subnet mask

 Description
    This initializes the global client data and prepares it to be used.
    This call must be made first, before any others.

 See Code
    cliapi.c

 See Also
    rtsmb_cli_shutdown

 Returns
    zero on success or a negative value on error


******************************************************************************/
int  rtsmb_cli_init (PFBYTE ip, PFBYTE mask);


/******************************************************************************

 rtsmb_cli_shutdown - gracefully cleans up after client

 Description
    This gracefully shuts down any resources used by the client.  It will also
    stop any current client sessions.

 See Code
    cliapi.c

 See Also
    rtsmb_cli_init

******************************************************************************/
void rtsmb_cli_shutdown (void);



/******************************************************************************

 rtsmb_cli_session_new_with_name - initialize a client session

    name - name of server to which we will connect
    blocking - whether to block on network socket or not
    broadcast_ip - optional ip on which to broadcast request
    psid - return value for the session id

 Description
    This sets up client session with the named server.  It will use
    the broadcast ip specified, or if that is 0, will use the global
    default set by a call to rtsmb_net_set_ip.  If 'blocking' is true,
    this session will be set up in blocking mode which means all calls
    will not return until the task is completed, including this one.

    If an error is returned, the session is dead and psid contains invalid
    contents.

    To discover the names of the servers on the network, enumerate them
    by calling rtsmb_cli_session_server_enum_start.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_close_session, rtsmb_cli_session_set_blocking,
    rtsmb_cli_session_restart, rtsmb_net_set_ip,
    rtsmb_cli_session_server_enum_start

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.


******************************************************************************/
int  rtsmb_cli_session_new_with_name (PFCHAR name, BBOOL blocking, PFBYTE broadcast_ip, PFINT psid, RTSMB_CLI_SESSION_DIALECT dialect);



/******************************************************************************

 rtsmb_cli_session_new_with_ip - initialize a client session

    name - name of server to which we will connect
    broadcast_ip - optional ip on which to broadcast request
    blocking - whether to block on network socket or not
    psid - return value for the session id

 Description
    This sets up client session with a server at the given ip address.  It
    will use the broadcast ip specified, or if that is 0, will use the global
    default set by a call to rtsmb_net_set_ip.  If 'blocking' is true,
    this session will be set up in blocking mode which means all calls
    will not return until the task is completed, including this one.

    If an error is returned, the session is dead and psid contains invalid
    contents.

    This function is not within the CIFS/SMB spec, but it is provided to support
    functionality that Windows clients offer.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_close_session, rtsmb_cli_session_set_blocking,
    rtsmb_cli_session_restart, rtsmb_net_set_ip,
    rtsmb_cli_session_server_enum_start

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.


******************************************************************************/
int rtsmb_cli_session_new_with_ip (PFBYTE ip, PFBYTE broadcast_ip, BBOOL blocking, PFINT psid, RTSMB_CLI_SESSION_DIALECT dialect);



/******************************************************************************

 rtsmb_cli_session_close_session - shuts down a client session

    sid - client session id to close

 Description
    This tears down a connection to the server specified by sid.  This id
    number is now invalid.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_session_new_with_name, rtsmb_cli_session_restart

 Returns
    zero on success or a negative value on failure

******************************************************************************/
void rtsmb_cli_session_close_session (int sid);


/******************************************************************************

 rtsmb_cli_session_restart - cleanly restarts client session

    sid - client session id to restart

 Description
    This tears down a connection to the server specified by sid and then starts
    it up again, preserving open files, connected shares, and users.  I have no
    idea when you would feel you wanted to do this, but it is here for
    completeness.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_session_new_with_name, rtsmb_cli_session_close_session

 Returns
    zero on success or a negative value on failure

******************************************************************************/
int  rtsmb_cli_session_restart (int sid);


/******************************************************************************

 rtsmb_cli_session_set_blocking - sets whether session calls block until done

    sid - client session id to set
    blocking - whether to block

 Description
    This sets the blocking status for a session.  When a session is in blocking
    mode, all calls will not return until the task is complete.  When a session
    is in non-blocking mode, you initiate tasks by calling a function and then
    let the session do its work by calling rtsmb_cli_session_cycle.  When a
    job is done, an optionally-registered callback is called to let you know.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_session_new_with_name, rtsmb_cli_session_cycle

 Returns
    zero on success or a negative value on failure

******************************************************************************/
int  rtsmb_cli_session_set_blocking (int sid, BBOOL blocking);



/******************************************************************************

 rtsmb_cli_session_cycle - lets a client session work

    sid - client session id to use
    timeout - maximum amount of time to block, in milliseconds

 Description
    This allows a client session to send pending requests, receive responses,
    and do housekeeping.  This must be called periodically for the session
    to survive.  'Timeout' may be negative, in which case there is no limit
    on the time to block.

    This only needs to be called when in non-blocking mode.

 See Code
    clissn.c

 See Also
    rtsmb_cli_sesson_set_blocking

 Returns
    zero on success or a negative value on failure

******************************************************************************/
int  rtsmb_cli_session_cycle (int sid, long timeout);


/******************************************************************************

 rtsmb_cli_session_set_job_callback - connects a function to a job

    sid - client session id to use
    job - job id to which the callback should be connected
    callback - a function to call when the job is done
    data - a pointer to data that will be passed to the callback function

 Description
    In non-blocking mode, some functions return a job id.  Using this job id,
    you can connect a callback function that will be called when the job is
    done.  This is very important, since otherwise, you would not know when
    the job is complete and valid data is available.  A job is guaranteed to
    complete, even if it only times out.  Your callback is called whether
    the job successfully completes or not.

    The format of the callback function is:
    void (*callback_function) (int job, int rv, PFVOID data)
    'Job' is obviously the job number.  'Rv' is the return value from the job
    (the return value that would be returned by an API function if in
    non-blocking mode).  This way, you can tell if the job succeeded or not.
    'Data' is the data you passed to rtsmb_cli_session_set_job_callback.

    A callback function will only ever be called in the middle of a
    call to rtsmb_cli_session_cycle.

    This only needs to be called in non-blocking mode.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_cycle

 Returns
    zero on success or a negative value on failure

******************************************************************************/
int  rtsmb_cli_session_set_job_callback (int sid, int job, RTSMB_JOB_CALLBACK callback, PFVOID data);



/******************************************************************************

 rtsmb_cli_session_logon_user - registers a user with the server

    sid - client session id to use
    user - a username with which to connect
    password - a password to pass to the server
    domain - domain name

 Description
    Some servers require a logon before any shares can be accessed.  This call
    performs that logon.  If you do not know of a valid user, just pass in
    some simple username (e.g. "anonymous") and an empty string for a
    password.  Most servers will accept this if they have guest permissions
    enabled.

    Only one user can be connected at one time.  If you wish to use multiple
    users, either connect two sessions to the server or use one user for
    a little while, disconnect it, and register the other.

    This should be called before doing any file I/O or connecting to a share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logoff_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_logon_user_uc

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_logon_user (int sid, PFCHAR user, PFCHAR password, PFCHAR domain);


/******************************************************************************

 rtsmb_cli_session_logoff_user - unregisters a user with the server

    sid - client session id to use

 Description
    This frees up the user data so that a different user can be connected.
    This function does not need to be called to 'clean up' the session
    when shutting down.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_logoff_user (int sid);


/******************************************************************************

 rtsmb_cli_session_connect_share - connects to a share on the server

    sid - client session id to use
    share - share name with which to connect
    password - password to hand the server

 Description
    You need to connect to shares before you can access any files.  This lets
    you do that.  If you do not know a password, just pass the empty string.
    Some servers will accept that and let you in.

    If you do not know the share name you are looking for, try enumerating
    the shares available on the server by calling
    rtsmb_cli_session_share_find_first.

    This should be called before doing any file I/O but should not be called
    before logging in a user.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_disconnect_share, rtsmb_cli_session_logon_user,
    rtsmb_cli_session_share_find_first

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_connect_share (int sid, PFCHAR share, PFCHAR password);


/******************************************************************************

 rtsmb_cli_session_disconnect_share - disconnects from a share on the server

    sid - client session id to use
    share - share name to disconnect

 Description
    This disconnects a share and frees up resources so that you might
    connect more shares.  This does not need to be called to 'clean up' when
    shutting a session down.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_disconnect_share, rtsmb_cli_session_logon_user,
    rtsmb_cli_session_share_find_first

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_disconnect_share (int sid, PFCHAR share);



/******************************************************************************

 rtsmb_cli_session_open - opens a file on the server

    sid - client session id to use
    share - share name to use
    file - filename to open, full path, relative to share
    flags - flags to control how the file is opened
    mode - flags to control permissions if file is created
    fid - return value for file id

 Description
    This opens a file for future reading or writing on the server.  'File'
    is of the form '\path\to\a.txt.'  'Flags' and 'mode' are taken from
    psmbfile.h.  'Fid' will be filled with a valid file identifier to pass
    to other file I/O functions.  This value is guaranteed to not exceed
    255.

    To close this file, call rtsmb_cli_session_close.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_close, rtsmb_cli_session_open_uc

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_open (int sid, PFCHAR share, PFCHAR file, int flags, int mode, PFINT fid);


/******************************************************************************

 rtsmb_cli_session_close - closes a file on the server

    sid - client session id to use
    fid - file identifier to close

 Description
    This closes a file identifier and invalidates it.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_open

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_close (int sid, int fid);


/******************************************************************************

 rtsmb_cli_session_read - reads a file on the server

    sid - client session id to use
    fid - file identifier to use
    data - a buffer to fill with the read data
    count - a maximum amount to read
    count_read - a return value for how many bytes were actually read

 Description
    This reads data from a file.  If the returned amount of bytes read
    is less than what you requested, the end of file was read.

    Note: this call can only handle RTSMB_CLI_SESSION_MAX_DATA_BYTES
    bytes at one time.  Trying to read more will result in an error.

    You need to be logged in, connected to the specified share, and have
    opened the file identifier.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_open, rtsmb_cli_session_write

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_read (int sid, int fid, PFBYTE data, int count, PFINT count_read);


/******************************************************************************

 rtsmb_cli_session_write - writes to a file on the server

    sid - client session id to use
    fid - file identifier to use
    data - a buffer to read the data from
    count - the number of bytes to send to the file
    written - a return value for how many bytes were actually written

 Description
    This writes data to a file.

    Note: this call can only handle RTSMB_CLI_SESSION_MAX_DATA_BYTES
    bytes at one time.  Trying to write more will result in an error.

    You need to be logged in, connected to the specified share, and have
    opened the file identifier.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_open, rtsmb_cli_session_read

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_write (int sid, int fid, PFBYTE data, int count, PFINT written);


/******************************************************************************

 rtsmb_cli_session_seek - changes pointer offset in file

    sid - client session id to use
    fid - file identifier to use
    offset - a relative offset into the file
    location - indicator for where to start the offset
    resulting_offset - a return value for new offset into file, from start

 Description
    This changes our pointer into the file.  If you open a file, and then
    read 16 byte, you are at offset 16.  To go back to offset 0, you would
    use this function.  'Offset' is a relative offset and can be negative.
    'Location' is one of three values:  RTSMB_SEEK_SET, RTSMB_SEEK_CUR,
    or RTSMB_SEEK_END.  SET means the offset is from the beginning, CUR
    means the offset is from our current location, and END means the offset
    is from the end of the file.

    You need to be logged in, connected to the specified share, and have
    opened the file identifier.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_open

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_seek (int sid, int fid, long offset, int location, PFLONG resulting_offset);


/******************************************************************************

 rtsmb_cli_session_truncate - changes size of a file

    sid - client session id to use
    fid - file identifier to use
    offset - new size of the file

 Description
    This changes the size of the file.  It may destroy data if the new
    size is less than the old size.  It may extend the file if the new
    size is larger than the old size.  If it extends the file, it extends
    it with 0-bytes.

    You need to be logged in, connected to the specified share, and have
    opened the file identifier.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_open

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_truncate (int sid, int fid, long offset);


/******************************************************************************

 rtsmb_cli_session_flush - flushes the file on the server

    sid - client session id to use
    fid - file identifier to use

 Description
    This flushes the file on the server.  The server must complete all
    waiting I/O calls before returning an answer to this.

    You need to be logged in, connected to the specified share, and have
    opened the file identifier.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_open

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_flush (int sid, int fid);


/******************************************************************************

 rtsmb_cli_session_rename - changes the name of a file on the server

    sid - client session id to use
    share - share name to use
    old_filename - current filename
    new_filename - what you want to call the file

 Description
    This changes the name of a file.  The new filename must not already
    exist.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_rename_uc

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_rename (int sid, PFCHAR share, PFCHAR old_filename, PFCHAR new_filename);


/******************************************************************************

 rtsmb_cli_session_delete - deletes a file on the server

    sid - client session id to use
    share - share name to use
    filename - file you wish to delete

 Description
    This deletes a file.  You may pass it a file pattern with wildcards if the
    server supports it (NT line and up).  But, since you can't depend on it,
    I would suggest deleting files one-by-one.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_delete_uc

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_delete (int sid, PFCHAR share, PFCHAR filename);


/******************************************************************************

 rtsmb_cli_session_mkdir - creates a directory on the server

    sid - client session id to use
    share - share name to use
    filename - directory name you wish to create

 Description
    This creates a directory.  If you specify a path that also includes
    uncreated directories along it (e.g. no directories exist on the share
    now, but you ask it to create '\one\two\three'), then those directories
    should be made, but this is not promised in the SMB specification.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_rmdir, rtsmb_cli_session_mkdir_uc

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_mkdir (int sid, PFCHAR share, PFCHAR filename);


/******************************************************************************

 rtsmb_cli_session_rmdir - deletes a directory on the server

    sid - client session id to use
    share - share name to use
    filename - directory name you wish to delete

 Description
    This deletes a directory.  It must be empty before you can do this.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_mkdir, rtsmb_cli_session_rmdir_uc

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_rmdir (int sid, PFCHAR share, PFCHAR filename);


/******************************************************************************

 rtsmb_cli_session_find_first - starts a directory traversal

    sid - client session id to use
    share - share name to use
    pattern - file pattern you want to search
    pdstat - a return location for information about the first file found

 Description
    This is analogous to Windows' FindFirstFile.  It will try to match the
    pattern given, if any, and if any files are found that match, they
    will be returned.  The first file's info will be put into pdstat.  For
    more of them, use the function rtsmb_cli_session_find_next.

    Note that returned filenames may be in Unicode even thought the pattern
    was in ASCII or it may be in ASCII even though the pattern was in
    Unicode.  Always check the value of pdstat->unicode.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_find_next, rtsmb_cli_session_find_close,
    rtsmb_cli_session_find_first_uc

 Returns
    In blocking mode, returns CSSN_RV_SEARCH_DATA_READY on availability
    of a file’s information, CSSN_RV_END_OF_SEARCH when no more files
    are available, or another negative value on failure.
    In non-blocking mode, returns a non-negative value on success
    indicating the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_find_first (int sid, PFCHAR share, PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);


/******************************************************************************

 rtsmb_cli_session_find_next - continues a directory traversal

    sid - client session id to use
    pdstat - a return location for information about the next file found

 Description
    This is analogous to Windows' FindNextFile.  You should pass it the
    same structure that you passed into rtsmb_cli_session_find_first.
    Upon completion, pdstat will be filled with the information for the
    next file.

    Note that returned filenames may be in Unicode even thought the pattern
    was in ASCII or it may be in ASCII even though the pattern was in
    Unicode.  Always check the value of pdstat->unicode.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_find_first, rtsmb_cli_session_find_close

 Returns
    In blocking mode, returns CSSN_RV_SEARCH_DATA_READY on availability
    of a file’s information, CSSN_RV_END_OF_SEARCH when no more files
    are available, or another negative value on failure.
    In non-blocking mode, returns a non-negative value on success
    indicating the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_find_next (int sid, PRTSMB_CLI_SESSION_DSTAT pdstat);


/******************************************************************************

 rtsmb_cli_session_find_close - ends a directory traversal

    sid - client session id to use
    pdstat - a DSTAT passed to previous find_* calls

 Description
    This is analogous to Windows' FindClose.  You should pass it the
    same structure that you passed into rtsmb_cli_session_find_first.
    This frees up resources for future calls to rtsmb_cli_session_find_first.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_find_first, rtsmb_cli_session_find_next

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_find_close (int sid, PRTSMB_CLI_SESSION_DSTAT pdstat);


/******************************************************************************

 rtsmb_cli_session_stat - gets information on a file by name

    sid - client session id to use
    share - share name to use
    file - a filename to get information about
    pstat - a return location for the information

 Description
    This fills pstat with information on the filename, if it exists.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_stat_uc

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_stat (int sid, PFCHAR share, PFCHAR file, PRTSMB_CLI_SESSION_FSTAT pstat);


/******************************************************************************

 rtsmb_cli_session_chmode - change attributes of file

    sid - client session id to use
    share - share name to use
    file - a filename to use
    attributes - new attributes to set

 Description
    This function changes the attributes of a particular file.  Attributes
    is either RTSMB_ATTRIB_RDONLY or 0 to indicate that it is a read only
    file or a read and write file, respectively.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_chmode_uc

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_chmode (int sid, PFCHAR share, PFCHAR file, int attributes);


/******************************************************************************

 rtsmb_cli_session_get_free - get disk size of a share

    sid - client session id to use
    share - share name to use
    total_units - return location for total number of units
    free_units - return location for free number of units
    blocks_per_unit - return location for number of blocks in each unit
    block_size - return location for size of each block in bytes

 Description
    This function gets the free size of a disk.  If you are not interested
    in any of the parameters, you can pass in 0.  Multiply block_size
    by blocks_per_unit and either free_units or total_units to get the
    free size or total size, respectively, in bytes.

    You need to be logged in and connected to the specified share.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_logon_user, rtsmb_cli_session_connect_share,
    rtsmb_cli_session_get_free_uc

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_get_free (int sid, PFCHAR share, PFINT total_units, PFINT free_units, PFINT blocks_per_unit, PFINT block_size);


/******************************************************************************

 rtsmb_cli_session_setfiletime -



 Description


 See Code
    clissn.c

 See Also


 Returns


******************************************************************************/
int  rtsmb_cli_session_setfiletime (int sid, PFCHAR share, PFCHAR filename, TIME atime, TIME wtime, TIME ctime, TIME htime);



/**
 * Here are Unicode versions of the above functions.  Their behaviour is the
 * same, but they take Unicode filenames.
 */
#if (INCLUDE_RTSMB_UNICODE)
int  rtsmb_cli_session_logon_user_uc (int sid, PFWCS user, PFCHAR password, PFWCS domain);
int  rtsmb_cli_session_open_uc (int sid, PFCHAR share, PFWCS file, int flags, int mode, PFINT fid);
int  rtsmb_cli_session_rename_uc (int sid, PFCHAR share, PFWCS old_filename, PFWCS new_filename);
int  rtsmb_cli_session_delete_uc (int sid, PFCHAR share, PFWCS filename);
int  rtsmb_cli_session_mkdir_uc (int sid, PFCHAR share, PFWCS filename);
int  rtsmb_cli_session_rmdir_uc (int sid, PFCHAR share, PFWCS filename);
int  rtsmb_cli_session_find_first_uc (int sid, PFCHAR share, PFWCS pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);
int  rtsmb_cli_session_stat_uc (int sid, PFCHAR share, PFWCS file, PRTSMB_CLI_SESSION_FSTAT pstat);
int  rtsmb_cli_session_chmode_uc (int sid, PFCHAR share, PFWCS file, int attributes);
#endif



/******************************************************************************

 rtsmb_cli_session_share_find_first - enumerate shares of a server

    sid - client session id to use
    pstat - a return location for the first share

 Description
    This function enumerates over the shares available on the server.
    If any are found, the first one's information will
    be returned in pstat.  It will only return shares that are disk
    shares, so shares like the IPC$ share or printer shares will not show up.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_share_find_next, rtsmb_cli_session_share_find_close

 Returns
    In blocking mode, returns CSSN_RV_SEARCH_DATA_READY on availability
    of a share's information, CSSN_RV_END_OF_SEARCH when no more shares
    are available, or another negative value on failure.
    In non-blocking mode, returns a non-negative value on success
    indicating the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_share_find_first (int sid, PRTSMB_CLI_SESSION_SSTAT pstat);


/******************************************************************************

 rtsmb_cli_session_share_find_next - continues enumeration of shares of a server

    sid - client session id to use
    pstat - a return location for the next share

 Description
    This function returns the next share from an enumeration started by
    rtsmb_cli_session_share_find_first.  'Pstat' must be the same structure
    as was passed to that function.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_share_find_first, rtsmb_cli_session_share_find_close

 Returns
    In blocking mode, returns CSSN_RV_SEARCH_DATA_READY on availability
    of a share's information, CSSN_RV_END_OF_SEARCH when no more shares
    are available, or another negative value on failure.
    In non-blocking mode, returns a non-negative value on success
    indicating the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_share_find_next (int sid, PRTSMB_CLI_SESSION_SSTAT pstat);


/******************************************************************************

 rtsmb_cli_session_share_find_close - closes enumeration of shares of a server

    sid - client session id to use
    pstat - the same structure passed to rtsmb_cli_session_share_find_first

 Description
    This function closes an enumeration and frees up resources for future
    enumerations.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_share_find_first, rtsmb_cli_session_share_find_next

 Returns
    In blocking mode, returns zero on success or a negative value on failure.
    In non-blocking mode, returns a non-negative value on success indicating
    the job id or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_share_find_close (int sid, PRTSMB_CLI_SESSION_SSTAT pstat);



/******************************************************************************

 rtsmb_cli_session_server_enum_start - starts enumeration of servers on network

    pstat - a structure that will be initialized for future calls
    ip - an ip to use while we enumerate the servers
    bip - a broadcast ip to use while we enumerate the servers

 Description
    This function begins an enumeration of the servers in the network.  'Ip'
    and 'bip' may be 0, in which case the global default set by
    rtsmb_net_set_ip will be used.

    The semantics of this family of calls is a little weird.  Start off a search
    with enum_start.  Call enum_cycle until either RTSMB_CLI_SSN_RV_END_OF_SEARCH
    is returned, indicating there are no more servers, another negative number
    is returned, indicating some error, or a positive number is returned,
    indicating you can start getting names.  On a zero, keep cycling.

    However, once you start getting names from next_name, do so until
    RTSMB_CLI_SSN_RV_END_OF_SEARCH is returned.  Once this happens, you need
    to repeat the cycling process.  Whenever a cycle returns
    RTSMB_CLI_SSN_RV_END_OF_SEARCH, the search is truly over, and you should
    close it.  But, when a next_name call returns RTSMB_CLI_SSN_RV_END_OF_SEARCH,
    it merely means that that group of names is done.

    Note that this will return *all* servers on the network.  Not just in one
    workgroup.  Each block of servers returned from one cycle call will be
    in one workgroup, but there is not a way to discover the name of that
    workgroup right now.

    You do not need to be connected to a server to call this, but this call
    will still use up a session context to perform its duty.  So, keep in mind
    that you will have one less session context while this is being called.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_server_enum_cycle, rtsmb_cli_session_server_enum_next_name,
    rtsmb_cli_session_server_enum_close, rtsmb_net_set_ip

 Returns
    Returns zero on success or a negative value on failure.

******************************************************************************/
int  rtsmb_cli_session_server_enum_start (PRTSMB_CLI_SESSION_SRVSTAT pstat, PFBYTE ip, PFBYTE bip);


/******************************************************************************

 rtsmb_cli_session_server_enum_cycle - continues enumeration of servers on network

    pstat - a structure that was initialized earlier
    timeout - a maximum amount of time we can block on the network

 Description
    This function continues an enumeration of the servers in the network.  See
    rtsmb_cli_session_server_enum_start for more information about how to
    use this.

    You do not need to be connected to a server to call this, but this call
    will still use up a session context to perform its duty.  So, keep in mind
    that you will have one less session context while this is being called.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_server_enum_start, rtsmb_cli_session_server_enum_next_name,
    rtsmb_cli_session_server_enum_close

 Returns
    Zero if you must keep cycling, a positive value if you can start reading
    names, RTSMB_CLI_SSN_RV_END_OF_SEARCH if the search is completely over,
    or another negative value on an error.

******************************************************************************/
int  rtsmb_cli_session_server_enum_cycle (PRTSMB_CLI_SESSION_SRVSTAT pstat, int timeout);


/******************************************************************************

 rtsmb_cli_session_server_enum_next_name - continues enumeration of servers on network

    pstat - a structure that was initialized earlier
    name - a return location for one server name

 Description
    This function continues an enumeration of the servers in the network.  Use
    it to start reading server names that we have discovered.  See
    rtsmb_cli_session_server_enum_start for more information about how to
    use this.

    You do not need to be connected to a server to call this, but this call
    will still use up a session context to perform its duty.  So, keep in mind
    that you will have one less session context while this is being called.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_server_enum_start, rtsmb_cli_session_server_enum_cycle,
    rtsmb_cli_session_server_enum_close

 Returns
    RTSMB_CLI_SSN_RV_END_OF_SEARCH if you must go back to cycling,
    RTSMB_CLI_SSN_RV_SEARCH_DATA_READY if 'name' was filled with a server
    name, or another negative numer on an error.

******************************************************************************/
int  rtsmb_cli_session_server_enum_next_name (PRTSMB_CLI_SESSION_SRVSTAT pstat, PFCHAR name);


/******************************************************************************

 rtsmb_cli_session_server_enum_close - closes an enumeration of servers on network

    pstat - a structure that was initialized earlier

 Description
    This function stops an enumeration of the servers in the network.  See
    rtsmb_cli_session_server_enum_start for more information about how to
    use this.

    You do not need to be connected to a server to call this, but this call
    will still use up a session context to perform its duty.  So, keep in mind
    that you will have one less session context while this is being called.

 See Code
    clissn.c

 See Also
    rtsmb_cli_session_server_enum_start, rtsmb_cli_session_server_enum_cycle,
    rtsmb_cli_session_server_enum_next_name

 Returns
    zero on success or a negative value on error.

******************************************************************************/
int  rtsmb_cli_session_server_enum_close (PRTSMB_CLI_SESSION_SRVSTAT pstat);




#if (INCLUDE_RTSMB_CLIENT_EZ)
/**
 * The "EZ" part of the API.  These calls are designed for simplicity and
 * ease of use.
 *
 * You pass it a URI of the form "//SERVER/SHARE/FILE/PATH.txt",
 * and the forward slashes can be backward slashes instead.  All passed
 * URI's must be full -- there is no concept of a current directory.
 *
 * Each call will block until the task is completed.
 *
 * All flags (attributes, mode) are taken from psmbfile.h.
 *
 * Look in clissn.h for the definition of RTSMB_CLI_SESSION_DSTAT -- it is very
 * similar to the DSTAT in psmbfile.h.
 *
 * Note that you can easily search for servers on the network or search a
 * server's shares by specifing a wildcard in those parts of the path
 * when using find_first.  So, to get a list of all servers in the network
 * starting with 'A', you could call rtsmb_cli_ez_find_first ("//A*", &stat).
 * To get a list of shares on the server 'ADAM', you could call
 * rtsmb_cli_ez_find_first ("\\\\ADAM\\*", &stat);
 *
 *
 * Warning:  Mixing use of the two API's is possible, but not recommended.
 *          In particular, the EZ API makes some assumptions that you may
 *          not want it to make.  To wit, it tries to find an open session with
 *          a server of the same name as given it to use; it, if all
 *          session contexts are taken, will close the least recently used
 *          session; and it leaves sessions open.
 */



/******************************************************************************

 rtsmb_cli_ez_set_user - sets the username and password for the EZ layer

    name - the username to use
    password - the password to use

 Description
    This function sets up the EZ layer to use the specified username and
    password when connecting to servers.  Use this if you have particular
    credentials that you think may give you better access to the files on
    a server.

 See Code
    cliez.c

******************************************************************************/
void rtsmb_cli_ez_set_user (PFCHAR username, PFCHAR password, PFCHAR domain );


/******************************************************************************

 rtsmb_cli_ez_open - opens a file for reading or writing

    name - the filename to open
    flags - the flags to change how we open the file
    mode - what permissions to use if creating the file

 Description
    This function opens a file.  'Flags' and 'mode' take values found in
    psmbfile.h

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_close, rtsmb_cli_ez_open_uc

 Returns
    non-negative value on success representing the file id or a negative
    value on error

******************************************************************************/
int  rtsmb_cli_ez_open (PFCHAR name, int flags, int mode);


/******************************************************************************

 rtsmb_cli_ez_read - reads from a file

    fid - the file id to use
    buffer - buffer to put read contents
    count - the maximum amount to read

 Description
    This function reads data from an open file.  If the returned bytes read
    is less than 'count,' the end of file was reached.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_write, rtsmb_cli_ez_open

 Returns
    non-negative value on success representing the number of bytes read or
    a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_read (int fd, PFBYTE buffer, unsigned int count);


/******************************************************************************

 rtsmb_cli_ez_write - writes to a file

    fid - the file id to use
    buffer - buffer to read data from
    count - the number of bytes to write

 Description
    This function writes data to an open file.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_read, rtsmb_cli_ez_open

 Returns
    non-negative value on success representing the number of bytes read or
    a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_write (int fd, PFBYTE buffer, unsigned int count);


/******************************************************************************

 rtsmb_cli_ez_seek - changes pointer offset into file

    fd - the file descriptor to use
    offset - the relative offset to set the pointer to
    origin - a value indicating where the offset starts

 Description
    This function sets where the file pointer is.  For example, if you opened
    a file, and read 16 bytes, you will be at offset 16.

    'Offset' may be negative.  'Origin' can take the value RTSMB_SEEK_SET,
    RTSMB_SEEK_CUR, or RTSMB_SEEK_END.  SET is from the beginning, CUR is
    from the current location, and END is from the end.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_open

 Returns
    non-negative value on success representing the new offset from the
    start of the file or a negative value on error

******************************************************************************/
long rtsmb_cli_ez_seek (int fd, long offset, int origin);


/******************************************************************************

 rtsmb_cli_ez_close - closes file identifier

    fd - the file descriptor to close

 Description
    This function closes and invalidates a file descriptor.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_open

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_close (int fd);


/******************************************************************************

 rtsmb_cli_ez_truncate - changes the size of a file

    fd - the file descriptor to use
    offset - new size of file

 Description
    This function changes the size of a file.  If 'offset' is larger than the
    file's current size, the file is extended with 0-bytes.  If 'offset' is
    smaller than the file's current size, the file is truncated.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_open

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_truncate (int fd, long offset);


/******************************************************************************

 rtsmb_cli_ez_flush - flushes a file

    fd - the file descriptor to flush

 Description
    This function flushes a file.  All pending reads and writes will be completed
    before this call returns.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_open

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_flush (int fd);


/******************************************************************************

 rtsmb_cli_ez_rename - moves a file

    old_filename - current name of file to move
    new_filename - desired name of file

 Description
    This function renames a file.  'New_filename' must not exist.  You cannot
    rename a file across servers or across shares.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_rename_uc

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_rename (PFCHAR old_filename, PFCHAR new_filename);


/******************************************************************************

 rtsmb_cli_ez_delete - deletes a file

    filename - filename to delete

 Description
    This deletes a file.  You may pass it a file pattern with wildcards if the
    server supports it (NT line and up).  But, since you can't depend on it,
    I would suggest deleting files one-by-one.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_delete_uc

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_delete (PFCHAR filename);


/******************************************************************************

 rtsmb_cli_ez_mkdir - creates a directory

    filename - directory to create

 Description
    This function creates a directory.  You must have write access.  The
    directory must not already exist.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_mkdir_uc

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_mkdir (PFCHAR filename);


/******************************************************************************

 rtsmb_cli_ez_rmdir - deletes a directory

    filename - directory to delete

 Description
    This function deletes a directory.  You must have write access.  The
    directory must be empty.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_rmdir_uc

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_rmdir (PFCHAR filename);


/******************************************************************************

 rtsmb_cli_ez_find_first - starts a directory traversal

    pattern - pattern to match
    pdstat - return location for information on file

 Description
    This function is analogous to Windows' FindFirstFile.  It will take the
    pattern you give it and return matching filenames one by one.

    Note that this function actually combines several different functionalities
    from the session layer -- This allows you to enumerate the servers
    on the network, the shares on a server, or files on a share.  That is,
    you can search on '// *', '//server/ *', or '//server/share/ *' for example.

    Also note that the returned filename maybe in Unicode even though your
    pattern was ASCII or ASCII even though your pattern was Unicode.  Always
    check the value of pdstat->unicode.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_find_next, rtsmb_cli_ez_find_close,
    rtsmb_cli_ez_find_first_uc

 Returns
    a positive value if data is available, zero if no results were found, or a
    negative value on error

******************************************************************************/
int  rtsmb_cli_ez_find_first (PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);


/******************************************************************************

 rtsmb_cli_ez_find_next - continues a directory traversal

    pdstat - return location for information on file

 Description
    This function is analogous to Windows' FindNextFile.  It will continue
    a prior search and return matching filenames one by one.

    Note that the returned filename maybe in Unicode even though your
    pattern was ASCII or ASCII even though your pattern was Unicode.  Always
    check the value of pdstat->unicode.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_find_first, rtsmb_cli_ez_find_close

 Returns
    a positive value if data is available, zero if the search is over and there
    are no more results, or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_find_next (PRTSMB_CLI_SESSION_DSTAT pdstat);


/******************************************************************************

 rtsmb_cli_ez_find_close - closes a directory traversal

    pdstat - structure from a prior call

 Description
    This function is analogous to Windows' FindClose.  It will close
    a prior search and free up resources for future searches.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_find_first, rtsmb_cli_ez_find_next

 Returns
    zero on success or a negative value on error

******************************************************************************/
void rtsmb_cli_ez_find_close (PRTSMB_CLI_SESSION_DSTAT pdstat);


/******************************************************************************

 rtsmb_cli_ez_stat - gets information on a file

    filename - filename to query
    pfstat - return location for file's information

 Description
    This function gets some basic information about a file, like timestamps
    and size.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_stat_uc

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_stat (PFCHAR filename, PRTSMB_CLI_SESSION_FSTAT pfstat);


/******************************************************************************

 rtsmb_cli_ez_chmode - changes file attributes

    filename - filename to use
    attributes - new attributes to set

 Description
    This function sets some basic attributes about a file.  Right now, you can
    only really change the readonly flag.  So, set this to either 0 or
    RTSMB_ATTRIB_READONLY.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_chmode_uc

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_chmode (PFCHAR filename, int attributes);


/******************************************************************************

 rtsmb_cli_ez_get_free - gets share size

    filename - filename to use
    total_blocks - return location for total units in file system
    free_blocks - return location for total free units in file system
    sectors_per_block - return location for number of sectors in each block
    bytes_per_sector - return location for number of bytes in each sector

 Description
    This function retrieves the current disk size of a share.  Note that
    filename can be any file on the share or the share itself.

    On an error, non of the arguments are altered.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_get_free_uc

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_get_free (PFCHAR filename, PFINT total_blocks, PFINT free_blocks, PFINT sectors_per_block, PFINT bytes_per_sector);


/******************************************************************************

 rtsmb_cli_ez_get_cwd - gets the current working directory

    filename - buffer to fill with working directory
    size - size in characters of buffer

 Description
    This function retrieves the current working directory and fills 'filename'
    with it.  For example, if on a prior call to rtsmb_cli_ez_set_cwd, you
    set the working directory to '//server/share/path,' then this would fill
    'filename' with '//server/share/path.'

    If you have not called rtsmb_cli_ez_set_cwd, then there is no current
    working directory and 'filename' will contain the empty string after this
    call.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_set_cwd, rtsmb_cli_ez_get_cwd_uc

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_get_cwd (PFCHAR filename, rtsmb_size size);


/******************************************************************************

 rtsmb_cli_ez_set_cwd - sets the current working directory

    filename - filename to set as the current working directory

 Description
    This function sets the current working directory.  The current working
    directory is a prefix that is attached to any pathnames that we cannot
    parse.  For example, if you set the current working directory to '//server'
    and pass in '/share/path/a.txt,' then we will not be able to parse the
    filename and will create a new path '//server/share/path/a.txt' to use.

    'Filename' must be a valid path.

    If you have not yet called rtsmb_cli_ez_set_cwd, then there is no current
    working directory and unparsable paths return an error.

 See Code
    cliez.c

 See Also
    rtsmb_cli_ez_get_cwd, rtsmb_cli_ez_set_cwd_uc

 Returns
    zero on success or a negative value on error

******************************************************************************/
int  rtsmb_cli_ez_set_cwd (PFCHAR filename);

/****************************************************************************** */
void rtsmb_init_port_alt (void);
void rtsmb_init_port_well_know (void);


/**
 * Here are Unicode versions of the above functions.  Their behaviour is the
 * same, but they take Unicode filenames.
 */
#if (INCLUDE_RTSMB_UNICODE)
void rtsmb_cli_ez_set_user_uc (PFWCS username, PFCHAR password, PFWCS domain );
int  rtsmb_cli_ez_open_uc (PFWCS name, int flags, int mode);
int  rtsmb_cli_ez_rename_uc (PFWCS old_filename, PFWCS new_filename);
int  rtsmb_cli_ez_delete_uc (PFWCS filename);
int  rtsmb_cli_ez_mkdir_uc (PFWCS filename);
int  rtsmb_cli_ez_rmdir_uc (PFWCS filename);
int  rtsmb_cli_ez_find_first_uc (PFWCS pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);
int  rtsmb_cli_ez_stat_uc (PFWCS filename, PRTSMB_CLI_SESSION_FSTAT pfstat);
int  rtsmb_cli_ez_chmode_uc (PFWCS filename, int attributes);
int  rtsmb_cli_ez_get_free_uc (PFWCS filename, PFINT total_blocks, PFINT free_blocks, PFINT sectors_per_block, PFINT bytes_per_sector);
int  rtsmb_cli_ez_get_cwd_uc (PFWCS filename, rtsmb_size size);
int  rtsmb_cli_ez_set_cwd_uc (PFWCS filename);
#endif
#endif /* INCLUDE_RTMSB_CLIENT_EZ */

#endif /* INCLUDE_RTMSB_CLIENT */

#endif
