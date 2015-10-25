 /*
 | RTPDEBUG.C - Runtime Platform Debug Services
 |
 | EBS - RT-Platform
 |
 |  $Author: vmalaiya $
 |  $Date: 2006/07/17 15:29:02 $
 |  $Name:  $
 |  $Revision: 1.3 $
 |
 | Copyright EBS Inc. , 2006
 | All rights reserved.
 | This code may not be redistributed in source or linkable object form
 | without the consent of its author.
 |
 | Module description:
 |  If not running within a debugger that redirects OutputDebugString()
 |  it is recommended that an application similar to DebugView is
 |  used to capture the output for later viewing.
 |
 |  DebugView is a freeware application that can be found at Sysinternals
 |  (www.sysinternals.com).  As described on www.sysinternals.com:
 |
 |     "DebugView is an application that lets you monitor debug
 |      output on your local system, or any computer on the
 |      network that you can reach via TCP/IP. It is capable of
 |      displaying both kernel-mode and Win32 debug output, so
 |      you don’t need a debugger to catch the debug output your
 |      applications or device drivers generate, nor do you need
 |      to modify your applications or drivers to use
 |      non-standard debug output APIs."
*/


/************************************************************************
* Headers
************************************************************************/
#include "rtp.h"
#include "rtpdebug.h"

#include <stdio.h>
#include <windows.h>

/************************************************************************
* Configuration
************************************************************************/
/* #define RTP_DEBUG_OUTPUT_FILE_AND_LINE */

/************************************************************************
* Defines
************************************************************************/
#define RTP_DEBUG_STRING_LEN 4096

/************************************************************************
* Types
************************************************************************/

/************************************************************************
* Data
************************************************************************/

/************************************************************************
* Macros
************************************************************************/

/************************************************************************
* Function Prototypes
************************************************************************/

/************************************************************************
* Function Bodies
************************************************************************/

/*----------------------------------------------------------------------*
                         rtp_debug_output_str
 *----------------------------------------------------------------------*/
void _rtp_debug_output_str (
	char* msg,
	const char *file,
	long line_num
	)
{
char buffer[RTP_DEBUG_STRING_LEN];
int len = 0;

#ifdef RTP_DEBUG_OUTPUT_FILE_AND_LINE
	len  = _snprintf(buffer,       RTP_DEBUG_STRING_LEN,       "File: (%s)", file);
	len += _snprintf(buffer + len, RTP_DEBUG_STRING_LEN - len, "Line: %d\n", line_num);
#endif

	len += _snprintf(buffer + len, RTP_DEBUG_STRING_LEN - len, msg);
	OutputDebugString(buffer);
}


/*----------------------------------------------------------------------*
                         rtp_debug_output_int
 *----------------------------------------------------------------------*/
void _rtp_debug_output_int (
	long val
	)
{
char buffer[RTP_DEBUG_STRING_LEN];
int len;

	len = _snprintf(buffer, RTP_DEBUG_STRING_LEN, "%d", val);
    OutputDebugString(buffer);
}

static void __rtp_debug_output_errno (
	char* msg,
	long err,
	const char *file,
	long line_num
	)
{
char buffer[RTP_DEBUG_STRING_LEN];
int len = 0;

#ifdef RTP_DEBUG_OUTPUT_FILE_AND_LINE
	len  = _snprintf(buffer,       RTP_DEBUG_STRING_LEN,       "File: %s\n", file);
	len += _snprintf(buffer + len, RTP_DEBUG_STRING_LEN - len, "Line: %d\n", line_num);
#endif
	len += _snprintf(buffer + len, RTP_DEBUG_STRING_LEN - len, msg);
	len += _snprintf(buffer + len, RTP_DEBUG_STRING_LEN - len, "error # (%d) : ", err);
{
LPVOID lpMsgBuf;
FormatMessage(
    FORMAT_MESSAGE_ALLOCATE_BUFFER |
    FORMAT_MESSAGE_FROM_SYSTEM |
    FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    err,
    0, // Default language
    (LPTSTR) &lpMsgBuf,
    0,
    NULL
);
	len += _snprintf(buffer + len, RTP_DEBUG_STRING_LEN - len, "%s", (char *) lpMsgBuf);
LocalFree( lpMsgBuf );
}

	len += _snprintf(buffer + len, RTP_DEBUG_STRING_LEN - len, msg);
	len += _snprintf(buffer + len, RTP_DEBUG_STRING_LEN - len, ".\n");

	OutputDebugString(buffer);
}

/*----------------------------------------------------------------------*
                         rtp_debug_syslog_printf
 *----------------------------------------------------------------------*/

void _rtp_debug_syslog_printf(int dbg_lvl, char *fmt, ...)
{
char buffer[RTP_DEBUG_STRING_LEN];
 va_list argptr=0;
 va_start(argptr,fmt);
 vsprintf(buffer, fmt, argptr);
 va_end(argptr);
 fprintf(stderr, "%s",buffer);

 fflush(stderr);
}


void _rtp_debug_output_neterrno (
	char* msg,
	long err,
	const char *file,
	long line_num
	)
{
	__rtp_debug_output_errno (msg, err, file, line_num);
}

void _rtp_debug_output_errno(
	char* msg,
	const char *file,
	long line_num
	)
{
	__rtp_debug_output_errno (msg, GetLastError(), file, line_num);
}


/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
