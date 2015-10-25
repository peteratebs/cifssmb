 /*
 | RTPDEBUG.C - Runtime Platform Debug Services
 |
 | EBS - RT-Platform
 |
 |  $Author: vmalaiya $
 |  $Date: 2006/07/17 15:29:01 $
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
	len  = snprintf(buffer,       RTP_DEBUG_STRING_LEN,       "File: %s\n", file);
	len += snprintf(buffer + len, RTP_DEBUG_STRING_LEN - len, "Line: %d\n", line_num);
#endif

	len = len + snprintf(buffer + len, (size_t) (RTP_DEBUG_STRING_LEN - len), "%s", msg);
	fprintf(stderr, "%s", buffer);
	fflush(stderr);
}


/*----------------------------------------------------------------------*
                         rtp_debug_output_int
 *----------------------------------------------------------------------*/
void _rtp_debug_output_int (
	long val
	)
{
char buffer[RTP_DEBUG_STRING_LEN];

	snprintf(buffer, RTP_DEBUG_STRING_LEN, "%d", (int) val);
	fprintf(stderr, "%s", buffer);
	fflush(stderr);
}


/*----------------------------------------------------------------------*
                         rtp_debug_output_printf
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

/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
