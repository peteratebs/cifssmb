//
// SMBDEBUG.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2004
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Functions for Outputing unicode/Ascii debug information

#include "smbdebug.h"
#include "rtpdebug.h"

char cnv_msg[100];
void _rtsmb_debug_output_str(void* msg, int type)
{

	switch (type)
	{
		case RTSMB_DEBUG_TYPE_ASCII:
        	rtp_printf("%s", msg);
			break;

		case RTSMB_DEBUG_TYPE_UNICODE:
		case RTSMB_DEBUG_TYPE_SYS_DEFINED:
			#if (INCLUDE_RTSMB_UNICODE)
				rtsmb_util_unicode_to_ascii (msg, (PFCHAR) cnv_msg, CFG_RTSMB_USER_CODEPAGE);
                rtp_printf("%s", cnv_msg);
			#else
                rtp_printf("%s", msg);
			#endif
			break;
	}
}

void _rtsmb_debug_output_int(long val)
{
    rtp_printf("%d", val);
}
void _rtsmb_debug_output_dint(unsigned long val)
{
    rtp_printf("%lu", val);
}
