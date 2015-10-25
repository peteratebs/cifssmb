#ifndef __SMB_DEBUG_H__
#define __SMB_DEBUG_H__

#include "smbdefs.h"
#include "smbutil.h"

void _rtsmb_debug_output_str(void* msg, int type);
void _rtsmb_debug_output_int(long val);

#define RTSMB_DEBUG_TYPE_ASCII       0
#define RTSMB_DEBUG_TYPE_UNICODE     1
#define RTSMB_DEBUG_TYPE_SYS_DEFINED 2

#ifndef RTSMB_DEBUG
#define RTSMB_DEBUG 1
#endif
#ifdef RTSMB_DEBUG
#ifndef RTP_DEBUG
#define RTP_DEBUG
#endif
#define RTSMB_DEBUG_OUTPUT_STR(msg, type)  _rtsmb_debug_output_str(msg, type)
#define RTSMB_DEBUG_OUTPUT_INT(val)  _rtsmb_debug_output_int(val)
#define RTSMB_DEBUG_OUTPUT_DINT(val)       _rtsmb_debug_output_dint(val)
#define RTSMB_DEBUG_SET_LABEL(val,STRING) val=STRING;
#else
#define RTSMB_DEBUG_OUTPUT_STR(msg, type)
#define RTSMB_DEBUG_OUTPUT_INT(msg)
#define RTSMB_DEBUG_OUTPUT_DINT(msg)
#define RTSMB_DEBUG_SET_LABEL(val,STRING)
#endif /* RTSMB_DEBUG */


#endif /* __SMB_DEBUG_H__ */
