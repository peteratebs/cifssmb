 /*
 | RTPSTDUP.H - Runtime Platform Services
 |
 |   UNIVERSAL CODE - DO NOT CHANGE
 |
 | EBS - RT-Platform 
 |
 |  $Author: vmalaiya $
 |  $Date: 2006/07/17 15:29:00 $
 |  $Name:  $
 |  $Revision: 1.3 $
 |
 | Copyright EBS Inc. , 2006
 | All rights reserved.
 | This code may not be redistributed in source or linkable object form
 | without the consent of its author.
 |
 | Module description:
 |  [tbd]
*/

#ifndef __RTPSTDUP_H__
#define __RTPSTDUP_H__

#include "rtpmem.h"

/************************************************************************
 * API functions
 ************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

char           * _rtp_strdup (const char *str);
unsigned short * _rtp_wcsdup (unsigned short *wstr);

#ifdef RTP_TRACK_LOCAL_MEMORY

char           * _rtp_debug_strdup (const char *str, const char *file, long line);
unsigned short * _rtp_debug_wcsdup (unsigned short *wstr, const char *file, long line);

#define rtp_strdup(X) _rtp_debug_strdup(X, __FILE__, __LINE__)
#define rtp_wcsdup(X) _rtp_debug_wcsdup(X, __FILE__, __LINE__)

#else

#define rtp_strdup _rtp_strdup
#define rtp_wcsdup _rtp_wcsdup

#endif

#define rtp_strfree rtp_free
#define rtp_wcsfree rtp_free

#ifdef __cplusplus
}
#endif

#endif /*__RTPSTDUP_H__*/

/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
