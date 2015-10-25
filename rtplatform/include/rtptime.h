 /*
 | RTPTIME.H - Runtime Platform Services
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

#ifndef __RTPTIME_H__
#define __RTPTIME_H__

#include "rtp.h"


/************************************************************************
 * API functions
 ************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

unsigned long rtp_get_system_msec (void);
unsigned long rtp_get_system_sec  (void);

#ifdef __cplusplus
}
#endif

#endif /*__RTPTIME_H__*/

/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
