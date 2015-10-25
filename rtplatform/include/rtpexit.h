 /*
 | RTPEXIT.H - Runtime Platform Services
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

#ifndef __RTPEXIT_H__
#define __RTPEXIT_H__

#include "rtp.h"

/************************************************************************
 * Type definitions
 ************************************************************************/

/************************************************************************
 * Kernel API                                                           *
 ************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

void rtp_abort (void);
void rtp_exit  (int exitvalue);

#ifdef __cplusplus
}
#endif

#endif /* __RTPEXIT_H__ */

/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
