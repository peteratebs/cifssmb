/*
|  RTPROT.H - 
| 
|  EBS - 
| 
|   $Author: vmalaiya $
|   $Date: 2006/07/17 15:29:00 $
|   $Name:  $
|   $Revision: 1.3 $
| 
|  Copyright EBS Inc. , 2006
|  All rights reserved.
|  This code may not be redistributed in source or linkable object form
|  without the consent of its author.
*/ 

#ifndef __RTPROT_H__
#define __RTPROT_H__

#ifdef __cplusplus
extern "C" {
#endif

unsigned long   rtp_lrotl    (unsigned long, int);
unsigned long   rtp_lrotr    (unsigned long, int);

#ifdef __cplusplus
}
#endif

#endif /* __RTPROT_H__ */
