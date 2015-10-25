/*
|  RTPRAND.H - Runtime Platform Pseudo-random number generator
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

#ifndef __RTPRAND_H__
#define __RTPRAND_H__

/*#define rtp_rand  */
/*#define rtp_srand */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef rtp_rand
int  rtp_rand  (void);
#endif
#ifndef rtp_srand
void rtp_srand (unsigned int seed);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __RTPRAND_H__ */
