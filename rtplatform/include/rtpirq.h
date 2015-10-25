 /*
 | RTPIRQ.H - Runtime Platform IRQ Services
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

#ifndef __RTPIRQ_H__
#define __RTPIRQ_H__

#include "rtp.h"

/************************************************************************
 * Type definitions
 ************************************************************************/
typedef RTP_HANDLE RTP_IRQCNTXT;

/************************************************************************
 * Kernel API                                                           *
 ************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

RTP_IRQCNTXT rtp_irq_push_disable (void);
void         rtp_irq_pop          (RTP_IRQCNTXT previousLevel);
void         rtp_irq_disable      (void);
void         rtp_irq_enable       (void);

#ifdef __cplusplus
}
#endif

#endif /* __RTPIRQ_H__ */

/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
