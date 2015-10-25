 /*
 | RTPTIMER.H - 
 |
 | EBS - 
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
*/

#ifndef __RTPTIMER_H__
#define __RTPTIMER_H__

#include "rtp.h"

struct s_RTPTimerJob;

typedef struct s_RTPTimerJob RTPTimerJob;

struct s_RTPTimerJob
{
	RTPTimerJob*  next;
	RTPTimerJob*  prev;
	unsigned long scheduledTimeMsec;
	void        (*timerFunction) (int,void*);
	void*         timerData;
	unsigned long repeat;
	unsigned      listId;
};

typedef RTPTimerJob RTP_TIMER;

#define RTP_TIMER_STATUS_CANCELLED   -1

#define RTP_TIMER_REPEAT_INFINITE     0x7fffffff

#ifdef __cplusplus
extern "C" {
#endif

int  rtp_timer_init     (void);

void rtp_timer_shutdown (void);

int  rtp_timer_start    (RTP_TIMER* timer, 
                         void (*fn)(int, void*), 
                         void* data, 
                         long msecInterval,
                         unsigned long repeat);
                        
int  rtp_timer_stop     (RTP_TIMER* timer);

#ifdef __cplusplus
}
#endif

#endif /* __RTPTIMER_H__ */
