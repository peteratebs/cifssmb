 /*
 | RTPTERM.H - Runtime Platform Services
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

#ifndef __RTPTERM_H__
#define __RTPTERM_H__

#include "rtp.h"


/************************************************************************
 * Terminal API                                                         *
 ************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

int     rtp_term_init           (void);
int     rtp_term_kbhit          (void);
int     rtp_term_getch          (void);
void    rtp_term_putc           (char ch);
void    rtp_term_puts           (const char * string);
int     rtp_term_cputs          (const char * string);
int     rtp_term_gets           (char * string);
int     rtp_term_promptstring   (char * string, unsigned int handle_arrows);

int     rtp_term_up_arrow       (void);
int     rtp_term_down_arrow     (void);
int     rtp_term_left_arrow     (void);
int     rtp_term_right_arrow    (void);
int     rtp_term_escape_key     (void);

#ifdef __cplusplus
}
#endif

#endif /* __RTPTERM_H__ */

/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
