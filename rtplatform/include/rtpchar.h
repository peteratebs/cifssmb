/*
|  RTPCHAR.H - Runtime Platform Character Utilities
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

#ifndef __RTPCHAR_H__
#define __RTPCHAR_H__

/*#define rtp_isalnum   */
/*#define rtp_iscntrl   */
/*#define rtp_isdigit   */
/*#define rtp_isprint   */
/*#define rtp_isspace   */
/*#define rtp_isupper   */
/*#define rtp_isxdigit  */
/*#define rtp_tolower   */
/*#define rtp_toupper   */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef rtp_isalnum
int rtp_isalnum  (int chr);
#endif
#ifndef rtp_iscntrl
int rtp_iscntrl  (int ch);
#endif
#ifndef rtp_isdigit
int rtp_isdigit  (int ch);
#endif
#ifndef rtp_isprint
int rtp_isprint  (int ch);
#endif
#ifndef rtp_isspace
int rtp_isspace  (int ch);
#endif
#ifndef rtp_isupper
int rtp_isupper  (int ch);
#endif
#ifndef rtp_isxdigit
int rtp_isxdigit (int chr);
#endif
#ifndef rtp_tolower
int rtp_tolower  (int c);
#endif
#ifndef rtp_toupper
int rtp_toupper  (int c);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __RTPCHAR_H__ */
