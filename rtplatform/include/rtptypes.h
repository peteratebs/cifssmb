 /*
 | RTPTYPES.H - Runtime Platform Services
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

#ifndef __RTPTYPES_H__
#define __RTPTYPES_H__

#define RTP_FAR
#define RTP_CONST  const
#define RTP_EXTERN extern

typedef char                              RTP_INT8;
typedef RTP_CONST char                    RTP_CINT8;
typedef unsigned char                     RTP_UINT8;
typedef RTP_CONST unsigned char           RTP_CUINT8;
typedef short                             RTP_INT16;
typedef RTP_CONST short                   RTP_CINT16;
typedef unsigned short                    RTP_UINT16;
typedef RTP_CONST unsigned short          RTP_CUINT16;
typedef long                              RTP_INT32;
typedef RTP_CONST long                    RTP_CINT32;
typedef unsigned long                     RTP_UINT32;
typedef RTP_CONST unsigned long           RTP_CUINT32;
                                     
typedef char                              RTP_CHAR;
typedef RTP_CONST char                    RTP_CCHAR;
typedef unsigned char                     RTP_UCHAR;
typedef RTP_CONST unsigned char           RTP_CUCHAR;
                                     
typedef char RTP_FAR*                     RTP_PFINT8;
typedef unsigned char RTP_FAR*            RTP_PFUINT8;
typedef RTP_CONST unsigned char RTP_FAR*  RTP_PFCUINT8;
typedef short RTP_FAR*                    RTP_PFINT16;
typedef unsigned short RTP_FAR*           RTP_PFUINT16;
typedef RTP_CONST unsigned short RTP_FAR* RTP_PFCUINT16;
typedef long RTP_FAR*                     RTP_PFINT32;
typedef unsigned long RTP_FAR*            RTP_PFUINT32;
typedef RTP_CONST unsigned long RTP_FAR*  RTP_PFCUINT32;

typedef char RTP_FAR*                     RTP_PFCHAR;
typedef RTP_CONST char RTP_FAR*           RTP_PFCCHAR;
typedef unsigned char RTP_FAR*            RTP_PFUCHAR;
typedef RTP_CONST unsigned char RTP_FAR*  RTP_PFCUCHAR;

typedef unsigned                      RTP_BOOL;

#define RTP_TRUE  1
#define RTP_FALSE 0

#define KS_CONSTANT const
#if (__cplusplus)
#define KS_GLOBAL_CONSTANT extern const
#else
#define KS_GLOBAL_CONSTANT const
#endif
#define KS_EXTERN_GLOBAL_CONSTANT extern const
typedef int RTP_FAR *                     RTP_PFINT;
typedef void  RTP_FAR *                   RTP_PFVOID;
typedef long  RTP_FAR *                   RTP_PFLONG;
typedef KS_CONSTANT char  RTP_FAR * PFCCHAR;
#if (0)  /* 64bitpointer */ /* tbd - move to rtplatform */
#define RTP_UINT64     unsigned long long
#define RTP_INT64      long long
#define RTP_UADDR      RTP_UINT64
#define RTP_ADDR       RTP_INT64
#define RTP_VOID_ADDR  RTP_INT64
#else
#define RTP_UADDR      RTP_UINT32
#define RTP_ADDR       RTP_INT32
#define RTP_VOID_ADDR  RTP_INT32
#endif
#define RTP_NUM_INTS 1 /* hopefully not used (number of interrupts) */
typedef	int PRTIP_CALLBACKS; // wrong
void RTP_DEBUG_ERROR(RTP_PFCCHAR string, int type, RTP_UINT32 val1, RTP_UINT32 val2);
#endif /*__RTPTYPES_H__*/



/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
