 /*
 | RTPTIME.C - Runtime Platform Timing Services
 |
 |   PORTED TO THE LINUX PLATFORM
 |
 | EBS - RT-Platform
 |
 |  $Author: vmalaiya $
 |  $Date: 2006/07/17 15:29:01 $
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



/************************************************************************
* Headers
************************************************************************/
#include "rtp.h"
#include "rtptime.h"

#include <sys/time.h>

/************************************************************************
* Defines
************************************************************************/

/************************************************************************
* Types
************************************************************************/

/************************************************************************
* Data
************************************************************************/

/************************************************************************
* Macros
************************************************************************/

/************************************************************************
* Function Prototypes
************************************************************************/

/************************************************************************
* Function Bodies
************************************************************************/

/*----------------------------------------------------------------------*
                         rtp_get_system_msec
 *----------------------------------------------------------------------*/
unsigned long rtp_get_system_msec (void)
{
unsigned long elapsed_msec;
struct timeval timeval;

    gettimeofday (&timeval, 0);
    elapsed_msec = (unsigned long) (timeval.tv_sec * 1000 + timeval.tv_usec / 1000);
    return (elapsed_msec);
}


/*----------------------------------------------------------------------*
                         rtp_get_system_sec
 *----------------------------------------------------------------------*/
unsigned long rtp_get_system_sec (void)
{
unsigned long elapsed_sec;
struct timeval timeval;

    gettimeofday (&timeval, 0);
    elapsed_sec = (unsigned long)timeval.tv_sec;
    return (elapsed_sec);
}


/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
