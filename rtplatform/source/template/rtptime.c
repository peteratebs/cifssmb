 /*
 | RTPTIME.C - Runtime Platform Timing Services
 |
 | EBS - RT-Platform 
 |
 |  $Author: vmalaiya $
 |  $Date: 2006/07/17 15:29:02 $
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
/** @memo   Retrieves the elapsed milliseconds since the 
    application started.

    @doc    Retrieves the elapsed milliseconds since the 
    application started. Can be used as a millisecond timer 
    by storing the first call and periodically checking 
    against successive calls until the timeout period has 
    been reached.

    @return The elapsed milliseconds. There is no error return.
 */
unsigned long rtp_get_system_msec (void)
{
    rtp_not_yet_implemented ();
    return (0);
}


/*----------------------------------------------------------------------*
                         rtp_get_system_sec
 *----------------------------------------------------------------------*/
/** @memo   Retrieves the elapsed seconds since the 
    application started.

    @doc    Retrieves the elapsed seconds since the 
    application started. Can be used as a second timer 
    by storing the first call and periodically checking 
    against successive calls until the timeout period 
    has been reached.

    @return The elapsed seconds. There is no error return.
 */
unsigned long rtp_get_system_sec (void)
{
    rtp_not_yet_implemented ();
    return (0);
}


/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
