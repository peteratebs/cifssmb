 /*
 | RTPDLLIST.C - 
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

/*****************************************************************************
 * Header files
 *****************************************************************************/

#include "rtpdllist.h"

/*****************************************************************************
 * Macros
 *****************************************************************************/

/*****************************************************************************
 * Types
 *****************************************************************************/

/*****************************************************************************
 * Function Prototypes
 *****************************************************************************/

/*****************************************************************************
 * Data
 *****************************************************************************/

/*****************************************************************************
 * Function Definitions
 *****************************************************************************/

#ifndef RTP_DLLIST_INLINE

/*---------------------------------------------------------------------------*/
void rtp_dllist_init (
		RTP_DLLIST_NODE* x
	)
{
	RTP_DLLIST_INIT(x);
}

/*---------------------------------------------------------------------------*/
void rtp_dllist_insert_after (
		RTP_DLLIST_NODE* x,
		RTP_DLLIST_NODE* y
	)
{
	RTP_DLLIST_INSERT_AFTER(x,y);
}

/*---------------------------------------------------------------------------*/
void rtp_dllist_insert_before (
		RTP_DLLIST_NODE* x,
		RTP_DLLIST_NODE* y
	)
{
	RTP_DLLIST_INSERT_BEFORE(x,y);
}

/*---------------------------------------------------------------------------*/
void rtp_dllist_remove (
		RTP_DLLIST_NODE* x
	)
{
	RTP_DLLIST_REMOVE(x);
}

/*---------------------------------------------------------------------------*/
void rtp_dllist_replace (
		RTP_DLLIST_NODE* x,
		RTP_DLLIST_NODE* r
	)
{
	RTP_DLLIST_REPLACE(x,r);
}

#endif /* RTP_DLLIST_INLINE */
