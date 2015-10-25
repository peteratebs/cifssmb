 /*
 | RTPSIGNL.C - Runtime Platform Signal Services
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
#include "rtpsignl.h"
#include "rtpdebug.h"

#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

/************************************************************************
* Defines
************************************************************************/

/************************************************************************
* Types
************************************************************************/
typedef struct s_RTP_Sem_Struct
{
	pthread_mutex_t	mutex;
	pthread_cond_t	condition;
	int			    semCount;
}_RTP_Sem_Struct;

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

/************************************************************************
 * Semaphore [signalling] services                                      *
 ************************************************************************/

/*----------------------------------------------------------------------*
                         _rtp_sig_semaphore_alloc
 *----------------------------------------------------------------------*/
int _rtp_sig_semaphore_alloc (RTP_HANDLE *newSem, const char *name)
{
	_RTP_Sem_Struct*    token;

	token = (_RTP_Sem_Struct*) malloc(sizeof(_RTP_Sem_Struct));

	if(pthread_mutex_init(&(token->mutex), NULL))
	{
		free(token);
		return (-1);
	}

	if(pthread_cond_init(&(token->condition), NULL))
	{
		pthread_mutex_destroy(&(token->mutex));
		free(token);
		return (-1);
	}

	token->semCount = 0;
	*newSem = (RTP_HANDLE)token;
	return(0);
}


/*----------------------------------------------------------------------*
                         _rtp_sig_semaphore_free
 *----------------------------------------------------------------------*/
void _rtp_sig_semaphore_free (RTP_HANDLE semHandle)
{
	_RTP_Sem_Struct* token;
	token = (_RTP_Sem_Struct*)semHandle;
	pthread_mutex_destroy(&(token->mutex));
	pthread_cond_destroy(&(token->condition));
	free (token);
}


/*----------------------------------------------------------------------*
                       _rtp_sig_semaphore_wait_timed
 *----------------------------------------------------------------------*/
int _rtp_sig_semaphore_wait_timed (RTP_HANDLE semHandle, long msecs)
{
	int retVal;
	_RTP_Sem_Struct* token;
	struct timespec ts;
	struct timeval tp;

	token = (_RTP_Sem_Struct*)semHandle;

	if (pthread_mutex_lock(&(token->mutex)))
	{
		return (-1);
	}

    retVal =  gettimeofday(&tp, NULL);

    /* Convert from timeval to timespec */
    ts.tv_sec  = tp.tv_sec;
    tp.tv_usec += msecs;
    ts.tv_nsec = tp.tv_usec * 1000;


	while (token->semCount <= 0)
	{
		retVal = pthread_cond_timedwait(&(token->condition), &(token->mutex), &ts);
		if (retVal && (errno != EINTR) )
		break;
	}
	if ( retVal )
	{
		if (pthread_mutex_unlock(&(token->mutex)) )
		{
			return (-1);
		}
		return (-1);
	}

	token->semCount--;

	if (pthread_mutex_unlock(&(token->mutex)))
	{
		return (-1);
	}
	return(0);
}


/*----------------------------------------------------------------------*
                          _rtp_sig_semaphore_clear
 *----------------------------------------------------------------------*/
void _rtp_sig_semaphore_clear (RTP_HANDLE semHandle)
{
    while (_rtp_sig_semaphore_wait_timed (semHandle, 0) == 0)
    {
        ;
    }
}


/*----------------------------------------------------------------------*
                          _rtp_sig_semaphore_wait
 *----------------------------------------------------------------------*/
int _rtp_sig_semaphore_wait (RTP_HANDLE semHandle)
{
	int retVal;
	_RTP_Sem_Struct* token;
	token = (_RTP_Sem_Struct*)semHandle;

	if (pthread_mutex_lock(&(token->mutex)))
	{
		return (-1);
	}

	while (token->semCount <= 0)
	{
		retVal = pthread_cond_wait(&(token->condition), &(token->mutex));
		if (retVal && errno != EINTR )
		{
			if (pthread_mutex_unlock(&(token->mutex)))
			{
				return (-1);
			}
			return(-1);
		}
	}

	token->semCount--;

	if (pthread_mutex_unlock(&(token->mutex)))
	{
		return (-1);
	}
	return(0);
}


/*----------------------------------------------------------------------*
                         _rtp_sig_semaphore_signal
 *----------------------------------------------------------------------*/
void _rtp_sig_semaphore_signal (RTP_HANDLE semHandle)
{
	_RTP_Sem_Struct* token;
	token = (_RTP_Sem_Struct*)semHandle;

	pthread_mutex_lock(&(token->mutex));
	token->semCount ++;
	pthread_mutex_unlock(&(token->mutex));
	pthread_cond_signal(&(token->condition));
}


/*----------------------------------------------------------------------*
                       _rtp_sig_semaphore_signal_isr
 *----------------------------------------------------------------------*/
void _rtp_sig_semaphore_signal_isr (RTP_HANDLE semHandle)
{
	_RTP_Sem_Struct* token;
	token = (_RTP_Sem_Struct*)semHandle;

	pthread_mutex_lock(&(token->mutex));
	token->semCount ++;
	pthread_mutex_unlock(&(token->mutex));
	pthread_cond_signal(&(token->condition));
}


/************************************************************************
 * Mutex [lock] services                                                *
 ************************************************************************/

/*----------------------------------------------------------------------*
                          _rtp_sig_mutex_alloc
 *----------------------------------------------------------------------*/
int _rtp_sig_mutex_alloc (RTP_HANDLE *newMutex, const char *name)
{
    pthread_mutex_t *linMutex;
    pthread_mutexattr_t attrs;

    linMutex = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t));
    if (!linMutex)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_sig_mutex_alloc: error could not allocate memory.\n");
#endif
        return(-1);
    }

    pthread_mutexattr_init (&attrs);
    pthread_mutexattr_settype (&attrs, PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init (linMutex, &attrs);
    pthread_mutexattr_destroy (&attrs);

    *newMutex = (RTP_HANDLE)linMutex;
    return(0);
}


/*----------------------------------------------------------------------*
                          _rtp_sig_mutex_free
 *----------------------------------------------------------------------*/
void _rtp_sig_mutex_free (RTP_HANDLE mutexHandle)
{
    if (pthread_mutex_destroy((pthread_mutex_t *)mutexHandle) != 0)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_sig_mutex_free: error mutex is locked.\n");
#endif
    }

    free((void *)mutexHandle);
}


/*----------------------------------------------------------------------*
                       _rtp_sig_mutex_claim_timed
 *----------------------------------------------------------------------*/
int _rtp_sig_mutex_claim_timed (RTP_HANDLE mutexHandle, long msecs)
{
#ifdef LINUXTOBEIMPLEMENTED
    DWORD result;

#ifdef RTP_DEBUG
    int  err;
    /* ----------------------------------- */
    /*  Clear the error state by setting   */
    /*  to 0.                              */
    /* ----------------------------------- */
    SetLastError (0);
#endif

    if (msecs == (-1))
    {
        result = WaitForSingleObject((HANDLE)mutexHandle, INFINITE);
    }
    else
    {
        result = WaitForSingleObject((HANDLE)mutexHandle, msecs);
    }

    if (result == WAIT_FAILED || result == WAIT_TIMEOUT)
    {
#ifdef RTP_DEBUG
        err = GetLastError();
        RTP_DEBUG_OUTPUT_STR("rtp_sig_mutex_claim_timed: error returned ");
        RTP_DEBUG_OUTPUT_INT(err);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }

    return (0);
#else
    return (0);
#endif
}


/*----------------------------------------------------------------------*
                          _rtp_sig_mutex_claim
 *----------------------------------------------------------------------*/
int _rtp_sig_mutex_claim (RTP_HANDLE mutexHandle)
{
    if (pthread_mutex_lock((pthread_mutex_t *)mutexHandle) != 0)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_sig_mutex_claim: error invalid mutex.\n");
#endif
        return (-1);
    }

    return (0);
}


/*----------------------------------------------------------------------*
                          _rtp_sig_mutex_release
 *----------------------------------------------------------------------*/
void _rtp_sig_mutex_release (RTP_HANDLE mutexHandle)
{
    if (pthread_mutex_unlock((pthread_mutex_t *)mutexHandle) != 0)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_sig_mutex_release: error invalid mutex.\n");
#endif
    }
}


/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
