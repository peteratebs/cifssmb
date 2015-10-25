 /*
 | RTPTHRD.C - Runtime Platform Thread Services
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
#include "rtpthrd.h"
#include "rtpsignl.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/************************************************************************
* Defines
************************************************************************/
/* Thread status flag values. May be by the kernel background timer task
   to provide an orderly approach to ending tasks and freeing task stacks */
#define RTP_THREAD_IS_FREE             0
#define RTP_THREAD_STARTING            1
#define RTP_THREAD_IS_RUNNING          2
#define RTP_THREAD_MUST_BE_KILLED      3
#define RTP_THREAD_STACK_MUST_BE_FREED 4

/************************************************************************
* Type definitions
*************************************************************************/
typedef struct _rtp_thread_context
{
    int        state;
    int        priority;
    char       name[CFG_NAME_SIZE];
	void     (*entryPoint)(void *);
	void      *userData;
}
rtp_thread_context;

/************************************************************************
* Data
************************************************************************/
const unsigned int stackSizeMap [5] = {
                               0x1000,
							   0x2000,
							   0x4000,
							   0x8000,
							   0xffff
                             };

static pthread_key_t threadKey;

/************************************************************************
* Macros
************************************************************************/

/************************************************************************
* Utility Function Prototypes
************************************************************************/
void *_rtp_threadFunction(void *ctx);
rtp_thread_context * _rtp_allocThreadContext(void);
void _rtp_freeThreadContext(rtp_thread_context *ctx);

/************************************************************************
* Function Bodies
************************************************************************/

/************************************************************************
 * Thread services                                                      *
 ************************************************************************/

/*----------------------------------------------------------------------*
                            rtp_threads_init
 *----------------------------------------------------------------------*/
int rtp_threads_init (void)
{
    if(pthread_key_create( &threadKey, NULL))
	{
		threadKey = 0;
		return(-1);
	}
	return(0);
}


/*----------------------------------------------------------------------*
                           rtp_threads_shutdown
 *----------------------------------------------------------------------*/
void rtp_threads_shutdown (void)
{
	pthread_key_delete( threadKey );
}


/*----------------------------------------------------------------------*
                            rtp_thread_spawn
 *----------------------------------------------------------------------*/
int rtp_thread_spawn (RTP_HANDLE         * newThread,
                      RTP_ENTRY_POINT_FN   entryPoint,
                      const char         * name,
                      int                  stackSizeIndex,
                      int                  priorityIndex,
                      void               * userData)
{
pthread_t hThread;
pthread_attr_t attrs;
rtp_thread_context *ctx;
size_t stackSize;
int response;

	ctx = _rtp_allocThreadContext();
	if (!ctx)
	{
		return (-1);
	}

	ctx->state = RTP_THREAD_STARTING;

    if (stackSizeIndex < -2)
	{
		stackSizeIndex = -2;
	}

	if (stackSizeIndex > 2)
	{
		stackSize = (size_t) stackSizeIndex;
	}
	else
	{
		stackSize = (size_t) stackSizeMap[stackSizeIndex + 2];
	}

	if (name)
	{
    	strncpy (ctx->name, name, CFG_NAME_SIZE-1);
    	ctx->name[CFG_NAME_SIZE-1] = '\0';
    }
    else
    {
    	ctx->name[0] = 0;
    }

	ctx->priority   = 0;
	ctx->entryPoint = entryPoint;
	ctx->userData   = userData;

    if (pthread_attr_init (&attrs))
    {
        _rtp_freeThreadContext (ctx);
        return (-1);
    }

#ifdef _POSIX_THREAD_ATTR_STACKSIZE
stackSize = 0x40000;
    pthread_attr_setstacksize (&attrs, stackSize);
#endif

#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
    {
        /* Not fully implemented right now.  Correct thing to do would be
           to change the sched_policy and then adjust sched_priority to
           be something within min and max allowable values. */
        struct sched_param params;
        params.sched_priority = 0;
        pthread_attr_setschedparam (&attrs, &params);
    }
#endif

    pthread_attr_setdetachstate (&attrs, PTHREAD_CREATE_DETACHED);

	response = pthread_create(&hThread,             /* returns the thread identifier */
                              &attrs,               /* thread attributes */
	                          _rtp_threadFunction,  /* thread function */
	                          (void *) ctx);        /* argument to thread function */

	/* Check the return value for success. */
	if (response != 0)
	{
		_rtp_freeThreadContext (ctx);
		return (-1);
	}

	*newThread = (RTP_HANDLE) ctx;

    return (0);
}


/*----------------------------------------------------------------------*
                            rtp_thread_handle
 *----------------------------------------------------------------------*/
int rtp_thread_handle (RTP_HANDLE * currentThread)
{
    *currentThread = (RTP_HANDLE) pthread_getspecific (threadKey);

	if (*currentThread)
	{
		return (0);
	}

	return (-1);
}


/*----------------------------------------------------------------------*
                          rtp_thread_user_data
 *----------------------------------------------------------------------*/
int rtp_thread_user_data (void ** userData)
{
	RTP_HANDLE currentHandle;

    if (rtp_thread_handle(&currentHandle) != 0)
    {
        return (-1);
    }

    return (rtp_thread_user_data_by_handle (currentHandle, userData));
}


/*----------------------------------------------------------------------*
                       rtp_thread_user_data_by_handle
 *----------------------------------------------------------------------*/
int rtp_thread_user_data_by_handle (RTP_HANDLE handle, void ** userData)
{
	*userData = ((rtp_thread_context *) handle)->userData;
	return (0);
}


/*----------------------------------------------------------------------*
                              rtp_thread_name
 *----------------------------------------------------------------------*/
int rtp_thread_name (char ** name)
{
	RTP_HANDLE currentHandle;

    if (rtp_thread_handle(&currentHandle) != 0)
    {
        return (-1);
    }

    return (rtp_thread_name_by_handle (currentHandle, name));
}


/*----------------------------------------------------------------------*
                          rtp_thread_name_by_handle
 *----------------------------------------------------------------------*/
int rtp_thread_name_by_handle (RTP_HANDLE handle, char ** name)
{
	*name = ((rtp_thread_context *) handle)->name;
	return (0);
}


/*----------------------------------------------------------------------*
                             rtp_thread_sleep
 *----------------------------------------------------------------------*/
void rtp_thread_sleep (long msecs)
{
    if (msecs < 0)
    {
        return;
    }
    else
    {
        usleep ((__useconds_t)msecs);
    }
}


/*----------------------------------------------------------------------*
                             rtp_thread_yield
 *----------------------------------------------------------------------*/
void rtp_thread_yield (void)
{
    sleep (0);
}


/************************************************************************
* Internal utility functions
************************************************************************/

void *_rtp_threadFunction(void * ctx )
{
rtp_thread_context *t = (rtp_thread_context *) ctx;
    pthread_setspecific(threadKey, ctx);

    t->state = RTP_THREAD_IS_RUNNING;
	t->entryPoint(t->userData);
	_rtp_freeThreadContext(t);

	pthread_exit (NULL);
    return (0);
}


rtp_thread_context * _rtp_allocThreadContext(void)
{
	return ((rtp_thread_context *) malloc(sizeof(rtp_thread_context)));
}

void _rtp_freeThreadContext(rtp_thread_context *ctx)
{
	free(ctx);
}

/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
