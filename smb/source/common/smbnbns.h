#ifndef __SMB_NBNS_H__
#define __SMB_NBNS_H__

#include "smbdefs.h"
#include "smbnb.h"
#include "rtpnet.h"

#define RTSMB_NBNS_TYPE_NB	           0x20
#define RTSMB_NBNS_CLASS_IN	           0x1

#define RTSMB_NBNS_PORT                 137 // well-known port number
#define RTSMB_NBNS_PORT_ALT            9137 // possibly use alternative port
                                            // for ease of debugging

typedef struct
{
	word id;
	word flags;

	word question_count;
	word answer_count;
	word authority_count;
	word additional_count;
} RTSMB_NBNS_HEADER;
typedef RTSMB_NBNS_HEADER RTSMB_FAR *PRTSMB_NBNS_HEADER;

typedef struct
{
	char name[RTSMB_NB_NAME_SIZE + 1];	/* null ended */

	word type;
	word class;

} RTSMB_NBNS_QUESTION;
typedef RTSMB_NBNS_QUESTION RTSMB_FAR *PRTSMB_NBNS_QUESTION;

typedef struct
{
	BBOOL pointer;
	char name[RTSMB_NB_NAME_SIZE + 1];	/* null ended */

	word type;
	word class;
	dword time_to_live;

	word data_size;
	PFBYTE data;

} RTSMB_NBNS_RESOURCE;
typedef RTSMB_NBNS_RESOURCE RTSMB_FAR *PRTSMB_NBNS_RESOURCE;

typedef struct
{
	RTSMB_UINT16 flags;
	RTSMB_UINT8  ip_addr[4];
}
RTSMB_NBNS_NAME_INFO;
typedef RTSMB_NBNS_NAME_INFO RTSMB_FAR * PRTSMB_NBNS_NAME_INFO;


int rtsmb_nbns_fill_header (PFVOID buf, rtsmb_size size,
	PFVOID origin, PRTSMB_NBNS_HEADER pHeader);
int rtsmb_nbns_read_header (PFVOID buf, rtsmb_size size,
	PFVOID origin, PRTSMB_NBNS_HEADER pHeader);

int rtsmb_nbns_fill_question (PFVOID buf, rtsmb_size size,
	PFVOID origin, PRTSMB_NBNS_QUESTION pQuestion);
int rtsmb_nbns_read_question (PFVOID buf, rtsmb_size size,
	PFVOID origin, PRTSMB_NBNS_QUESTION pQuestion);

int rtsmb_nbns_fill_resource (PFVOID buf, rtsmb_size size,
	PFVOID origin, PRTSMB_NBNS_RESOURCE pResource);
int rtsmb_nbns_read_resource (PFVOID buf, rtsmb_size size,
	PFVOID origin, PRTSMB_NBNS_RESOURCE pResource);

int rtsmb_nbns_fill_name_query (PFVOID buf, rtsmb_size size, word id, PFCHAR name, byte name_type);

int rtsmb_nbns_read_name_query_response (PFVOID buf, rtsmb_size size, PRTSMB_NBNS_NAME_INFO info, int max_entries);

#define RTSMB_NBNS_QUERY_STATUS_PENDING  0
#define RTSMB_NBNS_QUERY_STATUS_RESOLVED 1
#define RTSMB_NBNS_QUERY_STATUS_TIMEOUT  2
#define RTSMB_NBNS_QUERY_STATUS_ERROR    3
#define RTSMB_NBNS_QUERY_STATUS_CLOSED   4

typedef struct
{
	RTP_SOCKET sock;
	PFCHAR     name;
	int        status;
	long       start_time_msec;
	int        retries_left;
	int        timeout_msec;
}
RTSMB_NBNS_NAME_QUERY;
typedef RTSMB_NBNS_NAME_QUERY RTSMB_FAR * PRTSMB_NBNS_NAME_QUERY;

/*-----------------------------------------------------------------------------
 rtsmb_nbns_query_name - initiate a NetBIOS name query

 query - pointer to a user-managed instance of a RTSMB_NBNS_NAME_QUERY struct.
 name  - the name of the server to query (since the query struct only stores
         a reference to the string and not a copy of the string, the data this
         argument points to must remain valid for the duration of the name
         query)

 This function initializes the query data structure and sends a name query
 broadcast on the network.  The status of this query can be retrieved at any
 time by checking query->status, which takes one of the following values:

   RTSMB_NBNS_QUERY_STATUS_PENDING  - the query has been sent and we are
                                      waiting for the response
   RTSMB_NBNS_QUERY_STATUS_RESOLVED - a response has arrived; to retrieve the
                                      information, call
                                      rtsmb_nbns_get_name_query_response
   RTSMB_NBNS_QUERY_STATUS_TIMEOUT  - the query has timed out without a
                                      response
   RTSMB_NBNS_QUERY_STATUS_ERROR    - an error has occurred which prevents
                                      the query from completing
   RTSMB_NBNS_QUERY_STATUS_CLOSED   - this query is closed

 The status field of a RTSMB_NBNS_NAME_QUERY is only updated inside
 rtsmb_nbns_query_cycle.  If the status is anything but
 RTSMB_NBNS_QUERY_STATUS_CLOSED, rtsmb_nbns_close_query must eventually
 be called to release any resources associated with the name query.

 Returns
  0 on success
  <0 on failure
 ----------------------------------------------------------------------------*/

int  rtsmb_nbns_query_name (PRTSMB_NBNS_NAME_QUERY query, PFCHAR name);

/*-----------------------------------------------------------------------------
 rtsmb_nbns_query_cycle - Update the status of a set of queries

 queryList   - an array of RTSMB_NBNS_NAME_QUERY structs.
 listSize    - the size of the array
 msecTimeout - the maximum number of milliseconds to wait for any network I/O

 ----------------------------------------------------------------------------*/

void rtsmb_nbns_query_cycle (PRTSMB_NBNS_NAME_QUERY queryList, int listSize, long msecTimeout);

/*-----------------------------------------------------------------------------
 rtsmb_nbns_get_name_query_response - Read the result of a query

 query   - the name query that is resolved
 info    - an array of RTSMB_NBNS_NAME_INFO structs to hold the resolution data
 max_entries - the size of the array

 Returns
  0 on success
  <0 on failure
 ----------------------------------------------------------------------------*/

int  rtsmb_nbns_get_name_query_response (PRTSMB_NBNS_NAME_QUERY query, PRTSMB_NBNS_NAME_INFO info, int max_entries);

/*-----------------------------------------------------------------------------
 rtsmb_nbns_close_query - Must be called to release resources associated
                          with a NetBIOS name query

 This function must be called if the query->status is anything except
 RTSMB_NBNS_QUERY_STATUS_CLOSED.
 ----------------------------------------------------------------------------*/

void rtsmb_nbns_close_query (PRTSMB_NBNS_NAME_QUERY query);

#endif /* __SMB_NBNS_H__ */
