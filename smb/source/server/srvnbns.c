//
// SRVNBNS.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// This file contains all the functions necessary for the RTSMB server to be a member
// of the local network workgroup.  Here, we send out name registration requests and
// respond to name queries.

#include "smbdefs.h"
#include "rtpchar.h"  /* _YI_ 9/24/2004 */
#include "rtpscnv.h"  /* _YI_ 9/24/2004 */
#include "rtpprint.h" /* _VM_ 12/27/2004 */

#if (INCLUDE_RTSMB_SERVER)

#include "srvnbns.h"
#include "srvnet.h"
#include "smbnb.h"
#include "srvrsrcs.h"
#include "srvutil.h"

#include "srvcfg.h"
#include "smbutil.h"
#include "smbnbns.h"
#include "smbpack.h"
#include "smbnet.h"
#include "smbnbds.h"
#include "srvrap.h"
#include "srvbrws.h"
#include "smbdebug.h"

#include "rtptime.h"
#include "rtpsignl.h"
#include "rtpscnv.h"


//============================================================================
//    IMPLEMENTATION PRIVATE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
#define NAME_TABLE_SIZE				20 /* _YI_ */
#define NAME_CACHE_SIZE				2 /* only needed for master browser lookups and our server-client right now */
#define NAME_QUERY_SIZE				NAME_CACHE_SIZE

#define NB_FLAGS_BNODE	(0)
#define NB_FLAGS_PNODE	(0x2000)
#define NB_FLAGS_MNODE	(0x4000)
#define NB_FLAGS_GROUP	(0x8000)

typedef enum
{
	NS_NONAME = 0,
	NS_PENDING,
	NS_REGISTERED
} NBS_NAMESTATE_T;

//============================================================================
//    IMPLEMENTATION PRIVATE STRUCTURES
//============================================================================

typedef struct
{
	char name[RTSMB_NB_NAME_SIZE+1];	// space-filled
	BBOOL group;
	BBOOL announce;
	NBS_NAMESTATE_T status;
	word transID;
	int numSent;
	unsigned long nextSendBase;

} NBS_NAME_TABLE_ENTRY_T;
typedef NBS_NAME_TABLE_ENTRY_T RTSMB_FAR *PNBS_NAME_TABLE_ENTRY;

typedef struct
{
	BBOOL inUse;
	char name[RTSMB_NB_NAME_SIZE+1];	// space-filled
	byte ip [4];

} NBS_NAME_CACHE_ENTRY_T;
typedef NBS_NAME_CACHE_ENTRY_T RTSMB_FAR *PNBS_NAME_CACHE_ENTRY;

typedef struct
{
	BBOOL inUse;
	char name[RTSMB_NB_NAME_SIZE+1];	// space-filled
	int numQueries;
	unsigned long endTimeBase;

} NBS_NAME_QUERY_ENTRY_T;
typedef NBS_NAME_QUERY_ENTRY_T RTSMB_FAR *PNBS_NAME_QUERY_ENTRY;


//============================================================================
//    IMPLEMENTATION REQUIRED EXTERNAL REFERENCES (AVOID)
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE DATA
//============================================================================
RTSMB_STATIC NBS_NAME_TABLE_ENTRY_T nameTable[NAME_TABLE_SIZE];	// our own names

RTSMB_STATIC NBS_NAME_CACHE_ENTRY_T nameCache[NAME_CACHE_SIZE];	// names of others
RTSMB_STATIC int lastCacheIndex;	// last inserted cache index

RTSMB_STATIC NBS_NAME_QUERY_ENTRY_T nameQueryTable[NAME_QUERY_SIZE];	// names waiting to be queried
RTSMB_STATIC int lastQueryIndex;	// last inserted query index
RTSMB_STATIC unsigned long nameQueryTableSem;

//============================================================================
//    INTERFACE DATA
//============================================================================
char ns_groupName[RTSMB_NB_NAME_SIZE+1];		// space appended name
char ns_groupNameAbrv[RTSMB_NB_NAME_SIZE+1];	// null ended name
char ns_netName[RTSMB_NB_NAME_SIZE+1];		// space appended name
char ns_netNameAbrv[RTSMB_NB_NAME_SIZE+1];	// null ended name
char ns_globalName[RTSMB_NB_NAME_SIZE+1];	// space appended name
char ns_globalNameAbrv[RTSMB_NB_NAME_SIZE+1];	// null ended name

RTSMB_STATIC BBOOL doAnnouncements;

//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTION PROTOTYPES
//============================================================================

RTSMB_STATIC word rtsmb_srv_nbns_get_next_transfer_id(void);
RTSMB_STATIC void rtsmb_srv_nbns_run_name_table (void);

RTSMB_STATIC void rtsmb_srv_nbns_send_name_register_request(word tranID, PFCHAR name, BBOOL group);
RTSMB_STATIC void rtsmb_srv_nbns_send_name_query(word tranID, PFCHAR name);
RTSMB_STATIC void rtsmb_srv_nbns_send_name_overwrite(word transID, PFCHAR name, BBOOL group);

//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTIONS
//============================================================================

/*
===============
 rtsmb_srv_nbns_add_name - adds a new name to the name table so that it may be claimed
 	newName - must be a valid netBios name of 16 characters
===============
*/
BBOOL rtsmb_srv_nbns_add_name (PFCHAR newName, BBOOL group, char suf, BBOOL announce)
{
	int i;
	for(i=0; i < NAME_TABLE_SIZE; i++)
	{
		if(nameTable[i].status == NS_NONAME)
		{
			rtsmb_util_make_netbios_name (nameTable[i].name, newName, (byte)suf);
			nameTable[i].group = group;
			nameTable[i].transID = rtsmb_srv_nbns_get_next_transfer_id();
			nameTable[i].announce = announce;
			nameTable[i].status = announce ? NS_PENDING : NS_REGISTERED;
			nameTable[i].nextSendBase = rtp_get_system_msec () - RTSMB_NB_BCAST_RETRY_TIMEOUT;
			nameTable[i].numSent = 0;

			if (announce)
			{
				doAnnouncements = TRUE;
			}

			return(TRUE);
		}
	}

	RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_nbns_add_name:  Name table is full\n", RTSMB_DEBUG_TYPE_ASCII);
	return(FALSE);
}

BBOOL rtsmb_srv_nbns_remove_name (PFCHAR name, char suf)
{
	int i;
	char nbs_name [RTSMB_NB_NAME_SIZE + 1];

	rtsmb_util_make_netbios_name (nbs_name, name, (byte)suf);

	for (i = 0; i < NAME_TABLE_SIZE; i++)
	{
		if(nameTable[i].status != NS_NONAME)
		{
			if (tc_memcmp (nbs_name, nameTable[i].name, RTSMB_NB_NAME_SIZE) == 0)
			{
				nameTable[i].status = NS_NONAME;
				return TRUE;
			}
		}
	}

	return FALSE;
}


RTSMB_STATIC
void rtsmb_srv_nbns_run_name_table (void)
{
	int i;
	BBOOL anotherSend = FALSE;

	for (i = 0; i < NAME_TABLE_SIZE; i++)
	{
		if (nameTable[i].status == NS_PENDING)
		{
			anotherSend = TRUE;

			if (IS_PAST (nameTable[i].nextSendBase, RTSMB_NB_BCAST_RETRY_TIMEOUT))
			{
				if (nameTable[i].numSent < RTSMB_NB_BCAST_RETRY_COUNT)
				{
					int index;
					char tmpBuffer[32];
					char * buffer = tmpBuffer;

					RTSMB_DEBUG_OUTPUT_STR ("rtsmb_srv_nbns_run_name_table:  Requesting NETBIOS ", RTSMB_DEBUG_TYPE_ASCII);
					RTSMB_DEBUG_OUTPUT_STR ((nameTable[i].group ? "group" : "unique"), RTSMB_DEBUG_TYPE_ASCII);
				    RTSMB_DEBUG_OUTPUT_STR ("name ", RTSMB_DEBUG_TYPE_ASCII);
				    for (index = 0; index <15; index++)
				    {
				    	tmpBuffer[index] = nameTable[i].name[index];
					}
					tmpBuffer[15] = '\0';
				    RTSMB_DEBUG_OUTPUT_STR (buffer, RTSMB_DEBUG_TYPE_ASCII);
				    RTSMB_DEBUG_OUTPUT_STR (", type 0x", RTSMB_DEBUG_TYPE_ASCII);
				    for (index = 0; index <32; index++)
				    {
				    	tmpBuffer[index] = '\0';
					}
				    buffer = rtp_itoa (nameTable[i].name[15], buffer, 16);
				    RTSMB_DEBUG_OUTPUT_STR (buffer, RTSMB_DEBUG_TYPE_ASCII);
				    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);

					rtsmb_srv_nbns_send_name_register_request(nameTable[i].transID,
									nameTable[i].name,
									nameTable[i].group);

					nameTable[i].numSent++;
					nameTable[i].nextSendBase = rtp_get_system_msec ();
				}
				else
				{
					/* SEND OUT A NAME CLAIM PACKET */
					int index;
					char tmpBuffer[32];
					char * buffer = tmpBuffer;

					RTSMB_DEBUG_OUTPUT_STR ("rtsmb_srv_nbns_run_name_table:  Claiming NETBIOS ", RTSMB_DEBUG_TYPE_ASCII);
					RTSMB_DEBUG_OUTPUT_STR ((nameTable[i].group ? "group" : "unique"), RTSMB_DEBUG_TYPE_ASCII);
				    RTSMB_DEBUG_OUTPUT_STR ("name ", RTSMB_DEBUG_TYPE_ASCII);
				    for (index = 0; index <15; index++)
				    {
				    	tmpBuffer[index] = nameTable[i].name[index];
					}
					tmpBuffer[15] = '\0';
				    RTSMB_DEBUG_OUTPUT_STR (buffer, RTSMB_DEBUG_TYPE_ASCII);
				    RTSMB_DEBUG_OUTPUT_STR (", type 0x", RTSMB_DEBUG_TYPE_ASCII);
				    for (index = 0; index <32; index++)
				    {
				    	tmpBuffer[index] = '\0';
					}
				    buffer = rtp_itoa (nameTable[i].name[15], buffer, 16);
				    RTSMB_DEBUG_OUTPUT_STR (buffer, RTSMB_DEBUG_TYPE_ASCII);
				    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);

					rtsmb_srv_nbns_send_name_overwrite(nameTable[i].transID,
										nameTable[i].name,
										nameTable[i].group);
					nameTable[i].status = NS_REGISTERED;

					/* if we just registered our server name, start the announcements */
					if (nameTable[i].name[RTSMB_NB_NAME_SIZE - 1] == RTSMB_NB_NAME_TYPE_SERVER)
					{
						rtsmb_srv_browse_set_announcement_info (TRUE);
						rtsmb_srv_browse_restart_announcements ();
					}
				}
			}
		}
	}

	if (!anotherSend)
		doAnnouncements = FALSE;	/* don't run again */
}


RTSMB_STATIC
void rtsmb_srv_nbns_clear_name_query (PFCHAR name)
{
	int i;

	rtp_sig_mutex_claim((RTP_MUTEX) nameQueryTableSem);

	for (i = 0; i < NAME_QUERY_SIZE; i++)
	{
		if (nameQueryTable[i].inUse &&
			rtsmb_strcasecmp (name, nameQueryTable[i].name, CFG_RTSMB_USER_CODEPAGE) == 0)
		{
			nameQueryTable[i].inUse = FALSE;
			break;
		}
	}

	rtp_sig_mutex_release((RTP_MUTEX) nameQueryTableSem);
}


// so many packets are very similar, so I use this
// function to make a standard name register request, but change the opcodes
// returns size of data
RTSMB_STATIC
int rtsmb_srv_nbns_fill_name_register_request (word transID, PFCHAR name, BBOOL group, word opcodes)
{
	RTSMB_NBNS_HEADER header;
	RTSMB_NBNS_QUESTION question;
	RTSMB_NBNS_RESOURCE resource;
	char data[6];
	rtsmb_size data_size = 6;
	PFVOID buf, data_buf;
	rtsmb_size buf_size = prtsmb_srv_ctx->small_buffer_size;
	int r;

	header.id = transID;
	header.flags = opcodes;
	header.question_count = 1;
	header.answer_count = 0;
	header.authority_count = 0;
	header.additional_count = 1;

	rtsmb_util_make_netbios_name (question.name, name, (byte)name[RTSMB_NB_NAME_SIZE - 1]);
	question.type = RTSMB_NBNS_TYPE_NB;
	question.class = RTSMB_NBNS_CLASS_IN;

	resource.pointer = TRUE;
	resource.type = RTSMB_NBNS_TYPE_NB;
	resource.class = RTSMB_NBNS_CLASS_IN;
	resource.time_to_live = 0x000493e0;
	resource.data_size = (word) data_size;
	resource.data = (PFBYTE) data;

	data_buf = data;
	PACK_WORD (data_buf, &data_size, (word) (group ? NB_FLAGS_GROUP : 0), TRUE, -1);
	PACK_ITEM (data_buf, &data_size, rtsmb_srv_net_get_host_ip (), 4, -1);

	buf = prtsmb_srv_ctx->namesrvBuffer;

	r = rtsmb_nbns_fill_header (buf, buf_size, prtsmb_srv_ctx->namesrvBuffer, &header);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	buf_size -= (rtsmb_size)r;

	r = rtsmb_nbns_fill_question (buf, buf_size, prtsmb_srv_ctx->namesrvBuffer, &question);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	buf_size -= (rtsmb_size)r;

	r = rtsmb_nbns_fill_resource (buf, buf_size, prtsmb_srv_ctx->namesrvBuffer, &resource);
	ASSURE (r >= 0, -1);
	buf = PADD (buf, r);
	buf_size -= (rtsmb_size)r;

	return PDIFF (buf, prtsmb_srv_ctx->namesrvBuffer);
}

/*
================
 Makes several broadcasts to see if the name
  is available

	word transID - Transaction ID
	PFCHAR name - compressed nbs name
	BBOOL group - true if this is a group name
================
*/
RTSMB_STATIC
void rtsmb_srv_nbns_send_name_register_request(word transID, PFCHAR name, BBOOL group)
{
	int size;

	size = rtsmb_srv_nbns_fill_name_register_request (transID, name, group, 0x2910);
	if (size < 0)
	{
		RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_nbns_send_name_register_request: Failed while packing packet.\n", RTSMB_DEBUG_TYPE_ASCII);
		return;
	}

	rtsmb_net_write_datagram (rtsmb_srv_net_get_nbns_socket (), rtsmb_srv_net_get_broadcast_ip (), 
                           rtsmb_nbns_port, prtsmb_srv_ctx->namesrvBuffer, size);
}

// demands that we be given this name (we have
// ostensibly already checked that no one else has it)
RTSMB_STATIC
void rtsmb_srv_nbns_send_name_overwrite (word transID, PFCHAR name, BBOOL group)
{
	int size;

	size = rtsmb_srv_nbns_fill_name_register_request (transID, name, group, 0x2810);
	if (size < 0)
	{
		RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_nbns_send_name_overwrite: Failed while packing packet.\n", RTSMB_DEBUG_TYPE_ASCII);
		return;
	}

	rtsmb_net_write_datagram (rtsmb_srv_net_get_nbns_socket (), rtsmb_srv_net_get_broadcast_ip (), rtsmb_nbns_port, prtsmb_srv_ctx->namesrvBuffer, size);
}

#if (0)
// asks that other servers remember us
RTSMB_STATIC
void rtsmb_srv_nbns_send_name_refresh_request (word transID, PFCHAR name, BBOOL group)
{
	int size;

	size = rtsmb_srv_nbns_fill_name_register_request (transID, name, group, 0x4810);
	if (size < 0)
	{
		RTSMB_DEBUG_OUTPUT_STR("rtsmb_srv_nbns_send_name_refresh_request: Failed while packing packet.\n", RTSMB_DEBUG_TYPE_ASCII);
		return;
	}

	rtsmb_net_write_datagram (rtsmb_srv_net_get_nbns_socket (), rtsmb_srv_net_get_broadcast_ip (), rtsmb_nbns_port, prtsmb_srv_ctx->namesrvBuffer, size);
}
#endif

/*
================
 	asks who has this name

	word transID - Transaction ID
	PFCHAR name - compressed nbs name
	BBOOL group - true if this is a group name
================
*/
RTSMB_STATIC
void rtsmb_srv_nbns_send_name_query(word transID, PFCHAR name)
{
	RTSMB_NBNS_HEADER header;
	RTSMB_NBNS_QUESTION question;
	PFVOID buf;
	rtsmb_size buf_size = prtsmb_srv_ctx->small_buffer_size;
	int r;

	header.id = transID;
	header.flags = 0x0110;
	header.question_count = 1;
	header.answer_count = 0;
	header.authority_count = 0;
	header.additional_count = 0;

	rtsmb_util_make_netbios_name (question.name, name, 	(byte)name[RTSMB_NB_NAME_SIZE - 1]);
	question.type = RTSMB_NBNS_TYPE_NB;
	question.class = RTSMB_NBNS_CLASS_IN;

	buf = prtsmb_srv_ctx->namesrvBuffer;

	r = rtsmb_nbns_fill_header (buf, buf_size, prtsmb_srv_ctx->namesrvBuffer, &header);
	if (r < 0) return;
	buf = PADD (buf, r);
	buf_size -= (rtsmb_size)r;

	r = rtsmb_nbns_fill_question (buf, buf_size, prtsmb_srv_ctx->namesrvBuffer, &question);
	if (r < 0) return;
	buf = PADD (buf, r);
	buf_size -= (rtsmb_size)r;

	rtsmb_net_write_datagram (rtsmb_srv_net_get_nbns_socket (), rtsmb_srv_net_get_broadcast_ip (), rtsmb_nbns_port, prtsmb_srv_ctx->namesrvBuffer, PDIFF (buf, prtsmb_srv_ctx->namesrvBuffer));
}

/* value is the response -- 0x0 for positive response, else negative response */
/* ownerType is the node type of the original source that we are replying to */
RTSMB_STATIC
void rtsmb_srv_nbns_send_name_register_response (word transID, PFCHAR name, BBOOL group, byte value)
{
	RTSMB_NBNS_HEADER header;
	RTSMB_NBNS_RESOURCE resource;
	char data[6];
	rtsmb_size data_size = 6;
	PFVOID buf;
	rtsmb_size buf_size = prtsmb_srv_ctx->small_buffer_size;
	int r;

	header.id = transID;
	header.flags = (word)(0xad80 | (value & 0xF));
	header.question_count = 0;
	header.answer_count = 1;
	header.authority_count = 0;
	header.additional_count = 0;

	resource.pointer = FALSE;
	tc_strcpy (resource.name, name);
	resource.type = RTSMB_NBNS_TYPE_NB;
	resource.class = RTSMB_NBNS_CLASS_IN;
	resource.time_to_live = 0;
	resource.data_size = (word) data_size;
	resource.data = (PFBYTE) data;

	rtsmb_pack_add_word (data, &data_size, (word) ((group ? 0x80 : 0)), TRUE);
	rtsmb_pack_add (PADD (data, 2), &data_size, rtsmb_srv_net_get_host_ip (), 4);

	buf = prtsmb_srv_ctx->namesrvBuffer;

	r = rtsmb_nbns_fill_header (buf, buf_size, prtsmb_srv_ctx->namesrvBuffer, &header);
	if (r < 0) return;
	buf = PADD (buf, r);
	buf_size -= (rtsmb_size)r;

	r = rtsmb_nbns_fill_resource (buf, buf_size, prtsmb_srv_ctx->namesrvBuffer, &resource);
	if (r < 0) return;
	buf = PADD (buf, r);
	buf_size -= (rtsmb_size)r;

	rtsmb_net_write_datagram (rtsmb_srv_net_get_nbns_socket (),
		rtsmb_srv_net_get_last_remote_ip (), rtsmb_srv_net_get_last_remote_port (),
		prtsmb_srv_ctx->namesrvBuffer, PDIFF (buf, prtsmb_srv_ctx->namesrvBuffer));
}


/*
================
 RTSMB_STATIC void rtsmb_srv_nbns_send_positive_name_query_response()
================
*/
RTSMB_STATIC
void rtsmb_srv_nbns_send_positive_name_query_response (PRTSMB_NBNS_HEADER pHeader, PRTSMB_NBNS_QUESTION pQuestion)
{
	RTSMB_NBNS_HEADER header;
	RTSMB_NBNS_RESOURCE resource;
	char data[6];
	rtsmb_size data_size = 6;
	PFVOID buf;
	rtsmb_size buf_size = prtsmb_srv_ctx->small_buffer_size;
	int r;

	header.id = pHeader->id;
	header.flags = 0x8500;
	header.question_count = 0;
	header.answer_count = 1;
	header.authority_count = 0;
	header.additional_count = 0;

	resource.pointer = FALSE;
	tc_strcpy (resource.name, pQuestion->name);
	resource.type = RTSMB_NBNS_TYPE_NB;
	resource.class = RTSMB_NBNS_CLASS_IN;
	resource.time_to_live = 0x000493e0;
	resource.data_size = (word) data_size;
	resource.data = (PFBYTE) data;

	rtsmb_pack_add_word (data, &data_size, 0, TRUE);
	rtsmb_pack_add (PADD (data, 2), &data_size, rtsmb_srv_net_get_host_ip (), 4);

	buf = prtsmb_srv_ctx->namesrvBuffer;

	r = rtsmb_nbns_fill_header (buf, buf_size, prtsmb_srv_ctx->namesrvBuffer, &header);
	if (r < 0) return;
	buf = PADD (buf, r);
	buf_size -= (rtsmb_size)r;

	r = rtsmb_nbns_fill_resource (buf, buf_size, prtsmb_srv_ctx->namesrvBuffer, &resource);
	if (r < 0) return;
	buf = PADD (buf, r);
	buf_size -= (rtsmb_size)r;

	rtsmb_net_write_datagram (rtsmb_srv_net_get_nbns_socket (),
		rtsmb_srv_net_get_last_remote_ip (), rtsmb_srv_net_get_last_remote_port (),
		prtsmb_srv_ctx->namesrvBuffer, PDIFF (buf, prtsmb_srv_ctx->namesrvBuffer));
}


RTSMB_STATIC
void rtsmb_srv_nbns_process_name_query_request (PFBYTE origin, PFBYTE buf, rtsmb_size size, PRTSMB_NBNS_HEADER pHeader)
{
	RTSMB_NBNS_QUESTION question;
	int r;

	r = rtsmb_nbns_read_question (buf, size, origin, &question);
	if (r < 0) return;

	if (rtsmb_srv_nbns_is_in_name_table (question.name, TRUE))
	{
		RTSMB_DEBUG_OUTPUT_STR ("rtsmb_srv_nbns_process_name_query_request:  Responding to name query for name ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (question.name, RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);
		rtsmb_srv_nbns_send_positive_name_query_response (pHeader, &question);
	}
}

RTSMB_STATIC
void rtsmb_srv_nbns_process_name_query_response (PFBYTE origin, PFBYTE buf, rtsmb_size size, PRTSMB_NBNS_HEADER pHeader)
{
	RTSMB_NBNS_RESOURCE resource;
	byte data[6];
	int r;

	/* Now, according to spec, there could be many valid ips in the response.
	   However, we only ever currently query for unique names, not group names,
	   where there would be multiple ips.  So, we can just assume there is one
	   ip in here, and we only need 6 bytes of data.  To remove this assumption,
	   just increase the size of data to 200 or so. */
	resource.data = data;
	resource.data_size = 6;
	r = rtsmb_nbns_read_resource (buf, size, origin, &resource);
	if (r < 0) return;

	/* the ip is now bytes 3 to 6 of the byte array data */

	/* add name to our cache */
	CLAIM_NAME_CACHE ();
	lastCacheIndex = (lastCacheIndex + 1) % NAME_CACHE_SIZE;
	tc_strcpy (nameCache[lastCacheIndex].name, resource.name);
	tc_memcpy (nameCache[lastCacheIndex].ip, data + 2, 4);
	nameCache[lastCacheIndex].inUse = TRUE;
	RELEASE_NAME_CACHE ();

	rtsmb_srv_nbns_clear_name_query (resource.name);
}


RTSMB_STATIC
void rtsmb_srv_nbns_process_name_register_request (PFBYTE origin, PFBYTE buf, rtsmb_size size, PRTSMB_NBNS_HEADER pHeader)
{
	int i, r;
	RTSMB_NBNS_QUESTION question;

	/**
	 * Some node is asking us if we agree with their name.  Let's go through
	 * our registered and pending names and see if we conflict with them.
	 */

	r = rtsmb_nbns_read_question (buf, size, origin, &question);
	if (r < 0) return;

	/* now see if name is in our table */
	for (i = 0; i < NAME_TABLE_SIZE; i ++)
	{
		if (nameTable[i].status == NS_PENDING || nameTable[i].status == NS_REGISTERED)
		{
			if (nameTable[i].group == FALSE &&
				tc_strcmp (question.name, nameTable[i].name) == 0)
			{
				break;
			}
		}
	}

	if (i >= NAME_TABLE_SIZE)
	{
		/* we didn't find the name or it was a group name; just silently ignore
			We could send positive response? -- seems wasteful of bandwidth */
		return;
	}

	/* crud, they are asking for the same name we have; deny them */
	rtsmb_srv_nbns_send_name_register_response (pHeader->id, nameTable[i].name, FALSE, 0x6);

	RTSMB_DEBUG_OUTPUT_STR ("rtsmb_srv_nbns_process_name_register_request:  Someone else wants to register the name ", RTSMB_DEBUG_TYPE_ASCII);
	RTSMB_DEBUG_OUTPUT_STR (question.name, RTSMB_DEBUG_TYPE_ASCII);
	RTSMB_DEBUG_OUTPUT_STR (".  I am denying the request.\n", RTSMB_DEBUG_TYPE_ASCII);
}


RTSMB_STATIC
void rtsmb_srv_nbns_process_negative_name_register_response (PFBYTE origin, PFBYTE buf, rtsmb_size size, PRTSMB_NBNS_HEADER pHeader)
{
	int i, j, numspaces, r;
	BBOOL surrender = FALSE, allnines;
	RTSMB_NBNS_RESOURCE resource;
	byte data[6];
	char oldname [RTSMB_NB_NAME_SIZE + 1];

	/**
	 * We find out what name is being rejected, and
	 * try again with a similar, but different name.
	 */

	resource.data = data;
	resource.data_size = 6;
	r = rtsmb_nbns_read_resource (buf, size, origin, &resource);
	if (r < 0) return;

	/* now find name in our table */
	for (i = 0; i < NAME_TABLE_SIZE; i ++)
	{
		if (nameTable[i].status == NS_PENDING)
		{
			/* just compare name, not suffix */
			if (tc_strncmp (resource.name, nameTable[i].name, RTSMB_NB_NAME_SIZE - 1) == 0)
			{
				break;
			}
		}
	}

	if (i >= NAME_TABLE_SIZE)
	{
		/* name was not found, or was not pending.  Tough luck. */
		return;
	}

	/* record old name */
	tc_strcpy (oldname, resource.name);


	/* now we find a new name for ourselves */

	/**
	 * find string part (the beginning part that isn't a number)
	 * get number part (may be there from running this algo previously
	 * append string part and number + 1 part to get new name, space allowing
	 */
	j = RTSMB_NB_NAME_SIZE - 2;

	while (j >= 0 && tc_isspace (resource.name[j]))
	{
		j--;
	}

	numspaces = RTSMB_NB_NAME_SIZE - 2 - j;
	allnines = TRUE;
	while (j >= 0 && tc_isdigit (resource.name[j]))
	{
		if (resource.name[j] != '9')
			allnines = FALSE;

		j--;
	}

	if (allnines && numspaces == 0)
	{
		/* no more room for added digits, so we give up */
		surrender = TRUE;
	}
	else
	{
		char str [RTSMB_NB_NAME_SIZE + 1];
		unsigned int num;

		tc_strncpy (str, resource.name, (unsigned)(j + 1));
		str[j + 1] = '\0';

		if (numspaces == RTSMB_NB_NAME_SIZE - 2 - j)
		{
			/* if no digits, start counting at 2 */
			num = 2;
		}
		else
		{
			/* add one to the previous value */
			num = (unsigned int)(tc_atoi (&resource.name[j + 1]) + 1);
		}

		rtp_sprintf (resource.name, "%s%u", str, num);
	}


	/* reset global concept of our name */
	tc_strcpy (ns_netNameAbrv, resource.name);
	tc_strcpy (ns_netName, resource.name);

	/* fill ns_netName with whitespace */
	for (j = (int)tc_strlen (ns_netName); j < RTSMB_NB_NAME_SIZE; j++)
		ns_netName[j] = ' ';
	ns_netName[j] = '\0';

	/* now we reset all our names in the name table */
	for (i = 0; i < NAME_TABLE_SIZE; i ++)
	{
		/* just compare name, not suffix */
		if (tc_strncmp (oldname, nameTable[i].name, RTSMB_NB_NAME_SIZE - 1) == 0)
		{
			if (surrender)
			{
				nameTable[i].status = NS_NONAME;
			}
			else
			{
				tc_strncpy (nameTable[i].name, ns_netName, RTSMB_NB_NAME_SIZE - 1);
				nameTable[i].status = NS_PENDING;
				nameTable[i].transID = rtsmb_srv_nbns_get_next_transfer_id();
				nameTable[i].numSent = 0;
				nameTable[i].nextSendBase = rtp_get_system_msec () - RTSMB_NB_BCAST_RETRY_TIMEOUT;
			}
		}
	}

	RTSMB_DEBUG_OUTPUT_STR ("rtsmb_srv_nbns_process_negative_name_register_response:  The name ", RTSMB_DEBUG_TYPE_ASCII);
	RTSMB_DEBUG_OUTPUT_STR (oldname, RTSMB_DEBUG_TYPE_ASCII);
	RTSMB_DEBUG_OUTPUT_STR (" we wanted is taken.  Trying name ", RTSMB_DEBUG_TYPE_ASCII);
	RTSMB_DEBUG_OUTPUT_STR (resource.name, RTSMB_DEBUG_TYPE_ASCII);
	RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);

	/* now we need to restart our announcements because our name changed */
	rtsmb_srv_browse_restart_announcements ();
}


RTSMB_STATIC
word rtsmb_srv_nbns_get_next_transfer_id(void)
{
	static word lastTransID = 0;

	++lastTransID;

	return lastTransID;
}

//============================================================================
//    INTERFACE FUNCTIONS
//============================================================================
/*
================
 void rtsmb_srv_nbns_init() -
================
*/
void rtsmb_srv_nbns_init (PFCHAR net_name, PFCHAR group_name)
{
	int i;

	lastCacheIndex = -1;
	lastQueryIndex = -1;

	rtp_sig_mutex_alloc((RTP_MUTEX *) &nameQueryTableSem, (const char*)0);

	for(i = 0; i < NAME_CACHE_SIZE; i++)
		nameCache[i].inUse = FALSE;

	for(i = 0; i < NAME_QUERY_SIZE; i++)
		nameQueryTable[i].inUse = FALSE;

	for(i = 0; i < NAME_TABLE_SIZE; i++)
		nameTable[i].status = NS_NONAME;

	if (net_name)
	{
		rtsmb_util_make_netbios_name (ns_netName, net_name, '\0');
		tc_strcpy(ns_netNameAbrv, net_name);
	}
	else
	{
		rtsmb_util_make_netbios_name (ns_netName, CFG_RTSMB_DEFAULT_NET_NAME, '\0');
		tc_strcpy(ns_netNameAbrv, CFG_RTSMB_DEFAULT_NET_NAME);
	}
	rtsmb_util_latin_string_toupper (ns_netNameAbrv);

	if (group_name)
	{
		rtsmb_util_make_netbios_name (ns_groupName, group_name, '\0');
		tc_strcpy(ns_groupNameAbrv, group_name);
	}
	else
	{
		rtsmb_util_make_netbios_name (ns_groupName, CFG_RTSMB_DEFAULT_GROUP_NAME, '\0');
		tc_strcpy(ns_groupNameAbrv, CFG_RTSMB_DEFAULT_GROUP_NAME);
	}
	rtsmb_util_latin_string_toupper (ns_groupNameAbrv);

	rtsmb_util_make_netbios_name (ns_globalName, RTSMB_NB_DEFAULT_NAME, '\0');
	tc_strcpy(ns_globalNameAbrv, RTSMB_NB_DEFAULT_NAME);
	rtsmb_util_latin_string_toupper (ns_globalNameAbrv);

	rtsmb_srv_nbns_add_name(ns_netName, FALSE, RTSMB_NB_NAME_TYPE_WORKSTATION, TRUE);
	rtsmb_srv_nbns_add_name(ns_netName, FALSE, RTSMB_NB_NAME_TYPE_SERVER, TRUE);//file service

	rtsmb_srv_nbns_add_name(ns_globalName, FALSE, RTSMB_NB_NAME_TYPE_SERVER, FALSE);

	rtsmb_srv_nbns_add_name(ns_groupName, TRUE, RTSMB_NB_NAME_TYPE_WORKSTATION, TRUE);
	//rtsmb_srv_nbns_add_name(ns_groupName, TRUE, RTSMB_NB_NAME_TYPE_ELECTION_SERVICE, TRUE);
	rtsmb_srv_nbns_add_name(ns_groupName, TRUE, RTSMB_NB_NAME_TYPE_SERVER, TRUE);
}


/* restarts our name registration routine */
void rtsmb_srv_nbns_restart (void)
{
	int i;

	/* restart all names */
	for(i = 0; i < NAME_TABLE_SIZE; i++)
	{
		if (nameTable[i].status != NS_NONAME)
		{
			nameTable[i].transID = rtsmb_srv_nbns_get_next_transfer_id();
			nameTable[i].status = nameTable[i].announce ? NS_PENDING : NS_REGISTERED;
			nameTable[i].nextSendBase = rtp_get_system_msec () - RTSMB_NB_BCAST_RETRY_TIMEOUT;
			nameTable[i].numSent = 0;
		}
	}

	/* do announcements */
	doAnnouncements = TRUE;
}


BBOOL rtsmb_srv_nbns_is_in_name_table (PFCHAR name, BBOOL lookAtSuffix)
{
	int i;

	for (i = 0; i < NAME_TABLE_SIZE; i++)
	{
	    /* When connecting to share using IP address WINNT uses *SMBSERVER and
           XP uses *SMBSERV as default nb names */
        if (tc_strcmp("*SMBSERVER", name) == 0 ||  tc_strcmp("*SMBSERV", name) == 0)
        {
            return TRUE;
        }
        if (rtsmb_strcasencmp (nameTable[i].name, name,
			lookAtSuffix ? RTSMB_NB_NAME_SIZE : RTSMB_NB_NAME_SIZE - 1, CFG_RTSMB_USER_CODEPAGE) == 0)
			return TRUE;
	}

	return FALSE;
}

// dest must be size 4
// dest has valid data if return is TRUE
BBOOL rtsmb_srv_nbns_get_ip_from_cache (PFCHAR name, BBOOL lookAtSuffix, PFBYTE dest)
{
	int i;

	CLAIM_NAME_CACHE ();
	for (i = 0; i < NAME_CACHE_SIZE; i++)
	{
		if (nameCache[i].inUse)
		{
			if (rtsmb_strcasencmp (nameCache[i].name, name,
				lookAtSuffix ? RTSMB_NB_NAME_SIZE : RTSMB_NB_NAME_SIZE - 1, CFG_RTSMB_USER_CODEPAGE) == 0)
			{
				tc_memcpy (dest, nameCache[i].ip, 4);
				RELEASE_NAME_CACHE ();
				return TRUE;
			}
		}
	}
	RELEASE_NAME_CACHE ();

	return FALSE;
}

/* just internal now, might need to be global.  */
RTSMB_STATIC
void rtsmb_srv_nbns_invalidate_name (PFCHAR nbsName)
{
	char normalName [RTSMB_NB_NAME_SIZE];

	tc_strncpy (normalName, nbsName, RTSMB_NB_NAME_SIZE - 1);
	normalName [RTSMB_NB_NAME_SIZE - 1] = '\0';

	rtsmb_srv_nbns_invalidate_one_name (normalName,	(byte)nbsName[RTSMB_NB_NAME_SIZE - 1]);
}

RTSMB_STATIC
void rtsmb_srv_nbns_run_name_query_table (void)
{
	int i;

	rtp_sig_mutex_claim((RTP_MUTEX) nameQueryTableSem);

	for (i = 0; i < NAME_QUERY_SIZE; i++)
	{
		if (nameQueryTable[i].inUse)
		{
			if (IS_PAST (nameQueryTable[i].endTimeBase, RTSMB_NB_BCAST_RETRY_TIMEOUT))
			{
				rtsmb_srv_nbns_send_name_query (rtsmb_srv_nbns_get_next_transfer_id (), nameQueryTable[i].name);

				if (nameQueryTable[i].numQueries >= 3)
				{
					nameQueryTable[i].inUse = FALSE;	/* give up */
					/* invalidate it, since it doesn't seem to exist */
					rtsmb_srv_nbns_invalidate_name (nameQueryTable[i].name);
				}
				else
				{
					nameQueryTable[i].endTimeBase = rtp_get_system_msec ();
					nameQueryTable[i].numQueries ++;
				}
			}
		}
	}



	rtp_sig_mutex_release((RTP_MUTEX) nameQueryTableSem);
}

void rtsmb_srv_nbns_invalidate_ip (PFBYTE ip)
{
	int i;
#if INCLUDE_RTSMB_DC
	char dcName [RTSMB_NB_NAME_SIZE + 1];
	BBOOL isDC;

	isDC = (MS_GetPDCName (dcName) != (void)0);

	if (isDC)
		dcName[RTSMB_NB_NAME_SIZE - 1] = RTSMB_NB_NAME_TYPE_SERVER;
#endif

	CLAIM_NAME_CACHE ();
	for (i = 0; i < NAME_CACHE_SIZE; i++)
	{
		if (nameCache[i].inUse &&
			tc_memcmp (nameCache[i].ip, ip, 4) == 0)
		{
			nameCache[i].inUse = FALSE;

#if INCLUDE_RTSMB_DC
			if (isDC && tc_strcmp (nameCache[i].name, dcName) == 0)
				rtsmb_srv_net_pdc_invalidate ();
#endif
		}
	}
	RELEASE_NAME_CACHE ();
}

void rtsmb_srv_nbns_invalidate_one_name (PFCHAR name, byte type)
{
	int i;
	char nbsName [RTSMB_NB_NAME_SIZE + 1];
#if INCLUDE_RTSMB_DC
	char dcName [RTSMB_NB_NAME_SIZE + 1];
	BBOOL isDC;

	isDC = MS_GetPDCName (dcName) != (void)0;

	if (isDC)
		dcName[RTSMB_NB_NAME_SIZE - 1] = RTSMB_NB_NAME_TYPE_SERVER;
#endif

	rtsmb_util_make_netbios_name (nbsName, name, type);

	CLAIM_NAME_CACHE ();
	for (i = 0; i < NAME_CACHE_SIZE; i++)
	{
		if (nameCache[i].inUse &&
			tc_strcmp (nameCache[i].name, nbsName) == 0)
		{
			nameCache[i].inUse = FALSE;

#if INCLUDE_RTSMB_DC
			if (isDC && tc_strcmp (nameCache[i].name, dcName) == 0)
				rtsmb_srv_net_pdc_invalidate ();
#endif

			break;
		}
	}
	RELEASE_NAME_CACHE ();
}

/* invalidates all names matching |name|, ignoring type suffix */
void rtsmb_srv_nbns_invalidate_all_names (PFCHAR name)
{
	int i;
	char nbsName [RTSMB_NB_NAME_SIZE + 1];
#if INCLUDE_RTSMB_DC
	char dcName [RTSMB_NB_NAME_SIZE + 1];
	BBOOL isDC;

	isDC = MS_GetPDCName (dcName) != (void)0;

	if (isDC)
		dcName[RTSMB_NB_NAME_SIZE - 1] = RTSMB_NB_NAME_TYPE_SERVER;
#endif

	rtsmb_util_make_netbios_name (nbsName, name, '\0');

	CLAIM_NAME_CACHE ();
	for (i = 0; i < NAME_CACHE_SIZE; i++)
	{
		if (nameCache[i].inUse &&
			tc_strncmp (nameCache[i].name, nbsName, RTSMB_NB_NAME_SIZE - 1) == 0)
		{
			nameCache[i].inUse = FALSE;

#if INCLUDE_RTSMB_DC
			if (isDC && tc_strcmp (nameCache[i].name, dcName) == 0)
				rtsmb_srv_net_pdc_invalidate ();
#endif
		}
	}
	RELEASE_NAME_CACHE ();
}

/*
================
 void rtsmb_srv_nbns_cycle() -
================
*/
void rtsmb_srv_nbns_cycle (void)
{
	if (doAnnouncements)
	{
		rtsmb_srv_nbns_run_name_table();
	}

	rtsmb_srv_nbns_run_name_query_table ();
} // End rtsmb_srv_nbns_cycle

/*
================
 void rtsmb_srv_nbrtsmb_srv_nbns_shutdown() -
================
*/
void rtsmb_srv_nbns_shutdown (void)
{
	/**
	 * We could send releases for all our names here too.
	 */
	rtsmb_srv_browse_set_announcement_info (FALSE);

} // End rtsmb_srv_nbrtsmb_srv_nbns_shutdown

/*
================
 BBOOL rtsmb_srv_nbns_process_packet() - Processes a name service packet
================
*/
BBOOL rtsmb_srv_nbns_process_packet (PFBYTE buf, rtsmb_size size)
{
	RTSMB_NBNS_HEADER header;
	int r;

	r = rtsmb_nbns_read_header (buf, size, buf, &header);
	if (r < 0)
	{
		return FALSE;
	}

	if (header.question_count == 1 && header.answer_count == 0 &&
		header.authority_count == 0 && header.additional_count == 0 &&
		(header.flags & 0xFFFF) == 0x0110)
	{
		/* Name Query Request */

		rtsmb_srv_nbns_process_name_query_request (buf, PADD (buf, r), size - (rtsmb_size)r, &header);
		return TRUE;
	}
	else if (header.question_count == 0 && header.answer_count == 1 &&
		header.authority_count == 0 && header.additional_count == 0 &&
		(header.flags & 0xFD7F) == 0x8500)
	{
		/* Positive Name Query Response */

		rtsmb_srv_nbns_process_name_query_response (buf, PADD (buf, r), size - (rtsmb_size)r, &header);
		return TRUE;
	}
	else if (header.question_count == 1 && header.answer_count == 0 &&
		header.authority_count == 0 && header.additional_count == 1 &&
		(header.flags & 0xFFEF) == 0x2900)
	{
		/* Name Registration Request */

		rtsmb_srv_nbns_process_name_register_request (buf, PADD (buf, r), size - (rtsmb_size)r, &header);
		return TRUE;
	}
	else if (header.question_count == 1 && header.answer_count == 0 &&
		header.authority_count == 0 && header.additional_count == 1 &&
		(header.flags & 0xFFEF) == 0x2800)
	{
		/* Name Overwrite Request & Demand */
		return TRUE;
	}
	else if (header.question_count == 0 && header.answer_count == 1 &&
		header.authority_count == 0 && header.additional_count == 0 &&
		(header.flags & 0xFFF0) == 0xAD80)
	{
		/* Name Registration Response */

		if ((header.flags & 0x000F) == 0x0000)
		{
			/* Positive Response */
			/* great -- they like our name; we don't need to do anything */
		}
		else
		{
			/* Negative Response */

			/* crud, someone else took our name; we'll think up a new one */
			rtsmb_srv_nbns_process_negative_name_register_response (buf,
			PADD (buf, r),
			size - (rtsmb_size)r,
			&header);
		}

		return TRUE;
	}

	return FALSE;
}

BBOOL rtsmb_srv_nbns_is_in_name_cache (PFCHAR name, byte type)
{
	char nbsname [RTSMB_NB_NAME_SIZE + 1];
	byte ip[4];

	rtsmb_util_make_netbios_name (nbsname, name, type);

	/* is name in cache? if so, early exit */
	return rtsmb_srv_nbns_get_ip_from_cache (nbsname, TRUE, ip);
}


void rtsmb_srv_nbns_start_query_for_name (PFCHAR name, byte type)
{
	int i;

	if (NAME_QUERY_SIZE == 0)
	{
		return;
	}

	rtp_sig_mutex_claim((RTP_MUTEX) nameQueryTableSem);

	/* find an empty spot in name table */
	for (i = 0; i < NAME_QUERY_SIZE; i++)
	{
		if (!nameQueryTable[i].inUse)
		{
			break;
		}
	}

	if (i == NAME_QUERY_SIZE)
	{
		/* hmmm.. none are available.  let's kill the oldest */
		lastQueryIndex = (lastQueryIndex + 1) % NAME_QUERY_SIZE;
		i = lastQueryIndex;
	}

	/* let's fill it in */
	nameQueryTable[i].inUse = TRUE;
	rtsmb_util_make_netbios_name (nameQueryTable[i].name, name, type);
	nameQueryTable[i].numQueries = 0;
	/* make sure that we start right away */
	nameQueryTable[i].endTimeBase = rtp_get_system_msec () - RTSMB_NB_BCAST_RETRY_TIMEOUT;

	rtp_sig_mutex_release((RTP_MUTEX) nameQueryTableSem);
}

/* these all return a null-ended string of, at most, size 16 */
/* 'full' versions pad out the 16 chars with spaces */
PFCHAR rtsmb_srv_nbns_get_our_group_full (void)
{
	return ns_groupName;
}

PFCHAR rtsmb_srv_nbns_get_our_group (void)
{
	return ns_groupNameAbrv;
}

PFCHAR rtsmb_srv_nbns_get_our_name_full (void)
{
	return ns_netName;
}

PFCHAR rtsmb_srv_nbns_get_our_name (void)
{
	return ns_netNameAbrv;
}

long rtsmb_srv_nbns_get_next_wake_timeout (void)
{
	/* scan through our waiting name registrations and our waiting name queries */
	int i;
	long rv = 0x7FFFFFFF;
	unsigned long current_time = rtp_get_system_msec ();

	for (i = 0; i < NAME_TABLE_SIZE; i++)
	{
		if(nameTable[i].status == NS_PENDING)
		{
			rv = MIN (rv, (long) (nameTable[i].nextSendBase + RTSMB_NB_BCAST_RETRY_TIMEOUT - current_time));
			rv = MAX (0, rv);
		}
	}

	rtp_sig_mutex_claim((RTP_MUTEX) nameQueryTableSem);

	for (i = 0; i < NAME_QUERY_SIZE; i++)
	{
		if(nameQueryTable[i].inUse)
		{
			rv = MIN (rv, (long) (nameQueryTable[i].endTimeBase + RTSMB_NB_BCAST_RETRY_TIMEOUT - current_time));
			rv = MAX (0, rv);
		}
	}

	rtp_sig_mutex_release((RTP_MUTEX) nameQueryTableSem);

	return (rv == 0x7FFFFFFF) ? -1 : rv;
}


#endif /* INCLUDE_RTSMB_SERVER */
