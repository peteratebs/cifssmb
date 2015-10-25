#ifndef __SMB_BROWSE_BUF_H__
#define __SMB_BROWSE_BUF_H__

#include "smbdefs.h"
#include "smbobjs.h"
#include "smbnb.h"

/* These structures are for packing and reading Datagram */
/* Service packets.										 */
/*														 */	 	
													

//Struct for NETBIOS Datagram Service header
typedef struct
{
	byte type;
	byte flags;
	word id;
	word size;
	word packet_offset;	/* usually 0 */
	
	byte source_ip[4];
	word source_port;
	
	char source_name [RTSMB_NB_NAME_SIZE + 1];
	char destination_name [RTSMB_NB_NAME_SIZE + 1];
	
} RTSMB_NBDS_HEADER;
typedef RTSMB_NBDS_HEADER RTSMB_FAR *PRTSMB_NBDS_HEADER;

//Struct for NETBIOS Datagram Service Anouncements
typedef struct
{
	byte opcode;
	byte update_count;
	dword periodicity;
	rtsmb_char server_name[16];
	byte version_major;
	byte version_minor;
	dword type;
	
	byte browse_version_major;
	byte browse_version_minor;
	word signature;
	
	dword comment_size;
	PFRTCHAR comment;
	
} RTSMB_NBDS_HOST_ANNOUNCEMENT;
typedef RTSMB_NBDS_HOST_ANNOUNCEMENT RTSMB_FAR *PRTSMB_NBDS_HOST_ANNOUNCEMENT;

//Struct for NETBIOS Datagram Service Election Requests
typedef struct
{
	byte version;
	dword criteria;
	dword up_time;
	rtsmb_char server_name [RTSMB_NB_NAME_SIZE + 1];
	
} RTSMB_NBDS_REQUEST_ELECTION;
typedef RTSMB_NBDS_REQUEST_ELECTION RTSMB_FAR *PRTSMB_NBDS_REQUEST_ELECTION;

//Struct for NETBIOS Datagram Service Become Backup packet
typedef struct
{
	rtsmb_char name [RTSMB_NB_NAME_SIZE + 1];
	
} RTSMB_NBDS_BECOME_BACKUP;
typedef RTSMB_NBDS_BECOME_BACKUP RTSMB_FAR *PRTSMB_NBDS_BECOME_BACKUP;

//Struct for NETBIOS Datagram Service Announcement Requests
typedef struct
{
	rtsmb_char name [RTSMB_NB_NAME_SIZE + 1];
	
} RTSMB_NBDS_ANNOUNCEMENT_REQUEST;
typedef RTSMB_NBDS_ANNOUNCEMENT_REQUEST RTSMB_FAR *PRTSMB_NBDS_ANNOUNCEMENT_REQUEST;



int rtsmb_nbds_fill_header (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_NBDS_HEADER pHeader);
int rtsmb_nbds_read_header (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_NBDS_HEADER pHeader);

int rtsmb_nbds_fill_smb_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader);
int rtsmb_nbds_read_smb_header (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader);

int rtsmb_nbds_fill_transaction (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION pTransaction);
int rtsmb_nbds_read_transaction (PFVOID origin, PFVOID buf, rtsmb_size size,
	PRTSMB_HEADER pHeader, PRTSMB_TRANSACTION pTransaction);

int rtsmb_nbds_fill_get_backup_list (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_BROWSE_GET_BACKUP_LIST pGet);
int rtsmb_nbds_read_get_backup_list (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_BROWSE_GET_BACKUP_LIST pGet);


int rtsmb_nbds_fill_whole_backup_list (dword token);



#endif /* __SMB_BROWSE_BUF_H__ */
