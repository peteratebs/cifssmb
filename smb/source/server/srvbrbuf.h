#ifndef __SRV_BROWSE_BUF_H__
#define __SRV_BROWSE_BUF_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "smbbrbuf.h"

int rtsmb_srv_browse_fill_host_announcement (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_HOST_ANNOUNCEMENT pBrowse);
int rtsmb_srv_browse_read_host_announcement (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_HOST_ANNOUNCEMENT pBrowse);

int rtsmb_srv_browse_fill_request_election (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_REQUEST_ELECTION prequest);
int rtsmb_srv_browse_read_request_election (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_REQUEST_ELECTION prequest);

int rtsmb_srv_browse_fill_become_backup (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_BECOME_BACKUP prequest);
int rtsmb_srv_browse_read_become_backup (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_BECOME_BACKUP prequest);

int rtsmb_srv_browse_fill_announcement_request (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_NBDS_ANNOUNCEMENT_REQUEST prequest);

int rtsmb_srv_browse_fill_get_backup_list_response (PFVOID origin, PFVOID buf, rtsmb_size size, 
	PRTSMB_HEADER pHeader, PRTSMB_BROWSE_GET_BACKUP_LIST_R presponse);


int rtsmb_srv_browse_fill_whole_announcement (BBOOL domain, BBOOL shutdown);
int rtsmb_srv_browse_fill_whole_request_election (void);
int rtsmb_srv_browse_fill_whole_announcement_request (void);
int rtsmb_srv_browse_fill_whole_get_backup_list_response (int count, dword token);
int rtsmb_srv_browse_fill_whole_become_backup (PFCHAR name);


#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SMB_BROWSE_BUF_H__ */
