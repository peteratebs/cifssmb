#ifndef __SMB_NBDS_H__
#define __SMB_NBDS_H__

#include "smbdefs.h"
#include "smbnb.h"
// 1021
#define RTSMB_NBDS_PORT        138   /* well-known port number */
#define RTSMB_NBDS_PORT_ALT   9138   /* alternate port number to use */

#define RTSMB_NBDS_DIRECT_UNIQUE_DATAGRAM   0x10
#define RTSMB_NBDS_DIRECT_GROUP_DATAGRAM    0x11

#define RTSMB_NBDS_DATAGRAM_HEADER_SIZE     82  /* 14 + 34 + 34 (control bytes plus 2 names)*/

/* Some defines that set server types */
#define SV_TYPE_WORKSTATION         0x00000001  // All workstations
#define SV_TYPE_SERVER              0x00000002  // All servers
#define SV_TYPE_SQLSERVER           0x00000004  // Any server running with SQL server
#define SV_TYPE_DOMAIN_CTRL         0x00000008  // Primary domain controller
#define SV_TYPE_DOMAIN_BAKCTRL      0x00000010  // Backup domain controller
#define SV_TYPE_TIME_SOURCE         0x00000020  // Server running the timesource service
#define SV_TYPE_AFP                 0x00000040  // Apple File Protocol servers
#define SV_TYPE_NOVELL              0x00000080  // Novell servers
#define SV_TYPE_DOMAIN_MEMBER       0x00000100  // Domain Member
#define SV_TYPE_PRINTQ_SERVER       0x00000200  // Server sharing print queue
#define SV_TYPE_DIALIN_SERVER       0x00000400  // Server running dialin service
#define SV_TYPE_XENIX_SERVER        0x00000800  // Xenix server
#define SV_TYPE_NT                  0x00001000  // NT workstation
#define SV_TYPE_WFW                 0x00002000  // Server running Windows For Workgroups
#define SV_TYPE_SERVER_NT           0x00008000  // Windows NT non DC server
#define SV_TYPE_POTENTIAL_BROWSER   0x00010000  // Server that can run the browser service
#define SV_TYPE_BACKUP_BROWSER      0x00020000  // Backup browser server
#define SV_TYPE_MASTER_BROWSER      0x00040000  // Master Browser server
#define SV_TYPE_DOMAIN_MASTER       0x00080000  // Domain Master Browser server
#define SV_TYPE_WINDOWS             0x00400000  // Windows 95 or later
#define SV_TYPE_LOCAL_LIST_ONLY     0x40000000  // Enumerate only entries marked "local"
#define SV_TYPE_DOMAIN_ENUM         0x80000000  // Enumerate Domains.  The pszServer and pszDomain parameters must be NULL


typedef struct
{
    dword type; /* if type is 0, this information is invalid and unused */

    char name [RTSMB_NB_NAME_SIZE + 1]; /* tbd - change this to 16bit */
    char comment [RTSMB_MAX_COMMENT_SIZE + 1];

    dword periodicity;
    unsigned long time_received;

    byte update_count; /* unused by us */
    byte version_major; /* unused by us */
    byte version_minor; /* unused by us */
    byte browse_version_major; /* unused by us */
    byte browse_version_minor; /* unused by us */
    word signature; /* unused by us */

} RTSMB_BROWSE_SERVER_INFO;
typedef RTSMB_BROWSE_SERVER_INFO RTSMB_FAR *PRTSMB_BROWSE_SERVER_INFO;



void rtsmb_nbds_init (void);
void rtsmb_nbds_cycle (long timeout);
void rtsmb_nbds_shutdown (void);

int rtsmb_nbds_get_backup_server (int domain_index, PFCHAR dest, int alt_index);

RTP_SOCKET rtsmb_nbds_get_socket (void);

word rtsmb_nbds_get_next_datagram_id (void);
PFCHAR rtsmb_nbds_get_last_remote_name (void);
PFBYTE rtsmb_nbds_get_last_remote_ip (void);
int rtsmb_nbds_get_last_remote_port (void);

int  rtsmb_nbds_write (PFVOID data, rtsmb_size size, PFBYTE remote, int port);


/**
 * Browser commands
 */
#define RTSMB_NBDS_COM_HOST_ANNOUNCEMENT           1
#define RTSMB_NBDS_COM_ANNOUNCEMENT_REQUEST        2
#define RTSMB_NBDS_COM_REQUEST_ELECTION            8
#define RTSMB_NBDS_COM_GET_BACKUP_LIST_REQUEST     9
#define RTSMB_NBDS_COM_GET_BACKUP_LIST_RESPONSE   10
#define RTSMB_NBDS_COM_BECOME_BACKUP              11
#define RTSMB_NBDS_COM_DOMAIN_ANNOUNCEMENT        12
#define RTSMB_NBDS_COM_MASTER_ANNOUNCEMENT        13
#define RTSMB_NBDS_COM_LOCAL_MASTER_ANNOUNCEMENT  15


/**
 * Some #defines to control the netbios datagram service.  It is not recommended
 * that these be changed.
 */
#define RTSMB_NBDS_SMB_SIZE                69 /* size of all the smb stuff before browser content */
#define RTSMB_NBDS_BACKUP_RETRY_DELAY      RTSMB_NB_BCAST_RETRY_TIMEOUT
#define RTSMB_NBDS_BACKUP_EXPIRE_DELAY     1200000L /* 20 minutes in milliseconds */
#define RTSMB_NBDS_ELECTION_VERSION        0x01
#define RTSMB_NBDS_BROWSER_VERSION_MINOR   0x0F /* from draft-leach-cifs-browser-spec-00.txt */
#define RTSMB_NBDS_BROWSER_VERSION_MAJOR   0x01
#define RTSMB_NBDS_BROWSER_VERSION         ((RTSMB_NBDS_BROWSER_VERSION_MAJOR << 8) | RTSMB_NBDS_BROWSER_VERSION_MINOR)


#endif /* __SMB_NBDS_H__ */
