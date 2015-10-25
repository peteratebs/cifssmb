#ifndef __SRV_OPLOCK_H__
#define __SRV_OPLOCK_H__

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

typedef struct smb_oplocks_s {
        BOOL (*receive_message)(fd_set *fds, char *buffer, int buffer_len);
        BOOL (*set_oplock)(files_struct *fsp, int oplock_type);
        void (*release_oplock)(files_struct *fsp);
        BOOL (*parse_message)(char *msg_start, int msg_len, SMB_INO_T *inode, SM
B_DEV_T *dev);
        BOOL (*msg_waiting)(fd_set *fds);
        int notification_fd;
}SMB_OPLOCKS_T;
typedef SMB_OPLOCKS_T RTSMB_FAR *PSMB_OPLOCKS;

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_OPLOCK_H__ */
