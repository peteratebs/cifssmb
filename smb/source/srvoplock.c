struct rtsmb_oplocks {
        BOOL (*receive_message)(fd_set *fds, char *buffer, int buffer_len);
        BOOL (*set_oplock)(files_struct *fsp, int oplock_type);
        void (*release_oplock)(files_struct *fsp);
        BOOL (*parse_message)(char *msg_start, int msg_len, SMB_INO_T *inode, SM
B_DEV_T *dev);
        BOOL (*msg_waiting)(fd_set *fds);
        int notification_fd;
}