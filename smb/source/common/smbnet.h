#ifndef __SMB_NET_H__
#define __SMB_NET_H__

extern int rtsmb_nbds_port;
extern int rtsmb_nbns_port;

extern int rtsmb_nbss_port;
extern int rtsmb_nbss_direct_port;

int rtsmb_net_read (RTP_SOCKET sock, PFVOID buf, dword bufsize, dword size);
int rtsmb_net_read_datagram (RTP_SOCKET sock, PFVOID pData, int size, PFBYTE remoteAddr, PFINT remotePort);

int rtsmb_net_write (RTP_SOCKET sock, PFVOID pData, int size);
void rtsmb_net_write_datagram (RTP_SOCKET socket, PFBYTE remote, int port, PFVOID pData, int size);

int rtsmb_net_str_to_ip (PFCHAR pfAddrStr, PFBYTE pfAddr);
PFCHAR rtsmb_net_ip_to_str (PFBYTE pfAddr, PFCHAR pfAddrStr);

int rtsmb_net_socket_new (RTP_SOCKET* sock_ptr, int port, BBOOL reliable);

void rtsmb_net_set_ip (PFBYTE host_ip, PFBYTE mask_ip);
PFBYTE rtsmb_net_get_host_ip (void);
PFBYTE rtsmb_net_get_broadcast_ip (void);
BBOOL rtsmb_net_are_valid_ips (void);	/* returns TRUE if some ip has been set */

#endif /* __SMB_NET_H__ */
