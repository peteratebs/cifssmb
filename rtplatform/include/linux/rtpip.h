#ifndef __RTPIP_H__
#define __RTPIP_H__

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>

#define rtp_in_addr_t in_addr_t;
#define rtp_in_addr   in_addr;
#define rtp_inet_ntoa inet_ntoa;

rtp_in_addr_t get_my_IP (void);

#endif