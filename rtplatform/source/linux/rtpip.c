/* little utility to get the IP address of the machine
- prints the IP address in triple-dotted form xxx.yyy.zzz.www,
or nothing if can't get it.
- this code is a fragment from EpidEm code.
*/
#include "rtpip.h"
#include "rtpprint.h"
#include "rtpnet.h"
#include "rtp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>

/*
Returns the IP address of this host.
- if host have more than 1 IP, only 1 (the first) is returned.
- return is in network byte order
- thanks to Doct. Ghini (www.cs.unibo.it/~ghini)
return: 0 if unsuccessful, the IP otherwise
*/

in_addr_t get_my_IP()
{
	char name[80]; /*store my hostname*/
	struct hostent * hostent_ptr;
	int ret;

	ret = gethostname (name, 80);

	if(ret == -1) {
		rtp_printf ("ERROR gethostname() failed, Errno=%d \nDescription: %s\n", errno, strerror(errno));
		return 0;
	}

	hostent_ptr = gethostbyname(name);

	if(hostent_ptr == NULL)
	{
		rtp_printf ("ERROR gethostbyname() failed, h_errno=%d \nDescription: %s\n", h_errno, hstrerror(h_errno));
		return 0;
	}

/*h_addr_list contains IPs of this host in network byte order */
return ((struct in_addr *)hostent_ptr->h_addr_list[0])->s_addr; /*get the first IP.*/
}
