/* EBS SMB Client Application entery point.
    This module initializes TCP networking and then calls an interactive test shell
    that demonstrates SMB client commands

    Note: using a fixed ip address, recompile with
*/
#if defined(_WIN32)||defined(_WIN64)
#define RTSMB_WINDOWS 1
#define RTSMB_LINUX  0
#elif defined(__linux)
#define RTSMB_WINDOWS   0
#define RTSMB_LINUX     1
#else
#error Unsupported OS......
#endif

#define CALL_SHELL 1        /* If 1 call the interactive shell, otherwise call (archane) test routines. */

#if (RTSMB_WINDOWS)
#include <windows.h>
#endif
#include "cliapi.h"
#include "smbutil.h"
#include "rtpnet.h"
#include "rtpprint.h"
#include "clirpc.h"
#include "clsrvsvc.h"


/* Instructions..
    EBS CIFS SMB Client shell and tests

    To build ..
    Select
    CALL_SHELL or
    CALL_TESTS

    Initialize the following variables

        my_ip[]  - The IP address of the machine where the client test is running
        my_mask[] - The network mask for the lan (usually {255, 255, 255, 0} }

        The default configuration is:

            The IP address is: {192,168,1,3};
            The lan mask is {255, 255, 255, 0};


    To run the shell or test..

    If running on Windows - Setting up the client (where the test will be executed)

    Disable SMB and NetBios support on the client machine where the tests will
    be built and executed from:

    To do this select:

        control panel|network connections

        Right click on Active Lan connection

        Properties:

              File and Printer Sharing For Microsoft Network - Un-check this box
              Click on  Internet Protocol (TCP/IP)
              Click the "Advanced" button
              Select the WINS tab
              click on Disable Netbios over TCP-IP

*/



#if (RTSMB_WINDOWS)
static void socket_init ();
#endif
#if (CALL_SHELL)
int smb_test_main(int argc, char *argv[]);
int smb_cli_shell(void);
#endif
int smbclientmain(int argc, char *argv[])
{
#if (RTSMB_WINDOWS)
    socket_init ();
#endif
#if (CALL_SHELL)
    return(smb_cli_shell());
#else
    return(smb_test_main(argc, argv));
#endif
}

#if (RTSMB_WINDOWS)
static void socket_init ()
{
    #define WINSOCK_VER 0x0101
    int result;

    RTSMB_STATIC struct WSAData wsa_data;

    result = WSAStartup (WINSOCK_VER, &wsa_data);

    if (result)
    {
        rtp_printf(("init: Winsock start up failed\n"));
    }
}
#endif

#if (0)
/* Helpers, see shel and test */
void mark_rv (int job, int rv, void *data)
{
    int *idata = (int *)data;
    *idata = rv;
    if (rv==-52)
        rtp_printf("Bad Permissions, Marked = %d\n",*idata);
}
int wait_on_job(int sid, int job)
{
    int rv = RTSMB_CLI_SSN_RV_INVALID_RV;
    int r;
    rtsmb_cli_session_set_job_callback(sid, job, mark_rv, &rv);

    while(rv == RTSMB_CLI_SSN_RV_INVALID_RV)
    {
        r = rtsmb_cli_session_cycle(sid, 10);
        if (r < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "\n wait_on_job: rtsmb_cli_session_cycle returned error == %d\n",r);
            return r;
        }
        if (rv == RTSMB_CLI_SSN_RV_INVALID_RV)
        {
            //rtp_printf("\n In the middle of cycling");
        }
    }
    return rv;
}
#endif
