//THIS FILE NEEDS WORK BEFORE IT WILL RUN!  DAN - 5/20/04

/* This file is a sample main loop that I use for testing.  It is not part
of RT-SMB proper and need not show up in your code.  If you want to use
parts of this for your main loop, please do. */


//#define RTSMB_RTIP
#define RTSMB_WIN
//#define RTSMB_LINUX

#include "srvapi.h"
#include "cliapi.h"
#include "smbutil.h"
#include <stdlib.h>

#ifdef RTSMB_WIN
#include <winsock.h>
#endif

#ifdef RTSMB_RTIP
#define RTTARGET    1
#define RTKMSP3     1
#include <rtip.h>
#endif

#include "psmbfile.h"

RTSMB_STATIC char spinner[4] = {'\\', '-', '/', '|'};
RTSMB_STATIC int spinState = 0;

unsigned char *malloc_wrap (int i)
{
    return malloc (i);
}


/****************************************************
 * Server Main Loop
 ****************************************************/
void rtsmb_main (void)
{
//  PRINTF (("%c", spinner[spinState]));

    //while (1)
    {
        spinState++;
        spinState = (spinState)%4;
        PRINTF (("\b%c",spinner[spinState]));
#ifdef POLLOS
        xn_pollos_cycle ();
#endif
        rtsmb_srv_cycle (1000);
    }
}


#ifdef RTSMB_WIN
#define WINSOCK_VER 0x0101

RTSMB_STATIC struct WSAData wsa_data;

/****************************************************
 * Initialize Socket for Windows
 ****************************************************/
int SOCK_Init (void)
{
    int result;
    char hostname[100];
    struct hostent *he;
    byte ip [4];

    result = WSAStartup (WINSOCK_VER, &wsa_data);

    if (result)
    {
        PRINTF (("init: Winsock start up failed\n"));
        return -1;
    }

    result = gethostname (hostname, 100);

    if (result)
    {
        PRINTF (("init: Winsock start up failed\n"));
        return -1;
    }

    he = gethostbyname (hostname);

    if (!he)
    {
        PRINTF (("init: Winsock start up failed\n"));
        return -1;
    }

    // just use the first one
    tc_memcpy (ip, he->h_addr_list[0], 4);

    rtsmb_srv_init (ip, NULL, NULL, NULL);
    rtsmb_cli_init (ip, NULL);

    return 0;
}


/****************************************************
 * Shut Down Socket for Windows
 ****************************************************/
void SOCK_Shutdown (void)
{
    WSACleanup();
}


#elif defined (RTSMB_RTIP)

/****************************************************
 * Initialize socket for RTIP
 ****************************************************/
int SOCK_Init (void)
{
    int iface;
    byte tnet_localHost[4] = {192, 168, 1, 43};
    byte tnet_maskip[4] = {255, 255, 255, 0};

    PRINTF (("about to init xn_rtip\n"));
    //   px_init ();
    if(xn_rtip_init()!=0)
    {
        PRINTF (("SOCK_Init: Error in xn_rtip_init\n"));
        return -1;
    }

    PRINTF (("about to open xn_interface config\n"));
    // packard bell
//  iface = xn_interface_open_config (NE2000_DEVICE, MINOR_0, 0x220, 10, 0);
    // IntelliStation
//  iface = xn_interface_open_config (I82559_DEVICE, MINOR_0, 0x78e0, 8, 0xf000);
    // Toshiba
    iface = xn_interface_open_config (CE3_PCMCIA_DEVICE, MINOR_0, 0x110, 10, 0);

    if(iface < 0)
    {
        PRINTF (("SOCK_Init: Interface Open Failed - returned %s\n",
            xn_geterror_string (xn_getlasterror ())));
        return -1;
    }

        PRINTF (("about to set ip\n"));
    if(xn_set_ip(iface, tnet_localHost, tnet_maskip))
    {
        PRINTF (("SOCK_Init: xn_set_ip error\n"));
        return -1;
    }

    rtsmb_srv_init (tnet_localHost, tnet_maskip, NULL, NULL);
    rtsmb_cli_init (tnet_localHost, tnet_maskip);

    return 0;
}


/****************************************************
 * Shutdown socket for RTIP
 ****************************************************/
void SOCK_Shutdown (void)
{
}

#elif defined (RTSMB_LINUX)

#include <netdb.h>
#include <unistd.h>

/****************************************************
 * Initialize socket for Linux
 ****************************************************/
int SOCK_Init (void)
{
    return 0;
}

/****************************************************
 * Shutdown socket for Linux
 ****************************************************/
void SOCK_Shutdown (void)
{
}
#endif

#ifndef RTSMB_LINUX
#include <conio.h>
#endif

#ifdef RTSMB_WIN
#include <time.h>
#include <winnt.h>
#endif

#include "srvcfg.h"

#define SHARE_SERVER "toshiba"

#include "clitest.h"

/****************************************************
 * Main Method
 ****************************************************/
int main (int argc, char *argv[])
{
    int go;
    int total, free, per, size;
    char cwd [SMBF_FILENAMESIZE + 1];
//  int sid;
    RTSMB_CLI_SESSION_DSTAT dstat;

    go = 1;
    if (SOCK_Init ())
        return 1;

//  rtsmb_cli_session_new_with_name (argv[1], TRUE, NULL, &sid);
//  rtsmb_cli_session_full_server_enum (sid, 0xFFFFFFFF, argv[2], NULL, 0);
//  return 0;

    PRINTF (("Initialized rtsmb\n"));

    rtsmb_cli_ez_set_cwd ("//blah/c");

    rtsmb_cli_ez_open ("yo.txt", RTP_FILE_O_CREAT | RTP_FILE_O_RDONLY, RTP_FILE_S_IREAD);

    rtsmb_cli_ez_get_cwd (cwd, SMBF_FILENAMESIZE);
    printf ("cwd is %s\n", cwd);

    rtsmb_cli_ez_set_cwd ("//blah/c/trans2");

    rtsmb_cli_ez_open ("\\yo.txt", RTP_FILE_O_CREAT | RTP_FILE_O_RDONLY, RTP_FILE_S_IREAD);

    rtsmb_cli_ez_get_cwd (cwd, SMBF_FILENAMESIZE);
    printf ("cwd is %s\n", cwd);

    PRINTF (("Starting client test\n"));
//  rtsmb_cli_test_regression ("blah", 1);

#if defined (RTSMB_LINUX)
    rtsmb_srv_share_add_tree ("c", "testbed dir", NULL, "/rtsmb", SHARE_FLAGS_CASE_SENSITIVE, SECURITY_READWRITE, NULL);
    rtsmb_srv_share_add_ipc (NULL);
#elif 0
    rtsmb_srv_read_config ("c:\\smbconf.txt");
#else

    rtsmb_cli_ez_set_user ("Michael Terry", "hello");

    rtsmb_srv_share_add_tree ("c", "testbed dir", NULL, "c:\\rtsmb", SHARE_FLAGS_8_3 | SHARE_FLAGS_CREATE, SECURITY_READWRITE, NULL);
//  if (rtsmb_srv_share_add_tree ("c", "testbed dir", NULL, "\\\\" SHARE_SERVER "\\c", SHARE_FLAGS_8_3, SECURITY_READWRITE, NULL) < 0)
        //abort ();
    rtsmb_srv_share_add_ipc (NULL);
  //  rtsmb_srv_share_add_printer ("printer", "Test Printer", 1, NULL, "c:\\", 0, NULL, "HP LaserJet 1100");

    //rtsmb_srv_set_mode (AUTH_SHARE_MODE);

    rtsmb_srv_set_mode (AUTH_USER_MODE);
    rtsmb_srv_register_group ("ebs");
    rtsmb_srv_set_group_permissions ("ebs", "c", SECURITY_READWRITE);
    rtsmb_srv_set_group_permissions ("ebs", "IPC$", SECURITY_READWRITE);
    rtsmb_srv_set_group_permissions ("ebs", "printer", SECURITY_READWRITE);

    rtsmb_srv_register_group ("nonebs");
    rtsmb_srv_set_group_permissions ("nonebs", "c", SECURITY_READ);
    rtsmb_srv_set_group_permissions ("nonebs", "IPC$", SECURITY_READWRITE);
    rtsmb_srv_set_group_permissions ("nonebs", "printer", SECURITY_READWRITE);

    rtsmb_srv_register_user (SMB_GUESTNAME, NULL);
    rtsmb_srv_add_user_to_group (SMB_GUESTNAME, "nonebs");

    rtsmb_srv_register_user ("TONY", "roxor");
    rtsmb_srv_add_user_to_group ("TONY", "ebs");

    rtsmb_srv_register_user ("JOHN", "hello");
    rtsmb_srv_add_user_to_group ("JOHN", "ebs");

    rtsmb_srv_register_user ("MIKE TERRY", "blarg");
    rtsmb_srv_add_user_to_group ("MIKE TERRY", "ebs");

    rtsmb_srv_register_user ("MIKE", "blarg");
    rtsmb_srv_add_user_to_group ("MIKE", "ebs");


#endif
//  os_spawn_task (TASKCLASS_CURRENT, rtsmb_main, 0,0,0,0);

    while (1)
    {
        rtsmb_srv_cycle (-1);
        if (go++ % 2 == 0)
        {
        //  printf ("0");
        }
        else
        {
    //      printf ("-");
        }
    }

    printf ("Press return to shut down SMB Server \n");
    //Main Loop
    while(go)
    {
        int r;
    //  ks_sleep (ks_ticks_p_sec () * 2);
        rtsmb_main ();
#ifndef RTSMB_LINUX
        if(kbhit())
        {
            switch (getch())
            {
            case 'q':   go = 0;
                        break;
            case 'r':   rtsmb_srv_share_remove ("c");
                        break;
            case 'a':   rtsmb_srv_share_add_tree ("c", "windows dir", NULL, "c:\\rtsmb", SHARE_FLAGS_8_3, SECURITY_READWRITE, "blarggity24");
                        break;
            case 'i':   {
                byte newip[4] = {192,168,1,100};
                byte newmask[4] = {255, 255, 0, 0};
                        rtsmb_srv_set_ip (newip, newmask);
                        }
                        break;
            case 'u':   {
                byte newip[4] = {192,168,1,20};
                byte newmask[4] = {255, 255, 255, 0};
                        rtsmb_srv_set_ip (newip, newmask);
                        }
                        break;
#ifdef RTSMB_RTIP
            case 'p':   PRINTF (("Starting Debug Output:\n"));
                        DEBUG_ERROR ("\n\n", PORTS_TCP, 0, 0);
                        break;
#endif

            case '1':   r = rtsmb_cli_ez_open ("//blah/c/yo.txt", RTP_FILE_O_CREAT | RTP_FILE_O_RDONLY, RTP_FILE_S_IREAD);
                        PRINTF (("On EZ open, fd is %i\n", r));
                        break;

            case '2':   r = rtsmb_cli_ez_get_free ("//blah/c/yo.txt", &total, &free, &per, &size);
                        PRINTF (("total: %i, free: %i, per: %i, size: %i\n", total, free, per, size));
                        break;

            case '3':   r = rtsmb_cli_ez_find_first ("//*", &dstat);

                        printf ("Start of server search.\n");
                        while (r == 1)
                        {
                            if (dstat.unicode)
                            {
                                PRINTF (("  server name: %S\n", dstat.filename));
                            }
                            else
                            {
                                PRINTF (("  server name: %s\n", dstat.filename));
                            }

                            r = rtsmb_cli_ez_find_next (&dstat);
                        }

                        rtsmb_cli_ez_find_close (&dstat);
                        break;

            default:    break;
            }
       }
#endif
    }

    //Shutdown
    PRINTF (("main: shutting down\n"));

    rtsmb_cli_shutdown ();
    rtsmb_srv_shutdown ();
    SOCK_Shutdown ();

    return(0);
}//main

