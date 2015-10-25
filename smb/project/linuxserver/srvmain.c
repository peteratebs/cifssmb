/*
  srvmain.c - Sample server program for windows or linux, that should port relatively easilly to most run time environments



  This file is a sample main loop that is used for testing.
  It is not part of RT-SMB proper and need not be included in your code.
  If you want to use parts of this for your main loop, please do.

  If the line #define USE_CONFIG_FILE is TRUE then the share names and access control is provided by the confirguration file.

  The sample configuration file contains documentation for the file.

  srvmain.c is duplicated in the linux and windows projects.

  The only differences are:
  For windows,
  #define RTSMB_WIN is enabled
  For linux
  #ifdef RTSMB_LINUX is enabled

*/
#define RTSMB_WIN
// #define RTSMB_LINUX

#include "srvapi.h"
#include "smbdebug.h"
#include "rtpprint.h"
#include "rtpterm.h"
#include "psmbfile.h"
#include "rtpscnv.h"

//#define USE_CONFIG_FILE


#define NETWORK_NAME "EBSRTSMB"
// #define NETWORK_GROUP "EBSGRP"
#define NETWORK_GROUP "MSHOME"


#if (defined(RTSMB_LINUX))
#define SHARE_PATH "/usr"
#define TEMP_PATH "/tmp"
#elif (defined(RTSMB_WIN))
#define SHARE_PATH "C:\\TESTSMB\\EBS"
#define TEMP_PATH "\\TEMP"
#else
#error "SHARE_PATH_NOT_DEFINED"
#endif

RTSMB_STATIC char spinner[4] = {'\\', '-', '/', '|'};
RTSMB_STATIC int spinState = 0;
RTSMB_STATIC byte ip[4] = {192, 168, 1, 2};
RTSMB_STATIC byte mask_ip[4] = {255, 255, 255, 0};


static void help_security_mode(void);

void rtsmb_main (void)
{
	spinState = (++spinState)%4;
	rtp_printf("\b%c",spinner[spinState]);
	rtsmb_srv_cycle (1000);
}

static void in_ipaddress(byte *pip, byte *pmask_ip);
static int in_printer(char *printerName,char *driverName,char *tempPath,char *prnFile);
static byte in_loginmode(void);
static int in_share(byte security_code, char *shareName,char *sharePath,char *shareDesc,char *sharePass, char *secCode);
static int in_user(char * userName, char *userPass, char *userPerm);
static int in_guestaccount(void);

int smbservermain ()
{
	int go;
	int  have_printer;
	byte counter;
	byte security_mode;

	go = 1;
	/* Start ertfs on windows*/
	//pc_ertfs_init ();

	if (rtp_net_init () < 0)
	{
		return -1;
	}
	/* Retrieve ip address and mask from console and initialize server */
	in_ipaddress(ip, mask_ip);
	rtsmb_srv_init (ip, mask_ip, NETWORK_NAME , NETWORK_GROUP);
    rtp_printf ("Initialized rtsmb\n");

#ifdef USE_CONFIG_FILE
    rtsmb_srv_read_config ("smb_config.txt");
#else
	rtp_printf("Note: The demo does not actually print data, it just captures print data to a temporary file.\n");
	rtp_printf("Add a printer (y/n) ? ");

	rtp_printf("\n");

	{
	char printerName[32];
	char driverName[32];
	char tempPath[32];
	char prnFile[32];
		rtp_strcpy(printerName, "SmbPrinter");
		rtp_strcpy(driverName, "HP LaserJet 1100");
		rtp_strcpy(tempPath, TEMP_PATH);
		rtp_strcpy(prnFile, "SmbPrintData.prn");

		have_printer = in_printer(printerName,driverName, tempPath, prnFile);
	if (have_printer)
		rtsmb_srv_share_add_printer (printerName, driverName, 1, (PSMBFILEAPI)0, tempPath, 0, (PFCHAR)0, prnFile);
	}
	security_mode =	in_loginmode();

    //rtsmb_srv_share_add_tree (SHARE_NAME, DESCRIPTION,  NULL, SHARE_PATH, SHARE_FLAGS_8_3, SECURITY_READWRITE, NULL);
	//rtsmb_srv_share_add_tree (SHARE_NAME, DESCRIPTION, (PSMBFILEAPI)0, SHARE_PATH, SHARE_FLAGS_CREATE, SECURITY_READWRITE, (PFCHAR)0);

	rtsmb_srv_share_add_ipc ((PFCHAR)0);

	rtsmb_srv_set_mode (security_mode);

	rtsmb_srv_register_group ("rw_access");
	rtsmb_srv_register_group ("rd_access");

	{
	char shareName[32];
	char sharePath[32];
	char shareDesc[32];
	char sharePass[32];
	char secCode[32];
	char *psharePass;

		rtp_strcpy(shareName, "share0");
		rtp_strcpy(shareDesc, "Rtsmbshare");
		rtp_strcpy(sharePath, SHARE_PATH);
		rtp_strcpy(sharePass, "");
		rtp_strcpy(secCode,"2");

		if (in_share(security_mode, shareName, sharePath, shareDesc, sharePass, secCode))
		{
		byte security_mode; /* Defult is 2  SECURITY_READWRITE */
		char *psharePass;
			if (sharePass[0])
				psharePass = &sharePass[0];
			else
				psharePass = 0;
			security_mode = (byte)(secCode[0] -'0');
		 	rtsmb_srv_share_add_tree (shareName, shareDesc, (PSMBFILEAPI)0, sharePath, SHARE_FLAGS_CREATE, security_mode, (PFCHAR)psharePass);
		 	rtsmb_srv_set_group_permissions ("rw_access", shareName, SECURITY_READWRITE);
		 	rtsmb_srv_set_group_permissions ("rd_access", shareName, SECURITY_READ);
		}
	}

	//	rtsmb_srv_set_group_permissions ("rw_access", SHARE_NAME, SECURITY_READWRITE);
	rtsmb_srv_set_group_permissions ("rw_access", "IPC$", SECURITY_READWRITE);
	rtsmb_srv_set_group_permissions ("rd_access", "IPC$", SECURITY_READWRITE);

	//rtsmb_srv_register_group ("ro_access");
	//rtsmb_srv_set_group_permissions ("ro_access", SHARE_NAME, SECURITY_READ);
	//rtsmb_srv_set_group_permissions ("ro_access", "IPC$", SECURITY_READWRITE);

	//rtsmb_srv_register_group ("wo_access");
	//rtsmb_srv_set_group_permissions ("wo_access", SHARE_NAME, SECURITY_WRITE);
	//rtsmb_srv_set_group_permissions ("wo_access", "IPC$", SECURITY_READWRITE);

    /* No access */
    //rtsmb_srv_register_group ("nonebs");
	//rtsmb_srv_set_group_permissions ("nonebs", SHARE_NAME, SECURITY_NONE);
	//rtsmb_srv_set_group_permissions ("nonebs", "IPC$", SECURITY_NONE);

	//rtsmb_srv_register_user (SMB_GUESTNAME, (PFCHAR)0);
    //rtsmb_srv_register_user (SMB_GUESTNAME, "ebs");
	//rtsmb_srv_add_user_to_group (SMB_GUESTNAME, "rw_access");

	if (security_mode == AUTH_USER_MODE)
	{
	char userName[32];
	char userPass[32];
	char userPerm[32];

		if (in_guestaccount())
			rtsmb_srv_register_user (SMB_GUESTNAME, (PFCHAR)0);

		rtp_strcpy(userPass, "user");
		rtp_strcpy(userPass, "password");
		rtp_printf("Add users, enter a blank user to stop : ");
		while (in_user(userName, userPass, userPerm))
		{
			rtsmb_srv_register_user (userName, userPass);
			if (rtp_strcmp(userPerm, "rw") == 0)
					{rtsmb_srv_add_user_to_group (userName, "rw_access");break;}
			else if (rtp_strcmp(userPerm, "r") == 0)
				{rtsmb_srv_add_user_to_group (userName, "rd_access");break;}
		}
	}

#endif //USE_CONFIG_FILE
	//Main Loop
	while(go)
	{
		rtsmb_main ();
		if(rtp_term_kbhit())
		{
//			switch (getch())
			switch (rtp_term_getch())
			{
			case 'q':	go = 0;
						break;
			default:	break;
			}
		}
	}

	//Shutdown
	rtp_printf("main: shutting down\n");

	rtsmb_srv_shutdown ();
	rtp_net_exit ();

	return(0);
}//main

static void help_security_mode(void)
{
	rtp_printf("Sorry no help for you . \n");
}

static void in_ipaddress(byte *pip, byte *pmask_ip)
{
	byte counter;
	for (counter=0;counter<4;counter++)
	{
	char inbuffer[32];
        rtp_itoa(pip[counter], inbuffer, 10);
		rtp_printf("Byte %d IP Address: ",counter);
		rtp_term_promptstring (inbuffer, 0);
		pip[counter] = (unsigned char)rtp_atoi(inbuffer);
	}
	for (counter=0; counter<4; counter++)
	{
	char inbuffer[32];
        rtp_itoa(pmask_ip[counter], inbuffer, 10);
		rtp_printf("Byte %d IP Mask: ",counter);
		rtp_term_promptstring (inbuffer, 0);
		pmask_ip[counter] = (unsigned char)rtp_atoi(inbuffer);
	}
	rtp_printf("IP Address: %d.%d.%d.%d\n",pip[0],pip[1],pip[2],pip[3]);
	rtp_printf("IP Mask   : %d.%d.%d.%d\n",pmask_ip[0],pmask_ip[1],pmask_ip[2],pmask_ip[3]);

}

static int in_printer(
	char *printerName,
	char *driverName,
	char *tempPath,
	char *prnFile)
{
int have_printer;
	rtp_printf("Note: The demo does not actually print data, it just captures print data to a temporary file.\n");
	rtp_printf("Add a printer (y/n) ? ");

	have_printer = rtp_term_getch();
	rtp_printf("\n");

	if (have_printer == 'y' || have_printer == 'Y')
	{
		rtp_printf("Set up printer. press enter to keep defaults. \n");
		rtp_printf("Printer name : ");
		rtp_term_promptstring (printerName, 0);
		rtp_printf("Driver name : ");
		rtp_term_promptstring (driverName, 0);
		rtp_printf("Print Capture Path : ");
		rtp_term_promptstring (tempPath, 0);
		rtp_printf("Print Capture File : ");
		rtp_term_promptstring (prnFile, 0);

		return(1);
	}
	return(0);
}

static byte in_loginmode(void)
{
	byte security_mode;
	char which_share_mode[32];
	do {
		rtp_strcpy(which_share_mode, "s");
		rtp_printf("press '?' for help or ..\n");
		rtp_printf("Press 's' for share based passwords, 'u' for user passwords: ");
		rtp_term_promptstring (which_share_mode, 0);
		if (which_share_mode[0] == '?')
			help_security_mode();
	} while (which_share_mode[0] != 's' && which_share_mode[0] != 'u');
	if (which_share_mode[0] == 's')
		security_mode = AUTH_SHARE_MODE;
	else
		security_mode = AUTH_USER_MODE;
	return(security_mode);
}

static int in_share(byte security_mode, char *shareName,char *sharePath,char *shareDesc,char *sharePass, char *secCode)
{
		rtp_printf("Set up shares press enter to keep defaults. \n");
		rtp_printf("Share name : ");
		rtp_term_promptstring (shareName, 0);
		if (!shareName[0])
			return(0);
		rtp_printf("Share Path : ");
		rtp_term_promptstring (sharePath, 0);
		rtp_printf("Share Description : ");
		rtp_term_promptstring (shareDesc, 0);

		if (security_mode == AUTH_SHARE_MODE)
		{
			rtp_printf("Share Password (leave empty for no passwords): ");
			rtp_term_promptstring (sharePass, 0);
			rtp_printf("0==READONLY, 1==WRITEONLY, 2==READWRITE, 3==NOACCES, 4==NO SECRITY\n");
			rtp_printf("Share Security 0,1,2,3,4: ");
			rtp_term_promptstring (secCode, 0);
		 }
		return(1);

}

static int in_user(char * userName, char *userPass, char *userPerm)
{
	rtp_term_promptstring (userName, 0);
	if (userName[0])
	{
		rtp_printf("Password  : ");
		rtp_term_promptstring (userPass, 0);
		rtsmb_srv_register_user (userName, userPass);
		for(;;)
		{
			rtp_strcpy(userPerm, "rw");
			rtp_printf("Select access rights , 'r'ead or 'rw' read-write  : ");
			rtp_term_promptstring (userPerm, 0);
			if (rtp_strcmp(userPerm, "rw") == 0)
				break;
			else if (rtp_strcmp(userPerm, "r") == 0)
				break;
		}
		return(1);
	}
	return(0);
}
static int in_guestaccount(void)
{
	char allow[32];
	rtp_printf("Allow Guest login (y/n) : ");
	rtp_term_promptstring (allow, 0);
	if (allow[0] == 'Y' || allow[0] == 'y')
		return(1);
	return(0);
}

