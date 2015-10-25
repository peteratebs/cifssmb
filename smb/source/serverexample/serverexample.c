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

/* Guess linux or windows based on compiler.. if this is wrong it's easy to fix */
#if (defined( _WIN32)||defined(_WIN64))
#define RTSMB_WIN
#endif

#ifdef __linux
#define RTSMB_LINUX
#endif

#include "srvapi.h"
#include "smbdebug.h"
#include "rtpprint.h"
#include "rtpterm.h"
#include "psmbfile.h"
#include "rtpscnv.h"
#include "rtpthrd.h"

//#define USE_CONFIG_FILE

#if (defined(RTSMB_LINUX))
//#define SHARE_PATH "/usr"
// #define SHARE_PATH "/home/peter/SmbTest"
// #define SHARE_PATH "/media/sf_0a_share_with_virtual_box/ebs/ebssmb_pre_v2"
#define SHARE_PATH "/media"
#define TEMP_PATH "/tmp"
static int select_linux_interface(unsigned char *pip, unsigned char *pmask_ip);
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
RTSMB_STATIC int pollforcommands = 1;

#if (defined(RTSMB_LINUX))
#	define USE_KB_FILE 0
#else
#   define USE_KB_FILE 0
#endif

#define SRVGETCHAR() rtp_term_getch()
#define SRVKBHIT() rtp_term_kbhit()
#define SRVPROMPT(A,B)  rtp_term_promptstring (A, B)
////////////////////////////////////////////////////

static void help_security_mode(void);
static int smbserver_runtimecommand(void);
static int smbserver_runtimeadduser(void);
static int smbserver_runtimeaddshare(void);
static int smbserver_runtimemodifyuser(void);
static int smbserver_runtimemodifyshare(void);
static int smbserver_runtimeaddprinter(void);
static int smbserver_runtimemodifyprinter(void);
static int smbserver_serverdisable(void);
static int smbserver_serverenable(void);

void rtsmb_main (void)
{
	spinState += 1;
	spinState = spinState%4;
	rtp_printf("\b%c",spinner[spinState]);
	rtsmb_srv_cycle (1000);
}

static int in_bool(char *prompt, char defaultC);
static void in_ipaddress(byte *pip, byte *pmask_ip);
static int in_printer(char *printerName,char *driverName,char *tempPath,char *prnFile);
static byte in_loginmode(void);
static int in_share(byte security_code, char *shareName,char *sharePath,char *shareDesc,char *sharePass, char *secCode);
static int in_user(char * userName, char *userPass, char *userPerm);
static int in_guestaccount(void);
static void in_name(char *network_name, char *network_group);
static int in_pollforcommands(void);

static byte security_mode;

int go; /* Variable loop on.. Note: Linux version needs sigkill support to clean up */
int smbservermain ()
{

	go = 1;

 	if (rtp_net_init () < 0)
	{
		return -1;
	}



	rtp_printf("\nConfigure Rtsmb server...\n");
	rtp_printf("Press return to use defaults.. \n");

#ifdef RTSMB_LINUX
    if (select_linux_interface(ip, mask_ip) < 0)
#endif
    { // Resort to selecting he address by hand if linux retrieve address failed
	  rtp_printf("Note: The default values can be changed by editing serverexample.c and recompiling.\n");
	  rtp_printf("=========================================================\n\n ");
	  /* Retrieve ip address and mask from console and initialize server */
	  in_ipaddress(ip, mask_ip);
    }

    rtp_printf("Using PORT numbers (137 and 138),SMB/SAMBA should not also be running on this device.\n");
    rtsmb_init_port_well_know();
    // See also: rtsmb_init_port_alt();

	/* Retrieve the name and workgroup */
	{
	char network_name[32];
	char network_group[32];

		rtp_strcpy(network_name, "EBSRTSMB");
//		rtp_strcpy(network_group, "MSHOME");
		rtp_strcpy(network_group, "WORKGROUP");

        rtp_printf("Node Name :%s Workgroup:%s\n",network_name, network_group);
//		in_name(network_name, network_group);
		rtsmb_srv_init (ip, mask_ip, network_name , network_group);
	}


#ifdef USE_CONFIG_FILE
    rtsmb_srv_read_config ("smb_config.txt");
#else

	/* Prompt for printers. */
	smbserver_runtimeaddprinter();

	rtsmb_srv_share_add_ipc ((PFCHAR)0);

	/* Ask for user or share based security */
	security_mode =	in_loginmode();
	rtsmb_srv_set_mode (security_mode);

	/* Register names used by Rtsmb to control read write permissions */
	rtsmb_srv_register_group ("rw_access");
	rtsmb_srv_register_group ("rd_access");

	/* Prompt for shares. */
	smbserver_runtimeaddshare();

	/* Everyone must be able to read and write the IPC pipe */
	rtsmb_srv_set_group_permissions ("rw_access", "IPC$", SECURITY_READWRITE);
	rtsmb_srv_set_group_permissions ("rd_access", "IPC$", SECURITY_READWRITE);

	/* Old cruft, demonstrates some other security */

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

	/* Prompt for user name and passwords */

	if (security_mode == AUTH_USER_MODE)
	{
	//char userName[32];
	//char userPass[32];
	//char userPerm[32];

		if (in_guestaccount())
		{
			rtsmb_srv_register_user (SMB_GUESTNAME, SMB_GUESTPASSWORD);
			rtsmb_srv_add_user_to_group (SMB_GUESTNAME, "rd_access");
		}
		rtp_printf("Add users, enter a blank user name to stop adding .. \n");
		rtp_printf("To stop adding users press BACKSPACE until the input field is empty followed by <return>.. \n");
		while (smbserver_runtimeadduser() == 1)
			;
	}

#endif //USE_CONFIG_FILE

#ifdef RTSMB_LINUX
	pollforcommands = in_pollforcommands();
#else
	pollforcommands = 1;
#endif

	if (pollforcommands)
	{
		rtp_printf("\n\n\n\n\n\n");
		rtp_printf("Server is running... Press return to enter a command or to quit\n");
	}
	else
	{
		rtp_printf("\n The Server is running.. Press control C to exit\n");
	}

	//Inside smbservermain
	/*************************************************************************************/
	while(go){
		rtsmb_main ();

		if(pollforcommands && SRVKBHIT())
		{
#ifdef RTSMB_WIN
			SRVGETCHAR();
#endif //RTSMB_WIN
			if (smbserver_runtimecommand() == -1)
				break;
			else
				rtp_printf("Server is running... Press return to enter a command or to quit\n");
		}
	} // while (go)
	/************************************************************************************/

	//Shutdown
	rtp_printf("main: shutting down\n");

	rtsmb_srv_shutdown ();
	rtp_net_exit ();

	return(0);
}//smbservermain

static int smbserver_runtimeadduser(void)
{
	/* Prompt for user name and passwords */
	if (security_mode == AUTH_USER_MODE)
	{
	char userName[32];
	char userPass[32];
	char userPerm[32];


		rtp_strcpy(userName, "");
		rtp_strcpy(userPass, "");
		rtp_printf("Add a new user .. \n");
		if (in_user(userName, userPass, userPerm))
		{
			if (!rtsmb_srv_register_user (userName, userPass))
			{
				rtp_printf("rtsmb_srv_register_user() failed. check configuration\n");
			}
			else
			{
				rtp_printf("rtsmb_srv_register_user() succeeded.\n");

				if (rtp_strcmp(userPerm, "rw") == 0 && !rtsmb_srv_add_user_to_group (userName, "rw_access"))
				{
					rtp_printf("rtsmb_srv_add_user_to_group() failed. check configuration\n");
				}
				else if (/* rtp_strcmp(userPerm, "r") == 0 && */!rtsmb_srv_add_user_to_group (userName, "rd_access"))
				{
					rtp_printf("rtsmb_srv_add_user_to_group() failed. check configuration\n");
				}
			}
			return(1);
		}
	}
	return(0);
}//smbserver_runtimeadduser

int smbserver_runtimemodifyuser (void)
{
	char userName[32]="";
	char *puserName;
	int newsecCode;

	if (security_mode == AUTH_USER_MODE)
	{
		rtp_printf("User to modify  : ");
		SRVPROMPT (userName, 0);
		rtp_printf("\nEnter new access rights");
		rtp_printf("\n0==READONLY, 1==READWRITE");
		rtp_printf("\nUser access-rights 0,1: ");
		rtp_scanf ("%d",&newsecCode);

		if (userName[0])
			puserName = &userName[0];
		else
			puserName = 0;

		if(puserName != 0)
		{
			switch(newsecCode)
			{
				case 0:
				{
					rtsmb_srv_remove_user_from_group (puserName, "rw_access");
					rtsmb_srv_remove_user_from_group (puserName, "rd_access");
					if(!rtsmb_srv_add_user_to_group (puserName, "rd_access"))
						rtp_printf("rtsmb_srv_add_user_to_group() failed. check configuration\n");
					break;
				}
				case 1:
				{
					rtsmb_srv_remove_user_from_group (puserName, "rw_access");
					rtsmb_srv_remove_user_from_group (puserName, "rd_access");
					if(!rtsmb_srv_add_user_to_group (puserName, "rw_access"))
						rtp_printf("rtsmb_srv_add_user_to_group() failed. check configuration\n");
					break;
				}
				default:
					rtp_printf("\nInvalid User access\n");
			}
		}
		else
			rtp_printf("\nUsername invalid\n");
		return(1);
	}
	return(0);
}//smbserver_runtimemodifyuser

static int smbserver_runtimeaddshare(void)
{
char shareName[32];
char sharePath[32];
char shareDesc[32];
char sharePass[32];
char secCode[32];

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
	 	if (rtsmb_srv_share_add_tree (shareName, shareDesc, 0, sharePath, SHARE_FLAGS_CREATE, security_mode, (PFCHAR)psharePass) == 0)
			rtp_printf("Share added.\n");
		else
			rtp_printf("Share add failed\n");
	 	if (!rtsmb_srv_set_group_permissions ("rw_access", shareName, SECURITY_READWRITE))
			rtp_printf("Set rw_access group permissions failed\n");
	 	if (!rtsmb_srv_set_group_permissions ("rd_access", shareName, SECURITY_READ))
			rtp_printf("Set rd_access group permissions failed\n");
	}
	return(0);
}//smbserver_runtimeaddshare

int smbserver_runtimemodifyshare (void)
{
	char cur_share_name[32]="";
	char new_share_name[32]="";
	char newsecCode[32]="";
	byte newpermissions;
	char *pcur_share_name;

	rtp_printf("\nShare to modify:");
	SRVPROMPT (cur_share_name, 0);
	rtp_printf("\nEnter new share name or press enter to keep the current name: ");
	SRVPROMPT (new_share_name, 0);
	rtp_printf("\nEnter new access rights or press enter to keep the current access rights");
	rtp_printf("\n0==READONLY, 1==WRITEONLY, 2==READWRITE, 3==NOACCES, 4==NO SECRITY");
	rtp_printf("\nShare Security 0,1,2,3,4: ");
	SRVPROMPT (newsecCode, 0);

	if (newsecCode[0])
		newpermissions = (byte)(newsecCode[0] -'0');
	else
		newpermissions = 99;// If not changing, assign any value <0 or >4

	if (cur_share_name[0])
		pcur_share_name = &cur_share_name[0];
	else
		pcur_share_name = 0;

	if(pcur_share_name != 0)
	{
        if(rtsmb_srv_share_modify (cur_share_name, new_share_name, newpermissions) == 0)
		{
			rtp_printf("Share Modified.\n");
		}
        else
		{
            rtp_printf("Share Modify failed.\n");
		}
	}
	else
		rtp_printf("Share to Modify name Invalid\n");

	return(0);
}//smbserver_runtimemodifyshare

static int smbserver_runtimeaddprinter(void)
{
	/* Prompt to add a printer */
	char printerName[32];
	char driverName[32];
	char tempPath[32];
	char prnFile[32];
	int  have_printer;

		rtp_strcpy(printerName, "SmbPrinter");
		rtp_strcpy(driverName, "HP LaserJet 1100");
		rtp_strcpy(tempPath, TEMP_PATH);
		rtp_strcpy(prnFile, "SmbPrintData.prn");

//		have_printer = in_printer(printerName,driverName, tempPath, prnFile);
	have_printer = 1;
	if (have_printer)
		rtsmb_srv_share_add_printer (printerName, driverName, 1, (PSMBFILEAPI)0, tempPath, SHARE_FLAGS_CREATE, (PFCHAR)0, prnFile);

	return(0);
}//smbserver_runtimeaddprinter

static int smbserver_runtimemodifyprinter(void)
{
	char cur_printer_name[32]="";
	char new_printer_name[32]="";
	char *pcur_printer_name;

	rtp_printf("\nPrinter to modify:");
	SRVPROMPT (cur_printer_name, 0);
	rtp_printf("\nEnter new printer name or press enter to keep the current name: ");
	SRVPROMPT (new_printer_name, 0);

	if (cur_printer_name[0])
		pcur_printer_name = &cur_printer_name[0];
	else
		pcur_printer_name = 0;

	if(pcur_printer_name != 0)
	{
        if(rtsmb_srv_printer_modify (cur_printer_name, new_printer_name))
		{
			rtp_printf("Printer name Modified.\n");
		}
        else
		{
            rtp_printf("Printer name modification failed.\n");
		}
	}
	else
		rtp_printf("Printer to Modify name Invalid\n");

	return(0);
}//EOF smbserver_runtimemodifyprinter

static int smbserver_serverdisable(void)
{
	rtsmb_srv_disable ();
	rtp_printf("Server Disabled\n");

	for(;;)
	{
		if(in_bool("Enable? (y/n) : ", 'Y'))
		{
			smbserver_serverenable();
			break;
		}
	}

	return (0);
}//EOF smbserver_serverdisable

static int smbserver_serverenable(void)
{
	char network_name[32];
	char network_group[32];

		rtp_strcpy(network_name, "EBSRTSMB");
		rtp_strcpy(network_group, "MSHOME");

	rtp_printf("Enter server name or press return for the default : ");
	SRVPROMPT (network_name, 0);
	rtp_printf("Enter group name or press return for the default : ");
	SRVPROMPT (network_group, 0);
	rtp_printf("\n");

	rtsmb_srv_enable (network_name, network_group);
	return (0);
}//smbserver_serverenable

static int smbserver_runtimecommand(void)
{
	char which_command[32];
	char which_name[32];

	for (;;)
	{
		rtp_printf("\nPress 'S' to add a file share.\n");
		rtp_printf("Press 's' to remove a file share or a print share.\n");
		rtp_printf("Press 'M' to modify a file share.\n");
		rtp_printf("***********************\n");
		rtp_printf("Press 'P' to add a printer.\n");
		rtp_printf("Press 'p' to modify printer name\n");
		rtp_printf("***********************\n");
		if (security_mode == AUTH_USER_MODE)
		{
			rtp_printf("Press 'U' to add an user.\n");
			rtp_printf("Press 'u' to remove an user.\n");
			rtp_printf("Press 'm' to modify an user.\n");
			rtp_printf("***********************\n");
		}
		rtp_printf("\nPress 'D' to disable the server\n");
		rtp_printf("Press 'q' to quit.\n");
		rtp_printf("\nCommand : ");
		rtp_strcpy(which_command, "");
		SRVPROMPT (which_command, 0);

		switch (which_command[0])
		{
		case 'P':
			{
				smbserver_runtimeaddprinter();
				return(0);
				break;
			}
		case 'p':
			{
				smbserver_runtimemodifyprinter();
				return(0);
				break;
			}
		case 'U':
			{
				smbserver_runtimeadduser();
				return(0);
				break;
			}
		case 'u':
			{
				if (security_mode == AUTH_USER_MODE)
				{
					rtp_strcpy(which_name, "user");
					rtp_printf("User to remove  : ");
					SRVPROMPT (which_name, 0);
					if (rtsmb_srv_delete_user(which_name))
						rtp_printf("Removed\n");
					else
						rtp_printf("Failed\n");
				return(0);
					return(0);
				}
				break;
			}
		case 'm':
			{
				smbserver_runtimemodifyuser ();
				return(0);
				break;
			}
		case 'S':
			{
				smbserver_runtimeaddshare();
				return(0);
				break;
			}
		case 's':
			{
				rtp_strcpy(which_name, "share0");
				rtp_printf("Share to remove  : ");
				SRVPROMPT (which_name, 0);
				if (rtsmb_srv_share_remove(which_name) == 0)
					rtp_printf("Removed\n");
				else
					rtp_printf("Failed\n");
				return(0);
				break;
			}
		case 'M':
			{
				smbserver_runtimemodifyshare ();
				return(0);
				break;
			}
		case 'q':
			{
				return(-1);
				break;
			}
		case 'D':
			{
				smbserver_serverdisable ();
				return(0);
				break;
			}
		}
	}
}//smbserver_runtimecommand


static void help_security_mode(void)
{
	rtp_printf("Sorry no help for you . \n");
}//help_security_mode


static int in_bool(char *prompt, char defaultC)
{
	char allow[32];
	allow[0] = defaultC;
	allow[1] = 0;
	rtp_printf("%s", prompt);
	SRVPROMPT (allow, 0);
	if (allow[0] == 'Y' || allow[0] == 'y')
		return(1);
	else
		return(0);
}//in_bool

static void in_ipaddress(byte *pip, byte *pmask_ip)
{
	byte counter;
/******** Not sure this works try on Linux***********/
/*
#ifdef RTSMB_LINUX
	rtp_in_addr_t my_ip = get_my_IP();
	if (my_ip != 0)
	{
		struct rtp_in_addr temp;
		temp.s_addr = my_ip;
		rtp_printf("%s\n", rtp_inet_ntoa(temp));
	}
#endif
*/
/********************/
	for (counter=0;counter<4;counter++)
	{
	char inbuffer[32];
        rtp_itoa(pip[counter], inbuffer, 10);
		rtp_printf("Byte %d IP Address: ",counter);
		SRVPROMPT (inbuffer, 0);
		pip[counter] = (unsigned char)rtp_atoi(inbuffer);
	}
	for (counter=0; counter<4; counter++)
	{
	char inbuffer[32];
        rtp_itoa(pmask_ip[counter], inbuffer, 10);
		rtp_printf("Byte %d IP Mask: ",counter);
		SRVPROMPT (inbuffer, 0);
		pmask_ip[counter] = (unsigned char)rtp_atoi(inbuffer);
	}
	rtp_printf("IP Address: %d.%d.%d.%d\n",pip[0],pip[1],pip[2],pip[3]);
	rtp_printf("IP Mask   : %d.%d.%d.%d\n",pmask_ip[0],pmask_ip[1],pmask_ip[2],pmask_ip[3]);

}//in_ipaddress

static int in_printer(
	char *printerName,
	char *driverName,
	char *tempPath,
	char *prnFile)
{
int have_printer;
	rtp_printf("Note: The demo does not actually print data, it just captures print data to a temporary file.\n\n");

	have_printer = in_bool("Add a printer (y/n) ? ", 'Y');
	rtp_printf("\n");

	if (have_printer)
	{
		rtp_printf("Set up printer. press enter to keep defaults. \n");
		rtp_printf("Printer name : ");
		SRVPROMPT (printerName, 0);
		rtp_printf("Driver name : ");
		SRVPROMPT (driverName, 0);
		rtp_printf("Print Capture Path : ");
		SRVPROMPT (tempPath, 0);
		rtp_printf("Print Capture File : ");
		SRVPROMPT (prnFile, 0);
		rtp_printf("\n");
		return(1);
	}
	return(0);
}//in_printer

static byte in_loginmode(void)
{
	byte security_mode;
	char which_share_mode[32];
	do {
		rtp_strcpy(which_share_mode, "s");
		rtp_printf("press '?' for help or ..\n");
		rtp_printf("Press 's' for share based passwords, 'u' for user passwords: ");
		SRVPROMPT (which_share_mode, 0);
		if (which_share_mode[0] == '?')
			help_security_mode();
	} while (which_share_mode[0] != 's' && which_share_mode[0] != 'u');
	if (which_share_mode[0] == 's')
		security_mode = AUTH_SHARE_MODE;
	else
		security_mode = AUTH_USER_MODE;
	rtp_printf("\n");
	return(security_mode);
}//in_loginmode

static int in_share(byte security_mode, char *shareName,char *sharePath,char *shareDesc,char *sharePass, char *secCode)
{
		rtp_printf("Set up shares press enter to keep defaults. \n");
		rtp_printf("Share name : ");
		SRVPROMPT (shareName, 0);
		if (!shareName[0])
			return(0);
		rtp_printf("Share Path : ");
		SRVPROMPT (sharePath, 0);
		rtp_printf("Share Description : ");
		SRVPROMPT (shareDesc, 0);

		if (security_mode == AUTH_SHARE_MODE)
		{
			rtp_printf("Share Password (leave empty for no passwords): ");
			SRVPROMPT (sharePass, 0);
			rtp_printf("0==READONLY, 1==WRITEONLY, 2==READWRITE, 3==NOACCES, 4==NO SECURITY\n");
			rtp_printf("Share Security 0,1,2,3,4: ");
			SRVPROMPT (secCode, 0);
		 }
		rtp_printf("\n");
		return(1);

}// in_share

static int in_user(char * userName, char *userPass, char *userPerm)
{
	rtp_printf("User Name  : ");
	SRVPROMPT (userName, 0);
	if (userName[0])
	{
		rtp_printf("Password  : ");
		SRVPROMPT (userPass, 0);
		rtsmb_srv_register_user (userName, userPass);
		for(;;)
		{
			rtp_strcpy(userPerm, "rw");
			rtp_printf("Select access rights , 'r'ead or 'rw' read-write  : ");
			SRVPROMPT (userPerm, 0);
			if (rtp_strcmp(userPerm, "rw") == 0)
				break;
			else if (rtp_strcmp(userPerm, "r") == 0)
				break;
		}
		rtp_printf("\n");
		return(1);
	}
	rtp_printf("\n");
	return(0);
}//in_user

static int in_guestaccount(void)
{
	return(in_bool("Allow Guest login (y/n) : ", 'N'));
}//in_guestaccount

static void in_name(char *network_name, char *network_group)
{
	rtp_printf("Enter server name and group name. \n");
	rtp_printf("Note: Change the name if more than one Rtsmb server is running on the network. \n\n");

	rtp_printf("Enter server name or press return for the default : ");
	SRVPROMPT (network_name, 0);
	rtp_printf("Enter group name or press return for the default : ");
	SRVPROMPT (network_group, 0);
	rtp_printf("\n");
}//in_name

static int in_pollforcommands(void)
{
	rtp_printf("Type N or n to disable keyboard polling while the server is executing \n");
	rtp_printf(" If keyboard polling is enabled you may add and remove shares, add and remove users and display statistics\n");
	rtp_printf(" from the console while the server is running.\n");
	rtp_printf(" Note: Linux users should disable keyboard polling if polling appears to interfere with socket IO\n");

	return(in_bool("Poll keyboard for commands (y/n) : ", 'N'));
}//in_pollforcommands



#ifdef __linux
#include <stdio.h>
#include <unistd.h>
#include <string.h> /* for strncpy */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

static int select_linux_interface(unsigned char *pip, unsigned char *pmask_ip)
{
 int fd;
 struct ifreq ifr;
 unsigned char *p;
 char *interface_name = "eth0";

 printf("Getting address and mask for of %s\n", interface_name);

 fd = socket(AF_INET, SOCK_DGRAM, 0);
 if (fd < 0)
 {
   printf("Error opening a socket\n");
   return -1;
 }
 /* I want to get an IPv4 IP address */
 ifr.ifr_addr.sa_family = AF_INET;

 /* I want IP address attached to "eth0" */
 strncpy(ifr.ifr_name, interface_name, IFNAMSIZ-1);

 int r = ioctl(fd, SIOCGIFADDR, &ifr);
 if (r < 0)
 {
ioctl_error:
   printf("Error performing ioctl() on a socket\n");
   close(fd);
   return -1;
 }
 printf("return == %d\n", r);
 p = &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
 printf("ip address: %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
 pip[0]=p[0]; pip[1]=p[1]; pip[2]=p[2]; pip[3]=p[3];

 ioctl(fd, SIOCGIFNETMASK, &ifr);
 if (r < 0)
  goto ioctl_error;
 p = &((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
 printf("mask:%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr));
 pmask_ip[0]=p[0]; pmask_ip[1]=p[1]; pmask_ip[2]=p[2]; pmask_ip[3]=p[3];

 printf("Success: Using device %s\n", interface_name);
 close(fd);
 return 0;
}

#endif
