/*                                                                                     */
/* CLITST.C - RTSMB Client demo program                                                */
/*                                                                                     */
/* EBS Inc. - RTSMB                                                                    */
/*                                                                                     */
/* Copyright EBS Inc. , 1993                                                           */
/* All rights reserved.                                                                */
/* This code may not be redistributed in source or linkable object form                */
/* without the consent of its author.                                                  */
/*                                                                                     */
/*  Module description:                                                                */
/*      This module contains demo program for RTSMB client.  It runs and               */
/*      interactive client (calling clishell.c) to send command to a SMB server or     */
/*      will run regression test (in this file).  There are 2 regression tests:        */
/*      ez layer API and standard layer API.                                           */
/*      See "how_to_run_client.txt" for more instructions on running the SHELL.        */
/*                                                                                     */
/*      NOTE: the session for SHELL is set up in non-blocking mode so each call        */
/*            needs to wait until job finishes but the regression is is in blocking    */
/*            mode so calls do not need to wait until job finishes.                    */

#include "cliapi.h"    /* SMB client API */
#include "rtpprint.h"  /* RTPlatform */

#include "conio.h"
#include <windows.h>

#include "smbtst.h"

#ifdef RTSMB_RTIP
#include "config.h"
#endif

/* --------------------------------------------------------   */
#define INTERACTIVE     1
#define RUN_FOREVER_EZ  0  /* if run forever, run EZ API layer vs standard API layer */

#define TRY_ENUM_SRV      1
#define TRY_NEW_WITH_NAME 0
#define TRY_NEW_WITH_IP_IF_NAME_FAILS 0
#define TRY_ANONYMOUS     0

/* --------------------------------------------------------   */
#ifndef RTSMB_RTIP
byte my_ip_address[4]   = {192, 168, 1, 4};  /* local IP address */
byte his_ip_address[4]  = {192, 168, 1, 5};  /* remote IP address */
byte ip_mask_address[4] = {0xff, 0xff, 0xff, 0};
#endif

#if (INTERACTIVE)
static char ServerName  [SMBF_FILENAMESIZE] = NETWORK_NAME;
static char ShareName   [SMBF_FILENAMESIZE] = SHARE_NAME;
static char FileName    [SMBF_FILENAMESIZE] = "xx";
static char NewFileName [SMBF_FILENAMESIZE] = "zz";
static char NewDirName  [SMBF_FILENAMESIZE] = "newdir";
#if (1)
static char UserName    [SMBF_FILENAMESIZE] = "user";
static char Password    [SMBF_FILENAMESIZE] = "password";
#else
static char UserName    [SMBF_FILENAMESIZE] = "anonymous";
static char Password    [SMBF_FILENAMESIZE] = "xyz";
#endif

#else   /* #IF INTERACTIVE */

#define ServerName  NETWORK_NAME       /*AVAILABLE CIFS/SMB ServerName ON YOUR NETWORK */
#define ShareName   "DAN1"             /*ShareName ON THAT ServerName THAT YOU HAVE READ/WRITE ACCESS TO */
#define FileName    "test.txt"         /*A FileName NAME ON THAT ServerName... DOESN'T NEED TO EXIST */
#define NewFileName "test-ren.txt"     /*A NEW FileName NAME NOT ON THAT ServerName */
#define NewDirName  "rtsmb"            /*A NEW DIRECTORY NAME NOT ON THAT ServerName */
#define UserName    "dan"              /*VALID UserName NAME ON THAT ServerName */
#define Password    "ebsebs"           /*VALID Password FOR GIVEN UserName */

#endif  /* #IF INTERACTIVE */

int group_num;
int test_num;

/* --------------------------------------------------------   */
/* static functions                                              */

int smb_cli_regression(void);
#if (INCLUDE_RTSMB_SERVER)
int smbservermain(void);
#endif

int test_ez_layer(char * server_name, BBOOL interactive);
int test_standard_layer(char * server_name, byte * bip, BBOOL interactive);

int server_enum_test_1 (char *server_name);
int do_create_file (int session_id, char *ShareName, char *FileName, RTP_BOOL interactive);
int test_standard_layer_list_dir(int session_id, char *ShareName, char *pattern);

#ifdef RTSMB_WIN
int socket_init (void);
int smb_cli_test_main (void);
#endif

/* --------------------------------------------------------   */
void demo_pause(BBOOL interactive)
{
char c;

    if (interactive)
    {
        rtp_printf("Press Any Key To Continue ...\n");
        while (!kbhit ())
        {       
        }
        c = getch ();
    }
}

void smb_display_test_passed(void)
{
    rtp_printf("\nGROUP %d TEST %d PASSED\n", group_num, test_num);
}

void smb_display_test_failed(void)
{
    rtp_printf("\nGROUP %d TEST %d FAILED\n", group_num, test_num);
}

void demo_print_unicode(char * comment, char *unicode_name)
{
    char printable_name[50];
    int   i;

    rtp_printf("%s ", comment);
    for (i=0; unicode_name[i*2] != '\0';i++)
    {
        printable_name[i] = unicode_name[i*2];
    }
    printable_name[i] = '\0';
    rtp_printf("%s\n", printable_name);
}



/* --------------------------------------------------------    */
/* ENTRY POINT                                                 */
/* --------------------------------------------------------    */
int smb_cli_test_main (void)
{
    int     c;

    do
    {
        /* ------------------------------------------------    */
        rtp_printf("\n\nRun Alt Port Numbers(Y/y) or Well-Known(N/n)");
        while (!kbhit ())
        {       
        }
        c = getch ();
        if (c == 'Y' || c == 'y')
        {
            rtsmb_init_port_alt ();
        }
    
        if (c == 'N' || c == 'n')
        {
            rtsmb_init_port_well_know ();
        }

        /* ------------------------------------------------    */
        rtp_printf("\n\nRun Shell(Y/y) or Regression Test(N/n) or quit(Q/q)");
        while (!kbhit ())
        {       
        }
        c = getch ();
        rtp_printf("\n");
        if (c == 'Y' || c == 'y')
        {
            rtp_printf("\n\nRun Shell(Y/y) or File Test(N/n) or quit(Q/q)");
            while (!kbhit ())
            {       
            }
            c = getch ();

            rtp_printf("\n");

            if (c == 'Y' || c == 'y')
            {
                smb_cli_shell();  /* see clishell.c */
            }
            if (c == 'N' || c == 'n')
            {
                do_shell_file_test();  /* see clishell.c */
            }
        }
    
        else if (c == 'N' || c == 'n')
        {
            smb_cli_regression();
        }
    } while (c != 'q' && c != 'Q');

    return(1);
}

/* --------------------------------------------------------------    */
int smb_cli_regression(void)
{
    byte    bip[4];
    int     c, r;
    BBOOL   run_forever, interactive;
    char    server_name[40];
    int     cnt = 1;

    /* ----------------------------------------------------    */
    /* create net-broadcast address                            */
    tc_mv4(bip, my_ip_address, 4);
    bip[3] = 0xff;  

#if (TRY_ENUM_SRV)
    do
    {
        rtp_printf("\nGet Server Name %d\n", cnt);
        server_enum_test_1(server_name);
        cnt++;
    } while (0 /*rtp_strlen(server_name) == 0*/);
#else
    server_name[0] = '\0';
#endif

    if (rtp_strlen(server_name) == 0)
        rtp_strcpy(server_name, NETWORK_NAME);

    /* ----------------------------------------------------    */
    rtsmb_cli_init (my_ip_address, ip_mask_address);   

    /* ----------------------------------------------------    */
    interactive = RTP_FALSE;

    run_forever = FALSE;
    rtp_printf("\n\nRun Forever? (Y/N)\n");
    while (!kbhit ())
    {       
    }
    c = getch ();
    if (c == 'Y' || c == 'y')
    {
        run_forever = RTP_TRUE;
    }

    do
    {

        /* ------------------------------------------------    */
#if (RUN_FOREVER_EZ)
        c = 'y';  /* default to ez layer - might want to modify */
#else
        c = 'n';  /* default to not ez layer - might want to modify */
#endif
        if (!run_forever)
        {
            rtp_printf("test client ez api(Y/y) or Standard layer(N/n)?\n");
            while (!kbhit ())
            {       
            }
            c = getch ();
        }
        if (c == 'Y' || c == 'y')
        {
            /* --------------------------------------------    */
            r = test_ez_layer(server_name, interactive);
            if (r < 0)
            {
                rtp_printf("EZ LAYER TEST FAILED\n");
                return(-1);
            }
            else
            {
                rtp_printf("EZ LAYER TEST SUCCEEDED\n");
            }
            continue;
        }
        else 
        {
            /* --------------------------------------------    */
            r = test_standard_layer(server_name, bip, interactive);
            if (r < 0)
            {

                rtp_printf("STANDARD LAYER TEST FAILED\n");
                smb_display_test_failed();
                return(-1);
            }
        }

        c = 'y';
        if (!run_forever)
        {
            rtp_printf("\n TEST AGAIN? (Y/N) \n");
            while (!kbhit ())
            {       
            }
            c = getch ();
        }
    } while(c == 'Y' || c == 'y');
        
    return 1;
}

/* --------------------------------------------------------------    */
/*                                                                   */
/*                    TESTING OF EZ API LAYER                        */
/*                          ENUMERATION                              */
/*                                                                   */
/* --------------------------------------------------------------    */

int test_ez_layer(char * server_name, BBOOL interactive)
{
    int r, fid;
    char data[100];
    RTSMB_CLI_SESSION_DSTAT dstat;
    int num_found;

#if (INTERACTIVE)
    char srvAlone[SMBF_FILENAMESIZE];
    char srvShare[SMBF_FILENAMESIZE];
    char srvShareFile[SMBF_FILENAMESIZE];
#endif


    /* --------------------------------------------------------------    */
    /*                          ENUMERATION                              */
    /* --------------------------------------------------------------    */
    rtsmb_cli_ez_set_user (UserName, Password, "Domain");  /* tbd - Domain */

    rtp_printf ("Enumerating ServerNames on network\n");
    num_found = 0;
    r = rtsmb_cli_ez_find_first ("\\\\*", &dstat);
    while (r == 1)
    {
        num_found++;
        if (dstat.unicode)
        {
            demo_print_unicode("     ServerName named (unicode): ", dstat.filename);
        }
        else
        {
            rtp_printf ("     ServerName: %s\n", dstat.filename);
        }

        r = rtsmb_cli_ez_find_next (&dstat);
    }

    if (r == 0)
    {
        rtp_printf ("Finished enumeration of ServerNames successfully\n");
        if (!num_found)
        {
            rtp_printf("   although non were found!!!\n");
        }
    }
    else
    {
        rtp_printf ("Failed enumeration of ServerNames: error is %d\n", r);
        return -1;
    }
    rtsmb_cli_ez_find_close (&dstat);

    rtp_printf ("\n");
    
    /* ----------------------------------------------------              */
    /* Do a search for ShareNames on \\<ServerName> where ServerName is  */
    /* defined to be a known CIFS/SMB ServerName on network              */
    /* ----------------------------------------------------              */
    rtp_printf("enumerate ShareNames on ServerName\n");

    demo_pause(interactive);

    rtp_strcpy(ServerName, server_name);

#if (INTERACTIVE) 
    if (interactive)
    {
        rtp_printf ("Enter Server Name:");
        rtp_term_promptstring (ServerName, 0);
    }
#endif
        
    num_found = 0;
#if (INTERACTIVE) 
    /* set srvAlone to zero   */
    rtp_memset(srvAlone,0,sizeof(char)*SMBF_FILENAMESIZE);
    rtp_strcat(srvAlone,"\\\\");
    rtp_strcat(srvAlone,ServerName);
    rtp_strcat(srvAlone,"\\*");
    rtp_printf ("Enumerating ShareNames on ServerName %s\n", srvAlone);

    r = rtsmb_cli_ez_find_first (srvAlone, &dstat);
#else
    r = rtsmb_cli_ez_find_first ("\\\\" ServerName "\\*", &dstat);
#endif
    
    while (r == 1)
    {
        num_found++;
        if (dstat.unicode)
        {
            demo_print_unicode("     ShareName named (unicode): ", dstat.filename);
        }
        else
        {
            rtp_printf ("     ShareName named: %s\n", dstat.filename);
        }

        r = rtsmb_cli_ez_find_next (&dstat);
    }
    if (r == 0)
    {
        rtp_printf ("Finished enumeration of ShareNames on %s successfully\n", ServerName);
        if (!num_found)
        {
            rtp_printf("   although non were found!!!\n");
        }
    }
    else
    {
        rtp_printf ("Failed enumeration of ShareNames on %s\n", ServerName);
        return -1;
    }
    rtsmb_cli_ez_find_close (&dstat);

    rtp_printf ("\n");

    /* ----------------------------------------------------              */
    /* Do a search for FileNames on \\<ServerName>\<ShareName> where     */
    /* ServerName is defined to be a known CIFS/SMB ServerName on        */
    /* network and ShareName is a known CIFS/SMB ShareName on that       */
    /* ServerName                                                        */
    /* ----------------------------------------------------              */
    rtp_printf("enumerate FileNames on ShareName %s\n", ShareName);
        
    num_found = 0;
#if (INTERACTIVE)
    rtp_strcpy(ShareName, SHARE_NAME);
    if (interactive)
    {
        rtp_printf ("Enter Share Name:");
        rtp_term_promptstring (ShareName, 0);
    }
        
    /* set srvShare to zero   */
    rtp_memset(srvShare,0,sizeof(char)*SMBF_FILENAMESIZE);

    rtp_strcat(srvShare,"\\\\");
    rtp_strcat(srvShare,ServerName);
    rtp_strcat(srvShare,"\\");
    rtp_strcat(srvShare,ShareName);
    rtp_strcat(srvShare,"\\*");
    rtp_printf ("Enumerating FileNames on ShareName\n");
    r = rtsmb_cli_ez_find_first(srvShare, &dstat);  

#else   /* #IF INTERACTIVE */
    rtp_printf ("Enumerating FileNames on ShareName\n");
    r = rtsmb_cli_ez_find_first ("\\\\" ServerName "\\" ShareName "\\*", &dstat);
#endif  /* #IF INTERACTIVE */

    while (r == 1)
    {
        num_found++;
        if (dstat.unicode)
        {
            demo_print_unicode("     FileName named (unicode): ", dstat.filename);
        }
        else
        {
            rtp_printf ("     FileName named: %s\n", dstat.filename);
        }

        r = rtsmb_cli_ez_find_next (&dstat);
    }
    if (r == 0)
    {
        rtp_printf ("Finished enumeration of FileNames on %s successfully\n", ShareName);
        if (!num_found)
        {
            rtp_printf("   although non were found!!!\n");
        }
    }
    else
    {
        rtp_printf ("Failed enumeration of FileNames on %s, error = %d\n", ShareName, r);
        return -1;
    }
    rtsmb_cli_ez_find_close (&dstat);

    rtp_printf ("\n");

    /* --------------------------------------------------------------    */
    /*                                                                   */
    /*                    TESTING OF EZ API LAYER                        */
    /*                          FileName I/O                             */
    /*                                                                   */
    /* --------------------------------------------------------------    */
    
    
    /* ----------------------------------------------------    */
    /*                Open \\ServerName\ShareName\FileName     */
    /* ----------------------------------------------------    */

#if (INTERACTIVE)
    if (interactive)
    {
        rtp_printf("Enter Filename:");
        rtp_term_gets(FileName);
    }
    
    /* set srvShareName to zero   */
    rtp_memset(srvShareFile,0,sizeof(char)*SMBF_FILENAMESIZE);
    
    rtp_strcat(srvShareFile,"\\\\");
    rtp_strcat(srvShareFile,ServerName);
    rtp_strcat(srvShareFile,"\\");
    rtp_strcat(srvShareFile,ShareName);
    rtp_strcat(srvShareFile,"\\");
    rtp_strcat(srvShareFile,FileName);

    rtp_printf("Opening %s\n",srvShareFile);
    fid = rtsmb_cli_ez_open (srvShareFile, 
             RTP_FILE_O_TRUNC | RTP_FILE_O_CREAT | RTP_FILE_O_RDWR, 
             RTP_FILE_S_IREAD | RTP_FILE_S_IWRITE);

#else   /* #IF INTERACTIVE */
    rtp_printf("Opening ");
    rtp_printf("\\\\" ServerName "\\" ShareName "\\" FileName);
    rtp_printf("\n");
    fid = rtsmb_cli_ez_open ("\\\\" ServerName "\\" ShareName "\\" FileName, 
              RTP_FILE_O_TRUNC | RTP_FILE_O_CREAT | RTP_FILE_O_RDWR, 
              RTP_FILE_S_IREAD | RTP_FILE_S_IWRITE);
#endif  /* #IF INTERACTIVE */   

    if (fid < 0)
    {
        rtp_printf("ez open of %s failed! error = %d\n", FileName, fid);
        return -1;
    }

    rtp_printf ("ez open succeeded! File %s exists on server if it didn't...\n", FileName);

    demo_pause(interactive);

    rtp_printf("\n");

    /* ----------------------------------------------------    */
    /*             Read current contents of FileName           */
    /* ----------------------------------------------------    */

    r = (int) rtsmb_cli_ez_seek (fid, 0, RTSMB_SEEK_SET);
    if (r < 0)
    {
        rtp_printf("ez seek failed\n");
    }   

    /*CLEAR DATA BUFFER   */
    rtp_memset(data,'\0', 100);
    r = rtsmb_cli_ez_read (fid, (PFBYTE)data, 100);
    if ( r < 0)
    {
        rtp_printf("ez read test failed! error = %d\n", r);
        return -1;
    }
        rtp_printf("ez read successful!\n");    

    demo_pause(interactive);

    rtp_printf ("\n");

    /* ----------------------------------------------------   */
    /*                   Write data to FileName               */
    /* ----------------------------------------------------   */

    /*CLEAR DATA BUFFER   */
    rtp_memset(data,'\0', 100);

    rtp_strcpy (data, "EBS TEST");
    r = rtsmb_cli_ez_write (fid, (PFBYTE) data, 20);
    if ( r < 0)
    {
        rtp_printf("ez write failed!\n");
        return -1;
    }
    
    rtp_memset(data,'\0', 100);
    rtsmb_cli_ez_seek (fid, 0, RTSMB_SEEK_SET);
    r = rtsmb_cli_ez_read (fid, (PFBYTE)data, 100);
    if ( r != 20)
    {
        rtp_printf("ez write failed!");
        return -1;
    }
    rtp_printf("ez write succeeded!\n");

    rtp_printf("Wrote Data ...\n%s\n to file %s\n",data, FileName);

    demo_pause(interactive);

    rtp_printf ("\n");

    /* ----------------------------------------------------   */
    /*                 Truncate data in FileName              */
    /* ----------------------------------------------------   */

    /* CLEAR DATA BUFFER   */
    rtp_memset(data,'\0', 100);

    rtsmb_cli_ez_truncate (fid, 3);
    rtsmb_cli_ez_seek (fid, 0, RTSMB_SEEK_SET);
    r = rtsmb_cli_ez_read (fid, (PFBYTE)data, 100);
    if (r != 3)
    {
        rtp_printf("ez truncate failed!\n");
        return -1;
    }
    rtp_printf("ez truncate succeeded!\n");
    rtp_printf("Truncated %s to 3 bytes ...\n", FileName);

    demo_pause(interactive);

    rtp_printf ("\n");

    /* ----------------------------------------------------    */
    /*                       Close FileName                    */
    /* ----------------------------------------------------    */
    r = rtsmb_cli_ez_close (fid);
    if ( r < 0)
    {
        rtp_printf("ez close failed!\n");
        return -1;
    }
    rtp_printf("\nez close succeeded!\n");

    rtp_printf ("\n");

    /* ----------------------------------------------------   */
    /*                     close session                      */
    /* ----------------------------------------------------   */
    rtp_printf (("Closing session\n"));
    rtsmb_cli_shutdown();

    return 0;
}

/* --------------------------------------------------------------        */
/* CALLS TO SMB CLIENT */
/* --------------------------------------------------------------        */
int clitst_create_new_session(char *ServerName, char *bip)
{
int session_id;
int r;
byte ip_addr[4];
int dialect = CSSN_DIALECT_NT;

#ifdef SUPPORT_SMB2
    dialect = CSSN_DIALECT_SMB2_2002;
#endif

    r = rtsmb_cli_session_resolve_name (ServerName, bip, ip_addr);
rtp_printf("RESULT RESOLVE NAME: IP is %d.%d.%d.%d\n", 
    ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
    if (r < 0)
    {
        rtp_printf("-- Resolving Name: r = %d\n", r);
    }
    tc_mv4(his_ip_address, ip_addr, 4);


#if (TRY_NEW_WITH_NAME)
    r = rtsmb_cli_session_new_with_name (ServerName, TRUE, bip, &session_id, dialect);
    rtp_printf("-- After new_with_name: session_id = %d\n", session_id);

    if (r < 0)
    {
        rtp_printf("-- Creating new blocking session with name failed: session_id = %d; r = %d\n",
            session_id, r);
#if (TRY_NEW_WITH_IP_IF_NAME_FAILS)
        rtp_printf("-- Call new with ip\n");
        r = rtsmb_cli_session_new_with_ip (his_ip_address, NULL, RTP_TRUE, &session_id, dialect);
        if (r < 0)
        {  
            rtp_printf("-- Creating new blocking session with ip failed; r = %d\n", r);
            return -1;
        }
        rtp_printf("-- After new_with_ip: session_id = %d\n", session_id);
#endif
    }
    else
    {
        rtp_printf("-- Creating new blocking session successful, session ID = %i\n", session_id);
    }
#else
    /* just do new with IP */
    rtp_printf("-- Call new with ip\n");
    r = rtsmb_cli_session_new_with_ip (his_ip_address, NULL, RTP_TRUE, &session_id, dialect);
    if (r < 0)
    {  
        rtp_printf("-- Creating new blocking session with ip failed; r = %d\n", r);
        return -1;
    }
    rtp_printf("-- After new_with_ip: session_id = %d\n", session_id);
#endif

    return(session_id);
}

/* --------------------------------------------------------------        */
/*                                                                       */
/*                    TESTING OF STANDARD API LAYER                      */
/*                                                                       */
/* --------------------------------------------------------------        */
int test_standard_layer(char * server_name, byte * bip, BBOOL interactive)
{
    int bytes_read;
    int fid;
    int session_id1, session_id2;
    int r;
    char data[100];
    RTSMB_CLI_SESSION_DSTAT dstat;
    RTSMB_CLI_SESSION_FSTAT fstat;
    char new_file_name[100];
    char new_file_name2[100];
    char new_dir_name[100];

    /* ----------------------------------------------------    */
    /* TEST SETUP */
    /* ----------------------------------------------------    */
    if (rtp_strlen(server_name) < 0)
    {
        rtp_printf ("OOPS: server name 0 len => failure");
        return(-1);
    }

    rtp_strcpy(ServerName, server_name);
    if (interactive)
    {
        rtp_printf ("Enter Server Name:");
        rtp_term_promptstring (ServerName, 0);

    }

#if (TRY_ANONYMOUS)
    /* ----------------------------------------------------    */
    /* GROUP 1                                                 */
    /* ----------------------------------------------------    */
    group_num = 1;

    /* ----------------------------------------------------      */
    /*         logon to anonymous and connect to IPC             */
    /* ----------------------------------------------------      */
    test_num = 1;

    /* negotiate dialect and find out security */
    session_id1 = clitst_create_new_session(ServerName, bip);
    if (session_id1 < 0)
    {
        rtp_printf("CLITST: create session for %s failed with %d\n",
            ServerName, session_id1);
        return(-1);  /* tbd - can continue if don't do anonymouls logon */
    }

    smb_display_test_passed();

    /* ----------------------------------------------------    */
    test_num = 2;

    /* log on as anonymous */
    r = rtsmb_cli_session_logon_user (session_id1, "", "", "Domain");
    if (r < 0)
    {
        rtp_printf("-- logon of Anonymous failed - continue though!\n");
    }
    else
    {
        rtp_printf("-- logon of UserName %s with Password %s successful!\n", UserName, Password);  
    }
                                                                
    /* ----------------------------------------------------    */
    test_num = 3;

    if (session_id1 >= 0 && r == 0)
    {
        /* look at IPC$ */
        r = rtsmb_cli_session_connect_share (session_id1, "IPC$", NULL);
        if (r < 0)
        {                                           
            rtp_printf("connecting to ShareName IPC$ r = %d failed!\n", r);
            rtsmb_cli_session_close_session (session_id1);  /* only do for blocking mode */
            return -1;
        }
        else
        {
            rtp_printf("connecting to ShareName IPC$ successful!\n");
        }
    
        smb_display_test_passed();
    }
        
    rtsmb_cli_session_close_session (session_id1);  /* only do for blocking mode */
#endif /* TRY_ANONYMOUS */

    /* ----------------------------------------------------    */
    /* GROUP 2                                                 */
    /* ----------------------------------------------------    */
    group_num = 2;

    /* ----------------------------------------------------    */
    /*                   create new session                    */
    /* ----------------------------------------------------    */
    test_num = 1;

    session_id1 = clitst_create_new_session(ServerName, bip);
    if (session_id1 < 0)
    {
        rtp_printf("CLITST: create session for %s failed with %d\n",
            ServerName, session_id1);
        return -1;
    }

    smb_display_test_passed();

    /* ----------------------------------------------------      */
    /*                logon UserName to session                  */
    /* ----------------------------------------------------      */
    test_num = 2;

    if (interactive)
    {
        rtp_printf("Enter UserName:");
        rtp_term_promptstring (UserName, 0);
        rtp_printf("Enter Password:");
        rtp_term_promptstring (Password, 0);
    }

    rtp_printf("before logon: session_id = %d\n", session_id1);

    r = rtsmb_cli_session_logon_user (session_id1, UserName, Password, "Domain");
    if (r < 0)
    {
        rtp_printf("-- logon of UserName %s with Password %s error %d failed!\n", UserName, Password, r);
        rtsmb_cli_session_close_session (session_id1);  /* only do for blocking mode */
        return -1;
    }
    else
    {
        rtp_printf("-- logon of UserName %s with Password %s successful!\n", UserName, Password);  
    }
                                                            
#if (0)                                       
    /* ----------------------------------------------------      */
    /*                create another session and logon           */
    /* ----------------------------------------------------      */
    rtp_printf("-- Call new with ip again\n");
    session_id2 = clitst_create_new_session(ServerName, bip);
    if (session_id2 < 0)
    {
        rtp_printf("CLITST: create session for %s failed with %d\n",
            ServerName, session_id2);
    }
    rtp_printf("-- After new_with_ip: session_id2 = %d\n", session_id2);

    r = rtsmb_cli_session_logon_user (session_id2, "user1", "password1", "Domain");
    if (r < 0)
    {
        rtp_printf("-- logon of UserName u1 with Password p1 failed!\n", UserName, Password);
    }
    else
    {
        rtp_printf("-- logon of UserName %s with Password %s successful!\n", UserName, Password);  
    }
#endif                                                      

    smb_display_test_passed();

    /* ----------------------------------------------------    */
    test_num = 3;

    rtp_strcpy(ShareName, SHARE_NAME);
    if (interactive)
    {
        rtp_printf ("Enter Share Name:");
        rtp_term_promptstring (ShareName, 0);
    }

    r = rtsmb_cli_session_connect_share (session_id1, ShareName, NULL);
    if (r < 0)
    {                                           
        rtp_printf("connecting to ShareName %s r = %d failed!\n", ShareName, r);
        rtsmb_cli_session_close_session (session_id1);  /* only do for blocking mode */
        return -1;
    }
    else
    {
        rtp_printf("connecting to ShareName %s successful!\n", ShareName);
    }

    smb_display_test_passed();

    /* ----------------------------------------------------    */
    /*                    open a FileName                      */
    /* ----------------------------------------------------    */
    test_num = 4;

    if (interactive)
    {
        rtp_printf("Enter Filename:");
        rtp_term_gets(FileName);
    }

    r = rtsmb_cli_session_open (session_id1, ShareName, FileName, RTP_FILE_O_CREAT | RTP_FILE_O_RDWR, RTP_FILE_S_IWRITE | RTP_FILE_S_IREAD, &fid);
    if (r < 0)
    {
        rtp_printf("opening of FileName %s failed!\n", FileName);
        rtsmb_cli_session_close_session (session_id1);  /* only do for blocking mode */
        return -1;
    }
    else
    {
        rtp_printf("opening of FileName %s successful!\n", FileName);   
    }

    smb_display_test_passed();

    /* ----------------------------------------------------      */
    /*                   read from FileName                      */
    /* ----------------------------------------------------      */
    test_num = 5;

    r = rtsmb_cli_session_read (session_id1, fid, (PFBYTE)data, 100, &bytes_read);
    if (r < 0)
    {
        rtp_printf("reading from FileName %s failed!\n", FileName);
        rtsmb_cli_session_close_session (session_id1);  /* only do for blocking mode */
        return -1;
    }
    else
    {
        rtp_printf("reading from FileName %s successful!\n", FileName); 
    }

    smb_display_test_passed();

    /* ----------------------------------------------------      */
    /*              seek to beginning of FileName                */
    /* ----------------------------------------------------      */
    test_num = 6;

    r = rtsmb_cli_session_seek (session_id1, fid, 0, RTSMB_SEEK_SET, NULL);
    if (r < 0)
    {
        rtp_printf("seeking to beginning of FileName %s failed!\n", FileName);
        rtsmb_cli_session_close_session (session_id1);  /* only do for blocking mode */
        return -1;
    }
    else
    {
        rtp_printf("seeking to beginning of FileName %s successful!\n", FileName);  
    }

    /* ----------------------------------------------------      */
    /*                 write 20 bytes to FileName                */
    /* ----------------------------------------------------      */
    test_num = 7;

    r = rtsmb_cli_session_write (session_id1, fid, (PFBYTE)"BBBBBBBBBBBBBBBBBBBB", 20, NULL);
    if (r < 0)
    {
        rtp_printf("writing to FileName %s failed!\n", FileName);
        rtsmb_cli_session_close_session (session_id1);  /* only do for blocking mode */
        return -1;
    }
    else
    {
        rtp_printf("writing to FileName %s successful!\n", FileName);   
    }

    smb_display_test_passed();

    /* ----------------------------------------------------      */
    /*              truncate FileName to 5 bytes                 */
    /* ----------------------------------------------------      */
    test_num = 8;

    r = rtsmb_cli_session_truncate (session_id1, fid, 5);
    if (r < 0)
    {
        rtp_printf("truncating FileName %s failed!\n", FileName);
        rtsmb_cli_session_close_session (session_id1);  /* only do for blocking mode */
        return -1;
    }
    rtsmb_cli_session_seek (session_id1, fid, 0, RTSMB_SEEK_SET, NULL);
    rtsmb_cli_session_read (session_id1, fid, (PFBYTE )data, 100, &bytes_read);
    if (bytes_read != 5)
    {
        rtp_printf("truncate did not work properly\n");
        rtsmb_cli_session_close_session (session_id1);  /* only do for blocking mode */
        return -1;
    }
    else
    {
        rtp_printf("truncate worked successfully!\n");
    }

    smb_display_test_passed();

    /* ----------------------------------------------------      */
    /*                     close a FileName                      */
    /* ----------------------------------------------------      */
    test_num = 9;

    r = rtsmb_cli_session_close (session_id1, fid);
    if (r < 0)
    {
        rtp_printf("closing of FileName %s failed!\n", FileName);
        return -1;
    }
    else
    {
        rtp_printf("closing of FileName %s successful!\n", FileName);   
    }

    demo_pause(interactive);

    smb_display_test_passed();

    /* ----------------------------------------------------      */
    /*                    rename FileName                        */
    /* ----------------------------------------------------      */
    test_num = 10;

    if (interactive)
    {
        rtp_printf("Enter New File Name for renaming:");
        rtp_term_gets(NewFileName);
    }

    r = rtsmb_cli_session_rename (session_id1, ShareName, FileName, NewFileName); 

    if (r < 0)
    {
        rtp_printf("renaming of FileName %s to %s failed!\n", FileName, NewFileName);
        return -1;
    }
    else
    {
        rtp_printf("renaming of FileName %s to %s successful!\n", FileName, NewFileName);   
    }
    
    demo_pause(interactive);

    smb_display_test_passed();
        
    /* ----------------------------------------------------      */
    /*                rename FileName back to original           */
    /* ----------------------------------------------------      */
    test_num = 11;

    r = rtsmb_cli_session_rename (session_id1, ShareName, NewFileName, FileName);
    if (r < 0)
    {
        rtp_printf("renaming of FileName %s to %s failed!\n", NewFileName, FileName);
        return -1;
    }
    else
    {
        rtp_printf("renaming of FileName %s to %s successful!\n", NewFileName, FileName);   
    }

    smb_display_test_passed();

    demo_pause(interactive);

    /* ----------------------------------------------------      */
    /*                        stat FileName                      */
    /* ----------------------------------------------------      */
    test_num = 12;

    r = rtsmb_cli_session_stat (session_id1, ShareName, FileName, &fstat); 
    if (r < 0)
    {
        rtp_printf("statting FileName %s failed!\n", FileName);
        return -1;
    }
    rtp_printf("%s has size: %i and attributes %i\n", FileName, fstat.fsize, fstat.fattributes);
    
    smb_display_test_passed();

    /* ----------------------------------------------------          */
    /*                list all FileNames on ShareName                */
    /* ----------------------------------------------------          */
    test_num = 13;

    if (test_standard_layer_list_dir(session_id1, ShareName, "*.*") < 0)
    {
        return(-1);
    }

    smb_display_test_passed();

    demo_pause(interactive);

    /* ----------------------------------------------------      */
    /*                    delete FileName                        */
    /* ----------------------------------------------------      */
    test_num = 14;

    r = rtsmb_cli_session_delete (session_id1, ShareName, FileName);
    if (r < 0)
    {
        rtp_printf("deleting of FileName %s failed!\n", FileName);
        return -1;
    }
    else
    {
        rtp_printf("deleting of FileName %s  successful!\n", FileName); 
    }
    
    smb_display_test_passed();

    /* ----------------------------------------------------   */
    /* GROUP 3                                                */
    /* ----------------------------------------------------   */
    group_num = 3;

    /* ----------------------------------------------------   */
    /*                    make directory                      */
    /* ----------------------------------------------------   */
    test_num  = 1;

    if (interactive)
    {
        rtp_printf("Enter New Directory: ");
        rtp_term_gets(NewDirName);
    }

    /* newdir is directory name */
    r = rtsmb_cli_session_mkdir (session_id1, ShareName, NewDirName); 
    if (r < 0)
    {
        rtp_printf("making directory %s failed!\n", NewDirName);
        return -1;
    }
    else
    {
        rtp_printf("making directory %s  successful!\n", NewDirName);   
    }

    smb_display_test_passed();

    /* ----------------------------------------------------         */
    /*        create file in directory                              */
    /* ----------------------------------------------------         */
    test_num  = 2;

    /* newdir\xx */
    rtp_strcpy(new_file_name, NewDirName);
    rtp_strcat(new_file_name, "\\");
    rtp_strcat(new_file_name, "xx");

    /* newdir\yy */
    rtp_strcpy(new_file_name2, NewDirName);
    rtp_strcat(new_file_name2, "\\");
    rtp_strcat(new_file_name2, "yy");

    if (do_create_file (session_id1, ShareName, new_file_name, 
                        interactive) < 0)
    {
        rtp_printf("create file %s failed\n", new_file_name);
    }

    smb_display_test_passed();

    /* ----------------------------------------------------          */
    /*                list all FileNames on ShareName                */
    /* ----------------------------------------------------          */
    test_num = 3;

    rtp_printf("EXPECT to see newdir directory\n");
    if (test_standard_layer_list_dir(session_id1, ShareName, "*.*") < 0)
    {
        return(-1);
    }

    smb_display_test_passed();

    demo_pause(interactive);

    /* ----------------------------------------------------      */
    /*                    rename FileName                        */
    /* ----------------------------------------------------      */
    test_num = 3;

    if (interactive)
    {
        rtp_printf("Enter New File Name for renaming:");
        rtp_term_gets(NewFileName);
    }

    r = rtsmb_cli_session_rename (session_id1, ShareName, new_file_name, 
                                  new_file_name2); 

    if (r < 0)
    {
        rtp_printf("renaming of FileName %s to %s failed!\n", FileName, NewFileName);
        return -1;
    }
    else
    {
        rtp_printf("renaming of FileName %s to %s successful!\n", FileName, NewFileName);   
    }
    
    demo_pause(interactive);

    smb_display_test_passed();
        

    /* ----------------------------------------------------          */
    /*                list all FileNames on ShareName                */
    /* ----------------------------------------------------          */
    test_num  = 4;

    rtp_strcpy(new_dir_name, NewDirName);
    rtp_strcat(new_dir_name, "\\");
    rtp_strcat(new_dir_name, "*");

    rtp_printf("EXPECT to see newdir\\yy file\n");
    if (test_standard_layer_list_dir(session_id1, ShareName, new_dir_name) < 0)
    {
        return(-1);
    }

    smb_display_test_passed();

    demo_pause(interactive);

    /* ----------------------------------------------------      */
    /*                    delete FileName                        */
    /* ----------------------------------------------------      */
    test_num = 5;

    r = rtsmb_cli_session_delete (session_id1, ShareName, new_file_name2);
    if (r < 0)
    {
        rtp_printf("deleting of FileName %s failed!\n", FileName);
        return -1;
    }
    else
    {
        rtp_printf("deleting of FileName %s  successful!\n", FileName); 
    }
    
    smb_display_test_passed();

    /* ----------------------------------------------------   */
    /*                    remove directory                    */
    /* ----------------------------------------------------   */
    test_num = 6;

    r = rtsmb_cli_session_rmdir (session_id1, ShareName, NewDirName); 
    if (r < 0)
    {
        rtp_printf("removing directory %s failed!\n", NewDirName);
        return -1;
    }
    else
    {
        rtp_printf("removing directory %s  successful!\n", NewDirName); 
    }

    smb_display_test_passed();

    demo_pause(interactive);
    
    /* ----------------------------------------------------          */
    /*                list all FileNames on ShareName                */
    /* ----------------------------------------------------          */
    test_num  = 7;

    if (test_standard_layer_list_dir(session_id1, ShareName, "*.*") < 0)
    {
        return(-1);
    }

    smb_display_test_passed();

    demo_pause(interactive);
    
    /* ----------------------------------------------------      */
    /*                  disconnect from  ShareName               */
    /* ----------------------------------------------------      */
    group_num = 4;
    test_num  = 1;

    rtp_printf("disconnecting from ShareName: %s\n", ShareName);
    r = rtsmb_cli_session_disconnect_share(session_id1, ShareName);
    if (r < 0)
    {
        rtp_printf("disconnecting to ShareName %s failed!\n", ShareName);
        return -1;
    }
    else
    {
        rtp_printf("ShareName disconnect successful!\n");   
    }

    smb_display_test_passed();

    /* ----------------------------------------------------      */
    /*                  logoff                                   */
    /* ----------------------------------------------------      */
    rtp_printf("logging off UserName %s\n", UserName);
    r = rtsmb_cli_session_logoff_user (session_id1);
    if (r < 0)
    {
        rtp_printf("logging off UserName failed!\n");
        return -1;
    }
    else
    {
        rtp_printf("logging off UserName successful!\n");   
    }

    smb_display_test_passed();

    /* ----------------------------------------------------   */
    /*                     close session                      */
    /* ----------------------------------------------------   */
    rtp_printf ("Closing session\n");
    rtsmb_cli_session_close_session (session_id1);

    smb_display_test_passed();

    return 0;

}


/* --------------------------------------------------------   */
/* Sets server_name to the first ServerName found             */
int server_enum_test_1 (char *server_name)
{
  RTSMB_CLI_SESSION_SRVSTAT srvstat;
  char srvname[16];
  int r;
  int cnt = 0;

  rtp_printf("\n");

  server_name[0] = '\0';

  rtsmb_cli_init(my_ip_address, ip_mask_address);

  r = rtsmb_cli_session_server_enum_start(&srvstat, NULL, NULL);
  if(r < 0)
  {
    rtp_printf("could not start the enumeration\n");
    return 1;
  }
  do
  {
    do
    {
      r = rtsmb_cli_session_server_enum_cycle(&srvstat, 10);  
      if(r == 0)
      {
        cnt++;
        if (cnt == 300)
        {
            rtp_printf("server_enum_test_1 - In middle of cycling\n");
            cnt = 0;
        }
      }
    }while(r == 0);

    if(r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
      rtp_printf("END OF SEARCH\n");
      break;
    }
    else if(r != RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
    {
       rtp_printf("Error in cycling\n");
       break;
    }
    do
    {
        r = rtsmb_cli_session_server_enum_next_name(&srvstat, srvname);
        if(r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
            rtp_printf("CLIENT TEST: server name is %s\n", srvname);
            rtp_strcpy(server_name, srvname);  /* pass back to caller */
        }
    }while(r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY);

    if(r != RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
        rtp_printf("error getting names\n");
        break;
    }
  }while(1);
  rtsmb_cli_session_server_enum_close(&srvstat);
  rtsmb_cli_shutdown();

  rtp_printf("server_enum_test_1() returns\n");
  return 0;
}

/* --------------------------------------------------------   */
/* DIR                                                        */
/* --------------------------------------------------------   */
int test_standard_layer_list_dir(int session_id, char *ShareName, char *pattern)
{
    int r;
    RTSMB_CLI_SESSION_DSTAT dstat;

    r = rtsmb_cli_session_find_first (session_id, ShareName, pattern, &dstat);

    if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
        rtp_printf("NO FILES FOUND\n");
        return(0);
    }

    rtp_printf("DIRECTORY:\n");

    /* first name   */
    if (r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
    {
        if (dstat.unicode)
        {
            demo_print_unicode("FileName is (unicode): ", dstat.filename);
        }
        else
        {
            rtp_printf ("FileName is: %s\n", dstat.filename);
        }
    }
    else if (r < 0)
    {
        rtp_printf("find first on ShareName %s failed! error is %d\n", 
            ShareName, r);
        return -1;
    }

    /* get second name   */
    r = rtsmb_cli_session_find_next (session_id, &dstat);

    while (r != RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
        if (r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
            if (dstat.unicode)
            {
                demo_print_unicode("FileName is (unicode): ", dstat.filename);
            }
            else
            {
                rtp_printf ("FileName is: %s\n", dstat.filename);
            }
            
            r = rtsmb_cli_session_find_next (session_id, &dstat);
        }
        else
        {
            rtp_printf("DIR - r = %d\n", r);
            break;
        }
    }

    r = rtsmb_cli_session_find_close (session_id, &dstat);
    if (r < 0)
    {
        rtp_printf("find close failed!\n");
        return -1;
    }
    return(0);
}

/* --------------------------------------------------------   */
/* CREATE FILE                                                */
/* --------------------------------------------------------   */
int do_create_file (int session_id, char *ShareName, char *FileName, RTP_BOOL interactive)
{
    int r, fid;

    /* ----------------------------------------------------    */
    /*                    open a FileName                      */
    /* ----------------------------------------------------    */
    r = rtsmb_cli_session_open (session_id, ShareName, FileName, RTP_FILE_O_CREAT | RTP_FILE_O_RDWR, RTP_FILE_S_IWRITE | RTP_FILE_S_IREAD, &fid);
    if (r < 0)
    {
        rtp_printf("opening of FileName %s failed!\n", FileName);
        return -1;
    }
    else
    {
        rtp_printf("opening of FileName %s successful!\n", FileName);   
    }

    rtp_printf ("\n");

    /* ----------------------------------------------------      */
    /*                 write 20 bytes to FileName                */
    /* ----------------------------------------------------      */
    r = rtsmb_cli_session_write (session_id, fid, (PFBYTE)"BBBBBBBBBBBBBBBBBBBB", 20, NULL);
    if (r < 0)
    {
        rtp_printf("writing to FileName %s failed!\n", FileName);
        return -1;
    }
    else
    {
        rtp_printf("writing to FileName %s successful!\n", FileName);   
    }

    /* ----------------------------------------------------      */
    /*                     close a FileName                      */
    /* ----------------------------------------------------      */
    r = rtsmb_cli_session_close (session_id, fid);
    if (r < 0)
    {
        rtp_printf("closing of FileName %s failed!\n", FileName);
        return -1;
    }
    else
    {
        rtp_printf("closing of FileName %s successful!\n", FileName);   
    }

    rtp_printf ("\n");

    demo_pause(interactive);

    return(0);
}
    
/* ------------------------------------  */
/* initialize your network stack here    */
/* ------------------------------------  */
#ifdef RTSMB_WIN
int socket_init ()
{
    #define WINSOCK_VER 0x0101
    int result;
    RTSMB_STATIC struct WSAData wsa_data;

    result = WSAStartup (WINSOCK_VER, &wsa_data);
    
    if (result)
    {
        PRINTF(("init: Winsock start up failed\n"));
        return -1;
    }
    return 0;
}

int socket_shutdown(void)
{
    WSACleanup();
    return 0;
}
#endif
