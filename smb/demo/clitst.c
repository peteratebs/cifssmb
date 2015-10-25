#include "cliapi.h"

#include "conio.h"
//#include "stdio.h"
#include <windows.h>

#if (INCLUDE_RTIP)
#include "config.h"
#else
byte my_ip_address[4]   = {192, 168, 1, 4};  /* local IP address */
byte ip_mask_address[4] = {0xff, 0xff, 0xff, 0};
#endif
#include "smbtst.h"
#include "rtpprint.h"

#define INTERACTIVE  1

// -------------------------------------------------------- //
/* external functions */
void smb_cli_shell(void);

// -------------------------------------------------------- //
/* static functions */

int smb_cli_regression(void);
#if (INCLUDE_RTSMB_SERVER)
int smbservermain(void);
#endif

int test_ez_layer(char * server_name, BBOOL run_forever);
int test_standard_layer(char * server_name, byte * bip, BBOOL run_forever);


// -------------------------------------------------------- //
#if (INTERACTIVE)
static char ServerName  [SMBF_FILENAMESIZE] = NETWORK_NAME;
static char ShareName   [SMBF_FILENAMESIZE] = SHARE_NAME;
static char FileName    [SMBF_FILENAMESIZE] = "xx";
static char NewFileName [SMBF_FILENAMESIZE] = "zz";
static char NewDirName  [SMBF_FILENAMESIZE] = "newdir";
static char UserName    [SMBF_FILENAMESIZE] = "anonymous";
static char Password    [SMBF_FILENAMESIZE] = "xyz";

#else   /* #IF INTERACTIVE */

#define ServerName  NETWORK_NAME       //AVAILABLE CIFS/SMB ServerName ON YOUR NETWORK
#define ShareName   "DAN1"             //ShareName ON THAT ServerName THAT YOU HAVE READ/WRITE ACCESS TO
#define FileName    "test.txt"         //A FileName NAME ON THAT ServerName... DOESN'T NEED TO EXIST
#define NewFileName "test-ren.txt"     //A NEW FileName NAME NOT ON THAT ServerName
#define NewDirName  "rtsmb"            //A NEW DIRECTORY NAME NOT ON THAT ServerName
#define UserName    "dan"              //VALID UserName NAME ON THAT ServerName
#define Password    "ebsebs"           //VALID Password FOR GIVEN UserName

#endif  /* #IF INTERACTIVE */

int server_enum_test_1 (char *server_name);
int test_standard_layer_list_dir(int session_id, char *ShareName);
#ifdef RTSMB_WIN
int socket_init (void);
int smb_cli_test_main (void);
#endif

// -------------------------------------------------------- //
void demo_pause(BBOOL run_forever)
{
char c;

    if (!run_forever)
    {
        rtp_printf("Press Any Key To Continue ...\n");
        while (!kbhit ())
        {       
        }
        c = getch ();
    }
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



// -------------------------------------------------------- 
// ENTRY POINT
// -------------------------------------------------------- 
int smb_cli_test_main (void)
{
    int     r;
    int     c;

    do
    {
        // ------------------------------------------------ 
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

        // ------------------------------------------------ 
        rtp_printf("\n\nRun Shell(Y/y) or Regression Test(N/n) or quit(Q/q)");
        while (!kbhit ())
        {       
        }
        c = getch ();
        if (c == 'Y' || c == 'y')
        {
            smb_cli_shell();
        }
    
        if (c == 'N' || c == 'n')
        {
            smb_cli_regression();
        }
    } while (c != 'q' && c != 'Q');

	return(1);
}

// -------------------------------------------------------------- 
int smb_cli_regression(void)
{
    byte bip[4];
    int     c, r;
    BBOOL   run_forever;
    char    server_name[40];
    int     cnt = 1;

    // ---------------------------------------------------- 
    /* create net-broadcast address */
    tc_mv4(bip, my_ip_address, 4);
    bip[3] = 0xff;  // spr - was 4

    do
    {
        rtp_printf("\nGet Server Name %d\n", cnt);
        server_enum_test_1(server_name);
        cnt++;
    } while (rtp_strlen(server_name) == 0);

    // ---------------------------------------------------- 
    rtsmb_cli_init (my_ip_address, ip_mask_address);   

    // ---------------------------------------------------- 
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

        // ------------------------------------------------ 
        c = 'y';  /* default to not ez layer - might want to modify - tbd */
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
            // -------------------------------------------- 
            r = test_ez_layer(server_name, run_forever);
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
            // -------------------------------------------- 
            r = test_standard_layer(server_name, bip, run_forever);
            if (r < 0)
            {
                rtp_printf("STANDARD LAYER TEST FAILED\n");
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

// -------------------------------------------------------------- 
//                                                                
//                    TESTING OF EZ API LAYER                     
//                          ENUMERATION                           
//                                                                
// -------------------------------------------------------------- 

int test_ez_layer(char * server_name, BBOOL run_forever)
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


    // -------------------------------------------------------------- 
    //                          ENUMERATION                           
    // -------------------------------------------------------------- 
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
    
    // ---------------------------------------------------- 
    // Do a search for ShareNames on \\<ServerName> where ServerName is 
    // defined to be a known CIFS/SMB ServerName on network     
    // ---------------------------------------------------- 
    rtp_printf("enumerate ShareNames on ServerName\n");

    demo_pause(run_forever);

    rtp_strcpy(ServerName, server_name);

#if (INTERACTIVE) 
    if (!run_forever)
    {
        rtp_printf ("Enter Server Name:");
        rtp_term_promptstring (ServerName, 0);
    }
#endif
        
    num_found = 0;
#if (INTERACTIVE) 
    /* set srvAlone to zero */
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

    // ---------------------------------------------------- 
    // Do a search for FileNames on \\<ServerName>\<ShareName> where    
    // ServerName is defined to be a known CIFS/SMB ServerName on   
    // network and ShareName is a known CIFS/SMB ShareName on that  
    // ServerName                                               
    // ---------------------------------------------------- 
    rtp_printf("enumerate FileNames on ShareName %s\n", ShareName);
        
    num_found = 0;
#if (INTERACTIVE)
    rtp_strcpy(ShareName, SHARE_NAME);
    if (!run_forever)
    {
        rtp_printf ("Enter Share Name:");
        rtp_term_promptstring (ShareName, 0);
    }
        
    /* set srvShare to zero */
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

    // -------------------------------------------------------------- 
    //                                                                
    //                    TESTING OF EZ API LAYER                     
    //                          FileName I/O                          
    //                                                                
    // -------------------------------------------------------------- 
    
    
    // ---------------------------------------------------- 
    //                Open \\ServerName\ShareName\FileName  
    // ---------------------------------------------------- 

#if (INTERACTIVE)
    if (!run_forever)
    {
        rtp_printf("Enter Filename:");
        rtp_term_gets(FileName);
    }
    
    /* set srvShareName to zero */
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

    demo_pause(run_forever);

    rtp_printf ("\n");

    // ---------------------------------------------------- 
    //             Read current contents of FileName        
    // ---------------------------------------------------- 

    r = (int) rtsmb_cli_ez_seek (fid, 0, RTSMB_SEEK_SET);
    if (r < 0)
    {
        rtp_printf("ez seek failed\n");
    }   

    //CLEAR DATA BUFFER
    rtp_memset(data,'\0', 100);
    r = rtsmb_cli_ez_read (fid, (PFBYTE)data, 100);
    if ( r < 0)
    {
        rtp_printf("ez read test failed! error = %d\n", r);
        return -1;
    }
        rtp_printf("ez read successful!\n");    

    demo_pause(run_forever);

    rtp_printf ("\n");

    // ----------------------------------------------------
    //                   Write data to FileName            
    // ----------------------------------------------------  

    //CLEAR DATA BUFFER
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

    demo_pause(run_forever);

    rtp_printf ("\n");

    // ----------------------------------------------------
    //                 Truncate data in FileName           
    // ----------------------------------------------------  

    // CLEAR DATA BUFFER
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

    demo_pause(run_forever);

    rtp_printf ("\n");

    // ---------------------------------------------------- 
    //                       Close FileName                 
    // ---------------------------------------------------- 
    r = rtsmb_cli_ez_close (fid);
    if ( r < 0)
    {
        rtp_printf("ez close failed!\n");
        return -1;
    }
    rtp_printf("\nez close succeeded!\n");

    rtp_printf ("\n");

#if (0)
    // ----------------------------------------------------
    //                     close session                   
    // ----------------------------------------------------
    rtp_printf (("Closing session\n"));
    rtsmb_cli_session_close_session (session_id);

    rtp_printf ("\n");
#endif

    return 0;
}

// -------------------------------------------------------------- 
//                                                                
//                    TESTING OF STANDARD API LAYER                     
//                                                                
// -------------------------------------------------------------- 
int test_standard_layer(char * server_name, byte * bip, BBOOL run_forever)
{
    int bytes_read;
    int fid;
    int session_id;
    int r;
    char data[100];
    RTSMB_CLI_SESSION_DSTAT dstat;
    RTSMB_CLI_SESSION_FSTAT fstat;


    // ---------------------------------------------------- 
    //                   create new session                 
    // ----------------------------------------------------  
    if (rtp_strlen(server_name) < 0)
    {
        rtp_printf ("OOPS: server name 0 len => failure");
        return(-1);
    }

    rtp_strcpy(ServerName, server_name);
    if (!run_forever)
    {
        rtp_printf ("Enter Server Name:");
        rtp_term_promptstring (ServerName, 0);

    }

#ifdef SUPPORT_SMB2
    r = rtsmb_cli_session_new_with_name (ServerName, TRUE, bip, &session_id, CSSN_DIALECT_SMB2_2002); /* SPR - dialect */
#else
    r = rtsmb_cli_session_new_with_name (ServerName, TRUE, bip, &session_id, CSSN_DIALECT_NT);  
#endif
    if (r < 0)
    {
        rtp_printf("Creating new blocking session failed\n");
        return -1;
    }
    else
    {
        rtp_printf("Creating new blocking session successful, session ID = %i\n", session_id);
    }

    rtp_printf ("\n");
    
    // ----------------------------------------------------
    //                logon UserName to session                 
    // ----------------------------------------------------  
    if (!run_forever)
    {
        rtp_printf("Enter UserName:");
        rtp_term_promptstring (UserName, 0);
        rtp_printf("Enter Password:");
        rtp_term_promptstring (Password, 0);
    }

    r = rtsmb_cli_session_logon_user (session_id, UserName, Password, "Domain");
    if (r < 0)
    {
        rtp_printf("logon of UserName %s with Password %s failed!\n", UserName, Password);
        return -1;
    }
    else
    {
        rtp_printf("logon of UserName %s with Password %s successful!\n", UserName, Password);  
    }

    rtp_strcpy(ShareName, SHARE_NAME);
    if (!run_forever)
    {
        rtp_printf ("Enter Share Name:");
        rtp_term_promptstring (ShareName, 0);
    }

    r = rtsmb_cli_session_connect_share (session_id, ShareName, NULL);
    if (r < 0)
    {
        rtp_printf("connecting to ShareName %s failed!\n", ShareName);
        return -1;
    }
    else
    {
        rtp_printf("connecting to ShareName %s successful!\n", ShareName);
    }

    rtp_printf ("\n");

    // ----------------------------------------------------
    //                    open a FileName                     
    // ----------------------------------------------------  
    if (!run_forever)
    {
        rtp_printf("Enter Filename:");
        rtp_term_gets(FileName);
    }

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

    // ----------------------------------------------------
    //                   read from FileName                     //
    // ----------------------------------------------------

    r = rtsmb_cli_session_read (session_id, fid, (PFBYTE)data, 100, &bytes_read);
    if (r < 0)
    {
        rtp_printf("reading from FileName %s failed!\n", FileName);
        return -1;
    }
    else
    {
        rtp_printf("reading from FileName %s successful!\n", FileName); 
    }

    rtp_printf ("\n");

    // ----------------------------------------------------
    //              seek to beginning of FileName               //
    // ----------------------------------------------------
    r = rtsmb_cli_session_seek (session_id, fid, 0, RTSMB_SEEK_SET, NULL);
    if (r < 0)
    {
        rtp_printf("seeking to beginning of FileName %s failed!\n", FileName);
        return -1;
    }
    else
    {
        rtp_printf("seeking to beginning of FileName %s successful!\n", FileName);  
    }

    // ----------------------------------------------------
    //                 write 20 bytes to FileName               //
    // ----------------------------------------------------
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

    // ----------------------------------------------------
    //              truncate FileName to 5 bytes                //
    // ----------------------------------------------------
    r = rtsmb_cli_session_truncate (session_id, fid, 5);
    if (r < 0)
    {
        rtp_printf("truncating FileName %s failed!\n", FileName);
        return -1;
    }
    rtsmb_cli_session_seek (session_id, fid, 0, RTSMB_SEEK_SET, NULL);
    rtsmb_cli_session_read (session_id, fid, (PFBYTE )data, 100, &bytes_read);
    if (bytes_read != 5)
    {
        rtp_printf("truncate did not work properly\n");
        return -1;
    }
    else
    {
        rtp_printf("truncate worked successfully!\n");
    }

    // ----------------------------------------------------
    //                     close a FileName                     //
    // ----------------------------------------------------
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

    demo_pause(run_forever);

    // ----------------------------------------------------
    //                    rename FileName                       //
    // ----------------------------------------------------
    if (!run_forever)
    {
        rtp_printf("Enter New File Name for renaming:");
        rtp_term_gets(NewFileName);
    }

    r = rtsmb_cli_session_rename (session_id, ShareName, FileName, NewFileName); 

    if (r < 0)
    {
        rtp_printf("renaming of FileName %s to %s failed!\n", FileName, NewFileName);
        return -1;
    }
    else
    {
        rtp_printf("renaming of FileName %s to %s successful!\n", FileName, NewFileName);   
    }
    
    rtp_printf ("\n");

    demo_pause(run_forever);

        
    // ----------------------------------------------------
    //                rename FileName back to original          //
    // ----------------------------------------------------
    r = rtsmb_cli_session_rename (session_id, ShareName, NewFileName, FileName);
    if (r < 0)
    {
        rtp_printf("renaming of FileName %s to %s failed!\n", NewFileName, FileName);
        return -1;
    }
    else
    {
        rtp_printf("renaming of FileName %s to %s successful!\n", NewFileName, FileName);   
    }

    rtp_printf ("\n");

    demo_pause(run_forever);

    // ----------------------------------------------------
    //                        stat FileName                     //
    // ----------------------------------------------------
    r = rtsmb_cli_session_stat (session_id, ShareName , FileName , &fstat); 
    if (r < 0)
    {
        rtp_printf("statting FileName %s failed!\n", FileName);
        return -1;
    }
    rtp_printf("%s has size: %i and attributes %i\n", FileName, fstat.fsize, fstat.fattributes);
    
    rtp_printf ("\n");

    // ----------------------------------------------------
    //                list all FileNames on ShareName               
    // ----------------------------------------------------
    if (test_standard_layer_list_dir(session_id, ShareName) < 0)
    {
        return(-1);
    }

    rtp_printf ("\n");

    demo_pause(run_forever);

    // ----------------------------------------------------
    //                    delete FileName                       //
    // ----------------------------------------------------
    r = rtsmb_cli_session_delete (session_id, ShareName, FileName);
    if (r < 0)
    {
        rtp_printf("deleting of FileName %s failed!\n", FileName);
        return -1;
    }
    else
    {
        rtp_printf("deleting of FileName %s  successful!\n", FileName); 
    }
    
    rtp_printf ("\n");

    // ----------------------------------------------------
    //                    make directory                    //
    // ----------------------------------------------------
    if (!run_forever)
    {
        rtp_printf("Enter New Directory: ");
        rtp_term_gets(NewDirName);
    }

    r = rtsmb_cli_session_mkdir (session_id, ShareName, NewDirName); 
    if (r < 0)
    {
        rtp_printf("making directory %s failed!\n", NewDirName);
        return -1;
    }
    else
    {
        rtp_printf("making directory %s  successful!\n", NewDirName);   
    }

    rtp_printf ("\n");

    // ----------------------------------------------------
    //                    remove directory                  //
    // ----------------------------------------------------
    r = rtsmb_cli_session_rmdir (session_id, ShareName, NewDirName); 
    if (r < 0)
    {
        rtp_printf("removing directory %s failed!\n", NewDirName);
        return -1;
    }
    else
    {
        rtp_printf("removing directory %s  successful!\n", NewDirName); 
    }

    rtp_printf ("\n");

    demo_pause(run_forever);
    
    // ----------------------------------------------------
    //                list all FileNames on ShareName               
    // ----------------------------------------------------
    if (test_standard_layer_list_dir(session_id, ShareName) < 0)
    {
        return(-1);
    }

    rtp_printf ("\n");

    demo_pause(run_forever);
    
    // ----------------------------------------------------
    //                  disconnect from  ShareName              //
    // ----------------------------------------------------
    rtp_printf("disconnecting from ShareName: %s\n", ShareName);
    r = rtsmb_cli_session_disconnect_share(session_id, ShareName);
    if (r < 0)
    {
        rtp_printf("disconnecting to ShareName %s failed!\n", ShareName);
        return -1;
    }
    else
    {
        rtp_printf("ShareName disconnect successful!\n");   
    }

    rtp_printf ("\n");

    // ----------------------------------------------------
    //                  disconnect from  ShareName              //
    // ----------------------------------------------------
    rtp_printf("logging off UserName %s\n", UserName);
    r = rtsmb_cli_session_logoff_user (session_id);
    if (r < 0)
    {
        rtp_printf("logging off UserName failed!\n");
        return -1;
    }
    else
    {
        rtp_printf("logging off UserName successful!\n");   
    }

    rtp_printf ("\n");

    // ----------------------------------------------------
    //                     close session                   
    // ----------------------------------------------------
    rtp_printf (("Closing session\n"));
    rtsmb_cli_session_close_session (session_id);

    rtp_printf ("\n");

    return 0;

}


// --------------------------------------------------------
int server_enum_test_1 (char *server_name)
{
  RTSMB_CLI_SESSION_SRVSTAT srvstat;
  char srvname[16];
  int r;

  rtp_printf("\n");

  server_name[0] = '\0';

  // spr - changed from his_ip_address to my_ip_address otherwise
  // server response tries to send to loopback
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
        rtp_printf("In middle of cycling\n");
        //rtp_thread_sleep(2);  /* tbd - shouldn't have to do this here */
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
  return 0;
}

// --------------------------------------------------------
int test_standard_layer_list_dir(int session_id, char *ShareName)
{
    int r;
    RTSMB_CLI_SESSION_DSTAT dstat;

    r = rtsmb_cli_session_find_first (session_id, ShareName, "*.*", &dstat);

    if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
        rtp_printf("NO FILES FOUND\n");
    }
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

    while (r != RTSMB_CLI_SSN_RV_END_OF_SEARCH)
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

    r = rtsmb_cli_session_find_close (session_id, &dstat);
    if (r < 0)
    {
        rtp_printf("find close failed!\n");
        return -1;
    }
    return(0);
}
    
// ------------------------------------//
// initialize your network stack here  //
// ------------------------------------//
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
