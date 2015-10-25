#define USE_HTTP_INTERFACE 0


#include "cliapi.h"
#include "smbutil.h"
#include "rtpnet.h"
#include "rtpterm.h"
#include "rtpprint.h"
#include "rtpstr.h"
#include "clirpc.h"
#include "clsrvsvc.h"
#include "rtpscnv.h"
#include "rtpprint.h"
#include "rtpexit.h"
#include "rtpchar.h"
#include "wchar.h"
#if (USE_HTTP_INTERFACE)
#include "httpsrv.h"
#include "htmlutils.h"
#endif

extern int http_advanced_server_demo(void);

#define HISTORY_MODE 1 /* Set to one, to remember parts of Url zero to prompt for all elements of URL */
#define COMMAND_BUFFER_SIZE 80

char shell_buffer[2048];

int wait_on_job(int sid, int job);

static int do_connect_share(int sid, char *sharename);
static char *do_getserver_name(void);
static RTSMB_CLI_SESSION_DIALECT do_get_session_dialect(void);
static int do_setserver_command(void);
static char *do_getuser_name(void);
static int do_setuser_command(void);
static char *do_getpassword(void);
static int do_setpassword_command(void);
static char *do_getdomain_name(void);
static int do_setdomain_command(void);
static char *do_getshare_name(void);
static int do_setshare_command(void);
static int do_net_command(char *command);
static int do_cli_info (void);
static void in_ipaddress(byte *pip, byte *pmask_ip);
unsigned char my_ip[] = {192,168,1,6};
unsigned char my_mask[] = {255, 255, 255, 0};

// ==========
char *enum_cmd = "ENUMSRV";
char *lookup_cmd = "LOOKUPSRV";
char *shares_cmd = "LISTSHARES";
char *ls_cmd = "LS";
char *cat_cmd = "CAT";
char *read_cmd = "READFILE";
char *fill_cmd = "FILLFILE";
char *setserver_cmd    = "SETSERVER";
char *setshare_cmd    = "SETSHARE";
char *setuser_cmd     = "SETUSER";
char *setpassword_cmd = "SETPASSWORD";
//char *cre8_cmd = "CRE8";
char *del_cmd = "DEL";
char *mkdir_cmd = "MKDIR";
char *rmdir_cmd = "RMDIR";
char *loop_cmd = "LOOP";
char *quit_cmd = "QUIT";
char *net_cmd = "NET";
char *logoff_cmd = "LOGOFF";
char *dump_cmd = "SHOWSTATE";

static char *file_cmds[][2] = {
    {"FOPEN", "FOPEN filename {W|T|E}       ((W)rite,(T)runcate,(E)xclusive - select one or more.)"},
    {"FCLOSE","FCLOSE  fd#"},
    {"FAREAD", "FAREAD  fd# #nLines            (-1 lines == read to end) "},
    {"FAWRITE","FAWRITE fd#                    (reads text from stdin and writes to file)"},
    {"FREAD", "FREAD   fd# #nBytes            (-1 == read to end) "},
    {"FWRITE","FWRITE  fd# #nBytes            (Write byte pattern to the current file location)"},
    {"FSEEK", "FSEEK   fd# [S|C|E] #Offset    ( seek (S)et|(C)ur|(E)nd OFFSET )"},
    {"FSTAT", "FSTAT   fd#"},
    {0,0}
 };
static int do_fhandle_open_command(char *command);
static int do_fhandle_close_command(char *command);
static int do_fhandle_aread_command(char *command);
static int do_fhandle_awrite_command(char *command);
static int do_fhandle_read_command(char *command);
static int do_fhandle_write_command(char *command);
static int do_fhandle_seek_command(char *command);
static int do_fhandle_stat_command(char *command);

typedef int (do_file_function_t)(char *p);
static do_file_function_t *file_functions[] =
{
 do_fhandle_open_command,
 do_fhandle_close_command,
 do_fhandle_aread_command,
 do_fhandle_awrite_command,
 do_fhandle_read_command,
 do_fhandle_write_command,
 do_fhandle_seek_command,
 do_fhandle_stat_command
};



static int do_enum_command(void);
static int do_lookup_command(char *nbsname);
static int do_enum_shares_command(void);
static int do_connect_server(int *sid);
static int do_logon_server(int sid);
static int do_prompt_ls_command(int doLoop);
static int do_quit_command(void);
#define DEL_COMMAND   1
#define MKDIR_COMMAND 2
#define RMDIR_COMMAND 3
#define READ_COMMAND 1
#define WRITE_COMMAND 2
#define CAT_COMMAND  3
static int do_file_command(int which_command, char *command);
static int do_dir_command(int which_command, char *command);
static int do_logoff_command(char *command);

static int do_connect_server_worker(int *sid,char *server_name, RTSMB_CLI_SESSION_DIALECT dialect);
static int do_logon_server_worker(int sid,  char *user_name, char *password, char *domain);
static int do_ls_command_worker(int doLoop,int sid, char *sharename,char *pattern,char *jSonBuffer);
static int do_ls_command(char *command);

static int do_loop_command();


#include <stdarg.h>
#define CLI_DEBUG  1
#define CLI_PROMPT 2
#define CLI_ALERT  3

#if (USE_HTTP_INTERFACE)
void HttpConsoleOutPut(char *output);
int HttpConsoleRunning;
#endif

void smb_cli_term_printf(int dbg_lvl, char *fmt, ...)
{
static char buffer[1024];

 va_list argptr=0;
 va_start(argptr,fmt);
 rtp_vsprintf(buffer, fmt, argptr);
 va_end(argptr);
 if (dbg_lvl==CLI_DEBUG)
    rtp_printf("??? %s",buffer);
 else if (dbg_lvl==CLI_ALERT)
    rtp_printf("!!!! %s",buffer);
 else
 {
    rtp_printf("   %s",buffer);
#if (USE_HTTP_INTERFACE)
 if (HttpConsoleRunning)
 {
     rtp_strcat (buffer,"<br>");
     HttpConsoleOutPut(buffer);
 }
#endif
 }
}


static void smbcli_prompt(char *promptstr, char *buffer, int length)
{
//  rtp_term_c
    int i;
    smb_cli_term_printf(CLI_PROMPT,promptstr);
    //gets (buffer);
#if (USE_HTTP_INTERFACE)
    if (HttpConsoleRunning)
    {
        buffer[0]=0;
        while (!buffer[0])
            HttpGetConsoleInPut(buffer);
    }
    else
#endif
        rtp_term_gets(buffer);
     /* strip trailing newline */
        for (i = 0; i < (int)rtp_strlen(buffer); i++)
        {
            if ( buffer[i] == '\n' || buffer[i] == '\r' )
                buffer[i] = '\0';
        }
}
static int exit_shell;


void smb_cli_term_get_command(char *command_buffer)
{
#if (HISTORY_MODE)
    smb_cli_term_printf(CLI_PROMPT,"%s\n","History mode is on you will be prompted for server, login  and  share names");
    smb_cli_term_printf(CLI_PROMPT,"%s\n","When none are stored from previous commands ");
    smb_cli_term_printf(CLI_PROMPT,"%s\n","To overide the history variables use SETSXXXX commands ");
#else
    smb_cli_term_printf(CLI_PROMPT,"%s\n","History mode is off, you will be prompted for server, login  and  share names");
    smb_cli_term_printf(CLI_PROMPT,"%s\n","For each command you execute");
#endif
    smb_cli_term_printf(CLI_PROMPT,"%s\n","                  =======");
    smb_cli_term_printf(CLI_PROMPT,"%s\n"," ");
    smb_cli_term_printf(CLI_PROMPT,"%s\n",enum_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",lookup_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",shares_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",ls_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",cat_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",read_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",fill_cmd);
    //   rtp_term_puts(cre8_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",del_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",mkdir_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n","                  =======");
    smb_cli_term_printf(CLI_PROMPT,"%s\n",rmdir_cmd);
#if (HISTORY_MODE)
    smb_cli_term_printf(CLI_PROMPT,"%s\n",setserver_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",setshare_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",setuser_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",setpassword_cmd);
#endif
    smb_cli_term_printf(CLI_PROMPT,"%s\n","                  =======");
    smb_cli_term_printf(CLI_PROMPT,"%s\n",net_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",logoff_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",dump_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n","                  =======");
    {
        int i;
        for (i =0; file_cmds[i][0]; i++)
            smb_cli_term_printf(CLI_PROMPT,"%s\n",file_cmds[i][1]);
    }
    smb_cli_term_printf(CLI_PROMPT,"%s\n",quit_cmd);

    smbcli_prompt("Type command : ", command_buffer, COMMAND_BUFFER_SIZE);
}



#if (USE_HTTP_INTERFACE)
static void spawn_web_server(void);
#endif

#if (USE_HTTP_INTERFACE)
static int do_cli_web_command(NVPairList *pPairList,char *jSonBuffer, int outbufferLength);
static int do_net_command_web(NVPairList *pPairList,char *jSonBuffer, int outbufferLength);
#endif
static int do_ls_command_web(char *command,char *jSonBuffer, int outbufferLength);
static char *web_cmds[] = {
    "LogOn"        ,
    "LogOff"       ,
    "Use"          ,
    "EnumShares"   ,
    "EnumServers"  ,
    "ClientStats"  ,
    "RefreshLocal" ,
    "RefreshRemote",
    0,
 };
static int do_fhandle_open_command(char *command);
static int do_fhandle_close_command(char *command);
static int do_fhandle_aread_command(char *command);
static int do_fhandle_awrite_command(char *command);
static int do_fhandle_read_command(char *command);
static int do_fhandle_write_command(char *command);
static int do_fhandle_seek_command(char *command);
static int do_fhandle_stat_command(char *command);

#if (USE_HTTP_INTERFACE)
typedef int (do_web_function_t)(NVPairList *pPairList, char *outbuffer, int outbufferLength);
static do_web_function_t *web_functions[] =
{
 do_cli_web_command,
 do_cli_web_command,
 do_cli_web_command,
 do_cli_web_command,
 do_cli_web_command,
 do_cli_web_command,
 do_cli_web_command,
 do_cli_web_command,
};
#endif

#if (USE_HTTP_INTERFACE)
int smb_cli_shell_proc_web(NVPairList *pPairList, char *outbuffer, int outbufferLength)
{
   int i;
   int r=-1;
   NVPair *pCommand,*pMedia;

   rtp_strcpy(outbuffer, "Command Not Found");

   pCommand = HTTP_GetNameValuePairAssociative (pPairList,"command");
   pMedia = HTTP_GetNameValuePairAssociative (pPairList,"media");
   // media (remote|local) and
   if (!pCommand)
   {
       return -1;
   }
   {
       for (i =0; web_cmds[i]; i++)
       {
           if (rtp_strnicmp(pCommand->value, web_cmds[i], rtp_strlen(web_cmds[i])) == 0)
           {
               r = web_functions[i](pPairList,outbuffer, outbufferLength);
               break;
           }
       }
   }
   return r;
}
#endif


static void smb_cli_shell_proc(char *command_buffer);

/* ENTRY POINT */
void smb_cli_shell(void)
{
char command_buffer[COMMAND_BUFFER_SIZE];

    in_ipaddress(my_ip, my_mask);
    smb_cli_term_printf(CLI_PROMPT,"Using IP address %d,%d,%d,%d\n", my_ip[0],my_ip[1],my_ip[2],my_ip[3]);
    smb_cli_term_printf(CLI_PROMPT,"Using IP mask    %d,%d,%d,%d\n", my_mask[0],my_mask[1],my_mask[2],my_mask[3]);

    smbcli_prompt("Type (A cr) to use alternate PORT numbers that don't clash with SMB" , command_buffer, COMMAND_BUFFER_SIZE);
    if (command_buffer[0] == 'A' || command_buffer[0] == 'a')
    {
        smb_cli_term_printf(CLI_PROMPT,"Using alternate PORT numbers (9137 and 9138)\n");
        rtsmb_init_port_alt();
    }
    else
    {
        smb_cli_term_printf(CLI_PROMPT,"Using PORT numbers (137 and 138),SMB/SAMBA should not also be running on this device.\n");
        rtsmb_init_port_well_know();
    }
#if (USE_HTTP_INTERFACE)
    smb_cli_term_printf(CLI_PROMPT,"Calling web server module\n");
    spawn_web_server();
    HttpConsoleRunning=1;
#endif
    while (!exit_shell)
    {
        smb_cli_term_get_command(command_buffer);
        smb_cli_shell_proc(command_buffer);
    }
}

static void smb_cli_shell_proc(char *command_buffer)
{
   int Done=0;

   {
       int i;
       for (i =0; file_cmds[i][0]; i++)
       {
           if (rtp_strnicmp(command_buffer, file_cmds[i][0], rtp_strlen(file_cmds[i][0])) == 0)
           {
               file_functions[i](command_buffer+rtp_strlen(file_cmds[i][0])+1);
               Done=1;
               break;
           }
       }
   }
   if(Done)
       ;
   else if (rtp_strcmp(command_buffer, quit_cmd) == 0)
        do_quit_command();
   else if (rtp_strcmp(command_buffer, enum_cmd) == 0)
    do_enum_command();
   else if (rtp_strcmp(command_buffer, lookup_cmd) == 0)
   {
    smbcli_prompt("Type name to look up : ", command_buffer, COMMAND_BUFFER_SIZE);
    do_lookup_command(command_buffer);
   }
   else if (rtp_strcmp(command_buffer, shares_cmd) == 0)
   {
    do_enum_shares_command();
   }
   else if (rtp_strnicmp(command_buffer, ls_cmd, rtp_strlen(ls_cmd)) == 0)
       do_ls_command(command_buffer+rtp_strlen(ls_cmd)+1);
   else if (rtp_strnicmp(command_buffer, cat_cmd,rtp_strlen(cat_cmd)) == 0)
    do_file_command(CAT_COMMAND,command_buffer+rtp_strlen(cat_cmd)+1);
   else if (rtp_strnicmp(command_buffer, read_cmd,rtp_strlen(read_cmd)) == 0)
    do_file_command(READ_COMMAND,command_buffer+rtp_strlen(read_cmd)+1);
   else if (rtp_strnicmp(command_buffer, fill_cmd,rtp_strlen(fill_cmd)) == 0)
    do_file_command(WRITE_COMMAND,command_buffer+rtp_strlen(fill_cmd)+1);
   else if (rtp_strnicmp(command_buffer, mkdir_cmd,rtp_strlen(mkdir_cmd)) == 0)
    do_dir_command(MKDIR_COMMAND,command_buffer+rtp_strlen(mkdir_cmd)+1);
   else if (rtp_strnicmp(command_buffer, rmdir_cmd,rtp_strlen(rmdir_cmd)) == 0)
    do_dir_command(RMDIR_COMMAND,command_buffer+rtp_strlen(rmdir_cmd)+1);
   else if (rtp_strnicmp(command_buffer, del_cmd,rtp_strlen(del_cmd)) == 0)
    do_dir_command(DEL_COMMAND,command_buffer+rtp_strlen(del_cmd)+1);
   else if (rtp_strnicmp(command_buffer, logoff_cmd,rtp_strlen(logoff_cmd)) == 0)
    do_logoff_command(command_buffer+rtp_strlen(logoff_cmd)+1);
   else if (rtp_strnicmp(command_buffer, net_cmd,3) == 0)
    do_net_command(command_buffer+rtp_strlen(net_cmd)+1);
   else if(rtp_stricmp(command_buffer, dump_cmd) == 0)
       do_cli_info ();
   else if (rtp_strcmp(command_buffer, loop_cmd) == 0)
    do_loop_command();
   else if (rtp_strcmp(command_buffer, setserver_cmd) == 0)
    do_setserver_command();
   else if (rtp_strcmp(command_buffer, setshare_cmd) == 0)
    do_setshare_command();
   else if (rtp_strcmp(command_buffer, setuser_cmd) == 0)
    do_setuser_command();
   else if (rtp_strcmp(command_buffer, setpassword_cmd) == 0)
    do_setpassword_command();
}


static int do_quit_command(void)
{
    smb_cli_term_printf(CLI_PROMPT,"Quitting ...................................");
    exit_shell = 1;
    return 0;
}
#define STRCONSTLENGTH(S) sizeof(S)-1

typedef struct RtsmbCliFile_s {
    int fid;
    int session_fid;
    int session_id;
} RtsmbCliFile;

struct CliShellShare_s {
    int  ConnectionNo;
    char shareString[32];
};
struct CliShellConnection_s {
    int sid;
    RTSMB_CLI_SESSION_DIALECT dialect;
    char server_name[80];
    char userString[80];
    char passwordString[80];
};
#define MAX_FILES  8
#define MAX_SHARES 4
#define MAX_CONNECTIONS 2
struct CliShell_s {
    struct RtsmbCliFile_s ClishellFiles[MAX_FILES];
    struct CliShellConnection_s ClishellConnections[MAX_CONNECTIONS];
    struct CliShellShare_s ClishellShares[MAX_SHARES];
};
static struct CliShell_s Clishell;


static int CmdToFdno(char *command)
{
int v = -1;
    while (rtp_isdigit(*command))
    {
        if (v==-1) v = 0;
        v *= 10;
        v += (int)(*command-'0');
        command++;
    }
    return v;
}
static int CmdToDrvId(char *command)
{
int idNo=-1;
  if (command[1]==':')
  {
      idNo = (int)command[0]-'A';
      if (idNo>25)
          idNo = (int)command[0]-'a';
      if (idNo >= TABLE_SIZE(Clishell.ClishellShares))
      {
          smb_cli_term_printf(CLI_ALERT,"As configured the maximum Drive Id is: %c\n", (char) ('a' + TABLE_SIZE(Clishell.ClishellShares)-1));
          return -1;
      }
  }
  else
        smb_cli_term_printf(CLI_ALERT,"Bad arguments\n");
  return idNo;
}
static int do_net_command(char *command)
{
int doHelp=0;
int idNo = 0;
int ConnectionNo=0;
BBOOL DoOpenConnection=FALSE;
char dialectString[20];
dialectString[0]=0;
    smb_cli_term_printf(CLI_ALERT,"Inside with command == %s\n", command);
//    command += STRCONSTLENGTH("NET ");
    smb_cli_term_printf(CLI_ALERT,"Inside 2 with command == %s STRCONSTLENGTH{\"USE\") == %d\n", command,(int)STRCONSTLENGTH("USE"));

    if (rtp_strnicmp(command,"USE", STRCONSTLENGTH("USE"))==0)
    {
        command += STRCONSTLENGTH("USE");
        smb_cli_term_printf(CLI_ALERT,"Inside 3 with command == %s \n", command);
        if (command[0] == 0)
        {
            /* net use - List all connections */
            smb_cli_term_printf(CLI_ALERT,"%s\n", "List all connections");
        }
        else if (command[0]==' ')
        {
            command++;
            smb_cli_term_printf(CLI_ALERT,"Inside 4 with command == %s \n", command);
            idNo=CmdToDrvId(command);
            if (idNo<0)
                return 0;
            command += 2;
            if (*command != ' ')
                doHelp = 1;
            else
            {
                command++;
                /* Check if /delete */
                if (rtp_strnicmp(command,"/delete", STRCONSTLENGTH("/delete"))==0)
                {
                    if (rtsmb_cli_session_disconnect_share (Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid, Clishell.ClishellShares[idNo].shareString)<0)
                    {
                        smb_cli_term_printf(CLI_ALERT,"Share disconnect failed\n");
                    }
                    else
                        smb_cli_term_printf(CLI_ALERT,"Share Deleted \n");
                    return 0;

                }
                else if (rtp_strnicmp(command,"\\\\", STRCONSTLENGTH("\\\\"))==0)
                {
                    char *nextSpace, *nextSlash;
                    unsigned len;
                    char server_name[80];
                    char userString[80];
                    char passwordString[80];
                    char shareString[80];

                    doHelp = 1; /* Assume it's wrong */

                    /* Parse url strng and optional user and password */

                    command += STRCONSTLENGTH("\\\\");
                    nextSlash=rtp_strstr(command,"\\");
                    nextSpace=rtp_strstr(command," ");

                    // Clishell.ClishellConnections[ConnectionNo].server_name[0]=Clishell.ClishellConnections[ConnectionNo].passwordString[0]=Clishell.ClishellConnections[ConnectionNo].userString[0] = Clishell.ClishellShares[idNo].shareString[0] = 0;
                    server_name[0]=passwordString[0]=userString[0] = shareString[0] = 0;

                    /* set length of the host name */
                    if ((nextSlash && !nextSpace) || nextSpace > nextSlash)
                        len = (unsigned) (nextSlash - command);
                    else if (nextSpace)
                        len = (unsigned) (nextSpace - command);
                    else
                        len = rtp_strlen(command);
                    rtp_memcpy(server_name, command, len);
                    server_name[len]=0;
                    smb_cli_term_printf(CLI_ALERT,"Url:%s \n",server_name);
                    doHelp = 0;
                    command += len;
                    if (command == nextSlash)
                    {
                        command += 1;
                        /* get the share name */
                        if (nextSpace)
                            len = (unsigned) (nextSpace - command);
                        else
                            len = rtp_strlen(command);
                        rtp_memcpy(shareString, command, len);
                        command += len;
                        shareString[len]=0;
                        smb_cli_term_printf(CLI_ALERT,"Share:%s \n",shareString);
                        rtp_strcpy(Clishell.ClishellShares[idNo].shareString, shareString);
                    }
                    if (nextSpace)
                    {
                        /* Now check for user */
                        command = nextSpace+1;
                        if (rtp_strnicmp(command,"/user:", STRCONSTLENGTH("/user:"))==0)
                        {
                            command += STRCONSTLENGTH("/user:");
                            nextSpace=rtp_strstr(command," ");
                            len = nextSpace?(unsigned) (nextSpace - command): rtp_strlen(command);
                            rtp_memcpy(userString, command, len);
                            userString[len]=0;
                            smb_cli_term_printf(CLI_ALERT,"User:%s \n",userString);
                            nextSpace=rtp_strstr(command," ");
                        }
                    }
                    if (nextSpace)
                    {
                        /* Now check for password */
                        command = nextSpace+1;
                        if (rtp_strnicmp(command,"/password:", STRCONSTLENGTH("/password:"))==0)
                        {
                            command += STRCONSTLENGTH("/password:");
                            nextSpace=rtp_strstr(command," ");
                            len = nextSpace?(unsigned) (nextSpace - command): rtp_strlen(command);
                            rtp_memcpy(passwordString, command, len);
                            passwordString[len]=0;
                            smb_cli_term_printf(CLI_ALERT,"Password:%s \n",passwordString);
                            nextSpace=rtp_strstr(command," ");
                        }
                    }
                    if (nextSpace)
                    {
                        /* Now check for dialect */
                        command = nextSpace+1;
                        if (rtp_strnicmp(command,"/dialect:", STRCONSTLENGTH("/dialect:"))==0)
                        {
                            command += STRCONSTLENGTH("/dialect:");
                            nextSpace=rtp_strstr(command," ");
                            len = nextSpace?(unsigned) (nextSpace - command): rtp_strlen(command);
                            rtp_memcpy(dialectString, command, len);
                            dialectString[len]=0;
                            smb_cli_term_printf(CLI_ALERT,"Dialect:%s \n",dialectString);
                            nextSpace=rtp_strstr(command," ");
                        }
                    }
                    /* Test if it's already connected. */
                    if (server_name[0])
                    {
                        int i;
                        int freeConnection=-1;

                        ConnectionNo = -1;
                        for (i =0; i < MAX_CONNECTIONS; i++)
                        {
                            if (Clishell.ClishellConnections[i].server_name[0]==0)
                            {
                                if (freeConnection<0) freeConnection=i;
                            }
                            else if (rtp_strcmp(Clishell.ClishellConnections[i].server_name,server_name)==0)
                            {
                                ConnectionNo = i;
                            }
                        }
                        if (ConnectionNo < 0)
                        {
                            ConnectionNo = freeConnection;
                            rtp_strcpy(Clishell.ClishellConnections[ConnectionNo].server_name,server_name);
                            rtp_strcpy(Clishell.ClishellConnections[ConnectionNo].passwordString,passwordString);
                            rtp_strcpy(Clishell.ClishellConnections[ConnectionNo].userString,userString);
                            DoOpenConnection = TRUE;
                        }
                        if (ConnectionNo < 0)
                        {
                            smb_cli_term_printf(CLI_ALERT,"No connections are available \n");
                            return -1;
                        }

                    }
                }
            }
        }
        else
            doHelp = 1;
    }
    else if (1 || rtp_strnicmp(command,"HELP", 4)==0)
        doHelp = 1;
    if (doHelp)
    {
        smb_cli_term_printf(CLI_PROMPT,"%s\n","net use D: \\\\url [/user:name] [/password:password] [/dialect:{0,1,2}]");
        smb_cli_term_printf(CLI_PROMPT,"%s\n","net use D: (displays info)");
        smb_cli_term_printf(CLI_PROMPT,"%s\n","net use D: /delete (closes connection)");
        smb_cli_term_printf(CLI_PROMPT,"%s\n","net use (lists all connections)");
        smb_cli_term_printf(CLI_PROMPT,"%s\n","net help");
        return 0;
    }

    if (DoOpenConnection)
    {
        //  0==CSSN_DIALECT_PRE_NT, 1==CSSN_DIALECT_NT, 2==CSSN_DIALECT_SMB2_2002:
        //  Fix this later, for now default to /NT dialect
        if (dialectString[0]==0)
            Clishell.ClishellConnections[ConnectionNo].dialect = 1;
        else
            Clishell.ClishellConnections[ConnectionNo].dialect=(int)(dialectString[0]-'0');

        smb_cli_term_printf(CLI_ALERT,"Connecting to %s\n",Clishell.ClishellConnections[ConnectionNo].server_name);
        if (do_connect_server_worker(&Clishell.ClishellConnections[ConnectionNo].sid, Clishell.ClishellConnections[ConnectionNo].server_name, Clishell.ClishellConnections[ConnectionNo].dialect)!=1)
        {
            smb_cli_term_printf(CLI_ALERT,"Failed Connecting to %s\n",Clishell.ClishellConnections[ConnectionNo].server_name);
            return -1;
        }
        smb_cli_term_printf(CLI_ALERT,"Logging on with username: %s password: %s \n",Clishell.ClishellConnections[ConnectionNo].userString,Clishell.ClishellConnections[ConnectionNo].passwordString);
        if (do_logon_server_worker(Clishell.ClishellConnections[ConnectionNo].sid,  Clishell.ClishellConnections[ConnectionNo].userString, Clishell.ClishellConnections[ConnectionNo].passwordString, "Domain") < 0)
        {
            smb_cli_term_printf(CLI_ALERT,"Failed Logging on with username: %s password: %s \n",Clishell.ClishellConnections[ConnectionNo].userString,Clishell.ClishellConnections[ConnectionNo].passwordString);
            return -1;
        }
    }
    else
    {
        smb_cli_term_printf(CLI_ALERT,"Using existing Log on with username: %s password: %s \n",Clishell.ClishellConnections[ConnectionNo].userString,Clishell.ClishellConnections[ConnectionNo].passwordString);
    }
    if (Clishell.ClishellShares[idNo].shareString[0])
    {
        int sh_val=0;

        Clishell.ClishellShares[idNo].ConnectionNo=ConnectionNo;
        smb_cli_term_printf(CLI_ALERT,"Connecting to sharename : %s \n",Clishell.ClishellShares[idNo].shareString);
        while(!sh_val)
        {
            sh_val = do_connect_share(Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid, Clishell.ClishellShares[idNo].shareString);
            if(!sh_val)
            {
                smb_cli_term_printf(CLI_ALERT,"Unknown logon or share. Use SETUSER, SETPASSWORD, SETSHARE for changing values.\n\n");
                return -1;
            }
        }
        smb_cli_term_printf(CLI_ALERT,"Succesfully connected to sharename : %s \n",Clishell.ClishellShares[idNo].shareString);
    }

    return 0;

    /* USE ID \\url:\path /user:name /password:password */
    /* USE ID */
    /* USE ID /delete */
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

static int do_enum_command(void)
{
  RTSMB_CLI_SESSION_SRVSTAT srvstat;
  char srvname[32];
  int r;
  rtsmb_cli_init( my_ip, (PFBYTE)&my_mask[0]);
  r = rtsmb_cli_session_server_enum_start(&srvstat, NULL, NULL);
  if(r < 0)
  {
    smb_cli_term_printf(CLI_ALERT,"\n could not start the enumeration");
    return 1;
  }
  do
  {
    do
    {
      r = rtsmb_cli_session_server_enum_cycle(&srvstat, 10);
      if(r == 0)
      {
//        smb_cli_term_printf(CLI_PROMPT,"\n In middle of cycling");
      }
    }while(r == 0);
    if(r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
      break;
    }
    else if(r != RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
    {
       smb_cli_term_printf(CLI_ALERT,"\n Error in cycling");
       return 1;
    }
    do
    {
        r = rtsmb_cli_session_server_enum_next_name_uc(&srvstat, (PFWCS)&srvname[0]);
        if(r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
          smb_cli_term_printf(CLI_PROMPT,"Unicode [%ls]\n", (wchar_t *) srvname);
        }
        r = rtsmb_cli_session_server_enum_next_name(&srvstat, srvname);
        if(r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
          smb_cli_term_printf(CLI_PROMPT,"[%s]\n", srvname);
        }
    }while(r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY);
    if(r != RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
        smb_cli_term_printf(CLI_ALERT, "Error getting names");
        return 1;
    }
  }while(1);
  rtsmb_cli_session_server_enum_close(&srvstat);
  rtsmb_cli_shutdown();
  return 0;
}

static int do_lookup_command(char *nbsname)
{
    RTSMB_NBNS_NAME_QUERY list[20];
    int argc;
    char *argv[2];
    int i;
    int done = 0;

    rtsmb_cli_init(my_ip, (PFBYTE)&my_mask[0]);
    /* Cahnge to multi format soi we don't have to recode */
    argc = 2;
    argv[0] = "unused";
    argv[1] = nbsname;


    for (i=1; i<argc; i++)
    {
        rtsmb_nbns_query_name(&list[i-1], argv[i]);
    }

    smb_cli_term_printf(CLI_PROMPT,"Resolving NetBIOS names...");
    while (!done)
    {
        smb_cli_term_printf(CLI_PROMPT,".");
        rtsmb_nbns_query_cycle(list, argc-1, 1);
//      rtsmb_nbns_query_cycle(list, argc-1, 1000);

        done = 1;
        for (i=0; i<argc-1; i++)
        {
            RTSMB_NBNS_NAME_INFO info[5];
            int num_addrs;

            switch (list[i].status)
            {
            case RTSMB_NBNS_QUERY_STATUS_RESOLVED:
                smb_cli_term_printf(CLI_PROMPT,"\nHost %s resolved: ", list[i].name);
                num_addrs = rtsmb_nbns_get_name_query_response(&list[i], info, 5);
                for (;num_addrs > 0; num_addrs--)
                {
                    smb_cli_term_printf(CLI_PROMPT,"%d.%d.%d.%d \n",
                            info[num_addrs-1].ip_addr[0],
                            info[num_addrs-1].ip_addr[1],
                            info[num_addrs-1].ip_addr[2],
                            info[num_addrs-1].ip_addr[3]);
                }

            case RTSMB_NBNS_QUERY_STATUS_ERROR:
                rtsmb_nbns_close_query(&list[i]);
                break;

            case RTSMB_NBNS_QUERY_STATUS_TIMEOUT:
                smb_cli_term_printf (CLI_ALERT,"\nQuery: %s timed out \n", list[i].name);
                rtsmb_nbns_close_query(&list[i]);
                break;

            case RTSMB_NBNS_QUERY_STATUS_PENDING:
                done = 0;
                break;
            }
        }
    }

    rtsmb_cli_shutdown();
    return 0;
}

static int do_enum_shares_command(void)
{
    int r, sid;
    RTSMB_CLI_SESSION_SSTAT sstat;

    rtsmb_cli_init(my_ip, (PFBYTE)&my_mask[0]);

    if (!do_connect_server(&sid))
        return(0);
    if (!do_logon_server(sid))
        return(0);

    /* now enumerate the shares on this server */
    r = rtsmb_cli_session_share_find_first(sid, &sstat);
    if (r < 0)
    {
        smb_cli_term_printf (CLI_ALERT,"Share enumeration failed!\n");
        return 1;
    }
    r = wait_on_job(sid, r);
    while (r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
    {
        //char temp[200];
        //rtsmb_util_rtsmb_to_ascii (sstat.name, temp, 0);
        smb_cli_term_printf(CLI_PROMPT,"Found share: %s\n", sstat.name);
        r = rtsmb_cli_session_share_find_next(sid, &sstat);
        if (r != RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
            if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
                break;
            if (r < 0)
            {
                smb_cli_term_printf (CLI_ALERT,"Share enumeration failed!\n");
                return 1;
            }
            r = wait_on_job(sid, r);
        }
    }
    rtsmb_cli_session_share_find_close(sid, &sstat);
    rtsmb_cli_shutdown();
    return(0);
}

static const char *month_names[] =
{
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec"
};

static int do_logoff_command(char *command)
{
    if (*command==0)
    {
        smb_cli_term_printf(CLI_PROMPT,"%s \n", "usage: LOGOFF a:");
        return 0;
    }
    else
    {
        int idNo;
        command++;
        idNo =CmdToDrvId(command);
        if (idNo < 0)
            return 0;
        Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].server_name[0]=0;
        return rtsmb_cli_session_logoff_user(Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid);
    }
}


#if (0)

/* Create a json representation of the data record we are encodng
{
    "HasA429Sample": 1
    "A429Sample": [
        {
            "id": "1",
            "word": "21233"
        },
    "HasDiscreteSample": 1
    "DiscreteSample": [
        {
            "id": "1",
            "open": "1"
        },
    ]
    "HasAnalogSample": 1
    "AnalogSample": [
        {
            "id": "1",
            "value": "1"
        },
    ]
    "has_GMTms": "1",
    "GMTms": "xxxxxxxxx"

{
    "Status":  0
    "FileCount":  0
    "Results": [
    "FileName":   "xxxxx",
    "Attributes": "xxxxx",
    "Size":       "xxxxx",
     ]
}

*/
static int jsonEncodeSampleStreams(char *Jsonbuffer, A429SampleStream_t *pA429iStream, DiscreteSampleStream_t *pDiscreteiStream, AnalogSampleStream_t *pAnalogiStream,bool has_GMTms, uint64_t GMTms)
{
A429Sample_t    *pA429Sample;
DiscreteSample_t  *pDiscreteSample;
AnalogSample_t  *pAnalogSample;
char *jsonUintFmtComma=     "    \"%s\": %u,\n";
char *jsonUintFmt=     "    \"%s\": %u\n";
char *jsonUint64Fmt=   "    \"%s\": %llu,\n";
char *jsonArrayFmt=   "    \"%s\": [\n";
char *jsonA429ItemFmt="    {\n        \"id\": %u,\n        \"word\": %u\n    }%s";
char *jsonDiscreteItemFmt="  {\n        \"id\": %u,\n        \"open\": %d\n    }%s";
char *jsonAnalogItemFmt="  {\n        \"id\": %u,\n        \"value\": %d\n    }%s";
char *ArrayItemEnd=   ",\n";
char *LastArrayItemEnd=   "\n";
char *jsonArrayEnd=   "    ]\n";
int haspA429,hasDiscrete,hasAnalog;
char *pJsonbuffer = Jsonbuffer;
    pA429iStream->ResetFn(pA429iStream);
    haspA429 = (pA429iStream->GetNextFn(pA429iStream)!=0);
    pDiscreteiStream->ResetFn(pDiscreteiStream);
    hasDiscrete = (pDiscreteiStream->GetNextFn(pDiscreteiStream)!=0);
    pAnalogiStream->ResetFn(pAnalogiStream);
    hasAnalog = (pAnalogiStream->GetNextFn(pAnalogiStream)!=0);

    pJsonbuffer += rtp_sprintf(pJsonbuffer, "{\n");

    pJsonbuffer += rtp_sprintf(pJsonbuffer, jsonUintFmtComma, "HasGMTms",  (int)has_GMTms);
    if (has_GMTms)
    {
        pJsonbuffer += rtp_sprintf(pJsonbuffer, jsonUint64Fmt, "GMTms", GMTms);
    }
    pJsonbuffer += rtp_sprintf(pJsonbuffer,jsonUintFmtComma,  "HasA429Sample",  haspA429);
    pA429iStream->ResetFn(pA429iStream);
    if (haspA429)
    {
        pJsonbuffer += rtp_sprintf(pJsonbuffer, jsonArrayFmt,  "A429Sample");
        pA429Sample = pA429iStream->GetNextFn(pA429iStream);
        while (pA429Sample)
        {
            A429Sample_t *NextItem = pA429iStream->GetNextFn(pA429iStream);
            pJsonbuffer += rtp_sprintf(pJsonbuffer, jsonA429ItemFmt, pA429Sample->Port_id, pA429Sample->dataword, NextItem?ArrayItemEnd:LastArrayItemEnd);
            pA429Sample=NextItem;
        }
        pJsonbuffer += rtp_sprintf(pJsonbuffer,"%s", jsonArrayEnd);
        pJsonbuffer += rtp_sprintf(pJsonbuffer, ",\n");
    }

    pJsonbuffer += rtp_sprintf(pJsonbuffer,jsonUintFmtComma,  "HasDiscreteSample",  hasDiscrete);
    pDiscreteiStream->ResetFn(pDiscreteiStream);
    if (hasDiscrete)
    {
        pJsonbuffer += rtp_sprintf(pJsonbuffer, jsonArrayFmt,  "DiscreteSample");
        pDiscreteSample = pDiscreteiStream->GetNextFn(pDiscreteiStream);
        while (pDiscreteSample)
        {
            DiscreteSample_t *NextItem = pDiscreteiStream->GetNextFn(pDiscreteiStream);
            pJsonbuffer += rtp_sprintf(pJsonbuffer, jsonDiscreteItemFmt, pDiscreteSample->Port_id, pDiscreteSample->open, NextItem?ArrayItemEnd:LastArrayItemEnd);
            pDiscreteSample=NextItem;
        }
        pJsonbuffer += rtp_sprintf(pJsonbuffer,"%s", jsonArrayEnd);
        pJsonbuffer += rtp_sprintf(pJsonbuffer, ",\n");
    }

    pJsonbuffer += rtp_sprintf(pJsonbuffer, hasAnalog?jsonUintFmtComma:jsonUintFmt,  "HasAnalogSample",  hasAnalog);
    pAnalogiStream->ResetFn(pAnalogiStream);
    if (hasAnalog)
    {
        pJsonbuffer += rtp_sprintf(pJsonbuffer, jsonArrayFmt,  "AnalogSample");
        pAnalogSample = pAnalogiStream->GetNextFn(pAnalogiStream);
        while (pAnalogSample)
        {
            AnalogSample_t *NextItem = pAnalogiStream->GetNextFn(pAnalogiStream);
            pJsonbuffer += rtp_sprintf(pJsonbuffer, jsonAnalogItemFmt, pAnalogSample->Port_id, pAnalogSample->value, NextItem?ArrayItemEnd:LastArrayItemEnd);
            pAnalogSample=NextItem;
        }
        pJsonbuffer += rtp_sprintf(pJsonbuffer,"%s", jsonArrayEnd);
    }
    pJsonbuffer += rtp_sprintf(pJsonbuffer, "}\n");
    return (int) (pJsonbuffer - Jsonbuffer);
}

//======================================
#endif
static int do_ls_command_worker(int doLoop,int sid, char *sharename,char *pattern,char *jSonBuffer)
{
    RTSMB_CLI_SESSION_DSTAT dstat1;
    int JsonClose=0;
    smb_cli_term_printf(CLI_ALERT,"performing LS on %s\\%s \n", sharename, pattern);
    do
    {
        int r1 = rtsmb_cli_session_find_first(sid, sharename, pattern, &dstat1);
        if(r1 < 0)
        {
            rtp_printf("\n Error getting files\n");
            return 1;
        }
        r1 = wait_on_job(sid, r1);

        if (r1 == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
            JsonClose=1;
            smb_cli_term_printf(CLI_PROMPT,"{ \"Status\":  %d, \"Results\": [ ", 0);
            if (jSonBuffer)
                jSonBuffer += rtp_sprintf(jSonBuffer,"{ \"Status\":  %d, \"Results\": [ ", 0);
        }
        while(r1 == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
            char temp[200];

            rtsmb_util_rtsmb_to_ascii ((PFRTCHAR) dstat1.filename, temp, 0);
            {
                DATE_STR d;
                RTP_DATE rtpDateStruct;
                dword  unix_time = rtsmb_util_time_date_to_unix (rtsmb_util_time_ms_to_date (/*(TIME)*/dstat1.fctime64));
                char attrib_string[8];
                byte fattributes = dstat1.fattributes;

                smb_cli_term_printf(CLI_PROMPT,"Cheat on directory meaning for now \n");
                if (fattributes & 0x02) // RTP_FILE_ATTRIB_ISDIR)
                    attrib_string[0] = 'd';
                else
                    attrib_string[0] = '0';
                attrib_string[1] = 'r';
                attrib_string[2] = 'w';
                attrib_string[3] = 0;


                rtpDateStruct =  rtsmb_util_time_unix_to_rtp_date (unix_time);
                smb_cli_term_printf(CLI_PROMPT,"%s %2d %4d  %8d %-40.40s\n", month_names[(rtpDateStruct.month-1)%12], (int)rtpDateStruct.day, (int)rtpDateStruct.year, (int)dstat1.fsize, temp );

    smb_cli_term_printf(CLI_PROMPT,"{\"FileName\":   \"%s\",    \"Date\": \"%s %2d %4d\", \"Attributes\": \"%s\",  \"Size\":       %d},",
                                      temp,month_names[(rtpDateStruct.month-1)%12], (int)rtpDateStruct.day, (int)rtpDateStruct.year, attrib_string, (int)dstat1.fsize);

                if (jSonBuffer)
                    jSonBuffer += rtp_sprintf(jSonBuffer, "{\"FileName\":   \"%s\",    \"Date\": \"%s %2d %4d\", \"Attributes\": \"%s\",  \"Size\":       %d},",
                                      temp,month_names[(rtpDateStruct.month-1)%12], (int)rtpDateStruct.day, (int)rtpDateStruct.year, attrib_string, (int)dstat1.fsize);
            }
            r1 = rtsmb_cli_session_find_next(sid, &dstat1);
            if(r1 >= 0)
            {
                r1 = wait_on_job(sid, r1);
            }
        }
        r1 = rtsmb_cli_session_find_next(sid, &dstat1);
        rtsmb_cli_session_find_close(sid, &dstat1);
    } while(doLoop);
    if (JsonClose)
    {
        smb_cli_term_printf(CLI_PROMPT,"%s", "] }");
        if (jSonBuffer)
            jSonBuffer += rtp_sprintf(jSonBuffer, "%s", "] }");
    }
    return 0;
}

static int do_prompt_ls_command(int doLoop)
{
    RTSMB_CLI_SESSION_DSTAT dstat1;
    int sid;
    int r1;
    char *sharename;
    char pattern[256];
    int srv_val = 0;
    int log_val = 0;
    int sh_val = 0;

    while(!srv_val)
    {
        srv_val = do_connect_server(&sid);
        smb_cli_term_printf(CLI_ALERT,"\ndo_connect_server returns %d\n ",srv_val);
        if(!srv_val)
        {
            smb_cli_term_printf(CLI_ALERT,"\nUnknown Server. Use SETSERVER for changing the value.\n ");
            return 0;
        }
    }

    while(!log_val)
    {
        log_val = do_logon_server(sid);
        if(!log_val)
        {
            smb_cli_term_printf(CLI_ALERT,"\nUnknown user or wrong password. Please check.\n");
            return 0;
        }
    }

    sharename = do_getshare_name();
    while(!sh_val)
    {
        sh_val = do_connect_share(sid, sharename);
        if(!sh_val)
        {
            smb_cli_term_printf(CLI_ALERT,"Unknown logon or share. Use SETUSER, SETPASSWORD, SETSHARE for changing values.\n\n");
            return 0;
        }
    }
    smbcli_prompt("Pattern (* always works):  ", pattern, 256);

    do_ls_command_worker(doLoop,sid,sharename,pattern,0);
    rtsmb_cli_shutdown();
    return 0;
}

#if (USE_HTTP_INTERFACE)
// process NET USE D: \\Sharename /user:xxxx /password:yyyy
// process NET USE D: \\Sharename /user:xxxx /password:yyyy
static int do_net_command_web(NVPairList *pPairList,char *outbuffer, int outbufferLength)
{
   NVPair *pCommand;

   rtp_strcpy(outbuffer, "Command Not Found");

   pCommand = HTTP_GetNameValuePairAssociative (pPairList,"command");

    if (do_net_command(pCommand->value)<0)
        return -1;
    else
        return 0;

}
static int do_cli_web_command(NVPairList *pPairList,char *jSonBuffer, int outbufferLength)
{
int ConnectionNo=0;
NVPair *Command;

    Command = HTTP_GetNameValuePairAssociative (pPairList,"command");
    smb_cli_term_printf(CLI_ALERT,"do_cli_web_command command=%s\n",Command->value);

    if (rtp_strcmp(Command->value, "LogOn") == 0)
    {
    NVPair *RemoteHost,*User,*Password;
    int sid;
    RTSMB_CLI_SESSION_DIALECT dialect = 1;  // 0==CSSN_DIALECT_PRE_NT, 1==CSSN_DIALECT_NT, 2==CSSN_DIALECT_SMB2_2002:

        RemoteHost = HTTP_GetNameValuePairAssociative (pPairList,"RemoteHost");
        User       = HTTP_GetNameValuePairAssociative (pPairList,"User");
        Password   = HTTP_GetNameValuePairAssociative (pPairList,"Password");
        if (do_connect_server_worker(&sid, RemoteHost->value, dialect)==1)
        {
            if (do_logon_server_worker(sid,  User->value, Password->value, "domain"))
            {
                rtp_sprintf(jSonBuffer, "{ SessionId: %d }" , sid);
                return 0;
            }
            else
                rtp_strcpy(jSonBuffer,"Log On Failed, Bad Username or password");

        }
        else
        {
            rtp_strcpy(jSonBuffer,"Connect Failed");
        }
        return -1;
    }
    if (rtp_strcmp(Command->value, "LogOff") == 0)
    {
    NVPair *SessionId,*Sharename;
        SessionId  = HTTP_GetNameValuePairAssociative (pPairList,"SessionId");
        Sharename  = HTTP_GetNameValuePairAssociative (pPairList,"Sharename");
        if (do_connect_share(rtp_atoi(SessionId->value), Sharename->value)==1)
        {
            rtp_sprintf(jSonBuffer, "Success");
            return 0;
        }
        else
        {
            return -1;

        }
    }
    if (rtp_strcmp(Command->value, "Use") == 0)
    {
    NVPair *SessionId,*ShareName,*DriveName;
        SessionId  = HTTP_GetNameValuePairAssociative (pPairList,"SessionId");
        ShareName  = HTTP_GetNameValuePairAssociative (pPairList,"ShareName");
        DriveName  = HTTP_GetNameValuePairAssociative (pPairList,"DriveName");

        if (do_connect_share(rtp_atoi(SessionId->value), ShareName->value)==1)
        {
            rtp_sprintf(jSonBuffer, "Use:Succeeded");
            return 0;
        }
        else
        {
            rtp_sprintf(jSonBuffer, "Use:Failed");
            return -1;
        }
    }
    if (rtp_strcmp(Command->value, "RefreshRemote") == 0)
    {
    NVPair *SessionId,*ShareName,*DriveName;
        SessionId  = HTTP_GetNameValuePairAssociative (pPairList,"SessionId");
        ShareName  = HTTP_GetNameValuePairAssociative (pPairList,"ShareName");
        if (do_ls_command_worker(0,rtp_atoi(SessionId->value), ShareName->value,"*",jSonBuffer)==0)
            return 0;
        else
            rtp_sprintf(jSonBuffer, "RefreshRemote:Failed");
         return -1;

    }
/*
        smb_cli_term_printf(CLI_ALERT,"Connecting to %s\n",Clishell.ClishellConnections[ConnectionNo].server_name);
        if (do_connect_server_worker(&Clishell.ClishellConnections[ConnectionNo].sid, Clishell.ClishellConnections[ConnectionNo].server_name, Clishell.ClishellConnections[ConnectionNo].dialect)!=1)
        {
            smb_cli_term_printf(CLI_ALERT,"Failed Connecting to %s\n",Clishell.ClishellConnections[ConnectionNo].server_name);
            return -1;
        }
        smb_cli_term_printf(CLI_ALERT,"Logging on with username: %s password: %s \n",Clishell.ClishellConnections[ConnectionNo].userString,Clishell.ClishellConnections[ConnectionNo].passwordString);
        if (do_logon_server_worker(Clishell.ClishellConnections[ConnectionNo].sid,  Clishell.ClishellConnections[ConnectionNo].userString, Clishell.ClishellConnections[ConnectionNo].passwordString, "Domain") < 0)
        {
            smb_cli_term_printf(CLI_ALERT,"Failed Logging on with username: %s password: %s \n",Clishell.ClishellConnections[ConnectionNo].userString,Clishell.ClishellConnections[ConnectionNo].passwordString);
            return -1;
        }
*/
    return 0;
}
#endif

#if (USE_HTTP_INTERFACE)
static int do_ls_command_web(char *command,char *jSonBuffer, int outbufferLength)
{
   int idNo = CmdToDrvId(command);
   if (idNo < 0)
       return 0;
   return do_ls_command_worker(FALSE,Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid,Clishell.ClishellShares[idNo].shareString,"*",jSonBuffer);
}
#endif


static int do_ls_command(char *command)
{
    if (*command==0)
        return do_prompt_ls_command(FALSE);
    else
    {
        int idNo;
        idNo =CmdToDrvId(command);
        if (idNo < 0)
            return 0;
        return do_ls_command_worker(FALSE,Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid,Clishell.ClishellShares[idNo].shareString,"*",0);
    }
}

static int do_file_command_worker_complete(RtsmbCliFile *pFile, int r, char *Operation)
{
    if(r >= 0)
        r = wait_on_job(pFile->session_id, r);
    if(r < 0)
        smb_cli_term_printf(CLI_ALERT,"\n Error: %s\n", Operation);
    return r;
}
static int do_file_command_open_worker(int SessionId,RtsmbCliFile *pFile,char *sharename, char *filename, word options,word flags)
{
int r;
    pFile->session_id      = SessionId;
    r = rtsmb_cli_session_open(pFile->session_id, sharename, filename, options, flags, &pFile->session_fid);
    r = do_file_command_worker_complete(pFile, r, "Opening file");
    if(r < 0)
    {
        pFile->session_id      = 0;
        pFile->session_fid      = -1;
    }
   return r;

}
static int do_file_command_close_worker(RtsmbCliFile *pFile)
{
int r;
    r = rtsmb_cli_session_close(pFile->session_id, pFile->session_fid);
    r = do_file_command_worker_complete(pFile, r, "Close file");
    return r;
}
static int do_file_command_io_worker(RtsmbCliFile *pFile,void *buffer, int count, BBOOL isRead)
{
int r,transferred;
    if (isRead)
    {
        r = rtsmb_cli_session_read(pFile->session_id, pFile->session_fid, buffer, count, &transferred);
        r = do_file_command_worker_complete(pFile, r, "Reading");
    }
    else
    {
        r = rtsmb_cli_session_write(pFile->session_id, pFile->session_fid, buffer, count, &transferred);
        r = do_file_command_worker_complete(pFile, r, "Writing");
    }
    if(r < 0)
        transferred=-1;
    return transferred;
}


static int do_file_command_worker(int which_command,int sid, char *sharename, char *filename)
{
/*  RTSMB_CLI_SESSION_DSTAT dstat1; */
    int transferred;
    long total_transferred =0;
    int r,fd,l;
    RtsmbCliFile MyFile;
    RtsmbCliFile *pFile=&MyFile;
    if (which_command == WRITE_COMMAND)
    {
        r = do_file_command_open_worker(sid,pFile,sharename, filename,RTP_FILE_O_CREAT|RTP_FILE_O_RDWR|RTP_FILE_O_TRUNC,RTP_FILE_S_IWRITE|RTP_FILE_S_IREAD);
    }
    else
    {
        r = do_file_command_open_worker(sid,pFile,sharename, filename,RTP_FILE_O_RDONLY,RTP_FILE_S_IREAD);
    }
    if(r < 0)
        return 1;
    if (which_command == WRITE_COMMAND)
    {
        smb_cli_term_printf(CLI_ALERT,"Filling a file with hello world \n");
    }
    l = 0;
    for(;;)
    {
        transferred = 0;
        if (which_command == WRITE_COMMAND)
        {
            rtp_sprintf(shell_buffer, "(%d) - Hello again world from %s\n",l++, filename);
            r = do_file_command_io_worker(pFile,shell_buffer, (int)rtp_strlen(shell_buffer), FALSE);
        }
        else if (which_command == READ_COMMAND)
            r = do_file_command_io_worker(pFile,shell_buffer, 512, TRUE);
        else if (which_command == CAT_COMMAND)
            r = do_file_command_io_worker(pFile,shell_buffer, 80, TRUE);
        if(r < 0)
        {
            smb_cli_term_printf(CLI_ALERT,"\n Error transferring data");
            transferred=0;
            break;
        }
        else
           transferred=r;
        if (transferred <= 0)
            break;
        if (which_command == CAT_COMMAND)
            smb_cli_term_printf(CLI_PROMPT,"%s", shell_buffer);
        total_transferred += transferred;
        /* Th write just does writes 100 times, read stops at eof */
        if (which_command == WRITE_COMMAND && l > 100)
            break;
    }
    smb_cli_term_printf(CLI_PROMPT,"\n numbytes transfered is %ld\n", total_transferred);
    if (do_file_command_close_worker(pFile) < 0)
        return 0;
    return 0;
}

static int do_prompt_file_command(int which_command)
{
/*  RTSMB_CLI_SESSION_DSTAT dstat1; */
    int transferred;
    long total_transferred =0;
    int sid;
    int r;
    char *sharename;
    char filename[256];

    if (!do_connect_server(&sid))
        return(0);
    if (!do_logon_server(sid))
        return(0);

    sharename = do_getshare_name();
    if (!do_connect_share(sid, sharename))
        return(0);

    smbcli_prompt("Filename :  ", filename, 256);

    r = do_file_command_worker(which_command, sid, sharename, filename);
    rtsmb_cli_shutdown();
    return r;
}

static int do_file_command(int which_command, char *command)
{
  if (*command==0)
  {
    return do_prompt_file_command(which_command);
  }
  else
      {
        int idNo;
        idNo =CmdToDrvId(command);
        if (idNo < 0)
            return 0;
        command += 3;
        return do_file_command_worker(which_command,Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid,Clishell.ClishellShares[idNo].shareString,command);
    }
}
static int do_fhandle_open_command(char *command)
{
char *command_start = command;
char *filename_start = command;
char *mode_start = 0,*q=0;
word mode, flags;
int r;
int idNo, fdno;

    idNo=CmdToDrvId(command);
    if (idNo<0)
    {
        return -1;
    }
    command += 2;

    q = rtp_strstr(command,"\"");
    if (q)
    {
        command++;
        filename_start = command;
        q = rtp_strstr(command,"\"");
        if (!q)
        {
            smb_cli_term_printf(CLI_ALERT,"do_fhandle_open_command: Bad arguments\n");
            return -1;
        }
        *q = '0';
        mode_start = rtp_strstr(q+1," ");
    }
    else
    {
        command = rtp_strstr(command," ");
        if (!command)
        {
            smb_cli_term_printf(CLI_ALERT,"do_fhandle_open_command: Bad arguments\n");
            return -1;
        }
        command++;
        filename_start = command;
        mode_start = rtp_strstr(command," ");
    }

    if (!mode_start)
    {
        mode = RTP_FILE_O_RDONLY;
        flags = RTP_FILE_S_IREAD;
    }
    else
    {
        *mode_start++ = 0; /* Null trerminate file */
        mode = (word)RTP_FILE_O_CREAT|RTP_FILE_O_RDONLY;
        flags = RTP_FILE_S_IREAD;
        while(*mode_start)
        {
            if (*mode_start=='W' || *mode_start=='w')
            {
                mode &= (word)(~RTP_FILE_O_RDONLY);
                mode |= (word)RTP_FILE_O_RDWR;
                flags |= (word)RTP_FILE_S_IWRITE;
            }
            if (*mode_start=='T' || *mode_start=='t')
                mode |= (word)RTP_FILE_O_TRUNC;
            if (*mode_start=='E' || *mode_start=='e')
                mode &= (word)(~RTP_FILE_O_CREAT);
            mode_start++;
        }
        if ((mode & RTP_FILE_O_RDWR)!=RTP_FILE_O_RDWR)
            mode &= (word)(~RTP_FILE_O_CREAT);
    }

//TABLE_SIZE(Clishell.ClishellFiles

//    Clishell.ClishellFiles[fdno].fid;
//    Clishell.ClishellFiles[fdno].session_fid;
//    Clishell.ClishellFiles[fdno].session_id;

    for (fdno=0; fdno< MAX_FILES; fdno++)
    {
        if (Clishell.ClishellFiles[fdno].session_id==0)
            break;
    }
    if (fdno == MAX_FILES)
    {
        smb_cli_term_printf(CLI_PROMPT,"do_fhandle_open_command: Out of files\n");
        return -1;
    }
    r = do_file_command_open_worker(Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid,&Clishell.ClishellFiles[fdno],
                                        Clishell.ClishellShares[idNo].shareString,  filename_start, mode,flags);
    if (q)
        *q = '\"';
    if (r >= 0)
    {
        smb_cli_term_printf(CLI_PROMPT,"do_fhandle_open_command: File succesfully opened with fdno == %d\n", fdno);
    }
    else
        smb_cli_term_printf(CLI_PROMPT,"do_fhandle_open_command: File opened failed\n");
    return r;
}

static int do_fhandle_close_command(char *command)
{
int fdno;
    fdno=CmdToFdno(command);
    if (fdno<0)
        return -1;
    return do_file_command_close_worker(&Clishell.ClishellFiles[fdno]);
}
/* read fdno count */
static int do_fhandle_aread_command(char *command)
{
int r,fdno,lines;
    fdno=CmdToFdno(command);
    if (fdno<0)
        return -1;
    command += 2;
    if (fdno>9) command++;
    lines = (int)rtp_atol(command);
    if (lines < 0)
        lines = 32765;
    do {
        int i;
        r = do_file_command_io_worker(&Clishell.ClishellFiles[fdno],shell_buffer, 80, TRUE);
        if (r <= 0)
            break;
        shell_buffer[r]=0;
        for (i =0; i < r; i++)
            if (shell_buffer[i] == '\n')
                lines -= 1;
        smb_cli_term_printf(CLI_PROMPT,"%s",shell_buffer);
    } while (r>0 && lines > 0);
    return 0;
}

/* read fdno count */
static int do_fhandle_read_command(char *command)
{
    return 0;
}
static int do_fhandle_awrite_command(char *command)
{
    int r=0,lines =0,nbytes=0,prev=0;
    int fdno=CmdToFdno(command);
    if (fdno<0)
        return -1;

    smb_cli_term_printf(CLI_PROMPT,"Type in lines into the file. Type 2 empty lines to stop.\n");
    smb_cli_term_printf(CLI_PROMPT,"Preceed a line with !### to repeat the line ### times.\n");
    prev=0;
    do {
        int i,prev,l,repeat;
        char *p=shell_buffer;
        repeat = 1;
        smbcli_prompt("> ", shell_buffer, sizeof(shell_buffer));
        if (*p=='!')
        {
            p = rtp_strstr(shell_buffer," ");
            if (p)
            {
                *p=0;
                repeat = (int)rtp_atol(shell_buffer+1);
                p+=1;
            }
            else
                p = shell_buffer;
        }
        l = (int)rtp_strlen(p);
        shell_buffer[l++] = '\n';
        shell_buffer[l] = 0;
        if (l == 1 && prev==1)
            break;
        prev=l;
        while(repeat--)
        {
            r = do_file_command_io_worker(&Clishell.ClishellFiles[fdno],shell_buffer, l, FALSE);
            if (r <= 0)
                break;
            lines++;
            nbytes+=r;
        }
    } while (r>0);
    smb_cli_term_printf(CLI_PROMPT,"lines/bytes sent = %d %d\n", lines, nbytes);
    return 0;
}

static int do_fhandle_write_command(char *command)
{
    smb_cli_term_printf(CLI_PROMPT,"do_fhandle_write_command: %s\n", command);
    return 0;
}
static int do_fhandle_seek_command(char *command)
{
    smb_cli_term_printf(CLI_PROMPT,"do_fhandle_seek_command: %s\n", command);
    return 0;
}
static int do_fhandle_stat_command(char *command)
{
    smb_cli_term_printf(CLI_PROMPT,"do_fhandle_stat_command: %s\n", command);
    return 0;
}

static int do_dir_command_worker(int which_command,int sid,char *sharename,char *filename)
{
    int r;
    switch(which_command) {
        case DEL_COMMAND:
            r = rtsmb_cli_session_delete(sid, sharename, filename);
            break;
        case MKDIR_COMMAND:
            r = rtsmb_cli_session_mkdir(sid, sharename, filename);
            break;
        case RMDIR_COMMAND:
            r = rtsmb_cli_session_rmdir(sid, sharename, filename);
            break;
    }
    if(r < 0)
    {
failed:
        smb_cli_term_printf(CLI_ALERT,"Error executing command \n");
        return 0;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
        goto failed;
    return 0;
}

static int do_prompt_dir_command(int which_command)
{
    int sid;
    int r;
    char *sharename;
    char filename[256];

    if (!do_connect_server(&sid))
        return(0);
    if (!do_logon_server(sid))
        return(0);

    sharename = do_getshare_name();
    if (!do_connect_share(sid, sharename))
        return(0);

    smbcli_prompt("Name :  ", filename, 256);

    r = do_dir_command_worker(which_command,sid, sharename,filename);
    if(r < 0)
    {
        return 0;
    }
    rtsmb_cli_shutdown();
    return 0;
}

static int do_dir_command(int which_command, char *command)
{
  if (*command==0)
  {
    return do_prompt_dir_command(which_command);
  }
  else
      {
        int idNo;
        idNo =CmdToDrvId(command);
        if (idNo < 0)
            return 0;
        command += 3;
        return do_dir_command_worker(which_command,Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid,Clishell.ClishellShares[idNo].shareString,command);
    }
}



static int do_loop_command()
{
    do_prompt_ls_command(TRUE);

    return 0;
}

int looks_like_ip_addr(char *server_name)
{
    char *cur = server_name;
    int numPeriods=0;
    while('\0' != *cur)
    {
        if('.' == *cur)
            numPeriods++;

        cur++;
    }

    return (3 == numPeriods);
}

static int do_connect_server_worker(int *sid,char *server_name, RTSMB_CLI_SESSION_DIALECT dialect)
{
    int r;
    int i;

    smb_cli_term_printf(CLI_ALERT,"Connecting to server: %s\n",server_name);

    rtsmb_cli_init(my_ip, (PFBYTE)&my_mask[0]);
    if(looks_like_ip_addr(server_name))
    {
        int scanVals[4];
        BYTE ip[4];
        sscanf(server_name, "%d.%d.%d.%d", scanVals, scanVals+1, scanVals+2, scanVals+3);
        for(i=0; i<4; i++)
            ip[i] = (BYTE)scanVals[i];
        r = rtsmb_cli_session_new_with_ip (ip, NULL, FALSE, sid, dialect);
    }
    else
    {
        r = rtsmb_cli_session_new_with_name(server_name, FALSE, NULL, sid, dialect);
    }

    if(r < 0)
    {
        smb_cli_term_printf(CLI_PROMPT,"\n rtsmb_cli_session_new: Error starting session with server %s", server_name);
    }
    r = wait_on_job(*sid, r);
    if(r < 0)
    {
        smb_cli_term_printf(CLI_PROMPT,"\nError Creating Session with server %s", server_name);
        return 0;
    }
    //if(r < 0)
    //{
    //  smb_cli_term_printf(CLI_PROMPT,"\n Error during session create ??");
    //  return 0;
    //}
    return(1);
}

static int do_connect_server(int *sid)
{
    int r;
    char *server_name;
    int i;
    RTSMB_CLI_SESSION_DIALECT dialect;
    //smbcli_prompt("Server: ", gl_server_name);
    server_name = do_getserver_name();
    dialect = do_get_session_dialect();

    smb_cli_term_printf(CLI_ALERT,"server = %s\n",server_name);

    return do_connect_server_worker(sid, server_name, dialect);
}


/* Tools for loging on to server and connecting to shares, these work with
   with do_setuser_command() et al to reduce typing */
static int do_logon_server_worker(int sid,  char *user_name, char *password, char *domain)
{
    int r;

    smb_cli_term_printf(CLI_ALERT,"\nuser = %s",user_name);
    smb_cli_term_printf(CLI_ALERT,"\npassword = %s",password);
    smb_cli_term_printf(CLI_ALERT,"\ndomain = %s\n",domain);

    r = rtsmb_cli_session_logon_user(sid, user_name, password, domain);
    if(r < 0)
    {
        smb_cli_term_printf(CLI_PROMPT,"\n Error during user logon");
        return 0;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        smb_cli_term_printf(CLI_PROMPT,"\n Error during logon response");
        return 0;
    }
    return(1);
}

static int do_logon_server(int sid)
{
    int r;
    char *user_name;
    char *password;
    char *domain;
    user_name = do_getuser_name();
    password = do_getpassword();
    domain = do_getdomain_name();
    return do_logon_server_worker(sid,  user_name, password, domain);
}

static int do_connect_share(int sid, char *sharename)
{
    int r1;

    r1 = rtsmb_cli_session_connect_share(sid, sharename, "");
    if (r1 < 0)
    {

        smb_cli_term_printf(CLI_PROMPT,"\n Error connecting to share\n");
        return 0;
    }
    r1 = wait_on_job(sid, r1);

    if(r1 < 0)// || r2 < 0)
    {
        smb_cli_term_printf(CLI_PROMPT,"\n Error during connect to share response\n");
        return 0;
    }
    return 1;
}

/* Tools for inputting server, share, user password.. these save a lot of typing */
char gl_server_name[128]= {'1','9','2','.','1','6','8','.','1','.','6',0};
static int  server_name_is_set=1;
static char *do_getserver_name(void)
{
    if (!server_name_is_set)
        do_setserver_command();
    return(&gl_server_name[0]);
}
static RTSMB_CLI_SESSION_DIALECT do_get_session_dialect(void)
{
static int  dialog_is_set;
static char gl_dialog_string[32];
    while (!dialog_is_set)
    {
        smbcli_prompt("Select dialect: 0==CSSN_DIALECT_PRE_NT, 1==CSSN_DIALECT_NT, 2==CSSN_DIALECT_SMB2_2002: ", gl_dialog_string, 32);
        if (gl_dialog_string[0]>='0'&&gl_dialog_string[0]<='2')
            dialog_is_set=1;

    }
    return((RTSMB_CLI_SESSION_DIALECT)(gl_dialog_string[0]-'0'));
}


static int do_setserver_command(void)
{
#if (HISTORY_MODE)
    server_name_is_set = 1;
#endif
    smbcli_prompt("Server: ", gl_server_name, 128);
    return(1);
}
char gl_user_name[128];
int  user_name_is_set;
static char *do_getuser_name(void)
{
    if (!user_name_is_set)
        do_setuser_command();
    return(&gl_user_name[0]);
}

char gl_domain_name[128];
int  domain_name_is_set;
static char *do_getdomain_name(void)
{
    if (!domain_name_is_set)
        do_setdomain_command();
    return(&gl_domain_name[0]);
}

static int do_setuser_command(void)
{
#if (HISTORY_MODE)
    user_name_is_set = 1;
#endif
    smbcli_prompt("user: ", gl_user_name, 128);
    if (!gl_user_name[0])
    { /* Does not like an ampty string.. investigate */
        gl_user_name[0] = ' ';
        gl_user_name[1] = 0;
    }
    return(1);
}
static int do_setdomain_command(void)
{
#if (HISTORY_MODE)
    domain_name_is_set = 1;
#endif
    smbcli_prompt("domain: ", gl_domain_name, 128);
    return(1);
}

char gl_password[128];
int  password_name_is_set;
static char *do_getpassword(void)
{
    if (!password_name_is_set)
        do_setpassword_command();
    return(&gl_password[0]);
}
static int do_setpassword_command(void)
{
#if (HISTORY_MODE)
    password_name_is_set = 1;
#endif
    smbcli_prompt("password: ", gl_password, 128);
    return(1);
}
char gl_share_name[128];
int  share_name_is_set;
static char *do_getshare_name(void)
{
    if (!share_name_is_set)
        do_setshare_command();
    return(&gl_share_name[0]);
}
static int do_setshare_command(void)
{
#if (HISTORY_MODE)
    share_name_is_set = 1;
#endif
    smbcli_prompt("share: ", gl_share_name, 128);
    return(1);
}
static void in_ipaddress(byte *pip, byte *pmask_ip)
{
    byte counter;
    for (counter=0;counter<4;counter++)
    {
    char inbuffer[32];
        rtp_itoa(pip[counter], inbuffer, 10);
        smb_cli_term_printf(CLI_PROMPT,"Byte %d IP Address: ",counter);
        rtp_term_promptstring (inbuffer, 0);
        pip[counter] = (unsigned char)rtp_atoi(inbuffer);
    }
    for (counter=0; counter<4; counter++)
    {
    char inbuffer[32];
        rtp_itoa(pmask_ip[counter], inbuffer, 10);
        smb_cli_term_printf(CLI_PROMPT,"Byte %d IP Mask: ",counter);
        rtp_term_promptstring (inbuffer, 0);
        pmask_ip[counter] = (unsigned char)rtp_atoi(inbuffer);
    }
    smb_cli_term_printf(CLI_PROMPT,"IP Address: %d.%d.%d.%d\n",pip[0],pip[1],pip[2],pip[3]);
    smb_cli_term_printf(CLI_PROMPT,"IP Mask   : %d.%d.%d.%d\n",pmask_ip[0],pmask_ip[1],pmask_ip[2],pmask_ip[3]);

}

#include "clicfg.h"

static const char *SessionStateName[] = {"UNUSED", "DEAD  ", "QUERYING", "CONNECTING", "UNCONNECTED",
                                  "NEGOTIATED", "RECOVERY_QUERYING", "RECOVERY_NEGOTIATING",
                                  "RECOVERY_NEGOTIATED", "RECOVERY_LOGGING_ON",
                                  "RECOVERY_LOGGED_ON", "RECOVERY_TREE_CONNECTING",
                                  "RECOVERY_TREE_CONNECTED", "RECOVERY_FILE_OPENING",
                                  "RECOVERY_FILE_OPENED"};

//const char *UserStateName[] = {"UNUSED", "LOGGING ON", "LOGGED ON", "DIRTY"};
static const char *ShareStateName[] = {"UNUSED", "CONNECTING", "CONNECTED", "DIRTY"};
static const char *JobStateName[] = {"UNUSED", "FAKE  ", "STALLED", "WAITING", "DIRTY"};
//const char *ServerSearchStateName[] = {"UNUSED", "BACK UP", "LOGGING ON", "REQUESTING", "DATA READY",
//                                       "BACKUP AGAIN", "DONE LOCAL", "FINISH"};



static int do_cli_info (void)
{
    int session, job, share,fid,search_sid;
//  PRTSMB_CLI_SESSION_SHARE pShare;
//  PRTSMB_CLI_SESSION_JOB pJob;
//  PRTSMB_CLI_SESSION pSession;

rtp_printf("Hello prtsmb_cli_ctx->max_sessions == %d \n",(int)prtsmb_cli_ctx->max_sessions);
    for (session = 0; session < prtsmb_cli_ctx->max_sessions; session++)
    {

        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Session %d: %s. \n",session, SessionStateName[prtsmb_cli_ctx->sessions[session].state]);
        if (prtsmb_cli_ctx->sessions[session].state == CSSN_STATE_UNUSED)
            continue;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "    Server Name:      %s \n", prtsmb_cli_ctx->sessions[session].server_name);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "    Current Job Queue For Session\n", 0);
        for (job = 0; job < prtsmb_cli_ctx->max_jobs_per_session; job++)
        {
            if (prtsmb_cli_ctx->sessions[session].jobs[job].state == CSSN_JOB_STATE_UNUSED)
                continue;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Job State:            %s \n", JobStateName[prtsmb_cli_ctx->sessions[session].jobs[job].state]);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Request Message Id:   %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].mid);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Send  Retry count:    %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].send_count);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Reconnect Count:      %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].die_count);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Reconnect Count:      %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].die_count);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        response Value:       %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].response);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        error    Value:       %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].error);
        }
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "    Current Shares For The Session\n", 0);
        for (share = 0; share < prtsmb_cli_ctx->max_shares_per_session; share++)
        {
            if (prtsmb_cli_ctx->sessions[session].shares[share].state == CSSN_SHARE_STATE_UNUSED)
                continue;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Share Name:           %s \n", prtsmb_cli_ctx->sessions[session].shares[share].share_name);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Password  :           %s \n", prtsmb_cli_ctx->sessions[session].shares[share].password);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Tree Id   :           %d \n", (int)prtsmb_cli_ctx->sessions[session].shares[share].tid);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Connect Mid :         %d \n", (int)prtsmb_cli_ctx->sessions[session].shares[share].connect_mid);
        }
        for (fid = 0; fid < prtsmb_cli_ctx->max_fids_per_session; fid++)
        {
            if (prtsmb_cli_ctx->sessions[session].fids[fid].real_fid == CSSN_FID_STATE_UNUSED)
            {
                continue;
            }
            if (prtsmb_cli_ctx->sessions[session].fids[fid].real_fid == CSSN_FID_STATE_DIRTY)
            {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Real FileId:           %s \n", "Dirty. Must be reopened");
            }
            else
            {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        File Name:                %s \n", (int)prtsmb_cli_ctx->sessions[session].fids[fid].name);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Real FileId:              %d \n", prtsmb_cli_ctx->sessions[session].fids[fid].real_fid);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Smb  FileId:              %d \n", (int)prtsmb_cli_ctx->sessions[session].fids[fid].smb_fid);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Cached Offset:            %d \n", (int)prtsmb_cli_ctx->sessions[session].fids[fid].offset);
                if (prtsmb_cli_ctx->sessions[session].fids[fid].owning_share && prtsmb_cli_ctx->sessions[session].fids[fid].owning_share->share_name)
                {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Owning Share :            %s \n", prtsmb_cli_ctx->sessions[session].fids[fid].owning_share->share_name);
                }
                else
                {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Owning Share :            %s \n", "Lost");
                }
            }
//      prtsmb_cli_ctx->sessions[session].fids[fid].flags;
//      prtsmb_cli_ctx->sessions[session].fids[fid].mode;
        }

        for (search_sid = 0; search_sid < prtsmb_cli_ctx->max_searches_per_session; search_sid++)
        {
            if (prtsmb_cli_ctx->sessions[session].searches[search_sid].sid == -1)
                continue;
        }
//      pSession->user.state = CSSN_USER_STATE_UNUSED;
//      pSession->anon.state = CSSN_USER_STATE_UNUSED;

//      prtsmb_cli_ctx->sessions[i].share_search
//      prtsmb_cli_ctx->sessions[i].psmb2Session
//      prtsmb_cli_ctx->sessions[i].timestamp; /* tells how long it's been since the session has been used */

//      prtsmb_cli_ctx->sessions[i].wire;

//      prtsmb_cli_ctx->sessions[i].state;

//      prtsmb_cli_ctx->sessions[i].server_info;

//      prtsmb_cli_ctx->sessions[i].user;
//      prtsmb_cli_ctx->sessions[i].anon;   /* an anonymous user we have as a fallback */

    }
    return 0;
}


/*---------------------------------------------------------------------------*/
#if (USE_HTTP_INTERFACE)
void ServerEntryPoint (void *userData)
{
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Web server based interface is avaliable\n", 0);
    http_advanced_server_demo();
}
#endif

#if (USE_HTTP_INTERFACE)
/* ENTRY POINT FOR HTTP DEMO */
#include "rtpthrd.h"
static void spawn_web_server(void)
{
RTP_THREAD threadHandle;

    if (rtp_thread_spawn(&threadHandle, ServerEntryPoint, 0, 32768, 0, "Hello") < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Failed to spawn web server for user interface\n", 0);
    }
}
#endif
