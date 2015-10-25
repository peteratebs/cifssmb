 /*
 | RTPTERM.C - Runtime Platform Network Services
 |
 |   PORTED TO THE LINUX PLATFORM
 |
 | EBS - RT-Platform
 |
 |  $Author: vmalaiya $
 |  $Date: 2006/07/17 15:29:01 $
 |  $Name:  $
 |  $Revision: 1.3 $
 |
 | Copyright EBS Inc. , 2006
 | All rights reserved.
 | This code may not be redistributed in source or linkable object form
 | without the consent of its author.
 |
 | Module description:
 |  [tbd]
*/

/************************************************************************
* Headers
************************************************************************/
#include "rtp.h"
#include "rtpterm.h"
#include "rtpstr.h"

#include <stdio.h>
#include <sys/select.h>
#include <unistd.h>
#include <termios.h>
/************************************************************************
* Defines
************************************************************************/
#define TERMINAL_UP_ARROW       1001
#define TERMINAL_DOWN_ARROW     1002
#define TERMINAL_RIGHT_ARROW    1003
#define TERMINAL_LEFT_ARROW     1004

#define TERMINAL_ESCAPE         27

#define TERMINAL_THREAD_SLEEP   sleep(0)

/************************************************************************
* Types
************************************************************************/

/************************************************************************
* Data
************************************************************************/

/************************************************************************
* Macros
************************************************************************/

/************************************************************************
* Function Prototypes
************************************************************************/

/************************************************************************
* Function Bodies
************************************************************************/

static struct termios org_tio;
static int isset = 0;

static void setraw()
{

struct termios new_tio;
	if(isset)
		return;
	isset = 1;
	tcgetattr(STDIN_FILENO, &org_tio);
	new_tio = org_tio;
	new_tio.c_lflag = new_tio.c_lflag & (~((unsigned)ICANON) & ~((unsigned)ECHO));
	tcsetattr(STDIN_FILENO,TCSANOW, &new_tio);
}
static void clearraw()
{
	if (isset)
	{
		isset = 0;
		tcsetattr(STDIN_FILENO,TCSANOW, &org_tio);
	}
}
/*----------------------------------------------------------------------*
                            rtp_term_kbhit
 *----------------------------------------------------------------------*/

// ===============================
 #include <termios.h>

static struct termios initial_settings, new_settings;
static int peek_character = -1;

static void init_keyboard()
{
    tcgetattr(0,&initial_settings);
    new_settings = initial_settings;
    new_settings.c_lflag &= ~((unsigned)ICANON);
    new_settings.c_lflag &= ~((unsigned)ECHO);
    new_settings.c_lflag &= ~((unsigned)ISIG);
    new_settings.c_cc[VMIN] = 1;
    new_settings.c_cc[VTIME] = 0;
    tcsetattr(0, TCSANOW, &new_settings);
}

static void close_keyboard()
{
    tcsetattr(0, TCSANOW, &initial_settings);
}

static int kbhit()
{
unsigned char ch;
int nread;

    //if (peek_character != -1) return 1;
    new_settings.c_cc[VMIN]=0;
    tcsetattr(0, TCSANOW, &new_settings);
    nread = read(0,&ch,1);
   	if(nread == 1)
    {
      //  peek_character = ch;
		while (read(0,&ch,1) > 0); /* Empty the input buffer */
    }
    new_settings.c_cc[VMIN]=1;
    tcsetattr(0, TCSANOW, &new_settings);
    if(nread == 1)
    {
      //  peek_character = ch;
        return 1;
    }
    return 0;
}

/*
static int readch()
{
char ch;

    if(peek_character != -1)
    {
        ch = peek_character;
        peek_character = -1;
        return ch;
    }
    read(0,&ch,1);
    return ch;
}
*/

int kbrawmode = 0;
static int dokbhit()
{
	if (!kbrawmode)
	{
		init_keyboard();
		kbrawmode = 1;
	}
	if (kbhit())
	{
		rtp_term_puts("Okay you got me");
		close_keyboard();
		kbrawmode = 0;
		peek_character = -1;
		return(1);
	}

	return(0);
}

// ===============================
int rtp_term_kbhit (void)
{
    fd_set fds;
    struct timeval tv;

	return(dokbhit());

    /* Turn off Linux stream buffering */
//    setbuf (stdin, NULL);

    /* set up fd */
    FD_ZERO (&fds);
    FD_SET (STDIN_FILENO, &fds);

    tv.tv_sec = tv.tv_usec = 0;

    if (select (STDIN_FILENO + 1, &fds, NULL, NULL, &tv) == 1)
        return (1);
    else
        return (0);
}

static int old_rtp_term_kbhit (void)
{
    fd_set fds;
    struct timeval tv;


    /* Turn off Linux stream buffering */
//    setbuf (stdin, NULL);

    /* set up fd */
    FD_ZERO (&fds);
    FD_SET (STDIN_FILENO, &fds);

    tv.tv_sec = tv.tv_usec = 0;

    if (select (STDIN_FILENO + 1, &fds, NULL, NULL, &tv) == 1)
        return (1);
    else
        return (0);
}

/*----------------------------------------------------------------------*
                            rtp_term_getch
 *----------------------------------------------------------------------*/
int rtp_term_getch (void)
{
int ch = 0;

    /* Turn off Linux stream buffering */
    setbuf (stdin, NULL);

    ch = getchar();
    return (ch);
}


/*----------------------------------------------------------------------*
                             rtp_term_putc
 *----------------------------------------------------------------------*/
void rtp_term_putc (char ch)
{
    /* Turn off Linux stream buffering */
    setbuf (stdout, NULL);

	putchar(ch);
}



/************************************************************************/
/*      THERE IS NO NEED TO CHANGE ANYTHING BELOW THIS COMMENT          */
/************************************************************************/




/*----------------------------------------------------------------------*
                             rtp_term_puts
 *----------------------------------------------------------------------*/
void rtp_term_puts (const char * string)
{
	rtp_term_cputs(string);
	rtp_term_putc('\n');
}


/*----------------------------------------------------------------------*
                             rtp_term_cputs
 *----------------------------------------------------------------------*/
int rtp_term_cputs (const char * string)
{
    while (*string)
	{
		rtp_term_putc(*string++);
	}
	return (0);
}


/*----------------------------------------------------------------------*
                             rtp_term_gets
 *----------------------------------------------------------------------*/
int rtp_term_gets (char * string)
{
    *string = 0;
    return (rtp_term_promptstring(string,0));
}


static int coooked_getc()
{
int inesc, inbrace, ch;

	inesc = inbrace = 0;
	for(;;)
	{
    while (!old_rtp_term_kbhit( ))
    {
        /* ----------------------------------- */
        /*  Free resources to time critical    */
        /*  events.                            */
        /* ----------------------------------- */
        TERMINAL_THREAD_SLEEP;
    }
    ch = getchar();
	if (!inesc)
	{
		if (ch == 27)
			inesc = 1;
		else
		{
			if (ch == 127)
				ch = 2;
			return(ch);
		}
	}
	else if (inbrace)
	{
		if (ch == 68)
			return(2); /* Back space */
		inbrace = inesc = 0;
	}
	else if (ch == '[')
		inbrace = 1;
	else
		return(ch);
	}

}



/*----------------------------------------------------------------------*
                          rtp_term_promptstring
 *----------------------------------------------------------------------*/
int rtp_term_promptstring (char * string, unsigned int handle_arrows)
{
/* ----------------------------------- */
/*  Endptr always points to            */
/*  null-terminator.                   */
/* ----------------------------------- */
char * endptr = &string[rtp_strlen(string)];
int ch;
char clbuff[80];


	rtp_memset((unsigned char *)clbuff, ' ', 79);
	clbuff[0] = '\r';
	clbuff[78] = '\r';
	clbuff[79] = 0;

#define CLEAR_LINE() rtp_term_cputs(clbuff)
setraw();

    /* ----------------------------------- */
	/*  Print out the default answer.      */
	/* ----------------------------------- */
	rtp_term_cputs(string);


if (0)	for(;;)
	{
    	ch = coooked_getc();
		printf("Ch == %d '%c' \n", ch, ch);

	}
    ch = coooked_getc();
	while (ch != -1)
	{
		switch(ch)
		{
		    /* ----------------------------------- */
			/*  Return.                            */
			/* ----------------------------------- */
		    case '\n':
		    case '\r':
			    rtp_term_putc('\n');
				clearraw();
			    return (0);

            /* ----------------------------------- */
			/*  Backspace.                         */
			/* ----------------------------------- */
		    case 2: // '\b':
			    if(endptr > string)
			    {
				    rtp_term_cputs("\b \b");
				    *(--endptr) = 0;
			    }               /* ----------------------------------- */
			    goto getnext;   /*  Get next character.                */
			                    /* ----------------------------------- */

		    case TERMINAL_UP_ARROW:
			    if(handle_arrows)
			    {
			        /* ----------------------------------- */
				    /*  Erase the current line.            */
				    /* ----------------------------------- */
				    CLEAR_LINE();                       /* ----------------------------------- */
				    return (rtp_term_up_arrow ( ));     /*  TERMINAL_UP_ARROW                  */
			    }                                       /* ----------------------------------- */
			    break;

		    case TERMINAL_DOWN_ARROW:
			    if(handle_arrows)
			    {
			        /* ----------------------------------- */
				    /*  Erase the current line.            */
				    /* ----------------------------------- */
				    CLEAR_LINE();                       /* ----------------------------------- */
				    return (rtp_term_down_arrow ( ));   /*  TERMINAL_DOWN_ARROW                */
			    }                                       /* ----------------------------------- */
			    break;

		    case TERMINAL_ESCAPE:
			    if(handle_arrows)
			    {
				    /* ----------------------------------- */
				    /*  Erase the current line.            */
				    /* ----------------------------------- */
				    CLEAR_LINE();                       /* ----------------------------------- */
				    return (rtp_term_escape_key ( ));   /*  TERMINAL_ESCAPE                    */
			    }                                       /* ----------------------------------- */
			    break;
		}

        /* ----------------------------------- */
		/*  Display the editing.               */
		/* ----------------------------------- */
		rtp_term_putc((char)ch);
		*endptr++ = (char)ch;
		*endptr = 0;

getnext:
    	ch	= coooked_getc();

	}
	clearraw();
	return (-1);

}


/*----------------------------------------------------------------------*
                           rtp_term_up_arrow
 *----------------------------------------------------------------------*/
int rtp_term_up_arrow (void)
{
    return ((int) TERMINAL_UP_ARROW);
}


/*----------------------------------------------------------------------*
                          rtp_term_down_arrow
 *----------------------------------------------------------------------*/
int rtp_term_down_arrow (void)
{
    return ((int) TERMINAL_DOWN_ARROW);
}


/*----------------------------------------------------------------------*
                          rtp_term_left_arrow
 *----------------------------------------------------------------------*/
int rtp_term_left_arrow (void)
{
    return ((int) TERMINAL_LEFT_ARROW);
}


/*----------------------------------------------------------------------*
                          rtp_term_right_arrow
 *----------------------------------------------------------------------*/
int rtp_term_right_arrow (void)
{
    return ((int) TERMINAL_RIGHT_ARROW);
}


/*----------------------------------------------------------------------*
                          rtp_term_escape_key
 *----------------------------------------------------------------------*/
int rtp_term_escape_key (void)
{
    return ((int) TERMINAL_ESCAPE);
}



/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
