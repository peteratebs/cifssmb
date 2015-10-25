//
// PSMBOS.C - RTSMB OS Interface Layer for Windows
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc., 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Functions to deal with printers

//Replace with rtplatform stuff
#ifdef RTSMB_LINUX
#include "unistd.h" //used for fork and _exit
#include "stdlib.h" //used for exit
#endif

#include "psmbos.h"
#include "smbdefs.h"
#include "rtpfile.h" /* _YI_ */
#include "rtpprint.h"

/* These handles are used to remember the file streams
   of the printers to which we are attached. */
RTP_HANDLE printer_handle[4]; /* _YI_ */


/******************************************************************************

 rtsmb_osport_printer_init - Initialize a printer port for use

    ioPort - the printer port to initialize

 Description

    This function will be called before rtsmb_osport_printer_open,
    rtsmb_osport_printer_write, and rtsmb_osport_printer_close; so, it should
    be used to do any operating system-specific initialization of the hardware.
    Each printer needs to be initialized only once.

 Notes

    Printers can be mounted on any number of CIFS shares using the RTSMB
    server.  Each shared printer has an associated I/O port number used to
    identify its physical printer to the underlying operating system.  The
    scheme used to map this number to physical printers/hardware is left to
    whomever is porting RTSMB.

 See Also

    rtsmb_osport_printer_open, rtsmb_osport_printer_write,
       rtsmb_osport_printer_close

 Returns

    0 if successful, negative otherwise

******************************************************************************/

int rtsmb_osport_printer_init (int ioPort)
{

    if (ioPort < 1 || ioPort > 5)
        return -1;

    return 0;
}


/******************************************************************************

 rtsmb_osport_printer_open - Open a printer for writing data

    ioPort - the printer port to open

 Description

    This function opens a particular printer for writing data.  It is called
    after rtsmb_osport_printer_init for that same printer and before
    rtsmb_osport_printer_write.

 See Also

    rtsmb_osport_printer_init, rtsmb_osport_printer_write,
       rtsmb_osport_printer_close

 Returns

    0 if successful, negative otherwise

******************************************************************************/

#ifdef __linux
#   ifdef PRINT_VIA_CUPS //This file has to be deleted after printing via fork() and execve() lpr
    char *linux_printer[] = {"BAD", "/tmp/tempprnfile1","/tmp/tempprnfile2","/tmp/tempprnfile3","/tmp/tempprnfile4"};
#   else
    char *linux_printer[] = {"BAD", "/dev/usb/lp0","/dev/usb/lp1","/dev/usb/lp2","/dev/usb/lp3", "/dev/usb/lp4" };
#   endif
#endif

int rtsmb_osport_printer_open (int ioPort)
{
    /* _YI_ */
    const char *printer_name = (const char *)0;
    word mode;

    if (ioPort < 1 || ioPort > 5)
    {
        return -1;
    }
#if (defined(__linux))
    printer_name = linux_printer[ioPort];
#else // The below code is obsolete. Should investigate PrintMon for Windows.
    switch (ioPort)
    {
        case 1: printer_name = "LPT1"; break;
        case 2: printer_name = "LPT2"; break;
        case 3: printer_name = "LPT3"; break;
        case 4: printer_name = "LPT4"; break;
    }
#endif

#ifdef PRINT_VIA_CUPS
    mode = (word) (RTP_FILE_O_BINARY | RTP_FILE_O_RDWR | RTP_FILE_O_CREAT);
#else
    mode = (word) (RTP_FILE_O_BINARY | RTP_FILE_O_WRONLY /* | RTP_FILE_O_CREAT */);
#endif

    if (rtp_file_open(&printer_handle[ioPort - 1] , printer_name,   mode,   RTP_FILE_S_IWRITE) < 0)
    {
        return -1;
    }

    return 0;
}


/******************************************************************************

 rtsmb_osport_printer_write - Write data to a printer

    ioPort - the printer port to write to
    buffer - a pointer to the data to write
    size   - the number of bytes from buffer to write

 Description

    Writes a specified number of bytes to the given printer.

 See Also

     rtsmb_osport_printer_init, rtsmb_osport_printer_open,
       rtsmb_osport_printer_close

 Returns

     number of bytes written if successful, negative otherwise

******************************************************************************/

long rtsmb_osport_printer_write (int ioPort, unsigned char *buffer, long size)
{

    long written;

    if (ioPort < 1 || ioPort > 5)
    {
        return -1;
    }

    written = rtp_file_write(printer_handle[ioPort-1],buffer, size);

    if (written < size)
    {
        return -1;
    }
    return (long)written;

}

#ifdef RTSMB_LINUX
/*****************************************************************************

 rtsmb_osport_file_send_n_delete - Sends file with the print data to a printer
                                   via CUPS

    ioPort - the print file handle port

 Description

    Forks a child process, sends a system command to print via CUPS and deletes
    the temp print file.

 See Also

    rtsmb_osport_printer_init, rtsmb_osport_printer_write,
       rtsmb_osport_printer_open

 Returns

    0 if successful, negative otherwise

******************************************************************************/
rtsmb_osport_file_send_n_delete(int ioPort)
{
    pid_t pid;

    pid = fork();

    if (pid == 0)
    {
        int i;
        for(i=0;i<10;i++)
        {
            rtp_printf("child %d",i);
            sleep(1);
        //execve();
        }
        _exit(0);
    }
    else if(pid > 0)
    {
        int i;
        for (i = 0; i < 10; i++)
            {
                rtp_printf("parent: %d\n", i);
                sleep(1);
            }
            exit(0);

    }
    else
        rtp_printf("fork() failed");

    //rtp_file_delete(linux_printer[ioPort]);
    return 0;
}
#endif
/******************************************************************************

 rtsmb_osport_printer_close - close a printer

    ioPort - the printer port to close

 Description

    Closes a printer after all data has been written.

 See Also

    rtsmb_osport_printer_init, rtsmb_osport_printer_write,
       rtsmb_osport_printer_open

 Returns

    0 if successful, negative otherwise

******************************************************************************/

int rtsmb_osport_printer_close (int ioPort)
{

    int rv;
    if (ioPort < 1 || ioPort > 5)
    {
        return -1;
    }
    rv = rtp_file_close(printer_handle[ioPort - 1]);
    if (rv < 0)
    {
        return -1;
    }

    return 0;
}
