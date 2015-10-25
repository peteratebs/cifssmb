#ifndef __PSMBOS_H__
#define __PSMBOS_H__

/* types */
typedef void (*RTSMB_THREAD_FN)(void *context);

#ifdef INCLUDE_RTSMB_THREADSAFE
#define RTSMB_CLAIM_MUTEX(X)    rtp_sig_mutex_claim((RTP_MUTEX)(X))
#define RTSMB_RELEASE_MUTEX(X)  rtp_sig_mutex_release((RTP_MUTEX)(X))
#else
#define RTSMB_CLAIM_MUTEX(X)
#define RTSMB_RELEASE_MUTEX(X)
#endif

/* I/O related (only needed for printer sharing support */
int           rtsmb_osport_printer_init  (int ioPort);
int           rtsmb_osport_printer_open  (int ioPort);

#ifdef RTSMB_LINUX
int           rtsmb_osport_file_send_n_delete  (int ioPort);
#endif

long          rtsmb_osport_printer_write (int ioPort, unsigned char *buffer, long size);
int           rtsmb_osport_printer_close (int ioPort);

#endif
