#ifndef __SMB_DEFS_H__
#define __SMB_DEFS_H__

//****************************************************************************
//**
//**    SMBDEFS.H
//**    Header - This sets up cross-platform code and includes the correct
//**             network stack.  It also defines various constants needed by
//**             the code.
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
//common program headers

#include "rtptypes.h"
#include "rtpdebug.h"
#include "rtpstr.h" 
#include "rtptotc.h"
#include "smbconf.h"
#include "smb.h"

#if (1)
#include "rtpprint.h"
#define SMB_ERROR rtp_printf
#else
#define SMB_ERROR 
#endif
#define MIN(A, B) (((A) < (B)) ? (A) : (B))
#define MAX(A, B) (((A) > (B)) ? (A) : (B))

#define RTSMB_MIN MIN
#define RTSMB_MAX MAX

#ifdef WIN32
#include <assert.h>
#define RTSMB_ASSERT(X) assert(X)
#else
#define RTSMB_ASSERT(X)
#endif /* WIN32 */

#define PADD(p, n) ((PFVOID) (((RTP_ADDR) (p)) + ((RTP_ADDR) (n))))
#define PDIFF(p, q) (RTP_ADDR)((RTP_ADDR) (p) - (RTP_ADDR) (q))

// gets the index of item B in array A.  A must have at least one element
// this is very unsafe if you are not sure that B is in A and both pointers
// are valid
#define INDEX_OF(A, B)  ((int)(((RTP_ADDR) B - (RTP_ADDR) A) / (int)sizeof (A[0])))

// gets the size (number of indeces) in an array.
#define TABLE_SIZE(A)   (int) (sizeof (A) / sizeof (A[0]))


// for testing/measurement purposes, I find it convenient to disable static/const variables temporarily
#define RTSMB_STATIC static
#define RTSMB_CONST  const

#define BBOOL byte

#define RTSMB_TIME_INFINITE     0xFFFFFFFF


#if (INCLUDE_RTSMB_UNICODE)
typedef unsigned short  rtsmb_char;
#define RTSMB_STR_TOK   "%S"    /* rtp_printf argument for unicode string */
#else
typedef char            rtsmb_char;
#define RTSMB_STR_TOK   "%s"    /* rtp_printf argument for ascii string */
#endif

typedef unsigned char   byte;   //8-bit
typedef unsigned short  word;   //16-bit
typedef unsigned long   dword;  //32-bit
typedef unsigned long long ddword;  //32-bit
typedef unsigned long   rtsmb_size;

typedef byte              RTSMB_FAR * PFBYTE;
typedef word              RTSMB_FAR * PFWORD;
typedef dword             RTSMB_FAR * PFDWORD;
typedef ddword            RTSMB_FAR * PFDDWORD;
typedef unsigned short    RTSMB_FAR * PFWCS;
typedef rtsmb_char        RTSMB_FAR * PFRTCHAR;
typedef rtsmb_size        RTSMB_FAR * PFSIZE;
typedef char              RTSMB_FAR * PFCHAR;
typedef int               RTSMB_FAR * PFINT;
typedef long              RTSMB_FAR * PFLONG;
typedef void              RTSMB_FAR * PFVOID;
typedef BBOOL             RTSMB_FAR * PFBBOOL;


typedef unsigned short    RTSMB_CHAR16;
typedef char              RTSMB_CHAR8;
typedef unsigned char     RTSMB_UINT8;
typedef unsigned short    RTSMB_UINT16;
typedef unsigned long     RTSMB_UINT32;
typedef char              RTSMB_INT8;
typedef short             RTSMB_INT16;
typedef long              RTSMB_INT32;
typedef int               RTSMB_BOOL;

#define RTSMB_TRUE        1
#define RTSMB_FALSE       0

typedef unsigned short    SMB_DATE;
typedef unsigned short    SMB_TIME;

/* This is a time-since-microsoft-epoch struct.  That means it records
   how many 100-nanoseconds have passed since Jan. 1, 1601. */
typedef struct {
    dword low_time;
    dword high_time;
} TIME;

/* This is a time-since-microsoft-epoch struct as a 64 bit ddword.
   Same as TIME, it records how many 100-nanoseconds have passed since Jan. 1, 1601. */
typedef ddword FILETIME_T;

typedef struct {
    SMB_DATE date;
    SMB_TIME time;
} DATE_STR;


#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

/*
//This causes some compilers to complain
#if INCLUDE_RTSMB_PRINTF
#define PRINTF rtp_printf
#else
#define PRINTF
#endif
*/
#if INCLUDE_RTSMB_PRINTF
    #define PRINTF(p) rtp_printf p
#else
    #define PRINTF(p)
#endif

PFRTCHAR rtsmb_get_comment (void);

// some macros to change from our host byte ordering to intel byte ordering
// this is because all smb's are sent using intel byte ordering
// 'w' refers to word or short, 'd' refers to a dword or int

/*
#define SMB_SWAP_BYTES_W(A) ((word) (A >> 8 | A << 8))
#define SMB_SWAP_BYTES_D(A) ((dword) ((A >> 24) | (A << 24) | ((A >> 8) & 0x0000FF00) | ((A << 8) & 0x00FF0000)))
*/
#define SMB_SWAP_BYTES_W(A) (word) ((((A) >> 8) & 0x00ff) | (((A) << 8) & 0xff00))
#define SMB_SWAP_BYTES_D(A) (dword) ((((A) >> 8) & 0x0000ff00) | (((A) << 8) & 0x00ff0000) | (((A) >> 24) & 0x000000ff) | (((A) << 24) & 0xff000000))

#ifdef SUPPORT_SMB2
extern ddword swapdword(const ddword i);
#define SMB_SWAP_BYTES_DD(A) (ddword) swapdword(A)
#endif

#if RTSMB_INTEL_ORDER
    #define SMB_HTOIW(A)  A
    #define SMB_HTOID(A)  A
    #define SMB_HTOIDD(A) A
    #define SMB_ITOHW(A)  A
    #define SMB_ITOHD(A)  A
    #define SMB_ITOHDD(A) A
    #define SMB_HTONW(A)  SMB_SWAP_BYTES_W(A)
    #define SMB_HTOND(A)  SMB_SWAP_BYTES_D(A)
    #define SMB_HTONDD(A) SMB_SWAP_BYTES_DD(A)
    #define SMB_NTOHW(A)  SMB_SWAP_BYTES_W(A)
    #define SMB_NTOHD(A)  SMB_SWAP_BYTES_D(A)
    #define SMB_NTOHDD(A) SMB_SWAP_BYTES_DD(A)
#else
    #define SMB_HTOIW(A)  SMB_SWAP_BYTES_W(A)
    #define SMB_HTOID(A)  SMB_SWAP_BYTES_D(A)
    #define SMB_HTOIDD(A) SMB_SWAP_BYTES_D(A)
    #define SMB_ITOHW(A)  SMB_SWAP_BYTES_W(A)
    #define SMB_ITOHD(A)  SMB_SWAP_BYTES_D(A)
    #define SMB_ITOHDD(A) SMB_SWAP_BYTES_DD(A)
    #define SMB_HTONW(A)  A
    #define SMB_HTOND(A)  A
    #define SMB_HTONDD(A) A
    #define SMB_NTOHW(A)  A
    #define SMB_NTOHD(A)  A
    #define SMB_NTOHDD(A) A
#endif

#define MEMCLEAROBJ(S) tc_memset(&S,0,sizeof(S))
#define MEMCLEARPOBJ(S) tc_memset(S,0,sizeof(*S))

#include "psmbos.h"
#include "psmbnet.h"
#include "psmbfile.h"

#include "rtpsignl.h"
#include "rtpfile.h"
//****************************************************************************
//**
//**    END HEADER SMBDEFS.H
//**
//****************************************************************************
#endif /* __SMB_DEFS_H__ */
