#ifndef __SMBAPP__
#define __SMBAPP__ 1

// ---------------------------------------------------- 
/* ONLY ONE OF THE FOLLOWING 3 SHOULD BE DEFINED */

/* On Windows running Winsock */
//#define RTSMB_WIN

/* running Linux */
// #define RTSMB_LINUX

/* running RTIP */
#define RTSMB_RTIP

// ---------------------------------------------------- 
#define NETWORK_NAME     "EBSRTSMB"
// #define NETWORK_GROUP    "EBSGRP"
#define NETWORK_GROUP    "MSHOME"

#define SHARE_NAME       "share0"

#if (defined(RTSMB_LINUX))
#define SHARE_PATH "/usr"
#define TEMP_PATH  "/tmp"
#elif (defined(RTSMB_WIN))
#define SHARE_PATH  "C:\\TESTSMB"
#define TEMP_PATH   "C:\\TEMP"
#else
#define SHARE_PATH  "C:\\TESTSMB"
#define TEMP_PATH   "C:\\TEMP"
#endif

#endif  /* __SMBAPP__ */

