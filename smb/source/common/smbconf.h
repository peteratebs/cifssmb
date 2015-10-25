#ifndef __SMB_CONF_H__
#define __SMB_CONF_H__

#define INCLUDE_RTIP_RTPLATFORM 0
/* define the following for SMBv2 support */
//#define SUPPORT_SMB2


/* set this appropriately if you need far pointers */
#define RTSMB_FAR

/* set this to 0 if you are big-endian */
#define RTSMB_INTEL_ORDER    1


/* Change these to whatever you like, but make sure it stays
   less than 16 characters.

   If there is a conflict with the net name, numbers will be added on
   and such until we get to a unique one. */
#define CFG_RTSMB_DEFAULT_GROUP_NAME    "EBS"
#define CFG_RTSMB_DEFAULT_NET_NAME      "RTSMBSRV"

#define CFG_RTSMB_DEFAULT_COMMENT       "RTSMB Server"

/**
 * The following #defines decide what features RTSMB will build with.
 */

/**
 * If on, RTSMB will authenticate users using an encrypted form of their
 * password.  This requires DEC and MD4 libraries.
 *
 * If off, RTSMB will have the user send their plaintext password over the
 * wire.  Not recommended, unless you don't have access to encryption
 * libraries (and we provide those, so...).  Also, our DOS 8.3 file format
 * mangling algorithm uses the encryption code, so if you need that, leave
 * this on.
 */
#ifndef INCLUDE_RTSMB_ENCRYPTION
#define INCLUDE_RTSMB_ENCRYPTION                1
#endif

/**
 * If on, RTSMB will use unicode internally for all strings.  Without this,
 * RTSMB will not be able to handle unicode strings over the wire nor can it
 * pass unicode to the filesystem.
 *
 * Turning it off will save some memory (unicode buffers take up twice as many
 * bytes as plain ascii buffers).
 */
#ifndef INCLUDE_RTSMB_UNICODE
#define INCLUDE_RTSMB_UNICODE                   1
#endif

/**
 * Set this to the codepage you would like extended-ascii strings returned to the client as.
 *
 * US and Europe = RTSMB_CODEPAGE_LATIN1
 * Japan = RTSMB_CODEPAGE_SHIFTJIS
 */

#ifndef CFG_RTSMB_USER_CODEPAGE
#define CFG_RTSMB_USER_CODEPAGE   RTSMB_CODEPAGE_LATIN1
#endif

/**
 * If on, RTSMB will try to discover a domain controller on the network,
 * and if it finds one, will pass all log-on questions to it, instead
 * of relying on its own list of users/passwords.
 *
 * DO NOT ENABLE THIS RIGHT NOW.  Very experimental and will break your setup.
 */
#ifndef INCLUDE_RTSMB_DC
#define INCLUDE_RTSMB_DC                        0
#endif

/**
 * If off, RTSMB will not PRINTF anything to the screen.
 */
#ifndef INCLUDE_RTSMB_PRINTF
#define INCLUDE_RTSMB_PRINTF                    1
#endif

/**
 * If on, RTSMB will include code for the server.
 */
#ifndef INCLUDE_RTSMB_SERVER
#define INCLUDE_RTSMB_SERVER                    1
#endif

/**
 * If on, RTSMB will include code for the client.
 */
#ifndef INCLUDE_RTSMB_CLIENT
#define INCLUDE_RTSMB_CLIENT                    1
#endif

/**
 * If on, RTSMB will include code for the client EZ API.
 */
#ifndef INCLUDE_RTSMB_CLIENT_EZ
#define INCLUDE_RTSMB_CLIENT_EZ                 1
#endif

/**
 * Define this symbol to include support for threadsafe operation
 */
#define INCLUDE_RTSMB_THREADSAFE

/**
 * Define this symbol to have RTSMB use multiple threads to
 *  speed up certain operations
 */
/*#define INCLUDE_RTSMB_MULTITHREAD*/

/**
 * Define this symbol to allow SMB messages directly over TCP/IP
 *  transport (bypassing NetBIOS session service) on port 445
 */
#define RTSMB_ALLOW_SMB_OVER_TCP

/**
 * Define this symbol to enable zero-copy data writes in
 *  the RTSMB client (improves performance and removes write size
 *  restrictions; BUT any buffer passed to write API must remain
 *  intact until the operation is complete, even if using
 *  non-blocking asynchronous I/O)
 */
#define INCLUDE_RTSMB_CLI_ZERO_COPY

/**
 * Sanity checks and redifinitions that have to take place.
 */

/* If EZ is on, client must be turned on. */
#if (INCLUDE_RTSMB_CLIENT_EZ) && !(INCLUDE_RTMSB_CLIENT)
#undef  INCLUDE_RTSMB_CLIENT
#define INCLUDE_RTSMB_CLIENT 1
#endif

/* If multi-threading is on, then we must operate in threadsafe mode */
#ifdef INCLUDE_RTSMB_MULTITHREAD
#ifndef INCLUDE_RTSMB_THREADSAFE
#define INCLUDE_RTSMB_THREADSAFE
#endif
#endif

/* It is not recommended that you change these */
#define CFG_RTSMB_MAX_GROUPNAME_SIZE   10  // the maximum size of group names
#define CFG_RTSMB_MAX_USERNAME_SIZE    128 // the maximum size of account names
#define CFG_RTSMB_MAX_PASSWORD_SIZE    128 // the maximum size of passwords (must be at least 24 when using encryption)
#define CFG_RTSMB_MAX_DOMAIN_NAME_SIZE 128 // the maximum size of domain names


/* Helper stuff (don't change) */
#define CFG_RTSMB_EIGHT_THREE_BUFFER_SIZE 13

#endif /* __SMB_CONF_H__ */
