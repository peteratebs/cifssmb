/* Last edit: Wed Oct 04 09:46:28 2006
 * By: Yigal Hochberg
 * Wed Oct 04 2006: ifdef around include <xxx.h>
 * Wed Sep 20 2006: include trip.h, use xnet md5rsa and MD5_xxx macros
 */

/**
 * \file hmac_md5.c
 *
 * hmac md5 functions for ipsec.
 *
 * The basic code is taken from RFC 2104 HMAC February 1997
 * http://rfc.net/rfc2104.html
 */

#include "md5rsa.h"

#define MD5_INIT(context)              MD5Init(context)
#define MD5_UPDATE(context, sec, len)  MD5Update(context, sec, len)
#define MD5_FINAL(key, context)        MD5Final(context);                   \
                                       tc_memcpy(key, (context)->digest, 16)
#define MEMSET(mem, val, size)		   tc_memset(mem, val, (unsigned int)size)
#define MEMCPY(to, from ,len)		   tc_memcpy(to, from, (unsigned int)len)
/**
 * \note MD5_XXX macros are in rtip.h.
 *
 * Specifically: MD5_FINAL is defined as follows;
 *
 * define MD5_FINAL(key, context) MD5Final(context);  rtp_memcpy(key, (context)->digest, 16)
 */

/*
 * Function: hmac_md5
 *
 * RFC 2104  HMAC February 1997
 * http://rfc.net/rfc2104.html
 */

/**
 * hmac_md5()
 *
 * \brief Computes the hmac md5 digest of a given data and data-length and
 * given key and key-length.The computed digest is copied into a caller buffer
 * "diget".
 *
 * \return void
 */
void
hmac_md5(
  unsigned char*  text,         /**< pointer to data stream */
  int             text_len,     /**< length of data stream */
  unsigned char*  key,          /**< pointer to authentication key */
  int             key_len,      /**< length of authentication key */
  unsigned char   *digest)      /**< caller digest to be filled in by this function (len=16) */
{
    MD5_CTX context;
    unsigned char k_ipad[65];    /* inner padding -
                                  * key XORd with ipad
                                  */
    unsigned char k_opad[65];    /* outer padding -
                                  * key XORd with opad
                                  */
    unsigned char tk[16];
    int i;
    /* if key is longer than 64 bytes reset it to key=MD5(key) */
    if (key_len > 64) {

        MD5_CTX      tctx;

        MD5_INIT(&tctx);
        MD5_UPDATE(&tctx, key, (unsigned int)key_len);
        MD5_FINAL(tk, &tctx);

        key = tk;
        key_len = 16;
    }

    /*
     * the HMAC_MD5 transform looks like:
     *
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

    /* start out by storing key in pads */

    MEMSET( k_ipad, 0, sizeof k_ipad);
    MEMSET( k_opad, 0, sizeof k_opad);
    MEMCPY( k_ipad, key, key_len);
    MEMCPY( k_opad, key, key_len);

    /* XOR key with ipad and opad values */
    for (i=0; i<64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    /*
     * perform inner MD5
     */
    MD5_INIT(&context);                   /* init context for 1st
                                           * pass */
    MD5_UPDATE(&context, k_ipad, 64);     /* start with inner pad */
    MD5_UPDATE(&context, text, (unsigned int)text_len); /* then text of datagram */
    MD5_FINAL(digest, &context);          /* finish up 1st pass */
    /*
     * perform outer MD5
     */
    MD5_INIT(&context);                   /* init context for 2nd
                                           * pass */
    MD5_UPDATE(&context, k_opad, 64);     /* start with outer pad */
    MD5_UPDATE(&context, digest, 16);     /* then results of 1st
                                           * hash */
    MD5_FINAL(digest, &context);          /* finish up 2nd pass */

} /* end hmac_md5() */

/*  EOF: hmac_md5.c */
