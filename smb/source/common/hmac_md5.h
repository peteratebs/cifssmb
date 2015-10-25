/* Last edit: Wed Sep 20 14:20:52 2006
 * By: Yigal Hochberg
 */

/**
 * \file hmac_md5.h
 *
 * \brief hmac md5 function prototypes and related definitions.
 *
 * \date Wed Sep 20 2006
 *
 * \version $Id$
 */

#ifndef HMAC_MD5_H
#define HMAC_MD5_H

/*
 * Function: hmac_md5
 * RFC 2104  HMAC  February 1997
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
;

#endif /* HMAC_MD5_H */

/*  EOF: hmac_md5.h */
