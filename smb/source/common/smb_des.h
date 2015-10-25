/* crypto/des/des_locl.h */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef RTSMB_HEADER_DES_LOCL_H
#define RTSMB_HEADER_DES_LOCL_H

#ifndef RTSMB_DES_LONG
#define RTSMB_DES_LONG unsigned long
#endif

#if defined(WIN32) || defined(WIN16)
#ifndef MSDOS
#define MSDOS
#endif
#endif

//#include <math.h>

#ifdef RTSMB_NO_DES
#error DES is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

typedef unsigned char rtsmb_des_cblock[8];
typedef /* const */ unsigned char const_rtsmb_des_cblock[8];
/* With "const", gcc 2.8.1 on Solaris thinks that rtsmb_des_cblock *
 * and const_rtsmb_des_cblock * are incompatible pointer types. */

typedef struct rtsmb_des_ks_struct
	{
	union	{
		rtsmb_des_cblock cblock;
		/* make sure things are correct size on machines with
		 * 8 byte longs */
		RTSMB_DES_LONG deslong[2];
		} ks;
	int weak_key;
	} rtsmb_des_key_schedule[16];

#define RTSMB_DES_KEY_SZ 	(sizeof(rtsmb_des_cblock))
#define RTSMB_DES_SCHEDULE_SZ (sizeof(rtsmb_des_key_schedule))

#define RTSMB_DES_ENCRYPT	1
#define RTSMB_DES_DECRYPT	0

#define RTSMB_DES_CBC_MODE	0
#define RTSMB_DES_PCBC_MODE	1

#define rtsmb_des_ecb2_encrypt(i,o,k1,k2,e) \
	rtsmb_des_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))

#define rtsmb_des_ede2_cbc_encrypt(i,o,l,k1,k2,iv,e) \
	rtsmb_des_ede3_cbc_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(e))

#define rtsmb_des_ede2_cfb64_encrypt(i,o,l,k1,k2,iv,n,e) \
	rtsmb_des_ede3_cfb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n),(e))

#define rtsmb_des_ede2_ofb64_encrypt(i,o,l,k1,k2,iv,n) \
	rtsmb_des_ede3_ofb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n))

extern int rtsmb_des_check_key;	/* defaults to false */
extern int rtsmb_des_rw_mode;		/* defaults to RTSMB_DES_PCBC_MODE */
extern int rtsmb_des_set_weak_key_flag; /* set the weak key flag */

const char *rtsmb_des_options(void);
void rtsmb_des_ecb3_encrypt(const_rtsmb_des_cblock *input, rtsmb_des_cblock *output,
		      rtsmb_des_key_schedule ks1,rtsmb_des_key_schedule ks2,
		      rtsmb_des_key_schedule ks3, int enc);
RTSMB_DES_LONG rtsmb_des_cbc_cksum(const unsigned char *input,rtsmb_des_cblock *output,
		       long length,rtsmb_des_key_schedule schedule,
		       const_rtsmb_des_cblock *ivec);
/* rtsmb_des_cbc_encrypt does not update the IV!  Use rtsmb_des_ncbc_encrypt instead. */
void rtsmb_des_cbc_encrypt(const unsigned char *input,unsigned char *output,
		     long length,rtsmb_des_key_schedule schedule,rtsmb_des_cblock *ivec,
		     int enc);
void rtsmb_des_ncbc_encrypt(const unsigned char *input,unsigned char *output,
		      long length,rtsmb_des_key_schedule schedule,rtsmb_des_cblock *ivec,
		      int enc);
void rtsmb_des_xcbc_encrypt(const unsigned char *input,unsigned char *output,
		      long length,rtsmb_des_key_schedule schedule,rtsmb_des_cblock *ivec,
		      const_rtsmb_des_cblock *inw,const_rtsmb_des_cblock *outw,int enc);
void rtsmb_des_cfb_encrypt(const unsigned char *in,unsigned char *out,int numbits,
		     long length,rtsmb_des_key_schedule schedule,rtsmb_des_cblock *ivec,
		     int enc);
void rtsmb_des_ecb_encrypt(const_rtsmb_des_cblock *input,rtsmb_des_cblock *output,
		     rtsmb_des_key_schedule ks,int enc);

/* 	This is the DES encryption function that gets called by just about
	every other DES routine in the library.  You should not use this
	function except to implement 'modes' of DES.  I say this because the
	functions that call this routine do the conversion from 'char *' to
	long, and this needs to be done to make sure 'non-aligned' memory
	access do not occur.  The characters are loaded 'little endian'.
	Data is a pointer to 2 unsigned long's and ks is the
	rtsmb_des_key_schedule to use.  enc, is non zero specifies encryption,
	zero if decryption. */
void rtsmb_des_encrypt(RTSMB_DES_LONG *data,rtsmb_des_key_schedule ks, int enc);

/* 	This functions is the same as rtsmb_des_encrypt() except that the DES
	initial permutation (IP) and final permutation (FP) have been left
	out.  As for rtsmb_des_encrypt(), you should not use this function.
	It is used by the routines in the library that implement triple DES.
	IP() rtsmb_des_encrypt2() rtsmb_des_encrypt2() rtsmb_des_encrypt2() FP() is the same
	as rtsmb_des_encrypt() rtsmb_des_encrypt() rtsmb_des_encrypt() except faster :-). */
void rtsmb_des_encrypt2(RTSMB_DES_LONG *data,rtsmb_des_key_schedule ks, int enc);

void rtsmb_des_encrypt3(RTSMB_DES_LONG *data, rtsmb_des_key_schedule ks1,
	rtsmb_des_key_schedule ks2, rtsmb_des_key_schedule ks3);
void rtsmb_des_decrypt3(RTSMB_DES_LONG *data, rtsmb_des_key_schedule ks1,
	rtsmb_des_key_schedule ks2, rtsmb_des_key_schedule ks3);
void rtsmb_des_ede3_cbc_encrypt(const unsigned char *input,unsigned char *output, 
			  long length,
			  rtsmb_des_key_schedule ks1,rtsmb_des_key_schedule ks2,
			  rtsmb_des_key_schedule ks3,rtsmb_des_cblock *ivec,int enc);
void rtsmb_des_ede3_cbcm_encrypt(const unsigned char *in,unsigned char *out,
			   long length,
			   rtsmb_des_key_schedule ks1,rtsmb_des_key_schedule ks2,
			   rtsmb_des_key_schedule ks3,
			   rtsmb_des_cblock *ivec1,rtsmb_des_cblock *ivec2,
			   int enc);
void rtsmb_des_ede3_cfb64_encrypt(const unsigned char *in,unsigned char *out,
			    long length,rtsmb_des_key_schedule ks1,
			    rtsmb_des_key_schedule ks2,rtsmb_des_key_schedule ks3,
			    rtsmb_des_cblock *ivec,int *num,int enc);
void rtsmb_des_ede3_ofb64_encrypt(const unsigned char *in,unsigned char *out,
			    long length,rtsmb_des_key_schedule ks1,
			    rtsmb_des_key_schedule ks2,rtsmb_des_key_schedule ks3,
			    rtsmb_des_cblock *ivec,int *num);

void rtsmb_des_xwhite_in2out(const_rtsmb_des_cblock *rtsmb_des_key,const_rtsmb_des_cblock *in_white,
		       rtsmb_des_cblock *out_white);

int rtsmb_des_enc_read(int fd,void *buf,int len,rtsmb_des_key_schedule sched,
		 rtsmb_des_cblock *iv);
int rtsmb_des_enc_write(int fd,const void *buf,int len,rtsmb_des_key_schedule sched,
		  rtsmb_des_cblock *iv);
char *rtsmb_des_fcrypt(const char *buf,const char *salt, char *ret);
char *rtsmb_des_crypt(const char *buf,const char *salt);
#if !defined(PERL5) && !defined(__FreeBSD__) && !defined(NeXT)
char *crypt(const char *buf,const char *salt);
#endif
void rtsmb_des_ofb_encrypt(const unsigned char *in,unsigned char *out,int numbits,
		     long length,rtsmb_des_key_schedule schedule,rtsmb_des_cblock *ivec);
void rtsmb_des_pcbc_encrypt(const unsigned char *input,unsigned char *output,
		      long length,rtsmb_des_key_schedule schedule,rtsmb_des_cblock *ivec,
		      int enc);
RTSMB_DES_LONG rtsmb_des_quad_cksum(const unsigned char *input,rtsmb_des_cblock output[],
			long length,int out_count,rtsmb_des_cblock *seed);
void rtsmb_des_random_seed(rtsmb_des_cblock *key);
int rtsmb_des_random_key(rtsmb_des_cblock *ret);
int rtsmb_des_read_password(rtsmb_des_cblock *key,const char *prompt,int verify);
int rtsmb_des_read_2passwords(rtsmb_des_cblock *key1,rtsmb_des_cblock *key2,
			const char *prompt,int verify);
int rtsmb_des_read_pw_string(char *buf,int length,const char *prompt,int verify);
void rtsmb_des_set_odd_parity(rtsmb_des_cblock *key);
int rtsmb_des_check_key_parity(const_rtsmb_des_cblock *key);
int rtsmb_des_is_weak_key(const_rtsmb_des_cblock *key);
/* rtsmb_des_set_key (= set_key = rtsmb_des_key_sched = key_sched) calls
 * rtsmb_des_set_key_checked if global variable rtsmb_des_check_key is set,
 * rtsmb_des_set_key_unchecked otherwise. */
int rtsmb_des_set_key(const_rtsmb_des_cblock *key,rtsmb_des_key_schedule schedule);
int rtsmb_des_key_sched(const_rtsmb_des_cblock *key,rtsmb_des_key_schedule schedule);
int rtsmb_des_set_key_checked(const_rtsmb_des_cblock *key,rtsmb_des_key_schedule schedule);
void rtsmb_des_set_key_unchecked(const_rtsmb_des_cblock *key,rtsmb_des_key_schedule schedule);
void rtsmb_des_string_to_key(const char *str,rtsmb_des_cblock *key);
void rtsmb_des_string_to_2keys(const char *str,rtsmb_des_cblock *key1,rtsmb_des_cblock *key2);
void rtsmb_des_cfb64_encrypt(const unsigned char *in,unsigned char *out,long length,
		       rtsmb_des_key_schedule schedule,rtsmb_des_cblock *ivec,int *num,
		       int enc);
void rtsmb_des_ofb64_encrypt(const unsigned char *in,unsigned char *out,long length,
		       rtsmb_des_key_schedule schedule,rtsmb_des_cblock *ivec,int *num);
int rtsmb_des_read_pw(char *buf,char *buff,int size,const char *prompt,int verify);

/* The following definitions provide compatibility with the MIT Kerberos
 * library. The rtsmb_des_key_schedule structure is not binary compatible. */

#define _KERBEROS_DES_H

#define KRBDES_ENCRYPT RTSMB_DES_ENCRYPT
#define KRBDES_DECRYPT RTSMB_DES_DECRYPT

#ifdef KERBEROS
#  define ENCRYPT RTSMB_DES_ENCRYPT
#  define DECRYPT RTSMB_DES_DECRYPT
#endif

#ifndef NCOMPAT
#  define C_Block rtsmb_des_cblock
#  define Key_schedule rtsmb_des_key_schedule
#  define KEY_SZ RTSMB_DES_KEY_SZ
#  define string_to_key rtsmb_des_string_to_key
#  define read_pw_string rtsmb_des_read_pw_string
#  define random_key rtsmb_des_random_key
#  define pcbc_encrypt rtsmb_des_pcbc_encrypt
#  define set_key rtsmb_des_set_key
#  define key_sched rtsmb_des_key_sched
#  define ecb_encrypt rtsmb_des_ecb_encrypt
#  define cbc_encrypt rtsmb_des_cbc_encrypt
#  define ncbc_encrypt rtsmb_des_ncbc_encrypt
#  define xcbc_encrypt rtsmb_des_xcbc_encrypt
#  define cbc_cksum rtsmb_des_cbc_cksum
#  define quad_cksum rtsmb_des_quad_cksum
#  define check_parity rtsmb_des_check_key_parity
#endif

typedef rtsmb_des_key_schedule bit_64;
#define rtsmb_des_fixup_key_parity rtsmb_des_set_odd_parity

#ifdef  __cplusplus
}
#endif

#include "rtprot.h"

#define ITERATIONS 16
#define HALF_ITERATIONS 8

/* used in rtsmb_des_read and rtsmb_des_write */
#define MAXWRITE	(1024*16)
#define BSIZE		(MAXWRITE+4)

#define c2l(c,l)	(l =((RTSMB_DES_LONG)(*((c)++)))    , \
			 l|=((RTSMB_DES_LONG)(*((c)++)))<< 8L, \
			 l|=((RTSMB_DES_LONG)(*((c)++)))<<16L, \
			 l|=((RTSMB_DES_LONG)(*((c)++)))<<24L)

/* NOTE - c is not incremented as per c2l */
#define c2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((RTSMB_DES_LONG)(*(--(c))))<<24L; \
			case 7: l2|=((RTSMB_DES_LONG)(*(--(c))))<<16L; \
			case 6: l2|=((RTSMB_DES_LONG)(*(--(c))))<< 8L; \
			case 5: l2|=((RTSMB_DES_LONG)(*(--(c))));     \
			case 4: l1 =((RTSMB_DES_LONG)(*(--(c))))<<24L; \
			case 3: l1|=((RTSMB_DES_LONG)(*(--(c))))<<16L; \
			case 2: l1|=((RTSMB_DES_LONG)(*(--(c))))<< 8L; \
			case 1: l1|=((RTSMB_DES_LONG)(*(--(c))));     \
				} \
			}

#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24L)&0xff))

/* replacements for htonl and ntohl since I have no idea what to do
 * when faced with machines with 8 byte longs. */
#define HDRSIZE 4

#define n2l(c,l)	(l =((RTSMB_DES_LONG)(*((c)++)))<<24L, \
			 l|=((RTSMB_DES_LONG)(*((c)++)))<<16L, \
			 l|=((RTSMB_DES_LONG)(*((c)++)))<< 8L, \
			 l|=((RTSMB_DES_LONG)(*((c)++))))

#define l2n(l,c)	(*((c)++)=(unsigned char)(((l)>>24L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
			 *((c)++)=(unsigned char)(((l)     )&0xff))

/* NOTE - c is not incremented as per l2c */
#define l2cn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)>>24L)&0xff); \
			case 7: *(--(c))=(unsigned char)(((l2)>>16L)&0xff); \
			case 6: *(--(c))=(unsigned char)(((l2)>> 8L)&0xff); \
			case 5: *(--(c))=(unsigned char)(((l2)     )&0xff); \
			case 4: *(--(c))=(unsigned char)(((l1)>>24L)&0xff); \
			case 3: *(--(c))=(unsigned char)(((l1)>>16L)&0xff); \
			case 2: *(--(c))=(unsigned char)(((l1)>> 8L)&0xff); \
			case 1: *(--(c))=(unsigned char)(((l1)     )&0xff); \
				} \
			}

#if defined(WIN32) && defined(_MSC_VER)
#define	ROTATE(a,n)	(rtp_lrotr(a,n))
#else
#define	ROTATE(a,n)	(((a)>>(n))+((a)<<(32-(n))))
#endif

/* Don't worry about the LOAD_DATA() stuff, that is used by
 * fcrypt() to add it's little bit to the front */

#ifdef RTSMB_DES_FCRYPT

#define LOAD_DATA_tmp(R,S,u,t,E0,E1) \
	{ RTSMB_DES_LONG tmp; LOAD_DATA(R,S,u,t,E0,E1,tmp); }

#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
	t=R^(R>>16L); \
	u=t&E0; t&=E1; \
	tmp=(u<<16); u^=R^s[S  ]; u^=tmp; \
	tmp=(t<<16); t^=R^s[S+1]; t^=tmp
#else
#define LOAD_DATA_tmp(a,b,c,d,e,f) LOAD_DATA(a,b,c,d,e,f,g)
#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
	u=R^s[S  ]; \
	t=R^s[S+1]
#endif

/* The changes to this macro may help or hinder, depending on the
 * compiler and the architecture.  gcc2 always seems to do well :-).
 * Inspired by Dana How <how@isl.stanford.edu>
 * DO NOT use the alternative version on machines with 8 byte longs.
 * It does not seem to work on the Alpha, even when RTSMB_DES_LONG is 4
 * bytes, probably an issue of accessing non-word aligned objects :-( */
#ifdef RTSMB_DES_PTR

/* It recently occurred to me that 0^0^0^0^0^0^0 == 0, so there
 * is no reason to not xor all the sub items together.  This potentially
 * saves a register since things can be xored directly into L */

#if defined(RTSMB_DES_RISC1) || defined(RTSMB_DES_RISC2)
#ifdef RTSMB_DES_RISC1
#define D_ENCRYPT(LL,R,S) { \
	unsigned int u1,u2,u3; \
	LOAD_DATA(R,S,u,t,E0,E1,u1); \
	u2=(int)u>>8L; \
	u1=(int)u&0xfc; \
	u2&=0xfc; \
	t=ROTATE(t,4); \
	u>>=16L; \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP      +u1); \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x200+u2); \
	u3=(int)(u>>8L); \
	u1=(int)u&0xfc; \
	u3&=0xfc; \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x400+u1); \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x600+u3); \
	u2=(int)t>>8L; \
	u1=(int)t&0xfc; \
	u2&=0xfc; \
	t>>=16L; \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x100+u1); \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x300+u2); \
	u3=(int)t>>8L; \
	u1=(int)t&0xfc; \
	u3&=0xfc; \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x500+u1); \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x700+u3); }
#endif
#ifdef RTSMB_DES_RISC2
#define D_ENCRYPT(LL,R,S) { \
	unsigned int u1,u2,s1,s2; \
	LOAD_DATA(R,S,u,t,E0,E1,u1); \
	u2=(int)u>>8L; \
	u1=(int)u&0xfc; \
	u2&=0xfc; \
	t=ROTATE(t,4); \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP      +u1); \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x200+u2); \
	s1=(int)(u>>16L); \
	s2=(int)(u>>24L); \
	s1&=0xfc; \
	s2&=0xfc; \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x400+s1); \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x600+s2); \
	u2=(int)t>>8L; \
	u1=(int)t&0xfc; \
	u2&=0xfc; \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x100+u1); \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x300+u2); \
	s1=(int)(t>>16L); \
	s2=(int)(t>>24L); \
	s1&=0xfc; \
	s2&=0xfc; \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x500+s1); \
	LL^= *(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x700+s2); }
#endif
#else
#define D_ENCRYPT(LL,R,S) { \
	LOAD_DATA_tmp(R,S,u,t,E0,E1); \
	t=ROTATE(t,4); \
	LL^= \
	*(const RTSMB_DES_LONG *)(rtsmb_des_SP      +((u     )&0xfc))^ \
	*(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x200+((u>> 8L)&0xfc))^ \
	*(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x400+((u>>16L)&0xfc))^ \
	*(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x600+((u>>24L)&0xfc))^ \
	*(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x100+((t     )&0xfc))^ \
	*(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x300+((t>> 8L)&0xfc))^ \
	*(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x500+((t>>16L)&0xfc))^ \
	*(const RTSMB_DES_LONG *)(rtsmb_des_SP+0x700+((t>>24L)&0xfc)); }
#endif

#else /* original version */

#if defined(RTSMB_DES_RISC1) || defined(RTSMB_DES_RISC2)
#ifdef RTSMB_DES_RISC1
#define D_ENCRYPT(LL,R,S) {\
	unsigned int u1,u2,u3; \
	LOAD_DATA(R,S,u,t,E0,E1,u1); \
	u>>=2L; \
	t=ROTATE(t,6); \
	u2=(int)u>>8L; \
	u1=(int)u&0x3f; \
	u2&=0x3f; \
	u>>=16L; \
	LL^=rtsmb_des_SPtrans[0][u1]; \
	LL^=rtsmb_des_SPtrans[2][u2]; \
	u3=(int)u>>8L; \
	u1=(int)u&0x3f; \
	u3&=0x3f; \
	LL^=rtsmb_des_SPtrans[4][u1]; \
	LL^=rtsmb_des_SPtrans[6][u3]; \
	u2=(int)t>>8L; \
	u1=(int)t&0x3f; \
	u2&=0x3f; \
	t>>=16L; \
	LL^=rtsmb_des_SPtrans[1][u1]; \
	LL^=rtsmb_des_SPtrans[3][u2]; \
	u3=(int)t>>8L; \
	u1=(int)t&0x3f; \
	u3&=0x3f; \
	LL^=rtsmb_des_SPtrans[5][u1]; \
	LL^=rtsmb_des_SPtrans[7][u3]; }
#endif
#ifdef RTSMB_DES_RISC2
#define D_ENCRYPT(LL,R,S) {\
	unsigned int u1,u2,s1,s2; \
	LOAD_DATA(R,S,u,t,E0,E1,u1); \
	u>>=2L; \
	t=ROTATE(t,6); \
	u2=(int)u>>8L; \
	u1=(int)u&0x3f; \
	u2&=0x3f; \
	LL^=rtsmb_des_SPtrans[0][u1]; \
	LL^=rtsmb_des_SPtrans[2][u2]; \
	s1=(int)u>>16L; \
	s2=(int)u>>24L; \
	s1&=0x3f; \
	s2&=0x3f; \
	LL^=rtsmb_des_SPtrans[4][s1]; \
	LL^=rtsmb_des_SPtrans[6][s2]; \
	u2=(int)t>>8L; \
	u1=(int)t&0x3f; \
	u2&=0x3f; \
	LL^=rtsmb_des_SPtrans[1][u1]; \
	LL^=rtsmb_des_SPtrans[3][u2]; \
	s1=(int)t>>16; \
	s2=(int)t>>24L; \
	s1&=0x3f; \
	s2&=0x3f; \
	LL^=rtsmb_des_SPtrans[5][s1]; \
	LL^=rtsmb_des_SPtrans[7][s2]; }
#endif

#else

#define D_ENCRYPT(LL,R,S) {\
	LOAD_DATA_tmp(R,S,u,t,E0,E1); \
	t=ROTATE(t,4); \
	LL^=\
		rtsmb_des_SPtrans[0][(u>> 2L)&0x3f]^ \
		rtsmb_des_SPtrans[2][(u>>10L)&0x3f]^ \
		rtsmb_des_SPtrans[4][(u>>18L)&0x3f]^ \
		rtsmb_des_SPtrans[6][(u>>26L)&0x3f]^ \
		rtsmb_des_SPtrans[1][(t>> 2L)&0x3f]^ \
		rtsmb_des_SPtrans[3][(t>>10L)&0x3f]^ \
		rtsmb_des_SPtrans[5][(t>>18L)&0x3f]^ \
		rtsmb_des_SPtrans[7][(t>>26L)&0x3f]; }
#endif
#endif

	/* IP and FP
	 * The problem is more of a geometric problem that random bit fiddling.
	 0  1  2  3  4  5  6  7      62 54 46 38 30 22 14  6
	 8  9 10 11 12 13 14 15      60 52 44 36 28 20 12  4
	16 17 18 19 20 21 22 23      58 50 42 34 26 18 10  2
	24 25 26 27 28 29 30 31  to  56 48 40 32 24 16  8  0

	32 33 34 35 36 37 38 39      63 55 47 39 31 23 15  7
	40 41 42 43 44 45 46 47      61 53 45 37 29 21 13  5
	48 49 50 51 52 53 54 55      59 51 43 35 27 19 11  3
	56 57 58 59 60 61 62 63      57 49 41 33 25 17  9  1

	The output has been subject to swaps of the form
	0 1 -> 3 1 but the odd and even bits have been put into
	2 3    2 0
	different words.  The main trick is to remember that
	t=((l>>size)^r)&(mask);
	r^=t;
	l^=(t<<size);
	can be used to swap and move bits between words.

	So l =  0  1  2  3  r = 16 17 18 19
	        4  5  6  7      20 21 22 23
	        8  9 10 11      24 25 26 27
	       12 13 14 15      28 29 30 31
	becomes (for size == 2 and mask == 0x3333)
	   t =   2^16  3^17 -- --   l =  0  1 16 17  r =  2  3 18 19
		 6^20  7^21 -- --        4  5 20 21       6  7 22 23
		10^24 11^25 -- --        8  9 24 25      10 11 24 25
		14^28 15^29 -- --       12 13 28 29      14 15 28 29

	Thanks for hints from Richard Outerbridge - he told me IP&FP
	could be done in 15 xor, 10 shifts and 5 ands.
	When I finally started to think of the problem in 2D
	I first got ~42 operations without xors.  When I remembered
	how to use xors :-) I got it to its final state.
	*/
#define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
	(b)^=(t),\
	(a)^=((t)<<(n)))

#define IP(l,r) \
	{ \
	register RTSMB_DES_LONG tt; \
	PERM_OP(r,l,tt, 4,0x0f0f0f0fL); \
	PERM_OP(l,r,tt,16,0x0000ffffL); \
	PERM_OP(r,l,tt, 2,0x33333333L); \
	PERM_OP(l,r,tt, 8,0x00ff00ffL); \
	PERM_OP(r,l,tt, 1,0x55555555L); \
	}

#define FP(l,r) \
	{ \
	register RTSMB_DES_LONG tt; \
	PERM_OP(l,r,tt, 1,0x55555555L); \
	PERM_OP(r,l,tt, 8,0x00ff00ffL); \
	PERM_OP(l,r,tt, 2,0x33333333L); \
	PERM_OP(r,l,tt,16,0x0000ffffL); \
	PERM_OP(l,r,tt, 4,0x0f0f0f0fL); \
	}

extern const RTSMB_DES_LONG rtsmb_des_SPtrans[8][64];

void fcrypt_body(RTSMB_DES_LONG *out,rtsmb_des_key_schedule ks,
	RTSMB_DES_LONG Eswap0, RTSMB_DES_LONG Eswap1);
	
#endif
