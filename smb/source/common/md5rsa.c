/*
 ***********************************************************************
 ** md5.c -- the source code for MD5 routines                         **
 ** RSA Data Security, Inc. MD5 Message-Digest Algorithm              **
 ** Created: 2/17/90 RLR                                              **
 ** Revised: 1/91 SRD,AJ,BSK,JT Reference C ver., 7/10 constant corr. **
 ***********************************************************************
 */

/*
 ***********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved.  **
 **                                                                   **
 ** License to copy and use this software is granted provided that    **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message-     **
 ** Digest Algorithm" in all material mentioning or referencing this  **
 ** software or this function.                                        **
 **                                                                   **
 ** License is also granted to make and use derivative works          **
 ** provided that such works are identified as "derived from the RSA  **
 ** Data Security, Inc. MD5 Message-Digest Algorithm" in all          **
 ** material mentioning or referencing the derived work.              **
 **                                                                   **
 ** RSA Data Security, Inc. makes no representations concerning       **
 ** either the merchantability of this software or the suitability    **
 ** of this software for any particular purpose.  It is provided "as  **
 ** is" without express or implied warranty of any kind.              **
 **                                                                   **
 ** These notices must be retained in any copies of any part of this  **
 ** documentation and/or software.                                    **
 ***********************************************************************
 */

#include "smbutil.h" // _YI_

#define INCLUDE_MD5 1

#if (INCLUDE_MD5)
// ********************************************************************
// MD5
// ********************************************************************
/*
 ***********************************************************************
 **  Message-digest routines:                                         **
 **  To form the message digest for a message M                       **
 **    (1) Initialize a context buffer mdContext using MD5Init        **
 **    (2) Call MD5Update on mdContext and M                          **
 **    (3) Call MD5Final on mdContext                                 **
 **  The message digest is now in mdContext->digest[0...15]           **
 ***********************************************************************
 */

#include "md5rsa.h"

/* forward declaration   */
static void Transform(UINT4 *buf, UINT4 *in); /* _yi_ */

static RTSMB_UINT8 PADDING[64] =
{
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G, H and I are basic MD5 functions */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

/* The routine MD5Init initializes the message-digest context
   mdContext. All fields are set to zero.
 */
void MD5Init(MD5_CTX *mdContext)
{
  mdContext->i[0] = mdContext->i[1] = (UINT4)0;

  // Load magic initialization constants.
  mdContext->buf[0] = (UINT4)0x67452301ul;
  mdContext->buf[1] = (UINT4)0xefcdab89ul;
  mdContext->buf[2] = (UINT4)0x98badcfeul;
  mdContext->buf[3] = (UINT4)0x10325476ul;
}

/* The routine MD5Update updates the message-digest context to
   account for the presence of each of the characters inBuf[0..inLen-1]
   in the message whose digest is being computed.
 */
void MD5Update(MD5_CTX *mdContext, RTSMB_UINT8 *inBuf, unsigned int inLen)
{
UINT4 in[16];
int mdi;
unsigned int i, ii;

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* update number of bits */
  if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
    mdContext->i[1]++;
  mdContext->i[0] += ((UINT4)inLen << 3);
  mdContext->i[1] += ((UINT4)inLen >> 29);

  while (inLen--)
  {
    /* add new character to buffer, increment mdi */
    mdContext->in[mdi++] = *inBuf++;

    /* transform if necessary */
    if (mdi == 0x40)
    {
      for (i = 0, ii = 0; i < 16; i++, ii += 4)
      {
        in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
                (((UINT4)mdContext->in[ii+2]) << 16) |
                (((UINT4)mdContext->in[ii+1]) << 8) |
                ((UINT4)mdContext->in[ii]);
      }
      Transform(mdContext->buf, in);
      mdi = 0;
    }
  }
}

/* The routine MD5Final terminates the message-digest computation and
   ends with the desired message digest in mdContext->digest[0...15].
 */
void MD5Final(MD5_CTX *mdContext)
{
UINT4 in[16];
int mdi;
unsigned int i, ii;
unsigned int padLen;

  /* save number of bits */
  in[14] = mdContext->i[0];
  in[15] = mdContext->i[1];

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* pad out to 56 mod 64 */
  padLen = (unsigned int) ((mdi < 56) ? (56 - mdi) : (120 - mdi));
  MD5Update (mdContext, PADDING, padLen);

  /* append length in bits and transform */
  for (i = 0, ii = 0; i < 14; i++, ii += 4)
    in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
            (((UINT4)mdContext->in[ii+2]) << 16) |
            (((UINT4)mdContext->in[ii+1]) << 8)  |
            ((UINT4)mdContext->in[ii]);
  Transform(mdContext->buf, in);

  /* store buffer in digest */
  for (i = 0, ii = 0; i < 4; i++, ii += 4)
  {
    mdContext->digest[ii] = (RTSMB_UINT8)(mdContext->buf[i] & 0xFF);
    mdContext->digest[ii+1] =
      (RTSMB_UINT8)((mdContext->buf[i] >> 8) & 0xFF);
    mdContext->digest[ii+2] =
      (RTSMB_UINT8)((mdContext->buf[i] >> 16) & 0xFF);
    mdContext->digest[ii+3] =
      (RTSMB_UINT8)((mdContext->buf[i] >> 24) & 0xFF);
  }
}

// Basic MD5 step. Transforms buf based on in.
static void Transform(UINT4 *buf, UINT4 *in) /* _yi_ RTIP_STATIC */
{
UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

  /* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22

  FF ( a, b, c, d, in[ 0], S11, 3614090360ul); /* 1 */
  FF ( d, a, b, c, in[ 1], S12, 3905402710ul); /* 2 */
  FF ( c, d, a, b, in[ 2], S13,  606105819ul); /* 3 */
  FF ( b, c, d, a, in[ 3], S14, 3250441966ul); /* 4 */
  FF ( a, b, c, d, in[ 4], S11, 4118548399ul); /* 5 */
  FF ( d, a, b, c, in[ 5], S12, 1200080426ul); /* 6 */
  FF ( c, d, a, b, in[ 6], S13, 2821735955ul); /* 7 */
  FF ( b, c, d, a, in[ 7], S14, 4249261313ul); /* 8 */
  FF ( a, b, c, d, in[ 8], S11, 1770035416ul); /* 9 */
  FF ( d, a, b, c, in[ 9], S12, 2336552879ul); /* 10 */
  FF ( c, d, a, b, in[10], S13, 4294925233ul); /* 11 */
  FF ( b, c, d, a, in[11], S14, 2304563134ul); /* 12 */
  FF ( a, b, c, d, in[12], S11, 1804603682ul); /* 13 */
  FF ( d, a, b, c, in[13], S12, 4254626195ul); /* 14 */
  FF ( c, d, a, b, in[14], S13, 2792965006ul); /* 15 */
  FF ( b, c, d, a, in[15], S14, 1236535329ul); /* 16 */

  /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
  GG ( a, b, c, d, in[ 1], S21, 4129170786ul); /* 17 */
  GG ( d, a, b, c, in[ 6], S22, 3225465664ul); /* 18 */
  GG ( c, d, a, b, in[11], S23,  643717713ul); /* 19 */
  GG ( b, c, d, a, in[ 0], S24, 3921069994ul); /* 20 */
  GG ( a, b, c, d, in[ 5], S21, 3593408605ul); /* 21 */
  GG ( d, a, b, c, in[10], S22,   38016083ul); /* 22 */
  GG ( c, d, a, b, in[15], S23, 3634488961ul); /* 23 */
  GG ( b, c, d, a, in[ 4], S24, 3889429448ul); /* 24 */
  GG ( a, b, c, d, in[ 9], S21,  568446438ul); /* 25 */
  GG ( d, a, b, c, in[14], S22, 3275163606ul); /* 26 */
  GG ( c, d, a, b, in[ 3], S23, 4107603335ul); /* 27 */
  GG ( b, c, d, a, in[ 8], S24, 1163531501ul); /* 28 */
  GG ( a, b, c, d, in[13], S21, 2850285829ul); /* 29 */
  GG ( d, a, b, c, in[ 2], S22, 4243563512ul); /* 30 */
  GG ( c, d, a, b, in[ 7], S23, 1735328473ul); /* 31 */
  GG ( b, c, d, a, in[12], S24, 2368359562ul); /* 32 */

  /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
  HH ( a, b, c, d, in[ 5], S31, 4294588738ul); /* 33 */
  HH ( d, a, b, c, in[ 8], S32, 2272392833ul); /* 34 */
  HH ( c, d, a, b, in[11], S33, 1839030562ul); /* 35 */
  HH ( b, c, d, a, in[14], S34, 4259657740ul); /* 36 */
  HH ( a, b, c, d, in[ 1], S31, 2763975236ul); /* 37 */
  HH ( d, a, b, c, in[ 4], S32, 1272893353ul); /* 38 */
  HH ( c, d, a, b, in[ 7], S33, 4139469664ul); /* 39 */
  HH ( b, c, d, a, in[10], S34, 3200236656ul); /* 40 */
  HH ( a, b, c, d, in[13], S31,  681279174ul); /* 41 */
  HH ( d, a, b, c, in[ 0], S32, 3936430074ul); /* 42 */
  HH ( c, d, a, b, in[ 3], S33, 3572445317ul); /* 43 */
  HH ( b, c, d, a, in[ 6], S34,   76029189ul); /* 44 */
  HH ( a, b, c, d, in[ 9], S31, 3654602809ul); /* 45 */
  HH ( d, a, b, c, in[12], S32, 3873151461ul); /* 46 */
  HH ( c, d, a, b, in[15], S33,  530742520ul); /* 47 */
  HH ( b, c, d, a, in[ 2], S34, 3299628645ul); /* 48 */

  /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
  II ( a, b, c, d, in[ 0], S41, 4096336452ul); /* 49 */
  II ( d, a, b, c, in[ 7], S42, 1126891415ul); /* 50 */
  II ( c, d, a, b, in[14], S43, 2878612391ul); /* 51 */
  II ( b, c, d, a, in[ 5], S44, 4237533241ul); /* 52 */
  II ( a, b, c, d, in[12], S41, 1700485571ul); /* 53 */
  II ( d, a, b, c, in[ 3], S42, 2399980690ul); /* 54 */
  II ( c, d, a, b, in[10], S43, 4293915773ul); /* 55 */
  II ( b, c, d, a, in[ 1], S44, 2240044497ul); /* 56 */
  II ( a, b, c, d, in[ 8], S41, 1873313359ul); /* 57 */
  II ( d, a, b, c, in[15], S42, 4264355552ul); /* 58 */
  II ( c, d, a, b, in[ 6], S43, 2734768916ul); /* 59 */
  II ( b, c, d, a, in[13], S44, 1309151649ul); /* 60 */
  II ( a, b, c, d, in[ 4], S41, 4149444226ul); /* 61 */
  II ( d, a, b, c, in[11], S42, 3174756917ul); /* 62 */
  II ( c, d, a, b, in[ 2], S43,  718787259ul); /* 63 */
  II ( b, c, d, a, in[ 9], S44, 3951481745ul); /* 64 */

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}
#endif      // INCLUDE_MD5
