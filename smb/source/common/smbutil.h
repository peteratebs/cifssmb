#ifndef __SMB_UTIL_H__
#define __SMB_UTIL_H__

#include "smbdefs.h"
#include "rtpdutil.h"

/* A and B are bit fields.
   Returns one if all of B's on-bits are on in A, zero else. */
#define ON(A, B)	((BBOOL) ((((A) & (B)) == (B)) ? TRUE : FALSE))

/* A and B are bit fields.
   Returns one if all of B's on-bits are off in A, zero else. */
#define OFF(A, B)	((BBOOL) ((((~(A)) & (B)) == (B)) ? TRUE : FALSE))

/* A and B are bit fields.
   Turns all of B's on-bits to on in A. */
#define TURN_ON(A, B)	{(A) |= (B);}

/* A and B are bit fields.
   Turns all of B's on-bits to off in A. */
#define TURN_OFF(A, B)	{(A) &= ~(B);}

/* if A is false, return B */
#define ASSURE(A, B)    {if (!(A))	return B;}

/* if A is false, return */
#define ASSURE_V(A)     {if (!(A))	return;}

/* if A is false, print B and abort */
#define ASSERT(A, B)	{if (!(A))	{RTSMB_DEBUG_OUTPUT_STR(B, RTSMB_DEBUG_TYPE_SYS_DEFINED);\
                                     RTSMB_DEBUG_OUTPUT_STR("\n", RTSMB_DEBUG_TYPE_ASCII); abort ();}}

/* Caclulate ~F  where F is of tye T (ie: (byte)(~((byte) FLAG)) */
#define NOT_FLAG(T, F) ((T)(~((T) F)))
/* if the delay (in ms) has past since base, these evaluate to true */
/* this is done to handle overflows of the millisecond counter correctly */
#define IS_PAST(BASE, DELAY)  (((long) (rtp_get_system_msec () - ((unsigned long)BASE))) >= (long) (DELAY))
#define IS_PAST_THIS(TIME, BASE, DELAY)  (((long) ((TIME) - (BASE))) >= (long) (DELAY))

typedef unsigned short WORD;
typedef unsigned char  BYTE;

void rtsmb_util_unicode_to_ascii (PFWCS str, PFCHAR dest, int codepage);
void rtsmb_util_unicode_to_rtsmb (PFWCS str, PFRTCHAR dest, int codepage);
void rtsmb_util_ascii_to_unicode (PFCHAR str, PFWCS dest, int codepage);
void rtsmb_util_ascii_to_rtsmb (PFCHAR str, PFRTCHAR dest, int codepage);
void rtsmb_util_rtsmb_to_ascii (PFRTCHAR str, PFCHAR dest, int codepage);
void rtsmb_util_rtsmb_to_unicode (PFRTCHAR str, PFWCS dest, int codepage);

//CODEPAGE CONVERSION FUNCTIONS
void rtsmb_util_n_unicode_to_ascii (PFWCS str, PFCHAR dest, int inMax, int outMax, int codepage);
void rtsmb_util_n_ascii_to_unicode (PFCHAR str, PFWCS dest, int inMax, int outMax, int codepage);
void rtsmb_util_unicode_to_latin (PFWCS str, PFCHAR dest);
void rtsmb_util_unicode_to_shiftjis (PFWCS str, PFCHAR dest);
void rtsmb_util_latin_to_unicode (PFCHAR str, PFWCS dest);
void rtsmb_util_shiftjis_to_unicode (PFCHAR str, PFWCS dest);

void rtsmb_util_n_latin_to_unicode (PFCHAR str, PFWCS dest, int inMax, int outMax);
void rtsmb_util_n_shiftjis_to_unicode (PFCHAR str, PFWCS dest, int inMax, int outMax);
void rtsmb_util_n_unicode_to_latin (PFWCS str, PFCHAR dest, int inMax, int outMax);
void rtsmb_util_n_unicode_to_shiftjis (PFWCS str, PFCHAR dest, int inMax, int outMax);

int rtsmb_stricmp_latin (PFCHAR ch1, PFCHAR ch2);
int rtsmb_strnicmp_latin (PFCHAR ch1, PFCHAR ch2, rtsmb_size n) ;
int rtsmb_stricmp_sjis (PFCHAR ch1, PFCHAR ch2);
int rtsmb_strnicmp_sjis (PFCHAR ch1, PFCHAR ch2, rtsmb_size n);
int rtsmb_stricmp_uc (PFRTCHAR ch1, PFRTCHAR ch2);
int rtsmb_strnicmp_uc (PFRTCHAR ch1, PFRTCHAR ch2, rtsmb_size n);


PFRTCHAR rtsmb_util_string_to_upper (PFRTCHAR string, int codepage);
PFCHAR rtsmb_util_latin_string_toupper (PFCHAR string);

PFCHAR rtsmb_util_make_netbios_name (PFCHAR dest, PFCHAR name, byte type);
PFCHAR rtsmb_util_unmake_netbios_name (PFCHAR dest, PFBYTE type, PFCHAR name);



#if (INCLUDE_RTSMB_ENCRYPTION)
PFBYTE cli_util_encrypt_password_pre_nt (PFCHAR password, PFBYTE data, PFBYTE output);
PFBYTE cli_util_encrypt_password_nt (PFCHAR password, PFBYTE data, PFBYTE output);

PFBYTE cli_util_encrypt_password_lmv2 (PFCHAR password, PFBYTE serverChallenge, PFCHAR output,
									   PFBYTE uni_password, PFRTCHAR name, PFRTCHAR domainname); // _YI_
#endif


#if (INCLUDE_RTSMB_UNICODE)
#define rtsmb_len     rtp_wcslen
#define rtsmb_ncpy    rtp_wcsncpy
#define rtsmb_cpy     rtp_wcscpy
#define rtsmb_cmp     rtp_wcscmp
#define rtsmb_ncmp    rtp_wcsncmp
#define rtsmb_cat(a,b) rtp_wcscat(a, (const unsigned short *)(b))
#define rtsmb_chr     rtp_wcschr
#define rtsmb_toupper rtp_towupper
#else
#define rtsmb_len     rtp_strlen
#define rtsmb_ncpy    rtp_strncpy
#define rtsmb_cpy     rtp_strcpy
#define rtsmb_cmp     rtp_strcmp
#define rtsmb_ncmp    rtp_strncmp
#define rtsmb_cat(a,b) rtp_strcat(a, (const char *)(b))
#define rtsmb_chr     rtp_strchr
#define rtsmb_toupper rtp_toupper
#endif

/* some unicode convenience functions */
rtsmb_size rtsmb_util_wlen (PFWCS str);
PFWCS rtsmb_util_wncpy (PFWCS dest, PFWCS source, rtsmb_size count);
PFWCS rtsmb_util_wcpy (PFWCS dest, PFWCS source);
int rtsmb_util_wncmp (PFWCS left, PFWCS right, rtsmb_size count);
int rtsmb_util_wcmp (PFWCS left, PFWCS right);
PFWCS rtsmb_util_wcat (PFWCS dest, PFWCS str);
//PFWCS rtsmb_util_wchr (PFWCS dest, unsigned short c);
unsigned short rtsmb_util_wtoupper (unsigned short c);

int rtsmb_casecmp (PFRTCHAR ch1, PFRTCHAR ch2, int codepage);
int rtsmb_casencmp (PFRTCHAR ch1, PFRTCHAR ch2, rtsmb_size n, int codepage);

/* for ascii strings */
int rtsmb_strcasecmp (PFCHAR s, PFCHAR s2, int codepage);
int rtsmb_strcasencmp (PFCHAR s, PFCHAR s2, rtsmb_size n, int codepage);

int rtsmb_util_unicode_patcmp (PFWCS pat, PFWCS name, BBOOL dowildcard);
int rtsmb_util_ascii_patcmp (PFCHAR pat, PFCHAR name, BBOOL dowildcard);
int rtsmb_util_rtsmb_patcmp (PFRTCHAR pat, PFRTCHAR name, BBOOL dowildcard);

dword    rtsmb_util_time_ms_to_unix       (TIME ms_time);
dword    rtsmb_util_time_date_to_unix     (DATE_STR date);
DATE_STR rtsmb_util_time_unix_to_date     (dword unix_time);
DATE_STR rtsmb_util_time_ms_to_date       (TIME ms_time);
TIME     rtsmb_util_time_unix_to_ms       (dword unix_time);
TIME     rtsmb_util_time_date_to_ms       (DATE_STR date);
TIME     rtsmb_util_time_rtp_date_to_ms   (RTP_DATE rtp_date);
ddword rtsmb_util_get_current_filetime    (void);
dword    rtsmb_util_time_rtp_date_to_unix (RTP_DATE rtp_date);
RTP_DATE rtsmb_util_time_unix_to_rtp_date (dword unix_time);
RTP_DATE rtsmb_util_time_ms_to_rtp_date   (TIME ms_time);
void rtsmb_util_get_new_Guid              (byte *ppGuid);
byte rtsmb_util_smb_to_rtsmb_attributes (word smb_attributes);
word rtsmb_util_rtsmb_to_smb_attributes (byte rtsmb_attributes);

struct CodePageEntry
{
	int codePage;
	void (*toUnicode)(PFCHAR str, PFWCS dest);
	void (*fromUnicode)(PFWCS str, PFCHAR dest);
	int (*stricmp)(PFCHAR s1, PFCHAR s2);
	int (*strnicmp)(PFCHAR s1, PFCHAR s2, rtsmb_size n);
	void (*ntoUnicode)(PFCHAR str, PFWCS dest, int inMax, int outMax);
	void (*nfromUnicode)(PFWCS str, PFCHAR dest, int inMax, int outMax);

};



#endif /* __SMB_UTIL_H__ */
