//
// SMBUTIL.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Functions for Unicode/ASCII/SJIS conversion, string functions and
// time conversion


#include "smbutil.h"
#include "smbnb.h"
#include "smbsjis.h"

#include "rtpdutil.h"
#include "rtpfile.h"
#include "rtptotc.h"
#include "rtpstr.h"
#include "rtpwcs.h"
#include "hmac_md5.h"

//table of codepage function pointers
struct CodePageEntry cpTable[2] =
{
	{1252, rtsmb_util_latin_to_unicode, rtsmb_util_unicode_to_latin, rtsmb_stricmp_latin, rtsmb_strnicmp_latin, rtsmb_util_n_latin_to_unicode, rtsmb_util_n_unicode_to_latin},
	{932, rtsmb_util_shiftjis_to_unicode, rtsmb_util_unicode_to_shiftjis, rtsmb_stricmp_sjis, rtsmb_strnicmp_sjis, rtsmb_util_n_shiftjis_to_unicode, rtsmb_util_n_unicode_to_shiftjis}
};

static const WORD UnicodeMap437[] = // OEM char set, range 0x80..0xFF
{
 0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
 0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
 0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
 0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
 0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
 0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0
};

#if(0)
static const BYTE Upper437[] =
{
 0x80, 0x9A, 0x90, 0x41, 0x8E, 0x41, 0x8F, 0x80, 0x45, 0x45, 0x45, 0x49, 0x49, 0x49,
 0x8E, 0x8F, 0x90, 0x92, 0x92, 0x4F, 0x99, 0x4F, 0x55, 0x55, 0x59, 0x99, 0x9A, 0x9B,
 0x9C, 0x9D, 0x50, 0x9F, 0x41, 0x49, 0x4F, 0x55, 0xA5, 0xA5, 0xA6, 0xA7, 0xA8, 0xAA,
 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0x2B,
 0x2B, 0xDD, 0xDD, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2D, 0x2D, 0x2B, 0x2D, 0x2B,
 0xDD, 0xDD, 0x2B, 0x2B, 0x2D, 0x2D, 0xDD, 0x2D, 0x2B, 0x2D, 0x2D, 0x2D, 0x2D, 0x2B,
 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0xDD, 0x5F, 0xDD, 0xDD, 0x5F, 0x41, 0xE1,
 0x47, 0x50, 0x53, 0x53, 0xE6, 0x54, 0x46, 0x54, 0x4F, 0x44, 0x38, 0x46, 0x45, 0x4E,
 0x3D, 0xF1, 0x3D, 0x3D, 0x28, 0x29, 0xF6, 0x7E, 0xF8, 0xFA, 0xFA, 0x56, 0x4E, 0xFD,
 0xDD, 0xFF
};
static const char * Upper      = (const char*) Upper437;
#endif

static const WORD * UnicodeMap = UnicodeMap437;


static WORD ASCIIToUnicode(signed char c)
{
   return (WORD) ((c >= 0) ? c : (UnicodeMap[(BYTE)c - 0x80]));
}

/*-----------------------------------*/
static char UnicodeToASCII(WORD C)
{
   BYTE i;

   if (C < 0x80)
      return (char) C;
   for (i=0; i<0x80; i++)
      if (UnicodeMap[i] == C)
         return (char) (i+0x80);
   return '_';
}
/*-----------------------------------*/


/* It also mangles the data in the wide character string, transforming it
   to an array of non-wide characters.
*/
void rtsmb_util_unicode_to_ascii(PFWCS str, PFCHAR dest, int codepage)
{
	cpTable[codepage].fromUnicode(str,dest);
}


/* dest buffer must be twice the size of str */
/* note that str and dest may be the same for in-place conversion */
void rtsmb_util_ascii_to_unicode (PFCHAR str, PFWCS dest, int codepage)
{
	cpTable[codepage].toUnicode(str,dest);
}


/* convert up to n characters from unicode string to 8-bit */
/* note that str and dest may be the same for in-place conversion */
void rtsmb_util_n_unicode_to_ascii(PFWCS str, PFCHAR dest, int inMax, int outMax, int codepage)
{
	cpTable[codepage].nfromUnicode(str, dest, inMax, outMax);
}


/* convert up to n characters from 8-bit string to unicode */
/* note that str and dest may be the same for in-place conversion */
void rtsmb_util_n_ascii_to_unicode (PFCHAR str, PFWCS dest, int inMax, int outMax, int codepage)
{
	cpTable[codepage].ntoUnicode(str, dest, inMax, outMax);
}



void rtsmb_util_unicode_to_shiftjis (PFWCS str, PFCHAR dest)
{
	byte temp[2];
	long outPos = 0, inPos = 0, len;
	int sizeOfStr;
	byte * tempDest;

	sizeOfStr = (int)rtsmb_util_wlen(str);
	tempDest = (byte *) dest;
	while (str[inPos] && (inPos < sizeOfStr))
	{
		len = rtsmb_unicode_to_jis (temp, str[inPos]);
		switch (len)
		{
			case 1:
					tempDest[outPos] = temp[0];
					outPos++;
					break;
			case 2:
					tempDest[outPos] = temp[0];
					outPos++;
					tempDest[outPos] = temp[1];
					outPos++;
					break;
		}
		inPos++;
	}
	tempDest[outPos] = '\0';
}

void rtsmb_util_n_unicode_to_shiftjis (PFWCS str, PFCHAR dest, int inMax, int outMax)
{
	byte temp[2];
	long outPos = 0, inPos = 0, len;
	byte * tempDest = (byte *) dest;

	while (str[inPos] && (inPos < inMax) && (outPos < outMax))
	{
		len = rtsmb_unicode_to_jis (temp, str[inPos]);
		if (len == 2)
		{
			//if 2 byte shift-jis char, but only have room for 1 byte
			if (outPos + 1 == outMax)
			{
				break;
			}
		}
		switch (len)
		{
			case 1:
					tempDest[outPos] = temp[0];
					outPos++;
					break;
			case 2:
					tempDest[outPos] = temp[0];
					outPos++;
					tempDest[outPos] = temp[1];
					outPos++;
					break;
		}
		inPos++;
	}
}

void rtsmb_util_unicode_to_latin (PFWCS str, PFCHAR dest)
{
	rtsmb_size i;

	for (i = 0; str[i] != '\0'; i++)
	{
		dest[i] = UnicodeToASCII(str[i]);
	}

	dest[i] = '\0';

}


void rtsmb_util_n_unicode_to_latin (PFWCS str, PFCHAR dest, int inMax, int outMax)
{
	int i;

	for (i = 0; i < inMax && i < outMax && str[i]; i++)
	{
		dest[i] = UnicodeToASCII(str[i]);
	}
}

void rtsmb_util_shiftjis_to_unicode (PFCHAR str, PFWCS dest)
{
	unsigned short tempstr[SMBF_FILENAMESIZE + 1];
	unsigned short i;
	unsigned int destPos = 0;
	unsigned int strPos = 0;

	for (i=0; i < tc_strlen(str);i++)
	{
		strPos += (unsigned int) rtsmb_jis_to_unicode(tempstr + destPos, (PFBYTE) str + strPos);
		destPos++;
	}
	tc_memcpy(dest, tempstr, destPos * 2);
	dest[destPos] = '\0';
}

void rtsmb_util_n_shiftjis_to_unicode (PFCHAR str, PFWCS dest, int inMax, int outMax)
{
	unsigned short tempstr[SMBF_FILENAMESIZE + 1];
	unsigned int destPos = 0;
	unsigned int strPos = 0;

	while ((strPos + JIS_CHAR_LEN(str[strPos]) < (unsigned int)inMax) && (destPos < (unsigned int)outMax))
	{
		strPos += (unsigned int) rtsmb_jis_to_unicode(tempstr + destPos, (PFBYTE) str + strPos);
		destPos++;
	}
	tc_memcpy(dest, tempstr, destPos * 2 /*sizeof(unsigned short)*/);
}


void rtsmb_util_latin_to_unicode (PFCHAR str, PFWCS dest)
{
	rtsmb_size size;
	int i;

	size = (rtsmb_size) tc_strlen (str);
	for (i = (int)size; i >= 0; i--)
	{
	  dest[i] = ASCIIToUnicode(str[i]);
	}
}


void rtsmb_util_n_latin_to_unicode (PFCHAR str, PFWCS dest, int inMax, int outMax)
{
	int i;

	for (i = inMax - 1; i >= 0; i--)
	{
	  if (i < outMax)
	  {
		  dest[i] = ASCIIToUnicode(str[i]);
	  }
	}
}

/* Conversion to and from whatever rtsmb needs  */
void rtsmb_util_unicode_to_rtsmb (PFWCS str, PFRTCHAR dest, int codepage)
{
#if (INCLUDE_RTSMB_UNICODE)
    // This is broken ??
	rtsmb_util_wcpy (dest, str);
#else
	rtsmb_util_unicode_to_ascii (str, (PFCHAR) dest, codepage);
#endif
}

void rtsmb_util_ascii_to_rtsmb (PFCHAR str, PFRTCHAR dest, int codepage)
{
#if (INCLUDE_RTSMB_UNICODE)
	rtsmb_util_ascii_to_unicode (str, (PFWCS) dest, codepage);
#else
	tc_strcpy (dest, str);
#endif
}

void rtsmb_util_rtsmb_to_ascii (PFRTCHAR str, PFCHAR dest, int codepage)
{
#if (INCLUDE_RTSMB_UNICODE)
	rtsmb_util_unicode_to_ascii ((PFWCS) str, dest, codepage);
#else
	tc_strcpy (dest, str);
#endif
}

void rtsmb_util_rtsmb_to_unicode (PFRTCHAR str, PFWCS dest, int codepage)
{
#if !(INCLUDE_RTSMB_UNICODE)
	rtsmb_util_ascii_to_unicode ((PFCHAR) str, dest, codepage);
#else
	rtsmb_util_wcpy (dest, str);
#endif
}


/*  --------------------------------------------------
 *   WIDE CHARACTER STRING FUNCTIONS
 * --------------------------------------------------
 */
rtsmb_size rtsmb_util_wlen (PFWCS str)
{
	rtsmb_size rv = 0;

	while (str[rv] != '\0') {rv++;}

	return rv;
}

PFWCS rtsmb_util_wncpy (PFWCS dest, PFWCS source, rtsmb_size count)
{
	rtsmb_size i;

	for (i = 0; i < count; i++)
	{
		dest[i] = source[i];

		if (source[i] == '\0')
		{
			break;
		}
	}

	return dest;
}

PFWCS rtsmb_util_wcpy (PFWCS dest, PFWCS source)
{
	rtsmb_size i;

	for (i = 0; source[i] != '\0'; i++)
	{
		dest[i] = source[i];
	}

	dest[i] = '\0';

	return dest;
}

int rtsmb_util_wncmp (PFWCS left, PFWCS right, rtsmb_size count)
{
	rtsmb_size i;

	for (i = 0; i < count; i++)
	{
		if (left[i] < right[i])
		{
			return -1;
		}
		else if (left[i] > right[i])
		{
			return 1;
		}

		if (left[i] == '\0' && right[i] == '\0')
		{
			break;
		}
	}

	return 0;
}

int rtsmb_util_wcmp (PFWCS left, PFWCS right)
{
	rtsmb_size i;

	for (i = 0; left[i] != '\0'; i++)
	{
		if (left[i] < right[i])
		{
			return -1;
		}
		else if (left[i] > right[i])
		{
			return 1;
		}

		if (right[i] == '\0')
		{
			return 1;
		}
	}

	if (right[i] == '\0')
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

PFWCS rtsmb_util_wcat (PFWCS dest, PFWCS str)
{
	rtsmb_size i, j;

	/* get to end of dest */
	for (i = 0; dest[i] != '\0'; i++);

	/* start filling in from str */
	for (j = 0; str[j] != '\0'; j++, i++)
	{
		dest[i] = str[j];
	}

	dest[i] = '\0';

	return dest;
}



/*-----------------------------------*/
char rtsmb_util_latin_toupper(signed char c)
{
	//if (c >= 0)
	{
		if ((c >= 'a') && (c <= 'z'))
		{
			return (char) (c - ('a' - 'A'));
		}
		else
		{
			return c;
		}
	}
	//else
	//{
	//	return Upper[(BYTE)c - 0x80];
	//}
}


/*-----------------------------------*/
unsigned short rtsmb_util_wtoupper (unsigned short c)
{
   BYTE i;

   if (c < 0x80)
   {
      return ASCIIToUnicode(rtsmb_util_latin_toupper((char) c));
   }

   for (i=0; i<0x80; i++)
   {
      if (UnicodeMap[i] == c)
	  {
		  return ASCIIToUnicode(rtsmb_util_latin_toupper((char) (i + 0x80)));
	  }
   }

   return c;
}



/*-----------------------------------*/

int rtsmb_casecmp (PFRTCHAR ch1, PFRTCHAR ch2, int codepage)
{
	if (!ch1 || !ch2)
	{
		return 0;
	}
#if(INCLUDE_RTSMB_UNICODE)
	return rtsmb_stricmp_uc (ch1,ch2);
#else
	return cpTable[codepage].stricmp((char *)ch1,(char *)ch2);
#endif
}


/*-----------------------------------*/
int rtsmb_strcasecmp (PFCHAR ch1, PFCHAR ch2, int codepage)
{
	if (!ch1 || !ch2)
	{
		return 0;
	}
	return cpTable[codepage].stricmp(ch1,ch2);
}


/*-----------------------------------*/
int rtsmb_casencmp (PFRTCHAR ch1, PFRTCHAR ch2, rtsmb_size n, int codepage)
{
	if (!ch1 || !ch2)
	{
		return 0;
	}
#if(INCLUDE_RTSMB_UNICODE)
	return rtsmb_stricmp_uc (ch1,ch2);
#else
	return cpTable[codepage].strnicmp((char *) ch1, (char *) ch2, n);
#endif
}

/*-----------------------------------*/
int rtsmb_strcasencmp (PFCHAR ch1, PFCHAR ch2, rtsmb_size n, int codepage)
{
	if (!ch1 || !ch2)
	{
		return 0;
	}
	return cpTable[codepage].strnicmp(ch1,ch2,n);
}

/*-----------------------------------*/

int rtsmb_stricmp_uc (PFRTCHAR ch1, PFRTCHAR ch2)
{
	/* simplistic version that only case neutralizes ascii stuff.  How to
	better? */
#if (INCLUDE_RTSMB_UNICODE)
	rtsmb_size i;

	for (i = 0; ch1[i] && ch2[i]; i++)
	{
		rtsmb_char c1, c2;

      c1 = rtsmb_util_wtoupper(ch1[i]);
      c2 = rtsmb_util_wtoupper(ch2[i]);

		if (c1 < c2)
		{
			return -1;
		}
		else if (c1 > c2)
		{
			return 1;
		}
	}

	if (!ch1[i] && !ch2[i])
	{
		return 0;
	}
	else if (!ch1[i])
	{
		return -1;
	}
	else if (!ch2[i])
	{
		return 1;
	}

	return 0;
#else
	return -1;
#endif
}

int rtsmb_stricmp_latin (PFCHAR ch1, PFCHAR ch2)
{
	/* simplistic version that only case neutralizes ascii stuff.  How to
	better? */
	rtsmb_size i;

	for (i = 0; ch1[i] && ch2[i]; i++)
	{
      BYTE c1, c2;

      c1 = (BYTE) rtsmb_util_latin_toupper(ch1[i]);
      c2 = (BYTE) rtsmb_util_latin_toupper(ch2[i]);

		if (c1 < c2)
		{
			return -1;
		}
		else if (c1 > c2)
		{
			return 1;
		}
	}

	if (!ch1[i] && !ch2[i])
	{
		return 0;
	}
	else if (!ch1[i])
	{
		return -1;
	}
	else if (!ch2[i])
	{
		return 1;
	}

	return 0;
}

int rtsmb_stricmp_sjis (PFCHAR ch1, PFCHAR ch2)
{
	rtsmb_size i;


	for (i = 0; ch1[i] && ch2[i]; i++)
	{
		BYTE c1, c2;
		//new plan
		if ((unsigned char) ch1[i] < 0x80)
		{
			c1 = (BYTE) rtsmb_util_latin_toupper(ch1[i]);
		}
		else
		{
			c1 = (BYTE) ch1[i];
		}
		if ((unsigned char) ch2[i] < 0x80)
		{
			c2 = (BYTE) rtsmb_util_latin_toupper(ch2[i]);
		}
		else
		{
			c2 = (BYTE) ch2[i];
		}

		//now compare
		if (c1 < c2)
		{
			return -1;
		}
		else if (c1 > c2)
		{
			return 1;
		}
	}

	if (!ch1[i] && !ch2[i])
	{
		return 0;
	}
	else if (!ch1[i])
	{
		return -1;
	}
	else if (!ch2[i])
	{
		return 1;
	}

	return 0;
}



int rtsmb_strnicmp_uc (PFRTCHAR ch1, PFRTCHAR ch2, rtsmb_size n)
{
	/* simplistic version that only case neutralizes ascii stuff.  How to
	better? */

#if (INCLUDE_RTSMB_UNICODE)

	rtsmb_size i;

	for (i = 0; i < n && ch1[i] && ch2[i]; i++)
	{
		rtsmb_char c1, c2;

      c1 = rtsmb_util_wtoupper(ch1[i]);
      c2 = rtsmb_util_wtoupper(ch2[i]);

		if (c1 < c2)
		{
			return -1;
		}
		else if (c1 > c2)
		{
			return 1;
		}
	}

	if (i == n)
	{
		return 0;
	}

	if (!ch1[i] && !ch2[i])
	{
		return 0;
	}
	else if (!ch1[i])
	{
		return -1;
	}
	else if (!ch2[i])
	{
		return 1;
	}

	return 0;
#else
	return -1;
#endif
}


int rtsmb_strnicmp_latin (PFCHAR ch1, PFCHAR ch2, rtsmb_size n)
{
	/* simplistic version that only case neutralizes ascii stuff.  How to
	better? */
	rtsmb_size i;

	for (i = 0; i < n && ch1[i] && ch2[i]; i++)
	{
      BYTE c1, c2;

      c1 = (BYTE)rtsmb_util_latin_toupper(ch1[i]);
      c2 = (BYTE)rtsmb_util_latin_toupper(ch2[i]);

		if (c1 < c2)
		{
			return -1;
		}
		else if (c1 > c2)
		{
			return 1;
		}
	}

	if (i == n)
	{
		return 0;
	}

	if (!ch1[i] && !ch2[i])
	{
		return 0;
	}
	else if (!ch1[i])
	{
		return -1;
	}
	else if (!ch2[i])
	{
		return 1;
	}

	return 0;
}

int rtsmb_strnicmp_sjis (PFCHAR ch1, PFCHAR ch2, rtsmb_size n)
{
	/* simplistic version that only case neutralizes ascii stuff.  How to
	better? */
	rtsmb_size i;

	for (i = 0; i < n && ch1[i] && ch2[i]; i++)
	{
		BYTE c1, c2;
 		if ((unsigned char) ch1[i] < 0x80)
		{
			c1 = (BYTE) rtsmb_util_latin_toupper(ch1[i]);
		}
		else
		{
			c1 = (BYTE) ch1[i];
		}
		if ((unsigned char) ch2[i] < 0x80)
		{
			c2 = (BYTE) rtsmb_util_latin_toupper(ch2[i]);
		}
		else
		{
			c2 = (BYTE) ch2[i];
		}

		//now compare
		if ((unsigned char) c1 < (unsigned char) c2)
		{
			return -1;
		}
		else if ((unsigned char) c1 > (unsigned char) c2)
		{
			return 1;
		}
	}

	if (i == n)
	{
		return 0;
	}

	if (!ch1[i] && !ch2[i])
	{
		return 0;
	}
	else if (!ch1[i])
	{
		return -1;
	}
	else if (!ch2[i])
	{
		return 1;
	}

	return 0;

}

/**
 * |dest| and |str| CAN overlap.
 */
PFRTCHAR rtsmb_util_string_to_upper (PFRTCHAR string, int codepage)
{
#if (INCLUDE_RTSMB_UNICODE)
	rtsmb_size size;
	rtsmb_size i;

	size = rtsmb_len (string);
	for (i = 0; i < size; i++)
	{
		string[i] = rtsmb_util_wtoupper (string[i]);
	}

	return string;
#else
	if (codepage == RTSMB_CODEPAGE_SHIFTJIS)
	{
		rtsmb_size size = tc_strlen ((char *)  string);
		rtsmb_size i;

		for (i = 0; i < size; i++)
		{
			if (string[i] < 0x80)
			{
				string [i] = rtsmb_util_latin_toupper ((char) string[i]);
			}
		}
		return string;
	}
	else
	{
		return (rtsmb_char *) rtsmb_util_latin_string_toupper((char *) string);
	}
#endif
}

/**
 * |dest| and |str| CAN overlap.
 */
PFCHAR rtsmb_util_latin_string_toupper (PFCHAR string)
{
	rtsmb_size size;
	rtsmb_size i;

	size = (rtsmb_size) tc_strlen (string);
	for (i = 0; i < size; i++)
	{
		string[i] = rtsmb_util_latin_toupper (string[i]);
	}

	return string;
}

PFCHAR rtsmb_util_make_netbios_name (PFCHAR _dest, PFCHAR _name, byte type)
{
	rtsmb_size i;
	rtsmb_size numchars;
    PFBYTE dest = (PFBYTE)_dest;
    PFBYTE name = (PFBYTE)_name;

	numchars = MIN ((rtsmb_size) tc_strlen (name), RTSMB_NB_NAME_SIZE - 1);

	for(i = 0; i < numchars; i++)
		dest[i] = name[i];
	for(; i < RTSMB_NB_NAME_SIZE; i++)
		dest[i] = ' ';

	dest[RTSMB_NB_NAME_SIZE] = '\0';

	rtsmb_util_latin_string_toupper (dest);

	dest[RTSMB_NB_NAME_SIZE - 1] = type;

	return dest;
}

PFCHAR rtsmb_util_unmake_netbios_name (PFCHAR _dest, PFBYTE type, PFCHAR _name)
{
	int i;
    PFBYTE dest = (PFBYTE)_dest;
    PFBYTE name = (PFBYTE)_name;

	*type = name[RTSMB_NB_NAME_SIZE - 1];

	for (i = RTSMB_NB_NAME_SIZE - 2; i >= 0 && name[i] == ' '; i--);

	tc_strncpy (_dest, _name, (unsigned) i + 1);
	dest[i + 1] = '\0';

	return dest;
}



/*************************************************************************
 * rtsmb_util_unicode_patcmp - Compare a unicode string against a
 *                             pattern using wildcards
 *
 * Parameters:
 *		pat - the pattern to match the string against
 *		name - the string to match
 * 	dowildcard - if set to 0, disables the use of wildcards in doing
 *			the comparison
 *
 * Returns:
 *		1 if the string matches
 *		0 otherwise
 *
 * Examples:
 *		rtsmb_util_unicode_patcmp(L"he*, w*", L"hello, world", 1) returns 1
 *		rtsmb_util_unicode_patcmp(L"*z*", L"hello, world", 1) returns 0
 *		rtsmb_util_unicode_patcmp(L"he?lo, world", L"hello, world", 1) returns 1
 *		rtsmb_util_unicode_patcmp(L"he?lo, world", L"hello, world", 0) returns 0
 *
 *************************************************************************/

int rtsmb_util_unicode_patcmp (PFWCS pat, PFWCS name, BBOOL dowildcard)
{
	int p,n,i;
	int res = 0;
	unsigned short starstar[] = {'*', '.', '*', '\0'};
	unsigned short dot[] = {'.', '\0'};

	if (!rtsmb_util_wcmp(pat, starstar))
	{
		pat[1] = '\0';
	}
	if (!rtsmb_util_wcmp(pat, dot))
	{
		pat[0] = '*';
		pat[1] = '\0';
	}

	for(p=0,n=0; pat[p]!='\0'; p++,n++)
	{
		if (pat[p]=='*' && dowildcard)
		{
			for(i=n; name[i]!=0; i++)
                res |= rtsmb_util_unicode_patcmp(&(pat[p+1]),&(name[i]),dowildcard);
			res |= rtsmb_util_unicode_patcmp(&(pat[p+1]),&(name[i]),dowildcard);
			return(res);
		}

		if (name[n] == 0)
		{
			/* Match * with end of string */
			if (pat[p]=='*' && pat[p+1] == 0 && dowildcard)
				return(1);
			else
				return(0);
		}

		if ((pat[p]!='?' || !dowildcard) && pat[p]!=name[n])
				return(0);

	}
	if (name[n]==0)
		return(1);
	else
		return(0);
}

/*************************************************************************
 * rtsmb_util_ascii_patcmp - Compare a ASCII string against a
 *                             pattern using wildcards
 *
 * Parameters:
 *		pat - the pattern to match the string against
 *		name - the string to match
 * 	dowildcard - if set to 0, disables the use of wildcards in doing
 *			the comparison
 *
 * Returns:
 *		1 if the string matches
 *		0 otherwise
 *
 * Examples:
 *		rtsmb_util_ascii_patcmp("he*, w*", "hello, world", 1) returns 1
 *		rtsmb_util_ascii_patcmp("*z*", "hello, world", 1) returns 0
 *		rtsmb_util_ascii_patcmp("he?lo, world", "hello, world", 1) returns 1
 *		rtsmb_util_ascii_patcmp("he?lo, world", "hello, world", 0) returns 0
 *
 *************************************************************************/

int rtsmb_util_ascii_patcmp (PFCHAR pat, PFCHAR name, BBOOL dowildcard)
{
	int p,n,i;
	int res = 0;

	if (!tc_strcmp(pat,"*.*"))
	{
		pat[1] = '\0';
	}
	if (!tc_strcmp(pat,"."))
	{
		pat[0] = '*';
		pat[1] = '\0';
	}

	for(p=0,n=0; pat[p]!='\0'; p++,n++)
	{
		if (pat[p]=='*' && dowildcard)
		{
			for(i=n; name[i]!=0; i++)
                res |= rtsmb_util_ascii_patcmp(&(pat[p+1]),&(name[i]),dowildcard);
			res |= rtsmb_util_ascii_patcmp(&(pat[p+1]),&(name[i]),dowildcard);
			return(res);
		}

		if (name[n] == 0)
		{
			/* Match * with end of string */
			if (pat[p]=='*' && pat[p+1] == 0 && dowildcard)
				return(1);
			else
				return(0);
		}

		if ((pat[p]!='?' || !dowildcard) && pat[p]!=name[n])
				return(0);

	}
	if (name[n]==0)
		return(1);
	else
		return(0);
}

int rtsmb_util_rtsmb_patcmp (PFRTCHAR pat, PFRTCHAR name, BBOOL dowildcard)
{
#if (INCLUDE_RTSMB_UNICODE)
	return rtsmb_util_unicode_patcmp (pat, name, dowildcard);
#else
	return rtsmb_util_ascii_patcmp (pat, name, dowildcard);
#endif
}


#if (INCLUDE_RTSMB_ENCRYPTION)

#include "smb_des.h"
#include "smb_md4.h"

// S8 is the official 8-byte string for use as the data for smb encryption
#define S8	"KGS!@#$%"

RTSMB_STATIC
void seven_bytes_to_eight_bytes (byte *input, byte *output)
{
	byte buf [8];
	byte i;

	buf[0] = (byte) (input[0] & (0xFF << 1));

	for (i = 1; i < 7; i ++)
		buf[i] = (byte) (
				  ((input[i - 1] & (0xFF >> (8 - i))) << (8 - i)) |
				  ((input[i] & (0xFF << (i + 1))) >> (i)));

	buf[7] = (byte) ((input[6] & (0xFF >> 1)) << 1);

	tc_memcpy (output, buf, 8);
}

// key can be any length, but only the first 7 bytes are used
// data is 8-bytes
// buffer stores the 8-byte result when we are done
RTSMB_STATIC
void encrypt_block (PFBYTE chkey, PFBYTE data, PFBYTE buffer)
{
	rtsmb_des_cblock key;
	rtsmb_des_cblock output;
	rtsmb_des_key_schedule keySchedule;

	// SETUP keySchedule
	// use the first 7 bytes of the key to encrypt 8-byte data
	seven_bytes_to_eight_bytes (chkey, key);
	rtsmb_des_set_odd_parity (&key);
	rtsmb_des_set_key_unchecked (&key, keySchedule);

	rtsmb_des_ecb_encrypt ((rtsmb_des_cblock *) data, &output, keySchedule, RTSMB_DES_ENCRYPT);

	tc_memcpy (buffer, output, 8);
}

// p21 is 21 bytes long, data is 8 bytes long, output is 24 bytes long
RTSMB_STATIC
void encrypt24 (PFBYTE p21, PFBYTE data, PFBYTE output)
{
	encrypt_block (p21, data, output);
	encrypt_block (&p21[7], data, &output[8]);
	encrypt_block (&p21[14], data, &output[16]);
}

// DES encryption on password to achieve an encrypted
// 24 byte long password ('output').
// Password, data, and output can overlap.
PFBYTE cli_util_encrypt_password_pre_nt (PFCHAR password, PFBYTE data, PFBYTE output)
{
	byte p21 [21];
	byte p14 [14];

	// p21 is actually p16 with 5 null bytes appended.  we just null it now
	// and fill it as if it were p16
	tc_memset (&p21[16], 0, 5);

	tc_memset (p14, '\0', 14); // password is null-extended

	tc_strncpy ((PFCHAR) p14, password, 14);
	rtsmb_util_latin_string_toupper ((PFCHAR) p14);	// must be uppercase

	// encrypt S8 using 7-byte blocks from password
	encrypt_block (p14, (PFBYTE) S8, p21);
	encrypt_block (&p14[7], (PFBYTE) S8, &p21[8]);

	encrypt24 (p21, data, output);

	return output;
}

// DES encryption on password to achieve an encrypted
// 24 byte long password ('output').
// Password, data, and output can overlap.
//
// this is the nt version for encrypting passwords
PFBYTE cli_util_encrypt_password_nt (PFCHAR password, PFBYTE data, PFBYTE output)
{
	byte p21 [21];
	int dst, src;
	char unicode_lendian[(CFG_RTSMB_MAX_PASSWORD_SIZE + 1) * 2];

	// p21 is actually p16 with 5 null bytes appended.  we just null it now
	// and fill it as if it were p16
	tc_memset (&p21[16], 0, 5);

	// must make password unicode first
	for (src=0, dst=0; src<=CFG_RTSMB_MAX_PASSWORD_SIZE && password[src]; src++)
	{
		unicode_lendian[dst++] = password[src];
		unicode_lendian[dst++] = 0;
	}

	// get md4 of password
	RTSMB_MD4 ((const unsigned char *)unicode_lendian, (dword)dst, p21);

	encrypt24 (p21, data, output);

	return output;
}

// LMv2 response password encryption
PFBYTE cli_util_encrypt_password_lmv2 (PFCHAR password, PFBYTE serverChallenge, PFCHAR output,
									   PFBYTE uni_password, PFRTCHAR name, PFRTCHAR domainname) // _YI_
{
	BYTE unicode_lendian[(CFG_RTSMB_MAX_PASSWORD_SIZE + 1) * 2];
	BYTE nameDomainname[(CFG_RTSMB_MAX_USERNAME_SIZE + 1) * 4];

	BYTE concatChallenge[16];
	BYTE p21 [21];
	BYTE NTLMv2_Hash[16];
	PFBYTE clientNonce;
	int dst, src, ndLen;

	clientNonce = &uni_password[32];

	for (src=0, ndLen=0; src<=CFG_RTSMB_MAX_USERNAME_SIZE && name[src]; src++)
	{
#if (INCLUDE_RTSMB_UNICODE)
		nameDomainname[ndLen++] = (BYTE) rtsmb_util_wtoupper(name[src]);
#else
		nameDomainname[ndLen++] = (BYTE) rtsmb_util_latin_toupper(name[src]);
#endif
		nameDomainname[ndLen++] = (BYTE) 0;
	}
	// concatenate the uppercase username with the domainname
	tc_memcpy((PFCHAR) &nameDomainname[2*rtsmb_util_wlen((PFWCS)name)], domainname, 2*rtsmb_util_wlen((PFWCS)domainname));

	ndLen += 2*(int)rtsmb_util_wlen((PFWCS)domainname);

	// p21 is actually p16 with 5 null bytes appended.  we just null it now
	// and fill it as if it were p16
	tc_memset (&p21[16], 0, 5);

	// Convert the password to unicode
	for (src=0, dst=0; src<=CFG_RTSMB_MAX_PASSWORD_SIZE && password[src]; src++)
	{
		unicode_lendian[dst++] = (BYTE)password[src];
		unicode_lendian[dst++] = 0;
	}

	// get md4 of password.  This is the 16-byte NTLM hash
	RTSMB_MD4 (unicode_lendian, (dword)dst, p21);

	// The HMAC-MD5 message authentication code algorithm is applied to
	// the unicode (username,domainname) using the 16-byte NTLM hash as the key.
	// This results in a 16-byte value - the NTLMv2 hash.
	hmac_md5(nameDomainname,    /* pointer to data stream */
               ndLen,				/* length of data stream */
               p21,             /* pointer to remote authentication key */
               16,              /* length of authentication key */
               NTLMv2_Hash);    /* caller digest to be filled in */

	// The challenge from the Type 2 message is concatenated with the client nonce
	tc_memcpy(concatChallenge, serverChallenge, 8);
	tc_memcpy(&concatChallenge[8], clientNonce, 8);

	// The HMAC-MD5 message authentication code algorithm is applied to the
	// concatenated server challenge and client nonce value using the 16-byte NTLMv2 hash
	// as the key
	hmac_md5(concatChallenge,	/* pointer to data stream */
               16,				/* length of data stream */
               NTLMv2_Hash,		/* pointer to remote authentication key */
               16,				/* length of authentication key */
               (PFBYTE ) output);			/* caller digest to be filled in */

	tc_memcpy(&output[16], clientNonce, 8);

	return (PFBYTE )output;
}
#endif


#define SECS_IN_A_DAY           86400
#define DAYS_IN_FOUR_YEARS      1461

/* This records how many days are in each month. */
RTSMB_STATIC RTSMB_CONST int month_days [12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

#define SECS_BETWEEN_EPOCHS         0xB6109100
#define LOW_100NS_BETWEEN_EPOCHS    0xD53E8000
#define HIGH_100NS_BETWEEN_EPOCHS   0x019DB1DE
#define SECS_TO_100NS               10000000L     /* 10^7 */

/* hex digits and offsets */
RTSMB_STATIC
void rtmsb_util_time_put_digit_at_offset (int digit, int offset, TIME RTSMB_FAR *ms_time)
{
	PFDWORD t;
	dword temp;

	t = offset < 8 ? &ms_time->low_time : (offset -= 8, &ms_time->high_time);

	temp = (*t) & (0xFFFFFFFF << ((offset + 1) * 4));
	temp |= (*t) & (0xFFFFFFFF >> ((8 - offset) * 4));
	temp |= (dword)((digit & 0xF) << (offset * 4));

	*t = temp;
}

/* hex digits and offsets */
RTSMB_STATIC
dword rtmsb_util_time_get_dividend (int prior, int offset, TIME RTSMB_FAR *ms_time)
{
	PFDWORD t;
	dword temp;

	t = offset < 8 ? &ms_time->low_time : (offset -= 8, &ms_time->high_time);

	temp = (dword)prior << 4;
	temp |=  (  ((*t) & (dword)(0xF << (offset * 4)))  >> (offset * 4));

	return temp;
}

dword rtsmb_util_time_ms_to_unix (TIME ms_time)
{
	int offset;
	int remainder, window;
	TIME answer;

	answer.low_time = 0;
	answer.high_time = 0;

	/* get rid of uppermost bit, since that is the sign bit */
	ms_time.high_time = ms_time.high_time & 0x7FFFFFFF;

	for (offset = 14, remainder = 0; offset >= 0; offset --)
	{
		window = (int)rtmsb_util_time_get_dividend (remainder, offset, &ms_time);
		rtmsb_util_time_put_digit_at_offset (window / SECS_TO_100NS, offset, &answer);
		remainder = window % SECS_TO_100NS;
	}

	answer.low_time -= SECS_BETWEEN_EPOCHS;

	return answer.low_time;
}

DATE_STR rtsmb_util_time_unix_to_date (dword unix_time)
{
	DATE_STR date;
	dword day_time;
	dword tmp;
	int i;
	BBOOL leap = FALSE;

	day_time = unix_time % SECS_IN_A_DAY;
	date.time = 0;
	date.time |= (SMB_TIME)(((day_time / 3600) & 0x1F) << 11);
	date.time |= (SMB_TIME)((((day_time / 60) % 60) & 0x3F) << 5);
	tmp = (dword)((((day_time % 60) / 2 ) & 0x1F));
	date.time |= (SMB_TIME) tmp;

	/* Now, we are only concerned with the time span 1980 - 2099.  So, the only century year
	   is also a 400-year.  Thus, every four years in this span there is one leap year.  Thus,
	   a 4-year span has a constant amount of days. */
	day_time = unix_time / SECS_IN_A_DAY;
	date.date = 0;

	/* adjust unix time to 1980-based time */
	day_time -= (DAYS_IN_FOUR_YEARS * 2 + 730);

	tmp = day_time / DAYS_IN_FOUR_YEARS;
	tmp *= 4;
	day_time = day_time % DAYS_IN_FOUR_YEARS;

	if (day_time < 366)
	{
		leap = TRUE;
		tmp += 0;
	}
	else if (day_time < 731)
	{
		day_time -= 366;
		tmp += 1;
	}
	else if (day_time < 1096)
	{
		day_time -= 731;
		tmp += 2;
	}
	else
	{
		day_time -= 1096;
		tmp += 3;
	}

	/* year */
	date.date |= (SMB_DATE)((tmp & 0x7F) << 9);
	//year = tmp;

	for (i = 0, tmp = 0; i < 12; i++)
	{
		tmp += (dword)month_days [i];
		if (leap && i == 1)
		{
			tmp ++;
		}

		if (day_time < tmp)
		{
			/* month */
			date.date |= (SMB_DATE)(((i + 1) & 0xF) << 5);
			break;
		}
	}

	tmp -= (dword)month_days [i];
	if (leap && i == 1)
	{
		tmp --;
	}

	/* day */
	tmp = (dword)((day_time - tmp + 1) & 0x1F);
	date.date |= (SMB_DATE)tmp;

	return date;
}


DATE_STR rtsmb_util_time_ms_to_date (TIME ms_time)
{
	/* probably not good to do conversion through unix here */
	return rtsmb_util_time_unix_to_date (rtsmb_util_time_ms_to_unix (ms_time));
}

TIME rtsmb_util_time_date_to_ms (DATE_STR date)
{
	/* probably not good to do conversion through unix here */
	return rtsmb_util_time_unix_to_ms (rtsmb_util_time_date_to_unix (date));
}

TIME rtsmb_util_time_rtp_date_to_ms (RTP_DATE rtp_date)
{
	return rtsmb_util_time_unix_to_ms(rtsmb_util_time_rtp_date_to_unix(rtp_date));
}

RTP_DATE rtsmb_util_time_ms_to_rtp_date (TIME time)
{
	return rtsmb_util_time_unix_to_rtp_date(rtsmb_util_time_ms_to_unix(time));
}

dword rtsmb_util_time_date_to_unix (DATE_STR date)
{
	dword unix_time;
	BBOOL leap = FALSE;
	int i;

	unix_time = 0;
	unix_time += (dword)(date.time & 0x001F) * 2;
	unix_time += (dword)((date.time & 0x07E0) >> 5) * 60;
	unix_time += (dword)((date.time & 0xF800) >> 11) * 3600;
	unix_time += (dword)((date.date & 0x001F) - 1) * SECS_IN_A_DAY;


	unix_time += (dword) ((((date.date & 0xFE00) >> 9) / 4) * DAYS_IN_FOUR_YEARS * SECS_IN_A_DAY);

	switch (((date.date & 0xFE00) >> 9) % 4)
	{
		case 0:
			leap = TRUE;
			break;
		case 1:
			unix_time += 366 * SECS_IN_A_DAY;
			break;
		case 2:
			unix_time += 731 * SECS_IN_A_DAY;
			break;
		case 3:
			unix_time += 1096 * SECS_IN_A_DAY;
			break;
	}

	for (i = 0; i < ((date.date & 0x01E0) >> 5) - 1; i++)
	{
		if (leap && i == 1)
		{
			unix_time += SECS_IN_A_DAY;
		}

		unix_time += (dword) (month_days [i] * SECS_IN_A_DAY);
	}

	/* adjust time to 1970-based time */
	unix_time += (DAYS_IN_FOUR_YEARS * 2 + 730) * SECS_IN_A_DAY;

	return unix_time;
}

dword rtsmb_util_time_rtp_date_to_unix (RTP_DATE rtp_date)
{
	dword unix_time;
	BBOOL leap = FALSE;
	unsigned int i;

	unix_time = 0;
	unix_time += (rtp_date.second);  //seconds
	unix_time += (rtp_date.minute) * 60;  //minutes -> seconds
	unix_time += (rtp_date.hour + 4) * 3600;  //hours -> seconds

	unix_time += (rtp_date.day -1) * SECS_IN_A_DAY;

	unix_time += ((rtp_date.year - 1980) / 4) * DAYS_IN_FOUR_YEARS * SECS_IN_A_DAY;

	switch (rtp_date.year % 4)
	{
		case 0:
			leap = TRUE;
			break;
		case 1:
			unix_time += 366 * SECS_IN_A_DAY;
			break;
		case 2:
			unix_time += 731 * SECS_IN_A_DAY;
			break;
		case 3:
			unix_time += 1096 * SECS_IN_A_DAY;
			break;
	}

	for (i = 0; i < rtp_date.month - 1; i++)
	{
		if (leap && i == 1)
		{
			unix_time += SECS_IN_A_DAY;
		}

		unix_time += (dword) (month_days [i] * SECS_IN_A_DAY);
	}

	/* adjust time to 1970-based time */
	unix_time += (DAYS_IN_FOUR_YEARS * 2 + 730) * SECS_IN_A_DAY;

	return unix_time;
}


RTP_DATE rtsmb_util_time_unix_to_rtp_date (dword unix_time)
{
	RTP_DATE date;
	dword day_time;
	dword tmp;

	int i;
	BBOOL leap = FALSE;

	day_time = unix_time % SECS_IN_A_DAY;

	date.year = 0;
	date.msec = 0;
	date.dlsTime = 0;
	date.tzOffset = 0;

	date.hour = (day_time / 3600) - 4; //hours
	date.minute = ((((day_time / 60) % 60))); //minutes
	date.second = (((day_time % 60))); //seconds, might be (day_time %60) / 2


	/* Now, we are only concerned with the time span 1980 - 2099.  So, the only century year
	   is also a 400-year.  Thus, every four years in this span there is one leap year.  Thus,
	   a 4-year span has a constant amount of days. */
	day_time = unix_time / SECS_IN_A_DAY;

	/* adjust unix time to 1980-based time */
	day_time -= (DAYS_IN_FOUR_YEARS * 2 + 730);


	tmp = day_time / DAYS_IN_FOUR_YEARS;
	tmp *= 4;
	day_time = day_time % DAYS_IN_FOUR_YEARS;

	if (day_time < 366)
	{
		leap = TRUE;
		tmp += 0;
	}
	else if (day_time < 731)
	{
		day_time -= 366;
		tmp += 1;
	}
	else if (day_time < 1096)
	{
		day_time -= 731;
		tmp += 2;
	}
	else
	{
		day_time -= 1096;
		tmp += 3;
	}

	/* year */
	date.year = (tmp);
	date.year += 1980;

	//deal with month
	for (i = 0, tmp = 0; i < 12; i++)
	{
		tmp += (dword)month_days [i];
		if (leap && i == 1)
		{
			tmp ++;
		}

		if (day_time < tmp)
		{
			/* month */
			date.month = (unsigned)(i + 1);
			break;
		}
	}

	tmp -= (dword)month_days [i];
	if (leap && i == 1)
	{
		tmp --;
	}

	/* day */
	date.day = ((day_time - tmp + 1));

	return date;
}

ddword rtsmb_util_get_current_filetime(void)
{
RTP_DATE date;
TIME t;
ddword r;
    rtp_get_date (&date);
    t = rtsmb_util_time_rtp_date_to_ms(date);
    r = (ddword)t.high_time<<32|t.low_time;
    return r;
}


TIME rtsmb_util_time_unix_to_ms (dword unix_time)
{
	TIME answer;
	dword tmp1, tmp2, tmp3, tmp4, before;

	answer.low_time = 0;
	answer.high_time = 0;

	tmp1 = ((unix_time & 0x000000FF) >> 0)  * SECS_TO_100NS;
	tmp2 = ((unix_time & 0x0000FF00) >> 8)  * SECS_TO_100NS;
	tmp3 = ((unix_time & 0x00FF0000) >> 16) * SECS_TO_100NS;
	tmp4 = ((unix_time & 0xFF000000) >> 24) * SECS_TO_100NS;

	answer.low_time = tmp1;
	answer.high_time = 0;

	before = answer.low_time;
	answer.low_time += (tmp2 & 0xFFFFFF) << 8;
	answer.high_time += answer.low_time < before ? 1 : 0; /* did we carry? */
	answer.high_time += (tmp2 & 0xFF000000) >> 24;

	before = answer.low_time;
	answer.low_time += (tmp3 & 0xFFFF) << 16;
	answer.high_time += answer.low_time < before ? 1 : 0; /* did we carry? */
	answer.high_time += (tmp3 & 0xFFFF0000) >> 16;

	before = answer.low_time;
	answer.low_time += (tmp4 & 0xFF) << 24;
	answer.high_time += answer.low_time < before ? 1 : 0; /* did we carry? */
	answer.high_time += (tmp4 & 0xFFFFFF00) >> 8;

	/* now we have the right amount of 100-ns intervals */

	/* add the difference in epochs */
	before = answer.low_time;
	answer.low_time += LOW_100NS_BETWEEN_EPOCHS;
	answer.high_time += answer.low_time < before ? 1 : 0; /* did we carry? */
	answer.high_time += HIGH_100NS_BETWEEN_EPOCHS;

	return answer;
}


byte rtsmb_util_smb_to_rtsmb_attributes (word smb_attributes)
{
	byte rtsmb_attributes = 0;

	if (smb_attributes == SMB_FA_N || smb_attributes == 0)
	{
		return RTP_FILE_ATTRIB_RDWR;
	}
	if (smb_attributes & SMB_FA_RO)
	{
		rtsmb_attributes |= RTP_FILE_ATTRIB_RDONLY;
	}
	else
	{
		rtsmb_attributes |= RTP_FILE_ATTRIB_RDWR;
	}
	if (smb_attributes & SMB_FA_V)             rtsmb_attributes |= RTP_FILE_ATTRIB_ISVOL;
	if (smb_attributes & SMB_FA_H)             rtsmb_attributes |= RTP_FILE_ATTRIB_HIDDEN;
	if (smb_attributes & SMB_FA_S)             rtsmb_attributes |= RTP_FILE_ATTRIB_SYSTEM;
	if (smb_attributes & SMB_FA_A)             rtsmb_attributes |= RTP_FILE_ATTRIB_ARCHIVE;
	if (smb_attributes & SMB_FA_D)             rtsmb_attributes |= RTP_FILE_ATTRIB_ISDIR;

	return rtsmb_attributes;
}

word rtsmb_util_rtsmb_to_smb_attributes (byte rtsmb_attributes)
{
	word smb_attributes = 0;

	if (rtsmb_attributes & RTP_FILE_ATTRIB_ISDIR)   smb_attributes |= SMB_FA_D;
	if (rtsmb_attributes & RTP_FILE_ATTRIB_ISVOL)   smb_attributes |= SMB_FA_V;
	if (rtsmb_attributes & RTP_FILE_ATTRIB_RDONLY)  smb_attributes |= SMB_FA_RO;
	if (rtsmb_attributes & RTP_FILE_ATTRIB_HIDDEN)  smb_attributes |= SMB_FA_H;
	if (rtsmb_attributes & RTP_FILE_ATTRIB_SYSTEM)  smb_attributes |= SMB_FA_S;
	if (rtsmb_attributes & RTP_FILE_ATTRIB_ARCHIVE) smb_attributes |= SMB_FA_A;

	if (smb_attributes == 0)                     smb_attributes = SMB_FA_N;

	return smb_attributes;
}
