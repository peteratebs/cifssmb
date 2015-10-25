#ifndef __SMB_PACK_H__
#define __SMB_PACK_H__

#include "smbdefs.h"

#define PACK_ITEM(buf, buf_size, item, item_size, rv) \
{\
	if (!(buf = rtsmb_pack_add (buf, buf_size, item, item_size)))\
		return rv;\
}

#define PACK_STRING(buf, buf_size, string, nil, origin, rv) \
{\
	if (!(buf = rtsmb_pack_add_string (buf, buf_size, string, nil, origin)))\
		return rv;\
}

#define PACK_STRING_DIRECT(buf, buf_size, string, nil, uni, rv) \
{\
	if (!(buf = rtsmb_pack_add_string_direct (buf, buf_size, string, nil, uni)))\
		return rv;\
}

#define PACK_BYTE(buf, buf_size, b, rv) \
{\
	if (!(buf = rtsmb_pack_add_byte (buf, buf_size, b)))\
		return rv;\
}

#define PACK_WORD(buf, buf_size, w, no, rv) \
{\
	if (!(buf = rtsmb_pack_add_word (buf, buf_size, w, no)))\
		return rv;\
}

#define PACK_DWORD(buf, buf_size, d, no, rv) \
{\
	if (!(buf = rtsmb_pack_add_dword (buf, buf_size, d, no)))\
		return rv;\
}

#define PACK_DDWORD(buf, buf_size, d, no, rv) \
{\
	if (!(buf = rtsmb_pack_add_ddword (buf, buf_size, d, no)))\
		return rv;\
}

#define RTSMB_PACK_UNICODE	1
#define RTSMB_PACK_ASCII	-1
#define RTSMB_PACK_ANY		0

#define RTSMB_PACK_PAD_TO(i) \
{\
	RTP_ADDR padding_origin = (((RTP_ADDR) origin) % i);\
	RTP_ADDR padding_buffer = (((RTP_ADDR) buf) %i);\
	\
	if (padding_origin != padding_buffer)\
	{\
		RTP_ADDR padding_index, padding_stop = (padding_origin - padding_buffer + 4) % i;\
		for (padding_index = 0; padding_index < padding_stop; padding_index++)\
		{	RTSMB_PACK_BYTE (0);}\
	}\
}

/* some cheap programming macros to save me a bunch of code */
#define RTSMB_PACK_BYTE(b) PACK_BYTE (buf, &size, b, -1)
#define RTSMB_PACK_WORD(w) PACK_WORD (buf, &size, w, FALSE, -1)
#define RTSMB_PACK_DWORD(d) PACK_DWORD (buf, &size, d, FALSE, -1)
#define RTSMB_PACK_DDWORD(d) PACK_DDWORD (buf, &size, d, FALSE, -1)
#define RTSMB_PACK_ITEM(item, item_size) PACK_ITEM (buf, &size, item, item_size, -1)
#define RTSMB_PACK_STRING(str, uni) PACK_STRING (buf, &size, str, TRUE,\
		uni\
		? ((uni == 1) ? origin : (PFVOID)0)\
		: (ON (pHeader->flags2, SMB_FLG2_UNICODESTR) ? origin : (PFVOID)0), -1)

#define RTSMB_PACK_STRING_NO_NULL(str, uni) PACK_STRING (buf, &size, str, FALSE,\
		uni\
		? ((uni == 1) ? origin : (PFVOID)0)\
		: (ON (pHeader->flags2, SMB_FLG2_UNICODESTR) ? origin : (PFVOID)0), -1)

#define RTSMB_PACK_STRING_D(str, uni) PACK_STRING_DIRECT (buf, &size, str, TRUE,\
		(BBOOL) (uni ? ((uni == 1) ? TRUE : FALSE) : \
		(ON (pHeader->flags2, SMB_FLG2_UNICODESTR) ? TRUE : FALSE)), -1)

#define RTSMB_PACK_STRING_D_NO_NULL(str, uni) PACK_STRING_DIRECT (buf, &size, str, FALSE,\
		(BBOOL) (uni ? ((uni == 1) ? TRUE : FALSE) : \
		(ON (pHeader->flags2, SMB_FLG2_UNICODESTR) ? TRUE : FALSE)), -1)



PFVOID rtsmb_pack_add_unsafe (PFVOID buf, PFVOID item, rtsmb_size item_size);
PFVOID rtsmb_pack_add (PFVOID buf, PFSIZE buf_size,
	PFVOID item, rtsmb_size item_size);

/* if origin is NULL, the string is treated as ASCII.
   if origin is non-NULL, the string is treated as UNICODE.

   |nil| is whether or not to write the ending null*/
PFVOID rtsmb_pack_add_string (PFVOID buf, PFSIZE buf_size,
	PFRTCHAR string, BBOOL nil, PFVOID origin);

/* this doesn't pad to word boundary with the origin */
PFVOID rtsmb_pack_add_string_direct (PFVOID buf, PFSIZE buf_size,
	PFRTCHAR string, BBOOL nil, BBOOL unicode);

PFVOID rtsmb_pack_add_byte_unsafe (PFVOID buf, byte b);
PFVOID rtsmb_pack_add_byte (PFVOID buf, PFSIZE buf_size, byte b);

PFVOID rtsmb_pack_add_word_unsafe (PFVOID buf, word w, BBOOL netorder);
PFVOID rtsmb_pack_add_word (PFVOID buf, PFSIZE buf_size, word w,
	BBOOL netorder);

PFVOID rtsmb_pack_add_dword_unsafe (PFVOID buf, dword d, BBOOL netorder);
PFVOID rtsmb_pack_add_dword (PFVOID buf, PFSIZE buf_size, dword dw,
	BBOOL netorder);
PFVOID rtsmb_pack_add_ddword (PFVOID buf, PFSIZE buf_size,
	ddword d, BBOOL netorder);

#endif /* __SMB_PACK_H__ */
