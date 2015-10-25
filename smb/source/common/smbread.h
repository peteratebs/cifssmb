#ifndef __SMB_READ_H__
#define __SMB_READ_H__

#include "smbdefs.h"

#define READ_SKIP(buf, buf_size, skip_size, rv) \
{\
	if (!(buf = rtsmb_read_skip (buf, buf_size, skip_size)))\
		return rv;\
}

#define READ_ITEM(buf, buf_size, item, item_size, rv) \
{\
	if (!(buf = rtsmb_read (buf, buf_size, item, item_size)))\
		return rv;\
}

#define READ_STRING(buf, buf_size, string, string_size, origin, rv) \
{\
	if (!(buf = rtsmb_read_string (buf, buf_size, string, string_size, origin)))\
		return rv;\
}

#define READ_STRING_BYTES(buf, buf_size, string, string_size, bytes, null, origin, rv) \
{\
	if (!(buf = rtsmb_read_string_bytes (buf, buf_size, string, string_size, bytes, null, origin)))\
		return rv;\
}

#define READ_BYTE(buf, buf_size, b, rv) \
{\
		if (!(buf = rtsmb_read_byte (buf, buf_size, b)))\
			return rv;\
}

#define READ_WORD(buf, buf_size, w, no, rv) \
{\
		if (!(buf = rtsmb_read_word (buf, buf_size, w, no)))\
			return rv;\
}

#define READ_DWORD(buf, buf_size, d, no, rv) \
{\
		if (!(buf = rtsmb_read_dword (buf, buf_size, d, no)))\
			return rv;\
}

#define READ_DDWORD(buf, buf_size, d, no, rv) \
{\
		if (!(buf = rtsmb_read_ddword (buf, buf_size, d, no)))\
			return rv;\
}

#define RTSMB_READ_PAD_TO(i) \
{\
	int padding_origin = (((int) origin) % i);\
	int padding_buffer = (((int) buf) %i);\
	\
	if (padding_origin != padding_buffer)\
	{\
		RTSMB_READ_SKIP ((padding_origin - padding_buffer + 4) % i);\
	}\
}

#define RTSMB_READ_UNICODE	1
#define RTSMB_READ_ASCII	-1
#define RTSMB_READ_ANY		0

#define RTSMB_READ_SKIP(skip_size) READ_SKIP (buf, &size, skip_size, -1)
#define RTSMB_READ_BYTE(b) READ_BYTE (buf, &size, b, -1)
#define RTSMB_READ_WORD(w) READ_WORD (buf, &size, w, FALSE, -1)
#define RTSMB_READ_DWORD(d) READ_DWORD (buf, &size, d, FALSE, -1)
#define RTSMB_READ_DDWORD(d) READ_DDWORD (buf, &size, d, FALSE, -1)
#define RTSMB_READ_ITEM(item, item_size) READ_ITEM (buf, &size, item, item_size, -1)
#define RTSMB_READ_STRING(str, str_size, uni) \
{\
	/* str_size coming in is the size of the str buffer.  */\
	/* We need to convert it to the number of characters available */\
	/* for the buffer. */\
	PFRTCHAR str_in = str_size < 2 ? (PFRTCHAR)0 : str;\
	\
	READ_STRING (buf, &size, str_in, str_size,\
		uni\
		? ((uni == 1) ? origin : (PFVOID)0)\
		: (ON (pHeader->flags2, SMB_FLG2_UNICODESTR) ? origin : (PFVOID)0), -1);\
}
#define RTSMB_READ_STRING_BYTES(str, str_size, bytes, null, uni) \
{\
	/* str_size coming in is the size of the str buffer.  */\
	/* We need to convert it to the number of characters available */\
	/* for the buffer. */\
	PFRTCHAR str_in = str_size < 2 ? 0 : str;\
	\
	READ_STRING_BYTES (buf, &size, str_in, str_size, bytes, null,\
		uni\
		? ((uni == 1) ? origin : 0)\
		: (ON (pHeader->flags2, SMB_FLG2_UNICODESTR) ? origin : 0), -1);\
}


PFVOID rtsmb_read_unsafe (PFVOID buf, PFVOID item, rtsmb_size item_size);
PFVOID rtsmb_read (PFVOID buf, PFSIZE buf_size,
	PFVOID item, rtsmb_size item_size);

PFVOID rtsmb_read_string (PFVOID buf, PFSIZE buf_size,
	PFRTCHAR string, rtsmb_size string_size, PFVOID origin);
PFVOID rtsmb_read_string_bytes (PFVOID buf, PFSIZE buf_size,
	PFRTCHAR string, rtsmb_size string_size, rtsmb_size to_read, BBOOL null, PFVOID origin);

PFVOID rtsmb_read_byte_unsafe (PFVOID buf, PFBYTE b);
PFVOID rtsmb_read_byte (PFVOID buf, PFSIZE buf_size, PFBYTE b);

PFVOID rtsmb_read_word_unsafe (PFVOID buf, PFWORD w, BBOOL netorder);
PFVOID rtsmb_read_word (PFVOID buf, PFSIZE buf_size, PFWORD w,
	BBOOL netorder);

PFVOID rtsmb_read_dword_unsafe (PFVOID buf, PFDWORD d, BBOOL netorder);
PFVOID rtsmb_read_dword (PFVOID buf, PFSIZE buf_size, PFDWORD dw,
	BBOOL netorder);

PFVOID rtsmb_read_ddword (PFVOID buf, PFSIZE buf_size,
	PFDDWORD d, BBOOL netorder);


PFVOID rtsmb_read_skip (PFVOID buf, PFSIZE buf_size, rtsmb_size skip_size);


#endif /* __SMB_READ_H__ */
