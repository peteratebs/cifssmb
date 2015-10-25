//
// SMBNB.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Deal with NETBIOS names
//

#include "smbdefs.h"
#include "smbnb.h"
#include "smbpack.h"
#include "smbread.h"
#include "smbutil.h"

#define RTSMB_NB_CHAR_DECOMPRESS(c, h, l) {h=(byte)(((byte)(c>>4)&0x0F)+(byte)0x41); l=(byte)((byte)(c & 0x0F)+(byte)0x41);}
#define RTSMB_NB_CHAR_COMPRESS(h, l, c) {c= (byte)(((byte)(h-0x41)<<4) | (byte)((l-0x41) & 0x0F));}

/* |name| must be RTSMB_NB_NAME_SIZE big */
int rtsmb_nb_fill_name (PFVOID buf, rtsmb_size size, PFCHAR name)
{
	PFVOID s, e;
	int i;
	byte namebuf [RTSMB_NB_NAME_SIZE * 2 + 1];

	for (i = 0; i < RTSMB_NB_NAME_SIZE; i++)
	{
		RTSMB_NB_CHAR_DECOMPRESS (name[i], namebuf[i * 2], namebuf[(i * 2) + 1]);
	}
	namebuf[i * 2] = '\0';

	s = buf;
	PACK_BYTE (buf, &size, RTSMB_NB_NAME_SIZE * 2, -1);	/* size of name in bytes (once it's in the buffer) */
	PACK_ITEM (buf, &size, namebuf, RTSMB_NB_NAME_SIZE * 2 + 1, -1);
	e = buf;

	return (int) PDIFF (e, s);
}

/* |dest| must be (RTSMB_NB_NAME_SIZE + 1) characters big */
int rtsmb_nb_read_name (PFVOID buf, rtsmb_size size, PFCHAR dest)
{
	PFVOID e, s;
	byte b;
	int i;
    byte *bdest = (byte *) dest;
	byte namebuf [RTSMB_NB_NAME_SIZE * 2 + 1];

	s = buf;
	READ_BYTE (buf, &size, &b, -1);	/* size of name in bytes */
	ASSURE (b == RTSMB_NB_NAME_SIZE * 2, -1);
	READ_ITEM (buf, &size, namebuf, RTSMB_NB_NAME_SIZE * 2 + 1, -1);
	e = buf;

	for (i = 0; i < RTSMB_NB_NAME_SIZE; i++)
	{
		RTSMB_NB_CHAR_COMPRESS (namebuf[i * 2], namebuf[(i * 2) + 1], bdest[i]);
	}

	dest[i] = '\0';

	return (int) PDIFF (e, s);
}
