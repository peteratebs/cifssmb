//
// SMBPACK.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Basic functions to pack into buffer (outgoing packet)
//


#include "smbpack.h"
#include "smbutil.h"
#include "rtpstr.h" /* _YI_ 9/24/2004 */
#include "rtpwcs.h" /* _YI_ 9/24/2004 */

/**
 * No error checking is performed.
 */
PFVOID rtsmb_pack_add_unsafe (PFVOID buf, PFVOID item, rtsmb_size item_size)
{
    tc_memcpy (buf, item, item_size);

    return PADD (buf, item_size);
}

/**
 * Adds item to buf, wrt sizes.  buf and item must not overlap.
 */
PFVOID rtsmb_pack_add (PFVOID buf, PFSIZE buf_size,
    PFVOID item, rtsmb_size item_size)
{
    PFVOID rv;

    if (item_size > *buf_size)
    {
        /**
         * We don't have room.  Bail.
         */
        return (PFVOID)0;
    }

    rv = rtsmb_pack_add_unsafe (buf, item, item_size);

    *buf_size -= item_size;

    return rv;
}


PFVOID rtsmb_pack_add_ascii_string (PFVOID buf, PFSIZE buf_size,
    PFRTCHAR string, BBOOL nil)
{
    char tmp[20];
    rtsmb_size i = 0, j, len;
    rtsmb_char empty[] = {'\0'};
    PFRTCHAR s = string ? string : empty;

    len = rtsmb_len (s);

    while (i < len)
    {
        for (j = 0; j < 20 && s[i]; j++)
        {
            tmp[j] = (char) (s[i] & 0xFF);
            i++;
        }

        buf = rtsmb_pack_add (buf, buf_size, tmp, j);

        if (!buf)
        {
            return (PFVOID)0;
        }
    }

    if (nil)
    {
        char cempty = '\0';
        buf = rtsmb_pack_add (buf, buf_size, &cempty, 1);
    }

    return buf;
}

PFVOID rtsmb_pack_add_unicode_string (PFVOID buf, PFSIZE buf_size,
    PFRTCHAR string, BBOOL nil)
{
    unsigned short tmp[20];
    rtsmb_size i = 0, j, len;
    rtsmb_char empty[] = {'\0'};
    PFRTCHAR s = string ? string : empty;

    len = rtsmb_len (s);

    while (i < len)
    {
        for (j = 0; j < 20 && s[i]; j++)
        {
            tmp[j] = SMB_HTOIW(s[i]);
            i++;
        }

        buf = rtsmb_pack_add (buf, buf_size, tmp, j * 2);

        if (!buf)
        {
            return (PFVOID)0;
        }
    }

    if (nil)
    {
        unsigned short wempty = '\0';

        buf = rtsmb_pack_add (buf, buf_size, &wempty, 2);
    }

    return buf;
}

/**
 * Adds string to buf.  buf and string must not overlap.
 */
PFVOID rtsmb_pack_add_string (PFVOID buf, PFSIZE buf_size,
    PFRTCHAR string, BBOOL nil, PFVOID origin)
{
    if (origin)
    {
        if ((((RTP_ADDR) origin) % 2) != (((RTP_ADDR) buf) % 2))
        {
            /* origin and buf are not word-aligned, so we insert a byte */
            buf = rtsmb_pack_add_byte (buf, buf_size, 0);

            if (!buf)
            {
                return (PFVOID)0;
            }
        }

        return rtsmb_pack_add_unicode_string (buf, buf_size, string, nil);
    }
    else
    {
        return rtsmb_pack_add_ascii_string (buf, buf_size, string, nil);
    }
}

/**
 * Adds string to buf.  buf and item must not overlap.
 */
PFVOID rtsmb_pack_add_string_direct (PFVOID buf, PFSIZE buf_size,
    PFRTCHAR string, BBOOL nil, BBOOL unicode)
{
    if (unicode)
    {
        return rtsmb_pack_add_unicode_string (buf, buf_size, string, nil);
    }
    else
    {
        return rtsmb_pack_add_ascii_string (buf, buf_size, string, nil);
    }
}


/**
 * No error checking is performed.
 */
PFVOID rtsmb_pack_add_byte_unsafe (PFVOID buf, byte b)
{
    return rtsmb_pack_add_unsafe (buf, &b, 1);
}

/**
 * Adds b to buf.
 */
PFVOID rtsmb_pack_add_byte (PFVOID buf, PFSIZE buf_size, byte b)
{
    return rtsmb_pack_add (buf, buf_size, &b, 1);
}

/**
 * No error checking is performed.
 */
PFVOID rtsmb_pack_add_word_unsafe (PFVOID buf, word w, BBOOL netorder)
{
    w = (word) ((netorder) ? (SMB_HTONW (w)) : (SMB_HTOIW (w)));

    return rtsmb_pack_add_unsafe (buf, &w, 2);
}

/**
 * Adds w to buf.
 */
PFVOID rtsmb_pack_add_word (PFVOID buf, PFSIZE buf_size,
    word w, BBOOL netorder)
{
    w = (word) ((netorder) ? (SMB_HTONW (w)) : (SMB_HTOIW (w)));

    return rtsmb_pack_add (buf, buf_size, &w, 2);
}

/**
 * No error checking is performed.
 */
PFVOID rtsmb_pack_add_dword_unsafe (PFVOID buf, dword d, BBOOL netorder)
{
    d = (netorder) ? (SMB_HTOND (d)) : (SMB_HTOID (d));

    return rtsmb_pack_add_unsafe (buf, &d, 4);
}

/**
 * Adds dw to buf.
 */
PFVOID rtsmb_pack_add_dword (PFVOID buf, PFSIZE buf_size,
    dword d, BBOOL netorder)
{
    d = (netorder) ? (SMB_HTOND (d)) : (SMB_HTOID (d));

    return rtsmb_pack_add (buf, buf_size, &d, 4);
}

#ifdef SUPPORT_SMB2
/**
 * Adds dw to buf.
 */
PFVOID rtsmb_pack_add_ddword (PFVOID buf, PFSIZE buf_size,
    ddword d, BBOOL netorder)
{
    d = (netorder) ? (SMB_HTONDD (d)) : (SMB_HTOIDD (d));

    return rtsmb_pack_add (buf, buf_size, &d, 8);
}
#endif
