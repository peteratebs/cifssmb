//
// SMBBREAD.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Basic reading functions from the buffer (incoming packet)
//


#include "smbread.h"
#include "smbutil.h"


/**
 * No error checking is performed.
 */
PFVOID rtsmb_read_unsafe (PFVOID buf, PFVOID item, rtsmb_size item_size)
{
    tc_memcpy (item, buf, item_size);

    return PADD (buf, item_size);
}

/**
 * Adds item to buf, wrt sizes.  buf and item must not overlap.
 */
PFVOID rtsmb_read (PFVOID buf, PFSIZE buf_size,
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

    if (item)
        tc_memcpy (item, buf, item_size);

    rv = PADD (buf, item_size);

    *buf_size -= item_size;

    return rv;
}

PFVOID rtsmb_read_skip (PFVOID buf, PFSIZE buf_size, rtsmb_size skip_size)
{
    if (skip_size > *buf_size)
    {
        /**
         * We don't have room.  Bail.
         */
        return (PFVOID)0;
    }

    *buf_size -= skip_size;

    return PADD (buf, skip_size);
}

/* If num_bytes >= 0, then that many bytes will be read.  Otherwise, we
go until a null-byte */
RTSMB_STATIC
PFVOID rtsmb_read_ascii_string (PFVOID buf, PFSIZE buf_size,
    PFRTCHAR string, rtsmb_size string_size, int num_bytes)
{
    byte b;
    rtsmb_size num_chars = 0, null_spot = 0;
    byte temp_string[60];

    if (string_size > 60)
    {
        string_size = 60;
    }

    if (num_bytes)
    {
        do
        {
            if ((buf = rtsmb_read_byte (buf, buf_size, &b)) == (PFVOID)0)
            {
                return (PFVOID)0;
            }

            if (string_size > num_chars)
            {
                temp_string[num_chars] = b;
                null_spot = num_chars;
            }

            num_bytes --;
            num_chars ++;
        } while ((num_bytes < 0) ? b : num_bytes);
    }

    if (num_bytes == 0) // we exited previous loop by reading all of specified bytes
    {
        // because we didn't loop around again, we need to increment null_spot
        if (string_size > num_chars)
        {
            null_spot ++;
        }
    }
    temp_string[null_spot] = '\0';

    //convert 8-bit string to unicode (using current codepage) if RTSMB is using
    //unicode
    if (string)
    {
        rtsmb_util_ascii_to_rtsmb (temp_string, string, CFG_RTSMB_USER_CODEPAGE);
    }

    return buf;
}

/* If num_bytes >= 0, then that many bytes will be read.  Otherwise, we
go until a null-byte */
RTSMB_STATIC
PFVOID rtsmb_read_unicode_string (PFVOID buf, PFSIZE buf_size,
    PFRTCHAR string, rtsmb_size string_size, int num_bytes)
{
    word w;
    rtsmb_size num_chars = 0, null_spot = 0;

    if (num_bytes >= 0 && num_bytes % 2)
    {
        num_bytes++; /* read that extra bit -- though, this probably breaks no matter what */
    }
    if (num_bytes)
    {
        do
        {
            if ((buf = rtsmb_read_word (buf, buf_size, &w, FALSE)) == (PFVOID)0)
            {
                return (PFVOID)0;
            }

            if (string_size > num_chars)
            {
                if (string)
                {
#if (INCLUDE_RTSMB_UNICODE)
                    string[num_chars] = w;
#else
                    /* we ignore upper bits.  sorry, but no way to cleanly go back to ascii */
                    string[num_chars] = (char) (w & 0xFF);
#endif
                    null_spot = num_chars;
                }
            }

            num_bytes -= 2;
            num_chars ++;
        } while ((num_bytes < 0) ? w : num_bytes);
    }

    if (num_bytes == 0) /* we exited previous loop by reading all of specified bytes */
    {
        /* because we didn't loop around again, we need to increment null_spot */
        if (string_size > num_chars)
            null_spot ++;
    }

    if (string)
    {
        string[null_spot] = '\0';
    }

    return buf;
}

/**
 * Reads string from buf.  buf and item must not overlap.
 *
 * |string_size| is the max character size of the string.
 *
 * If |origin| is NULL, the string is ascii.  If |origin| is non-NULL,
 * the string is unicode, and |origin| points to the beginning of the
 * SMB message.
 */
PFVOID rtsmb_read_string (PFVOID buf, PFSIZE buf_size,
    PFRTCHAR string, rtsmb_size string_size, PFVOID origin)
{
    if (origin)
    {
        /* start of string and start of SMB must be word-aligned. */
        if ((((RTP_ADDR) origin) % 2) != (((RTP_ADDR) buf) % 2))
        {
            /* origin and buf are not word-aligned, so we pass a byte */
            buf = rtsmb_read_skip (buf, buf_size, 1);

            if (!buf)
            {
                return (PFVOID)0;
            }
        }
        return rtsmb_read_unicode_string (buf, buf_size, string, string_size, -1);
    }
    else
    {
        return rtsmb_read_ascii_string (buf, buf_size, string, string_size, -1);
    }
}

/**
 * |string_size| is the max character size of the string.
 *
 * If |origin| is NULL, the string is ascii.  If |origin| is non-NULL,
 * the string is unicode, and |origin| points to the beginning of the
 * SMB message.
 *
 * 'null' means is there a null in the buffer that we should pass?
 */
PFVOID rtsmb_read_string_bytes (PFVOID buf, PFSIZE buf_size,
    PFRTCHAR string, rtsmb_size string_size, rtsmb_size to_read, BBOOL null, PFVOID origin)
{
    PFVOID rv;

    if (origin)
    {
        /* start of string and start of SMB must be word-aligned. */
        if ((((RTP_ADDR) origin) % 2) != (((RTP_ADDR) buf) % 2))
        {
            /* origin and buf are not word-aligned, so we pass a byte */
            buf = rtsmb_read_skip (buf, buf_size, 1);

            if (!buf)
            {
                return (PFVOID) 0;
            }
        }
        rv = rtsmb_read_unicode_string (buf, buf_size, string, string_size, (int)   to_read);

        if (rv && null)
        {
            rv = rtsmb_read_skip (rv, buf_size, 2);
        }
    }
    else
    {
        rv = rtsmb_read_ascii_string (buf, buf_size, string, string_size, (int) to_read);

        if (rv && null)
        {
            rv = rtsmb_read_skip (rv, buf_size, 1);
        }
    }

    return rv;
}


/**
 * No error checking is performed.
 */
PFVOID rtsmb_read_byte_unsafe (PFVOID buf, PFBYTE b)
{
    return rtsmb_read_unsafe (buf, b, 1);
}

/**
 * Adds b to buf.
 */
PFVOID rtsmb_read_byte (PFVOID buf, PFSIZE buf_size, PFBYTE b)
{
    return rtsmb_read (buf, buf_size, b, 1);
}

/**
 * No error checking is performed.
 */
PFVOID rtsmb_read_word_unsafe (PFVOID buf, PFWORD w, BBOOL netorder)
{
    PFVOID rv;

    rv = rtsmb_read_unsafe (buf, w, 2);

    *w = (word) ((netorder) ? (SMB_NTOHW (*w)) : (SMB_ITOHW (*w)));

    return rv;
}

/**
 * Adds w to buf.
 */
PFVOID rtsmb_read_word (PFVOID buf, PFSIZE buf_size,
    PFWORD w, BBOOL netorder)
{
    PFVOID rv;

    rv = rtsmb_read (buf, buf_size, w, 2);

    *w = (word) ((netorder) ? (SMB_NTOHW (*w)) : (SMB_ITOHW (*w)));

    return rv;
}

/**
 * No error checking is performed.
 */
PFVOID rtsmb_read_dword_unsafe (PFVOID buf, PFDWORD d, BBOOL netorder)
{
    PFVOID rv;

    rv = rtsmb_read_unsafe (buf, d, 4);

    *d = (netorder) ? (SMB_NTOHD (*d)) : (SMB_ITOHD (*d));

    return rv;
}

/**
 * Adds dw to buf.
 */
PFVOID rtsmb_read_dword (PFVOID buf, PFSIZE buf_size,
    PFDWORD d, BBOOL netorder)
{
    PFVOID rv;

    rv = rtsmb_read (buf, buf_size, d, 4);

    *d = (netorder) ? (SMB_NTOHD (*d)) : (SMB_ITOHD (*d));

    return rv;
}

#ifdef SUPPORT_SMB2
/**
 * Adds ddw to buf.
 */
PFVOID rtsmb_read_ddword (PFVOID buf, PFSIZE buf_size,
    PFDDWORD d, BBOOL netorder)
{
    PFVOID rv;

    rv = rtsmb_read (buf, buf_size, d, 8);

    *d = (netorder) ? (SMB_NTOHDD (*d)) : (SMB_ITOHDD (*d));

    return rv;
}
#endif
