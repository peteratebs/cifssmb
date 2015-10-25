#ifndef __SMB_SJIS_H__
#define __SMB_SJIS_H__
/* Return the length of a JIS character, 1 or 2 */

#define JIS_CHAR_LEN(C)    (((((unsigned char)(C)) >= 0x81 && ((unsigned char)(C)) <= 0x9f) || \
                             (((unsigned char)(C)) >= 0xe0 && ((unsigned char)(C)) <= 0xfc))? 2 : 1)
#define EUC_JP_CHAR_LEN(C) (((C) & 0x80)? 2 : 1)


int rtsmb_jis_to_unicode (unsigned short *u, const unsigned char *sjisChar);
int rtsmb_unicode_to_jis (unsigned char *pjis, unsigned short u);

int rtsmb_euc_jp_to_unicode (unsigned short *uc, const unsigned short *eucJp);
int rtsmb_unicode_to_euc_jp (unsigned char *eucJp, unsigned short uc);

#endif  /* __SMB_SJIS_H__ */
