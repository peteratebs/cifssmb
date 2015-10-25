//
// COMMONWIRE_SMB2.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles the parsing of all SMB request packets for the server
//
#if (0)  /* SPR changed */
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#include "com_smb2.h"
#include "com_smb2_wiredefs.h"
#include "rtpnet.h"
#include "rtpstr.h"
#include "rtpmem.h"
#include "rtprand.h"


//#include "srvcmds.h"
#include "smbread.h"
#include "smbutil.h"
#include "smbpack.h"
#include "smbread.h"


byte *RTSmb2_Encryption_Get_Spnego_Next_token(dword SessionGlobalId,TYPELESS SecurityContext,rtsmb_size *buffer_size,int *isLast_token,dword *status, byte *InToken, int InTokenLength)
{
    *status = 0;
    *isLast_token=1;
    *buffer_size = sizeof("HELOOFROMSPEGOGETNEXT");
    return (byte *) "HELOOFROMSPEGOGETNEXT";
}
void RTSmb2_Encryption_Release_Spnego_Next_token(byte *Buffer)
{

}

dword RTSmb2_Encryption_Get_Spnego_New_SessionGlobalId(void)
{
    return 99;
}
void  RTSmb2_Encryption_Spnego_Clear_SessionGlobalId(dword SessionId)
{

}
byte *RTSmb2_Encryption_Get_Spnego_Default(rtsmb_size *buffer_size)
{
    *buffer_size = sizeof("HELOOFROMSPEGO");
    return (byte *) "HELOOFROMSPEGO";
}
void RTSmb2_Encryption_Release_Spnego_Default(byte *pBuffer){}
static char *algs[] = {"Algorithm1", "Algorith2","Algorithm3", 0};
byte **RTSmb2_Encryption_Get_AlgorithmList(void){ return (byte **)algs; }
BBOOL RTSmb2_Encryption_SignatureVerify(dword SessionGlobalId,TYPELESS SecurityContext,byte *Key, byte *Signature) {  return TRUE;}
TYPELESS RTSmb2_Encryption_GetSecurityContext(dword SessionGlobalId){return 1024;} ;
BBOOL RTSmb2_Encryption_ValidateNameWithSecurityContext(dword SessionGlobalId,TYPELESS SecurityContext,byte *UserName) {  return TRUE;}
BBOOL RTSmb2_Encryption_SetNameFromSecurityContext(dword SessionGlobalId,TYPELESS SecurityContext,byte *UserName) {  return TRUE;}
BBOOL RTSmb2_Encryption_InquireContextAnon(dword SessionGlobalId,TYPELESS SecurityContext){  return TRUE;}
BBOOL RTSmb2_Encryption_InquireContextGuest(dword SessionGlobalId,TYPELESS SecurityContext){  return TRUE;}

void  RTSmb2_Encryption_SetSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *SessionKey){SessionKey=(byte*)"SESSIONKEY";};
void  RTSmb2_Encryption_Get_Session_SigningKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *pSigningKey, byte *pSessionKey){pSigningKey=(byte*)"SIGNINGKEY";};
void  RTSmb2_Encryption_Get_Session_ApplicationKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *ApplicationKey,byte *SessionKey){ApplicationKey=(byte*)"APP_KEY";}
void  RTSmb2_Encryption_Get_Session_ChannelKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *ChannelKey,byte *pKey){ChannelKey=(byte*)"CHN_KEY";}
void  RTSmb2_Encryption_Get_Session_EncryptionKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *EncryptionKey, byte *SessionKey) {EncryptionKey=(byte*)"DEC_KEY";}
void  RTSmb2_Encryption_Get_Session_DecryptionKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext, byte *DecryptionKey, byte *SessionKey){DecryptionKey=(byte*)"ENC_KEY";}
void  RTSmb2_Encryption_SignMessage(dword SessionGlobalId,TYPELESS SecurityContext,byte *SessionKey, byte *Signature) {Signature=(byte*)"SIGNATURE";}

static byte spnegobuffer_in[1024];
byte *RTSmb2_Encryption_Get_Spnego_InBuffer(rtsmb_size *buffer_size)
{
    *buffer_size=1024;
    return spnegobuffer_in;

}
byte *RTSmb2_Encryption_Get_Encrypt_Buffer(byte *origin, rtsmb_size  buffer_size)
{
    return (byte *)rtp_malloc(buffer_size*2, 0);  /* SPR - added who paramter */
}
void RTSmb2_Encryption_Release_Encrypt_Buffer(byte *buffer)
{
    rtp_free (buffer);;
}

void RTSmb2_Encryption_Release_Spnego_InBuffer(byte *pBuffer)
{

}
int RTSmb2_Encryption_Encrypt_Buffer(byte *Dest, rtsmb_size dest_size, PRTSMB2_TRANSFORM_HEADER ptransform_header, byte *Source, rtsmb_size source_size)
{
rtsmb_size i;
    /* Fake encrypt by placing space after every byte */
    for(i =0; i < source_size; i++)
    {
        *Dest++=*Source++;
        *Dest++=32;
    }
//   rtp_memcpy(Dest, Source, source_size);
   rtp_memcpy(ptransform_header->Signature , "SIGNATURE9ABCDEF" , 16);
   rtp_memcpy(ptransform_header->Nonce,      "NONCE0123456789A" , 16);
   return source_size*2;
}

byte *RTSmb2_Encryption_Get_Decrypted_Buffer(byte *origin, int buffer_size,RTSMB2_TRANSFORM_HEADER *ptransform_header_smb2)
{
int i;
byte *Dest = origin;
byte *Source = origin;
    /* Fake decrypt by taking every other byte */
    for(i =0; i < ptransform_header_smb2->OriginalMessageSize; i++)
    {
        *Dest++=*Source++;
        Source++;
    }
    return origin;
}
void  RTSmb2_Encryption_Release_Decrypted_Buffer(byte *origin)
{
}

void  RTSmb2_Encryption_Sign_message(byte *Signature,byte *Key,byte SigningRule, byte *Message, rtsmb_size messageLength)
{
   rtp_memcpy(Signature , "IMSIGNEDBABYYAYA" , 16);
}



// ======================================

ddword swapdword(const ddword i)
{
    ddword  rval;
    ddword  *input = (ddword  *) &i;
    byte    *data = (byte *)&rval;
    data[0] = *input >> 56;
    data[1] = *input >> 48;
    data[2] = *input >> 40;
    data[3] = *input >> 32;
    data[4] = *input >> 24;
    data[5] = *input >> 16;
    data[6] = *input >> 8;
    data[7] = *input >> 0;
    return rval;
}


/* See RFC4122 */
void rtsmb_util_get_new_Guid(byte *pGuid)
{
ddword t;
dword *pdw;
word  *pw;
byte   *pb;
word clock_seq = (word) tc_rand();
byte node_address[6];

    rtp_net_get_node_address (node_address);
    pdw = (dword *) pGuid;
    t = rtsmb_util_get_current_filetime();
    *pdw++ = (dword) t;     /* [32] Time low */
    pw = (word *) pdw;                     /* [16] Time hi & version */
    *pw++ = (word) (t>>32) & 0xFFFF;       /* [16] Time mid */
    *pw  = (word) (t>>48) & 0x0FFF;        /* [16] Time hi & version */
    *pw++  |= (1<<12);
    pb  =  (byte *) pw;                     /* [16] clock_seq_hi & reserved */
    *pb =  (byte) ((clock_seq & 0x3F00) >> 8);
    *pb++ |= 0x80;
    tc_memcpy(pb, node_address, sizeof (node_address) );
}


const char *DebugSMB2CommandToString(int command)
{
char * r = 0;
	switch(command)
	{
        case SMB2_NEGOTIATE:
            r="SMB2_NEGOTIATE";
			break;
        case SMB2_SESSION_SETUP  :
            r="SMB2_SESSION_SETUP  ";
			break;
        case SMB2_LOGOFF         :
            r="SMB2_LOGOFF         ";
			break;
        case SMB2_TREE_CONNECT   :
            r="SMB2_TREE_CONNECT   ";
			break;
        case SMB2_TREE_DISCONNECT:
            r="SMB2_TREE_DISCONNECT";
			break;
        case SMB2_CREATE         :
            r="SMB2_CREATE         ";
			break;
        case SMB2_CLOSE          :
            r="SMB2_CLOSE          ";
			break;
        case SMB2_FLUSH          :
            r="SMB2_FLUSH          ";
			break;
        case SMB2_READ           :
            r="SMB2_READ           ";
			break;
        case SMB2_WRITE          :
            r="SMB2_WRITE          ";
			break;
        case SMB2_LOCK           :
            r="SMB2_LOCK           ";
			break;
        case SMB2_IOCTL          :
            r="SMB2_IOCTL          ";
			break;
        case SMB2_CANCEL         :
            r="SMB2_CANCEL         ";
			break;
        case SMB2_ECHO           :
            r="SMB2_ECHO           ";
			break;
        case SMB2_QUERY_DIRECTORY:
            r="SMB2_QUERY_DIRECTORY";
			break;
        case SMB2_CHANGE_NOTIFY  :
            r="SMB2_CHANGE_NOTIFY  ";
			break;
        case SMB2_QUERY_INFO     :
            r="SMB2_QUERY_INFO     ";
			break;
        case SMB2_SET_INFO       :
            r="SMB2_SET_INFO       ";
			break;
        case SMB2_OPLOCK_BREAK   :
            r="SMB2_OPLOCK_BREAK   ";
			break;
		default:
		    r=("UNKOWN COMMAND");
		    break;
	}
    return r;
}
#endif