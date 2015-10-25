#ifndef __SMB2_H__
#define __SMB2_H__

#include <stdio.h>

#include "com_smb2_wiredefs.h"




//****************************************************************************
//**
//**    smb2.h
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
#include "com_smb2_ssn.h"
//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================



extern void Smb2SrvModel_Global_Init(void);


#define RTSMB2_NBSS_TRANSFORM_HEADER_SIZE 52


//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================


#define TYPELESS int /* Types currently unresolved design */
#define HEREHERE

//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================

/*  Returns a list of supported Encryption algorithms */
extern void RTSmb2_Encryption_Release_Spnego_Default(byte *pBuffer);
extern byte *RTSmb2_Encryption_Get_Spnego_InBuffer(rtsmb_size *buffer_size);
extern byte *RTSmb2_Encryption_Get_Spnego_Next_token(dword SessionGlobalId,TYPELESS SecurityContext,rtsmb_size *buffer_size,int *isLast_token,dword *status, byte *InToken, int InTokenLength);
extern byte *RTSmb2_Encryption_Get_Encrypt_Buffer(byte *origin, rtsmb_size buffer_size);
extern void RTSmb2_Encryption_Release_Encrypt_Buffer(byte *buffer);
int RTSmb2_Encryption_Encrypt_Buffer(byte *Dest, rtsmb_size dest_size, PRTSMB2_TRANSFORM_HEADER ptransform_header, byte *Source, rtsmb_size source_size);
extern dword RTSmb2_Encryption_Get_Spnego_New_SessionGlobalId(void);
extern void  RTSmb2_Encryption_Spnego_Clear_SessionGlobalId(dword SessionId);
extern byte *RTSmb2_Encryption_Get_Spnego_Default(rtsmb_size *buffer_size);
extern byte **RTSmb2_Encryption_Get_AlgorithmList(void);
extern BBOOL RTSmb2_Encryption_SignatureVerify(dword SessionGlobalId,TYPELESS SecurityContext,byte *Key, byte *Signature);
extern void  RTSmb2_Encryption_Sign_message(byte *Signature,byte *Key,byte SigningRule, byte *Message, rtsmb_size messageLength);
extern TYPELESS RTSmb2_Encryption_GetSecurityContext(dword SessionGlobalId);
extern BBOOL RTSmb2_Encryption_ValidateNameWithSecurityContext(dword SessionGlobalId,TYPELESS SecurityContext,byte *UserName);
extern BBOOL RTSmb2_Encryption_SetNameFromSecurityContext(dword SessionGlobalId,TYPELESS SecurityContext,byte *UserName);
extern BBOOL RTSmb2_Encryption_InquireContextAnon(dword SessionGlobalId,TYPELESS SecurityContext);
extern BBOOL RTSmb2_Encryption_InquireContextGuest(dword SessionGlobalId,TYPELESS SecurityContext);

extern void RTSmb2_Encryption_Release_Spnego_Next_token(byte *Buffer);
extern void RTSmb2_Encryption_Release_Spnego_InBuffer(byte *pBuffer);
extern void  RTSmb2_Encryption_Release_Decrypted_Buffer(byte *origin);
byte *RTSmb2_Encryption_Get_Decrypted_Buffer(byte *origin, int buffer_size,RTSMB2_TRANSFORM_HEADER *ptransform_header_smb2);

extern void  RTSmb2_Encryption_SetSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *SessionKey);
extern void  RTSmb2_Encryption_Get_Session_SigningKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *pSigningKey, byte *pSessionKey);
extern void  RTSmb2_Encryption_Get_Session_ApplicationKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *ApplicationKey,byte *SessionKey);
extern void  RTSmb2_Encryption_Get_Session_ChannelKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *SigningKey,byte *pKey);
extern void  RTSmb2_Encryption_Get_Session_EncryptionKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *EncryptionKey, byte *SessionKey);
extern void  RTSmb2_Encryption_Get_Session_DecryptionKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext, byte *DecryptionKey, byte *SessionKey);
extern void  RTSmb2_Encryption_SignMessage(dword SessionGlobalId,TYPELESS SecurityContext,byte *SessionKey, byte *Signature);

extern const char *DebugSMB2CommandToString(int command);


//****************************************************************************
//**
//**    END HEADER smb2.h
//**
//****************************************************************************
#endif // __SMB2_H__
