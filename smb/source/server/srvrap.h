#ifndef __SRV_RAP_H__
#define __SRV_RAP_H__
//****************************************************************************
//**
//**    RAP.H
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvssn.h"

//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
#define RAP_COM_NET_SHARE_ENUM		0
#define RAP_COM_NET_SHARE_GETINFO	1
#define RAP_COM_NET_SERVER_GETINFO	13
#define RAP_COM_NET_ACCESS_GETINFO	42
#define RAP_COM_NET_WKSTA_GETINFO	63
#define RAP_COM_WPRINTQ_GETINFO		70
#define RAP_COM_NET_SERVER_ENUM2	104

//============================================================================
//    INTERFACE STRUCTURES / UTILITY CLASSES
//============================================================================
//============================================================================
//    INTERFACE DATA DECLARATIONS
//============================================================================
//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================

int RAP_Proc (PSMB_SESSIONCTX pCtx, 
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf, 
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left);
	
//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================

//****************************************************************************
//**
//**    END HEADER RAP.H
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_RAP_H__ */
