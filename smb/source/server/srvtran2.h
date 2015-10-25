#ifndef __SRV_TRAN2_H__
#define __SRV_TRAN2_H__
//****************************************************************************
//**
//**    srvtran2.h
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvshare.h"
#include "srvssn.h"

//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================

// values for TRANS2_QUERY_FS_INFORMATION informationLevel
#define SMB_INFO_ALLOCATION				0x0001
#define SMB_INFO_VOLUME					0x0002
#define SMB_QUERY_FS_VOLUME_INFO		0x0102
#define SMB_QUERY_FS_SIZE_INFO			0x0103
#define SMB_QUERY_FS_DEVICE_INFO		0x0104
#define SMB_QUERY_FS_ATTRIBUTE_INFO		0x0105

// values for the type of a device
#define FILE_DEVICE_BEEP				0x00000001
#define FILE_DEVICE_CD_ROM				0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM	0x00000003
#define FILE_DEVICE_CONTORLLER			0x00000004
#define FILE_DEVICE_DATALINK			0x00000005
#define FILE_DEVICE_DFS					0x00000006
#define FILE_DEVICE_DISK				0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM	0x00000008
#define FILE_DEVICE_FILE_SYSTEM			0x00000009
#define FILE_DEVICE_INPORT_PORT			0x0000000a
#define FILE_DEVICE_KEYBOARD			0x0000000b
#define FILE_DEVICE_MAILSLOT			0x0000000c
#define FILE_DEVICE_MIDI_IN				0x0000000d
#define FILE_DEVICE_MIDI_OUT			0x0000000e
#define FILE_DEVICE_MOUSE				0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER	0x00000010
#define FILE_DEVICE_NAMED_PIPE			0x00000011
#define FILE_DEVICE_NETWORK				0x00000012
#define FILE_DEVICE_NETWORK_BROWSER		0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM	0x00000014
#define FILE_DEVICE_NULL				0x00000015
#define FILE_DEVICE_PARALLEL_PORT		0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD	0x00000017
#define FILE_DEVICE_PRINTER				0x00000018
#define FILE_DEVICE_SCANNER				0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT	0x0000001a
#define FILE_DEVICE_SERIAL_PORT			0x0000001b
#define FILE_DEVICE_SCREEN				0x0000001c
#define FILE_DEVICE_SOUND				0x0000001d
#define FILE_DEVICE_STREAMS				0x0000001e
#define FILE_DEVICE_TAPE				0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM	0x00000020
#define FILE_DEVICE_TRANSPORT			0x00000021
#define FILE_DEVICE_UNKNOWN				0x00000022
#define FILE_DEVICE_VIDEO				0x00000023
#define FILE_DEVICE_VIRTUAL_DISK		0x00000024
#define FILE_DEVICE_WAVE_IN				0x00000025
#define FILE_DEVICE_WAVE_OUT			0x00000026
#define FILE_DEVICE_8042_PORT			0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR	0x00000028
#define FILE_DEVICE_BATTERY				0x00000029
#define FILE_DEVICE_BUS_EXTENDER		0x0000002a
#define FILE_DEVICE_MODEM				0x0000002b
#define FILE_DEVICE_VDM					0x0000002c

// values for the characteristics of a device
#define FILE_REMOVABLE_MEDIA			0x00000001
#define FILE_READ_ONLY_DEVICE			0x00000002
#define FILE_FLOPPY_DISKETTE			0x00000004
#define FILE_WRITE_ONE_MEDIA			0x00000008
#define FILE_REMOVE_DEVICE				0x00000010
#define FILE_DEVICE_IS_MOUNTED			0x00000020
#define FILE_VIRTUAL_VOLUME				0x00000040

// values for the attributes of a file system
#define ATTRIBUTE_CASE_SENSITIVE_SEARCH		0x00000001
#define ATTRIBUTE_CASE_PRESERVED_NAMES		0x00000002
#define ATTRIBUTE_PERSISTENT_ACLS			0x00000004
#define ATTRIBUTE_FILE_COMPRESSION			0x00000008
#define ATTRIBUTE_VOLUME_QUOTAS				0x00000010
#define ATTRIBUTE_DEVICE_IS_MOUNTED			0x00000020
#define ATTRIBUTE_MAKE_IT_WORK_BETTER		0x00004000 // undocumented flag.  win98 sends it.  makes client send a 
													   // findFirst ("\*") in addition to searching
#define ATTRIBUTE_VOLUME_IS_COMPRESSED		0x00008000

//============================================================================
//    INTERFACE STRUCTURES / UTILITY CLASSES
//============================================================================
//============================================================================
//    INTERFACE DATA DECLARATIONS
//============================================================================
//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================

BBOOL ST2_FindFirst2 (PSMB_SESSIONCTX pCtx, 
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf, 
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left);

BBOOL ST2_FindNext2 (PSMB_SESSIONCTX pCtx, 
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf, 
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left);

BBOOL ST2_QueryFileInfo (PSMB_SESSIONCTX pCtx, 
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf, 
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left);

BBOOL ST2_QueryPathInfo (PSMB_SESSIONCTX pCtx, 
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf, 
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left);

BBOOL ST2_QueryFSInformation (PSMB_SESSIONCTX pCtx, 
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left);

BBOOL ST2_SetFileInformation (PSMB_SESSIONCTX pCtx, 
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left);

BBOOL ST2_SetPathInformation (PSMB_SESSIONCTX pCtx, 
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left);

//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================

//****************************************************************************
//**
//**    END HEADER srvtran2.h
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_TRAN2_H__ */
