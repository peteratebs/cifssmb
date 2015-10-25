//
// SRVTRAN2.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Trans2 is a sub protocol within the SMB protocol.  This file handles SMB
// Tran2 packets that come in
//

//============================================================================
//    IMPLEMENTATION HEADERS
//============================================================================
#include "smbdefs.h"

#include "rtpwcs.h" /* _YI_ 9/24/2004 */
#include "smbdebug.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvtran2.h"
#include "srvassrt.h"
#include "srvauth.h"
#include "srvfio.h"
#include "srvutil.h"
#include "smb.h"
#include "srvcmds.h"
#include "smbutil.h"
#include "srvans.h"

#include "srvcfg.h"

#include "rtptime.h"


//============================================================================
//    IMPLEMENTATION PRIVATE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
#define SMB_INFO_STANDARD					1
#define SMB_INFO_QUERY_EA_SIZE				2
#define SMB_INFO_QUERY_EAS_FROM_LIST		3
#define SMB_INFO_QUERY_ALL_EAS				4
#define SMB_INFO_IS_NAME_VALID				6
#define SMB_SET_FILE_BASIC_INFO             0x101
#define SMB_SET_FILE_DISPOSITION_INFO       0x102
#define SMB_SET_FILE_ALLOCATION_INFO        0x103
#define SMB_SET_FILE_END_OF_FILE_INFO       0x104

// used for find_first, find_next
#define SMB_FIND_FILE_DIRECTORY_INFO		0x101
#define	SMB_FIND_FILE_FULL_DIRECTORY_INFO	0x102
#define SMB_FIND_FILE_NAMES_INFO			0x103
#define SMB_FIND_FILE_BOTH_DIRECTORY_INFO	0x104

// used for query_path and query_file
#define SMB_QUERY_FILE_BASIC_INFO			0x101
#define SMB_QUERY_FILE_STANDARD_INFO		0x102
#define SMB_QUERY_FILE_EA_INFO				0x103
#define SMB_QUERY_FILE_NAME_INFO			0x104
#define SMB_QUERY_FILE_ALL_INFO				0x107
#define SMB_QUERY_FILE_ALT_NAME_INFO		0x108
#define SMB_QUERY_FILE_STREAM_INFO			0x109
#define SMB_QUERY_FILE_COMPRESSION_INFO		0x10B

#define FIND_FLAG_CLOSE_SEARCH				0x0001
#define FIND_FLAG_CLOSE_SEARCH_IF_END		0x0002
#define FIND_FLAG_RETURN_RESUME_KEYS		0x0004
#define FIND_FLAG_CONTINUE_SEARCH			0x0008
#define FIND_FLAG_BACKUP_INTENT				0x0010

//============================================================================
//    IMPLEMENTATION PRIVATE STRUCTURES
//============================================================================
//============================================================================
//    IMPLEMENTATION REQUIRED EXTERNAL REFERENCES (AVOID)
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE DATA
//============================================================================
//============================================================================
//    INTERFACE DATA
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTION PROTOTYPES
//============================================================================


//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTIONS
//============================================================================

// takes a context and fills out an smb packet for allocation info
// returns size of data
int fillSMB_INFO_ALLOCATION (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size)
{
	RTSMB_INFO_ALLOCATION info;
	dword blocks;
	dword bfree;
	dword sectors;
	word bytes;

	if (SMBFIO_GetFree (pCtx, pCtx->tid, &blocks, &bfree, &sectors, &bytes) == FALSE)
	{
		RTSMB_DEBUG_OUTPUT_STR("fillSMB_INFO_ALLOCATION: Error getting free space.\n", RTSMB_DEBUG_TYPE_ASCII);
		SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);
		return 0;
	}

	// flesh out SMB_INFO_ALLOCATION struct
	info.file_system_id = 0;
	info.sectors_per_unit = sectors;
	info.total_units = blocks;
	info.available_units = bfree;
	info.bytes_per_sector = bytes;

	return srv_cmd_fill_info_allocation (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

// takes a context and fills out an smb packet for volume info
// returns size of data
int fillSMB_INFO_VOLUME (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size)
{
	RTSMB_INFO_VOLUME info;
	rtsmb_char label[] = {'R', 'T', 'S', 'M', 'B', ' ', 'V', 'O', 'L', '\0'};

	// flesh out RTSMB_INFO_VOLUME struct
	info.serial_number = 0xfad32;
	info.label = label;

	return srv_cmd_fill_info_volume (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

// takes a context and fills out an smb packet for fs volume info
// returns size of data
int fillSMB_QUERY_FS_VOLUME_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size)
{
	RTSMB_QUERY_FS_VOLUME_INFO info;
	rtsmb_char label[] = {'R', 'T', 'S', 'M', 'B', ' ', 'V', 'O', 'L', '\0'};

	// flesh out SMB_QUERY_FS_VOLUME_INFO struct
	info.low_creation_time = 0;
	info.high_creation_time = 0;
	info.serial_number = 0xfad32;
	info.label = label;

	return srv_cmd_fill_query_fs_volume_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

// takes a context and fills out an smb packet for fs size info
// returns size of data
int fillSMB_QUERY_FS_SIZE_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size)
{
	RTSMB_QUERY_FS_SIZE_INFO info;
	dword blocks;
	dword bfree;
	dword sectors;
	word bytes;

	if (SMBFIO_GetFree (pCtx, pCtx->tid, &blocks, &bfree, &sectors, &bytes) == FALSE)
	{
		RTSMB_DEBUG_OUTPUT_STR("fillSMB_QUERY_FS_SIZE_INFO: Error getting free space.\n", RTSMB_DEBUG_TYPE_ASCII);
		SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);
		return 0;
	}

	// flesh out SMB_QUERY_FS_SIZE_INFO struct
	info.low_total_units = blocks;
	info.high_total_units = 0;
	info.low_free_units = bfree;
	info.high_free_units = 0;
	info.sectors_per_unit = sectors;
	info.bytes_per_sector = bytes;

	return srv_cmd_fill_query_fs_size_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

// takes a context and fills out an smb packet for fs device info
// returns size of data
int fillSMB_QUERY_FS_DEVICE_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size)
{
	RTSMB_QUERY_FS_DEVICE_INFO info;

	// flesh out SMB_QUERY_FS_DEVICE_INFO struct
	info.device_type = FILE_DEVICE_DISK_FILE_SYSTEM; // not too sure about this
	info.characteristics = FILE_REMOVABLE_MEDIA; // this is clearly application dependent

	return srv_cmd_fill_query_fs_device_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

// takes a context and fills out an smb packet for fs attribute info
// returns size of data
int fillSMB_QUERY_FS_ATTRIBUTE_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size)
{
	RTSMB_QUERY_FS_ATTRIBUTE_INFO info;
	rtsmb_char fs_name[] = {'F', 'A', 'T', '3', '2', '\0'};

	// flesh out SMB_QUERY_FS_ATTRIBUTE_INFO struct
	info.attributes = ATTRIBUTE_CASE_SENSITIVE_SEARCH | ATTRIBUTE_PERSISTENT_ACLS
								| ATTRIBUTE_CASE_PRESERVED_NAMES
								| ATTRIBUTE_MAKE_IT_WORK_BETTER; // see srvtran2.h
	info.max_filename_size = SMBF_FILENAMESIZE;
	info.fs_name = fs_name;

	return srv_cmd_fill_query_fs_attribute_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_INFO_STANDARD (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBDSTAT stat, BBOOL doResume, dword resume_key)
{
	RTSMB_FIND_FILE_INFO_STANDARD info;
	DATE_STR adate, wdate, cdate;

	info.valid_resume_key = doResume;
	info.resume_key = resume_key;

	adate = rtsmb_util_time_ms_to_date (stat->fatime64);
	wdate = rtsmb_util_time_ms_to_date (stat->fwtime64);
	cdate = rtsmb_util_time_ms_to_date (stat->fctime64);
	info.last_access_date = adate.date;
	info.last_access_time = adate.time;
	info.creation_date = cdate.date;
	info.creation_time = cdate.time;
	info.last_write_date = wdate.date;
	info.last_write_time = wdate.time;

	info.file_size = stat->fsize;
	info.allocation_size = stat->fsize;
	info.attributes = rtsmb_util_rtsmb_to_smb_attributes (stat->fattributes);

 	info.filename = (PFRTCHAR) stat->filename;
	info.filename_size = (byte)(rtsmb_len (info.filename) * sizeof (rtsmb_char));

	return srv_cmd_fill_find_file_info_standard (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

// bad naming, i know -- this if for info requests, not find
int fillSMB_INFO_STANDARD2 (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBFSTAT stat)
{
	RTSMB_INFO_STANDARD info;
	DATE_STR adate, cdate, wdate;

	adate = rtsmb_util_time_ms_to_date (stat->f_atime64);
	wdate = rtsmb_util_time_ms_to_date (stat->f_wtime64);
	cdate = rtsmb_util_time_ms_to_date (stat->f_ctime64);
	info.last_access_date = adate.date;
	info.last_access_time = adate.time;
	info.creation_date = cdate.date;
	info.creation_time = cdate.time;
	info.last_write_date = wdate.date;
	info.last_write_time = wdate.time;

	// allocationSize may not be correct
	info.file_size = stat->f_size;
	info.allocation_size = stat->f_size;
	info.attributes = rtsmb_util_rtsmb_to_smb_attributes (stat->f_attributes);

	return srv_cmd_fill_info_standard (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_INFO_QUERY_EA_SIZE (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBDSTAT stat, BBOOL doResume, dword resume_key)
{
	RTSMB_FIND_FILE_INFO_QUERY_EA_SIZE info;
	DATE_STR adate, cdate, wdate;

	info.valid_resume_key = doResume;
	info.resume_key = resume_key;

	adate = rtsmb_util_time_ms_to_date (stat->fatime64);
	wdate = rtsmb_util_time_ms_to_date (stat->fwtime64);
	cdate = rtsmb_util_time_ms_to_date (stat->fctime64);
	info.last_access_date = adate.date;
	info.last_access_time = adate.time;
	info.creation_date = cdate.date;
	info.creation_time = cdate.time;
	info.last_write_date = wdate.date;
	info.last_write_time = wdate.time;

	info.file_size = stat->fsize;
	info.allocation_size = stat->fsize;
	info.attributes = rtsmb_util_rtsmb_to_smb_attributes (stat->fattributes);
	info.ea_size = 0;

	info.filename = (PFRTCHAR) stat->filename;
	info.filename_size = (byte)rtsmb_len (info.filename);

	return srv_cmd_fill_find_file_info_query_ea_size (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_INFO_QUERY_EA_SIZE2 (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBFSTAT stat)
{
	RTSMB_INFO_QUERY_EA_SIZE info;
	DATE_STR adate, cdate, wdate;

	adate = rtsmb_util_time_ms_to_date (stat->f_atime64);
	wdate = rtsmb_util_time_ms_to_date (stat->f_wtime64);
	cdate = rtsmb_util_time_ms_to_date (stat->f_ctime64);
	info.last_access_date = adate.date;
	info.last_access_time = adate.time;
	info.creation_date = cdate.date;
	info.creation_time = cdate.time;
	info.last_write_date = wdate.date;
	info.last_write_time = wdate.time;

	info.file_size = stat->f_size;
	info.allocation_size = stat->f_size;
	info.attributes = rtsmb_util_rtsmb_to_smb_attributes (stat->f_attributes);
	info.ea_size = 0;

	return srv_cmd_fill_info_query_ea_size (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_FIND_FILE_DIRECTORY_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBDSTAT stat)
{
	RTSMB_FIND_FILE_DIRECTORY_INFO info;

	info.low_last_access_time = stat->fatime64.low_time;
	info.high_last_access_time = stat->fatime64.high_time;
	info.low_creation_time = stat->fctime64.low_time;
	info.high_creation_time = stat->fctime64.high_time;
	info.low_last_write_time = stat->fwtime64.low_time;
	info.high_last_write_time = stat->fwtime64.high_time;
	info.low_change_time = stat->fhtime64.low_time;
	info.high_change_time = stat->fhtime64.high_time;
	info.low_end_of_file = stat->fsize;
	info.high_end_of_file = 0;
	info.low_allocation_size = stat->fsize;
	info.high_allocation_size = 0;

	info.extended_file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat->fattributes);

	info.filename = (PFRTCHAR) stat->filename;

	info.file_index = 0;

	return srv_cmd_fill_find_file_directory_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_FIND_FILE_FULL_DIRECTORY_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBDSTAT stat)
{
	RTSMB_FIND_FILE_FULL_DIRECTORY_INFO info;

	info.low_last_access_time = stat->fatime64.low_time;
	info.high_last_access_time = stat->fatime64.high_time;
	info.low_creation_time = stat->fctime64.low_time;
	info.high_creation_time = stat->fctime64.high_time;
	info.low_last_write_time = stat->fwtime64.low_time;
	info.high_last_write_time = stat->fwtime64.high_time;
	info.low_change_time = stat->fhtime64.low_time;
	info.high_change_time = stat->fhtime64.high_time;
	info.low_end_of_file = stat->fsize;
	info.high_end_of_file = 0;
	info.low_allocation_size = stat->fsize;
	info.high_allocation_size = 0;

	info.extended_file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat->fattributes);

	info.filename = (PFRTCHAR) stat->filename;

	info.file_index = 0;
	info.ea_size = 0;

	return srv_cmd_fill_find_file_full_directory_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}


int fillSMB_FIND_FILE_BOTH_DIRECTORY_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBDSTAT stat)
{
	RTSMB_FIND_FILE_BOTH_DIRECTORY_INFO info;
	rtsmb_char dosname [CFG_RTSMB_EIGHT_THREE_BUFFER_SIZE];

	info.low_last_access_time = stat->fatime64.low_time;
	info.high_last_access_time = stat->fatime64.high_time;
	info.low_creation_time = stat->fctime64.low_time;
	info.high_creation_time = stat->fctime64.high_time;
	info.low_last_write_time = stat->fwtime64.low_time;
	info.high_last_write_time = stat->fwtime64.high_time;
	info.low_change_time = stat->fhtime64.low_time;
	info.high_change_time = stat->fhtime64.high_time;
	info.low_end_of_file = stat->fsize;
	info.high_end_of_file = 0;
	info.low_allocation_size = stat->fsize;
	info.high_allocation_size = 0;

	info.extended_file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat->fattributes);

	info.filename = (PFRTCHAR) stat->filename;

	SMBU_DOSifyName (info.filename, dosname, '\0');
	info.short_name_size = (byte)rtsmb_len ((PFRTCHAR) stat->short_filename);
	rtsmb_cpy (info.short_name, (PFRTCHAR) stat->short_filename);

	info.file_index = 0;
	info.ea_size = 0;

	return srv_cmd_fill_find_file_both_directory_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_FIND_FILE_NAMES_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBDSTAT stat)
{
	RTSMB_FIND_FILE_NAMES_INFO info;

	info.filename = (PFRTCHAR) stat->filename;
	info.filename_size = rtsmb_len (info.filename) * sizeof (rtsmb_char);

	info.file_index = 0;

	return srv_cmd_fill_find_file_names_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

void fillSMB_INFO_IS_NAME_VALID (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pOutHdr, PFRTCHAR fileName)
{
	rtsmb_char buf [SMBF_FILENAMESIZE + 1];

	// try to expand the name.  this will catch common name problems
	if (!SMBFIO_ExpandName (pCtx, pCtx->tid, fileName, buf, SMBF_FILENAMESIZE + 1))
	{
		pOutHdr->status = SMBU_MakeError (SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
	}
}

int fillSMB_QUERY_FILE_BASIC_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBFSTAT stat)
{
	RTSMB_QUERY_FILE_BASIC_INFO info;

	info.low_last_access_time = stat->f_atime64.low_time;
	info.high_last_access_time = stat->f_atime64.high_time;
	info.low_creation_time = stat->f_ctime64.low_time;
	info.high_creation_time = stat->f_ctime64.high_time;
	info.low_last_write_time = stat->f_wtime64.low_time;
	info.high_last_write_time = stat->f_wtime64.high_time;
	info.low_change_time = stat->f_htime64.low_time;
	info.high_change_time = stat->f_htime64.high_time;

	info.attributes = rtsmb_util_rtsmb_to_smb_attributes (stat->f_attributes);

	return srv_cmd_fill_query_file_basic_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_QUERY_FILE_STANDARD_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBFSTAT stat)
{
	RTSMB_QUERY_FILE_STANDARD_INFO info;

	info.low_allocation_size = stat->f_size;
	info.high_allocation_size = 0;
	info.low_end_of_file = stat->f_size;
	info.high_end_of_file = 0;

	info.number_of_links = 1; // we have no way to know
	info.delete_pending = FALSE; // we have no way to know
	info.is_directory = (stat->f_attributes & RTP_FILE_ATTRIB_ISDIR) ? 1 : 0;

	return srv_cmd_fill_query_file_standard_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_QUERY_FILE_EA_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBFSTAT stat)
{
	RTSMB_QUERY_FILE_EA_INFO info;

	info.ea_size = 0;

	return srv_cmd_fill_query_file_ea_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_QUERY_FILE_NAME_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PFRTCHAR filename)
{
	RTSMB_QUERY_FILE_NAME_INFO info;

	info.filename_size = rtsmb_len (filename);
	info.filename = filename;

	return srv_cmd_fill_query_file_name_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_QUERY_FILE_COMPRESSION_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBFSTAT stat)
{
	RTSMB_QUERY_FILE_COMPRESSION_INFO info;

	info.low_compressed_file_size = stat->f_size;
	info.high_compressed_file_size = 0;

	info.compression_format = 0;
	info.compression_unit_shift = 0;
	info.chunk_shift = 0;
	info.cluster_shift = 0;

	return srv_cmd_fill_query_file_compression_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillSMB_QUERY_FILE_STREAM_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBFSTAT stat, PFRTCHAR filename)
{
	RTSMB_QUERY_FILE_STREAM_INFO info;

	info.low_stream_size = stat->f_size;
	info.high_stream_size = 0;
	info.low_allocation_size = stat->f_size;
	info.high_allocation_size = 0;

	info.stream_name = filename;

	return srv_cmd_fill_query_file_stream_info (pCtx->write_origin, pOutBuf, size,
		pOutHdr, &info);
}

int fillFindWithInfo (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFBYTE *pByte, rtsmb_size size, PSMBDSTAT stat, word infoLevel, word flags)
{
	int r;
	int rv = 0;

	switch (infoLevel)
	{
	case SMB_INFO_STANDARD:
		if (ON (flags, FIND_FLAG_RETURN_RESUME_KEYS))
			r = fillSMB_INFO_STANDARD (pCtx, pInHdr, pOutHdr, *pByte, size, stat, TRUE, 0);
		else
			r = fillSMB_INFO_STANDARD (pCtx, pInHdr, pOutHdr, *pByte, size, stat, FALSE, 0);
		if (r == -1)
			rv = -1;
		else
			*pByte = PADD (*pByte, r);
		break;

	case SMB_INFO_QUERY_EA_SIZE:
		if (ON (flags, FIND_FLAG_RETURN_RESUME_KEYS))
			r = fillSMB_INFO_QUERY_EA_SIZE (pCtx, pInHdr, pOutHdr, *pByte, size, stat, TRUE, 0);
		else
			r = fillSMB_INFO_QUERY_EA_SIZE (pCtx, pInHdr, pOutHdr, *pByte, size, stat, FALSE, 0);
		if (r == -1)
			rv = -1;
		else
			*pByte = PADD (*pByte, r);
		break;

	case SMB_INFO_QUERY_EAS_FROM_LIST:
		if (ON (flags, FIND_FLAG_RETURN_RESUME_KEYS))
			r = fillSMB_INFO_QUERY_EA_SIZE (pCtx, pInHdr, pOutHdr, *pByte, size, stat, TRUE, 0);
		else
			r = fillSMB_INFO_QUERY_EA_SIZE (pCtx, pInHdr, pOutHdr, *pByte, size, stat, FALSE, 0);
		if (r == -1)
			rv = -1;
		else
			*pByte = PADD (*pByte, r);
		break;

	case SMB_FIND_FILE_DIRECTORY_INFO:
		r = fillSMB_FIND_FILE_DIRECTORY_INFO (pCtx, pInHdr, pOutHdr, *pByte, size, stat);
		if (r == -1)
			rv = -1;
		else
			*pByte = PADD (*pByte, r);
		break;

	case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
		r = fillSMB_FIND_FILE_FULL_DIRECTORY_INFO (pCtx, pInHdr, pOutHdr, *pByte, size, stat);
		if (r == -1)
			rv = -1;
		else
			*pByte = PADD (*pByte, r);
		break;

	case SMB_FIND_FILE_NAMES_INFO:
		r = fillSMB_FIND_FILE_NAMES_INFO (pCtx, pInHdr, pOutHdr, *pByte, size, stat);
		if (r == -1)
			rv = -1;
		else
			*pByte = PADD (*pByte, r);
		break;

	case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
		r = fillSMB_FIND_FILE_BOTH_DIRECTORY_INFO (pCtx, pInHdr, pOutHdr, *pByte, size, stat);
		if (r == -1)
			rv = -1;
		else
			*pByte = PADD (*pByte, r);
		break;

	default:
		*pByte = (PFBYTE)0;
		rv = -1;
	}

	if (rv != -1)
		pCtx->outBodySize += (rtsmb_size)rv;

	return rv;
}

int fillQueryWithInfo (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFBYTE pByte, rtsmb_size size, PFRTCHAR filename, word infoLevel)
{
	BBOOL worked;
	SMBFSTAT stat;
	// don't stat for the commands that don't need it
	switch (infoLevel)
	{
	case SMB_INFO_IS_NAME_VALID:
			fillSMB_INFO_IS_NAME_VALID (pCtx, pOutHdr, filename);
			return 0;
	case SMB_QUERY_FILE_NAME_INFO:
	case SMB_QUERY_FILE_ALT_NAME_INFO:
			return fillSMB_QUERY_FILE_NAME_INFO (pCtx, pInHdr, pOutHdr, pByte, size, filename);
	default:
			worked = SMBFIO_Stat (pCtx, pCtx->tid, filename, &stat);
			break;
	}

	if(worked == FALSE)
	{
		pOutHdr->status = SMBU_MakeError (SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
	}
	else
	{
		switch (infoLevel)
		{
		case SMB_INFO_STANDARD:
			return fillSMB_INFO_STANDARD2 (pCtx, pInHdr, pOutHdr, pByte, size, &stat);
		case SMB_INFO_QUERY_EA_SIZE:
			return fillSMB_INFO_QUERY_EA_SIZE2 (pCtx, pInHdr, pOutHdr, pByte, size, &stat);
		case SMB_QUERY_FILE_BASIC_INFO:
			return fillSMB_QUERY_FILE_BASIC_INFO (pCtx, pInHdr, pOutHdr, pByte, size, &stat);
		case SMB_QUERY_FILE_STANDARD_INFO:
			return fillSMB_QUERY_FILE_STANDARD_INFO (pCtx, pInHdr, pOutHdr, pByte, size, &stat);
		case SMB_QUERY_FILE_EA_INFO:
			return fillSMB_QUERY_FILE_EA_INFO (pCtx, pInHdr, pOutHdr, pByte, size, &stat);
		case SMB_QUERY_FILE_STREAM_INFO:
			return fillSMB_QUERY_FILE_STREAM_INFO (pCtx, pInHdr, pOutHdr, pByte, size, &stat, filename);
		case SMB_QUERY_FILE_COMPRESSION_INFO:
			return fillSMB_QUERY_FILE_COMPRESSION_INFO (pCtx, pInHdr, pOutHdr, pByte, size, &stat);

		case SMB_QUERY_FILE_ALL_INFO:
		case SMB_INFO_QUERY_EAS_FROM_LIST:
		case SMB_INFO_QUERY_ALL_EAS:
			pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_NOSUPPORT);
			break;

		default:
			pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD);
			break;
		}
	}

	return 0;
}

//============================================================================
//    INTERFACE FUNCTIONS
//============================================================================
/*
================
 Searches for files using wildcard expansion

 	WARNING: does not respect resume key flag or continue search flag, only sid
================
*/
BBOOL ST2_FindFirst2 (PSMB_SESSIONCTX pCtx,
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left)
{
	RTSMB_TRANS2_FIND_FIRST2 command;
	RTSMB_TRANS2_FIND_FIRST_R response;
	BBOOL isFound; // did we find a file?
	PUSER user;
	BBOOL error = FALSE;
	word sid;
	PSMBDSTAT stat;
	PFBYTE pNext;
	PFBYTE pLast = (PFBYTE)0;
	rtsmb_char string [SMBF_FILENAMESIZE + 1];
	dword space;
	int size;
	dword blockSize;

	ASSERT_UID (pCtx)
	ASSERT_TID (pCtx)
	ASSERT_DISK (pCtx)

	command.parent = pTransaction;
	command.filename_size = SMBF_FILENAMESIZE;
	command.filename = string;
	command.data_size = 0;
	command.data = (PFBYTE)0;
	size = srv_cmd_read_find_first2 (pCtx->read_origin, pInBuf,
		pCtx->current_body_size - (rtsmb_size)PDIFF (pInBuf, pCtx->read_origin), pInHdr, &command);
	if (size == -1) return FALSE;

	size = srv_cmd_fill_find_first (pCtx->tmpBuffer, pCtx->tmpBuffer, size_left,
		pOutHdr, &response);
	if (size == -1)	return FALSE;
	size_left -= (rtsmb_size)size;

	pNext = PADD (pCtx->tmpBuffer, size);
	pCtx->outBodySize += (rtsmb_size)size;

	user = SMBU_GetUser (pCtx, pCtx->uid);
	for (sid = 0; sid < prtsmb_srv_ctx->max_searches_per_uid; sid++)
		if (!user->searches[sid].inUse)
			break;

	if (sid == prtsmb_srv_ctx->max_searches_per_uid) // no free searches
	{
		word i;
		sid = 0;

		// find oldest search, kill it.
		for (i = 1; i < prtsmb_srv_ctx->max_searches_per_uid; i++)
			if (user->searches[sid].lastUse < user->searches[i].lastUse)
				sid = i;

		SMBFIO_GDone (pCtx, user->searches[sid].tid, &user->searches[sid].stat);
	}

	stat = &user->searches[sid].stat;
	user->searches[sid].lastUse = rtp_get_system_msec ();
	user->searches[sid].inUse = TRUE;
	user->searches[sid].tid = pOutHdr->tid;
	user->searches[sid].pid = pOutHdr->pid;

	space = size_left;

	isFound = SMBFIO_GFirst (pCtx, pCtx->tid, stat, string);

	// There are three reasons to stop getting files
	//	1) No more files to get
	//	2) No more files allowed by the requesting machine
	//	3) No more space in out going buffer
	//     we assume space for one, then guess the next block's size.
	//     We may get early exits, but that isn't a problem
	response.search_count = 0;
	while (isFound == TRUE)
	{
		int status;

		pLast = pNext;

		status = fillFindWithInfo (pCtx, pInHdr, pOutHdr, &pNext, space, stat, command.information_level, command.flags);

		if (status < 0)
		{
			pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
			error = TRUE;
			break;
		}

		if (++response.search_count >= command.search_count)
			break;

		blockSize = (dword) pNext - (dword) pLast;
		space -= blockSize;
		if (space < blockSize + SMBF_FILENAMESIZE)
			break;					// we are VERY conservative here. the problem is, we cannot
									// know the exact size until we GNext it, and if we do that,
									// we have to save that information until later if we don't
									// have enough space (since we can't unpop the search result).

		isFound = SMBFIO_GNext (pCtx, pCtx->tid, stat);
	}

	if (isFound == FALSE)
		response.end_of_search = 1;
	else
		response.end_of_search = 0;

	if (error || ON (command.flags, FIND_FLAG_CLOSE_SEARCH) ||
		(ON (command.flags, FIND_FLAG_CLOSE_SEARCH_IF_END) && response.end_of_search))
	{
		user->searches[sid].inUse = FALSE;
		SMBFIO_GDone (pCtx, pCtx->tid, stat);
	}

	response.last_name_offset = 0;
	response.ea_error_offset = 0;
	response.sid = sid;

	size = srv_cmd_fill_find_first (pCtx->tmpBuffer, pCtx->tmpBuffer, size_left,
		pOutHdr, &response);
	if (size == -1)	return FALSE;

	pTransactionR->parameter = pCtx->tmpBuffer;
	pTransactionR->parameter_count = (word)size;
	pTransactionR->data = PADD (pCtx->tmpBuffer, size);
	pTransactionR->data_count = (word) PDIFF (pNext, PADD (pCtx->tmpBuffer, size));
	pTransactionR->setup = (PFWORD)0;
	pTransactionR->setup_size = 0;

	return TRUE;
} // End ST2_FindFirst2


/*
================
 Searches for files, picks up where a findFirst2 left off

  	WARNING: does not respect resume key flag or continue search flag, only sid
================
*/

BBOOL ST2_FindNext2 (PSMB_SESSIONCTX pCtx,
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left)
{
	RTSMB_TRANS2_FIND_NEXT2 command;
	RTSMB_TRANS2_FIND_NEXT_R response;
	BBOOL isFound; // did we find a file?
	PUSER user;
	int size;
	BBOOL error = FALSE;
	word sid;
	PSMBDSTAT stat;
	PFBYTE pDataStart;
	PFBYTE pNext;
	PFBYTE pLast = (PFBYTE)0;
	dword space;
	dword blockSize;

	ASSERT_UID (pCtx)
	ASSERT_TID (pCtx)
	ASSERT_DISK (pCtx)

	command.parent = pTransaction;
	command.filename_size = SMBF_FILENAMESIZE;
	command.filename = (PFRTCHAR)0;
	size = srv_cmd_read_find_next2 (pCtx->read_origin, pInBuf,
		pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &command);
	if (size == -1) return FALSE;

	ASSERT_SID (pCtx, command.sid)

	response.search_count = 0;
	size = srv_cmd_fill_find_next (pCtx->tmpBuffer, pCtx->tmpBuffer, size_left,
		pOutHdr, &response);
	if (size == -1)	return FALSE;
	size_left -= (rtsmb_size)size;
	pCtx->outBodySize += (rtsmb_size)size;

	pNext = pDataStart = PADD (pCtx->tmpBuffer, size);

	user = SMBU_GetUser (pCtx, pCtx->uid);
	sid = command.sid;
	stat = &user->searches[sid].stat;

	space = size_left;

	isFound = SMBFIO_GNext (pCtx, pCtx->tid, stat);

	// There are three reasons to stop getting files
	//	1) No more files to get
	//	2) No more files allowed by the requesting machine
	//	3) No more space in out going buffer
	while (isFound == TRUE)
	{
		int status;

		pLast = pNext;

		status = fillFindWithInfo (pCtx, pInHdr, pOutHdr, &pNext, space, stat, command.information_level, command.flags);

		if (status < 0)
		{
			pOutHdr->status = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
			error = TRUE;
			break;
		}

		if (++response.search_count >= command.search_count)
			break;

		blockSize = (dword) pNext - (dword) pLast;
		space -= blockSize;
		if (space < blockSize + SMBF_FILENAMESIZE)
			break;					// we are VERY conservative here. the problem is, we cannot
									// know the exact size until we GNext it, and if we do that,
									// we have to save that information until later if we don't
									// have enough space (since we can't unpop the search result).

		isFound = SMBFIO_GNext (pCtx, pCtx->tid, stat);
	}

	if (isFound == FALSE)
		response.end_of_search = 1;
	else
		response.end_of_search = 0;

	if (error || ON (command.flags, FIND_FLAG_CLOSE_SEARCH) ||
		(ON (command.flags, FIND_FLAG_CLOSE_SEARCH_IF_END) && response.end_of_search))
	{
		user->searches[sid].inUse = FALSE;
		SMBFIO_GDone (pCtx, pCtx->tid, stat);
	}

	response.last_name_offset = 0;
	response.ea_error_offset = 0;

	size = srv_cmd_fill_find_next (pCtx->tmpBuffer, pCtx->tmpBuffer, size_left,
		pOutHdr, &response);
	if (size == -1)	return FALSE;

	pTransactionR->parameter = pCtx->tmpBuffer;
	pTransactionR->parameter_count = (word)size;
	pTransactionR->data = PADD (pCtx->tmpBuffer, size);
	pTransactionR->data_count = (word) PDIFF (pNext, PADD (pCtx->tmpBuffer, size));
	pTransactionR->setup = (PFWORD)0;
	pTransactionR->setup_size = 0;

	return TRUE;
} // End ST2_FindNext2

/*
================
	PSMB_SESSIONCTX pCtx - the context of the current smb session
	PFBYTE pInData - the incoming data
	dword offset - x
	PSMB_TRANSACTIONRS pOutTrans - the out going transaction response
================
*/
BBOOL ST2_QueryFileInfo (PSMB_SESSIONCTX pCtx,
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left)
{
	RTSMB_TRANS2_QUERY_FILE_INFORMATION command;
	int size;

	ASSERT_UID (pCtx)
	ASSERT_TID (pCtx)
	ASSERT_DISK (pCtx)
	ASSERT_PERMISSION (pCtx, SECURITY_READ)

	command.parent = pTransaction;
	size = srv_cmd_read_query_file_information (pCtx->read_origin, pInBuf,
		pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &command);
	if (size == -1) return FALSE;

	ASSERT_FID (pCtx, command.fid, FID_FLAG_DIRECTORY);

	size = fillQueryWithInfo (pCtx, pInHdr, pOutHdr,
		pCtx->tmpBuffer, size_left, SMBU_GetFileNameFromFid (pCtx, command.fid),
		command.information_level);
	if (size == -1)
		return FALSE;
	pCtx->outBodySize += (rtsmb_size)size;

	pTransactionR->data_count = (word)size;
	pTransactionR->data = pCtx->tmpBuffer;
	pTransactionR->parameter_count = 2;
	pTransactionR->parameter = PADD("\0",2);
	pTransactionR->setup_size = 0;
	pTransactionR->setup = (PFWORD)0;

	return TRUE;
} // End ST2_QueryFileInfo

BBOOL ST2_QueryPathInfo (PSMB_SESSIONCTX pCtx,
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left)
{
	RTSMB_TRANS2_QUERY_PATH_INFORMATION command;
	int size;
	rtsmb_char string [SMBF_FILENAMESIZE + 1];

	ASSERT_UID (pCtx)
	ASSERT_TID (pCtx)
	ASSERT_DISK (pCtx)
	ASSERT_PERMISSION (pCtx, SECURITY_READ)

	command.parent = pTransaction;
	command.filename = string;
	command.filename_size = SMBF_FILENAMESIZE;
	size = srv_cmd_read_query_path_information (pCtx->read_origin, pInBuf,
		pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &command);
	if (size == -1) return FALSE;

	size = fillQueryWithInfo (pCtx, pInHdr, pOutHdr,
		pCtx->tmpBuffer, size_left, command.filename,
		command.information_level);
	if (size == -1)
		return FALSE;
	pCtx->outBodySize += (rtsmb_size)size;

	pTransactionR->data_count = (word)size;
	pTransactionR->data = pCtx->tmpBuffer;
	pTransactionR->parameter_count = 2;
	pTransactionR->parameter = PADD("\0",2);
	pTransactionR->setup_size = 0;
	pTransactionR->setup = (PFWORD)0;

	return TRUE;
} // End ST2_QueryPathInfo




/*
================
 Gets filesystem info
	PSMB_SESSIONCTX pCtx - the context of the current smb session
	PFBYTE pInData - the incoming data
	dword offset - x
	PSMB_TRANSACTIONRS pOutTrans - the out going transaction response
================
*/
BBOOL ST2_QueryFSInformation (PSMB_SESSIONCTX pCtx,
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left)
{
	RTSMB_TRANS2_QUERY_FS_INFORMATION command;
	int size;
	PFVOID buf;

	buf = pCtx->tmpBuffer;
	ASSERT_UID (pCtx)
	ASSERT_TID (pCtx)
	ASSERT_DISK (pCtx)
	ASSERT_PERMISSION (pCtx, SECURITY_READ)

	command.parent = pTransaction;
	size = srv_cmd_read_query_fs_information (pCtx->read_origin, pInBuf,
		pCtx->current_body_size - (rtsmb_size)(PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &command);
	if (size == -1) return FALSE;

	pTransactionR->data_count = 0;
	pTransactionR->data = (PFBYTE)0;
	pTransactionR->parameter_count = 0;
	pTransactionR->parameter = (PFBYTE)0;
	pTransactionR->setup_size = 0;
	pTransactionR->setup = (PFWORD)0;
	switch (command.information_level)
	{
		case SMB_INFO_ALLOCATION:			size = fillSMB_INFO_ALLOCATION			(pCtx, pInHdr, pOutHdr, buf, size_left);	break;
		case SMB_INFO_VOLUME:				size = fillSMB_INFO_VOLUME				(pCtx, pInHdr, pOutHdr, buf, size_left);	break;
		case SMB_QUERY_FS_VOLUME_INFO:		size = fillSMB_QUERY_FS_VOLUME_INFO		(pCtx, pInHdr, pOutHdr, buf, size_left);	break;
		case SMB_QUERY_FS_SIZE_INFO:		size = fillSMB_QUERY_FS_SIZE_INFO		(pCtx, pInHdr, pOutHdr, buf, size_left);	break;
		case SMB_QUERY_FS_DEVICE_INFO:		size = fillSMB_QUERY_FS_DEVICE_INFO		(pCtx, pInHdr, pOutHdr, buf, size_left);	break;
		case SMB_QUERY_FS_ATTRIBUTE_INFO:	size = fillSMB_QUERY_FS_ATTRIBUTE_INFO	(pCtx, pInHdr, pOutHdr, buf, size_left);	break;
		default:
			RTSMB_DEBUG_OUTPUT_STR("ST2_QueryFSInformation: Unknown level of detail.\n", RTSMB_DEBUG_TYPE_ASCII);
			break;
	}

	if (size == -1)
		return FALSE;

	pTransactionR->data_count = (word)size;
	pTransactionR->data = buf;
	return TRUE;
} // End ST2_QueryFSInformation



void ST2_ProcSetInfoStandard (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr,
	PFVOID pInBuf, PRTSMB_HEADER pOutHdr, rtsmb_size size_left, PFRTCHAR filename)
{
	RTSMB_INFO_STANDARD info;
	long size;

	size = srv_cmd_read_info_standard (pCtx->read_origin, pInBuf,
		(rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &info);
	if (size == -1)
	{
		SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
		return;
	}

	/* only set the attributes.  file system support for other fields is weak right now. */
	if (!SMBFIO_Chmode (pCtx, pCtx->tid, filename, rtsmb_util_smb_to_rtsmb_attributes (info.attributes)))
	{
		/* assume the file is not there if an error occurs */
		SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
		return;
	}
}


static void ST2_ProcSetBasicInfo (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr,
							  PFVOID pInBuf, PRTSMB_HEADER pOutHdr, rtsmb_size size_left,
							  PFRTCHAR filename, int fid)
{
	RTSMB_QUERY_FILE_BASIC_INFO info;
	long size;
    TIME atime;
    TIME wtime;
    TIME ctime;
    TIME htime;

	size = srv_cmd_read_basic_info (pCtx->read_origin, pInBuf,
		(rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &info);
	if (size == -1)
	{
		SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
		return;
	}

	if (info.attributes != 0)
	{
   	if (info.attributes == SMB_FA_N) /* only normal is specified */
         info.attributes = 0;
	   if (!SMBFIO_Chmode (pCtx, pCtx->tid, filename, rtsmb_util_smb_to_rtsmb_attributes (info.attributes)))
	   {
		   /* assume the file is not there if an error occurs */
		   SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
		   return;
	   }
   }
   if (info.high_last_access_time ||
       info.high_creation_time ||
       info.high_last_write_time ||
       info.high_change_time)
   {
	   atime.high_time = info.high_last_access_time;
       atime.low_time = info.low_last_access_time;
       wtime.high_time = info.high_last_write_time;
       wtime.low_time = info.low_last_write_time;
       ctime.high_time = info.high_creation_time;
       ctime.low_time = info.low_creation_time;
       htime.high_time = info.high_change_time;
       htime.low_time = info.low_change_time;

       if (!SMBFIO_SetTime (pCtx, pCtx->tid, fid, &atime, &wtime, &ctime, &htime))
	   {
		   /* assume the file is not there if an error occurs */
		   SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
		   return;
	   }
   }
}

static void ST2_ProcAllocationInfo (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr,
	PFVOID pInBuf, PRTSMB_HEADER pOutHdr, rtsmb_size size_left, PFRTCHAR filename, int fid)
{
	RTSMB_FILE_ALLOCATION_INFO info;
	dword offset;
	BBOOL worked;
	SMBFSTAT stat;
	long size, store, eof;
    char buf[1] = {0};
	long num = 0;

	worked = SMBFIO_Stat (pCtx, pCtx->tid, filename, &stat);
    if(!worked || srv_cmd_read_allocation_info (pCtx->read_origin, pInBuf,
		(rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &info) < 0)
	{
		SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
		return;
	}
	offset = info.low_allocation_size;
    if(offset > stat.f_size)
    {
        /* Store file pointer */
        if ((size = SMBFIO_Seek (pCtx, pCtx->tid, fid, 0, RTSMB_SEEK_CUR)) < 0)
        {
		    SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
        }
        store = size;
        if (!SMBFIO_Truncate (pCtx, pCtx->tid, fid, offset))
        {
	        /* assume the file is not there if an error occurs */
	        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
	        return;
        }
	    if ((eof = SMBFIO_Seek (pCtx, pCtx->tid, fid, 0, RTSMB_SEEK_END)) < 0)
	    {
		    SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
	    }
        /* restore file pointer */
        if ((size = SMBFIO_Seek (pCtx, pCtx->tid, fid, store, RTSMB_SEEK_SET)) < 0)
        {
		    SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
        }
        /* fill the newly allocated space with 0s */
        while(num < (eof - store))
        {
    	    SMBFIO_Write (pCtx, pCtx->tid, fid, (PFBYTE)buf, 1);
    	    num++;
        }
        /* restore file pointer */
        if ((size = SMBFIO_Seek (pCtx, pCtx->tid, fid, store, RTSMB_SEEK_SET)) < 0)
        {
		    SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
        }
    }
}

static void ST2_ProcEndOfFileInfo (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr,
							  PFVOID pInBuf, PRTSMB_HEADER pOutHdr, rtsmb_size size_left,
							  PFRTCHAR filename, int fid)
{
	RTSMB_FILE_END_OF_FILE_INFO info;
	long size, store, eof;
	long offset;
	long num = 0;
//    char buf[1] = {0};

	if(srv_cmd_read_end_of_file_info (pCtx->read_origin, pInBuf,
		(rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &info) < 0)
	{
		SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
		return;
	}
	offset = (long)info.low_end_of_file;

    /* Store file pointer, also fail if offset value is > 2 Gigabytes since current seek utilities can't handle > 2 gig */
    if (offset < 0 || (size = SMBFIO_Seek (pCtx, pCtx->tid, fid, 0, RTSMB_SEEK_CUR)) < 0)
    {
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
    }
    store = size;
	/* get EOF marker */
    if ((size = SMBFIO_Seek (pCtx, pCtx->tid, fid, 0, RTSMB_SEEK_END)) < 0)
    {
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
    }
	if(offset > size)
    {
		if (!SMBFIO_Truncate (pCtx, pCtx->tid, fid, (dword)offset))
		{
			/* assume the file is not there if an error occurs */
			SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRDOS, SMB_ERRDOS_BADFILE);
			return;
		}
		if ((eof = SMBFIO_Seek (pCtx, pCtx->tid, fid, 0, RTSMB_SEEK_END)) < 0)
		{
			SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
		}
        /* restore file pointer */
        if ((size = SMBFIO_Seek (pCtx, pCtx->tid, fid, store, RTSMB_SEEK_SET)) < 0)
        {
		    SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
        }
        /* fill the newly allocated space with 0s */
        while(num < (eof - store))
	    {
	    	// The below one is working for both RTFS and Windows FS.
			SMBFIO_Truncate (pCtx, pCtx->tid, fid, (dword)(eof - store));
			num +=  (eof - store);
	    }
	}
	/* restore file pointer */
    if (SMBFIO_Seek (pCtx, pCtx->tid, fid, store, RTSMB_SEEK_SET) < 0)
    {
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
    }
    return;
}

/*
================
Sets information for a filename
================
*/
BBOOL ST2_SetPathInformation (PSMB_SESSIONCTX pCtx,
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left)
{
	RTSMB_TRANS2_SET_PATH_INFORMATION command;
	int size;
	PFVOID place;

	ASSERT_UID (pCtx)
	ASSERT_TID (pCtx)
	ASSERT_DISK (pCtx)
	ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

	command.parent = pTransaction;
	command.filename = (PFRTCHAR) pCtx->tmpBuffer;
	command.filename_size = prtsmb_srv_ctx->small_buffer_size;
	size = srv_cmd_read_trans2_set_path_information (pCtx->read_origin, pInBuf,
		(rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &command);
	if (size == -1) return FALSE;

	pTransactionR->data_count = 0;
	pTransactionR->data = (PFBYTE)0;
	pTransactionR->parameter_count = 0;
	pTransactionR->parameter = (PFBYTE)0;
	pTransactionR->setup_size = 0;
	pTransactionR->setup = (PFWORD)0;

	/* skip ahead to data part for easy reading */
	place = PADD (pCtx->read_origin, pTransaction->data_offset);
	if (place >= PADD (pInBuf, size_left))
	{
		/* malformed packet */
		SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
		return TRUE;
	}
	size_left -= (rtsmb_size)(PDIFF (place, pInBuf));
	pInBuf = place;

	switch (command.information_level)
	{
		case SMB_INFO_STANDARD:
			ST2_ProcSetInfoStandard (pCtx, pInHdr, pInBuf, pOutHdr, size_left, command.filename);
			break;
		default:
			RTSMB_DEBUG_OUTPUT_STR("ST2_SetPathInformation: Unhandled level of detail.\n", RTSMB_DEBUG_TYPE_ASCII);
			SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_NOSUPPORT);
			break;
	}

	return TRUE;
}

/*
================
 Sets information for a file identifier
================
*/
BBOOL ST2_SetFileInformation (PSMB_SESSIONCTX pCtx,
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left)
{
	RTSMB_TRANS2_SET_FILE_INFORMATION command;
//	RTSMB_FILE_DISPOSITION_INFO dispositionResponse;
	int size;
	PFRTCHAR filename;
	PFVOID place;

	ASSERT_UID (pCtx)
	ASSERT_TID (pCtx)
	ASSERT_DISK (pCtx)
	ASSERT_PERMISSION (pCtx, SECURITY_WRITE)

	command.parent = pTransaction;
	size = srv_cmd_read_trans2_set_file_information (pCtx->read_origin, pInBuf,
		(rtsmb_size)(SMB_BUFFER_SIZE - PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &command);
	if (size == -1) return FALSE;

	ASSERT_FID (pCtx, command.fid, FID_FLAG_ALL);

	pTransactionR->data_count = 0;
	pTransactionR->data = (PFBYTE)0;
	pTransactionR->parameter_count = 0;
	pTransactionR->parameter = (PFBYTE)0;
	pTransactionR->setup_size = 0;
	pTransactionR->setup = (PFWORD)0;

	/* skip ahead to data part for easy reading */
	place = PADD (pCtx->read_origin, pTransaction->data_offset);
	if (place >= PADD (pInBuf, size_left))
	{
		/* malformed packet */
		SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
		return TRUE;
	}
	size_left -= (rtsmb_size)(PDIFF (place, pInBuf));
	pInBuf = place;

	filename = SMBU_GetFileNameFromFid (pCtx, command.fid);

	switch (command.information_level)
	{
		case SMB_INFO_STANDARD:
			ST2_ProcSetInfoStandard (pCtx, pInHdr, pInBuf, pOutHdr, size_left, filename);
			break;
		case SMB_SET_FILE_BASIC_INFO:
			ST2_ProcSetBasicInfo (pCtx, pInHdr, pInBuf, pOutHdr, size_left, filename, SMBU_GetInternalFid(pCtx, command.fid, FID_FLAG_ALL,0));
			break;
		case SMB_SET_FILE_ALLOCATION_INFO:
			ST2_ProcAllocationInfo (pCtx, pInHdr, pInBuf, pOutHdr, size_left, filename, SMBU_GetInternalFid(pCtx, command.fid, FID_FLAG_ALL,0));
			break;
		case SMB_SET_FILE_END_OF_FILE_INFO:
			ST2_ProcEndOfFileInfo (pCtx, pInHdr, pInBuf, pOutHdr, size_left, filename, SMBU_GetInternalFid(pCtx, command.fid, FID_FLAG_ALL,0));
			break;
        case SMB_SET_FILE_DISPOSITION_INFO:
//        	dispositionResponse.file_is_deleted = 1;
            /* close the file if open*/
			SMBFIO_Close (pCtx, pCtx->tid, command.fid);
            /* delete the file */
            SMBFIO_Delete (pCtx, pCtx->tid, filename);
            break;
		default:
			RTSMB_DEBUG_OUTPUT_STR("ST2_SetFileInformation: Unhandled level of detail.\n", RTSMB_DEBUG_TYPE_ASCII);
			SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_NOSUPPORT);
			break;
	}


	if (command.information_level > 0x100)
	{

		/* information levels above 0x100 need one word in the response params.
	   	the spec doesn't say what that one word is, so we just zero it out. */

		pTransactionR->parameter_count = 2;
		pTransactionR->parameter = pCtx->tmpBuffer;
		tc_memset (pCtx->tmpBuffer, 0, 2);

	}
	return TRUE;
}

// ****************************************************************************
// **
// **    END MODULE SRVTRAN2.C
// **
// ****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */
