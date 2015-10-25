//
// SMBGLUE.C - 
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// We don't use these glue functions, at least that I can find
//
#include "smbglue.h"


PFCHAR (*rtsmb_glue_get_server_name_from_cache) (PFINT i) = 0;
BBOOL (*rtsmb_glue_are_other_workgroups) (void) = (BBOOL)0;
BBOOL (*rtsmb_glue_do_we_have_server_list) (void) = (BBOOL)0;
PFCHAR (*rtsmb_glue_get_our_server_name) (void) = 0;
void (*rtsmb_glue_process_nbds_message) (PFCHAR dest_name, byte command, PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_HEADER pheader) = 0;
