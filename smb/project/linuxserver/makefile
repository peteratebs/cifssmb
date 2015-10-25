# GNU Makefile for RTSMB Server Application

### Usage ##############################################################
### :make clean
### :make
### :make DEBUG=1              ------------------ For debugging purposes
########################################################################
incpath = .

# cflags+= -D SUPPORT_SMB2

## SET SMB_PATH
SMB_PATH = ../..

include ../mkgnu.inc

includes = . $(lib_to_rtsmb2_common_include) $(lib_to_rtsmb_common_include) $(lib_to_rtptarget_include) $(lib_to_rtpgeneric_include)

########################################################################
# SOURCE PATHS
########################################################################

vpath %.c   . $(app_to_RTSMB_path) $(lib_to_rtsmb_common_path) $(lib_to_rtsmb2_common_path) $(lib_to_rtsmb_server_demo_path) $(lib_to_rtsmb_server_path) $(lib_to_rtsmb_client_path) $(lib_to_rtptarget) $(lib_to_rtpgeneric)

vpath %.h   .. $(lib_to_rtsmb_common_include) $(lib_to_rtsmb2_common_include) $(lib_to_rtsmb_server_include) $(lib_to_rtsmb_client_include) $(lib_to_rtptarget_include) $(lib_to_rtpgeneric_include)

########################################################################
# OPERATING SYSTEM/ENVIRONMENT SPECIFIC MODULES
########################################################################
# The only files that should go here are files that are specific to one
# particular target, operating system, compiler, etc. and must go into
# the library.  Make sure your conditional(s) are as general as possible.

ifeq ($(os),LINUX)
#modules +=
endif

########################################################################
# EBS PACKAGES
########################################################################

ifeq ($(dortsmb),"Y")
defines +=
endif


#############################################################################
# SETUP
#############################################################################

# The basic required list of modules, defines, includes.

# clean up the modules, includes, defines
# dirs = $(lib_to_webc_path)

includes += $(lib_to_rtsmb_server_include)
dirs = $(lib_to_rtsmb_server_path)

cpfiles := $(foreach dir,$(dirs),$(wildcard $(dir)/*.cpp))
cpmodules := $(patsubst %.cpp,%,$(cpfiles))
cfiles := $(foreach dir,$(dirs),$(wildcard $(dir)/*.c))

#RTSMB COMMON FILES USED


# cfiles += $(lib_to_rtsmb2_common_path)/srv_smb2_model.c
# cfiles += $(lib_to_rtsmb2_common_path)/com_smb2_stubs.c
# cfiles += $(lib_to_rtsmb2_common_path)/srv_smb2_proc.c
# cfiles += $(lib_to_rtsmb2_common_path)/srv_smb2_wire.c
# cfiles += $(lib_to_rtsmb2_common_path)/com_smb2_wire.c



cfiles += $(lib_to_rtsmb_common_path)/des_enc.c
cfiles += $(lib_to_rtsmb_common_path)/ecb_enc.c
cfiles += $(lib_to_rtsmb_common_path)/md4_dgst.c
cfiles += $(lib_to_rtsmb_common_path)/md4_one.c
cfiles += $(lib_to_rtsmb_common_path)/psmbfile.c
cfiles += $(lib_to_rtsmb_common_path)/psmbnet.c
cfiles += $(lib_to_rtsmb_common_path)/psmbos.c
cfiles += $(lib_to_rtsmb_common_path)/set_key.c
cfiles += $(lib_to_rtsmb_common_path)/smbbrbuf.c
cfiles += $(lib_to_rtsmb_common_path)/smbbrcfg.c
cfiles += $(lib_to_rtsmb_common_path)/smbdebug.c
cfiles += $(lib_to_rtsmb_common_path)/smbglue.c
cfiles += $(lib_to_rtsmb_common_path)/smbnb.c
cfiles += $(lib_to_rtsmb_common_path)/smbnbds.c
cfiles += $(lib_to_rtsmb_common_path)/smbnbns.c
cfiles += $(lib_to_rtsmb_common_path)/smbnbss.c
cfiles += $(lib_to_rtsmb_common_path)/smbnet.c
cfiles += $(lib_to_rtsmb_common_path)/smbpack.c
cfiles += $(lib_to_rtsmb_common_path)/smbread.c
cfiles += $(lib_to_rtsmb_common_path)/smbsjis.c
cfiles += $(lib_to_rtsmb_common_path)/smbutil.c
cfiles += $(lib_to_rtsmb_common_path)/hmac_md5.c
cfiles += $(lib_to_rtsmb_common_path)/md5rsa.c
#RTPLATFORM FILES USED
cfiles += $(lib_to_rtpgeneric)/rtpchar.c
cfiles += $(lib_to_rtpgeneric)/rtpmtxdb.c
cfiles += $(lib_to_rtpgeneric)/rtprand.c
cfiles += $(lib_to_rtpgeneric)/rtprot.c
cfiles += $(lib_to_rtpgeneric)/rtpstr.c
cfiles += $(lib_to_rtpgeneric)/rtpscnv.c
cfiles += $(lib_to_rtpgeneric)/rtpwchar.c
cfiles += $(lib_to_rtpgeneric)/rtpwcs.c
cfiles += $(lib_to_rtpgeneric)/rtpwscnv.c
cfiles += $(lib_to_rtptarget)/rtpdate.c
cfiles += $(lib_to_rtptarget))/rtpdebug.c
cfiles += $(lib_to_rtptarget)/rtpdobj.c
cfiles += $(lib_to_rtptarget)/rtpfile.c
cfiles += $(lib_to_rtptarget)/rtpmem.c
cfiles += $(lib_to_rtptarget)/rtpnet.c
cfiles += $(lib_to_rtptarget)/rtpsignl.c
cfiles += $(lib_to_rtptarget)/rtpterm.c
cfiles += $(lib_to_rtptarget)/rtpthrd.c
cfiles += $(lib_to_rtptarget)/rtptime.c
cfiles += $(lib_to_rtptarget)/rtpwfile.c
#DEMO FILE
cfiles +=  $(lib_to_rtsmb_server_demo_path)/serverexample.c

cmodules := $(patsubst %.c,%,$(cfiles))

modules += $(cpmodules)
modules += $(cmodules)

modules  := $(sort $(modules))
#includes := $(sort $(includes))
defines  := $(sort $(defines))

# now set up the object list
blah1 = $(modules:%=%.$(obj))
objects = $(notdir $(blah1))
OBJDIR=./bin
OUT_OBJS = $(addprefix $(OBJDIR)/,$(objects))

#############################################################################
# RULES
#############################################################################
all: rtsmbserverapplication.out

$(OBJDIR)/rtsmbserverapplication.a: $(OUT_OBJS)
$(OBJDIR)/rtsmbserverapplication.o: rtsmbserverapplication.c

rtsmbserverapplication.out: $(OBJDIR)/rtsmbserverapplication.o $(OBJDIR)/rtsmbserverapplication.a

include ../rulesgnu.inc
#############################################################################
