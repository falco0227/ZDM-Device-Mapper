#* ---------------------------------------------------------------------------------------------
#* Copyright (c) 2014 Seagate Technologies
#* All rights reserved.
#* ---------------------------------------------------------------------------------------------

## Tools ##
RM		= rm -f

CC=gcc
CFLAGS=-I. -Wall
LD=gcc

CPP=g++
CPPFLAGS=-I. -Wall


DEFINES     	+= -D_LARGEFILE64_SOURCE
DEFINES     	+= -D_FILE_OFFSET_BITS=64

CFLAGS          += -Wno-unused-function
CPPFLAGS        += -Wno-unused-function

## Debug [Conditional compilation] ##
ifeq ($(DEBUG),1)
DEFINES     	+= -DDEBUG
endif

## Build Verbosity ##
ifeq ($(VERBOSE),1)
BE_QUIET=
else
BE_QUIET=@
endif

## Targets ##
TARGETS		+= zdmadm zdm-status zdm-zones

## Source Files ##
CPP_SOURCES	 =
C_SOURCES	 = libzdm zbc-ctrl zdmadm libcrc libsort crc64 is_mounted
SOURCES		 = $(addsuffix .c, $(C_SOURCES)) $(addsuffix .cpp, $(CPP_SOURCES))

## Header Files ##
INCFILES         = dm-zoned.h libcrc.h libsort.h libzoned.h libzoned.c
INCFILES        += list.h utypes.h libzdm.h zbc-ctrl.h is_mounted.h

## Output directory ##
OBJECTS_DIR	 =
OBJECTS		 = $(addsuffix .o, $(C_SOURCES)) $(addsuffix .o, $(CPP_SOURCES))

## Libraries ##
LIBS += `pkg-config libssl --libs`
LIBS += `pkg-config uuid --libs`

# NOTE: for sha/uuid support:
#   sudo apt-get install libssl-dev
#   sudo apt-get install uuid-dev

##
## Compiling Rules
##

all: $(TARGETS)

zdmadm: $(OBJECTS)
	@echo "Linking $@"
	$(BE_QUIET)$(LD) $(LFLAGS) -o $@ $^ $(LIBS)

zdm-status: zdm-status.c
	@echo "Building $@"
	$(BE_QUIET)$(CC) $(DEFINES) $(CFLAGS) $(INCPATH) $< -o $@

zdm-zones: zdm-zones.c
	@echo "Building $@"
	$(BE_QUIET)$(CC) $(DEFINES) $(CFLAGS) $(INCPATH) $< -o $@

%.o: %.cpp $(INCFILES)
	@echo "Compiling $<"
	$(BE_QUIET)$(CPP) $(DEFINES) $(CPPFLAGS) $(INCPATH) -c $< -o $@

%.o: %.c $(INCFILES)
	@echo "Compiling $<"
	$(BE_QUIET)$(CC) $(DEFINES) $(CFLAGS) $(INCPATH) -c $< -o $@

test: $(TARGETS)
	echo "TODO"

check: test

clean:
	$(BE_QUIET)$(RM) $(OBJECTS)

distclean: clean
	$(BE_QUIET)$(RM) $(TARGETS)
