#
# 0xN3utr0n - makefile sample
#

# MACROS

BPATH    = ./bin
CC       = cc
CLFAGS 	 = -g -Wall -Wextra -Werror -pedantic -Wconversion -pedantic -Wconversion -Wformat-security  -std=gnu99 -march=x86-64
SECFLAGS = -fstack-clash-protection -fstack-protector --param ssp-buffer-size=4 
SECFLAGS += -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -O3
SECFLAGS += -Wl,-z,noexecstack -fomit-frame-pointer
DYN      = -fPIC -pie 
OBJCPY   = objcopy -O binary --only-section=.text --only-section=.data

# Targets
all: stage1 Noteme clean

clean:
	@rm -rf $(BPATH)/*.o

# $ make test=1 
# Since some values must be hardcoded into stage1.bin,
# the same sample must be used always. Only compile for testing
# purposes.
stage1: stage1.asm
ifdef test
	@nasm -o $(BPATH)/$@.o -f elf64 $<
	@$(CC) $(DYN) $(CFLAGS) -N -nostdlib -o $(BPATH)/$@ $(BPATH)/$@.o
	@$(OBJCPY) $(BPATH)/$@ $(BPATH)/$@.bin
	@rm $(BPATH)/$@
endif

Noteme: noteme.c injection.c
	@$(CC) $(CFLAGS) $(SECFLAGS) $(DYN) -o $(BPATH)/Noteme $^
	@echo OK
