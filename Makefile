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
all: clean stage1 Noteme clean2

clean:
	@rm -rf $(BPATH)/*

clean2:
	@rm -rf $(BPATH)/*.o

stage1: stage1.asm
	@nasm -o $(BPATH)/$@.o -f elf64 $<
	@$(CC) $(DYN) $(CFLAGS) -N -nostdlib -o $(BPATH)/$@ $(BPATH)/$@.o
	@$(OBJCPY) $(BPATH)/$@ $(BPATH)/$@.bin
	@rm $(BPATH)/$@

Noteme: noteme.c injection.c
	@$(CC) $(CFLAGS) $(SECFLAGS) $(DYN) -o $(BPATH)/Noteme $^
	@echo OK
