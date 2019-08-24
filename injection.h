#ifndef INJECTION_H
#define INJECTION_H

#define _GNU_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#define NOTE 	    3
#define ANY         0
#define TXT         2
#define DYN         1
#define DATA        4

#define BUFF        250
#define ELF         0x0001
#define ENCRYPT     0x0010
#define THREAD      0x0100
#define STRIPPED    0x1000
#define PAGE_SIZE   0x200000

typedef struct
{
    char *name;
    int fd;
    struct stat st;
    uint8_t *mem;
    Elf64_Ehdr *head;
    Elf64_Phdr *segments;
} binary_t;

extern Elf64_Phdr *search_segment(binary_t *, int);
Elf64_Phdr *new_segment(binary_t *, binary_t *);
extern void set_entrypoint(binary_t *, uint64_t);
extern Elf64_Shdr *search_section(binary_t *, char *);
void repair_sections(binary_t *, size_t, size_t, size_t);
extern void err_handler(binary_t *, binary_t *, char *);
uint64_t small_payload(Elf64_Phdr *, uint8_t *, binary_t *, binary_t *);
uint64_t big_payload(Elf64_Phdr *, uint8_t *, binary_t *, binary_t *);
extern uint8_t *inject_payload(binary_t, binary_t, size_t *);
extern uint8_t *inject_stage1(binary_t *, binary_t *, size_t *);

uint32_t global_flags;
uint64_t final_entryp;

#endif
