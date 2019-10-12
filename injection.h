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

#define BUFF        250
#define PAGE_SIZE   0x200000

enum flags {ELF=1, ENCRYPT, THREAD, STRIPPED };
enum segments_types {NOTE, ANY, TXT, DYN, DATA};

typedef struct
{
    int fd;
    struct stat st;
    char *name;
    uint8_t *mem;
    Elf64_Ehdr *head;
    Elf64_Phdr *segments;
} binary_t;

extern Elf64_Phdr *search_segment(binary_t *, const int);
extern void set_entrypoint(binary_t *, const uint64_t);
extern Elf64_Shdr *search_section(binary_t *, const char *);
extern void err_handler(binary_t *, binary_t *, char *);
extern uint8_t *inject_payload(binary_t, binary_t, size_t *);
extern uint8_t *inject_stage1(binary_t *, binary_t *, size_t *);

extern uint32_t global_flags;
extern uint64_t final_entryp;

#endif
