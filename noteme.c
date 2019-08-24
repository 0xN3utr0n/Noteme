#include "injection.h"

#define SIZE_DATA_OFF           0x270
#define ADDR_DATA_OFF           0x2a0
#define PERM_DATA_OFF           0x2d0
#define PAYLOAD_ENTRYP_OFF      0x2e5
#define TARGET_ENTRYP_OFF       0x2ed
#define SEGMENT_ADDR_OFF        0x2f5
#define LOADER_DATA_OFF         0x82
#define NON_THREAD_OFF          0x65
#define MAX_NUM_LIST            5
#define ADDR_SIZE               8

typedef struct ptload
{
    uint64_t size;
    Elf64_Phdr *list[5];
} ptload_t;




/*
 * Small wrapper for modifying the offsets depending
 * on whether the THREAD option has been set or not.
*/

static inline size_t
thread_offset (int64_t data_off)
{
    return (global_flags & THREAD)? (size_t)data_off : (size_t)data_off - NON_THREAD_OFF;
}




void
bin_init (binary_t *ptr, char *name, int64_t len, int opt)
{
    uint8_t *temp_mem = NULL;

    if ((ptr->fd = open(name, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG)) < 0)
    {
        fprintf(stderr, "Failed to open %s:%s\n", name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (fstat(ptr->fd, &ptr->st) < 0)
    {
        fprintf(stderr, "Failed to stat %s:%s\n", name, strerror(errno));
        goto fatal;
    }

    if (opt == MAP_SHARED)
    {
        if (fallocate(ptr->fd, 0, 0, len) == -1)
        {
            fprintf(stderr, "Failed to set file size %s:%s\n", name, strerror(errno));
            goto fatal;
        }
    }

    if (len > 0)
         ptr->st.st_size += len;

    if (ptr->mem != NULL) //If it has already an allocated memory, make a backup and ...
        temp_mem = ptr->mem;

    ptr->mem = mmap(NULL, (uint64_t)ptr->st.st_size, PROT_READ | PROT_WRITE, opt, ptr->fd, 0);
    if (ptr->mem == MAP_FAILED)
    {
        fprintf(stderr, "Failed to mmap %s:%s\n", name, strerror(errno));
        goto fatal;
    }

    if (temp_mem != NULL)//... copy the content to newly allocated one.
        memcpy(ptr->mem, temp_mem, (size_t)len);

    ptr->name = name;

    return;

fatal:
    close(ptr->fd);
    exit(EXIT_FAILURE);
}




/*
 * Search for all the PT_LOAD segments inside the payload binary.
 * return a list of said segments.
 */

ptload_t
scan_elf_payload (binary_t *payload)
{
    Elf64_Phdr *ptr = payload->segments;
    ptload_t info   = {0};

    puts("\n[**] Payload information:");
    printf("Entrypoint\t-> 0x%lx\n", payload->head->e_entry);

    for (int8_t i = 0, cont = 0; i < payload->head->e_phnum; i++, ptr++)
    {
        if (ptr->p_type == PT_LOAD)
        {
            info.list[cont] = ptr;
            info.size += ptr->p_memsz;
            printf("%d) PT_LOAD\t-> 0x%lx\n", cont, ptr->p_vaddr);
            cont++;
        }
    }

    printf("Payload size\t-> %ldKB\n\n", info.size/1000);

    return info;
}




/*
 * Allocate memory and copy all valid payload's segments into it.
 * Return a list of said segments.
 */

ptload_t
pack_payload (binary_t *payload)
{
    uint8_t *new_pmem       = NULL; //New payload memory pointer
    uint8_t *temp           = NULL;
    ptload_t seg_info       = {0};  //PT_LOAD segments information

    seg_info = scan_elf_payload(payload);
    if (!seg_info.size)
    {
        fprintf(stderr, "Error: No valid segments found\n");
        return seg_info;
    }

    new_pmem = mmap(NULL, seg_info.size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (new_pmem == MAP_FAILED)
    {
        perror("ERROR MMAP");
        exit(EXIT_FAILURE);
    }

    temp = new_pmem;
    for(int8_t i = 0; i < MAX_NUM_LIST && seg_info.list[i] != NULL; i++)
    {
        memcpy(temp, seg_info.list[i]->p_offset + payload->mem, seg_info.list[i]->p_filesz);
        temp += seg_info.list[i]->p_filesz;
    }

    payload->mem = new_pmem;
    payload->st.st_size = (int64_t)seg_info.size;
    return seg_info;
}




/*
 * This function modifies the stub (for now stage1) with
 * hardcoded values such as addresses and segments' size. This information
 * is required at runtime, otherwise the injected code will
 * segfault.
 */

bool
mod_stage1 (ptload_t data, binary_t *stage1, void *payload_entryp, binary_t *final)
{
    size_t size_off         = thread_offset(SIZE_DATA_OFF);
    size_t addr_off         = thread_offset(ADDR_DATA_OFF);
    size_t perm_off         = thread_offset(PERM_DATA_OFF);
    uint8_t flags           = 0;
    Elf64_Phdr *txt_segm    = search_segment(final, TXT);
    Elf64_Phdr *new_segm    = search_segment(final, ANY);

    if (!txt_segm)
    {
        fprintf(stderr, "Error: TEXT segment not found\n");
        return false;
    }

    stage1->mem += (int64_t)thread_offset(0) * -1;
    stage1->st.st_size = (int64_t)thread_offset(stage1->st.st_size);

    if (new_segm->p_align < (uint64_t)stage1->st.st_size)
    {
        fprintf(stderr, "Error: Stub size is too big (%ldKB)\n", stage1->st.st_size/1000);
        return false;
    }

    // We will hardcode into the stub information about
    // the payload's segments.
    for (int8_t i = 0; i < MAX_NUM_LIST && data.list[i] != NULL; i++)
    {
        memcpy(&stage1->mem[size_off], &data.list[i]->p_memsz, ADDR_SIZE);
        memcpy(&stage1->mem[addr_off], &data.list[i]->p_vaddr, ADDR_SIZE);

        flags = (data.list[i]->p_flags & PF_W)? flags | PROT_WRITE : flags;
        flags = (data.list[i]->p_flags & PF_R)? flags | PROT_READ  : flags;
        flags = (data.list[i]->p_flags & PF_X)? flags | PROT_EXEC  : flags;

        memcpy(&stage1->mem[perm_off], &flags, 1);
        flags = 0; perm_off++; size_off += ADDR_SIZE; addr_off += ADDR_SIZE;
    }

    uint64_t seg_vaddr   = new_segm->p_vaddr; //The target PT_NOTE segment (now PT_LOAD)
    uint64_t txt_end     = txt_segm->p_vaddr + txt_segm->p_filesz;

    if (final->head->e_type == ET_DYN) // For PIE binaries.
            seg_vaddr -= (txt_end + thread_offset(LOADER_DATA_OFF));

    if (global_flags & THREAD)
    {
        txt_end -= final->head->e_entry;
        memcpy(&stage1->mem[TARGET_ENTRYP_OFF], &txt_end, ADDR_SIZE);
    }

    memcpy(&stage1->mem[thread_offset(PAYLOAD_ENTRYP_OFF)], payload_entryp, ADDR_SIZE);
    memcpy(&stage1->mem[thread_offset(SEGMENT_ADDR_OFF)], &seg_vaddr, ADDR_SIZE);

    return true;
}




/*
 * Check if @elf contains a valid ELF binary.
 * Only the header is checked.
*/

bool
check_elf(binary_t * elf, uint8_t hide)
{
    elf->head = (Elf64_Ehdr*) elf->mem;

    if (*elf->mem != 0x7f || strncmp((char *)(elf->mem+1), "ELF", 3))
            return false;

    if ((elf->head->e_ident[EI_CLASS] != ELFCLASS64) ||
        (elf->head->e_machine != EM_X86_64) || (elf->head->e_version != EV_CURRENT))
            return false;

    if ((elf->head->e_type != ET_EXEC) && (elf->head->e_type != ET_DYN))
            return false;

    if (elf->head->e_shoff == 0 || elf->head->e_shstrndx == 0)
            global_flags |= STRIPPED;

    elf->segments = (Elf64_Phdr*) (elf->head->e_phoff + elf->mem);

    if (!hide)
            printf("[**] Valid ELF\t-> %s\n", elf->name);

    return true;
}




void
help ()
{
    printf("Usage: noteme [-opt] \n\n");
    printf("Options ('<>' required fields):\n\n \
    \t-p '<filepath>' Payload (Static ELF or Shellcode) binary\n \
    \t-t '<filepath>' Target ELF binary\n \
    \t-o '<filepath>' Output filename\n \
    \t-T Run the payload in a independent thread\n \
    \t-h This help\n" );
    puts("\n");
}




int
main (int argc, char ** argv)
{
    int opt              = 0;
    size_t bin_size      = 0;
    ptload_t seg_info    = {0};
    binary_t final       = {0};
    binary_t payload     = {0};
    binary_t target      = {0};
    binary_t stage1      = {0};

    final.name = "packed.bin";

    if (argc < 2)
    {
        help();
        exit(EXIT_FAILURE);
    }

    while((opt = getopt(argc, argv, ":p:t:o:h:T")) != -1)
    {
        switch(opt)
        {
            case 'p':
                bin_init(&payload, optarg, 0, MAP_PRIVATE);
                break;

            case 't':
                bin_init(&target, optarg, 0, MAP_PRIVATE);
                break;

            case 'e':
                global_flags |= ENCRYPT; //Not implemented yet
                break;

            case 'o':
                final.name = optarg;
                break;

            case 'T':
                global_flags |= THREAD;
                break;

            case 'h':
                help();
                exit(EXIT_FAILURE);

            case '?':
                printf("unknown option: %c\n", optopt);
                break;
        }
    }

    if (!payload.mem || !target.mem)
    {
        help();
        exit(EXIT_FAILURE);
    }

    puts("\n\t##### NOTEME PACKER #####\n");
    puts("Written by: 0xN3utr0n - 0xN3utr0n@pm.me\n");

    if (!check_elf(&target, 0))
            err_handler(&target, &payload, "Invalid target ELF binary");

    if (check_elf(&payload, 0))
    {
        global_flags |= ELF;
        seg_info = pack_payload(&payload);
        if (seg_info.list == NULL)
            err_handler(&target, &payload, "Failed to pack the payload");
    }

    final.mem = inject_payload(target, payload, &bin_size);
    if (!check_elf(&final, 1))
            err_handler(&target, &payload, "Invalid packed ELF binary");

    if (global_flags & ELF) //If payload is an ELF, inject stub
    {
        bin_init(&stage1, "bin/stage1.bin", 0, MAP_PRIVATE);
        if (!mod_stage1(seg_info, &stage1, &payload.head->e_entry, &final))
                err_handler(&target, &payload, "Failed to modify the Stub");

        final.mem = inject_stage1(&final, &stage1, &bin_size);
    }

    bin_init(&final, final.name, (int64_t)bin_size, MAP_SHARED);

    set_entrypoint(&final, final_entryp);

    printf("[**] Injected code -> 0x%lx\n", final_entryp);
    puts("\nDone\n");
}

