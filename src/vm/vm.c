#include "vm.h"
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <time.h>

byte fetch(vm_environment* vm) {
    if(*vm->ip + 1 > vm->instructions_size) {
        printf("VM EXCEPTION: Fetch over instructions' size! (%ld + 1 > %ld)\n", vm->registers[17], vm->instructions_size);
        return 0;
    }
    return vm->instructions[(*vm->ip)++];
}

void fetch_to(vm_environment* vm, void* dest, size_t size) {
    if(*vm->ip + size > vm->instructions_size) {
        printf("VM EXCEPTION: Fetch over instructions' size! (%ld + %ld > %ld)\n", vm->registers[17], size, vm->instructions_size);
        return;
    }
    void* ptr = &vm->instructions[*vm->ip];
    *vm->ip += size;
    memcpy(dest, ptr, size);
}

unsigned long allocate(vm_environment* vm, unsigned long size) {
    if(*vm->hp + sizeof(unsigned long) + 1 + size > vm->vm_header.heap_size) {
        error:
        printf("VM EXCEPTION: Heapoverflow!\n");
        exit(-1);
    }
    if(size == 0)
        exit(-1);
    byte flags = 0;
    void* heap_area_ptr = NULL;
    unsigned long ref_index = 0;
    unsigned long i = 0;
    while(i != vm->vm_header.heap_size) {
        if(i + sizeof(unsigned long) + 1 > vm->vm_header.heap_size)
            goto error;
        unsigned long area_size = 0;
        memcpy(&area_size, &vm->heap_area[i], sizeof(unsigned long));
        memcpy(&flags, &vm->heap_area[i + sizeof(unsigned long)], sizeof(byte));
        if(i + area_size + 1 > vm->vm_header.heap_size)
            goto error;
        if(area_size == 0 
            || flags == 0 && area_size >= size) {
            heap_area_ptr = &vm->heap_area[i];
            break;
        }
        i += sizeof(unsigned long) + 1 + area_size;
        ref_index++;
    }
    if(heap_area_ptr == NULL)
        goto error;
    if(flags == 0)
        *vm->hp += sizeof(unsigned long) + 1 + size;
    flags = 1;
    memcpy(heap_area_ptr, &size, sizeof(unsigned long));
    memcpy(heap_area_ptr + sizeof(unsigned long), &flags, sizeof(byte));
    return ref_index;
}

void* get_refrence(vm_environment* vm, unsigned long refrence) {
    if(vm->vm_header.heap_size < refrence) {
        error:
        printf("VM EXCEPTION: Invalid refrence! (%ld)\nNOTE: This might mean a memory attack is taking place!\n", refrence);
        return NULL;
    }
    unsigned long ref_index = 0;
    unsigned long i = 0;
    while(i != vm->vm_header.heap_size) {
        if(i + sizeof(unsigned long) + 1 > vm->vm_header.heap_size)
            goto error;
        unsigned long size;
        memcpy(&size, &vm->heap_area[i], sizeof(unsigned long));
        if(i + size + 1 > vm->vm_header.heap_size)
            goto error;
        if(refrence == ref_index)
            return &vm->heap_area[i];
        i += sizeof(unsigned long) + 1 + size;
        ref_index++;
    }
    goto error;
}

void opc_const(vm_environment* vm) {
    byte size = fetch(vm);
    fetch_to(vm, &vm->stack[*vm->sp], size);
    *vm->sp += size;
}

void opc_push(vm_environment* vm) {
    byte size = fetch(vm);
    size_t offset;
    fetch_to(vm, &offset, sizeof(size_t));
    void* reg = &vm->registers[fetch(vm)];
    memcpy(&vm->stack[(*vm->sp) - offset + size], &vm->stack[(*vm->sp) - offset], offset);
    memcpy(&vm->stack[(*vm->sp) - offset], reg, size);
    *vm->sp += size;
}

void opc_pop(vm_environment* vm) {
    byte size = fetch(vm);
    unsigned long offset;
    fetch_to(vm, &offset, sizeof(unsigned long));
    void* reg = &vm->registers[fetch(vm)];
    if(*vm->bp > *vm->sp - offset - size) {
        return;
        // Exception handling
    }
    memcpy(reg, &vm->stack[*vm->sp - offset - size], size);
    memcpy(&vm->stack[*vm->sp - offset - size], &vm->stack[*vm->sp - offset], offset);
    *vm->sp -= size;
}

void opc_hpush(vm_environment* vm) {
    void* ptr = &vm->registers[fetch(vm)];
    size_t size, stack_offset, offset;
    fetch_to(vm, &size, sizeof(size_t));
    fetch_to(vm, &stack_offset, sizeof(size_t));
    fetch_to(vm, &offset, sizeof(size_t));
}

void opc_hpop(vm_environment* vm) {
    void* ptr = &vm->registers[fetch(vm)];
    size_t size, stack_offset, offset;
    fetch_to(vm, &size, sizeof(size_t));
    fetch_to(vm, &stack_offset, sizeof(size_t));
    fetch_to(vm, &offset, sizeof(size_t));
}

void opc_dup(vm_environment* vm) {
    size_t size, offset;
    fetch_to(vm, &size, sizeof(size_t));
    fetch_to(vm, &offset, sizeof(size_t));
    memcpy(&vm->stack[*vm->sp - offset + size], &vm->stack[*vm->sp - offset], offset);
    memcpy(&vm->stack[*vm->sp - offset], &vm->stack[*vm->sp  - offset - size], size);
    *vm->sp += size;
}

void opc_mov(vm_environment* vm) {
    byte reg = fetch(vm), reg_1 = fetch(vm);
    vm->registers[reg] = vm->registers[reg_1];
}

void opc_and(vm_environment* vm) {
    byte reg = fetch(vm);
    vm->registers[reg] = vm->registers[reg] & vm->registers[fetch(vm)];
}

void opc_or(vm_environment* vm) {
    byte reg = fetch(vm);
    vm->registers[reg] = vm->registers[reg] | vm->registers[fetch(vm)];
}

void opc_xor(vm_environment* vm) {
    byte reg = fetch(vm);
    vm->registers[reg] = vm->registers[reg] ^ vm->registers[fetch(vm)];
}

void opc_lt(vm_environment* vm) {
    *vm->cmp = *vm->cmp > 0;
}

void opc_mt(vm_environment* vm) {
    *vm->cmp = *vm->cmp < 0;
}

void opc_let(vm_environment* vm) {
    *vm->cmp = *vm->cmp >= 0;
}

void opc_met(vm_environment* vm) {
    *vm->cmp = *vm->cmp <= 0;
}

void opc_et(vm_environment* vm) {
    *vm->cmp = *vm->cmp == 0;
}

void opc_add(vm_environment* vm) {
    byte reg = fetch(vm);
    vm->registers[reg] = vm->registers[reg] + vm->registers[fetch(vm)];
}

void opc_sub(vm_environment* vm) {
    byte reg = fetch(vm);
    vm->registers[reg] = vm->registers[reg] - vm->registers[fetch(vm)];
}

void opc_mul(vm_environment* vm) {
    byte reg = fetch(vm);
    vm->registers[reg] = vm->registers[reg] * vm->registers[fetch(vm)];
}

void opc_div(vm_environment* vm) {
    byte reg = fetch(vm);
    vm->registers[reg] = vm->registers[reg] / vm->registers[fetch(vm)];
}

void opc_inc(vm_environment* vm) {
    vm->registers[fetch(vm)]++;
}

void opc_dec(vm_environment* vm) {
    vm->registers[fetch(vm)]--;
}

void opc_cmp(vm_environment* vm) {
    byte reg = fetch(vm), reg_1 = fetch(vm);
    *vm->cmp = vm->registers[reg] - vm->registers[reg_1];
}

void opc_je(vm_environment* vm) {
    unsigned long addr;
    fetch_to(vm, &addr, sizeof(unsigned long));
    if(*vm->cmp == 0)
        *vm->ip = addr;
}

void opc_jzl(vm_environment* vm) {
    unsigned long addr;
    fetch_to(vm, &addr, sizeof(unsigned long));
    if(*vm->cmp > 0)
        *vm->ip = addr;
}

void opc_jzr(vm_environment* vm) {
    unsigned long addr;
    fetch_to(vm, &addr, sizeof(unsigned long));
    if(*vm->cmp < 0)
        *vm->ip = addr;
}

void opc_jzle(vm_environment* vm) {
    unsigned long addr;
    fetch_to(vm, &addr, sizeof(unsigned long));
    if(*vm->cmp >= 0)
        *vm->ip = addr;
}

void opc_jzre(vm_environment* vm) {
    unsigned long addr;
    fetch_to(vm, &addr, sizeof(unsigned long));
    if(*vm->cmp <= 0)
        *vm->ip = addr;
}

void opc_jne(vm_environment* vm) {
    unsigned long addr;
    fetch_to(vm, &addr, sizeof(unsigned long));
    if(*vm->cmp != 0)
        *vm->ip = addr;
}

void opc_jmp(vm_environment* vm) {
    fetch_to(vm, vm->ip, sizeof(unsigned long));
}

void opc_call(vm_environment* vm) {
    size_t addr, offset;
    fetch_to(vm, &addr, sizeof(size_t));
    fetch_to(vm, &offset, sizeof(size_t));
    unsigned long ret_sp = *vm->sp - offset;
    unsigned long sp = *vm->sp;
    *vm->sp = ret_sp;
    memcpy(&vm->ptr_stack[*vm->psp], vm->registers, sizeof(vm->registers));
    *vm->sp = sp;
    *vm->ip = addr;
    *vm->psp += sizeof(vm->registers) / sizeof(unsigned long);
    *vm->bp = ret_sp;
}

void opc_ret(vm_environment* vm) {
    size_t ret_offset;
    fetch_to(vm, &ret_offset, sizeof(size_t));
    memcpy(vm->registers, 
        &vm->ptr_stack[*vm->psp - sizeof(vm->registers) / sizeof(unsigned long)], sizeof(vm->registers));
}

void opc_syscall(vm_environment* vm) {
    unsigned int call;
    fetch_to(vm, &call, sizeof(unsigned int));
    vm->syscalls[call](vm);
}

void opc_nop(vm_environment* vm) {
    asm("nop");
}

// Syscalls
void syscall_alloc(vm_environment* vm) {
    vm->registers[0] = allocate(vm, vm->registers[0]);
}

void syscall_dealloc(vm_environment* vm) {
    byte* ref = (byte*) get_refrence(vm, vm->registers[0]);
    ref[sizeof(unsigned long)] = 0;
}

void syscall_str_alloc(vm_environment* vm) {
    unsigned long size;
    fetch_to(vm, &size, sizeof(unsigned long));
    unsigned long h_ref = allocate(vm, size);
    void* ref = get_refrence(vm, h_ref) + sizeof(unsigned long) + sizeof(byte);
    fetch_to(vm, ref, size);
    vm->registers[0] = h_ref;
}

void syscall_write(vm_environment* vm) {
    write(vm->registers[2], get_refrence(vm, vm->registers[0]) + sizeof(unsigned long) + sizeof(byte), vm->registers[1]);
}

void syscall_read(vm_environment* vm) {
    read(vm->registers[2], get_refrence(vm, vm->registers[0]) + sizeof(unsigned long) + sizeof(byte), vm->registers[1]);
}

int create_vm(vm_environment* target, unsigned long heap_size, const char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if(file == NULL) {
        printf("ERROR: Unable to open file! (%s)\n", file_path);
        return 0;
    }
    fseek(file, 0, SEEK_END);
    size_t len = ftell(file);
    rewind(file);
    fread(&target->vm_header, sizeof(header), 1, file);
    if(heap_size != 0) target->vm_header.heap_size = heap_size;
    bzero(&target->registers, sizeof(target->registers));
    target->stack = calloc(target->vm_header.stack_size + (target->vm_header.pointer_stack_size * sizeof(unsigned long)) + heap_size, sizeof(byte));
    target->instructions_size = target->vm_header.instructions_size;
    target->ptr_stack = (unsigned long*) &target->stack[target->vm_header.stack_size];
    target->heap_area = &target->stack[target->vm_header.stack_size + (target->vm_header.pointer_stack_size * sizeof(unsigned long))];
    target->syscalls = calloc(sizeof(void (*)(vm_environment*)), 16);
    target->instructions = malloc(len);
    fread(target->instructions, sizeof(byte), len - sizeof(header), file);
    target->ip = &target->registers[17];
    target->sp = &target->registers[18];
    target->bp = &target->registers[19];
    target->psp = &target->registers[20];
    target->cmp = (signed long*) &target->registers[21];
    target->hp = &target->registers[22];
    *target->ip = target->vm_header.start_ip;
    
    // set op codes
    target->opc[CONST] = opc_const;
    target->opc[PUSH] = opc_push;
    target->opc[HPUSH] = opc_hpush;
    target->opc[POP] = opc_pop;
    target->opc[HPOP] = opc_hpop;
    target->opc[DUP] = opc_dup;
    target->opc[MOV] = opc_mov;
    target->opc[AND] = opc_and;
    target->opc[OR] = opc_or;
    target->opc[XOR] = opc_xor;
    target->opc[LT] = opc_lt;
    target->opc[MT] = opc_mt;
    target->opc[LET] = opc_let;
    target->opc[MET] = opc_met;
    target->opc[ET] = opc_et;
    target->opc[ADD] = opc_add;
    target->opc[SUB] = opc_sub;
    target->opc[MUL] = opc_mul;
    target->opc[DIV] = opc_div;
    target->opc[INC] = opc_inc;
    target->opc[DEC] = opc_dec;
    target->opc[CMP] = opc_cmp;
    target->opc[JE] = opc_je;
    target->opc[JZL] = opc_jzl;
    target->opc[JZR] = opc_jzr;
    target->opc[JZLE] = opc_jzle;
    target->opc[JZRE] = opc_jzre;
    target->opc[JNE] = opc_jne;
    target->opc[JMP] = opc_jmp;
    target->opc[CALL] = opc_call;
    target->opc[RET] = opc_ret;
    target->opc[NOP] = opc_nop;
    target->opc[SYSCALL] = opc_syscall;

    // set syscalls
    target->syscalls[0] = syscall_alloc;
    target->syscalls[1] = syscall_dealloc;
    target->syscalls[2] = syscall_str_alloc;
    target->syscalls[3] = syscall_write;
    target->syscalls[4] = syscall_read;

    target->initialized = 1;

    return 1;
}

void destroy_vm(vm_environment* vm) {
    free(vm->stack);
    free(vm->syscalls);
    munmap(vm->instructions, vm->instructions_size);
    vm->initialized = 0;
}

unsigned long execute(vm_environment* vm, int flags) {
    clock_t begin = clock();
    switch(flags) {
        case 0:
            while(*vm->ip != vm->instructions_size)
                vm->opc[fetch(vm)](vm);
            break;
        case 1:
            while(*vm->ip != vm->instructions_size) {
                vm->opc[fetch(vm)](vm);
                printf("{\n");
                for(byte i = 0;i < 32;i++)
                    printf("\tRegister %d = %ld\n", i, vm->registers[i]);
                printf("\tstack = [");
                for(unsigned long i = *vm->bp;i < *vm->sp;i++)
                    printf("%d, ", vm->stack[i]);
                printf("\b\b]\n}\n");
            }
            break;
    }
    clock_t end = clock();
    return end - begin;
}