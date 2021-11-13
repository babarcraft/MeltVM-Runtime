#ifndef VM_H_
#define VM_H_

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

typedef unsigned char byte;

enum op_code {
    CONST,
    PUSH, POP, HPUSH, HPOP, DUP,
    MOV, CALLNTV,
    AND, OR, XOR, LT, MT, LET, MET, ET,
    ADD, SUB, MUL, DIV,
    INC, DEC,
    CMP,
    JE, JZL, JZR, JZLE, JZRE, JNE,
    JMP,
    CALL,
    RET,
    SYSCALL,
    NOP
};

typedef struct header {
    unsigned long stack_size;
    unsigned long pointer_stack_size;
    unsigned long heap_size;
    unsigned long start_ip;
    unsigned long instructions_size;
} header;

typedef struct vm_environment {
    byte initialized : 1;
    header vm_header;

    byte* stack;
    unsigned long* ptr_stack;
    byte* heap_area;
    unsigned long registers[32];

    unsigned long* sp;
    unsigned long* bp;
    unsigned long* ip;
    unsigned long* hp;
    unsigned long* psp;
    signed long* cmp;

    unsigned long instructions_size;
    byte* instructions;

    void (*opc[255])(struct vm_environment* vm);
    void (**syscalls)(struct vm_environment* vm);
} vm_environment;

int create_vm(vm_environment*, unsigned long, const char*);

byte fetch(vm_environment*);
void fetch_to(vm_environment*, void*, size_t);

unsigned long allocate(vm_environment*, unsigned long);
void* get_refrence(vm_environment*, unsigned long);

// op codes
void opc_const(vm_environment*);
void opc_push(vm_environment*);
void opc_pop(vm_environment*);
void opc_hpush(vm_environment*);
void opc_hpop(vm_environment*);
void opc_dup(vm_environment*);
void opc_mov(vm_environment*);
void opc_and(vm_environment*);
void opc_or(vm_environment*);
void opc_xor(vm_environment*);
void opc_lt(vm_environment*);
void opc_mt(vm_environment*);
void opc_let(vm_environment*);
void opc_met(vm_environment*);
void opc_et(vm_environment*);
void opc_add(vm_environment*);
void opc_sub(vm_environment*);
void opc_mul(vm_environment*);
void opc_div(vm_environment*);
void opc_inc(vm_environment*);
void opc_dec(vm_environment*);
void opc_cmp(vm_environment*);
void opc_je(vm_environment*);
void opc_jzl(vm_environment*);
void opc_jzr(vm_environment*);
void opc_jzle(vm_environment*);
void opc_jzre(vm_environment*);
void opc_jne(vm_environment*);
void opc_jmp(vm_environment*);
void opc_call(vm_environment*);
void opc_ret(vm_environment*);
void opc_syscall(vm_environment*);
void opc_nop(vm_environment*);

// Syscalls
void syscall_alloc(vm_environment*);
void syscall_dealloc(vm_environment*);
void syscall_str_alloc(vm_environment*);
void syscall_write(vm_environment*);
void syscall_read(vm_environment*);

void destroy_vm(vm_environment*);

unsigned long execute(vm_environment*, int);

#endif