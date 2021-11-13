#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <strings.h>

#include "vm/vm.h"

#define DEFAULT_VM_HEAP_SIZE 1024L

static vm_environment main_vm;

void exit_handler(int signal, void* arg) {
    if(!main_vm.initialized)
        return;
    destroy_vm(&main_vm);
}

void signal_handler(int signal) {
    if(!main_vm.initialized)
        return;
    destroy_vm(&main_vm);
    exit(0);
}

int main(int arg_size, const char** args) {
    bzero(&main_vm, sizeof(vm_environment));
    on_exit(exit_handler, &main_vm);
    signal(SIGKILL, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    if(arg_size < 2) {
        printf("Insufficient arguments!\n");
        return 1;
    }
    printf("Executing file: %s\n", args[1]);
    create_vm(&main_vm, DEFAULT_VM_HEAP_SIZE, args[1]);
    unsigned long time = execute(&main_vm, (arg_size < 3)? 0 : (strcmp(args[2], "debug") == 0? 1 : 0));
    destroy_vm(&main_vm);
    printf("Execution took: %ldms\n", time);
    return 0;
}