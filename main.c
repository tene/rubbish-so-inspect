#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

int cb(struct dl_phdr_info *info, size_t size, void *data) {
    int j;
 
    printf("name=%s (%d segments)\n", info->dlpi_name,
        info->dlpi_phnum);
 
    for (j = 0; j < info->dlpi_phnum; j++) {
        uint32_t type = info->dlpi_phdr[j].p_type;
        //ElfW(Addr) addr = info->dlpi_addr + info->dlpi_phdr[j].p_vaddr;
        //printf("\t\t header %2d: address=%10p\n", j, (void *) (addr));
        printf("\t\t header %2d: ", j);
        switch(type) {
            case PT_NULL:
                printf("NULL");
                break;
            case PT_LOAD:
                printf("LOAD");
                break;
            case PT_DYNAMIC:
                printf("DYNAMIC");
                break;
            case PT_INTERP:
                printf("INTERP");
                break;
            case PT_NOTE:
                printf("NOTE");
                break;
            case PT_SHLIB:
                printf("SHLIB");
                break;
            case PT_PHDR:
                printf("PHDR");
                break;
            case PT_LOPROC:
                printf("LOPROC");
                break;
            case PT_HIPROC:
                printf("LOPROC");
                break;
            case PT_GNU_EH_FRAME:
                printf("GNU_EH_FRAME");
                break;
            case PT_GNU_STACK:
                printf("GNU_STACK");
                break;
            case PT_GNU_RELRO:
                printf("GNU_RELRO");
                break;
            default:
                printf("0x%x", type);
        }
        printf("\n");
    }
    return 0;
}

int main(int argc, char **argv) {
    void *lib_handle;
    void (*fn)();
    lib_handle = dlopen("./alpha.so", RTLD_NOW);
    fn = dlsym(lib_handle, "lol");
    (*fn)();
    dl_iterate_phdr(&cb, NULL);
    dlclose(lib_handle);
    return(0);
}
