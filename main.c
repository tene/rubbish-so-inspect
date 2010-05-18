#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

#define SMALLBUF 32

char * fill_dyn_tagname(ElfW(Sword) tag, char *name) {
    switch(tag) {
        case DT_NULL:
            strncpy(name, "DT_NULL", SMALLBUF-1);
            break;
        case DT_NEEDED:
            strncpy(name, "DT_NEEDED", SMALLBUF-1);
            break;
        case DT_PLTRELSZ:
            strncpy(name, "DT_PLTRELSZ", SMALLBUF-1);
            break;
        case DT_PLTGOT:
            strncpy(name, "DT_PLTGOT", SMALLBUF-1);
            break;
        case DT_HASH:
            strncpy(name, "DT_HASH", SMALLBUF-1);
            break;
        case DT_STRTAB:
            strncpy(name, "DT_STRTAB", SMALLBUF-1);
            break;
        case DT_SYMTAB:
            strncpy(name, "DT_SYMTAB", SMALLBUF-1);
            break;
        case DT_RELA:
            strncpy(name, "DT_RELA", SMALLBUF-1);
            break;
        case DT_RELASZ:
            strncpy(name, "DT_RELASZ", SMALLBUF-1);
            break;
        case DT_RELAENT:
            strncpy(name, "DT_RELAENT", SMALLBUF-1);
            break;
        case DT_STRSZ:
            strncpy(name, "DT_STRSZ", SMALLBUF-1);
            break;
        case DT_SYMENT:
            strncpy(name, "DT_SYMENT", SMALLBUF-1);
            break;
        case DT_INIT:
            strncpy(name, "DT_INIT", SMALLBUF-1);
            break;
        case DT_FINI:
            strncpy(name, "DT_FINI", SMALLBUF-1);
            break;
        case DT_SONAME:
            strncpy(name, "DT_SONAME", SMALLBUF-1);
            break;
        case DT_RPATH:
            strncpy(name, "DT_RPATH", SMALLBUF-1);
            break;
        case DT_SYMBOLIC:
            strncpy(name, "DT_SYMBOLIC", SMALLBUF-1);
            break;
        case DT_REL:
            strncpy(name, "DT_REL", SMALLBUF-1);
            break;
        case DT_RELSZ:
            strncpy(name, "DT_RELSZ", SMALLBUF-1);
            break;
        case DT_RELENT:
            strncpy(name, "DT_RELENT", SMALLBUF-1);
            break;
        case DT_PLTREL:
            strncpy(name, "DT_PLTREL", SMALLBUF-1);
            break;
        case DT_DEBUG:
            strncpy(name, "DT_DEBUG", SMALLBUF-1);
            break;
        case DT_TEXTREL:
            strncpy(name, "DT_TEXTREL", SMALLBUF-1);
            break;
        case DT_JMPREL:
            strncpy(name, "DT_JMPREL", SMALLBUF-1);
            break;
        case DT_BIND_NOW:
            strncpy(name, "DT_BIND_NOW", SMALLBUF-1);
            break;
        case DT_INIT_ARRAY:
            strncpy(name, "DT_INIT_ARRAY", SMALLBUF-1);
            break;
        case DT_FINI_ARRAY:
            strncpy(name, "DT_FINI_ARRAY", SMALLBUF-1);
            break;
        case DT_INIT_ARRAYSZ:
            strncpy(name, "DT_INIT_ARRAYSZ", SMALLBUF-1);
            break;
        case DT_FINI_ARRAYSZ:
            strncpy(name, "DT_FINI_ARRAYSZ", SMALLBUF-1);
            break;
        case DT_RUNPATH:
            strncpy(name, "DT_RUNPATH", SMALLBUF-1);
            break;
        case DT_FLAGS:
            strncpy(name, "DT_FLAGS", SMALLBUF-1);
            break;
        case DT_ENCODING:
            strncpy(name, "DT_ENCODING", SMALLBUF-1);
            break;
        case DT_LOPROC:
            strncpy(name, "DT_LOPROC", SMALLBUF-1);
            break;
        case DT_HIPROC:
            strncpy(name, "DT_HIPROC", SMALLBUF-1);
            break;
        case DT_VERSYM:
            strncpy(name, "DT_VERSYM", SMALLBUF-1);
            break;
        case DT_RELACOUNT:
            strncpy(name, "DT_RELACOUNT", SMALLBUF-1);
            break;
        case DT_RELCOUNT:
            strncpy(name, "DT_RELCOUNT", SMALLBUF-1);
            break;
        case DT_FLAGS_1:
            strncpy(name, "DT_FLAGS_1", SMALLBUF-1);
            break;
        case DT_VERDEF:
            strncpy(name, "DT_VERDEF", SMALLBUF-1);
            break;
        case DT_VERDEFNUM:
            strncpy(name, "DT_VERDEFNUM", SMALLBUF-1);
            break;
        case DT_VERNEED:
            strncpy(name, "DT_VERNEED", SMALLBUF-1);
            break;
        case DT_VERNEEDNUM:
            strncpy(name, "DT_VERNEEDNUM", SMALLBUF-1);
            break;
        default:
            snprintf(name, SMALLBUF-1, "0x%x", tag);
    }
    return name;
}
char * fill_phdr_name(uint32_t type, char *name) {
    switch(type) {
        case PT_NULL:
            strncpy(name, "NULL", SMALLBUF-1);
            break;
        case PT_LOAD:
            strncpy(name, "LOAD", SMALLBUF-1);
            break;
        case PT_DYNAMIC:
            strncpy(name, "DYNAMIC", SMALLBUF-1);
            break;
        case PT_INTERP:
            strncpy(name, "INTERP", SMALLBUF-1);
            break;
        case PT_NOTE:
            strncpy(name, "NOTE", SMALLBUF-1);
            break;
        case PT_SHLIB:
            strncpy(name, "SHLIB", SMALLBUF-1);
            break;
        case PT_PHDR:
            strncpy(name, "PHDR", SMALLBUF-1);
            break;
        case PT_TLS:
            strncpy(name, "TLS", SMALLBUF-1);
            break;
        case PT_LOPROC:
            strncpy(name, "LOPROC", SMALLBUF-1);
            break;
        case PT_HIPROC:
            strncpy(name, "LOPROC", SMALLBUF-1);
            break;
        case PT_GNU_EH_FRAME:
            strncpy(name, "GNU_EH_FRAME", SMALLBUF-1);
            break;
        case PT_GNU_STACK:
            strncpy(name, "GNU_STACK", SMALLBUF-1);
            break;
        case PT_GNU_RELRO:
            strncpy(name, "GNU_RELRO", SMALLBUF-1);
            break;
        default:
            snprintf(name, SMALLBUF-1, "0x%x", type);
    }
    return name;
}

int cb(struct dl_phdr_info *info, size_t size, void *data) {
    int j;
    char name[SMALLBUF];
    ElfW(Dyn) *dyn = NULL;
    ElfW(Word) *hash = NULL;
    Elf32_Word *gnuhash = NULL;
    const char *strtable = NULL;
    ElfW(Sym) *symtable = NULL;
    int symcount, symtabsize, strsize, syment;
 
    printf("name=%s (%d segments)\n", info->dlpi_name,
        info->dlpi_phnum);
 
    for (j = 0; j < info->dlpi_phnum; j++) {
        uint32_t type = info->dlpi_phdr[j].p_type;
        ElfW(Addr) addr = info->dlpi_addr + info->dlpi_phdr[j].p_vaddr;
        //printf("\t\t header %2d: address=%10p\n", j, (void *) (addr));
        printf("\t\t header %2d: %s\n", j, fill_phdr_name(type, name));
        switch(type) {
            case PT_DYNAMIC:
                dyn = (ElfW(Dyn) *) addr;
                break;
        }
    }

    if (dyn) {
        int i=0;
        printf("  Has dynamic symbols:\n");
        while (dyn[i].d_tag != DT_NULL) {
            switch(dyn[i].d_tag) {
                case DT_HASH:
                    printf("    Found hash!\n");
                    hash = (ElfW(Word) *) dyn[i].d_un.d_ptr;
                    break;
                case DT_GNU_HASH:
                    printf("    Found GNU hash!\n");
                    gnuhash = (Elf32_Word *) dyn[i].d_un.d_ptr;
                    break;
                case DT_STRTAB:
                    printf("    Found String Table!\n");
                    strtable = (const char *) dyn[i].d_un.d_ptr;
                    break;
                case DT_SYMTAB:
                    printf("    Found Symbol Table!\n");
                    symtable = (ElfW(Sym) *) dyn[i].d_un.d_ptr;
                    break;
                case DT_STRSZ:
                    strsize = (ElfW(Word)) dyn[i].d_un.d_val;
                    printf("    String Table size: %d\n", strsize);
                    break;
                case DT_SYMENT:
                    syment = (ElfW(Word)) dyn[i].d_un.d_val;
                    printf("    Symbol Table entry size: %d\n", syment);
                    break;
                //default:
                //    printf("    %s\n", fill_dyn_tagname(dyn[i].d_tag, name));
            }
            i++;
        };
        if (symtable && strtable) {
            // str table comes after sym table
            symtabsize = strtable - (char *) symtable;
            symcount = symtabsize/syment;
            printf("    Symbol Table size: %d\n", symtabsize);
            printf("    Symbol Table entries: %d\n", symcount);
        }
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
