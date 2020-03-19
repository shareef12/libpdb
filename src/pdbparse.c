#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "pdb.h"

/* TODO: Define these in cmake and make them available through a configure file */
#define PROGRAM_NAME "pdbparse"
#define PROGRAM_VERSION "0.1.0"
#define PROGRAM_LICENSE \
    "Copyright (c) 2020 Christian Sharpsten\n" \
    "This program is free software; you may redistribute it under the terms of\n" \
    "the Expat license. This program has absolutely no warranty."

/* 32 hex characters + 4 hyphens + enclosing braces */
#define GUID_STR_SIZE (32 + 4 + 2)


int snprintf_guid(char *str, size_t size, const struct guid *guid)
{
    return snprintf(str, size, "{%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}",
        guid->data1, guid->data2, guid->data3,
        guid->data4[0], guid->data4[1], guid->data4[2], guid->data4[3],
        guid->data4[4], guid->data4[5], guid->data4[6], guid->data4[7]);
}


int print_header(const struct pdb *pdb)
{
    assert(pdb != NULL);

    char sguid[GUID_STR_SIZE + 1] = {0};
    snprintf_guid(sguid, sizeof(sguid), &pdb->guid);

    puts("PDB Header:");
    printf("  %-17s: \n", "Magic"); /* TODO: Print magic */
    printf("  %-17s: %u\n", "Block size", pdb->block_size);
    printf("  %-17s: %u\n", "Number of blocks", pdb->nr_blocks);
    printf("  %-17s: %s\n", "Guid", sguid);
    printf("  %-17s: %u\n", "Age", pdb->age);
    printf("  %-17s: %u\n", "Number of streams", pdb->nr_streams);

    return 0;
}


int print_sections(const struct pdb *pdb)
{
    assert(pdb != NULL);

    puts("");
    puts("Section Headers:");
    puts("  [Nr] Name      Offset   VirtAddr           FileSiz  MemSiz   Flg");

    for (uint32_t i = 0; i < pdb->nr_sections; i++) {
        const struct image_section_header *s = &pdb->sections[i];
        printf("  [%2u] %-8.*s  0x%06x 0x%016x 0x%06x 0x%06x flag\n",
            i,
            IMAGE_SIZEOF_SHORT_NAME, s->name,
            s->pointer_to_raw_data,
            s->virtual_address,
            s->size_of_raw_data,
            s->misc.virtual_size);
    }

    return 0;
}


int print_public_symbols(const struct pdb *pdb)
{
    assert(pdb != NULL);

    /* Not the most efficient, but there is no way to know how many public
       symbols there are without iterating through them all */
    size_t nr_syms = 0;
    const struct symbol *sym = NULL;
    while ((sym = pdb_enum_public_symbols(pdb, sym)) != NULL) {
        nr_syms++;
    }

    puts("");
    printf("Public stream contains %zu symbols:\n", nr_syms);
    puts("   Num:    Value          Type    Name");



    /*
    const struct cv_public_symbol *cvsym = (const struct cv_public_symbol *)cvhdr;

            uint32_t sym_rva = 0;
            int err = lookup_rva(pdb, cvsym->section_idx, cvsym->section_offset, &sym_rva);
            if (err < 0) {*/
                /* Invalid section_idx */
                /*
                 * TODO: For some reason there are a few symbols that have an invalid section_idx.
                 *  They all have the same idx, one past the end of the sections array. There are
                 *  27 ntos sections, and they all have idx=28, so after subtracting 1, they are
                 *  section_idx == nr_sections, which would cause an overflow.
                 *
                 * WARNING: Invalid section index for symbol: __guard_flags idx=28 offset=0x1011c500
                 * WARNING: Invalid section index for symbol: __guard_longjmp_count idx=28 offset=0x0
                 * WARNING: Invalid section index for symbol: __ppe_base idx=28 offset=0x7da00000
                 * WARNING: Invalid section index for symbol: __pxe_top idx=28 offset=0x7dbedfff
                 * WARNING: Invalid section index for symbol: __pte_base idx=28 offset=0x0
                 * WARNING: Invalid section index for symbol: __pde_base idx=28 offset=0x40000000
                 * WARNING: Invalid section index for symbol: __pxe_selfmap idx=28 offset=0x7dbedf68
                 * WARNING: Invalid section index for symbol: __mm_pfn_database idx=28 offset=0x0
                 * WARNING: Invalid section index for symbol: __pxe_base idx=28 offset=0x7dbed000
                 * WARNING: Invalid section index for symbol: __guard_fids_count idx=28 offset=0x17c7
                 * WARNING: Invalid section index for symbol: __guard_iat_count idx=28 offset=0x2
                 * WARNING: Invalid section index for symbol: __guard_longjmp_table idx=28 offset=0x0
                 * WARNING: Invalid section index for symbol: __pte_top idx=28 offset=0xffffffff
                 * WARNING: Invalid section index for symbol: __pde_top idx=28 offset=0x7fffffff
                 *//*
                fprintf(stderr, "WARNING: Invalid section index for symbol: %s idx=%d offset=0x%x\n",
                    cvsym->mangled_name, cvsym->section_idx, cvsym->section_offset);
                // return NULL;
            }

            struct symbol *sym = calloc(1, sizeof(struct symbol) + sizeof(struct symbol_private) + strlen(cvsym->mangled_name) + 1);
            if (sym == NULL) {
                return NULL;
            }

            sym->name = (char *)sym + sizeof(struct symbol) + sizeof(struct symbol_private);
            sym->rva = sym_rva;
            sym->flags |= (cvsym->flags & CVPSF_CODE) ? SF_CODE : 0;
            sym->flags |= (cvsym->flags & CVPSF_FUNCTION) ? SF_FUNCTION : 0;
            sym->flags |= (cvsym->flags & CVPSF_MANAGED) ? SF_MANAGED : 0;
            sym->flags |= (cvsym->flags & CVPSF_MSIL) ? SF_MSIL : 0;
            SYMBOL_PRIVATE(sym)->index = next;
            strcpy(sym->name, cvsym->mangled_name);

            return sym;
            */




    size_t idx = 0;
    while ((sym = pdb_enum_public_symbols(pdb, sym)) != NULL) {
        /* TODO: Can a symbol have multiple flags set? */
        const char *sym_type;
        switch (sym->flags) {
        case 0: sym_type = "NOTYPE"; break;
        case SF_CODE: sym_type = "CODE"; break;
        case SF_FUNCTION: sym_type = "FUNC"; break;
        case SF_MANAGED: sym_type = "MANAGE"; break;
        case SF_MSIL: sym_type = "MSIL"; break;
        default:
            fprintf(stderr, "WARNING: Symbol %s has multiple flags values: 0x%x\n", sym->name, sym->flags);
            sym_type = "UNK";
            break;
        }

        printf("%6zu: %016x  %-6s  %s\n", idx, sym->rva, sym_type, sym->name);
        idx++;
    }

    return 0;
}



const struct pdb * pdb_open(const char *pdbfile)
{
    assert(pdbfile != NULL);
    assert(pdbfile > 0);

    int fd = open(pdbfile, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    struct stat sb = {0};
    int err = fstat(fd, &sb);
    if (err < 0) {
        close(fd);
        return NULL;
    }

    const void *ptr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        close(fd);
        return NULL;
    }
    close(fd);

    const struct pdb *pdb = pdb_load(ptr, sb.st_size);
    munmap((void *)ptr, sb.st_size);

    return pdb;
}


void pdb_close(const struct pdb *pdb)
{
    assert(pdb != NULL);

    if (pdb->streams != NULL) {
        free((void *)pdb->streams);
    }

    free((void *)pdb);
}


void print_version()
{
    puts(PROGRAM_NAME " " PROGRAM_VERSION);
    puts(PROGRAM_LICENSE);
}


void print_usage(FILE *stream)
{
    assert(stream != NULL);
    fputs("Usage: " PROGRAM_NAME " <option(s)> pdb-file\n", stream);
    fputs(" Display information about the contents of Microsoft PDB files\n", stream);
    fputs(" Options are:\n", stream);
    fputs("  -f --file-header       Display the PDB file header\n", stream);
    fputs("  -S --section-headers   Display the sections' headers\n", stream);
    fputs("     --sections          An alias for --section-headers\n", stream);
    fputs("  -s --syms              Display the public symbol table\n", stream);
    fputs("     --symbols           An alias for --syms\n", stream);
    fputs("  -h --help              Display this information\n", stream);
    fputs("  -v --version           Display the version number of " PROGRAM_NAME "\n", stream);
}


int main(int argc, char **argv)
{
    bool show_header = 0;
    bool show_sections = 0;
    bool show_syms = 0;

    static struct option long_options[] = {
        {"file-header",     no_argument, 0, 'f'},
        {"section-headers", no_argument, 0, 'S'},
        {"sections",        no_argument, 0, 'S'},
        {"syms",            no_argument, 0, 's'},
        {"symbols",         no_argument, 0, 's'},
        {"help",            no_argument, 0, 'h'},
        {"version",         no_argument, 0, 'v'},
    };

    while (true) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "fSshv", long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'f':
            show_header = true;
            break;

        case 'S':
            show_sections = true;
            break;

        case 's':
            show_syms = true;
            break;

        case 'h':
            print_usage(stdout);
            exit(EXIT_SUCCESS);

        case 'v':
            print_version();
            exit(EXIT_SUCCESS);

        case '?':
            print_usage(stderr);
            exit(EXIT_FAILURE);

        default:
            fprintf(stderr, PROGRAM_NAME ": Received unknown option: %c\n", c);
            abort();
        }
    }

    if (!show_header && !show_sections && !show_syms) {
        fputs(PROGRAM_NAME ": Warning: Nothing to do\n", stderr);
        print_usage(stderr);
        exit(EXIT_FAILURE);
    }

    if (optind == argc) {
        fputs(PROGRAM_NAME ": No pdb-file specified\n", stderr);
        print_usage(stderr);
        exit(EXIT_FAILURE);
    }

    if (optind + 1 < argc) {
        fputs(PROGRAM_NAME ": Too many arguments\n", stderr);
        print_usage(stderr);
        exit(EXIT_FAILURE);
    }

    const char *pdbpath = argv[optind];

    const struct pdb *pdb = pdb_open(pdbpath);
    if (pdb == NULL) {
        fprintf(stderr, "pdb_open failure\n");
        exit(EXIT_FAILURE);
    }

    if (show_header) {
        print_header(pdb);
    }

    if (show_sections) {
        print_sections(pdb);
    }

    if (show_syms) {
        print_public_symbols(pdb);
    }

    pdb_close(pdb);
    exit(EXIT_SUCCESS);
}
