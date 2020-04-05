#include "config.h"
#include "pdb.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PROGRAM_NAME "pdbparse"
#define PROGRAM_VERSION PROJECT_VERSION
#define PROGRAM_LICENSE PROJECT_LICENSE

/* 32 hex characters + 4 hyphens + enclosing braces */
#define GUID_STR_SIZE (32 + 4 + 2)


int snprintf_guid(char *str, size_t size, const struct guid *guid)
{
    return snprintf(str, size, "{%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}",
        guid->data1, guid->data2, guid->data3,
        guid->data4[0], guid->data4[1], guid->data4[2], guid->data4[3],
        guid->data4[4], guid->data4[5], guid->data4[6], guid->data4[7]);
}


void * open_pdb_file(const char *pathname)
{
    int fd = open(pathname, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error opening pdb file: %s (%u)\n", strerror(errno), errno);
        return NULL;
    }

    struct stat sb = {0};
    int err = fstat(fd, &sb);
    if (err < 0) {
        fprintf(stderr, "Error getting pdb file size: %s (%u)\n", strerror(errno), errno);
        close(fd);
        return NULL;
    }

    void *pdbdata = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (pdbdata == MAP_FAILED) {
        fprintf(stderr, "Error mapping pdb file: %s (%u)\n", strerror(errno), errno);
        return NULL;
    }

    if (!pdb_sig_match(pdbdata, sb.st_size)) {
        fprintf(stderr, "Not a pdb file: %s\n", pathname);
        goto err_munmap_pdbdata;
    }

    void *ctx = pdb_create_context(NULL, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Could not allocate libpdb context\n");
        goto err_munmap_pdbdata;
    }

    if (pdb_load(ctx, pdbdata, sb.st_size) < 0) {
        fprintf(stderr, "Error loading pdb file: %s\n", pdb_strerror(ctx));
        goto err_destroy_ctx;
    }

    munmap(pdbdata, sb.st_size);
    return ctx;

err_destroy_ctx:
    pdb_destroy_context(ctx);

err_munmap_pdbdata:
    munmap(pdbdata, sb.st_size);

    return 0;
}


void close_pdb_file(void *pdb_context)
{
    pdb_destroy_context(pdb_context);
}


void print_header(void *pdb)
{
    uint32_t block_size = 0;
    uint32_t nr_blocks = 0;
    const struct guid *guid = NULL;
    uint32_t age = 0;
    uint32_t nr_streams = 0;
    char sguid[GUID_STR_SIZE + 1] = {0};

    pdb_get_header(pdb, &block_size, &nr_blocks, &guid, &age, &nr_streams);
    snprintf_guid(sguid, sizeof(sguid), guid);

    puts("PDB Header:");
    printf("  %-17s: %u\n", "Block size", block_size);
    printf("  %-17s: %u\n", "Number of blocks", nr_blocks);
    printf("  %-17s: %s\n", "Guid", sguid);
    printf("  %-17s: %u\n", "Age", age);
    printf("  %-17s: %u\n", "Number of streams", nr_streams);
}


void print_sections(void *pdb)
{
    uint32_t nr_sections = pdb_get_nr_sections(pdb);
    const struct image_section_header *sections = pdb_get_sections(pdb);

    puts("");
    puts("Section Headers:");
    puts("  [Nr] Name      Offset   VirtAddr           FileSiz  MemSiz   Flg");

    for (uint32_t i = 0; i < nr_sections; i++) {
        const struct image_section_header *s = &sections[i];
        printf("  [%2u] %-8.*s  0x%06x 0x%016x 0x%06x 0x%06x 0x%08x\n",
            i,
            IMAGE_SIZEOF_SHORT_NAME, s->name,
            s->pointer_to_raw_data,
            s->virtual_address,
            s->size_of_raw_data,
            s->misc.virtual_size,
            s->characteristics);
    }

    puts("");
    puts("Flags:");
    puts("  IMAGE_SCN_CNT_CODE                  0x00000020");
    puts("  IMAGE_SCN_CNT_INITIALIZED_DATA      0x00000040");
    puts("  IMAGE_SCN_CNT_UNINITIALIZED_DATA    0x00000080");
    puts("  IMAGE_SCN_MEM_DISCARDABLE           0x02000000");
    puts("  IMAGE_SCN_MEM_NOT_CACHED            0x04000000");
    puts("  IMAGE_SCN_MEM_NOT_PAGED             0x08000000");
    puts("  IMAGE_SCN_MEM_SHARED                0x10000000");
    puts("  IMAGE_SCN_MEM_EXECUTE               0x20000000");
    puts("  IMAGE_SCN_MEM_READ                  0x40000000");
    puts("  IMAGE_SCN_MEM_WRITE                 0x80000000");
}


void print_public_symbols(void *pdb)
{
    uint32_t nr_symbols = 0;
    if (pdb_get_nr_public_symbols(pdb, &nr_symbols) < 0) {
        fprintf(stderr, "Error parsing symbol stream: %s\n", pdb_strerror(pdb));
        return;
    }

    const PUBSYM32 **symbols = calloc(nr_symbols, sizeof(void *));
    if (symbols == NULL) {
        fprintf(stderr, "Couldn't allocate memory for %d symbols\n", nr_symbols);
        return;
    }

    if (pdb_get_public_symbols(pdb, symbols) < 0) {
        fprintf(stderr, "Error getting symbols: %s\n", pdb_strerror(pdb));
        return;
    }

    /* Get the number of section headers so we can detect dynamic symbols */
    uint32_t nr_sections = pdb_get_nr_sections(pdb);

    puts("");
    printf("Public stream contains %u symbols:\n", nr_symbols);
    puts("   Num:  Value    Type    Name");

    for (uint32_t i = 0; i < nr_symbols; i++) {
        const PUBSYM32 *sym = symbols[i];

        /* TODO: Can a symbol have multiple flags set? */
        const char *sym_type;
        switch (sym->pubsymflags.grfFlags) {
        case cvpsfNone: sym_type = "NOTYPE"; break;
        case cvpsfCode: sym_type = "CODE"; break;
        case cvpsfFunction: sym_type = "FUNC"; break;
        case cvpsfManaged: sym_type = "MANAGE"; break;
        case cvpsfMSIL: sym_type = "MSIL"; break;
        default:
            fprintf(stderr, "WARNING: Symbol %s has multiple flags values: 0x%x\n", sym->name, sym->pubsymflags.grfFlags);
            sym_type = "UNK";
            break;
        }

        uint32_t sym_rva = 0;
        const char *sym_dynamic = "";

        /*
         * Some ntoskrnl symbols represent data that is subject to KASLR. These
         * symbols are emitted to the PDB with an invalid section index
         * (sym->seg - 1 == nr_sections). However, we still have section offset
         * information. I suspect this is relative to the base KASLR address
         * computed by the kernel.
         */
        if (sym->seg != 0 && (uint32_t)(sym->seg - 1) == nr_sections) {
            sym_rva = sym->off;
            sym_dynamic = " (dynamic)";
        }
        else {
            if (pdb_convert_section_offset_to_rva(pdb, sym->seg, sym->off, &sym_rva) < 0) {
                fprintf(stderr, "WARNING: No RVA translation for symbol: %s (idx=0x%x offset=0x%x): %s\n",
                    sym->name, sym->seg, sym->off, pdb_strerror(pdb));
            }
        }

        printf("%6u: %08x  %-6s  %s%s\n", i, sym_rva, sym_type, sym->name, sym_dynamic);
    }

    free(symbols);
}


void print_version(void)
{
    puts(PROGRAM_NAME " " PROGRAM_VERSION);
    puts(PROGRAM_LICENSE);
}


void print_usage(FILE *stream)
{
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

    /* clang-format off */
    static struct option long_options[] = {
        {"file-header",     no_argument, 0, 'f'},
        {"section-headers", no_argument, 0, 'S'},
        {"sections",        no_argument, 0, 'S'},
        {"syms",            no_argument, 0, 's'},
        {"symbols",         no_argument, 0, 's'},
        {"help",            no_argument, 0, 'h'},
        {"version",         no_argument, 0, 'v'},
    };
    /* clang-format on */

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

    void *pdb = open_pdb_file(pdbpath);
    if (pdb == NULL) {
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

    close_pdb_file(pdb);
    exit(EXIT_SUCCESS);
}
