#ifndef PDB_H
#define PDB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PDB_MAGIC "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
#define PDB_MAGIC_SZ (32)

typedef enum pdb_errno_t {
    /* General errors */
    EPDB_SUCCESS = 0,
    EPDB_SYSTEM_ERROR,
    EPDB_UNSUPPORTED_VERSION,
    EPDB_INVALID_PARAMETER,
    EPDB_NO_MORE_ITEMS,

    /* Errors related to file-format parsing */
    EPDB_INVALID_SUPERBLOCK = 0x10,
    EPDB_INVALID_BLOCK_IDX,
    EPDB_INVALID_STREAM_IDX,
    EPDB_STREAM_MISSING,
    EPDB_STREAM_TOO_SMALL,

    /* Errors related to symbols */
    EPDB_INVALID_SECTION_IDX = 0x20,
    EPDB_INVALID_SECTION_OFFSET,
} pdb_errno_t;

struct guid {
    union {
        struct {
            uint32_t data1;
            uint16_t data2;
            uint16_t data3;
            unsigned char data4[8];
        };
        unsigned char bytes[16];
    };
};


#define IMAGE_SIZEOF_SHORT_NAME 8

struct image_section_header {
    char name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t physical_address;
        uint32_t virtual_size;
    } misc;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
};

struct stream {
    uint32_t index;
    uint32_t size;
    const unsigned char *data;
};

struct pdb {
    /* PDB Header Information */
    const unsigned char magic[PDB_MAGIC_SZ];
    uint32_t block_size;
    uint32_t nr_blocks;
    struct guid guid;
    uint32_t age;

    /* Image section headers (post-optimization) */
    const struct image_section_header *sections;
    uint32_t nr_sections;

    /* Raw stream data */
    const struct stream *streams;
    uint32_t nr_streams;
};

enum symbol_flags {
    SF_CODE = 1,
    SF_FUNCTION = 2,
    SF_MANAGED = 4,
    SF_MSIL = 8,
};

struct symbol {
    char *name;
    uint32_t rva;
    int flags;
};

const struct pdb * pdb_open(const char *pdbfile);

const struct pdb * pdb_load(const void *pdbdata, size_t len);

void pdb_close(const struct pdb *pdb);

const struct symbol * pdb_lookup_public_symbol(const struct pdb *pdb, const char *name);

const struct symbol * pdb_enum_public_symbols(const struct pdb *pdb, const struct symbol *prev);

#endif // PDB_H
