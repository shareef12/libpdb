#ifndef PDB_H
#define PDB_H

#include "pdb/cvinfo.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#pragma pack(push,1)

#define PDB_SIGNATURE_SZ (32)

typedef enum pdb_errno_t {
    EPDB_SUCCESS = 0,
    EPDB_SYSTEM_ERROR,
    EPDB_ALLOCATION_FAILURE,
    EPDB_NO_PDB_LOADED,
    EPDB_INVALID_PARAMETER,
    EPDB_UNSUPPORTED_VERSION,
    EPDB_FILE_CORRUPT,
    EPDB_INVALID_SECTION_IDX,
    EPDB_INVALID_SECTION_OFFSET,
    EPDB_NOT_FOUND,
} pdb_errno_t;

struct guid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    unsigned char data4[8];
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

typedef void * (*malloc_fn)(size_t size);
typedef void (*free_fn)(void *ptr);


bool pdb_sig_match(void *data, size_t len);

void * pdb_create_context(malloc_fn user_malloc_fn, free_fn user_free_fn);
void pdb_reset_context(void *context);
void pdb_destroy_context(void *context);

int pdb_load(void *context, const void *pdbdata, size_t len);


void pdb_get_header(void *context, uint32_t *block_size, uint32_t *nr_blocks, const struct guid **guid, uint32_t *age, uint32_t *nr_streams);
uint32_t pdb_get_block_size(void *context);
uint32_t pdb_get_nr_blocks(void *context);
const struct guid * pdb_get_guid(void *context);
uint32_t pdb_get_age(void *context);

uint32_t pdb_get_nr_streams(void *context);
const unsigned char * pdb_get_stream(void *context, uint32_t stream_idx, uint32_t *stream_size);

uint32_t pdb_get_nr_sections(void *context);
const struct image_section_header * pdb_get_sections(void *context);

/* Iterate only through public symbols */
int pdb_get_nr_public_symbols(void *context, uint32_t *nr_public_symbols);
int pdb_get_public_symbols(void *context, const PUBSYM32 **symbols);

/* Iterate through *all* symbols (public + global) */
int pdb_get_nr_symbols(void *context, uint32_t *nr_symbols);
int pdb_get_symbols(void *context, const struct SYMTYPE **symbols);

/* Find a symbol by looking it up in the PDB symbol hashtable */
const PUBSYM32 * pdb_lookup_public_symbol(void *context, const char *name, bool case_sensitive);

int pdb_convert_section_offset_to_rva(void *context, uint16_t section_idx, uint32_t section_offset, uint32_t *rva);

pdb_errno_t pdb_errno(void *context);
const char * pdb_strerror(void *context);

#pragma pack(pop)

#endif // PDB_H
