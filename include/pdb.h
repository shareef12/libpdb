#ifndef PDB_H
#define PDB_H

#include "pdb/codeview.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PDB_SIGNATURE_SZ (32)

typedef enum pdb_errno_t {
    EPDB_SUCCESS = 0,
    EPDB_NO_PDB_LOADED,
    EPDB_SYSTEM_ERROR,
    EPDB_INVALID_PARAMETER,
    EPDB_UNSUPPORTED_VERSION,
    EPDB_FILE_CORRUPT,

    EPDB_INVALID_SECTION_IDX,
    EPDB_INVALID_SECTION_OFFSET,
} pdb_errno_t;

struct guid {
    union {
        struct {
            uint32_t data1;
            uint16_t data2;
            uint16_t data3;
            unsigned char data4[8];
        } __attribute__((packed));
        unsigned char bytes[16];
    };
} __attribute__((packed));

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
} __attribute__((packed));

typedef void * (*malloc_fn)(size_t size);
typedef void (*free_fn)(void *ptr);

/* TODO:
 *
 * New APIs
 *  - API for looking up a symbol in the hashtable
 *  - API for file-based IO to reduce memory usage?
 *      - Memory-reduced mode where we extract streams on demand?
 *  - API set for writing PDBs?
 *
 * New Features
 *  - Name demangling
 *  - Download files from a symbol server
 *  - Support for weird systems (preprocessor defines for using stuff like assert, errno, libcurl, fprintf, fread, etc. Also endianness...)
 *
 * Error Handling
 *  - Need additional checking in parse_symbol_stream for checking the contents of symbols (public and otherwise)
 *  - Need to add integer overflow detection in stream extraction
 *
 * Other
 *  - Implement hashtable parsing and searching
 *
 *  - Unit tests
 *  - Fuzzing
 *  - Packaging
 *  - Documentation
 */

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
int pdb_get_public_symbols(void *context, const struct cv_public_symbol **symbols);

/* Iterate through *all* symbols (public + global) */
int pdb_get_nr_symbols(void *context, uint32_t *nr_symbols);
int pdb_get_symbols(void *context, const struct cv_record_header **symbols);

/* Find a symbol by looking it up in the PDB symbol hashtable */
/* const struct cv_public_symbol * pdb_lookup_public_symbol(void *context, const char *mangled_name); */
/* const struct cv_global_symbol * pdb_lookup_global_symbol(void *context, const char *mangled_name); */

int pdb_convert_section_offset_to_rva(void *context, uint16_t section_idx, uint32_t section_offset, uint32_t *rva);

pdb_errno_t pdb_errno(void *context);
char * pdb_strerror(void *context);

#endif // PDB_H
