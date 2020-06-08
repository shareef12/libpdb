#ifndef PDB_H
#define PDB_H

#include "pdb/cvinfo.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)

#define PDB_EXPORT __attribute__((visibility("default")))

#define PDB_SIGNATURE_SZ (32)

typedef enum pdb_errno_t {
    EPDB_SUCCESS = 0,
    EPDB_SYSTEM_ERROR,
    EPDB_ALLOCATION_FAILURE,
    EPDB_NO_PDB_LOADED,
    EPDB_INVALID_PARAMETER,
    EPDB_UNSUPPORTED_VERSION,
    EPDB_PARSE_ERROR,
    EPDB_INVALID_SECTION_IDX,
    EPDB_INVALID_SECTION_OFFSET,
    EPDB_NOT_FOUND,
    EPDB_INVALID_IMAGE_NAME,
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

typedef void *(*malloc_fn)(size_t size);
typedef void (*free_fn)(void *ptr);
typedef void *(*realloc_fn)(void *ptr, size_t size);

/* Verify a PDB file's signature */
PDB_EXPORT bool pdb_sig_match(void *data, size_t len);

/* Global init and cleanup callbacks for libpdb */
PDB_EXPORT int pdb_global_init(void);
PDB_EXPORT int pdb_global_init_mem(
    malloc_fn user_malloc_fn, free_fn user_free_fn, realloc_fn user_realloc_fn);
PDB_EXPORT void pdb_global_cleanup(void);

/* Initialize and destroy a libpdb parser */
PDB_EXPORT void *pdb_create_context(void);
PDB_EXPORT void pdb_destroy_context(void *context);
PDB_EXPORT void pdb_reset_context(void *context);

/* Parse an in-memory PDB file */
PDB_EXPORT int pdb_load(void *context, const void *pdbdata, size_t length);

/* Get PDB header information */
PDB_EXPORT void pdb_get_header(
    void *context,
    uint32_t *block_size,
    uint32_t *nr_blocks,
    const struct guid **guid,
    uint32_t *age,
    uint32_t *nr_streams);
PDB_EXPORT uint32_t pdb_get_block_size(void *context);
PDB_EXPORT uint32_t pdb_get_nr_blocks(void *context);
PDB_EXPORT const struct guid *pdb_get_guid(void *context);
PDB_EXPORT uint32_t pdb_get_age(void *context);

/* Get a raw PDB stream */
PDB_EXPORT const unsigned char *pdb_get_stream(
    void *context, uint32_t stream_idx, uint32_t *stream_size);
PDB_EXPORT uint32_t pdb_get_nr_streams(void *context);

/* Get an image's section headers */
PDB_EXPORT const struct image_section_header *pdb_get_sections(void *context);
PDB_EXPORT uint32_t pdb_get_nr_sections(void *context);

/* Enumerate PDB symbols - public and global */
PDB_EXPORT int pdb_get_symbols(void *context, const struct SYMTYPE **symbols);
PDB_EXPORT int pdb_get_nr_symbols(void *context, uint32_t *nr_symbols);

/* Enumerate PDB symbols - public only */
PDB_EXPORT int pdb_get_public_symbols(void *context, const PUBSYM32 **symbols);
PDB_EXPORT int pdb_get_nr_public_symbols(void *context, uint32_t *nr_public_symbols);

/* Find a public symbol by hash */
PDB_EXPORT const PUBSYM32 *pdb_lookup_public_symbol(
    void *context, const char *name, bool case_sensitive);

/* Convert a section index/offset pair to an RVA */
PDB_EXPORT int pdb_convert_section_offset_to_rva(
    void *context, uint16_t section_idx, uint32_t section_offset, uint32_t *rva);

/* Get or set the symbol path for PDB retrieval */
PDB_EXPORT const char *pdb_get_symbol_path(void *context);
PDB_EXPORT void pdb_set_symbol_path(void *context, const char *symbol_path);
PDB_EXPORT int pdb_append_symbol_path(void *context, const char *symbol_path_part);

/* Load a PDB file for an executable */
PDB_EXPORT int pdb_load_from_sympath(
    void *context, const void *image, size_t length, bool mapped, bool check_pdbpath);

/* TODO: Add support for configuring an HTTP proxy */

/* Get libpdb error information */
PDB_EXPORT pdb_errno_t pdb_errno(void *context);
PDB_EXPORT const char *pdb_strerror(void *context);

#pragma pack(pop)

#endif  // PDB_H
