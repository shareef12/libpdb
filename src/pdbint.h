#ifndef PDBINT_H
#define PDBINT_H

#include "pdb.h"

#include "pdb/gsistream.h"

#include <stdint.h>

/*
 * libpdb uses assertions to catch usage errors when configured with
 * PDB_ENABLE_ASSERTIONS. Otherwise, it introduces additional semantics to
 * prevent an immediate crash.
 */
#if defined(PDB_ENABLE_ASSERTIONS) && !defined(NDEBUG)

#include <assert.h>

#define PDB_ASSERT(expr) assert(expr)
#define PDB_ASSERT_CTX_NOT_NULL(ctx, retval) assert((ctx) != NULL)
#define PDB_ASSERT_PDB_LOADED(ctx, retval) assert((ctx)->pdb_loaded)
#define PDB_ASSERT_PARAMETER(ctx, retval, expr) assert(expr)

#else

#define PDB_ASSERT(expr)

#define PDB_ASSERT_CTX_NOT_NULL(ctx, retval) \
    do {                                     \
        if ((ctx) == NULL) {                 \
            return (retval);                 \
        }                                    \
    } while (0)

#define PDB_ASSERT_PDB_LOADED(ctx, retval)     \
    do {                                       \
        if (!(ctx)->pdb_loaded) {              \
            (ctx)->error = EPDB_NO_PDB_LOADED; \
            return (retval);                   \
        }                                      \
    } while (0)

#define PDB_ASSERT_PARAMETER(ctx, retval, expr)    \
    do {                                           \
        if (!(expr)) {                             \
            (ctx)->error = EPDB_INVALID_PARAMETER; \
            return (retval);                       \
        }                                          \
    } while (0)

#endif  // PDB_ENABLE_ASSERTIONS

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*(array)))

struct stream {
    uint32_t size;
    const unsigned char *data;
};

struct sym_hashrec {
    const SYMTYPE *sym;
    const struct sym_hashrec *next;
    uint32_t c_ref;
};

struct sym_hashtable {
    struct sym_hashrec *buckets[NR_HASH_BUCKETS];
    struct sym_hashrec *hashrecs;
};

struct pdb_context {
    pdb_errno_t error;

    /* Symbol search path - can be get/set without a PDB loaded */
    const char *symbol_path;

    /*
     * The pathname for this PDB file. This is only used if the PDB was loaded
     * with pdb_load_from_sympath.
     */
    const char *pdb_pathname;

    /* true if we've loaded a pdb */
    bool pdb_loaded;

    /* Raw stream data */
    const struct stream *streams;
    uint32_t nr_streams;

    /* PDB Header Information */
    uint32_t block_size;
    uint32_t nr_blocks;
    struct guid guid;
    uint32_t age;

    /* Image section headers (post-optimization) */
    const struct image_section_header *sections;
    uint32_t nr_sections;

    /* Cached DBI stream info - this stream contains useful stream indices */
    const struct dbi_stream_header *dbi_header;
    const struct debug_header *dbg_header;

    /* Cached symbol information */
    bool symbol_streams_parsed;
    uint32_t nr_symbols;
    uint32_t nr_public_symbols;
    struct sym_hashtable pubsym_hashtab;
};

#endif  // PDBINT_H
