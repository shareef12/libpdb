#include "pdb.h"

#include "pdb/dbistream.h"
#include "pdb/pdbstream.h"
#include "pdb/msf.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <signal.h>
#include <stdio.h>

#ifdef PDB_ENABLE_ASSERTIONS
#include <assert.h>
#endif // PDB_ENABLE_ASSERTIONS

/*
 * TODO:
 *  - Add integer overflow validation
 */

#define PDB_SIGNATURE "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))
#define min(a, b) (((a) < (b)) ? (a) : (b))

/*
 * Declare these inline functions from cvinfo.h as extern, otherwise they will
 * not be included in our static library and link errors will result.
 */
extern __INLINE SYMTYPE *NextSym (const SYMTYPE * pSym);
extern __INLINE char *NextType (const char * pType);

/*
 * libpdb uses assertions to catch usage errors when configured with
 * PDB_ENABLE_ASSERTIONS. Otherwise, it introduces additional semantics to
 * prevent an immediate crash.
 */
#if defined(PDB_ENABLE_ASSERTIONS) && !defined(NDEBUG)

#define PDB_ASSERT(expr) assert(expr)
#define PDB_ASSERT_CTX_NOT_NULL(ctx, retval) assert((ctx) != NULL)
#define PDB_ASSERT_PDB_LOADED(ctx, retval) assert((ctx)->pdb_loaded)
#define PDB_ASSERT_PARAMETER(ctx, expr, retval) assert(expr)

#else

#define PDB_ASSERT(expr)

#define PDB_ASSERT_CTX_NOT_NULL(ctx, retval) do {       \
        if ((ctx) == NULL) {                            \
            return (retval);                            \
        }                                               \
    } while (0)

#define PDB_ASSERT_PDB_LOADED(ctx, retval) do {         \
        if (!(ctx)->pdb_loaded) {                       \
            (ctx)->error = EPDB_NO_PDB_LOADED;          \
            return (retval);                            \
        }                                               \
    } while (0)

#define PDB_ASSERT_PARAMETER(ctx, retval, expr) do {    \
        if (!(expr)) {                                  \
            (ctx)->error = EPDB_INVALID_PARAMETER;      \
            return (retval);                            \
        }                                               \
    } while (0)

#endif // PDB_ENABLE_ASSERTIONS

struct stream {
    uint32_t size;
    const unsigned char *data;
};

struct pdb_context {
    /* User-supplied memory alloc/free functions */
    malloc_fn malloc;
    free_fn free;
    pdb_errno_t error;

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
    bool symbol_stream_parsed;
    uint32_t nr_symbols;
    uint32_t nr_public_symbols;
};


static const char *errstrings[] = {
    "No error",
    "No PDB loaded",
    "System error",
    "Invalid parameter",
    "Unsupported version",
    "PDB file is corrupt",
    "Invalid section index",
    "Invalid section offset",
};


static void initialize_pdb_context(struct pdb_context *ctx, malloc_fn user_malloc_fn, free_fn user_free_fn)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->malloc = user_malloc_fn ? user_malloc_fn : malloc;
    ctx->free = user_free_fn ? user_free_fn : free;

    ctx->error = EPDB_SUCCESS;
    ctx->pdb_loaded = false;
    ctx->symbol_stream_parsed = false;
}


static void cleanup_pdb_context(struct pdb_context *ctx)
{
    ctx->free((void *)ctx->streams);
}


static size_t nr_blocks(size_t count, size_t block_size)
{
    PDB_ASSERT(block_size != 0);
    if (count == 0) {
        return 0;
    }
    return 1 + ((count - 1) / block_size);
}


static bool valid_superblock(const struct superblock *sb, size_t len)
{
    if (len < sizeof(struct superblock)) {
        return false;
    }

    bool valid =
        memcmp(sb->file_magic, PDB_SIGNATURE, PDB_SIGNATURE_SZ) == 0 &&
        sb->num_blocks > 0 &&
        sb->num_blocks * sb->block_size == len &&
        sb->free_block_map_block < sb->num_blocks &&
        sb->num_directory_bytes > 0 &&
        sb->block_map_addr < sb->num_blocks;

    switch (sb->block_size) {
        case 512:
        case 1024:
        case 2048:
        case 4096:
            break;
        default:
            valid = false;
            break;
    }

    return valid;
}


static int extract_stream_directory(
    const unsigned char *pdb,
    size_t len,
    const struct superblock *sb,
    const struct stream_directory **stream_directory,
    size_t *stream_directory_len)
{
    size_t nr_sd_blocks = nr_blocks(sb->num_directory_bytes, sb->block_size);
    if (sb->block_map_addr * sb->block_size + nr_sd_blocks > len) {
        /* Malformed pdb - block_map extends past end of file */
        return -1;
    }

    /* Allocate memory in a multiple of block_size to simplify copying */
    unsigned char *sd = calloc(sb->block_size, nr_sd_blocks);
    if (sd == NULL) {
        errno = ENOMEM;
        return -1;
    }

    const uint32_t *block_map = (const uint32_t *)(pdb + sb->block_map_addr * sb->block_size);
    for (size_t i = 0; i < nr_sd_blocks; i++) {
        if (block_map[i] >= sb->num_blocks) {
            /* Malformed pdb - invalid block index */
            goto err_free_sd;
        }

        memcpy(sd + i * sb->block_size, pdb + block_map[i] * sb->block_size, sb->block_size);
    }

    /* Validate that the stream directory contains valid contents */
    uint32_t num_streams = *(uint32_t *)sd;
    if (sizeof(uint32_t) + num_streams * sizeof(uint32_t) > sb->num_directory_bytes) {
        /* Malformed pdb - too many streams */
        goto err_free_sd;
    }

    size_t total_blocks = 0;
    const uint32_t *stream_sizes = (const uint32_t *)(sd + sizeof(uint32_t));
    for (size_t i = 0; i < num_streams; i++) {
        total_blocks += nr_blocks(stream_sizes[i], sb->block_size);
    }

    size_t computed_sdir_size =
        sizeof(uint32_t) +
        num_streams * sizeof(uint32_t) +
        total_blocks * sizeof(uint32_t);
    if (computed_sdir_size != sb->num_directory_bytes) {
        /* Malformed pdb - incorrect stream directory size */
        goto err_free_sd;
    }

    *stream_directory = (const struct stream_directory *)sd;
    *stream_directory_len = sb->num_directory_bytes;
    return 0;

err_free_sd:
    free(sd);
    return -1;
}


static int do_extract_streams(
    const unsigned char *pdb,
    const struct superblock *sb,
    const struct stream_directory *sd,
    const struct stream **streams,
    uint32_t *nr_streams)
{
    /* Extract all streams into a single large data structure */
    size_t total_sz = sd->num_streams * sizeof(struct stream);
    const uint32_t *stream_sizes = (const uint32_t *)((char *)sd + sizeof(uint32_t));
    for (uint32_t i = 0; i < sd->num_streams; i++) {
        total_sz += nr_blocks(stream_sizes[i], sb->block_size) * sb->block_size;
    }

    struct stream *strms = calloc(1, total_sz);
    if (strms == NULL) {
        errno = ENOMEM;
        return -1;
    }

    /* Defragment the streams so we have contiguous data for each one */
    const uint32_t *stream_blocks = stream_sizes + sd->num_streams;
    unsigned char *next_stream_data = (unsigned char *)(strms + sd->num_streams);
    for (uint32_t i = 0; i < sd->num_streams; i++) {
        strms[i].size = stream_sizes[i];
        strms[i].data = next_stream_data;

        for (size_t j = 0; j < nr_blocks(strms[i].size, sb->block_size); j++) {
            uint32_t block_idx = *stream_blocks;
            if (block_idx >= sb->num_blocks) {
                /* Malformed pdb - invalid block index */
                goto err_free_strms;
            }

            memcpy(next_stream_data, pdb + block_idx * sb->block_size, sb->block_size);

            next_stream_data += sb->block_size;
            stream_blocks++;
        }
    }

    *streams = strms;
    *nr_streams = sd->num_streams;
    return 0;

err_free_strms:
    free(strms);

    return -1;
}


static int extract_streams(
    struct pdb_context *ctx,
    const unsigned char *pdbdata,
    size_t len)
{
    const struct superblock *sb = (struct superblock *)pdbdata;
    bool valid = valid_superblock(sb, len);
    if (!valid) {
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    const struct stream_directory *sd = NULL;
    size_t sd_len = 0;
    int err = extract_stream_directory(pdbdata, len, sb, &sd, &sd_len);
    if (err < 0) {
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    const struct stream *strms = NULL;
    uint32_t nr_strms = 0;
    err = do_extract_streams(pdbdata, sb, sd, &strms, &nr_strms);
    free((void *)sd);
    if (err < 0) {
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    if (nr_strms < MIN_STREAM_COUNT) {
        /* Malformed PDB - a PDB has a minimum of 5 static streams */
        free((void *)strms);
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    ctx->block_size = sb->block_size;
    ctx->nr_blocks = sb->num_blocks;
    ctx->streams = strms;
    ctx->nr_streams = nr_strms;

    return 0;
}


static int parse_pdb_stream(struct pdb_context *ctx)
{
    if (PDB_STREAM_IDX >= ctx->nr_streams) {
        /* Malformed PDB - No PDB stream */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    const struct stream *stream = &ctx->streams[PDB_STREAM_IDX];
    if (stream->size < sizeof(struct pdb_stream_header)) {
        /* Malformed PDB - PDB stream too small */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    const struct pdb_stream_header *hdr = (const struct pdb_stream_header *)stream->data;
    if (hdr->version != PSV_VC70) {
        /* Unsupported PDB version */
        ctx->error = EPDB_UNSUPPORTED_VERSION;
        return -1;
    }

    // TODO: Parse name table

    ctx->age = hdr->age;
    memcpy(ctx->guid.bytes, hdr->unique_id, 16);

    return 0;
}


static int parse_dbi_stream(struct pdb_context *ctx)
{
    if (DBI_STREAM_IDX >= ctx->nr_streams) {
        /* Malformed PDB - No DBI stream */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    const struct stream *stream = &ctx->streams[DBI_STREAM_IDX];
    if (stream->size < sizeof(struct dbi_stream_header)) {
        /* Malformed PDB - DBI stream too small */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    const struct dbi_stream_header *hdr = (const struct dbi_stream_header *)stream->data;
    if (hdr->version_signature != -1 || hdr->version_header != DSV_V70) {
        /* Unknown version */
        ctx->error = EPDB_UNSUPPORTED_VERSION;
        return -1;
    }

    if (hdr->global_stream_index >= ctx->nr_streams ||
        hdr->public_stream_index >= ctx->nr_streams ||
        hdr->sym_record_stream >= ctx->nr_streams ||
        hdr->mfc_type_server_index >= ctx->nr_streams) {
        /* Malformed PDB - bad stream index */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    uint32_t total_sz = sizeof(struct dbi_stream_header) +
        hdr->mod_info_size +
        hdr->section_contribution_size +
        hdr->section_map_size +
        hdr->source_info_size +
        hdr->type_server_map_size +
        hdr->optional_dbg_header_size +
        hdr->ec_substream_size;
    if (total_sz != stream->size) {
        /* Malformed PDB - bad stream size */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    /* TODO: Parse module info substream */
    const void *mihdr = stream->data + sizeof(struct dbi_stream_header);

    /* TODO: Parse section contribution substream */
    const void *schdr = (char *)mihdr + hdr->mod_info_size;

    const struct section_map_header *smhdr = (const struct section_map_header *)((char *)schdr + hdr->section_contribution_size);
    if (sizeof(struct section_map_header) + sizeof(struct section_map_entry) * smhdr->count > hdr->section_map_size) {
        /* Malformed PDB - bad substream size */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    /* TODO: Parse source file info substream */
    const void *sihdr = (char *)smhdr + hdr->section_map_size;

    /* TODO: Parse type server map substream */
    const void *smaphdr = (char *)sihdr + hdr->source_info_size;

    /* TODO: Parse EC substream */
    const void *echdr = (char *)smaphdr + hdr->type_server_map_size;

    /* TODO: Parse optional debug header stream */
    const struct debug_header *dbghdr = (const struct debug_header *)((char *)echdr + hdr->ec_substream_size);
    if (sizeof(struct debug_header) > hdr->optional_dbg_header_size) {
        /* Malformed PDB - invalid substream size */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    for (uint16_t i = 0; i < DBI_NUM_DEBUG_HEADER_STREAMS; i++) {
        if (dbghdr->streams[i] != UINT16_MAX && dbghdr->streams[i] >= ctx->nr_streams) {
            /* Malformed PDB - invalid stream index */
            ctx->error = EPDB_FILE_CORRUPT;
            return -1;
        }
    }

    if (dbghdr->section_header_data_stream_index == UINT16_MAX) {
        /* Malformed PDB - No section header stream */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    const struct stream *shdr_stream = &ctx->streams[dbghdr->section_header_data_stream_index];
    uint32_t nr_sections = shdr_stream->size / sizeof(struct image_section_header);

    ctx->sections = (const struct image_section_header *)shdr_stream->data;
    ctx->nr_sections = nr_sections;
    ctx->dbi_header = hdr;
    ctx->dbg_header = dbghdr;

    return 0;
}


static int parse_symbol_stream(struct pdb_context *ctx)
{
    uint16_t symbols_stream_idx = ctx->dbi_header->sym_record_stream;
    if (symbols_stream_idx >= ctx->nr_streams) {
        /* Invalid stream index */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    const struct stream *stream = &ctx->streams[symbols_stream_idx];
    const SYMTYPE *sym = (const SYMTYPE *)stream->data;
    const SYMTYPE *stream_end = (const SYMTYPE *)(stream->data + stream->size);

    uint32_t nr_symbols = 0;
    uint32_t nr_public_symbols = 0;

    while (sym < stream_end) {
        const SYMTYPE *next = NextSym(sym);
        if (sym + sizeof(SYMTYPE) > stream_end || next > stream_end || next <= sym) {
            /* Stream too short - not enough data left for the full symbol */
            ctx->error = EPDB_FILE_CORRUPT;
            return -1;
        }

        /*
         * TODO: Validate that the symbol's contents are valid (i.e. all the
         *  symbols fields lie within sym <--> next) - this is currently on the
         *  caller to do.
         */

        nr_symbols++;
        if (sym->rectyp == S_PUB32) {
            nr_public_symbols++;
        }

        sym = next;
    }

    if (sym != stream_end) {
        /* Invalid stream size - does not match symbol contents */
        ctx->error = EPDB_FILE_CORRUPT;
        return -1;
    }

    ctx->symbol_stream_parsed = true;
    ctx->nr_symbols = nr_symbols;
    ctx->nr_public_symbols = nr_public_symbols;

    return 0;
}


void get_symbols(struct pdb_context *ctx, const SYMTYPE **symbols, bool public_only)
{
    PDB_ASSERT(ctx->symbol_stream_parsed);

    /* parse_symbol_stream has already performed symbol stream validation */
    uint16_t symbols_stream_idx = ctx->dbi_header->sym_record_stream;
    const struct stream *stream = &ctx->streams[symbols_stream_idx];
    const SYMTYPE *sym = (const SYMTYPE *)stream->data;

    for (size_t i = 0, j = 0; i < ctx->nr_symbols; i++) {
        if (public_only) {
            if (sym->rectyp == S_PUB32) {
                symbols[j++] =sym;
            }
        }
        else {
            symbols[j++] = sym;
        }

        sym = NextSym(sym);
    }
}


bool pdb_sig_match(void *data, size_t len)
{
    return memcmp(data, PDB_SIGNATURE, min(len, PDB_SIGNATURE_SZ)) == 0;
}


void * pdb_create_context(malloc_fn user_malloc_fn, free_fn user_free_fn)
{
    user_malloc_fn = user_malloc_fn ? user_malloc_fn : malloc;
    user_free_fn = user_free_fn ? user_free_fn : free;

    struct pdb_context *ctx = user_malloc_fn(sizeof(struct pdb_context));
    if (ctx == NULL) {
        return NULL;
    }

    initialize_pdb_context(ctx, user_malloc_fn, user_free_fn);

    return ctx;
}


void pdb_reset_context(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;
    if (ctx == NULL) {
        return;
    }

    cleanup_pdb_context(ctx);
    initialize_pdb_context(ctx, ctx->malloc, ctx->free);
}


void pdb_destroy_context(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;
    if (ctx == NULL) {
        return;
    }

    cleanup_pdb_context(ctx);
    ctx->free(ctx);
}


int pdb_load(void *context, const void *pdbdata, size_t len)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, -1);
    PDB_ASSERT_PARAMETER(ctx, -1, pdbdata != NULL && len > 0);

    if (ctx->pdb_loaded) {
        pdb_reset_context(context);
    }

    if (extract_streams(ctx, pdbdata, len) < 0) {
        return -1;
    }

    if (parse_pdb_stream(ctx) < 0) {
        return -1;
    }

    if (parse_dbi_stream(ctx) < 0) {;
        return -1;
    }

    /* TODO: Parse TPI stream */
    /* TODO: parse IPI stream */

    ctx->pdb_loaded = true;

    return 0;
}


void pdb_get_header(void *context, uint32_t *block_size, uint32_t *nr_blocks, const struct guid **guid, uint32_t *age, uint32_t *nr_streams)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    if (ctx == NULL || !ctx->pdb_loaded ||
        block_size == NULL ||
        nr_blocks == NULL ||
        guid == NULL ||
        age == NULL ||
        nr_streams == NULL) {
        return;
    }

    *block_size = ctx->block_size;
    *nr_blocks = ctx->nr_blocks;
    *guid = &ctx->guid;
    *age = ctx->age;
    *nr_streams = ctx->nr_streams;
}


uint32_t pdb_get_block_size(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, 0);
    PDB_ASSERT_PDB_LOADED(ctx, 0);

    return ctx->block_size;
}


uint32_t pdb_get_nr_blocks(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, 0);
    PDB_ASSERT_PDB_LOADED(ctx, 0);

    return ctx->nr_blocks;
}


const struct guid * pdb_get_guid(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, 0);
    PDB_ASSERT_PDB_LOADED(ctx, 0);

    return &ctx->guid;
}


uint32_t pdb_get_age(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, 0);
    PDB_ASSERT_PDB_LOADED(ctx, 0);

    return ctx->age;
}


uint32_t pdb_get_nr_streams(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, 0);
    PDB_ASSERT_PDB_LOADED(ctx, 0);

    return ctx->nr_streams;
}


const unsigned char * pdb_get_stream(void *context, uint32_t stream_idx, uint32_t *stream_size)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, NULL);
    PDB_ASSERT_PDB_LOADED(ctx, NULL);
    PDB_ASSERT_PARAMETER(ctx, NULL, stream_size != NULL);

    if (stream_idx >= ctx->nr_streams) {
        ctx->error = EPDB_INVALID_PARAMETER;
        return NULL;
    }

    *stream_size = ctx->streams[stream_idx].size;
    return ctx->streams[stream_idx].data;
}


uint32_t pdb_get_nr_sections(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, 0);
    PDB_ASSERT_PDB_LOADED(ctx, 0);

    return ctx->nr_sections;
}


const struct image_section_header * pdb_get_sections(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, NULL);
    PDB_ASSERT_PDB_LOADED(ctx, NULL);

    return ctx->sections;
}


int pdb_get_nr_public_symbols(void *context, uint32_t *nr_public_symbols)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, -1);
    PDB_ASSERT_PDB_LOADED(ctx, -1);
    PDB_ASSERT_PARAMETER(ctx, -1, nr_public_symbols != NULL);

    if (!ctx->symbol_stream_parsed) {
        int err = parse_symbol_stream(ctx);
        if (err < 0) {
            return -1;
        }
    }

    *nr_public_symbols = ctx->nr_public_symbols;

    return 0;
}


int pdb_get_public_symbols(void *context, const PUBSYM32 **symbols)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, -1);
    PDB_ASSERT_PDB_LOADED(ctx, -1);
    PDB_ASSERT_PARAMETER(ctx, -1, symbols != NULL);

    get_symbols(ctx, (const SYMTYPE **)symbols, true);

    return 0;
}


int pdb_get_nr_symbols(void *context, uint32_t *nr_symbols)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, -1);
    PDB_ASSERT_PDB_LOADED(ctx, -1);
    PDB_ASSERT_PARAMETER(ctx, -1, nr_symbols != NULL);

    /* Fast path - we've already iterated through all the symbols and cached the number */
    if (!ctx->symbol_stream_parsed) {
        int err = parse_symbol_stream(ctx);
        if (err < 0) {
            return -1;
        }
    }

    *nr_symbols = ctx->nr_symbols;

    return 0;
}


int pdb_get_symbols(void *context, const SYMTYPE **symbols)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, -1);
    PDB_ASSERT_PDB_LOADED(ctx, -1);
    PDB_ASSERT_PARAMETER(ctx, -1, symbols != NULL);

    get_symbols(ctx, symbols, false);

    return 0;
}


const PUBSYM32 * pdb_lookup_public_symbol(void *context, const char *mangled_name)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, NULL);
    PDB_ASSERT_PDB_LOADED(ctx, NULL);
    PDB_ASSERT_PARAMETER(ctx, NULL, mangled_name != NULL && *mangled_name != '\0');

    //uint16_t global_symbols_idx = PDB_PRIVATE(pdb)->dbi_header->global_stream_index;
    uint16_t global_symbols_idx = ctx->dbi_header->public_stream_index;
    if (global_symbols_idx >= ctx->nr_streams) {
        /* Not enough streams */
        return NULL;
    }

    const struct stream *stream = &ctx->streams[global_symbols_idx];

    // TODO: Parse the hash table

    return NULL;
}


int pdb_convert_section_offset_to_rva(void *context, uint16_t section_idx, uint32_t section_offset, uint32_t *rva)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, -1);
    PDB_ASSERT_PDB_LOADED(ctx, -1);
    PDB_ASSERT_PARAMETER(ctx, -1, rva != NULL);

    /* Sections indices in a PDB are 1-based */
    if (section_idx == 0 || section_idx > ctx->nr_sections) {
        /* NULL or invalid section index - no translation */
        ctx->error = EPDB_INVALID_SECTION_IDX;
        return -1;
    }
    section_idx -= 1;

    if (section_offset > ctx->sections[section_idx].misc.virtual_size) {
        /* Malformed PDB or invalid offset - address not in section */
        ctx->error = EPDB_INVALID_SECTION_OFFSET;
        return -1;
    }

    uint32_t section_base = ctx->sections[section_idx].virtual_address;
    if (section_base + section_offset < section_base) {
        /* Integer overflow - no valid RVA */
        ctx->error = EPDB_INVALID_SECTION_OFFSET;
        return -1;
    }

    *rva = section_base + section_offset;
    return 0;
}


pdb_errno_t pdb_errno(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;
    PDB_ASSERT_CTX_NOT_NULL(ctx, EPDB_INVALID_PARAMETER);

    return ctx->error;
}


char * pdb_strerror(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;
    PDB_ASSERT_CTX_NOT_NULL(ctx, NULL);

    PDB_ASSERT(ctx->error < ARRAY_SIZE(errstrings))

    if (ctx->error == EPDB_SYSTEM_ERROR) {
        return strerror(errno);
    }

    return errstrings[ctx->error];
}
