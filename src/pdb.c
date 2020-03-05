#include "pdb.h"

#include "codeview.h"
#include "dbistream.h"
#include "pdbstream.h"
#include "private.h"
#include "msf.h"

#include <assert.h>
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

/*
 * TODO:
 *  - Add integer overflow validation
 */


static size_t nr_blocks(size_t count, size_t block_size)
{
    assert(block_size > 0);
    if (count == 0) {
        return 0;
    }
    return 1 + ((count - 1) / block_size);
}


static int validate_superblock(const struct superblock *sb, size_t len)
{
    bool valid =
        len > sizeof(struct superblock) &&
        memcmp(sb->file_magic, PDB_SUPERBLOCK_MAGIC, PDB_SUPERBLOCK_MAGIC_SZ) == 0 &&
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

    return valid ? 0 : -1;
}


static int extract_stream_directory(
    const unsigned char *pdb,
    size_t len,
    const struct superblock *sb,
    const struct stream_directory **stream_directory,
    size_t *stream_directory_len)
{
    assert(stream_directory != NULL);
    assert(stream_directory_len != NULL);

    size_t nr_sd_blocks = nr_blocks(sb->num_directory_bytes, sb->block_size);
    if (sb->block_map_addr * sb->block_size + nr_sd_blocks > len) {
        /* Malformed pdb - block_map extends past end of file */
        return -1;
    }

    /* Allocate memory in a multiple of block_size to simplify copying */
    unsigned char *sd = calloc(sb->block_size, nr_sd_blocks);
    if (sd == NULL) {
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
        return -1;
    }

    /* Defragment the streams so we have contiguous data for each one */
    const uint32_t *stream_blocks = stream_sizes + sd->num_streams;
    unsigned char *next_stream_data = (unsigned char *)(strms + sd->num_streams);
    for (uint32_t i = 0; i < sd->num_streams; i++) {
        strms[i].index = i;
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
    const unsigned char *pdb,
    size_t len,
    const struct stream **streams,
    uint32_t *nr_streams)
{
    assert(streams != NULL);
    assert(nr_streams != NULL);

    int err = -1;

    const struct superblock *sb = (struct superblock *)pdb;
    err = validate_superblock(sb, len);
    if (err < 0) {
        return err;
    }

    const struct stream_directory *sd = NULL;
    size_t sd_len = 0;
    err = extract_stream_directory(pdb, len, sb, &sd, &sd_len);
    if (err < 0) {
        return err;
    }

    const struct stream *strms = NULL;
    uint32_t nr_strms = 0;
    err = do_extract_streams(pdb, sb, sd, &strms, &nr_strms);
    free((void *)sd);
    if (err < 0) {
        return err;
    }

    if (nr_strms < MIN_STREAM_COUNT) {
        /* Malformed PDB - a PDB has a minimum of 5 static streams */
        free((void *)strms);
        return -1;
    }

    *streams = strms;
    *nr_streams = nr_strms;
    return 0;
}


static int parse_pdb_stream(
    const struct stream *stream,
    uint32_t *age,
    unsigned char *guid)
{
    assert(stream != NULL);

    if (stream->size < sizeof(struct pdb_stream_header)) {
        /* Malformed PDB - PDB stream too small */
        return -1;
    }

    const struct pdb_stream_header *hdr = (const struct pdb_stream_header *)stream->data;
    if (hdr->version != PSV_VC70) {
        /* Unsupported PDB version */
        return -1;
    }

    // TODO: Parse name table

    *age = hdr->age;
    memcpy(guid, hdr->unique_id, 16);

    return 0;
}


static int parse_dbi_stream(
    struct pdb *pdb,
    const struct stream *stream,
    const struct dbi_stream_header **dbi_header)
{
    if (stream->size < sizeof(struct dbi_stream_header)) {
        /* Malformed PDB - DBI stream too small */
        return -1;
    }

    const struct dbi_stream_header *hdr = (const struct dbi_stream_header *)stream->data;
    if (hdr->version_signature != -1 || hdr->version_header != DSV_V70) {
        /* Unknown version */
        return -1;
    }

    if (hdr->global_stream_index >= pdb->nr_streams ||
        hdr->public_stream_index >= pdb->nr_streams ||
        hdr->sym_record_stream >= pdb->nr_streams ||
        hdr->mfc_type_server_index >= pdb->nr_streams) {
        /* Malformed PDB - bad stream index */
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
        return -1;
    }

    /* TODO: Parse module info substream */
    const void *mihdr = stream->data + sizeof(struct dbi_stream_header);

    /* TODO: Parse section contribution substream */
    const void *schdr = (char *)mihdr + hdr->mod_info_size;

    const struct section_map_header *smhdr = (const struct section_map_header *)((char *)schdr + hdr->section_contribution_size);
    if (sizeof(struct section_map_header) + sizeof(struct section_map_entry) * smhdr->count > hdr->section_map_size) {
        /* Malformed PDB - bad substream size */
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
        return -1;
    }

    for (uint16_t i = 0; i < DBI_NUM_DEBUG_HEADER_STREAMS; i++) {
        if (dbghdr->streams[i] != UINT16_MAX && dbghdr->streams[i] >= pdb->nr_streams) {
            /* Malformed PDB - invalid stream index */
            return -1;
        }
    }

    PDB_PRIVATE(pdb)->sm_header = smhdr;
    PDB_PRIVATE(pdb)->dbg_header = dbghdr;
    *dbi_header = hdr;

    return 0;
}


static int lookup_rva(const struct pdb *pdb, uint16_t section_idx, uint32_t section_offset, uint32_t *rva)
{
    assert(pdb != NULL);
    assert(rva != NULL);

    if (section_idx == 0) {
        /* NULL section index - no translation */
        puts("a");
        return -1;
    }
    section_idx -= 1;

    const struct debug_header *dbghdr = PDB_PRIVATE(pdb)->dbg_header;
    if (dbghdr->section_header_data_stream_index == UINT16_MAX) {
        /* No section header stream - can't translate address */
        puts("b");
        return -1;
    }

    const struct stream *shdr_stream = &pdb->streams[dbghdr->section_header_data_stream_index];
    uint32_t nr_sections = shdr_stream->size / sizeof(struct image_section_header);
    if (section_idx >= nr_sections) {
        fprintf(stderr, "section_idx = %d\n", section_idx);
        fprintf(stderr, "nr_sections = %d\n", nr_sections);
        fprintf(stderr, "size = %d\n", shdr_stream->size);
        fprintf(stderr, "ish_size = %lu\n", sizeof(struct image_section_header));

        /* Invalid section index - no translation */
        return -1;
    }

    const struct image_section_header *shdrs = (const struct image_section_header *)shdr_stream->data;
    if (section_offset > shdrs[section_idx].misc.virtual_size) {
        /* Malformed PDB or invalid offset - address not in section */
        puts("d");
        return -1;
    }

    /* TODO: Check for overflow */
    *rva = shdrs[section_idx].virtual_address + section_offset;
    return 0;
}


const struct symbol * pdb_lookup_public_symbol(const struct pdb *pdb, const char *name)
{
    //uint16_t global_symbols_idx = PDB_PRIVATE(pdb)->dbi_header->global_stream_index;
    uint16_t global_symbols_idx = PDB_PRIVATE(pdb)->dbi_header->public_stream_index;
    if (global_symbols_idx >= pdb->nr_streams) {
        /* Not enough streams */
        return NULL;
    }

    const struct stream *stream = &pdb->streams[global_symbols_idx];

    // TODO: Parse the hash table

    return NULL;
}


const struct symbol *pdb_enum_public_symbols(const struct pdb *pdb, const struct symbol *prev)
{
    assert(pdb != NULL);

    uint16_t symbols_stream_idx = PDB_PRIVATE(pdb)->dbi_header->sym_record_stream;
    if (symbols_stream_idx >= pdb->nr_streams) {
        /* Not enough streams */
        free((void *)prev);
        return NULL;
    }

    uint32_t next = 0;
    const struct stream *stream = &pdb->streams[symbols_stream_idx];

    if (prev != NULL) {
        uint32_t prev_index = prev->index;
        free((void *)prev);

        if (prev_index + sizeof(uint16_t) > stream->size) {
            /* Stream too short */
            return NULL;
        }

        uint16_t sym_size = *(uint16_t *)(stream->data + prev_index);
        next = prev_index + sizeof(uint16_t) + sym_size;
    }

    while (next + sizeof(struct cv_record_header) <= stream->size) {
        const struct cv_record_header *cvhdr = (const struct cv_record_header *)(stream->data + next);
        if (next + sizeof(uint16_t) + cvhdr->record_len > stream->size) {
            /* Stream too short */
            return NULL;
        }

        if (cvhdr->record_kind == S_PUB32) {
            const struct cv_public_symbol *cvsym = (const struct cv_public_symbol *)cvhdr;

            uint32_t sym_rva = 0;
            int err = lookup_rva(pdb, cvsym->section_idx, cvsym->section_offset, &sym_rva);
            if (err < 0) {
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
                 */
                fprintf(stderr, "WARNING: Invalid section index for symbol: %s idx=%d offset=0x%x\n",
                    cvsym->mangled_name, cvsym->section_idx, cvsym->section_offset);
                // return NULL;
            }

            struct symbol *sym = calloc(1, sizeof(struct symbol) + strlen(cvsym->mangled_name) + 1);
            if (sym == NULL) {
                return NULL;
            }

            sym->index = next;
            sym->is_code = (cvsym->flags & CVPSF_CODE) != 0;
            sym->is_function = (cvsym->flags & CVPSF_FUNCTION) != 0;
            sym->is_managed = (cvsym->flags & CVPSF_MANAGED) != 0;
            sym->is_msil = (cvsym->flags & CVPSF_MSIL) != 0;
            sym->rva = sym_rva;
            strcpy(sym->name, cvsym->mangled_name);

            return sym;
        }

        next += sizeof(uint16_t) + cvhdr->record_len;
    }

    /* End of stream - no more symbols */
    return NULL;
}


const struct pdb * pdb_load(const void *pdbdata, size_t len)
{
    assert(pdbdata != NULL);
    assert(len > 0);

    struct pdb *pdb = calloc(1, sizeof(struct pdb) + sizeof(struct pdb_private));
    if (pdb == NULL) {
        return NULL;
    }

    int err = extract_streams(pdbdata, len, &pdb->streams, &pdb->nr_streams);
    if (err < 0) {
        return NULL;
    }

    err = parse_pdb_stream(&pdb->streams[PDB_STREAM_IDX], &pdb->age, pdb->guid.bytes);
    if (err < 0) {
        goto err_close_pdb;
    }

    err = parse_dbi_stream(pdb, &pdb->streams[DBI_STREAM_IDX], &PDB_PRIVATE(pdb)->dbi_header);
    if (err < 0) {
        goto err_close_pdb;
    }

    /* TODO: Parse TPI stream */
    /* TODO: parse IPI stream */

    return pdb;

err_close_pdb:
    pdb_close(pdb);
    return NULL;
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
