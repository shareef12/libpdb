/**
 * This module contains code related to finding a PDB file in a local cache or
 * a remote symbol server.
 *
 * The search behavior implemented by Microsoft's symchk utility is actually
 * quite complex, and the specification for a symbol path is not well defined.
 * As such, there are a few edge cases where our behavior differs from that of
 * symchk. In the common cases, the search behavior implemented here should be
 * sufficient.
 *
 * Below is an attempt at enumerating the observed and expected behavior for
 * symbol searching.
 *
 * PDB Metadata
 * ============
 * Windows PEs that have debug information typically include the full path to a
 * PDB file the rdata section. They will typically have a debug directory in
 * the optional header that points to a codeview structure elsewhere in the
 * image. This codeview structure contains the path to the PDB file, along with
 * a GUID uniquely identifying the PDB and the age of the PDB. The name of the
 * PDB file, along with the GUID and age, are typically used to determine
 * complete search paths along the symbol path.
 *
 * Anatomy of a symbol path
 * ========================
 * Symbol path "parts" are strings separated by semicolons. Each "part" is
 * optionally prefixed with cache* or srv*. Parts that do not have a prefix are
 * considered to be a file system path or UNC path to a symbol share. Parts
 * that have a cache* or srv* prefix are considered to be symbol stores, and
 * have a different directory layout from standard unprefixed locations.
 *
 * NOTE: libpdb does not support SMB share lookups. To perform a lookup in a
 * symbol share, mount the share and specify the mount location as a local
 * path.
 *
 * Unprefixed symbol path parts
 * ----------------------------
 * When an unprefixed symbol path part is specified, symchk will examine the
 * following locations for a PDB that matches the specified image:
 *
 *  1. <sympath-part>/<pdbname>.pdb
 *  2. <sympath-part>/<image-ext>/<pdbname>.pdb
 *  3. <sympath-part>/symbols/<image-ext>/<pdbname>.pdb
 *
 * For instance, if the sympath were "/tmp/symbols", and we were searching for
 * a PDB matching "ntoskrnl.exe" with an embedded pdb basename of
 * "ntkrnlmp.pdb" in the debug directory, symchk will search the following
 * paths:
 *
 *  1. /tmp/symbols/ntkrnlmp.pdb
 *  2. /tmp/symbols/exe/ntkrnlmp.pdb
 *  3. /tmp/symbols/symbols/exe/ntkrnlmp.pdb
 *
 * These locations are never used as cache locations, and are typically only
 * used as quick workarounds for a user to specify a directory containing a
 * manually-curated collection of PDB files.
 *
 * NOTE: If a magic file named "pingme.txt" exists in the directory specified
 * by an unprefixed symbol path part, symchk will not follow the search rules
 * above, and instead search it as if it were a cache (see "cache*" prefix
 * below). When this is the case, it is only treated as a cache when searching
 * for a pdb file - no files are written to it.
 *
 * "cache*" prefixed symbol path parts
 * -----------------------------------
 * Symbol path parts prefixed with "cache*" indicate a local cache. Since it is
 * considered a symbol store cache, it has a different directory structure and
 * search behavior from unprefixed local paths.
 *
 * The structure of a cache directory is organized by pdb file name, with
 * subdirectories for each guid and age combination. When searching for a PDB
 * file, symchk checks the following paths:
 *
 *  1. <sympath-part>/<pdbname>.pdb/<guid><age>/<pdbname>.pdb
 *  2. <sympath-part>/<pdbname>.pdb/<guid><age>/<pdbname>.pd_
 *  3. <sympath-part>/<pdbname>.pdb/<guid><age>/file.ptr
 *
 * The first lookup is self-evident. The second is typically a compressed
 * version of the same PDB. The final lookup allows for one level of
 * indirection. The "file.ptr" file for a PDB contains an ascii pathname or URL
 * indicating the location of the actual PDB file. All non-numeric characters
 * are stripped from the guid.
 *
 * NOTE: libpdb differs from symchk for "cache*" lookups in two ways:
 *  1. symchk considers everything after "cache*" to be a single path, while
 *     libpdb splits the remainder on the "*" character, and considers each
 *     part a new cache location.
 *  2. libpdb does not support compressed PDB file retrieval through the ".pd_"
 *     lookups.
 *
 * "srv*" prefixed symbol path parts
 * ---------------------------------
 * Symbol path parts prefixed with "srv*" indicate a local or remote symbol
 * store location. Unlike "cache*" locations, symchk will split everything
 * after the "srv*" prefix on the "*" character, and interpret all paths except
 * for the last one as local cache locations. Lookup behavior for each of these
 * parts is identical to "cache*" lookups, except the last component can be a
 * URL, local path, or SMB share.
 *
 * Sympath cache behavior
 * ======================
 * When retrieving a symbol file, symchk will try to cache the PDB to all cache
 * locations specified earlier in the symbol path. For instance, if the PDB
 * file was downloaded from a symbol store specified in the 3rd symbol path
 * part (a "srv*" prefix), the PDB file will be cached to any cache locations
 * that were specified in the first or second parts.
 *
 * A non-intuitive fact to keep in mind is that even though a cache location
 * specified with a "srv*" prefix may appear to be solely associated with that
 * "srv*" location, it is also associated with all paths that appear to the
 * right of it in the symbol path. For instance, if a PDB was found in the
 * final "srv*" part of the below symbol path, the PDB would be cached to
 * "C:\symbols1", "C:\symbols2", and "C:\symbols3".
 *
 * "cache*C:\symbols1;srv*C:\symbols2*http://nonexistent.com/;srv*C:\symbols3*http://pdb-location.com/"
 *
 * If there are no suitable cache locations, symchk will try to find a suitable
 * default cache location (typically in %appdata%). libpdb will try to find the
 * user's cache directory and store symbols in a "symbols" subdirectory
 * (typically "~/.cache/symbols/").
 */

#include "pdb.h"

#include "pdbint.h"
#include "pe.h"
#include "sysdep.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 32 hex characters */
#define GUID_STR_SIZE (32)

/* Maximum size of a GUID and a uint32_t value concatenated */
#define MAX_GUID_AGE_STR_SIZE (GUID_STR_SIZE + 10)

struct image_pdb_info {
    const char *pdb_pathname; /* The PDB path embedded in the image */
    const char *pdb_basename; /* The basename of the image without an extension */
    struct guid guid;         /* The PDB guid */
    uint32_t age;             /* The PDB age */
};

struct found_pdb_info {
    const unsigned char *pdb_data;
    size_t pdb_data_len;
};

enum sympath_part_type {
    SPT_LOCAL,
    SPT_LOCAL_CACHE,
    SPT_SYMSRV,
};

struct sympath_part {
    enum sympath_part_type type;
    const char *location;
};

struct parsed_sympath {
    size_t nr_parts;
    struct sympath_part parts[];
};

static bool is_url(const char *path)
{
    return strncmp(path, "http://", 7) == 0 || strncmp(path, "https://", 8) == 0;
}

static int snprintf_guid(char *str, size_t size, const struct guid *guid)
{
    return snprintf(
        str, size, "%08X%04hX%04hX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", guid->data1,
        guid->data2, guid->data3, guid->data4[0], guid->data4[1], guid->data4[2], guid->data4[3],
        guid->data4[4], guid->data4[5], guid->data4[6], guid->data4[7]);
}

static int parse_symbol_path(const char *sympath, struct parsed_sympath **parsed_sympath)
{
    char *sp = pdb_strdup(sympath);
    if (sp == NULL) {
        return -1;
    }

    /* Pass 1: Count the number of sympath parts we need to allocate */
    size_t nr_parts = 0;

    char *c;
    char *part = pdb_strtok_r(sp, "*;", &c);
    while (part != NULL) {
        nr_parts++;
        part = pdb_strtok_r(NULL, "*;", &c);
    }

    pdb_free(sp);

    /* Allocate a single buffer large enough for all the parsed sympath structures */
    size_t sympath_len = strlen(sympath);
    size_t req_sz = sizeof(struct parsed_sympath);
    req_sz += sizeof(struct sympath_part) * nr_parts;
    req_sz += sympath_len + 1;

    struct parsed_sympath *parsed_sp = pdb_malloc(req_sz);
    if (parsed_sp == NULL) {
        return -1;
    }

    parsed_sp->nr_parts = 0;
    sp = (char *)(parsed_sp->parts + nr_parts);
    strncpy(sp, sympath, sympath_len + 1);

    /* Pass 2: Parse and populate parsed_sp */
    part = pdb_strtok_r(sp, ";", &c);
    struct sympath_part *sp_part = parsed_sp->parts;

    while (part != NULL) {
        /* Determine the type for this sympath part based on the prefix */
        if (strncmp(part, "srv*", 4) == 0) {
            part += 4;
        }
        else if (strncmp(part, "cache*", 6) == 0) {
            part += 6;
        }
        else {
            if (sys_is_absolute_path(part)) {
                sp_part->type = SPT_LOCAL;
                sp_part->location = part;
                sp_part++;
                goto parse_next_part;
            }
        }

        /* This is a srv* or cache* part. Enumerate locations. */
        char *c2;
        char *location = pdb_strtok_r(part, "*", &c2);
        while (location != NULL) {
            if (is_url(location)) {
                sp_part->type = SPT_SYMSRV;
                sp_part->location = location;
                sp_part++;
            }
            else if (sys_is_absolute_path(location)) {
                sp_part->type = SPT_LOCAL_CACHE;
                sp_part->location = location;
                sp_part++;
            }
            else {
                /* Skip over invalid locations */
            }

            location = pdb_strtok_r(NULL, "*", &c2);
        }

    parse_next_part:
        part = pdb_strtok_r(NULL, ";", &c);
    }

    parsed_sp->nr_parts = sp_part - parsed_sp->parts;
    *parsed_sympath = parsed_sp;

    return 0;
}

static void free_symbol_path(struct parsed_sympath *parsed_sympath)
{
    pdb_free(parsed_sympath);
}

static int vread_file_from_path(
    unsigned char **data, size_t *length, const char *pathfmt, va_list ap)
{
    va_list aq;

    va_copy(aq, ap);
    char *pathname = pdb_vasprintf(pathfmt, aq);
    va_end(aq);

    if (pathname == NULL) {
        return false;
    }

    if (is_url(pathname)) {
        if (sys_download_file(pathname, data, length) < 0) {
            goto err_free_path;
        }
    }
    else {
        if (sys_read_file(pathname, data, length) < 0) {
            goto err_free_path;
        }
    }

    pdb_free(pathname);
    return 0;

err_free_path:
    pdb_free(pathname);

    return -1;
}

/**
 * Read a file from a file path or URL.
 *
 * Callers should free the returned data with pdb_free
 */
static int read_file_from_path(unsigned char **data, size_t *length, const char *pathfmt, ...)
{
    va_list ap;

    va_start(ap, pathfmt);
    int retval = vread_file_from_path(data, length, pathfmt, ap);
    va_end(ap);

    return retval;
}

/**
 * Check to see if the PDB at pathname has the specified guid and age.
 */
static bool try_load_pdb_from_path(
    struct pdb_context *ctx,
    struct image_pdb_info *imageinfo,
    struct found_pdb_info *pdbinfo,
    const char *pathfmt,
    ...)
{
    va_list ap;
    unsigned char *pdbdata = NULL;
    size_t pdbdata_len = 0;

    va_start(ap, pathfmt);
    int retval = vread_file_from_path(&pdbdata, &pdbdata_len, pathfmt, ap);
    va_end(ap);

    if (retval < 0 || pdbdata == NULL || pdbdata_len == 0) {
        return false;
    }

    /* Parse the PDB file and check to see if it's a match */
    pdb_reset_context(ctx);
    if (pdb_load(ctx, pdbdata, pdbdata_len) < 0) {
        goto err_free_pdbdata;
    }

    /* The PDB is a match if the guid and age are the same */
    if (memcmp(&imageinfo->guid, pdb_get_guid(ctx), sizeof(struct guid)) == 0 &&
        imageinfo->age == pdb_get_age(ctx)) {
        pdbinfo->pdb_data = pdbdata;
        pdbinfo->pdb_data_len = pdbdata_len;
        return true;
    }

    pdb_reset_context(ctx);

err_free_pdbdata:
    pdb_free(pdbdata);
    return false;
}

/**
 * Check for a PDB file in a symbol path component.
 *
 * Symbol pat components consist of a "srv*" prefix, followed by an optional
 * cache path, and finally the location of the store, which can be a filesystem
 * path or an http or https URL.
 *
 * Callers should free the returned pathname.
 */
static bool try_load_pdb_from_symsrv(
    struct pdb_context *ctx,
    const char *symstore,
    struct image_pdb_info *imageinfo,
    struct found_pdb_info *pdbinfo)
{
    char sguid[GUID_STR_SIZE + 1] = {0};
    snprintf_guid(sguid, sizeof(sguid), &imageinfo->guid);

    /* Check <cachepath> / <pdbname> / <guid><age> / <pdbname> */
    if (try_load_pdb_from_path(
            ctx, imageinfo, pdbinfo, "%s/%s/%s%u/%s", symstore, imageinfo->pdb_basename, sguid,
            imageinfo->age, imageinfo->pdb_basename)) {
        return true;
    }

    /* TODO: Check for compressed PDB at <cachepath> / <pdbname> / <guid><age> / <pdbname>.pd_ */

    /* Check <cachepath> / <pdbname> / <guid><age> / file.ptr */
    char *file_ptr = NULL;
    size_t file_ptr_len = 0;
    if (read_file_from_path(
            (unsigned char **)&file_ptr, &file_ptr_len, "%s/%s/%s%u/file.ptr", symstore,
            imageinfo->pdb_basename, sguid, imageinfo->age) < 0) {
        return false;
    }

    bool success = try_load_pdb_from_path(ctx, imageinfo, pdbinfo, file_ptr);
    pdb_free(file_ptr);

    return success;
}

static bool try_load_pdb_from_local_path(
    struct pdb_context *ctx,
    const char *symstore,
    struct image_pdb_info *imageinfo,
    struct found_pdb_info *pdbinfo)
{
    /*
     * Check to see if a magic "pingme.txt" file exists. If one does, this
     * symstore is actually a cache directory. When this is the case, we need
     * to alter our search paths.
     */
    const char *pathname = pdb_asprintf("%s/pingme.txt", symstore);
    if (pathname == NULL) {
        return false;
    }

    bool is_symsrv_cache = sys_is_file(pathname);
    pdb_free((void *)pathname);
    if (is_symsrv_cache) {
        return try_load_pdb_from_symsrv(ctx, symstore, imageinfo, pdbinfo);
    }

    /* Check for various local paths */
    if (try_load_pdb_from_path(
            ctx, imageinfo, pdbinfo, "%s/%s", symstore, imageinfo->pdb_basename)) {
        return true;
    }

    /*
     * Normally, symchk.exe will use the image's extension as a directory name.
     * However, we don't know what the extension was since the caller handles
     * all file IO for us. It might be slightly less efficient, but we just try
     * all common extensions instead.
     */
    static const char *known_extensions[] = {"dll", "exe", "sys"};
    for (size_t i = 0; i < ARRAY_SIZE(known_extensions); i++) {
        if (try_load_pdb_from_path(
                ctx, imageinfo, pdbinfo, "%s/%s/%s", symstore, known_extensions[i],
                imageinfo->pdb_basename)) {
            return true;
        }
    }

    for (size_t i = 0; i < ARRAY_SIZE(known_extensions); i++) {
        return try_load_pdb_from_path(
            ctx, imageinfo, pdbinfo, "%s/symbols/%s/%s", symstore, known_extensions[i],
            imageinfo->pdb_basename);
    }

    return false;
}

/**
 * Search the symbol path for the specified PDB file.
 *
 * Returns the index in the sympath where the PDB file was found.
 */
static int load_pdb_from_sympath(
    struct pdb_context *ctx,
    struct parsed_sympath *sympath,
    struct image_pdb_info *imageinfo,
    struct found_pdb_info *pdbinfo)
{
    for (size_t i = 0; i < sympath->nr_parts; i++) {
        const struct sympath_part *part = &sympath->parts[i];
        switch (part->type) {
        case SPT_LOCAL:
            if (try_load_pdb_from_local_path(ctx, part->location, imageinfo, pdbinfo)) {
                return i;
            }
            break;

        case SPT_LOCAL_CACHE:
        case SPT_SYMSRV:
            if (try_load_pdb_from_symsrv(ctx, part->location, imageinfo, pdbinfo)) {
                return i;
            }
            break;

        default:
            /* BUG - Should never get here */
            return -1;
        }
    }

    /* No PDB found */
    return -1;
}

/**
 * Copy the found PDB's contents to all cache locations in the sympath up to
 * the part where it was found.
 *
 * Return the pathname to a cached on-disk copy of the PDB file. If the sympath
 * specifies multiple cache locations, this function returns the first cache
 * location in the sympath where this PDB was successfully stored.
 */
static void copy_pdb_to_sympath_caches(
    struct parsed_sympath *sympath,
    size_t found_idx,
    struct image_pdb_info *imageinfo,
    struct found_pdb_info *pdbinfo)
{
    char sguid[GUID_STR_SIZE + 1] = {0};
    snprintf_guid(sguid, sizeof(sguid), &imageinfo->guid);

    for (size_t i = found_idx + 1; i > 0; i--) {
        const struct sympath_part *part = &sympath->parts[i - 1];
        if (part->type != SPT_LOCAL_CACHE) {
            continue;
        }

        /*
         * Write the PDB to <cachepath> / <pdbname> / <guid><age> / <pdbname>
         * if it doesn't already exist.
         */
        char *pathname = pdb_asprintf(
            "%s/%s/%s%u/%s", part->location, imageinfo->pdb_basename, sguid, imageinfo->age,
            imageinfo->pdb_basename);
        if (pathname == NULL) {
            continue;
        }

        if (!sys_is_file(pathname)) {
            (void)sys_write_file(pathname, pdbinfo->pdb_data, pdbinfo->pdb_data_len);
        }
        pdb_free(pathname);
    }
}

static int rva_to_offset(
    uint32_t rva, const struct image_section_header *sections, uint16_t nr_sections, off_t *offset)
{
    for (uint16_t i = 0; i < nr_sections; i++) {
        const struct image_section_header *scn = &sections[i];
        if (scn->virtual_address <= rva && rva < scn->virtual_address + scn->misc.virtual_size) {
            off_t scn_offset = rva - scn->virtual_address;
            if (scn_offset >= scn->size_of_raw_data) {
                /*
                 * rva refers to an address that is not in the section's raw
                 * data. It does not have a file-based counterpart.
                 */
                return -1;
            }
            *offset = scn->pointer_to_raw_data + scn_offset;
            return 0;
        }
    }

    /* No conversion found */
    return -1;
}

static int offset_to_rva(
    uint32_t offset,
    const struct image_section_header *sections,
    uint16_t nr_sections,
    uint32_t *rva)
{
    for (uint16_t i = 0; i < nr_sections; i++) {
        const struct image_section_header *scn = &sections[i];
        if (scn->pointer_to_raw_data <= offset &&
            offset < scn->pointer_to_raw_data + scn->size_of_raw_data) {
            uint32_t scn_offset = offset - scn->pointer_to_raw_data;
            *rva = scn->virtual_address + scn_offset;
            return 0;
        }
    }

    return -1;
}

static int get_image_pdb_info(
    const unsigned char *imagedata, size_t imagelen, bool mapped, struct image_pdb_info *imageinfo)
{
    if (imagelen < sizeof(struct image_dos_header)) {
        /* Too small for DOS header */
        return -1;
    }

    /* Get the DOS header */
    struct image_dos_header *doshdr = (struct image_dos_header *)imagedata;
    if (doshdr->e_magic != IMAGE_DOS_SIGNATURE) {
        /* Invalid signature */
        return -1;
    }

    /* Get the NT headers */
    off_t nthdrs_offset = doshdr->e_lfanew;
    if (imagelen - nthdrs_offset < sizeof(struct image_nt_headers)) {
        /* Too small for NT headers */
        return -1;
    }

    struct image_nt_headers *nthdrs = (struct image_nt_headers *)(imagedata + nthdrs_offset);
    if (nthdrs->signature != IMAGE_NT_SIGNATURE) {
        /* Invalid signature */
        return -1;
    }

    /* Get the debug data directory and section headers (for RVA -> Offset conversion) */
    struct image_data_directory *dbgdir = NULL;

    if (nthdrs->file_header.machine == IMAGE_FILE_MACHINE_I386) {
        if (imagelen - nthdrs_offset < sizeof(struct image_nt_headers32)) {
            /* Too small for full NT headers */
            return -1;
        }

        struct image_nt_headers32 *nthdrs32 = (struct image_nt_headers32 *)nthdrs;
        dbgdir = &nthdrs32->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }
    else if (nthdrs->file_header.machine == IMAGE_FILE_MACHINE_AMD64) {
        if (imagelen - nthdrs_offset < sizeof(struct image_nt_headers64)) {
            /* Too small for full NT headers */
            return -1;
        }

        struct image_nt_headers64 *nthdrs64 = (struct image_nt_headers64 *)nthdrs;
        dbgdir = &nthdrs64->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }
    else {
        /* Unsupported architecture */
        return -1;
    }

    /*
     * Get the section headers so we can translate between RVAs and offsets.
     *
     * If the file is mapped, we need to translate offsets in the debug
     * directory to RVAs. If the file is not mapped, we need to translate RVAs
     * to offsets in order to find the debug directory.
     */
    uint16_t nr_sections = nthdrs->file_header.number_of_sections;
    off_t shdrs_offset = nthdrs_offset + sizeof(struct image_nt_headers) +
        nthdrs->file_header.size_of_optional_header;
    if (imagelen - shdrs_offset < sizeof(struct image_section_header) * nr_sections) {
        /* Too small for all section headers */
        return -1;
    }
    struct image_section_header *sections =
        (struct image_section_header *)(imagedata + shdrs_offset);

    /* Get the debug directory data offset */
    off_t dbg_offset = 0;
    if (mapped) {
        dbg_offset = dbgdir->virtual_address;
    }
    else {
        int err = rva_to_offset(dbgdir->virtual_address, sections, nr_sections, &dbg_offset);
        if (err < 0) {
            return -1;
        }
    }

    /* Get the debug directory */
    size_t nr_dbgents = dbgdir->size / sizeof(struct image_debug_directory);
    if (imagelen - dbg_offset < dbgdir->size ||
        dbgdir->size < sizeof(struct image_debug_directory)) {
        /* Too small for debug directory contents */
        return -1;
    }

    /* Search through debug directory entries for PDB 7.0 codeview entries */
    struct image_debug_directory *dbgents =
        (struct image_debug_directory *)(imagedata + dbg_offset);
    for (size_t i = 0; i < nr_dbgents; i++) {
        struct image_debug_directory *dbg = &dbgents[i];
        if (dbg->type != IMAGE_DEBUG_TYPE_CODEVIEW) {
            /* Unsupported debug information format */
            continue;
        }

        /* Get the debug codeview information */
        off_t cvinfo_offset = 0;
        if (mapped) {
            uint32_t cvinfo_rva = 0;
            int err = offset_to_rva(dbg->pointer_to_raw_data, sections, nr_sections, &cvinfo_rva);
            if (err < 0) {
                return -1;
            }
            cvinfo_offset = cvinfo_rva;
        }
        else {
            cvinfo_offset = dbg->pointer_to_raw_data;
        }

        if (imagelen - cvinfo_offset < dbg->size_of_data ||
            dbg->size_of_data < sizeof(struct cv_info_pdb70)) {
            /* Too small for codeview information */
            continue;
        }

        struct cv_info_pdb70 *cvinfo = (struct cv_info_pdb70 *)(imagedata + cvinfo_offset);
        if (cvinfo->cv_signature != CV_SIGNATURE_RSDS) {
            /* Unsupported codeview version */
            continue;
        }

        /*
         * Validate that the entire pdb file name fits in the codeview structure
         * and is null terminated.
         */
        size_t max_pdbname_sz = dbg->size_of_data - offsetof(struct cv_info_pdb70, pdb_file_name);
        if (strnlen(cvinfo->pdb_file_name, max_pdbname_sz) == max_pdbname_sz) {
            /* pdb_file_name is not null-terminated */
            return -1;
        }

        /* Extract the relevant information from the codeview section */
        char *pdb_pathname = pdb_strdup(cvinfo->pdb_file_name);
        if (pdb_pathname == NULL) {
            return -1;
        }

        char *pdb_basename = sys_basename(pdb_pathname);
        if (pdb_basename == NULL) {
            pdb_free(pdb_pathname);
            return -1;
        }

        imageinfo->pdb_pathname = pdb_pathname;
        imageinfo->pdb_basename = pdb_basename;
        memcpy(&imageinfo->guid, &cvinfo->signature, sizeof(imageinfo->guid));
        imageinfo->age = cvinfo->age;

        return 0;
    }

    return -1;
}

/**
 * Try to get the sympath from the following locations:
 *  1. An explicit user-specified symbol path
 *  2. A symbol path specified by the _NT_SYMBOL_PATH environment variable
 *  3. The default symbol cache location.
 *
 * Callers should free the returned path with pdb_free.
 */
static const char *get_sympath_for_search(struct pdb_context *ctx)
{
    const char *sympath = ctx->symbol_path;
    if (sympath != NULL) {
        return pdb_strdup(sympath);
    }

    sympath = getenv("_NT_SYMBOL_PATH");
    if (sympath != NULL) {
        return pdb_strdup(sympath);
    }

    return "";
}

static void free_image_pdb_info(struct image_pdb_info *imageinfo)
{
    if (imageinfo->pdb_pathname != NULL) {
        pdb_free((void *)imageinfo->pdb_pathname);
    }
    if (imageinfo->pdb_basename != NULL) {
        pdb_free((void *)imageinfo->pdb_basename);
    }
    memset(imageinfo, 0, sizeof(struct image_pdb_info));
}

const char *pdb_get_symbol_path(void *context)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, NULL);

    return ctx->symbol_path;
}

void pdb_set_symbol_path(void *context, const char *symbol_path)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, /* no-retval */);

    ctx->symbol_path = symbol_path;
}

int pdb_append_symbol_path(void *context, const char *symbol_path_part)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, -1);

    size_t old_sympath_len = strlen(ctx->symbol_path);
    size_t part_len = strlen(symbol_path_part);

    size_t new_len = old_sympath_len + 1 + part_len + 1;
    char *new_sympath = pdb_malloc(new_len);
    if (new_sympath == NULL) {
        ctx->error = EPDB_ALLOCATION_FAILURE;
        return -1;
    }

    strncpy(new_sympath, ctx->symbol_path, old_sympath_len);
    strncat(new_sympath, ";", 2);
    strncat(new_sympath, symbol_path_part, part_len);

    pdb_free((void *)ctx->symbol_path);
    ctx->symbol_path = new_sympath;

    return 0;
}

int pdb_load_from_sympath(
    void *context, const void *image, size_t length, bool mapped, bool check_pdbpath)
{
    struct pdb_context *ctx = (struct pdb_context *)context;

    PDB_ASSERT_CTX_NOT_NULL(ctx, -1);
    PDB_ASSERT_PARAMETER(ctx, -1, image != NULL && length > 0);

    int retval = -1;
    struct image_pdb_info imageinfo = {0};
    struct found_pdb_info pdbinfo = {0};
    struct parsed_sympath *sympath = NULL;

    /* Parse the image to get embedded pdb path, guid, and age */
    if (get_image_pdb_info(image, length, mapped, &imageinfo) < 0) {
        goto out_free_resources;
    }

    /*
     * Check the pdbpath from exe. If we find it here, don't copy it to any
     * caches.
     */
    if (check_pdbpath) {
        if (try_load_pdb_from_path(ctx, &imageinfo, &pdbinfo, imageinfo.pdb_pathname)) {
            retval = 0;
            goto out_free_resources;
        }
    }

    /* Parse and check the sympath for the requested PDB */
    const char *sympath_str = get_sympath_for_search(ctx);
    if (sympath_str == NULL) {
        return -1;
    }

    if (parse_symbol_path(sympath_str, &sympath) < 0) {
        goto out_free_resources;
    }

    int found_idx = load_pdb_from_sympath(ctx, sympath, &imageinfo, &pdbinfo);
    if (found_idx < 0) {
        ctx->error = EPDB_NOT_FOUND;
        goto out_free_resources;
    }

    copy_pdb_to_sympath_caches(sympath, found_idx, &imageinfo, &pdbinfo);
    retval = 0;

out_free_resources:
    free_image_pdb_info(&imageinfo);
    free_symbol_path(sympath);

    if (pdbinfo.pdb_data != NULL) {
        pdb_free((void *)pdbinfo.pdb_data);
    }

    return retval;
}
