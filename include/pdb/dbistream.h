#ifndef PDB_DBISTREAM_H
#define PDB_DBISTREAM_H

#include <stdint.h>

enum dbi_stream_version {
    DSV_VC41 = 930803,
    DSV_V50 = 19960307,
    DSV_V60 = 19970606,
    DSV_V70 = 19990903,
    DSV_V110 = 20091201
};

/*
struct dbi_build_number {
    uint16_t minor_version : 8;
    uint16_t major_version : 7;
    uint16_t new_version_format : 1;
}
*/

struct dbi_stream_header {
    int32_t version_signature;
    uint32_t version_header;
    uint32_t age;
    uint16_t global_stream_index;
    uint16_t build_number;
    uint16_t public_stream_index;
    uint16_t pdb_dll_version;
    uint16_t sym_record_stream;
    uint16_t pdb_dll_rbld;
    uint32_t mod_info_size;
    uint32_t section_contribution_size;
    uint32_t section_map_size;
    uint32_t source_info_size;
    uint32_t type_server_map_size;
    uint32_t mfc_type_server_index;
    uint32_t optional_dbg_header_size;
    uint32_t ec_substream_size;
    uint16_t flags;
    uint16_t machine;
    uint32_t padding;
} __attribute__((packed));

enum section_map_entry_flags {
    SMEF_READ = 1,
    SMEF_WRITE = 2,
    SMEF_EXECUTE = 4,
    SMEF_ADDRESS_IS_32BIT = 8,
    SMEF_IS_SELECTOR = 0x100,
    SMEF_IS_ABSOLUTE_ADDRESS = 0x200,
    SMEF_IS_GROUP = 0x400,
};

struct section_map_entry {
    uint16_t flags;
    uint16_t ovl;
    uint16_t group;
    uint16_t frame;
    uint16_t section_name;
    uint16_t class_name;
    uint32_t offset;
    uint32_t section_length;
} __attribute__((packed));

struct section_map_header {
    uint16_t count;
    uint16_t log_count;
    const struct section_map_entry entries[];
} __attribute__((packed));

#define DBI_NUM_DEBUG_HEADER_STREAMS 11

struct debug_header {
    union {
        struct {
            uint16_t fpo_data_stream_index;
            uint16_t exception_data_stream_index;
            uint16_t fixup_data_stream_index;
            uint16_t omap_to_source_data_stream_index;
            uint16_t omap_from_source_data_stream_index;
            uint16_t section_header_data_stream_index;
            uint16_t token_rid_map_stream_index;
            uint16_t xdata_stream_index;
            uint16_t pdata_stream_index;
            uint16_t new_fpo_data_stream_index;
            uint16_t original_section_header_data_stream_index;
        } __attribute__((packed));
        uint16_t streams[DBI_NUM_DEBUG_HEADER_STREAMS];
    };
} __attribute__((packed));

#endif  // PDB_DBISTREAM_H
