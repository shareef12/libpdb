#ifndef PDB_CODEVIEW_H
#define PDB_CODEVIEW_H

#include <stdint.h>

#define S_PUB32 0x110e

enum cv_public_symbol_flags {
    CVPSF_CODE = 1,
    CVPSF_FUNCTION = 2,
    CVPSF_MANAGED = 4,
    CVPSF_MSIL = 8,
};

struct cv_record_header {
    uint16_t record_len;  // Record length, not including this 2 byte field.
    uint16_t record_kind; // Record kind enum.
} __attribute__((packed));

struct cv_public_symbol {
    struct cv_record_header header;
    uint32_t flags;
    uint32_t section_offset;
    uint16_t section_idx;
    const char mangled_name[];
} __attribute__((packed));

#endif // PDB_CODEVIEW_H
