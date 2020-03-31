#include <stdint.h>

enum {
    gsi_hash_sc_impv_v70 = 0xeffe0000 + 19990810,   // 0xf12f091a
};

struct gsi_stream_header {
    uint32_t sym_hash_size;
    uint32_t addr_map_size;
    uint32_t nr_thunks;
    uint32_t thunk_size;
    uint32_t thunk_table_isect;
    uint32_t thunk_table_offset;
    uint32_t nr_sections;
};

#define NR_HASH_BUCKETS 4096

struct gsi_hash_header {
    uint32_t ver_signature;
    uint32_t ver_hdr;
    uint32_t cb_hr;
    uint32_t cb_buckets;
};

/* Microsoft refers to this struct as HRFile */
struct gsi_hashrec {
    uint32_t offset;
    uint32_t c_ref;
};

/* Microsoft refers to this struct as HROffsetCalc */
struct gsi_hashrec_offset_calc {
    int32_t pnext;
    int32_t psym;
    int32_t c_ref;
};
