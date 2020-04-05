#ifndef PDB_PDBSTREAM_H
#define PDB_PDBSTREAM_H

#include <stdint.h>

enum pdb_stream_version {
    PSV_VC2 = 19941610,
    PSV_VC4 = 19950623,
    PSV_VC41 = 19950814,
    PSV_VC50 = 19960307,
    PSV_VC98 = 19970604,
    PSV_VC70Dep = 19990604,
    PSV_VC70 = 20000404,
    PSV_VC80 = 20030901,
    PSV_VC110 = 20091201,
    PSV_VC140 = 20140508,
};

struct pdb_stream_header {
    uint32_t version;
    uint32_t signature;
    uint32_t age;
    unsigned char unique_id[16];
} __attribute__((packed));

#endif  // PDB_PDBSTREAM_H
