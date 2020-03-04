#ifndef PDB_PRIVATE_H
#define PDB_PRIVATE_H

#include "dbistream.h"

struct pdb_private {
    /* DBI stream info - this pointer is cached because it contains useful stream indices */
    const struct dbi_stream_header *dbi_header;

    /* Section map - this object is used to convert symbol offsets to RVAs */
    const struct section_map_header *sm_header;
    const struct debug_header *dbg_header;
};

#define PDB_PRIVATE(pdb) ((struct pdb_private *)(((char *)(pdb)) + sizeof(struct pdb)))

#endif // PDB_PRIVATE_H