#ifndef PDB_PRIVATE_H
#define PDB_PRIVATE_H

#include "dbistream.h"
#include "pdb.h"

struct pdb_private {
    /* DBI stream info - this pointer is cached because it contains useful stream indices */
    const struct dbi_stream_header *dbi_header;

    /* TODO: Is this still necessary? */
    const struct debug_header *dbg_header;
};

struct symbol_private {
    /* Index into the symbol record stream */
    uint32_t index;
};

#define PDB_PRIVATE(pdb) ((struct pdb_private *)(((char *)(pdb)) + sizeof(struct pdb)))
#define SYMBOL_PRIVATE(sym) ((struct symbol_private *)(((char *)(sym)) + sizeof(struct symbol)))

#endif // PDB_PRIVATE_H
