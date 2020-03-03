#include <stdio.h>
#include <stdlib.h>

#include "pdb.h"


int main(int argc, char **argv)
{
    const struct pdb *pdb = pdb_open(argv[1]);
    if (pdb == NULL) {
        exit(EXIT_FAILURE);
    }

    printf("PDB File: %s\n", argv[1]);
    printf("  nr_streams: %u\n", pdb->nr_streams);
    puts("");

    const struct symbol *sym = pdb_enum_public_symbols(pdb, NULL);
    while (sym != NULL) {
        printf("%4u %s (%d,%d,%d,%d): 0x%x\n", sym->index, sym->name, sym->is_code, sym->is_function, sym->is_managed, sym->is_msil, sym->rva);
        sym = pdb_enum_public_symbols(pdb, sym);
    }

    pdb_close(pdb);

    return 0;
}