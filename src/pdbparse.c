#include <stdio.h>
#include <stdlib.h>

#include "pdb.h"

#define GUID_STR_SIZE (32 + 4)

void sprint_guid(char *s, const struct guid *guid)
{
    sprintf(s, "%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
        guid->data1, guid->data2, guid->data3,
        guid->data4[0], guid->data4[1], guid->data4[2], guid->data4[3],
        guid->data4[4], guid->data4[5], guid->data4[6], guid->data4[7]);
}


int main(int argc, char **argv)
{
    const struct pdb *pdb = pdb_open(argv[1]);
    if (pdb == NULL) {
        fprintf(stderr, "pdb_open failure\n");
        exit(EXIT_FAILURE);
    }

    char sguid[GUID_STR_SIZE + 1] = {0};
    sprint_guid(sguid, &pdb->guid);

    printf("PDB File: %s\n", argv[1]);
    printf("  nr_streams: %u\n", pdb->nr_streams);
    printf("  guid: {%s}\n", sguid);
    printf("  age: %u\n", pdb->age);
    puts("");

    const struct symbol *sym = pdb_enum_public_symbols(pdb, NULL);
    while (sym != NULL) {
        printf("%4u %s (%d,%d,%d,%d): 0x%x\n", sym->index, sym->name, sym->is_code, sym->is_function, sym->is_managed, sym->is_msil, sym->rva);
        sym = pdb_enum_public_symbols(pdb, sym);
    }

    printf("done\n");

    pdb_close(pdb);

    return 0;
}