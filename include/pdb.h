#ifndef PDB_H
#define PDB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct guid {
    union {
        struct {
            uint32_t data1;
            uint16_t data2;
            uint16_t data3;
            unsigned char data4[8];
        };
        unsigned char bytes[16];
    };
};

struct stream {
    uint32_t index;
    uint32_t size;
    const unsigned char *data;
};

struct pdb {
    uint32_t nr_streams;
    const struct stream *streams;

    /* Metadata information from the PDB Stream. This can be used to match this
       PDB to an executable. */
    uint32_t age;
    struct guid guid;
};

struct symbol {
    uint32_t index;

    bool is_code;
    bool is_function;
    bool is_managed;
    bool is_msil;

    uint32_t rva;
    char name[];
};

const struct pdb * pdb_open(const char *pdbfile);

const struct pdb * pdb_load(const void *pdbdata, size_t len);

void pdb_close(const struct pdb *pdb);

const struct symbol * pdb_lookup_public_symbol(const struct pdb *pdb, const char *name);

const struct symbol * pdb_enum_public_symbols(const struct pdb *pdb, const struct symbol *prev);


#endif // PDB_H
