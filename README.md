# libpdb [![Build Status](https://travis-ci.org/shareef12/libpdb.svg?branch=master)](https://travis-ci.org/shareef12/libpdb)

libpdb is a Linux library for parsing Microsoft Program Database (PDB) files.

libpdb's primary purpose is to aid with reverse engineering of Windows binaries
on non-Windows targets. Additionally, it can be used to assist with
introspection of Windows targets in hypervisors or disk image forensics tools.

libpdb currently has the following major features:

* Retrieve PDB header information, including the guid and age of the target binary.
* Retrieve section header information.
* Enumerate symbols (public and global).
* Lookup a symbol directly by its name. This functionality is very fast, as it
  uses an embedded hashtable in the PDB file.

This project also provides `pdbparse` - a command-line utility for reading PDB
files. `pdbparse` implements an interface similar to `readelf`.

libpdb is written in C for maximum compatibility with other projects and
language runtimes. It is built as both a shared and static library.


## Example

libpdb tries to provide a simple to use interface. An example of parsing a PDB and
enumerating public symbols is provided below.

```C
int main(int argc, char **argv)
{
    /* Load a PDB file into memory via fopen/fread/mmap. */
    ...

    if (!pdb_sig_match(pdbdata, pdbdata_sz)) {
        exit(EXIT_FAILURE);
    }

    void *ctx = pdb_create_context(NULL, NULL);
    if (ctx == NULL) {
        exit(EXIT_FAILURE);
    }

    if (pdb_load(ctx, pdbdata, pdbdata_sz) < 0) {
        exit(EXIT_FAILURE);
    }

    /*
     * The PDB was parsed successfully. At this point, the original backing
     * storage for `pdbdata` can be safely freed.
     */

    uint32_t nr_symbols = 0;
    if (pdb_get_nr_public_symbols(pdb, &nr_symbols) < 0) {
        exit(EXIT_FAILURE);
    }

    const PUBSYM32 **symbols = calloc(nr_symbols, sizeof(void *));
    if (symbols == NULL) {
        exit(EXIT_FAILURE);
    }

    if (pdb_get_public_symbols(pdb, symbols) < 0) {
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < nr_symbols; i++) {
        const PUBSYM32 *sym = symbols[i];

        uint32_t sym_rva = 0;
        (void)pdb_convert_section_offset_to_rva(pdb, sym->seg, sym->off, &sym_rva);

        printf("sym rva=0x%08x name=%s\n", sym_rva, sym->name);
    }

    exit(EXIT_SUCCESS);
}
```


## Roadmap

There a number of planned features. These currently include:

- [ ] Add libpdb support for downloading PDB files from a symbol server
- [ ] Integrate a symbol name demangler into pdbparse for an alternate public
  symbol view
- [ ] Parse type information
- [ ] Parse module information, local symbols, and line number information.
- [ ] Add cross-compilation support for Windows and big-endian Unix machines
- [ ] Add support for building libpdb without libc in order to support alternative
  execution environments, such as embedded targets or kernel mode


## Credits

There are a number of other open-source PDB parsing libraries. A few are listed
here.

| Name | Description | Language |
| --- | --- | --- |
| `microsoft-pdb` [1] | Official Microsoft PDB headers. Does not build.       | C (Windows)   |
| `pdbex` [2]         | Application that generates C headers from PDB files.  | C++           |
| `pdbparse` [3]      | General PDB parsing package.                          | Python        |
| `pdb` [4]           | General PDB parsing library.                          | Rust          |

[1] <https://github.com/microsoft/microsoft-pdb> <br/>
[2] <https://github.com/wbenny/pdbex> <br/>
[3] <https://github.com/moyix/pdbparse> <br/>
[4] <https://github.com/willglynn/pdb> <br/>
