#ifndef PDB_MSF_H
#define PDB_MSF_H

#include <stdint.h>

#define PDB_SUPERBLOCK_MAGIC    "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
#define PDB_SUPERBLOCK_MAGIC_SZ (32)

#define OLD_DIRECTORY_STREAM_IDX 0
#define PDB_STREAM_IDX 1
#define TPI_STREAM_IDX 2
#define DBI_STREAM_IDX 3
#define IPI_STREAM_IDX 4

#define MIN_STREAM_COUNT 5

struct superblock {
    char file_magic[PDB_SUPERBLOCK_MAGIC_SZ];
    uint32_t block_size;
    uint32_t free_block_map_block;
    uint32_t num_blocks;
    uint32_t num_directory_bytes;
    uint32_t unknown;
    uint32_t block_map_addr;
};

struct stream_directory {
    uint32_t num_streams;
    // uint32_t stream_sizes[num_streams];
    // uint32_t stream_blocks[num_streams][];
};

#endif // PDB_MSF_H
