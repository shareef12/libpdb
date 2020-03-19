#ifndef PDB_MSF_H
#define PDB_MSF_H

#include <stdint.h>

#define OLD_DIRECTORY_STREAM_IDX 0
#define PDB_STREAM_IDX 1
#define TPI_STREAM_IDX 2
#define DBI_STREAM_IDX 3
#define IPI_STREAM_IDX 4

#define MIN_STREAM_COUNT 5

struct superblock {
    char file_magic[PDB_SIGNATURE_SZ];
    uint32_t block_size;
    uint32_t free_block_map_block;
    uint32_t num_blocks;
    uint32_t num_directory_bytes;
    uint32_t unknown;
    uint32_t block_map_addr;
} __attribute__((packed));

struct stream_directory {
    uint32_t num_streams;
    // uint32_t stream_sizes[num_streams];
    // uint32_t stream_blocks[num_streams][];
} __attribute__((packed));

#endif // PDB_MSF_H
