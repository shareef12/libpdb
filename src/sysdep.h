#ifndef LIBPDB_SYSDEP_H
#define LIBPDB_SYSDEP_H

#include <stdbool.h>
#include <stddef.h>

int sys_global_init(void);
void sys_global_cleanup(void);

bool sys_is_absolute_path(const char *path);

bool sys_is_file(const char *pathname);

bool sys_is_directory(const char *pathname);

char *sys_basename(const char *pathname);

int sys_makedirs(const char *dirpath);

int sys_read_file(const char *pathname, unsigned char **data, size_t *length);

int sys_write_file(const char *pathname, const unsigned char *data, size_t length);

int sys_download_file(const char *url, unsigned char **data, size_t *length);

size_t sys_get_user_cache_dir(char *dirpath, size_t dirpath_len);

#endif  // LIBPDB_SYSDEP_H
