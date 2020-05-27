#ifndef PDB_UTIL_H
#define PDB_UTIL_H

#include "pdb.h"
#include "pdbint.h"

#include <stdarg.h>
#include <stddef.h>

extern malloc_fn pdb_malloc;
extern free_fn pdb_free;
extern realloc_fn pdb_realloc;

/*
 * Derive calloc and strdup from user-provided allocator. Not only will they be
 * useful for us, but libcurl expects all of these callbacks to be defined if a
 * custom allocator is specified.
 */
void * pdb_calloc(size_t nmemb, size_t size);
char * pdb_strdup(const char *str);

/* Helper string functions for use symsrv functionality */
char * pdb_asprintf(const char *format, ...);
char * pdb_vasprintf(const char *format, va_list ap);

/*
 * Reimplement strtok_r for compatibility. Since strtok_r is a posix addition
 * and not specified in ansi c, it is not implemented in mingw.
 */
char * pdb_strtok_r(char *str, const char *delim, char **saveptr);

#endif  // PDB_UTIL_H