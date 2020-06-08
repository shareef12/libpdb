#include "util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

malloc_fn pdb_malloc = malloc;
free_fn pdb_free = free;
realloc_fn pdb_realloc = realloc;

void *pdb_calloc(size_t nmemb, size_t size)
{
    if (nmemb == 0 || size == 0) {
        return NULL;
    }

    size_t total_sz = nmemb * size;
    if (nmemb != total_sz / size) {
        /* Integer overflow */
        return NULL;
    }

    void *ptr = pdb_malloc(total_sz);
    if (ptr != NULL) {
        memset(ptr, 0, total_sz);
    }

    return ptr;
}

char *pdb_strdup(const char *str)
{
    size_t len = strlen(str) + 1;
    char *s = pdb_malloc(len);
    if (s == NULL) {
        return NULL;
    }

    strncpy(s, str, len);
    s[len - 1] = '\0';

    return s;
}

char *pdb_vasprintf(const char *format, va_list ap)
{
    va_list aq;

    va_copy(aq, ap);
    int size = vsnprintf(NULL, 0, format, aq);
    va_end(aq);

    if (size < 0) {
        return NULL;
    }

    size++; /* For '\0' */
    char *ptr = pdb_malloc(size);
    if (ptr == NULL) {
        return NULL;
    }

    va_copy(aq, ap);
    int sz = vsnprintf(ptr, size, format, aq);
    va_end(aq);

    if (sz < 0 || sz == size) {
        /* We consider truncation an error - this happens when there is a TOCTOU violation */
        pdb_free(ptr);
        return NULL;
    }

    return ptr;
}

char *pdb_asprintf(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    char *s = pdb_vasprintf(format, ap);
    va_end(ap);

    return s;
}

char *pdb_strtok_r(char *str, const char *delim, char **saveptr)
{
    if (str == NULL) {
        str = *saveptr;
    }

    /* Skip delimiter bytes */
    str += strspn(str, delim);
    if (*str == '\0') {
        return NULL;
    }

    /* Null terminate the new token */
    char *ret = str;
    str += strcspn(str, delim);
    if (*str) {
        *str++ = '\0';
    }

    /* Save a copy of our current state */
    *saveptr = str;

    return ret;
}
