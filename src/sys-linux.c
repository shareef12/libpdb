#include "sysdep.h"

#include "util.h"

#include <curl/curl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct curl_mem_buffer {
    unsigned char *mem;
    size_t size;
};

static size_t curl_write_mem_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    struct curl_mem_buffer *buf = (struct curl_mem_buffer *)userp;

    size_t realsize = size * nmemb;
    if (size == 0 || nmemb == 0 || realsize / size != nmemb) {
        return 0;
    }

    unsigned char *ptr = realloc(buf->mem, buf->size + realsize);
    if (ptr == NULL) {
        return 0;
    }

    buf->mem = ptr;
    memcpy(buf->mem + buf->size, contents, realsize);
    buf->size += realsize;

    return realsize;
}

bool sys_is_absolute_path(const char *path)
{
    return *path == '/';
}

bool sys_is_file(const char *pathname)
{
    return access(pathname, F_OK) == 0;
}

bool sys_is_directory(const char *pathname)
{
    int fd = open(pathname, O_DIRECTORY | O_CLOEXEC); /* NOLINT(hicpp-signed-bitwise) */
    if (fd >= 0) {
        close(fd);
        return true;
    }
    return false;
}

char *sys_basename(const char *pathname)
{
    char *pathsep = strrchr(pathname, '/');
    if (pathsep == NULL) {
        return pdb_strdup(pathname);
    }

    return pdb_strdup(pathsep + 1);
}

int sys_makedirs(const char *dirpath)
{
    /*
     * Recursively walk backwards through the string and try to create each
     * directory. We should not use sys_is_directory for validation, because
     * it's possible (though unlikely) that the user is asking us to create a
     * symbol cache in a directory they have write-only permissions to.
     *
     * Once we find a path we can create, walk forward again until all
     * directories are created or we encounter another error.
     */
    int err = mkdir(dirpath, 0775);
    if (err == 0 || errno != ENOENT) {
        /*
         * Base case - we created a directory or encountered an unexpected
         * error.
         */
        return err;
    }

    /*
     * Recursive case - a directory in the path does not exist. Try to create
     * parent directories.
     */
    char *dp = pdb_strdup(dirpath);
    if (dp == NULL) {
        return -1;
    }

    char *c;
    char *parent_dirpath = pdb_strtok_r(dp, "/", &c);
    if (parent_dirpath == NULL) {
        pdb_free(dp);
        return -1;
    }

    err = sys_makedirs(parent_dirpath);
    pdb_free(dp);
    if (err < 0) {
        return err;
    }

    /*
     * We successfully create parent directories. Try to create this one again.
     */
    return mkdir(dirpath, 0775);
}

int sys_read_file(const char *pathname, unsigned char **data, size_t *length)
{
    int fd = open(pathname, O_RDONLY | O_CLOEXEC); /* NOLINT(hicpp-signed-bitwise) */
    if (fd < 0) {
        return -1;
    }

    struct stat sb = {0};
    if (fstat(fd, &sb) < 0) {
        goto err_close_fd;
    }

    void *buf = pdb_malloc(sb.st_size);
    if (buf == NULL) {
        goto err_close_fd;
    }

    int err = read(fd, buf, sb.st_size);
    if (err < 0) {
        goto err_free_buf;
    }

    close(fd);

    *data = buf;
    *length = sb.st_size;

    return 0;

err_free_buf:
    pdb_free(buf);

err_close_fd:
    close(fd);

    return -1;
}

int sys_write_file(const char *pathname, const unsigned char *data, size_t length)
{
    int fd = open(
        pathname, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, /* NOLINT(hicpp-signed-bitwise) */
        0664);
    if (fd < 0) {
        return -1;
    }

    int err = write(fd, data, length);
    close(fd);

    return err;
}

int sys_download_file(const char *url, unsigned char **data, size_t *length)
{
    struct curl_mem_buffer buf = {
        .mem = NULL,
        .size = 0,
    };

    // TODO(shareef12): curl_global_init(CURL_GLOBAL_ALL);

    CURL *curl_handle = curl_easy_init();

    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_write_mem_callback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&buf);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libpdb/1.0");

    CURLcode err = curl_easy_perform(curl_handle);
    if (err != CURLE_OK) {
        pdb_free(buf.mem);
    }

    curl_easy_cleanup(curl_handle);

    // TODO(shareef12): curl_global_cleanup();

    *data = buf.mem;
    *length = buf.size;

    return 0;
}

size_t sys_get_user_cache_dir(char *dirpath, size_t dirpath_len)
{
    /* Follow the XDG Base Directory Specification */
    const char *cachedir = getenv("XDG_CACHE_HOME");
    if (cachedir != NULL && *cachedir != '\0') {
        return snprintf(dirpath, dirpath_len, "%s", cachedir);
    }

    const char *homedir = getenv("HOME");
    if (homedir != NULL && *homedir != '\0') {
        return snprintf(dirpath, dirpath_len, "%s/.cache", homedir);
    }

    return snprintf(dirpath, dirpath_len, "/tmp");
}
