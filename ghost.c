/* Reverse proxy implementation with SSL support
* Forwards HTTPS traffic to a remote host while following redirects
* and maintaining header integrity. Requires root for port 443.
*
* Compilation: gcc -o ghost ghost.c -lssl -lcrypto -lcurl
* Usage: ./ghost
*
* The proxy listens on port 443 and forwards all traffic to
* the configured remote host. It handles SSL/TLS connections
* on both ends and manages automatic redirect following.
*/

/* possible tasks to work on next 
*
* adding threading
* connection pooling?
* better resource limits
* sort of check for input validation
* filter
*
*/
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <curl/curl.h>
#include <time.h>

#define PORT      443
#define URL       "https://your-target-host.com"
#define CERT      "ghost.cer"
#define KEY       "ghost.pem"
#define TARGETHOST "your-target-host.com"

/* arbitrary sizes */
#define CACHE_MAX_ENTRIES 1000
#define CACHE_MAX_SIZE (100 * 1024 * 1024)
#define CACHE_ENTRY_TTL 300
#define POOL_SIZE 8

static SSL_CTX *ctx;
static struct Cache *global_cache;

struct CacheEntry {
    char *url;
    char *data;
    size_t size;
    time_t expires;
    char *content_type;
    int valid;
};

struct Cache {
    struct CacheEntry *entries;
    size_t count;
    size_t capacity;
    size_t total_size;
};

struct RequestContext {
    SSL *ssl;
    char *url;
    char *method;
    struct Cache *cache;
    char *content_type;
    size_t response_size;
    char *response_data;
};

/* debug helper */
static void
debug_request(const char *buf, int n)
{
    fprintf(stderr, "\n=== REQUEST START ===\n");
    fprintf(stderr, "%.*s", n, buf);
    fprintf(stderr, "\n=== REQUEST END ===\n");
}

static void
debug_headers(struct curl_slist *headers)
{
    struct curl_slist *h = headers;
    fprintf(stderr, "\n=== HEADERS START ===\n");
    while (h) {
        fprintf(stderr, "%s\n", h->data);
        h = h->next;
    }
    fprintf(stderr, "=== HEADERS END ===\n");
}
/* .. */

/* functions */
static struct Cache *cache_init(void);
static struct CacheEntry *cache_lookup(struct Cache *cache, const char *url);
static void cache_cleanup(struct Cache *cache);
static int cache_add(struct Cache *cache, const char *url, const char *data, size_t size, const char *content_type);
static size_t write_cb(void *ptr, size_t size, size_t nmemb, struct RequestContext *ctx);
static size_t header_cb(char *ptr, size_t size, size_t nmemb, struct RequestContext *ctx);
static char *get_path(const char *request);
static struct curl_slist *get_headers(const char *buf);
static void handle(SSL *ssl);
static SSL_CTX *sslsetup(void);
static int serverinit(void);

/* implementation */
static struct Cache *
cache_init(void)
{
    struct Cache *cache = malloc(sizeof(struct Cache));
    if (!cache) return NULL;

    cache->entries = calloc(CACHE_MAX_ENTRIES, sizeof(struct CacheEntry));
    if (!cache->entries) {
        free(cache);
        return NULL;
    }

    cache->count = 0;
    cache->capacity = CACHE_MAX_ENTRIES;
    cache->total_size = 0;
    return cache;
}

static struct CacheEntry *
cache_lookup(struct Cache *cache, const char *url)
{
    time_t now = time(NULL);
    
    for (size_t i = 0; i < cache->count; i++) {
        if (cache->entries[i].valid &&
            strcmp(cache->entries[i].url, url) == 0) {
            if (cache->entries[i].expires > now) {
                return &cache->entries[i];
            }
            cache->entries[i].valid = 0;
            return NULL;
        }
    }
    return NULL;
}

static void
cache_cleanup(struct Cache *cache)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < cache->count; i++) {
        if (cache->entries[i].valid && cache->entries[i].expires <= now) {
            cache->total_size -= cache->entries[i].size;
            free(cache->entries[i].url);
            free(cache->entries[i].data);
            free(cache->entries[i].content_type);
            cache->entries[i].valid = 0;
        }
    }
}

static int
cache_add(struct Cache *cache, const char *url, const char *data, 
          size_t size, const char *content_type)
{
    if (cache->count >= cache->capacity ||
        cache->total_size + size > CACHE_MAX_SIZE) {
        cache_cleanup(cache);
    }

    size_t slot = cache->count;
    for (size_t i = 0; i < cache->count; i++) {
        if (!cache->entries[i].valid) {
            slot = i;
            break;
        }
    }

    if (slot == cache->count) {
        if (cache->count >= cache->capacity) return 0;
        cache->count++;
    }

    cache->entries[slot].url = strdup(url);
    cache->entries[slot].data = malloc(size);
    cache->entries[slot].content_type = strdup(content_type);
    
    if (!cache->entries[slot].url || 
        !cache->entries[slot].data || 
        !cache->entries[slot].content_type) {
        free(cache->entries[slot].url);
        free(cache->entries[slot].data);
        free(cache->entries[slot].content_type);
        return 0;
    }

    memcpy(cache->entries[slot].data, data, size);
    cache->entries[slot].size = size;
    cache->entries[slot].expires = time(NULL) + CACHE_ENTRY_TTL;
    cache->entries[slot].valid = 1;
    cache->total_size += size;

    return 1;
}

/* implementation */
/* SSL forwarding callback for libcurl
 * Directly writes received data to SSL connection
 */
static size_t
write_cb(void *ptr, size_t size, size_t nmemb, struct RequestContext *ctx)
{
    size_t total = size * nmemb;
    fprintf(stderr, "\n=== SENDING %zu BYTES ===\n", total); // debug remove later

    if (strcmp(ctx->method, "GET") == 0) {
        char *new_data = realloc(ctx->response_data, ctx->response_size + total);
        if (new_data) {
            ctx->response_data = new_data;
            memcpy(ctx->response_data + ctx->response_size, ptr, total);
            ctx->response_size += total;
        }
    }

    return SSL_write(ctx->ssl, ptr, total);
}

static size_t
header_cb(char *ptr, size_t size, size_t nmemb, struct RequestContext *ctx)
{
    size_t total = size * nmemb;
    char header[1024];
    snprintf(header, sizeof(header), "%.*s", (int)total, ptr);

    if (strncasecmp(header, "Content-Type:", 13) == 0) {
        char *value = header + 13;
        while (*value == ' ') value++;
        ctx->content_type = strdup(value);
    }

    return total;
}

/* Request path extraction from HTTP request
 * Returns malloc'd path string
 */
static char *
get_path(const char *request)
{
    char *path_start = strchr(request, ' ');
    if (!path_start) return strdup("/");
    path_start++;
    
    char *path_end = strchr(path_start, ' ');
    if (!path_end) return strdup("/");

    char *path = malloc(path_end - path_start + 1);
    if (!path) return strdup("/");

    memcpy(path, path_start, path_end - path_start);
    path[path_end - path_start] = '\0';
    return path;
}

/* Get HTTP headers from original request and modify them for forwarding
 * 
 * Processes raw HTTP request buffer into curl_slist of headers
 * Sets target Host header first, then copies all original headers
 * except Connection, Accept-Encoding, and original Host
 * 
 * buf: Raw HTTP request buffer
 * returns: curl_slist of headers for forwarding, needs to be freed
 *
 * Example input:
 * GET / HTTP/1.1
 * Host: my-host.com
 * Accept: text/html,application/xhtml+xml
 * 
 * Becomes:
 * Host: your-target-server.com
 * Accept: text/html,application/xhtml+xml
 */
static struct curl_slist *
get_headers(const char *buf)
{
    struct curl_slist *headers = NULL;
    char host_header[256];
    snprintf(host_header, sizeof(host_header), "Host: %s", TARGETHOST);
    headers = curl_slist_append(headers, host_header);

    char *header_start = strstr(buf, "\r\n") + 2;
    char *header_end;
    char header[4096];

    while ((header_end = strstr(header_start, "\r\n")) != NULL) {
        if (header_start == header_end) break;
        size_t len = header_end - header_start;
        memcpy(header, header_start, len);
        header[len] = '\0';
        
        if (strncasecmp(header, "Connection:", 11) != 0 &&
            strncasecmp(header, "Accept-Encoding:", 16) != 0 &&
            strncasecmp(header, "Host:", 5) != 0) {
            headers = curl_slist_append(headers, header);
        }
        header_start = header_end + 2;
    }
    return headers;
}

/* SSL connection handler
 * Processes client request and forwards to remote server
 */
static void
handle(SSL *ssl)
{
    CURL *curl;
    CURLcode res;
    char buf[4096];
    char *path;
    char url[4096];
    int n;
    struct curl_slist *headers = NULL;
    char method[10] = {0};
    struct RequestContext ctx = {0};
    long response_code;

    /* measure time from cache */
    struct timespec start, end; // testing
    clock_gettime(CLOCK_MONOTONIC, &start); // testing

    curl = curl_easy_init();
    if (!curl) return;

    n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n <= 0) goto cleanup;

    buf[n] = '\0';
    debug_request(buf, n);

    sscanf(buf, "%s", method);
    ctx.method = method;

    path = get_path(buf);
    snprintf(url, sizeof(url), "%s%s", URL, path);
    ctx.url = url;
    free(path);

    if (strcmp(method, "GET") == 0) {
        struct CacheEntry *cached = cache_lookup(global_cache, url);
        if (cached) {
            SSL_write(ssl, cached->data, cached->size);
            goto cleanup;
        }
    }

    headers = get_headers(buf);
    debug_headers(headers); // debug remove later
    ctx.ssl = ssl;
    ctx.cache = global_cache;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (strcmp(method, "POST") == 0) {
        char *body = strstr(buf, "\r\n\r\n");
        if (body) {
            body += 4;
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        }
    }

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (strcmp(method, "GET") == 0 && response_code == 200 && 
            ctx.response_data && ctx.content_type) {
            cache_add(global_cache, url, ctx.response_data, 
                     ctx.response_size, ctx.content_type);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);               // dbg
    double time_spent = (end.tv_sec - start.tv_sec) +   // dbg
                   (end.tv_nsec - start.tv_nsec) / 1e9; // dbg 
    printf("Request took: %.3f seconds\n", time_spent); // dbg

cleanup:
    if (headers) curl_slist_free_all(headers);
    free(ctx.response_data);
    free(ctx.content_type);
    curl_easy_cleanup(curl);
}

/* SSL context setup
 * Initializes SSL library and loads certificates
 *
 * verbose output */
static SSL_CTX *
sslsetup(void)
{
    SSL_CTX *ctx;

    printf("loading ssl strings ... \n");
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    printf("creating new ssl context ... \n");
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "ssl context creation failed: ");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    printf("loading certificates %s ... \n", CERT);
    if (SSL_CTX_use_certificate_file(ctx, CERT, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "certificate loading failed ");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    printf("loading private key %s ... \n", KEY);
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY, SSL_FILETYPE_PEM) <= 0){
        fprintf(stderr, "private key loading failed: ");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
      
    return ctx;
}

/* Server socket initialization
 * Creates and binds listening socket
 */
static int
serverinit(void)
{
    struct sockaddr_in addr;
    int sd, opt = 1;

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) exit(1);

    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        fprintf(stderr, "setsockopt failed\n");
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("ghost needs to be run as root, exiting.\n");
        exit(1);
    } 

    if (listen(sd, 1) < 0) exit(1);

    return sd;
}

int
main(void)
{
    struct sockaddr_in addr;
    unsigned int len;
    SSL *ssl;
    int sock, conn;

    global_cache = cache_init();
    if (!global_cache) {
        fprintf(stderr, "Cache initialization failed\n");
        return 1;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    ctx = sslsetup();
    sock = serverinit();

    while (1) {
        len = sizeof(addr);
        conn = accept(sock, (struct sockaddr*)&addr, &len);
        if (conn < 0) continue;

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, conn);

        if (SSL_accept(ssl) <= 0)
            fprintf(stderr, "ssl accept failed\n");
        else
            handle(ssl);

        SSL_free(ssl);
        close(conn);
    }

    close(sock);
    SSL_CTX_free(ctx);
    curl_global_cleanup();
    EVP_cleanup();
    return 0;
}