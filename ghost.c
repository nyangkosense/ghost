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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <curl/curl.h>

#define BUFSIZ    4096
#define PORT      443
#define URL       "https://your-target-server.com"
#define CERT      "/path/to/your/cert.cer"
#define KEY       "/path/to/your/key.pem"

static SSL_CTX *ctx;

struct response {
    char *data;
    size_t size;
};

/* functions */
static size_t write_cb(void *ptr, size_t size, size_t nmemb, SSL *ssl);
static char *get_path(const char *request);
static void handle(SSL *ssl);
static SSL_CTX *sslsetup(void);
static int serverinit(void);

/* implementation */
/* SSL forwarding callback for libcurl
 * Directly writes received data to SSL connection
 */
static size_t
write_cb(void *ptr, size_t size, size_t nmemb, SSL *ssl)
{
    size_t total = size * nmemb;
    return SSL_write(ssl, ptr, total);
}

/* Request path extraction from HTTP request
 * Returns malloc'd path string
 */
static char *
get_path(const char *request)
{
    char *path_start, *path_end, *path;
    
    path_start = strchr(request, ' ');
    if (!path_start) return strdup("/");
    path_start++;
    
    path_end = strchr(path_start, ' ');
    if (!path_end) return strdup("/");

    path = malloc(path_end - path_start + 1);
    if (!path) return strdup("/");

    memcpy(path, path_start, path_end - path_start);
    path[path_end - path_start] = '\0';
    return path;
}

/* SSL connection handler
 * Processes client request and forwards to remote server
 */
static void
handle(SSL *ssl)
{
    CURL *curl;
    CURLcode res;
    char buf[BUFSIZ];
    char *path;
    char url[BUFSIZ];
    int n;
    struct curl_slist *headers = NULL;

    curl = curl_easy_init();
    if (!curl) return;

    n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n <= 0) goto cleanup;

    buf[n] = '\0';
    path = get_path(buf);
    snprintf(url, sizeof(url), "%s%s", URL, path);
    free(path);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ssl);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "Accept-Encoding: identity");
    headers = curl_slist_append(headers, "X-Ben: Rad");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);

cleanup:
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

/* SSL context setup
 * Initializes SSL library and loads certificates
 */
static SSL_CTX *
sslsetup(void)
{
    SSL_CTX *ctx;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) exit(1);

    if (SSL_CTX_use_certificate_file(ctx, CERT, SSL_FILETYPE_PEM) <= 0
        || SSL_CTX_use_PrivateKey_file(ctx, KEY, SSL_FILETYPE_PEM) <= 0)
        exit(1);

    return ctx;
}

/* Server socket initialization
 * Creates and binds listening socket
 */
static int
serverinit(void)
{
    struct sockaddr_in addr;
    int sd;

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) exit(1);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) exit(1);
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