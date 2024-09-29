#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <Windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define IP_ADDR "127.0.0.1"
#define PORT 443
#define BUF_SIZE 4096
#define CA_CERT_PATH "C:\\Users\\jujem\\source\\repos\\Socket\ Programming\\Client\\ca_cert.pem"

int top = -1;

/* Obtain the return value of an SSL operation and convert into a simplified
 * error code, which is easier to examine for failure. */
enum sslstatus 
{ 
    SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL 
};

struct ssl_client
{
    int fd;

    SSL* ssl;

    BIO* rbio; /* SSL reads from, we write to. */
    BIO* wbio; /* SSL writes to, we read from. */

    /* Bytes waiting to be written to socket. This is data that has been generated
     * by the SSL object, either due to encryption of user input, or, writes
     * requires due to peer-requested SSL renegotiation. */
    char* write_buf;
    size_t write_len;

    /* Bytes waiting to be encrypted by the SSL object. */
    char* encrypt_buf;
    size_t encrypt_len;

    /* Store the previous state string */
    const char* last_state;

    /* Method to invoke when unencrypted bytes are available. */
    void (*io_on_read)(char* buf, size_t len);
} client;

void error_stdout(char* msg)
{
    printf("%s", msg);
    exit(1);
}

void winsock_init()
{
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 0), &wsa_data) != 0)
        error_stdout("Winsock 라이브러리 초기화 실패\n");
}

void ssl_init() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
}

SSL_CTX* create_ssl_ctx()
{
    const SSL_METHOD* method = TLS_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("SSL context 생성에 문제가 생겼습니다.");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void ssl_ctx_config(SSL_CTX* ctx)
{
    /* Recommended to avoid SSLv2 & SSLv3 */
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    SSL_CTX_set_verify_depth(ctx, 10);
    SSL_CTX_load_verify_locations(ctx, CA_CERT_PATH, NULL);
}

SOCKET create_socket()
{
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
        error_stdout("소켓 생성 실패\n");
    return sock;
}

void connect_server(SOCKET sock)
{
    SOCKADDR_IN serv_addr;

    //서버의 IP주소와 port 번호로 연결 요청
    serv_addr.sin_family = AF_INET;
    inet_pton(AF_INET, IP_ADDR, &serv_addr.sin_addr.s_addr);
    serv_addr.sin_port = htons(PORT);
    int connect_status = connect(sock, (SOCKADDR*)&serv_addr, sizeof(serv_addr));
    if (connect_status < 0)
        error_stdout("클라이언트가 서버와 소켓 연결에 실패했습니다.\n");
}

void print_unencrypted_data(char* buf, size_t len) {
    printf("%.*s", (int)len, buf);
}

SSL* create_ssl(struct ssl_client* p,
    SSL_CTX* ctx,
    SOCKET sock)
{
    memset(p, 0, sizeof(struct ssl_client));
    p->fd = sock;
    p->rbio = BIO_new(BIO_s_mem());
    p->wbio = BIO_new(BIO_s_mem());
    p->ssl = SSL_new(ctx);

    SSL_set_connect_state(p->ssl);

    SSL_set_bio(p->ssl, p->rbio, p->wbio);
    SSL_set_fd(client.ssl, sock);
    p->io_on_read = print_unencrypted_data;
    return p->ssl;
}

/* Queue encrypted bytes. Should only be used when the SSL object has requested a
 * write operation. */
void queue_encrypted_bytes(const char* buf, size_t len)
{
    client.write_buf = (char*)realloc(client.write_buf, client.write_len + len);
    memcpy(client.write_buf + client.write_len, buf, len);
    client.write_len += len;
}

void print_ssl_state()
{
    const char* current_state = SSL_state_string_long(client.ssl);
    if (current_state != client.last_state) {
        if (current_state)
            printf("SSL-STATE: %s\n", current_state);
        client.last_state = current_state;
    }
}

static enum sslstatus get_sslstatus(SSL* ssl, int n)
{
    switch (SSL_get_error(ssl, n))
    {
    case SSL_ERROR_NONE:
        return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
        return SSLSTATUS_WANT_IO;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
        return SSLSTATUS_FAIL;
    }
}

enum sslstatus do_ssl_handshake()
{
    char buf[BUF_SIZE];
    enum sslstatus status;

    print_ssl_state();
    int n = SSL_do_handshake(client.ssl);
    print_ssl_state();
    printf("\n");
    status = get_sslstatus(client.ssl, n);

    /* Did SSL request to write bytes? */
    if (status == SSLSTATUS_WANT_IO)
        do {
            n = BIO_read(client.wbio, buf, sizeof(buf));
            if (n > 0)
                queue_encrypted_bytes(buf, n);
            else if (!BIO_should_retry(client.wbio))
                return SSLSTATUS_FAIL;
        } while (n > 0);

    /* TLS handshake 이후에 빈 문자열 전송 */
    SSL_write(client.ssl, "init", 5);

    return status;
}

/* Process SSL bytes received from the peer. The data needs to be fed into the
   SSL object to be unencrypted.  On success, returns 0, on SSL error -1. */
int on_read_cb(char* src, size_t len)
{
    char buf[BUF_SIZE];
    enum sslstatus status;
    int n;

    while (len > 0) {
        BIO_printf(client.rbio, "\n");
        n = BIO_write(client.rbio, src, len);

        if (n <= 0)
            return -1; /* assume bio write failure is unrecoverable */

        src += n;
        len -= n;

        if (!SSL_is_init_finished(client.ssl)) {
            if (do_ssl_handshake() == SSLSTATUS_FAIL)
                return -1;
            if (!SSL_is_init_finished(client.ssl))
                return 0;
        }

        /* The encrypted data is now in the input bio so now we can perform actual
         * read of unencrypted data. */

        do {
            n = SSL_read(client.ssl, buf, sizeof(buf));
            if (n > 0)
                client.io_on_read(buf, (size_t)n);
        } while (n > 0);

        status = get_sslstatus(client.ssl, n);

        /* Did SSL request to write bytes? This can happen if peer has requested SSL
         * renegotiation. */
        if (status == SSLSTATUS_WANT_IO)
            do {
                n = BIO_read(client.wbio, buf, sizeof(buf));
                if (n > 0)
                    queue_encrypted_bytes(buf, n);
                else if (!BIO_should_retry(client.wbio))
                    return -1;
            } while (n > 0);

        if (status == SSLSTATUS_FAIL)
            return -1;
    }

    return 0;
}

/* Read encrypted bytes from socket. */
int do_sock_read()
{
    char buf[BUF_SIZE];
    int n = recv(client.fd, buf, sizeof(buf), 0);

    if (n > 0)
        return on_read_cb(buf, (size_t)n);
    else
        return -1;
}


/* Write encrypted bytes to the socket. */
int do_sock_write()
{
    size_t n = send(client.fd, client.write_buf, client.write_len, 0);
    if (n > 0) {
        if ((size_t)n < client.write_len)
            memmove(client.write_buf, client.write_buf + n, client.write_len - n);
        client.write_len -= n;
        client.write_buf = (char*)realloc(client.write_buf, client.write_len);
        return 0;
    }
    else
        return -1;
}

DWORD WINAPI read_thread(void* param)
{
    SSL* ssl = (SSL*)param;
    char echo[BUF_SIZE] = { 0, };
    while (1) {
        //char buf[BUF_SIZE];
        int f = SSL_read(ssl, echo, BUF_SIZE);
        if (f < 0) 
        {
            int error_code = SSL_get_error(ssl, f);
            printf("error Code: %d\n", error_code);
            /*ERR_error_string(error_code, buf);
            printf("%s\n", buf);*/
            break;
        }
        
        printf("%s\n", echo);
    }
}
