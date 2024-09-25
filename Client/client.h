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

int top = -1;

SSL_CTX* ctx;

enum ssl_mode 
{ 
    SSLMODE_SERVER, SSLMODE_CLIENT 
};

/* Obtain the return value of an SSL operation and convert into a simplified
 * error code, which is easier to examine for failure. */
enum sslstatus { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL };

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
	//OpenSSL 라이브러리 초기화
	SSL_library_init();
    OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	//SSL Context 생성
	const SSL_METHOD* method = TLS_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("SSL context 생성에 문제가 생겼습니다.");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

    /* Recommended to avoid SSLv2 & SSLv3 */
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
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
    int fd,
    enum ssl_mode mode)
{
    memset(p, 0, sizeof(struct ssl_client));

    p->fd = fd;

    p->rbio = BIO_new(BIO_s_mem());
    p->wbio = BIO_new(BIO_s_mem());
    p->ssl = SSL_new(ctx);

    if (mode == SSLMODE_SERVER)
        SSL_set_accept_state(p->ssl);  /* ssl server mode */
    else if (mode == SSLMODE_CLIENT)
        SSL_set_connect_state(p->ssl); /* ssl client mode */

    SSL_set_bio(p->ssl, p->rbio, p->wbio);

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

    return status;
}

DWORD WINAPI read_thread(void* param)
{
	SSL* ssl = (SSL*)param;
    char echo[BUF_SIZE] = { "abcd" };
	while (1) {
        char buf[BUF_SIZE];
        int f = SSL_read(ssl, echo, BUF_SIZE);
        while ( f < 0) {
            int error_code = SSL_get_error(ssl, f);
            printf("%d\n", error_code);
            ERR_error_string(error_code, buf);
            printf("%s\n", buf);
        }
		printf("%s\n", echo);
	}
}
