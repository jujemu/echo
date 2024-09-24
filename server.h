#pragma once
#pragma comment(lib, "ws2_32")
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define PORT 443
#define SOCK_SIZE 10
#define PREFIX_SIZE 40
#define BUF_SIZE 100000
#define CERTIFICATE_PATH "C:\\Users\\jujem\\project\\server.crt"
#define KEY_PATH "C:\\Users\\jujem\\project\\server.key"

int top = -1;

SSL_CTX* ctx;
SOCKET client_socks[SOCK_SIZE];
SSL* ssls[SOCK_SIZE];
fd_set temp_fds, read_fds;

void error_stdout(const char* msg)
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

SOCKET create_socket()
{
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
		error_stdout("소켓 생성 실패\n");
	return sock;
}

void bind_sock(SOCKET sock)
{
	SOCKADDR_IN serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(PORT);
	if (bind(sock, (SOCKADDR*)&serv_addr, sizeof(serv_addr)))
	{
		closesocket(sock);
		WSACleanup();
		error_stdout("지정된 포트 번호와 바인드 실패");
	}
}

void ssl_init() {
	//OpenSSL 라이브러리 초기화
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	//SSL Context 생성
	const SSL_METHOD* method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("SSL context 생성에 문제가 생겼습니다.");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	//인증서 정보 불러오기
	if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE_PATH, SSL_FILETYPE_PEM) <= 0 ||
		SSL_CTX_use_PrivateKey_file(ctx, KEY_PATH, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

void print_unencrypted_data(char* buf, size_t len) {
	printf("%.*s", (int)len, buf);
}

enum ssl_mode { SSLMODE_SERVER, SSLMODE_CLIENT };

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

SSL* create_ssl(struct ssl_client* p,
	SOCKET client_sock,
	enum ssl_mode mode)
{
	memset(p, 0, sizeof(struct ssl_client));

	p->fd = (int)client_sock;
	p->rbio = BIO_new(BIO_s_mem());
	p->wbio = BIO_new(BIO_s_mem());
	p->ssl = SSL_new(ctx);

	if (mode == SSLMODE_SERVER)
		SSL_set_accept_state(p->ssl);  /* ssl server mode */
	else if (mode == SSLMODE_CLIENT)
		SSL_set_connect_state(p->ssl); /* ssl client mode */

	SSL_set_bio(p->ssl, p->rbio, p->wbio);

	p->io_on_read = print_unencrypted_data;
	SSL_set_fd(p->ssl, client_sock);
	return p->ssl;
}

void remove_element(size_t size, SOCKET sock) {
	top--;
	int found = size;
	for (int i = 0; i < size; i++)
	{
		if (client_socks[i] == sock)
		{
			if (i != size - 1) {
				found = i;
				break;
			}
			else {
				client_socks[i] = -1;
				ssls[i] = -1;
				return;
			}
		}
	}

	for (int i = found; i < size - 1; i++) {
		client_socks[i] = client_socks[i + 1];
		ssls[i] = ssls[i + 1];
	}
}

void SSL_read_fail(SOCKET sock)
{
	size_t size = sizeof(client_socks) / sizeof(SOCKET);
	remove_element(size, sock);
	closesocket(sock);
	FD_CLR(sock, &read_fds);
}

void push_client_sock(SOCKET sock, SSL* ssl)
{
	top++;
	client_socks[top] = sock;
	ssls[top] = ssl;
	FD_SET(sock, &read_fds);
}

void attach_noti(char* write_buf, char* read_buf, SOCKET sock)
{
	char s[] = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Content-Length: 130\r\n"
		"Connection: close\r\n\r\n\n\n";
	memset(write_buf, 0, BUF_SIZE);
	snprintf(write_buf, PREFIX_SIZE, s, (int)sock);
	strcat_s(write_buf, BUF_SIZE, read_buf);
}

int find_index(SOCKET* socks, size_t size, SOCKET sock) {
	for (int i = 0; i < size; i++) {
		if (socks[i] == sock)
			return i;
	}
	return -1;
}