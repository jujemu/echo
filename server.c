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
#define BUF_SIZE 256
#define CERTIFICATE_PATH "C:\\Users\\jujem\\project\\server.crt"
#define KEY_PATH "C:\\Users\\jujem\\project\\server.key"

void remove_element(SOCKET* arr, size_t size, SOCKET sock, SSL* ssls[]);

int top = -1;

SSL_CTX* ctx;
SOCKET client_socks[SOCK_SIZE];
SSL* ssls[SOCK_SIZE];
fd_set temp_fds, read_fds;

void error_stdout(char* msg)
{
	printf("%s", msg);
	exit(1);
}

int winsock_init()
{
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 0), &wsa_data) != 0)
		return -1;
	return 0;
}

int bind_sock(SOCKET sock, int port)
{
	SOCKADDR_IN serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);
	if (bind(sock, (SOCKADDR*)&serv_addr, sizeof(serv_addr)))
	{
		closesocket(sock);
		WSACleanup();
		return -1;
	} return 0;
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

void ssl_client_init(struct ssl_client* p,
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
}

void push_client_sock(SOCKET sock, SSL* ssl)
{
	top++;
	client_socks[top] = sock;
	ssls[top] = ssl;
	FD_SET(sock, &read_fds);
}

int main(void)
{
	//WinSock 라이브러리 초기화
	if (winsock_init() != 0)
		error_stdout("WinSock 라이브러리 초기화 실패");

	//리스닝 소켓 생성
	SOCKET serv_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (serv_sock == INVALID_SOCKET)
		error_stdout("WinSock 라이브러리 초기화 실패");

	//바인드 및 대기 상태 활성화
	if (bind_sock(serv_sock, PORT) != 0)
		error_stdout("지정된 포트 번호와 바인드 실패");
	listen(serv_sock, 10);

	//SSL 초기 설정; SSL 라이브러리 초기화 및 cert, key 가져오기
	ssl_init();

	//파일 디스크립터 세트에 리스닝 소켓을 등록한다.
	FD_ZERO(&read_fds);
	FD_SET(serv_sock, &read_fds);

	char buf[BUF_SIZE] = { 0, };
	char message[BUF_SIZE] = { 0, };
	int fd_num = 0, addr_len = 0;
	SOCKADDR_IN client_addr = { 0, };
	SOCKET current_sock = 0;
	
	while (1)
	{
		temp_fds = read_fds;
		fd_num = select(0, &temp_fds, NULL, NULL, NULL);

		for (int i = 0; i < temp_fds.fd_count; i++)
		{
			current_sock = temp_fds.fd_array[i];
			if (FD_ISSET(current_sock, &temp_fds))
			{
				//리스닝 소켓이 활성화되었다는 것은 클라이언트 소켓으로부터 연결 요청이 왔다는 의미
				//소켓과 연결할 SSL을 생성하고, 소켓 배열과 같은 인덱스에 SSL을 추가한다.
				if (current_sock == serv_sock)
				{
					addr_len = sizeof(client_addr);
					SOCKET client_sock = accept(serv_sock, (SOCKADDR*)&client_addr, &addr_len);
					printf("%d 소켓이 연결되었습니다.\n", (int)client_sock);

					SSL* ssl = SSL_new(ctx);
					SSL_set_fd(ssl, client_sock);
					ssl_client_init(&client, client_sock, SSLMODE_SERVER);

					push_client_sock(client_socks, client_sock);
				}
				else
				{
					int size = sizeof(client_socks) / sizeof(SOCKET);
					int index = find_index(client_socks, size, current_sock);
					if (index < 0 || ssls[index] == 0)
					{
						printf("클라이언트 소켓과 대응되는 소켓을 찾을 수 없습니다.\n");
						exit(1);
					}

					int receive_status = SSL_read(ssls[index], message, BUF_SIZE);
					if (receive_status <= 0)
					{
						size_t size = sizeof(client_socks) / sizeof(SOCKET);
						remove_element(client_socks, size, current_sock, ssls);
						closesocket(current_sock);
						FD_CLR(current_sock, &read_fds);
						break;
					}
					
					memset(buf, 0, BUF_SIZE);
					snprintf(buf, PREFIX_SIZE, "[This message is from %d]\t", (int)current_sock);
					strcat_s(buf, BUF_SIZE, message);
					for (int j = 0; j <= top; j++)
						if (client_socks[j] != -1 && current_sock != client_socks[j])
						{
							index = find_index(client_socks, size, client_socks[j]);
							SSL_write(ssls[index], buf, BUF_SIZE);
						}
				}
			}
			if (--fd_num <= 0)
				break;
		}
	}

	closesocket(serv_sock);
	WSACleanup();

	return 0;
}

void remove_element(SOCKET* socks, size_t size, SOCKET sock, SSL* ssls[]) {
	top--;
	int found = size;
	for (int i = 0; i < size; i++)
	{
		if (socks[i] == sock)
		{
			if (i != size - 1) {
				found = i;
				break;
			}
			else {
				socks[i] = -1;
				ssls[i] = -1;
				return;
			}
		}
	}

	for (int i = found; i < size-1; i++) {
		socks[i] = socks[i + 1];
		ssls[i] = ssls[i + 1];
	}
}

int find_index(SOCKET* socks, size_t size, SOCKET sock) {
	for (int i = 0; i < size; i++) {
		if (socks[i] == sock)
			return i;
	} 
	return -1;
}