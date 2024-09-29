#include "client.h"

int main(void)
{
	SSL_CTX* ctx = NULL;
	SSL* ssl = NULL;
	SOCKET client_sock = 0;

	//WinSock ���̺귯�� �ʱ�ȭ
	winsock_init();

	//SSL ���̺귯�� �ʱ�ȭ
	ssl_init();

	//SSL context ����
	ctx = create_ssl_ctx();
	ssl_ctx_config(ctx);

	//���� ������ ������ ���� ��û
	client_sock = create_socket();
	connect_server(client_sock);

	//SSL�� ���� ����
	ssl = create_ssl(&client, ctx, client_sock);

	do_ssl_handshake();

	//Blocking IO�� ó���ϴ� ������ ����
	HANDLE read_thread_handle = CreateThread(NULL, 0, read_thread, ssl, 0, NULL);

	char std_read_buf[BUF_SIZE] = { 0, };
	char std_write_buf[BUF_SIZE] = { 0, };
	while (1)
	{
		gets_s(std_read_buf, BUF_SIZE);
		if (strcmp(std_read_buf, "!q") == 0)
			break;
		SSL_write(ssl, std_read_buf, BUF_SIZE);
		/*int f = SSL_read(ssl, std_write_buf, BUF_SIZE);
		printf("ssl read return: %d\n", f);
		printf("std write_buf: %d\n", std_write_buf);*/
	}

	closesocket(client_sock);
	WSACleanup();

	return 0;
}