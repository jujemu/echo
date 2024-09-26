#include "client.h"

int main(void)
{
	//WinSock ���̺귯�� �ʱ�ȭ
	winsock_init();

	//SSL ���̺귯�� �ʱ�ȭ
	ssl_init();

	//���� ������ ������ ���� ��û
	SOCKET client_sock = create_socket();
	connect_server(client_sock);

	//SSL�� ���� ����
	SSL* ssl = create_ssl(&client, client_sock, SSLMODE_CLIENT);

	do_ssl_handshake();

	//Blocking IO�� ó���ϴ� ������ ����
	HANDLE read_thread_handle = CreateThread(NULL, 0, read_thread, ssl, 0, NULL);

	char read_buf[BUF_SIZE] = { 0, };
	while (1)
	{
		gets_s(read_buf, BUF_SIZE);
		if (strcmp(read_buf, "!q") == 0)
			break;
		SSL_write(ssl, read_buf, BUF_SIZE);
		/*SSL_read(ssl, read_buf, BUF_SIZE);
		printf("> %s\n", read_buf);*/
	}

	closesocket(client_sock);
	WSACleanup();

	return 0;
}