#pragma comment(lib, "ws2_32")
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <Windows.h>

#define BUF_SIZE 256

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("ip�ּҿ� port ��ȣ�� �־������մϴ�.");
		exit(1);
	}
	int port = atoi(argv[2]);
	char addr[16];
	strncpy_s(addr, sizeof(addr) - 1, argv[1], sizeof(addr)-1);
	addr[sizeof(addr) - 1] = '\0';

	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2, 0), &wsa_data);
	
	SOCKET client_sock = socket(AF_INET, SOCK_STREAM, 0);

	SOCKADDR_IN serv_addr;
	serv_addr.sin_family = AF_INET;
	inet_pton(AF_INET, addr, &serv_addr.sin_addr.s_addr);
	serv_addr.sin_port = htons(port);
	int connect_status = connect(client_sock, (SOCKADDR*)&serv_addr, sizeof(serv_addr));
	if (connect_status < 0)
	{
		printf("Ŭ���̾�Ʈ�� ������ ���� ���ῡ �����߽��ϴ�.\n");
		exit(1);
	}

	char buf[BUF_SIZE];
	char echo[BUF_SIZE];
	while (1)
	{
		printf("%s", "> ");
		gets_s(buf, BUF_SIZE);
		send(client_sock, buf, BUF_SIZE, 0);
		if (strcmp(buf, "!q") == 0)
			break;

		recv(client_sock, echo, BUF_SIZE, 0);
		printf("%s\n", echo);
	}

	closesocket(client_sock);
	WSACleanup();

	return 0;
}