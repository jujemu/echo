#pragma comment(lib, "ws2_32")
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>

#define BUF_SIZE 256

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("포트를 입력하세요.\n");
		exit(1);
	}
	int port = atoi(argv[1]);

	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2, 0), &wsa_data);

	SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	
	SOCKADDR_IN serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);
	if (bind(listen_sock, (SOCKADDR*)&serv_addr, sizeof(serv_addr))) 
	{
		printf("바인드 실패\n");
		closesocket(listen_sock);
		WSACleanup();
		exit(1);
	}

	listen(listen_sock, 10);

	SOCKADDR_IN client_addr;
	int size_client_addr = sizeof(client_addr);
	SOCKET data_sock = accept(listen_sock, (SOCKADDR*)&client_addr, &size_client_addr);
	
	char buf[BUF_SIZE];
	while (1)
	{
		recv(data_sock, buf, BUF_SIZE, 0);
		printf("%s\n", buf);
		if (strcmp(buf, "!q") == 0)
			break;
		send(data_sock, buf, BUF_SIZE, 0);
		send(data_sock, "close", BUF_SIZE, 0);
	}

	closesocket(listen_sock);
	closesocket(data_sock);
	WSACleanup();

	return 0;
}