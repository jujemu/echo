#pragma comment(lib, "ws2_32")
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>

#define SOCK_SIZE 10
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

	SOCKET serv_sock = socket(AF_INET, SOCK_STREAM, 0);
	
	SOCKADDR_IN serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);
	if (bind(serv_sock, (SOCKADDR*)&serv_addr, sizeof(serv_addr))) 
	{
		printf("바인드 실패\n");
		closesocket(serv_sock);
		WSACleanup();
		exit(1);
	}

	listen(serv_sock, 10);

	fd_set temp_fds, read_fds;
	FD_ZERO(&read_fds);
	FD_SET(serv_sock, &read_fds);

	char buf[BUF_SIZE];
	int fd_num, addr_len;
	SOCKADDR_IN client_addr;
	SOCKET current_sock;
	
	int top = -1;
	SOCKET client_socks[SOCK_SIZE];
	
	while (1)
	{
		temp_fds = read_fds;
		fd_num = select(0, &temp_fds, NULL, NULL, NULL);

		for (int i = 0; i < temp_fds.fd_count; i++)
		{
			current_sock = temp_fds.fd_array[i];
			if (FD_ISSET(current_sock, &temp_fds))
			{
				if (current_sock == serv_sock)
				{
					addr_len = sizeof(client_addr);
					SOCKET client_sock = accept(serv_sock, (SOCKADDR*)&client_addr, &addr_len);
					client_socks[++top] = client_sock;
					FD_SET(client_sock, &read_fds);
				}
				else
				{
					recv(current_sock, buf, BUF_SIZE, 0);

					if (strcmp(buf, "!q") == 0)
					{
						closesocket(current_sock);
						FD_CLR(current_sock, &read_fds);
						break;
					}

					for (int j = 0; j <= top; j++)
						if (current_sock != client_socks[j])
							send(client_socks[j], buf, BUF_SIZE, 0);
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