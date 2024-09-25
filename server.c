#include "server.h"

int main(void)
{
	//WinSock 라이브러리 초기화
	winsock_init();

	//SSL 라이브러리 초기화 및 cert, key 가져오기
	ssl_init();

	//리스닝 소켓 생성, 바인드, 대기 상태
	SOCKET serv_sock = create_socket();
	bind_sock(serv_sock);
	listen(serv_sock, 10);

	//소켓을 File Descriptor Set에 등록한다. -> select 함수로 등록된 소켓의 변화를 감지할 수 있다.
	FD_ZERO(&read_fds);
	FD_SET(serv_sock, &read_fds);

	char write_buf[BUF_SIZE] = { 0, };
	char read_buf[BUF_SIZE] = { 0, };
	int fd_num = 0, addr_len = 0;
	SOCKADDR_IN client_addr = { 0, };
	SOCKET current_sock = 0;

	while (1)
	{
		//현재 등록되어 있는 모든 소켓을 temp_fds에 복사한다.
		temp_fds = read_fds;

		//변화가 생길 때까지 스레드는 Blocking이 되고 time out을 지정할 수 있다.
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

					SSL* ssl = create_ssl(&client, client_sock, SSLMODE_SERVER);
					push_client_sock(client_sock, ssl);
				}
				//클라이언트 소켓에 변화를 감지
				else
				{
					//현재 소켓의 인덱스를 소켓 배열에서 찾는다.
					int size = sizeof(client_socks) / sizeof(SOCKET);
					int index = find_index(client_socks, size, current_sock);
					if (index < 0 || ssls[index] == 0)
						error_stdout("클라이언트 소켓과 대응되는 SSL을 찾을 수 없습니다.");

					//읽고
					if (SSL_read(ssls[index], read_buf, BUF_SIZE) < 0)
					{
						SSL_read_fail(current_sock);
						break;
					}

					//보낸다.
					attach_noti(write_buf, read_buf, current_sock);
					for (int j = 0; j <= top; j++)
						//if (client_socks[j] != -1 && current_sock != client_socks[j])
							SSL_write(ssls[j], write_buf, BUF_SIZE);
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
