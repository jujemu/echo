#include "server.h"

int main(void)
{
	char ssl_write_buf[BUF_SIZE] = { 0, };
	char std_read_buf[BUF_SIZE] = { 0, };
	int fd_num = 0;
	int addr_len = 0;
	SOCKET serv_sock = 0;
	SOCKET current_sock = 0;
	SOCKADDR_IN client_addr = { 0, };
	SSL* ssl = NULL;

	//WinSock 라이브러리 초기화
	winsock_init();

	//SSL 라이브러리 초기화 및 cert, key 가져오기
	ssl_init();

	//리스닝 소켓 생성, 바인드, 리슨
	serv_sock = create_socket();
	bind_sock(serv_sock);
	listen(serv_sock, 10);
	printf("서버 소켓 %d가 정상적으로 생성되어 bind 후 listen 상태입니다.\n\n", (int)serv_sock);

	//소켓을 File Descriptor Set에 등록한다. -> select 함수로 등록된 소켓의 변화를 감지할 수 있다.
	FD_ZERO(&read_fds);
	FD_SET(serv_sock, &read_fds);

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
					ssl = create_ssl(&client, client_sock, SSLMODE_SERVER);
					printf("%d 소켓과 연결되었습니다.\n", (int)client_sock);
					
					push_client_sock(client_sock, ssl);
				}
				//클라이언트 소켓에 변화를 감지
				else
				{
					//현재 소켓의 인덱스를 소켓 배열에서 찾는다.
					int socket_size = sizeof(client_socks) / sizeof(SOCKET);
					int index = find_index(client_socks, socket_size, current_sock);
					if (index < 0 || ssls[index] == 0)
						error_stdout("클라이언트 소켓과 대응되는 SSL을 찾을 수 없습니다.");

					//읽고
					int ssl_read_return = SSL_read(ssls[index], std_read_buf, BUF_SIZE);
					if (ssl_read_return < 0)
					{
						//SSL_read에서 음수의 응답을 받으면 클라이언트 소켓과 연결이 해제되었음을 의미한다.
						//연결된 소켓을 회수한다.
						SSL_read_fail(current_sock);
						printf("Socket %d와 연결이 해제되었습니다.\n\n", (int)current_sock);
						continue;
					}

					//클라이언트와 TLS 연결을 완료하기 위한 init 메시지 처리
					if (is_init(std_read_buf))
					{
						printf("%d client와 TLS 연결 완료\n\n", (int)current_sock);
						continue;
					}

					printf("ssl_read return : %d\n", ssl_read_return);
					printf("read buf : %s\n", std_read_buf);

					//보낸다.
					attach_noti(ssl_write_buf, std_read_buf, current_sock);

					for (int j = 0; j <= top; j++)
					{
						if (client_socks[j] != -1 && current_sock != client_socks[j])
						{
							int write_return = SSL_write(ssls[j], ssl_write_buf, BUF_SIZE);
							printf("ssl, , current sock, client sock: %p %d\n", ssls[j], (int)current_sock);
							printf("write return : %d\n", write_return);
							printf("write_buf: %s\n\n", ssl_write_buf);
						}
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
