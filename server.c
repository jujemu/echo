#include "server.h"

int main(void)
{
	//WinSock ���̺귯�� �ʱ�ȭ
	winsock_init();

	//SSL ���̺귯�� �ʱ�ȭ �� cert, key ��������
	ssl_init();

	//������ ���� ����, ���ε�, ��� ����
	SOCKET serv_sock = create_socket();
	bind_sock(serv_sock);
	listen(serv_sock, 10);	

	//������ File Descriptor Set�� ����Ѵ�. -> select �Լ��� ��ϵ� ������ ��ȭ�� ������ �� �ִ�.
	FD_ZERO(&read_fds);
	FD_SET(serv_sock, &read_fds);

	char write_buf[BUF_SIZE] = { 0, };
	char read_buf[BUF_SIZE] = { 0, };
	int fd_num = 0, addr_len = 0;
	SOCKADDR_IN client_addr = { 0, };
	SOCKET current_sock = 0;
	
	while (1)
	{
		//���� ��ϵǾ� �ִ� ��� ������ temp_fds�� �����Ѵ�.
		temp_fds = read_fds;

		//��ȭ�� ���� ������ ������� Blocking�� �ǰ� time out�� ������ �� �ִ�.
		fd_num = select(0, &temp_fds, NULL, NULL, NULL);

		for (int i = 0; i < temp_fds.fd_count; i++)
		{
			current_sock = temp_fds.fd_array[i];
			if (FD_ISSET(current_sock, &temp_fds))
			{
				//������ ������ Ȱ��ȭ�Ǿ��ٴ� ���� Ŭ���̾�Ʈ �������κ��� ���� ��û�� �Դٴ� �ǹ�
				//���ϰ� ������ SSL�� �����ϰ�, ���� �迭�� ���� �ε����� SSL�� �߰��Ѵ�.
				if (current_sock == serv_sock)
				{
					addr_len = sizeof(client_addr);
					SOCKET client_sock = accept(serv_sock, (SOCKADDR*)&client_addr, &addr_len);
					printf("%d ������ ����Ǿ����ϴ�.\n", (int)client_sock);

					SSL* ssl = create_ssl(&client, client_sock, SSLMODE_SERVER);
					push_client_sock(client_sock, ssl);
				}
				//Ŭ���̾�Ʈ ���Ͽ� ��ȭ�� ����
				else
				{
					//���� ������ �ε����� ���� �迭���� ã�´�.
					int size = sizeof(client_socks) / sizeof(SOCKET);
					int index = find_index(client_socks, size, current_sock);
					if (index < 0 || ssls[index] == 0)
						error_stdout("Ŭ���̾�Ʈ ���ϰ� �����Ǵ� SSL�� ã�� �� �����ϴ�.");

					//�а�
					if (SSL_read(ssls[index], read_buf, BUF_SIZE) < 0)
					{
						SSL_read_fail(current_sock);
						break;
					}
					
					const char* http_response = "HTTP/1.1 200 OK\r\n"
						"Content-Type: text/html; charset=UTF-8\r\n"
						"Content-Length: 130\r\n"
						"Connection: close\r\n\r\n"
						"Hello\r\n";

					//������.

					int target = 0;
					char target_s[5] = { "\r\n\r\n" };
					for (int k = 119; k < sizeof(read_buf); k++)
					{
						int flag = 1;
						for (int j = 0; j < sizeof(target_s)-1; j++)
						{
							if (read_buf[k+j] != target_s[j])
							{
								flag = 0;
								break;
							}
						}

						if (flag)
						{
							target = k;
						}
					}

					memmove(read_buf, &read_buf[target], BUF_SIZE);
					read_buf[sizeof(read_buf) - 1] = '\0';

					attach_noti(write_buf, read_buf, current_sock);
					for (int j = 0; j <= top; j++)
						//if (client_socks[j] > 0 && current_sock != client_socks[j])
							//SSL_write(ssls[j], http_response, sizeof(http_response));
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
