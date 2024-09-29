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
	SSL* ssl = NULL;

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

					ssl = create_ssl(&client, client_sock, SSLMODE_SERVER);
					printf("ssl, client sock: %p %d\n", ssl, client_sock);
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
					int f = 0;
					if ((f = SSL_read(ssls[index], read_buf, BUF_SIZE)) < 0)
					{
						SSL_read_fail(current_sock);
						continue;
					}
					printf("read buf : %s\n", read_buf);
					printf("ssl_read return : %d\n", f);

					//������.
					attach_noti(write_buf, read_buf, current_sock);
					if (is_init(read_buf)) {
						printf("%d client�� TLS ���� �Ϸ�\n", current_sock);
						continue;
					}

					for (int j = 0; j <= top; j++)
					{
						if (client_socks[j] != -1 && current_sock != client_socks[j])
						{
							int write_return = SSL_write(ssls[j], write_buf, BUF_SIZE);
							printf("ssl, , current sock, client sock: %p %d\n", ssls[j], (int)current_sock);
							printf("write return : %d\n", write_return);
							printf("write_buf: %s\n\n", write_buf);
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
