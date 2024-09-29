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

	//WinSock ���̺귯�� �ʱ�ȭ
	winsock_init();

	//SSL ���̺귯�� �ʱ�ȭ �� cert, key ��������
	ssl_init();

	//������ ���� ����, ���ε�, ����
	serv_sock = create_socket();
	bind_sock(serv_sock);
	listen(serv_sock, 10);
	printf("���� ���� %d�� ���������� �����Ǿ� bind �� listen �����Դϴ�.\n\n", (int)serv_sock);

	//������ File Descriptor Set�� ����Ѵ�. -> select �Լ��� ��ϵ� ������ ��ȭ�� ������ �� �ִ�.
	FD_ZERO(&read_fds);
	FD_SET(serv_sock, &read_fds);

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
					ssl = create_ssl(&client, client_sock, SSLMODE_SERVER);
					printf("%d ���ϰ� ����Ǿ����ϴ�.\n", (int)client_sock);
					
					push_client_sock(client_sock, ssl);
				}
				//Ŭ���̾�Ʈ ���Ͽ� ��ȭ�� ����
				else
				{
					//���� ������ �ε����� ���� �迭���� ã�´�.
					int socket_size = sizeof(client_socks) / sizeof(SOCKET);
					int index = find_index(client_socks, socket_size, current_sock);
					if (index < 0 || ssls[index] == 0)
						error_stdout("Ŭ���̾�Ʈ ���ϰ� �����Ǵ� SSL�� ã�� �� �����ϴ�.");

					//�а�
					int ssl_read_return = SSL_read(ssls[index], std_read_buf, BUF_SIZE);
					if (ssl_read_return < 0)
					{
						//SSL_read���� ������ ������ ������ Ŭ���̾�Ʈ ���ϰ� ������ �����Ǿ����� �ǹ��Ѵ�.
						//����� ������ ȸ���Ѵ�.
						SSL_read_fail(current_sock);
						printf("Socket %d�� ������ �����Ǿ����ϴ�.\n\n", (int)current_sock);
						continue;
					}

					//Ŭ���̾�Ʈ�� TLS ������ �Ϸ��ϱ� ���� init �޽��� ó��
					if (is_init(std_read_buf))
					{
						printf("%d client�� TLS ���� �Ϸ�\n\n", (int)current_sock);
						continue;
					}

					printf("ssl_read return : %d\n", ssl_read_return);
					printf("read buf : %s\n", std_read_buf);

					//������.
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
