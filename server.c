#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>

#define BUF_SIZE 256

int main(int argc, char* argv[])
{
    char buf[BUF_SIZE];

    WSADATA wsaData;
    SOCKET listen_sock, data_sock;
    SOCKADDR_IN servAddr, clntAddr;

    // ��Ʈ �Է� �ޱ�
    if (argc != 2)
    {
        printf("give me port\n");
        exit(1);
    }
    int port = atoi(argv[1]);

    // TCP ���� ����
    WSAStartup(MAKEWORD(2, 0), &wsaData);
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET)
    {
        printf("Creating socket fails");
        exit(1);
    }

    // ���Ͽ� �ʿ��� ip�ּ�, ��Ʈ ���ε�
    memset(&servAddr, 0, sizeof(servAddr)); // �ּ� �ʱ�ȭ
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port); // 16��Ʈ
    if (bind(listen_sock, (SOCKADDR*)&servAddr, sizeof(servAddr)) == SOCKET_ERROR)
    {
        printf("Binding fails");
        closesocket(listen_sock);
        WSACleanup();
        exit(1);
    }

    listen(listen_sock, 10);

    // Ŭ���̾�Ʈ�� ��û�� �ް� �����͸� �ۼ����� ������ ����
    // accept�� �Լ��� Blocking �̱� ������ ���� ��û�� ���� ������ �����ִ�.
    printf("waiting for request of client.\n");
    int size_clntAddr = sizeof(clntAddr);
    data_sock = accept(listen_sock, (SOCKADDR*)&clntAddr, &size_clntAddr);
    printf("Connection is created.\n");

    // echo
    char msg[] = "Connection is complete. To close this socket, send me !q\n";
    send(data_sock, msg, sizeof(msg), 0);
    while (1)
    {
        recv(data_sock, buf, BUF_SIZE, 0);
        printf("%s\n", buf);
        if (strcmp(buf, "!q") == 0)
            break;
        send(data_sock, buf, BUF_SIZE, 0);
        send(data_sock, "\n\n", BUF_SIZE, 0);
    }

    closesocket(listen_sock);
    closesocket(data_sock);
    WSACleanup();

    return 0;
}