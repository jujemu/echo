#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <Windows.h>

#define BUF_SIZE 256

int main(int argc, char* argv[])
{
    char buf[BUF_SIZE] = { 0 };
    char output[BUF_SIZE] = { "Hello, " };

    WSADATA wsaData;
    SOCKET client_sock;
    SOCKADDR_IN server_addr;

    // ������ ������ ip �ּ�, port number �ޱ�
    if (argc != 3)
    {
        printf("give me ip address, port of server\n");
        exit(1);
    }
    int port = atoi(argv[2]);

    // TCP ���� ����
    WSAStartup(MAKEWORD(2, 0), &wsaData);
    client_sock = socket(AF_INET, SOCK_STREAM, 0);
    printf("Socket is created.\n");

    // ���� ���ϰ� ����
    //memset((char*)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr.s_addr);
    server_addr.sin_port = htons(port); // 16��Ʈ
    if (connect(client_sock, (SOCKADDR*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        printf("Connection fails\n");
        closesocket(client_sock);
        WSACleanup();
        exit(1);
    }

    Sleep(1000);
    recv(client_sock, output, BUF_SIZE, 0);
    printf("%s", output);

    // �޼��� ������
    while (1)
    {
        printf("%c", '>');
        memset(buf, 0, BUF_SIZE);
        gets_s(buf, BUF_SIZE);
        send(client_sock, buf, BUF_SIZE, 0);
        if (strcmp(buf, "!q") == 0)
            break;

        // ���� ������ �ٽ� �޴´�.
        while (1)
        {
            recv(client_sock, output, BUF_SIZE, 0);
            if (strncmp(output, "\n\n", 2) == 0)
                break;
            printf("%s\n", output);
        }
    }

    closesocket(client_sock);
    WSACleanup();

    return 0;
}