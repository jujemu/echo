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

    // 포트 입력 받기
    if (argc != 2)
    {
        printf("give me port\n");
        exit(1);
    }
    int port = atoi(argv[1]);

    // TCP 소켓 생성
    WSAStartup(MAKEWORD(2, 0), &wsaData);
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET)
    {
        printf("Creating socket fails");
        exit(1);
    }

    // 소켓에 필요한 ip주소, 포트 바인딩
    memset(&servAddr, 0, sizeof(servAddr)); // 주소 초기화
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port); // 16비트
    if (bind(listen_sock, (SOCKADDR*)&servAddr, sizeof(servAddr)) == SOCKET_ERROR)
    {
        printf("Binding fails");
        closesocket(listen_sock);
        WSACleanup();
        exit(1);
    }

    listen(listen_sock, 10);

    // 클라이언트의 요청을 받고 데이터를 송수신할 소켓을 생성
    // accept는 함수는 Blocking 이기 때문에 연결 요청을 받을 때까지 멈춰있다.
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