#pragma comment(lib, "ws2_32")
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <Windows.h>

#define BUF_SIZE 256

DWORD WINAPI thread_func(void* param);
void goto_xy(int, int);
COORD get_current_cursor();
void set_send_cursor();
void clean_send_message(COORD cursorPos, int length);

SOCKET client_sock;

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("ip주소와 port 번호가 주어져야합니다.");
		exit(1);
	}
	int port = atoi(argv[2]);
	char addr[16];
	strncpy_s(addr, sizeof(addr) - 1, argv[1], sizeof(addr)-1);
	addr[sizeof(addr) - 1] = '\0';

	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2, 0), &wsa_data);
	
	client_sock = socket(AF_INET, SOCK_STREAM, 0);

	SOCKADDR_IN serv_addr;
	serv_addr.sin_family = AF_INET;
	inet_pton(AF_INET, addr, &serv_addr.sin_addr.s_addr);
	serv_addr.sin_port = htons(port);
	int connect_status = connect(client_sock, (SOCKADDR*)&serv_addr, sizeof(serv_addr));
	if (connect_status < 0)
	{
		printf("클라이언트가 서버와 소켓 연결에 실패했습니다.\n");
		exit(1);
	}

	HANDLE read_thread = CreateThread(NULL, 0, thread_func, NULL, 0, NULL);

	char buf[BUF_SIZE];
	while (1)
	{
		set_send_cursor();
		COORD cursorPos = get_current_cursor();
		printf("%s", "> ");
		gets_s(buf, BUF_SIZE);
		send(client_sock, buf, BUF_SIZE, 0);
		clean_send_message(cursorPos, strlen(buf)+3);
		if (strcmp(buf, "!q") == 0)
			break;
	}

	closesocket(client_sock);
	WSACleanup();

	return 0;
}

DWORD WINAPI thread_func(void* param) {
	char echo[BUF_SIZE];
	while (1) {
		if (recv(client_sock, echo, BUF_SIZE, 0) <= 0)
			exit(1);
		goto_xy(0, 0);
		printf("%s\n", echo);
	}
}

void goto_xy(int x, int y)
{
	COORD Pos;
	Pos.X = x;
	Pos.Y = y;
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), Pos);
}

COORD get_current_cursor() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
	return consoleInfo.dwCursorPosition;
}

void set_send_cursor() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (GetConsoleScreenBufferInfo(hConsole, &consoleInfo)) {
		goto_xy(0, consoleInfo.srWindow.Bottom - consoleInfo.srWindow.Top - 1);
	}
	else {
		printf("Failed to get console buffer info\n");
	}
}

void clean_send_message(COORD cursorPos, int length) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD written;

	FillConsoleOutputCharacter(hConsole, ' ', length, cursorPos, &written);
}