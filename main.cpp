#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
#include <iostream>
#include <string>

#define ICMP_ECHO 8 
#define ICMP_ECHOREPLY 0 
#define ICMP_MIN 8             // minimum 8 byte icmp packet (just header) 

#define STATUS_FAILED 0xFFFF 
#define DEF_PACKET_SIZE 32 
#define MAX_PACKET 1024 

/* The IP header */
typedef struct iphdr
{
	unsigned int h_len : 4;			// length of the header 
	unsigned int version : 4;		// Version of IP 
	unsigned char tos;				// Type of service 
	unsigned short total_len;		// total length of the packet 
	unsigned short ident;			// unique identifier 
	unsigned short frag_and_flags;	// flags 
	unsigned char ttl;
	unsigned char proto;			// protocol (TCP, UDP etc) 
	unsigned short checksum;		// IP checksum 
	unsigned int sourceIP;
	unsigned int destIP;
}IpHeader;

// 
// ICMP header 
// 
typedef struct _ihdr {
	BYTE i_type;     // Тип сообщения
	BYTE i_code;     // Код  /* type sub code */ 
	USHORT i_cksum;  // Контрольная сумма
	USHORT i_id;     // ID
	USHORT i_seq;    // Серийный номер
	ULONG timestamp; // Временная метка
}IcmpHeader;         // ICMP Сообщение включает заголовок и данные

USHORT checkSum(USHORT *, int);
void decodeResponse(char *, const int, struct sockaddr_in *);
void getMAC();
void help();
bool checkInput(std::string , int &);
bool getAddress(char *, SOCKADDR_IN *);
void closeMySocket(const int );

int main (int argc, char **argv)
{
	if (argc < 2) {
		help();
		return 0;
	}

	char *hostname;                  // Хост-имя удаленного компьютера
	int package_emount = 4;          // Число отсылаемых пакетов
	int timeout = 1000;
	int response_timeout = 1000;

	for (auto i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			help();
			return 0;
		}

		if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--destination") == 0) {
			hostname = argv[i + 1];
			i += 1;
		}

		if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--count") == 0) {
			if (checkInput(argv[i + 1], package_emount)) {
				if (package_emount <= 0) package_emount = 4;
			}
			else
				return 1;
			
			i += 1;
		}

		if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timeout") == 0) {
			if (checkInput(argv[i + 1], timeout)) {
				if (timeout <= 0) timeout = 1000;
			}
			else
				return 1;

			i += 1;
		}

		if (strcmp(argv[i], "-rt") == 0 || strcmp(argv[i], "--response_timeout") == 0) {
			if (checkInput(argv[i + 1], response_timeout)) {
				if (response_timeout <= 0) response_timeout = 1000;
			}
			else
				return 1;

			i += 1;
		}
	}

	//Инициализация WinSocket
	WSADATA WSAData;
	if (WSAStartup(MAKEWORD(2, 1), &WSAData) != 0)
	{
		printf("WSAStartup failed: %d\n", GetLastError());
	}

	//Открываем сокет
	/*Создаем "сырой" сокет для его дальнейшего заполнения*/
	int sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (INVALID_SOCKET == sockRaw)
	{
		printf("WSASocket() failed: %d\n", GetLastError());
	}

	//Устанавливаем таймаут (в милисекундах) на прием / отправку ICMP пакета
	int bread;
	bread = setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&response_timeout, sizeof(response_timeout));
	if (SOCKET_ERROR == bread)
	{
		printf("failed to set send timeout: %d\n", GetLastError());

		// закрываем сокет
		closeMySocket(sockRaw);

		return 0;
	}

	bread = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, 
		(char*)&response_timeout, sizeof(response_timeout));
	if (SOCKET_ERROR == bread)
	{
		printf("failed to set receive timeout: %d\n", GetLastError());

		// закрываем сокет
		closeMySocket(sockRaw);

		return 0;
	}

	//7. Подготавливаем пакет.
	//***********************************************************************

	//проверка существования введенного хост-имени
	SOCKADDR_IN dest_sin;     // Данные об удаленном хосте
	ZeroMemory(&dest_sin, sizeof(dest_sin));    // обнуляем память

	if (!getAddress(hostname, &dest_sin))
	{
		std::cout << "host name error\n";

		// закрываем сокет
		closeMySocket(sockRaw);

		return 0;
	}

	// **********************************************************************
	char *icmp_data;
	try {
		icmp_data = (char *) ::operator new (MAX_PACKET);
	}
	catch (std::bad_alloc& ex) {
		std::cout << "Caught bad_alloc: " << ex.what() << "\n";
		std::cout << "for icmp_data\n";

		// закрываем сокет
		closeMySocket(sockRaw);

		return -1;
	}

	memset(icmp_data, 0, MAX_PACKET);

	IcmpHeader *icmp_hdr;

	icmp_hdr = (IcmpHeader*)icmp_data;
	// заполняем ICMP заголовка
	icmp_hdr->i_type = ICMP_ECHO;                   // тип отправляемого сообщения
	icmp_hdr->i_code = 0;                           // код отправляемого сообщения
	icmp_hdr->i_id = (USHORT)GetCurrentProcessId(); // в id ICMP заголовка заносим номер текущего процесса
	icmp_hdr->i_cksum = 0;                          // обнуляем тестовую сумму
	icmp_hdr->i_seq = 0;                            // обнуляем номер ICMP сообщения

	char *datapart = icmp_data + sizeof(IcmpHeader);
	// Заполняем чем-нибудь буфер для отправки.
	const int DATA_SIZE = DEF_PACKET_SIZE;
	memset(datapart, 'm', DATA_SIZE - sizeof(IcmpHeader));

	//8. Выполняем ping.
	// **********************************************************
	char *recvbuf;                          // буфер присланных сообщений
	try {
		recvbuf = (char *) ::operator new (MAX_PACKET);
	}
	catch (std::bad_alloc& ex) {
		std::cout << "Caught bad_alloc: " << ex.what() << "\n";
		std::cout << "for packet counter\n";

		// освобождаем память
		::operator delete(icmp_data);

		// закрываем сокет
		closeMySocket(sockRaw);

		return -1;
	}

	SOCKADDR_IN from_sin;		    // Данные о локальном хосте
	int iRecvLen = sizeof(from_sin);
	int bwrote;
	USHORT seq_no = 0;                  // Счетчик пакетов

	while (seq_no < package_emount)     // отправляем n-ое количество пакетов
	{
		// обнуляем проверочную сумму ICMP заголовка
		((IcmpHeader*)icmp_data)->i_cksum = 0;
		// заполняем оставшиеся поля ICMP заголовка
		((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
		((IcmpHeader*)icmp_data)->i_seq = seq_no++;
		// указываем контрольную сумму
		((IcmpHeader*)icmp_data)->i_cksum = checkSum((USHORT*)icmp_data, DATA_SIZE);

		// отсылаем пакет
		bwrote = sendto(sockRaw, icmp_data, DATA_SIZE, 0, 
			(struct sockaddr*)&dest_sin, sizeof(dest_sin));
		if (SOCKET_ERROR == bwrote)
		{
			if (GetLastError() == WSAETIMEDOUT)
			{
				std::cout << "timed out\n";
				continue;
			}
			fprintf(stderr, "sendto failed: %d\n", GetLastError());

			// освобождаем память
			::operator delete(icmp_data);
			::operator delete(recvbuf);

			// закрываем сокет
			closeMySocket(sockRaw);

			return 0;
		}
		if (bwrote < DATA_SIZE)
		{
			fprintf(stdout, "Wrote %d bytes\n", bwrote);
		}
		// принимаем пакет
		bread = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, 
			(struct sockaddr*)&from_sin, &iRecvLen);
		if (SOCKET_ERROR == bread)
		{
			if (GetLastError() == WSAETIMEDOUT)
			{
				std::cout << "timed out\n";
				continue;
			}
			fprintf(stderr, "recvfrom failed: %d\n", GetLastError());

			// освобождаем память
			::operator delete(icmp_data);
			::operator delete(recvbuf);

			// закрываем сокет
			closeMySocket(sockRaw);

			return 0;
		}
		// разбираем полученный пакет
		decodeResponse(recvbuf, bread, &from_sin);
		// Ждем...
		Sleep(timeout);
		// ...продолжаем
	}

	getMAC();
	system("pause");

	//Завершаем работу.
	// освобождаем память
	::operator delete(icmp_data);
	::operator delete(recvbuf);

	// закрываем сокет
	closeMySocket(sockRaw);

	std::cout << "Press ENTER to quit\n";
	std::cin.getline(hostname, 15);
	return 0;
}

/*
Ответ является IP пакетом. ICMP данные находятся в его заголовке
*/
void decodeResponse(char *buf, const int bytes, struct sockaddr_in *from)
{
	IpHeader *iphdr = (IpHeader *)buf;      //Полученные данные представляют собой исходную IP-дейтаграмму.

	const unsigned short IP_HEADER_LENGTH = iphdr->h_len * 4; // number of 32-bit words *4 = bytes 

	char dstAddress[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &from->sin_addr, dstAddress, sizeof(dstAddress));
		
	if (bytes < IP_HEADER_LENGTH + ICMP_MIN)
	{
		if (nullptr != dstAddress)
			printf("Too few bytes from %s\n", dstAddress);
	}

	IcmpHeader *icmphdr = (IcmpHeader*)(buf + IP_HEADER_LENGTH);

	if (3 == icmphdr->i_type)
	{
		if (nullptr != dstAddress)
			printf("network unreachable -- Response from %s.\n", dstAddress);
		return;
	}

	if ((USHORT)GetCurrentProcessId() != icmphdr->i_id)
	{
		fprintf(stderr, "someone else's packet!\n");
		return;
	}
	printf("%d bytes from %s:", bytes, dstAddress);
	printf(" icmp_seq = %d ", icmphdr->i_seq);
	printf(" time: %d ms ", GetTickCount() - icmphdr->timestamp);
	printf(" ttl: %d\n", iphdr->ttl);
}

//Полная проверка ICMP
USHORT checkSum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;

	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}

	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

void getMAC() {
	PIP_ADAPTER_INFO AdapterInfo;

	try {
		AdapterInfo = (IP_ADAPTER_INFO  *) ::operator new (sizeof(IP_ADAPTER_INFO));
	}
	catch (std::bad_alloc) {
		std::cout << "Error allocating memory needed to call GetAdaptersinfo\n";
		return;
	}

	// Make an initial call to GetAdaptersInfo to get 
	// the necessary size into the dwBufLen variable
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		::operator delete(AdapterInfo);
		try {
			AdapterInfo = (IP_ADAPTER_INFO  *) ::operator new (dwBufLen);
		}
		catch (std::bad_alloc) {
			std::cout << "Error allocating memory needed to call GetAdaptersinfo\n";
			return;
		}
	}

	char *mac_address;

	try {
		mac_address = (char *) ::operator new (18);
	}
	catch (std::bad_alloc) {
		std::cout << "Error allocating memory needed to MAC_address\n";
		::operator delete(AdapterInfo);
		return;
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		std::cout << '\n';
		// Получаем указатель на AdapterInfo
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do {
			sprintf(mac_address, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

			// печатаем все адреса
			printf("Address: %s, mac: %s\n\n",
				pAdapterInfo->IpAddressList.IpAddress.String, mac_address);

			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}

	::operator delete(AdapterInfo);
	::operator delete(mac_address);
}

void help() {
	std::cout << "Usage: ping.exe" << " -d <destination ip>\n\n";
	std::cout << "\tAlso you can use: \n" <<
		"\t-c <count of packages>\n" <<
		"\t-d <destination ip>\n" <<
		"\t-t <timeout in ms>\n" <<
		"\t-rt <response_timeout>\n";
}

bool checkInput(std::string param, int &value) {
	std::size_t pos{};
	try
	{
		value = std::stoi(param, &pos);
		if (pos != param.length())
			throw std::invalid_argument("Only digits please!");
	}
	catch (std::invalid_argument const& ex)
	{
		std::cout << "std::invalid_argument::what(): " << ex.what() << '\n';
		return false;
	}
	catch (std::out_of_range const& ex)
	{
		std::cout << "std::out_of_range::what(): " << ex.what() << '\n';
		return false;
	}

	return true;
}

bool getAddress(char *hostname, SOCKADDR_IN *destination_S_I) {
	DWORD dwRetval;
	struct addrinfo          hints;
	struct addrinfo          *result;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;				/* Allow IPv4 */
	hints.ai_socktype = SOCK_STREAM;		/* Datagram socket */
	hints.ai_flags = AI_PASSIVE;			/* For wildcard IP address */
	hints.ai_protocol = IPPROTO_TCP;        /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	dwRetval = getaddrinfo(hostname, NULL, &hints, &result);

	if (0 != dwRetval) {
		printf("getaddrinfo failed with error: %d\n", dwRetval);
		freeaddrinfo(result);
		return false;
	}

	destination_S_I->sin_addr = ((struct sockaddr_in *) result->ai_addr)->sin_addr;
	destination_S_I->sin_family = AF_INET;

	freeaddrinfo(result);
	return true;
}

void  closeMySocket(const int socketRaw) {
	/* winsock requires a special function for sockets */
	shutdown(socketRaw, SD_BOTH);
	closesocket(socketRaw);
	/* clean up winsock */
	WSACleanup();
}
