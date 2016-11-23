#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>

#include "windivert.h"

int main(void)
{
	int i;
	HANDLE handle;

	char *filter = "tcp.DstPort == 80 or tcp.SrcPort == 80";
	
	handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("WinDivertOpen Error: %d\n", GetLastError());
		exit(EXIT_FAILURE);
	}

	char pPacket[0xFFFF];

	WINDIVERT_ADDRESS pAddr;

	UINT packetLen;

	PWINDIVERT_IPHDR ppIpHdr;
	PWINDIVERT_IPV6HDR ppIpv6Hdr;
	PWINDIVERT_ICMPHDR ppIcmpHdr;
	PWINDIVERT_ICMPV6HDR ppIcmpv6Hdr;
	PWINDIVERT_TCPHDR ppTcpHdr;
	PWINDIVERT_UDPHDR ppUdpHdr;
	PVOID ppData;
	UINT pDataLen;

	bool flag = false;

	UINT writeLen;
	while (1)
	{
		if (WinDivertRecv(handle, pPacket, sizeof(pPacket), &pAddr, &packetLen) == 0)
		{
			printf("WinDivertRecv Error: %d\n", GetLastError());
			exit(EXIT_FAILURE);
		}

		WinDivertHelperParsePacket(pPacket, packetLen, &ppIpHdr, &ppIpv6Hdr, &ppIcmpHdr, &ppIcmpv6Hdr,
			&ppTcpHdr, &ppUdpHdr, &ppData, &pDataLen);

		if ((pAddr.Direction == WINDIVERT_DIRECTION_OUTBOUND) && (pDataLen >= 4))
		{
			for (i = 0; i <= pDataLen - 4; i++)
			{
				if (strncmp((const char *)ppData + i, "gzip", 4) == 0)
				{
					memset((unsigned char *)ppData + i, ' ', 4);
					flag = true;
				}
			}

			if (flag == false)
			{
				printf("gzip > "    " 실패\n");
			}
		}

		if ((pAddr.Direction == WINDIVERT_DIRECTION_INBOUND) && pDataLen >= 7)
		{
			for (i = 0; i <= pDataLen - 7; i++)
			{
				if (strncmp((const char *)ppData + i, "Michael", 7) == 0)
				{
					memcpy((char *)ppData + i, "Uihyeon", 7);
					flag = false;
				}					
			}
			if (flag == false)
			{
				printf("Michael > Uihyeon 성공\n");
			}
			else 
			{
				printf("Michael > Uihyeon 실패\n");
			}
		}

		printf("packetLen: %d\n", packetLen);

		WinDivertHelperCalcChecksums(pPacket, packetLen, 0);

		WinDivertSend(handle, pPacket, packetLen, &pAddr, &writeLen);
	}

	return 0;
}


