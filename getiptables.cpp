// A simple program to dump TCP/UDP table information as consumable JSON.
//
// (C) 2021 CubicleSoft.  All Rights Reserved.

#define UNICODE
#define _UNICODE
#define _CRT_SECURE_NO_WARNINGS

#ifdef _MBCS
#undef _MBCS
#endif

#include <cstdio>
#include <cstdlib>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <tchar.h>

#include "utf8/utf8_util.h"
#include "utf8/utf8_file_dir.h"
#include "utf8/utf8_mixed_var.h"
#include "json/json_serializer.h"
#include "network/network_init.h"

// Initialize networking.
CubicleSoft::Network::Init GxNetworkInit;

#ifdef SUBSYSTEM_WINDOWS
// If the caller is a console application and is waiting for this application to complete, then attach to the console.
void InitVerboseMode(void)
{
	if (::AttachConsole(ATTACH_PARENT_PROCESS))
	{
		if (::GetStdHandle(STD_OUTPUT_HANDLE) != INVALID_HANDLE_VALUE)
		{
			freopen("CONOUT$", "w", stdout);
			setvbuf(stdout, NULL, _IONBF, 0);
		}

		if (::GetStdHandle(STD_ERROR_HANDLE) != INVALID_HANDLE_VALUE)
		{
			freopen("CONOUT$", "w", stderr);
			setvbuf(stderr, NULL, _IONBF, 0);
		}
	}
}
#endif

void DumpSyntax(TCHAR *currfile)
{
#ifdef SUBSYSTEM_WINDOWS
	InitVerboseMode();
#endif

	_tprintf(_T("(C) 2021 CubicleSoft.  All Rights Reserved.\n\n"));

	_tprintf(_T("Syntax:  %s [options]\n\n"), currfile);

	_tprintf(_T("Options:\n"));

	_tprintf(_T("\t/v\n\
\tVerbose mode.\n\
\n\
\t/tcponly\n\
\tOnly output TCP table information.\n\
\tIncompatible with 'udponly'.\n\
\n\
\t/udponly\n\
\tOnly output UDP table information.\n\
\tIncompatible with 'tcponly'.\n\
\n\
\t/state=State\n\
\tOnly output table information for the specified state.\n\
\tMap only be one of:\n\
\t\tCLOSED\n\
\t\tLISTEN\n\
\t\tSYN-SENT\n\
\t\tSYN-RECEIVED\n\
\t\tESTABLISHED\n\
\t\tFIN-WAIT-1\n\
\t\tFIN-WAIT-2\n\
\t\tCLOSE-WAIT\n\
\t\tCLOSING\n\
\t\tLAST-ACK\n\
\t\tTIME-WAIT\n\
\t\tDELETE-TCB\n\
\n\
\t/localip=IPAddr\n\
\tOnly output table information for the specified local IP address.\n\
\n\
\t/localport=PortNum\n\
\tOnly output table information for the specified local port number.\n\
\n\
\t/remoteip=IPAddr\n\
\tOnly output table information for the specified remote IP address.\n\
\n\
\t/remoteport=PortNum\n\
\tOnly output table information for the specified remote port number.\n\
\n\
\t/sort\n\
\tSort the output.\n\
\n\
\t/file=OutputFile\n\
\tFile to write the JSON output to instead of stdout.\n\n"));

#ifdef SUBSYSTEM_WINDOWS
	_tprintf(_T("\t/attach\n"));
	_tprintf(_T("\tAttempt to attach to a parent console if it exists.\n\n"));
#endif
}


void DumpOutput(CubicleSoft::UTF8::File &OutputFile, CubicleSoft::JSON::Serializer &OutputJSON)
{
	size_t y;

	if (OutputFile.IsOpen())  OutputFile.Write((std::uint8_t *)OutputJSON.GetBuffer(), OutputJSON.GetCurrPos(), y);
	else  printf("%s", OutputJSON.GetBuffer());

	OutputJSON.ResetPos();
}

void DumpWinError(CubicleSoft::JSON::Serializer &OutputJSON, DWORD winerror)
{
	LPTSTR errmsg = NULL;
	CubicleSoft::UTF8::UTF8MixedVar<char[8192]> TempVar;

	::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, winerror, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&errmsg, 0, NULL);

	if (errmsg == NULL)  OutputJSON.AppendStr("winerror", "Unknown Windows error message.");
	else
	{
		TempVar.SetUTF8(errmsg);
		OutputJSON.AppendStr("winerror", TempVar.GetStr());

		::LocalFree(errmsg);
	}
}

void DumpErrorMsg(CubicleSoft::UTF8::File &OutputFile, CubicleSoft::JSON::Serializer &OutputJSON, const char *errorstr, const char *errorcode, DWORD winerror)
{
	OutputJSON.AppendBool("success", false);
	OutputJSON.AppendStr("error", errorstr);
	OutputJSON.AppendStr("errorcode", errorcode);
	DumpWinError(OutputJSON, winerror);
	OutputJSON.AppendUInt("winerrorcode", winerror);

	DumpOutput(OutputFile, OutputJSON);
}

bool IP4AddrMatches(struct addrinfo *ipptr, u_long addr)
{
	while (ipptr != NULL)
	{
		if (ipptr->ai_family == AF_INET && ((struct sockaddr_in *)ipptr->ai_addr)->sin_addr.S_un.S_addr == addr)  return true;

		ipptr = ipptr->ai_next;
	}

	return false;
}

bool IP6AddrMatches(struct addrinfo *ipptr, struct in6_addr addr)
{
	while (ipptr != NULL)
	{
		if (ipptr->ai_family == AF_INET6 && !memcmp(&((struct sockaddr_in6 *)ipptr->ai_addr)->sin6_addr, &addr, sizeof(struct in6_addr)))  return true;

		ipptr = ipptr->ai_next;
	}

	return false;
}

void AppendTCPState(CubicleSoft::JSON::Serializer &OutputJSON, DWORD state)
{
	switch (state)
	{
		case MIB_TCP_STATE_CLOSED:  OutputJSON.AppendStr("state", "CLOSED");  break;
		case MIB_TCP_STATE_LISTEN:  OutputJSON.AppendStr("state", "LISTEN");  break;
		case MIB_TCP_STATE_SYN_SENT:  OutputJSON.AppendStr("state", "SYN-SENT");  break;
		case MIB_TCP_STATE_SYN_RCVD:  OutputJSON.AppendStr("state", "SYN-RECEIVED");  break;
		case MIB_TCP_STATE_ESTAB:  OutputJSON.AppendStr("state", "ESTABLISHED");  break;
		case MIB_TCP_STATE_FIN_WAIT1:  OutputJSON.AppendStr("state", "FIN-WAIT-1");  break;
		case MIB_TCP_STATE_FIN_WAIT2:  OutputJSON.AppendStr("state", "FIN-WAIT-2");  break;
		case MIB_TCP_STATE_CLOSE_WAIT:  OutputJSON.AppendStr("state", "CLOSE-WAIT");  break;
		case MIB_TCP_STATE_CLOSING:  OutputJSON.AppendStr("state", "CLOSING");  break;
		case MIB_TCP_STATE_LAST_ACK:  OutputJSON.AppendStr("state", "LAST-ACK");  break;
		case MIB_TCP_STATE_TIME_WAIT:  OutputJSON.AppendStr("state", "TIME-WAIT");  break;
		case MIB_TCP_STATE_DELETE_TCB:  OutputJSON.AppendStr("state", "DELETE-TCB");  break;
		default:
		{
			OutputJSON.AppendStr("state", "UNKNOWN");
			OutputJSON.AppendUInt("state_val", state);

			break;
		}
	}
}

void AppendTCPOffloadState(CubicleSoft::JSON::Serializer &OutputJSON, DWORD state)
{
	switch (state)
	{
		case TcpConnectionOffloadStateInHost:  OutputJSON.AppendStr("offload_state", "InHost");  break;
		case TcpConnectionOffloadStateOffloading:  OutputJSON.AppendStr("offload_state", "Offloading");  break;
		case TcpConnectionOffloadStateOffloaded:  OutputJSON.AppendStr("offload_state", "Offloaded");  break;
		case TcpConnectionOffloadStateUploading:  OutputJSON.AppendStr("offload_state", "Uploading");  break;
		default:
		{
			OutputJSON.AppendStr("state", "UNKNOWN");
			OutputJSON.AppendUInt("state_val", state);

			break;
		}
	}
}

enum IPTablesMode
{
	TCPUDPMode,
	TCPMode,
	UDPMode
};

int _tmain(int argc, TCHAR **argv)
{
	bool verbose = false;
	IPTablesMode mode = TCPUDPMode;
	bool states[MIB_TCP_STATE_DELETE_TCB + 1] = { false };
	bool usestates = false;
	struct addrinfo hints, *localip = NULL, *remoteip = NULL;
	DWORD localport = (DWORD)-1, remoteport = (DWORD)-1;
	BOOL sort = FALSE;
	LPTSTR filename = NULL;
	int result = 0;
	const char *errorstr = NULL, *errorcode = NULL;
	DWORD winerror;

	CubicleSoft::UTF8::UTF8MixedVar<char[8192]> TempVar;

	// Process command-line options.
	int x;
	for (x = 1; x < argc; x++)
	{
		if (!_tcsicmp(argv[x], _T("/v")))  verbose = true;
		else if (!_tcsicmp(argv[x], _T("/?")) || !_tcsicmp(argv[x], _T("/h")))
		{
			DumpSyntax(argv[0]);

			return 1;
		}
		else if (!_tcsicmp(argv[x], _T("/tcponly")))  mode = TCPMode;
		else if (!_tcsicmp(argv[x], _T("/udponly")))  mode = UDPMode;
		else if (!_tcsncicmp(argv[x], _T("/state="), 7))
		{
			int statenum = -1;

			if (!_tcsicmp(argv[x] + 7, _T("CLOSED")))  statenum = MIB_TCP_STATE_CLOSED;
			else if (!_tcsicmp(argv[x] + 7, _T("LISTEN")))  statenum = MIB_TCP_STATE_LISTEN;
			else if (!_tcsicmp(argv[x] + 7, _T("SYN-SENT")))  statenum = MIB_TCP_STATE_SYN_SENT;
			else if (!_tcsicmp(argv[x] + 7, _T("SYN-RECEIVED")))  statenum = MIB_TCP_STATE_SYN_RCVD;
			else if (!_tcsicmp(argv[x] + 7, _T("ESTABLISHED")))  statenum = MIB_TCP_STATE_ESTAB;
			else if (!_tcsicmp(argv[x] + 7, _T("FIN-WAIT-1")))  statenum = MIB_TCP_STATE_FIN_WAIT1;
			else if (!_tcsicmp(argv[x] + 7, _T("FIN-WAIT-2")))  statenum = MIB_TCP_STATE_FIN_WAIT2;
			else if (!_tcsicmp(argv[x] + 7, _T("CLOSE-WAIT")))  statenum = MIB_TCP_STATE_CLOSE_WAIT;
			else if (!_tcsicmp(argv[x] + 7, _T("CLOSING")))  statenum = MIB_TCP_STATE_CLOSING;
			else if (!_tcsicmp(argv[x] + 7, _T("LAST-ACK")))  statenum = MIB_TCP_STATE_LAST_ACK;
			else if (!_tcsicmp(argv[x] + 7, _T("TIME-WAIT")))  statenum = MIB_TCP_STATE_TIME_WAIT;
			else if (!_tcsicmp(argv[x] + 7, _T("DELETE-TCB")))  statenum = MIB_TCP_STATE_DELETE_TCB;

			if (statenum > -1)
			{
				states[statenum] = true;
				usestates = true;
			}
		}
		else if (!_tcsncicmp(argv[x], _T("/localip="), 9))
		{
			TempVar.SetUTF8(argv[x] + 9);

			::ZeroMemory(&hints, sizeof(hints));
			hints.ai_flags = AI_NUMERICHOST;
			hints.ai_family = AF_UNSPEC;

			if (::getaddrinfo(TempVar.MxStr, NULL, &hints, &localip) != 0)
			{
				errorstr = "Unable to convert/parse local IP address.";
				errorcode = "invalid_local_ip";
				winerror = ::WSAGetLastError();
			}
		}
		else if (!_tcsncicmp(argv[x], _T("/localport="), 11))  localport = (DWORD)_tstoi(argv[x] + 11);
		else if (!_tcsncicmp(argv[x], _T("/remoteip="), 10))
		{
			TempVar.SetUTF8(argv[x] + 10);

			::ZeroMemory(&hints, sizeof(hints));
			hints.ai_flags = AI_NUMERICHOST;
			hints.ai_family = AF_UNSPEC;

			if (::getaddrinfo(TempVar.MxStr, NULL, &hints, &remoteip) != 0)
			{
				errorstr = "Unable to convert/parse remote IP address.";
				errorcode = "invalid_remote_ip";
				winerror = ::WSAGetLastError();
			}
		}
		else if (!_tcsncicmp(argv[x], _T("/remoteport="), 12))  remoteport = (DWORD)_tstoi(argv[x] + 12);
		else if (!_tcsicmp(argv[x], _T("/sort")))  sort = TRUE;
		else if (!_tcsncicmp(argv[x], _T("/file="), 6))  filename = argv[x] + 6;
		else if (!_tcsicmp(argv[x], _T("/attach")))
		{
#ifdef SUBSYSTEM_WINDOWS
			// For the Windows subsystem only, attempt to attach to a parent console if it exists.
			InitVerboseMode();
#endif
		}
		else
		{
			// Probably reached the command to execute portion of the arguments.
			break;
		}
	}

	if (verbose)
	{
#ifdef SUBSYSTEM_WINDOWS
		InitVerboseMode();
#endif

		_tprintf(_T("Arguments:\n"));
		for (int x2 = 0; x2 < argc; x2++)
		{
			_tprintf(_T("\targv[%d] = %s\n"), x2, argv[x2]);
		}
		_tprintf(_T("\n"));
	}

	// Handle output to a file.
	CubicleSoft::UTF8::File OutputFile;
	size_t y;
	if (filename != NULL)
	{
		TempVar.SetUTF8(filename);
		if (!OutputFile.Open(TempVar.GetStr(), O_CREAT | O_WRONLY | O_TRUNC))
		{
#ifdef SUBSYSTEM_WINDOWS
			InitVerboseMode();
#endif

			_tprintf(_T("Unable to open '%s' for writing.\n"), filename);

			return 1;
		}
	}

	char outputbuffer[4096];
	CubicleSoft::JSON::Serializer OutputJSON;

	OutputJSON.SetBuffer((std::uint8_t *)outputbuffer, sizeof(outputbuffer));
	OutputJSON.StartObject();

	if (errorstr != NULL)
	{
		DumpErrorMsg(OutputFile, OutputJSON, errorstr, errorcode, winerror);

		result = 1;
	}
	else
	{
		OutputJSON.AppendBool("success", true);

		ULONG tablesize = 65536, tablesize2;
		char *tablebuffer = new char[tablesize];
		sockaddr_in ip4addr = { AF_INET, 0 };
		sockaddr_in6 ip6addr = { AF_INET6, 0 };
		u_short localport2, remoteport2;
		DWORD tempsize;

		if (mode == TCPUDPMode || mode == TCPMode)
		{
			// TCP v4.
			OutputJSON.StartObject("tcp4");

			PMIB_TCPTABLE2 tcptable2ptr = (PMIB_TCPTABLE2)tablebuffer;

			tablesize2 = tablesize;
			while ((winerror = ::GetTcpTable2(tcptable2ptr, &tablesize2, sort)) == ERROR_INSUFFICIENT_BUFFER)
			{
				delete[] tablebuffer;

				tablesize = tablesize2;
				tablebuffer = new char[tablesize];
				tcptable2ptr = (PMIB_TCPTABLE2)tablebuffer;
			}

			if (winerror != NO_ERROR)
			{
				DumpErrorMsg(OutputFile, OutputJSON, "The call to GetTcpTable2 failed.", "get_tcp_table_failed", winerror);

				result = 1;
			}
			else
			{
				OutputJSON.AppendBool("success", true);

				OutputJSON.StartArray("info");

				for (x = 0; x < (int)tcptable2ptr->dwNumEntries; x++)
				{
					localport2 = ::ntohs((u_short)tcptable2ptr->table[x].dwLocalPort);
					remoteport2 = ::ntohs((u_short)tcptable2ptr->table[x].dwRemotePort);

					// Check state, IP addresses, and port numbers for matches.
					if (usestates && !states[tcptable2ptr->table[x].dwState])  continue;
					if (localip != NULL && !IP4AddrMatches(localip, (u_long)tcptable2ptr->table[x].dwLocalAddr))  continue;
					if (localport != (DWORD)-1 && localport != (DWORD)localport2)  continue;
					if (remoteip != NULL && !IP4AddrMatches(remoteip, (u_long)tcptable2ptr->table[x].dwRemoteAddr))  continue;
					if (remoteport != (DWORD)-1 && remoteport != (DWORD)remoteport2)  continue;

					OutputJSON.SetValSplitter(",\n\n");
					OutputJSON.StartObject();
					OutputJSON.SetValSplitter(", ");

					AppendTCPState(OutputJSON, tcptable2ptr->table[x].dwState);

					ip4addr.sin_addr.S_un.S_addr = (u_long)tcptable2ptr->table[x].dwLocalAddr;
					tempsize = TempVar.GetMaxSize();
					if (::WSAAddressToStringA((LPSOCKADDR)&ip4addr, sizeof(ip4addr), NULL, TempVar.GetStr(), &tempsize) == 0)  OutputJSON.AppendStr("local_ip", TempVar.GetStr());
					else  OutputJSON.AppendNull("local_ip");

					OutputJSON.AppendUInt("local_port", localport2);

					ip4addr.sin_addr.S_un.S_addr = (u_long)tcptable2ptr->table[x].dwRemoteAddr;
					tempsize = TempVar.GetMaxSize();
					if (::WSAAddressToStringA((LPSOCKADDR)&ip4addr, sizeof(ip4addr), NULL, TempVar.GetStr(), &tempsize) == 0)  OutputJSON.AppendStr("remote_ip", TempVar.GetStr());
					else  OutputJSON.AppendNull("remote_ip");

					OutputJSON.AppendUInt("remote_port", remoteport2);

					OutputJSON.AppendUInt("pid", tcptable2ptr->table[x].dwOwningPid);

					AppendTCPOffloadState(OutputJSON, tcptable2ptr->table[x].dwOffloadState);

					DumpOutput(OutputFile, OutputJSON);

					OutputJSON.EndObject();
				}

				OutputJSON.EndArray();
			}

			OutputJSON.EndObject();

			// TCP v6.
			OutputJSON.SetValSplitter(",\n\n");
			OutputJSON.StartObject("tcp6");
			OutputJSON.SetValSplitter(", ");

			PMIB_TCP6TABLE2 tcp6table2ptr = (PMIB_TCP6TABLE2)tablebuffer;

			tablesize2 = tablesize;
			while ((winerror = ::GetTcp6Table2(tcp6table2ptr, &tablesize2, sort)) == ERROR_INSUFFICIENT_BUFFER)
			{
				delete[] tablebuffer;

				tablesize = tablesize2;
				tablebuffer = new char[tablesize];
				tcp6table2ptr = (PMIB_TCP6TABLE2)tablebuffer;
			}

			if (winerror != NO_ERROR)
			{
				DumpErrorMsg(OutputFile, OutputJSON, "The call to GetTcp6Table2 failed.", "get_tcp_table_failed", winerror);

				result = 1;
			}
			else
			{
				OutputJSON.AppendBool("success", true);

				OutputJSON.StartArray("info");

				for (x = 0; x < (int)tcp6table2ptr->dwNumEntries; x++)
				{
					localport2 = ::ntohs((u_short)tcp6table2ptr->table[x].dwLocalPort);
					remoteport2 = ::ntohs((u_short)tcp6table2ptr->table[x].dwRemotePort);

					// Check state, IP addresses, and port numbers for matches.
					if (usestates && !states[tcp6table2ptr->table[x].State])  continue;
					if (localip != NULL && !IP6AddrMatches(localip, tcp6table2ptr->table[x].LocalAddr))  continue;
					if (localport != (DWORD)-1 && localport != (DWORD)localport2)  continue;
					if (remoteip != NULL && !IP6AddrMatches(remoteip, tcp6table2ptr->table[x].RemoteAddr))  continue;
					if (remoteport != (DWORD)-1 && remoteport != (DWORD)remoteport2)  continue;

					OutputJSON.SetValSplitter(",\n\n");
					OutputJSON.StartObject();
					OutputJSON.SetValSplitter(", ");

					AppendTCPState(OutputJSON, tcp6table2ptr->table[x].State);

					ip6addr.sin6_addr = (in6_addr)tcp6table2ptr->table[x].LocalAddr;
					tempsize = TempVar.GetMaxSize();
					if (::WSAAddressToStringA((LPSOCKADDR)&ip6addr, sizeof(ip6addr), NULL, TempVar.GetStr(), &tempsize) == 0)  OutputJSON.AppendStr("local_ip", TempVar.GetStr());
					else  OutputJSON.AppendNull("local_ip");

					OutputJSON.AppendUInt("local_port", localport2);

					OutputJSON.AppendUInt("local_scope_id", tcp6table2ptr->table[x].dwLocalScopeId);

					ip6addr.sin6_addr = (in6_addr)tcp6table2ptr->table[x].RemoteAddr;
					tempsize = TempVar.GetMaxSize();
					if (::WSAAddressToStringA((LPSOCKADDR)&ip6addr, sizeof(ip6addr), NULL, TempVar.GetStr(), &tempsize) == 0)  OutputJSON.AppendStr("remote_ip", TempVar.GetStr());
					else  OutputJSON.AppendNull("remote_ip");

					OutputJSON.AppendUInt("remote_port", remoteport2);

					OutputJSON.AppendUInt("remote_scope_id", tcp6table2ptr->table[x].dwRemoteScopeId);

					OutputJSON.AppendUInt("pid", tcp6table2ptr->table[x].dwOwningPid);

					AppendTCPOffloadState(OutputJSON, tcp6table2ptr->table[x].dwOffloadState);

					DumpOutput(OutputFile, OutputJSON);

					OutputJSON.EndObject();
				}

				OutputJSON.EndArray();
			}

			OutputJSON.EndObject();
		}

		if (mode == TCPUDPMode || mode == UDPMode)
		{
			// UDP v4.
			OutputJSON.SetValSplitter(",\n\n");
			OutputJSON.StartObject("udp4");
			OutputJSON.SetValSplitter(", ");

			PMIB_UDPTABLE udptableptr = (PMIB_UDPTABLE)tablebuffer;

			tablesize2 = tablesize;
			while ((winerror = ::GetUdpTable(udptableptr, &tablesize2, sort)) == ERROR_INSUFFICIENT_BUFFER)
			{
				delete[] tablebuffer;

				tablesize = tablesize2;
				tablebuffer = new char[tablesize];
				udptableptr = (PMIB_UDPTABLE)tablebuffer;
			}

			if (winerror != NO_ERROR)
			{
				DumpErrorMsg(OutputFile, OutputJSON, "The call to GetUdpTable failed.", "get_udp_table_failed", winerror);

				result = 1;
			}
			else
			{
				OutputJSON.AppendBool("success", true);

				OutputJSON.StartArray("info");

				for (x = 0; x < (int)udptableptr->dwNumEntries; x++)
				{
					localport2 = ::ntohs((u_short)udptableptr->table[x].dwLocalPort);

					// Check state, IP address, and port number for matches.
					if (usestates && !states[MIB_TCP_STATE_LISTEN])  continue;
					if (localip != NULL && !IP4AddrMatches(localip, (u_long)udptableptr->table[x].dwLocalAddr))  continue;
					if (localport != (DWORD)-1 && localport != (DWORD)localport2)  continue;

					OutputJSON.SetValSplitter(",\n\n");
					OutputJSON.StartObject();
					OutputJSON.SetValSplitter(", ");

					OutputJSON.AppendStr("state", "LISTEN");

					ip4addr.sin_addr.S_un.S_addr = (u_long)udptableptr->table[x].dwLocalAddr;
					tempsize = TempVar.GetMaxSize();
					if (::WSAAddressToStringA((LPSOCKADDR)&ip4addr, sizeof(ip4addr), NULL, TempVar.GetStr(), &tempsize) == 0)  OutputJSON.AppendStr("local_ip", TempVar.GetStr());
					else  OutputJSON.AppendNull("local_ip");

					OutputJSON.AppendUInt("local_port", localport2);

					DumpOutput(OutputFile, OutputJSON);

					OutputJSON.EndObject();
				}

				OutputJSON.EndArray();
			}

			OutputJSON.EndObject();

			// UDP v6.
			OutputJSON.SetValSplitter(",\n\n");
			OutputJSON.StartObject("udp6");
			OutputJSON.SetValSplitter(", ");

			PMIB_UDP6TABLE udp6tableptr = (PMIB_UDP6TABLE)tablebuffer;

			tablesize2 = tablesize;
			while ((winerror = ::GetUdp6Table(udp6tableptr, &tablesize2, sort)) == ERROR_INSUFFICIENT_BUFFER)
			{
				delete[] tablebuffer;

				tablesize = tablesize2;
				tablebuffer = new char[tablesize];
				udp6tableptr = (PMIB_UDP6TABLE)tablebuffer;
			}

			if (winerror != NO_ERROR)
			{
				DumpErrorMsg(OutputFile, OutputJSON, "The call to GetUdp6Table failed.", "get_udp_table_failed", winerror);

				result = 1;
			}
			else
			{
				OutputJSON.AppendBool("success", true);

				OutputJSON.StartArray("info");

				for (x = 0; x < (int)udp6tableptr->dwNumEntries; x++)
				{
					localport2 = ::ntohs((u_short)udp6tableptr->table[x].dwLocalPort);

					// Check state, IP address, and port number for matches.
					if (usestates && !states[MIB_TCP_STATE_LISTEN])  continue;
					if (localip != NULL && !IP6AddrMatches(localip, udp6tableptr->table[x].dwLocalAddr))  continue;
					if (localport != (DWORD)-1 && localport != (DWORD)localport2)  continue;

					OutputJSON.SetValSplitter(",\n\n");
					OutputJSON.StartObject();
					OutputJSON.SetValSplitter(", ");

					OutputJSON.AppendStr("state", "LISTEN");

					ip6addr.sin6_addr = (in6_addr)udp6tableptr->table[x].dwLocalAddr;
					tempsize = TempVar.GetMaxSize();
					if (::WSAAddressToStringA((LPSOCKADDR)&ip6addr, sizeof(ip6addr), NULL, TempVar.GetStr(), &tempsize) == 0)  OutputJSON.AppendStr("local_ip", TempVar.GetStr());
					else  OutputJSON.AppendNull("local_ip");

					OutputJSON.AppendUInt("local_port", localport2);

					OutputJSON.AppendUInt("local_scope_id", udp6tableptr->table[x].dwLocalScopeId);

					DumpOutput(OutputFile, OutputJSON);

					OutputJSON.EndObject();
				}

				OutputJSON.EndArray();
			}

			OutputJSON.EndObject();
		}

		delete[] tablebuffer;
	}

	OutputJSON.EndObject();
	OutputJSON.Finish();

	DumpOutput(OutputFile, OutputJSON);

	if (!OutputFile.IsOpen())  printf("\n");
	else  OutputFile.Write("\n", y);

	OutputFile.Close();

	if (localip != NULL)  ::freeaddrinfo(localip);
	if (remoteip != NULL)  ::freeaddrinfo(remoteip);

	// Let the OS clean up after this program.  It is lazy, but whatever.
	if (verbose)  _tprintf(_T("Return code = %i\n"), result);

	return result;
}

#ifdef SUBSYSTEM_WINDOWS
#ifndef UNICODE
// Swiped from:  https://stackoverflow.com/questions/291424/canonical-way-to-parse-the-command-line-into-arguments-in-plain-c-windows-api
LPSTR* CommandLineToArgvA(LPSTR lpCmdLine, INT *pNumArgs)
{
	int retval;
	retval = ::MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, lpCmdLine, -1, NULL, 0);
	if (!SUCCEEDED(retval))  return NULL;

	LPWSTR lpWideCharStr = (LPWSTR)malloc(retval * sizeof(WCHAR));
	if (lpWideCharStr == NULL)  return NULL;

	retval = ::MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, lpCmdLine, -1, lpWideCharStr, retval);
	if (!SUCCEEDED(retval))
	{
		free(lpWideCharStr);

		return NULL;
	}

	int numArgs;
	LPWSTR* args;
	args = ::CommandLineToArgvW(lpWideCharStr, &numArgs);
	free(lpWideCharStr);
	if (args == NULL)  return NULL;

	int storage = numArgs * sizeof(LPSTR);
	for (int i = 0; i < numArgs; i++)
	{
		BOOL lpUsedDefaultChar = FALSE;
		retval = ::WideCharToMultiByte(CP_ACP, 0, args[i], -1, NULL, 0, NULL, &lpUsedDefaultChar);
		if (!SUCCEEDED(retval))
		{
			::LocalFree(args);

			return NULL;
		}

		storage += retval;
	}

	LPSTR* result = (LPSTR *)::LocalAlloc(LMEM_FIXED, storage);
	if (result == NULL)
	{
		::LocalFree(args);

		return NULL;
	}

	int bufLen = storage - numArgs * sizeof(LPSTR);
	LPSTR buffer = ((LPSTR)result) + numArgs * sizeof(LPSTR);
	for (int i = 0; i < numArgs; ++ i)
	{
		BOOL lpUsedDefaultChar = FALSE;
		retval = ::WideCharToMultiByte(CP_ACP, 0, args[i], -1, buffer, bufLen, NULL, &lpUsedDefaultChar);
		if (!SUCCEEDED(retval))
		{
			::LocalFree(result);
			::LocalFree(args);

			return NULL;
		}

		result[i] = buffer;
		buffer += retval;
		bufLen -= retval;
	}

	::LocalFree(args);

	*pNumArgs = numArgs;
	return result;
}
#endif

int CALLBACK WinMain(HINSTANCE /* hInstance */, HINSTANCE /* hPrevInstance */, LPSTR lpCmdLine, int /* nCmdShow */)
{
	int argc;
	TCHAR **argv;
	int result;

#ifdef UNICODE
	argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
#else
	argv = CommandLineToArgvA(lpCmdLine, &argc);
#endif

	if (argv == NULL)  return 0;

	result = _tmain(argc, argv);

	::LocalFree(argv);

	return result;
}
#endif
