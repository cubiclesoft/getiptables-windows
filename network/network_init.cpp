// Cross-platform network initialization wrapper.
// (C) 2021 CubicleSoft.  All Rights Reserved.

#define _CRT_SECURE_NO_WARNINGS

#include "network_init.h"

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
	#include <winsock2.h>
	#include <windows.h>
#else
	#include <signal.h>
#endif

namespace CubicleSoft
{
	namespace Network
	{
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64) || defined(WIN64)
		Init::Init() : MxStarted(false)
		{
			WSADATA WSAData;
			if (::WSAStartup(MAKEWORD(2, 2), &WSAData))  return;
			if (LOBYTE(WSAData.wVersion) != 2 || HIBYTE(WSAData.wVersion) != 2)  return;

			MxStarted = true;
		}

		Init::~Init()
		{
			if (MxStarted)  ::WSACleanup();
		}
#else
		Init::Init() : MxStarted(false)
		{
			// Ignore SIGPIPE signals from unexpected pipe disconnects such as a remote socket closing.
			void (*handler)(int);
			handler = signal(SIGPIPE, SIG_IGN);
			if (handler != SIG_DFL)  signal(SIGPIPE, handler);

			MxStarted = true;
		}

		Init::~Init()
		{
			// Restore the original SIGPIPE handler.
			void (*handler)(int);
			handler = signal(SIGPIPE, SIG_DFL);
			if (handler != SIG_IGN)  signal(SIGPIPE, handler);
		}
#endif
	}
}
