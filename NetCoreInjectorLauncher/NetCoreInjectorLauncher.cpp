// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "Header.h"
#include "../NetCoreInjector/pch.h"


int wmain(int args, wchar_t *argv[])
{
#if DEBUG
	std::cin.get();
#endif

	Launch(argv);
}

