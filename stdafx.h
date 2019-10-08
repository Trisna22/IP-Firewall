#pragma once

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <Windows.h>
#include <fwpmu.h>
#include <list>
#include <strsafe.h>
#include <CommCtrl.h>
#include <wlanapi.h>
#include <sstream>
#include <io.h>
#include <fstream>

using namespace std;

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "wlanapi.lib")


/*
	Name:					IP Firewall 
	Author:					Trisna Quebe
	Copyrights:				Trisna Quebe (c) 2019-2020
	Creation Date:			7-10-2019

	Description:			The IP Firewall provides a firewall service for 
							every IP address that is specified in the black-list file.
							The firewall depends on the wifi network you are connected to.
							For example: At home you have different IP settings than on a
							public network.

	@@@  @@@@@@@      @@@@@@@@  @@@  @@@@@@@   @@@@@@@@  @@@  @@@  @@@   @@@@@@   @@@       @@@
	@@@  @@@@@@@@     @@@@@@@@  @@@  @@@@@@@@  @@@@@@@@  @@@  @@@  @@@  @@@@@@@@  @@@       @@@
	@@!  @@!  @@@     @@!       @@!  @@!  @@@  @@!       @@!  @@!  @@!  @@!  @@@  @@!       @@!
	!@!  !@!  @!@     !@!       !@!  !@!  @!@  !@!       !@!  !@!  !@!  !@!  @!@  !@!       !@!
	!!@  @!@@!@!      @!!!:!    !!@  @!@!!@!   @!!!:!    @!!  !!@  @!@  @!@!@!@!  @!!       @!!
	!!!  !!@!!!       !!!!!:    !!!  !!@!@!    !!!!!:    !@!  !!!  !@!  !!!@!!!!  !!!       !!!
	!!:  !!:          !!:       !!:  !!: :!!   !!:       !!:  !!:  !!:  !!:  !!!  !!:       !!:
	:!:  :!:          :!:       :!:  :!:  !:!  :!:       :!:  :!:  :!:  :!:  !:!   :!:       :!:
	 ::   ::           ::        ::  ::   :::   :: ::::   :::: :: :::   ::   :::   :: ::::   :: ::::
	:     :            :        :     :   : :  : :: ::     :: :  : :     :   : :  : :: : :  : :: : :

	Trisna Quebe (c) 2019

*/