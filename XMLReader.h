#pragma once

#include <string>
#include <fstream>
#include <sstream>
#include <Windows.h>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Kernel32.lib")

using namespace std;

class XMLReader
{
public:
	XMLReader(string);
	~XMLReader();
	bool IsReady();
	int RetrieveIPAddressesInFile();
	string RetrieveIP(int);
	bool CheckIPInList(string);
private:
	bool IsGoodToGo = false;
	ifstream XMLFile;
	string FileName;
};

/*   Constructor of XMLReader class.   */
XMLReader::XMLReader(string fileName)
{
	XMLFile.open(fileName, ios::beg);
	if (!XMLFile.is_open())
	{
		if (errno == ERROR_FILE_NOT_FOUND)
		{
			MessageBoxA(NULL, "XMLReader: File doesn't exists!", "IF: Warning", MB_OK | MB_ICONWARNING);
			return;
		}
		else
		{
			stringstream ss;
			ss << "XMLReader: Failed to open the file " << fileName << "!\nError code: " << GetLastError() << endl;
			MessageBoxA(NULL, ss.str().c_str(), "IF: Error", MB_OK | MB_ICONERROR);
			return;
		}
	}
	else
	{
		FileName = fileName;
	}
	XMLFile.close();

	IsGoodToGo = true;
}

/*   Deconstructor of XMLReader class.   */
XMLReader::~XMLReader()
{

}

/*   Checks if the class is ready to go.   */
bool XMLReader::IsReady()
{
	return IsGoodToGo;
}

/*   Gets the number of IP addresses in wifi profile.   */
int XMLReader::RetrieveIPAddressesInFile()
{
	XMLFile.open(FileName.c_str(), ios::beg);
	if (!XMLFile.is_open())
	{
		stringstream ss;
		ss << "Failed to open file! Error code: " << errno << endl;
		MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return -1;
	}

	int count = 0;
	string line;
	while (getline(XMLFile, line))
	{
		//	Count the <IP> elements inside the <WIFI> element
		if (line.find("<IP>") != string::npos && line.find("</IP>") != string::npos)
			count++;
	}
	XMLFile.close();
	return count;
}

/*   Gets the IP address from wifi profile.   */
string XMLReader::RetrieveIP(int count)
{
	XMLFile.open(FileName.c_str(), ios::beg);
	if (!XMLFile.is_open())
	{
		stringstream ss;
		ss << "Failed to open file! Error code: " << errno << endl;
		MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return "ERROR_OPENING_FILE";
	}

	string searchString = "<IP>";
	string line;
	int row = 0;
	while (getline(XMLFile, line))
	{
		if (row == count && line.find("<IP>") != string::npos && line.find("</IP>") != string::npos)
		{
			XMLFile.close();
			string a = line.substr(4);
			string ip = a.substr(0, a.find_first_of("<"));
			return ip;
		}
		else if (line.find("<IP>") != string::npos && line.find("</IP>") != string::npos)
			row++;
		else
			continue;
	}
	XMLFile.close();
	return "IP_NOT_FOUND";
}

/*   Checks if IP already exists in list.   */
bool XMLReader::CheckIPInList(string IP)
{
	XMLFile.open(FileName.c_str(), ios::beg);
	if (!XMLFile.is_open())
	{
		stringstream ss;
		ss << "Failed to open file! Error code: " << errno << endl;
		MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return false;
	}

	string line;
	string searchString = "<IP>" + IP + "</IP>";
	while (getline(XMLFile, line))
	{
		if (line.find(searchString) != string::npos)
		{
			XMLFile.close();
			return true;
		}
	}

	XMLFile.close();
	return false;
}