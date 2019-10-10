#pragma once

#include "stdafx.h"
#include "XMLReader.h"
#include "XMLWriter.h"

#include <WS2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

class RuleHandler
{
public:
	RuleHandler(string);
	bool AddRule(string);
	bool DeleteRule(string);
	bool IsReady();
private:
	string FileName = "NO_FILE";
	string TempFile = "NO_FILE";
	bool IsGoodToGo = false;
	bool IsIPAddress(string);
};

/*   Constructer of class.   */
RuleHandler::RuleHandler(string fileName)
{
	XMLReader reader(fileName);
	if (!reader.IsReady())
	{
		string msg = "Failed to open XMLReader for RuleHandler!";
		MessageBox(0, msg.c_str(), "IF: Error", MB_OK | MB_ICONERROR);
		return;
	}

	this->FileName = fileName;
	this->TempFile = fileName + ".2";
	IsGoodToGo = true;
}

/*   Checks if RuleHandler is ready.   */
bool RuleHandler::IsReady()
{
	return IsGoodToGo;
}

/*   Adds IP rule to list.   */
bool RuleHandler::AddRule(string IP)
{
	if (IP.length() == 0 || IP == "0.0.0.0")
	{
		MessageBox(0, "No IP string given!", "IF: Warning", MB_OK | MB_ICONWARNING);
		return false;
	}

	if (IsIPAddress(IP) == false)
	{
		MessageBox(0, "Not a valid IP address!", "IF: Warning", MB_OK | MB_ICONWARNING);
		return false;
	}

	//	Checks if IP already exists in the list.
	XMLReader reader(this->FileName);
	if (!reader.IsReady())
	{
		string msg = "Failed to open XMLReader for RuleHandler!";
		MessageBox(0, msg.c_str(), "IF: Error", MB_OK | MB_ICONERROR);
		return false;
	}

	if (reader.CheckIPInList(IP) == true)
	{
		MessageBox(0, "IP already exists in list!", "IF: Warning", MB_OK | MB_ICONWARNING);
		return false;
	}

	//	Adds IP to list.
	XMLWriter writer(this->FileName);
	if (writer.WriteIPElement(IP) == false)
	{
		MessageBox(0, "Failed to write IP to list!", "IF: Error", MB_OK | MB_ICONERROR);
		writer.CloseXMLFile();
		return false;
	}

	writer.CloseXMLFile();
	return true;
}

/*   Deletes IP element from file.   */
bool RuleHandler::DeleteRule(string IP)
{
	ifstream reader(this->FileName, ios::beg);
	ofstream output(this->TempFile, ios::trunc);

	string line;
	string searchData = "<IP>" + IP + "</IP>";
	bool FileDeleted = false;

	while (getline(reader, line))
	{
		if (line.find(searchData) != string::npos)
		{
			FileDeleted = true;
			continue;
		}
		else
			output << line << endl;
	}

	reader.close();
	output.close();

	MoveFileEx(this->TempFile.c_str(), this->FileName.c_str(), MOVEFILE_REPLACE_EXISTING);

	return FileDeleted;
}


/*   Checks if string is IP address.   */
bool RuleHandler::IsIPAddress(string IP)
{
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, IP.c_str(), &(sa.sin_addr));
	return result != 0;
}