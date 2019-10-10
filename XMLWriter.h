#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <Windows.h>
#include <fstream>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Kernel32.lib")

using namespace std;

class XMLWriter
{
public:
	XMLWriter(string);
	~XMLWriter();
	bool IsGood();
	bool WriteIPElement(string);
	bool CloseXMLFile();

private:
	FILE* XMLFile;
	bool GoodToGo = false;
};

/*   Constructor of XMLWriter class.   */
XMLWriter::XMLWriter(string FileName)
{
	if (fopen_s(&XMLFile, FileName.c_str(), "a") != 0)
	{
		if (errno == ERROR_FILE_NOT_FOUND)
		{
			MessageBox(0, "XMLWriter: File doesn't exists!", "IF: Warning", MB_OK | MB_ICONWARNING);
			return;
		}
		else
		{
			string msg = "XMLWriter: Error occured on opening file! Error code: " + to_string(errno);
			MessageBox(0, msg.c_str(), "IF: Error", MB_OK | MB_ICONERROR);
			return;
		}
	}

	GoodToGo = true;
}

/*   Deconstructor of XMLWriter class.   */
XMLWriter::~XMLWriter()
{

}

/*   Checks if the XMLWriter is ready to go.   */
bool XMLWriter::IsGood()
{
	return GoodToGo;
}

/*   Writes the IP to the file.   */
bool XMLWriter::WriteIPElement(string IPAttribute)
{
	if (XMLFile == NULL)
	{
		string msg = "Failed to write start element! Error code: " + to_string(errno);
		MessageBox(0, msg.c_str(), "IF: Error", MB_OK | MB_ICONERROR);
		return false;
	}

	//	Write data to file.
	string data = "<IP>" + IPAttribute + "</IP>\n";
	int numwritten = fwrite(data.c_str(), sizeof(char), data.length(), XMLFile);
	if (numwritten == NULL)
	{
		string msg = "Failed to write the IP-element! Error code: " + to_string(errno);
		MessageBoxA(NULL, msg.c_str(), "IF: Error", MB_OK | MB_ICONERROR);
		return false;
	}

	return true;
}

/*   Closes the XML file when done.   */
bool XMLWriter::CloseXMLFile()
{
	if (fclose(XMLFile) != NULL)
	{
		string msg = "Failed to close the XML file! Error code: " + to_string(errno);
		MessageBoxA(NULL, msg.c_str(), "IF: Error", MB_OK | MB_ICONERROR);
		return false;
	}
	return true;
}