/**
 * FileHandler.cpp
 * Author: nav
 */

#include "FileHandler.hpp"

namespace MiniFirewall {

	FileHandler::FileHandler(string filename) {
		m_fWriteHandle.open((const char*)filename.c_str(), ios::out | ios::app);
		m_fReadHandle.open((const char*)filename.c_str(), ios::in);
	}

	FileHandler::~FileHandler() {
		m_fWriteHandle.close();
		m_fReadHandle.close();
	}

	void FileHandler::m_vWrite(string rule) {
		if(m_fWriteHandle.is_open()){
			m_fWriteHandle<<rule;
		} else{
			cout << "File is not open";
		}
	}

	void FileHandler::m_vRead() {
		string line;
		if(m_fReadHandle.is_open()){
			while(getline(m_fReadHandle, line)){
				cout << line<<"\n";
			}
		} else{
			cout<<"\nERR: File open failed";
		}
	}
}
