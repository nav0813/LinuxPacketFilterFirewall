#include <iostream>
#include "OptionsParser.hpp"
#include "FileHandler.hpp"

#define FILENAME "/proc/fwpolicy"

int main(int argc, char* argv[]){
	MiniFirewall::OptionsParser parser(argc, argv);
	MiniFirewall::FileHandler fileHandler(FILENAME);
	parser.m_vParse();
	if(!parser.m_bIsRulePrint()){
		if(parser.m_bIsValidRule()){
			fileHandler.m_vWrite(parser.m_sGetFirewallPolicy());
		}
	} else {
		fileHandler.m_vRead();
	}
}
