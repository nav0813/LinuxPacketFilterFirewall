/**
 * OptionsParser.cpp
 *  Author: nav
 */

#include "OptionsParser.hpp"

namespace MiniFirewall{

	OptionsParser::OptionsParser(int count, char** args): m_iNumArgs(count),
								m_aOptionsArray(args),
								m_bValidRule(true),
								m_bRulePrint(false),
								m_sPkt(string("PKT")),
								m_sSrcAddr(string("SRCIP*")),
								m_sDstAddr(string("DSTIP*")),
								m_sSrcPt(string("SRCPT*")),
								m_sDstPt(string("DSTPT*")),
								m_sProto(string("PROTO")),
								m_sAct(string("ACT")),
								m_sTrail(string(" ")),
								m_sFirewallRule(string(" ")){}

	void OptionsParser::m_vParse(){
		int opt, options = 0;
		struct option longopts[] =
			{
				{"in", no_argument, 0, 'a'},
				{"out", no_argument, 0, 'b'},
				{"proto", required_argument, 0, 'c'},
				{"srcip", required_argument, 0, 'd'},
				{"dstip", required_argument, 0, 'e'},
				{"srcpt", required_argument, 0, 'f'},
				{"dstpt", required_argument, 0, 'g'},
				{"action", required_argument, 0, 'i'},
				{"print", no_argument, 0, 'j'},
				{"help", no_argument, 0, 'l'},
				{0, 0, 0, 0}
			};

		while((opt = getopt_long(m_iNumArgs, m_aOptionsArray, "abc:d:e:f:g:i:jl", longopts, &options)) != -1) {
			switch(opt) {
				case 'a':
					m_sPkt.append("INC");
					break;
				case 'b':
					m_sPkt.append("OUT");
					break;
				case 'd':
					m_sSrcAddr.replace(5, 1, optarg);
					break;
				case 'c':
					m_sProto.append(optarg);
					break;
				case 'e':
					m_sDstAddr.replace(5, 1, optarg);
					break;
				case 'f':
					m_sSrcPt.replace(5, 1, optarg);
					break;
				case 'g':
					m_sDstPt.replace(5, 1, optarg);
					break;
				case 'i':
					m_sAct.append(optarg);
					break;
				case 'j':
					m_bRulePrint = true;
					m_bValidRule = false;
					break;
				case 'l':
					m_bValidRule = false;
					cout<<"\nUsage:";
					cout<<"\n./MiniFirewall --in/--out --proto <ALL/TCP/UDP> --dstip <IP address> --dstpt <port number> --srcip <IP address> --srcpt <port number>--action <BLOCK/UNBLOCK>\n";
					break;
				case ':':
					m_bValidRule = false;
					cout<<"\noption needs a value";
					break;
				case '?':
					m_bValidRule = false;
					cout<<"\nunknown option ";
					break;
				default:
					break;
			}
		}
		m_sFirewallRule = m_sPkt + m_sAct + m_sSrcAddr + m_sDstAddr + m_sProto + m_sSrcPt + m_sDstPt + m_sTrail;
	}
}
