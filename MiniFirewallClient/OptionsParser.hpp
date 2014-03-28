/**
 * OptionsParser.hpp
 * Author: nav
 */

#ifndef OPTIONSPARSER_HPP_
#define OPTIONSPARSER_HPP_
#include <string>
#include <iostream>
#include <fstream>
#include <getopt.h>
using std::string;
using std::cout;


namespace MiniFirewall{
	/**
	 * FileHandler provides the functionality to write the parsed firewall 
	 * rules to a /proc filesystem
	 */
	class OptionsParser {
	public:
		/**
		 * Ctor 
		 * @param count - number of options 
		 * @param args - options array
		 */
		OptionsParser(int count, char** args);
		
  	        /**
		 * Dtor 
		 */
		virtual ~OptionsParser(){}
		
		/**
		 * Parse the options array for firewall policy options
		 */
		void m_vParse();
		
		/**
		 * Getter method that returns the flow
		 * i.e. whether the policy is for incoming or outgoing packets
		 */
		string m_sGetFlow() const {return m_sPkt;}
		
		/**
		 * Getter method that returns the source address value
		 */
		string m_sGetSrcAddr() const {return m_sSrcAddr;}
		
		/**
		 * Getter method that returns the destination address value
		 */
		string m_sGetDstAddr() const {return m_sDstAddr;}
		
		/**
		 * Getter method that returns the source port value
		 */
		string m_sGetSrcPt() const {return m_sSrcPt;}
		
		/**
		 * Getter method that returns the destination port value
		 */
		string m_sGetDstPt() const {return m_sDstPt;}
		
		/**
		 * Getter method that returns the protocol value
		 */
		string m_sGetProto() const {return m_sProto;}
		
		/**
		 * Getter method that returns the action value
		 */
		string m_sGetAct() const {return m_sAct;}
		
		/**
		 * Getter method that returns the trail string
		 */
		string m_sGetTrail() const {return m_sTrail;}
		
		/**
		 * Getter method that returns the parsed firewall policy
		 */
		string m_sGetFirewallPolicy() const {return m_sFirewallRule;}
		
		/**
		 * Returns true if the parsed firewall policy is valid
		 */
		bool m_bIsValidRule() const {return m_bValidRule;}

		/**
		 * Returns true the firewall policies have to be printed
		 */
		bool m_bIsRulePrint() const {return m_bRulePrint;}
		
	private:
		/**
		 * Stores the number of options
		 */
		int m_iNumArgs;
		
		/**
		 * Stores the options array
		 */
		char** m_aOptionsArray;
		
		/**
		 * True when a parsed rule is valid
		 */
		bool m_bValidRule;
		
		/**
		 * True when the firewall policies have to be printed
		 */
		bool m_bRulePrint;
		
		/**
		 * Strings to store the options
		 */
		string m_sPkt, m_sSrcAddr, m_sDstAddr, m_sSrcPt, m_sDstPt;
		string m_sProto, m_sAct, m_sTrail, m_sFirewallRule;

		// Avoiding the use of compiler give-aways
		OptionsParser(const OptionsParser&);
		OptionsParser& operator=(const OptionsParser&);
	};
}

#endif /* FILEHANDLER_HPP_ */
