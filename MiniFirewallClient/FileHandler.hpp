/**
 * FileHandler.hpp
 * Author: nav
 */

#ifndef FILEHANDLER_HPP_
#define FILEHANDLER_HPP_
#include <string>
#include <iostream>
#include <fstream>
using std::string;
using std::ifstream;
using std::ofstream;
using std::ios;
using std::cout;


namespace MiniFirewall{
	/**
	 * FileHandler provides the functionality to write the parsed firewall 
	 * rules to a /proc filesystem
	 */
	class FileHandler {
	public:
		/**
		 * Ctor parameterized with the name of the /proc file
		 * Opens the file to read and write
		 * @param filename - file name 
		 */
		explicit FileHandler(string filename);

		/**
		 * m_vWrite method writes a parsed rule to the file
		 * @param rule - firewall policy 
		 */
		void m_vWrite(string rule);
		
		/**
		 * m_vRead method reads the firewall policy and prints to stdout
		 */
		void m_vRead();
		
		/**
		 * Dtor to close the file handles
		 */
		virtual ~FileHandler();
	private:
		/**
		 * Handle to read the file
		 */
		ifstream m_fReadHandle;
		
		/**
		 * Handle to write to the file
		 */
		ofstream m_fWriteHandle;

		// Avoiding the use of compiler give-aways
		FileHandler(const FileHandler&);
		FileHandler& operator=(const FileHandler&);
	};
}

#endif /* FILEHANDLER_HPP_ */
