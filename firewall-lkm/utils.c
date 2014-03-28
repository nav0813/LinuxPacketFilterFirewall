#include "utils.h"

/* struct to store the rules*/
struct t_rule {
	char pkt; // 0 - outgoing, 1- incoming, 2 - error
	char block; // 0 - unblock, 1 - block, 2 - error
	unsigned int srcip; // source ip address
	unsigned int dstip; // destination ip address
	unsigned int srcpt; //source port number
	unsigned int dstpt; //destination port number
	char proto; // 0 - all, 1 - tcp, 2 - udp, 3 - error
};

/* Array to store the rules*/
extern int ruleCount;
extern struct t_rule T_RULES[];

/* Utility functions */
/**
 * Converts the port number from string to interger
 * @param str - port number as string
 * @return port number as integer
 */
unsigned int str_to_port(char* str)
{
	unsigned int port = 0;
	char* ch;
	if(strncmp(str, "*", 1)  == 0){
		return port;
	}
	port = (unsigned int) simple_strtol(str, &ch, 10);
	return port;
}

/**
 * Converts the ip address from string to interger
 * @param str - ip address as string
 * @return ip address as integer
 */
unsigned int str_to_ip(char* str, int len)
{
	unsigned int ip = 0; int i=0, j=0;
	char quad1[4], quad2[4], quad3[4], quad4[4]; 
	unsigned int q1, q2, q3, q4;
	char* ch;

	while((str[i] != '.') && (i < len)){
		quad1[j++] = str[i++];
	}
	quad1[j] = '\0';
	j=0;i++;
	while((str[i] != '.')&&(i < len)){
		quad2[j++] = str[i++];
	}
	quad2[j] = '\0';
	j=0; i++;
	while((str[i] != '.') && (i < len)){
		quad3[j++] = str[i++];
	}
	quad3[j] = '\0';
	i++;j=0;
	while(i < len){
		quad4[j++] = str[i++];
	}
	quad4[j] = '\0';

	q1 = (unsigned int)simple_strtol(quad1, &ch, 10);
	q2 = (unsigned int)simple_strtol(quad2, &ch, 10);
	q3 = (unsigned int)simple_strtol(quad3, &ch, 10);
	q4 = (unsigned int) simple_strtol(quad4, &ch, 10);

	q1 *= 16777216;
	q2 *= 65536;
	q3 *= 256;
	ip = q1 + q2 + q3 + q4;
	
	if(strncmp(str, "*", 1) == 0){
		return ip;
	}

	return ip;	
}

/**
 * Compare the IP address for equality
 * @param pktip - IP address from the packet
 * @param ruleip - IP address from the firewall rules
 * @return bool - true if equal, else false
 */
bool compare_ip(unsigned int pktip, unsigned int ruleip)
{
	if(ruleip == 0){
		return true;
	}
	if(pktip == ruleip){
		printk(KERN_INFO"firewall: IP address matches. IP in pkt %u in rule %u", pktip, ruleip);
		return true;
	}else{
		return false;	
	}
}

/**
 * Compare the port numbers for equality
 * @param pktpt - port number from the packet in network byte order
 * @param rulept - port number from the firewall rules in host byte order
 * @return bool - true if equal, else false
 */
bool compare_port(unsigned int pktpt, unsigned int rulept)
{
	pktpt = (unsigned int)ntohs(pktpt);
	if(rulept == 0){
		return true;
	}
	if(pktpt == rulept){
		printk(KERN_INFO"\nfirewall: compare_port %u %u returning true", pktpt, rulept);
		return true;		
	} else {
		return false;
	}
}




