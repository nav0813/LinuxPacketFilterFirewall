#include "procfsHelper.h"

static char* rules; //used in creating the /proc entry
static int rule_index; //index for rules in /proc entry
static int next_rule; //index to next rule in /proc entry

/**
 * Read function for the proc entry
 */
int firewall_read(char* page, char** start, off_t off, int count, int* eof, void* data) {
	int len;
	if (off > 0) {
		*eof = 1;
		return 0;
	}
	
	/* Wrap-around */
	if (next_rule >= rule_index) {
		len = sprintf(page, "EOR\n");
		next_rule = 0;
		return len;
	}
	printk(KERN_INFO "firewall: firewall_read returns %s\n", &rules[next_rule]);
	len = sprintf(page, "%s\n", &rules[next_rule]);
	next_rule += len;
	return len;
}

