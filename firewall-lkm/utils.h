#ifndef _UTILS_H_
#define _UTILS_H_

#include <linux/string.h>
#include <asm/uaccess.h>

//extern struct t_rule;
//void processRule (char* prule, struct t_rule rules[], int index);
//void processRule (char* prule);

/* Utility functions */
unsigned int str_to_port(char*);
unsigned int str_to_ip(char*, int);
bool compare_ip(unsigned int, unsigned int);
bool compare_port(unsigned int, unsigned int);

#endif /* _UTILS_H_ */
