#ifndef _PROCFSHELPER_H_
#define _PROCFSHELPER_H_

#include <linux/proc_fs.h>
#include "utils.h"

/* Read and write functions for the proc entry */
ssize_t firewall_write(struct file* fp, const char __user* buff, unsigned long len, void* data);
int firewall_read(char* page, char** start, off_t off, int count, int* eof, void* data);
#endif /*_PROCFSHELPER_H_*/
