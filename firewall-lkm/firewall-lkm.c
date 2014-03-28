/******************************************************************************************************************
 * This is the source file for the LKM that does packet-filterng based on the rules set from the user-space
 * program. This files contains netfilter hook functions for incoming and outgoing packets, read and write 
 * functions for the /proc entry, and module init and exit functions.
 * Author: Nav
 *******************************************************************************************************************/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/netfilter.h>

#include "netfltrHooks.h"
#include "procfsHelper.h"
//#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PACKET-FILTER FIREWALL");
MODULE_AUTHOR("Nav");

static struct proc_dir_entry* proc_entry; //handle for /proc entry
static char* rules; //used in creating the /proc entry
static int rule_index; //index for rules in /proc entry
static int next_rule; //index to next rule in /proc entry

static struct nf_hook_ops in_nfho; //Incoming net filter hook option struct
static struct nf_hook_ops out_nfho; //Outgoing net filter hook option struct

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

int ruleCount = 0;
struct t_rule T_RULES[100];

void processRule (char* prule, struct t_rule rules[], int index);

/* Module init and cleanup functions */
int firewall_init(void);
void firewall_cleanup(void);

/* Setting the module init and exit functions */
module_init(firewall_init);
module_exit(firewall_cleanup);

/**
 * Module init function
 */
int firewall_init(void)
{
	printk(KERN_INFO "firewall: firewall_init CALLED.  MODULE IS NOW LOADED.\n");
	rules = (char* )vmalloc(PAGE_SIZE);
	if( rules == NULL ) {
		printk(KERN_INFO"firewall: RULES MEM ALLOC FAILED\n");
	} else {
		memset(rules, 0, PAGE_SIZE);
		proc_entry = create_proc_entry("fwpolicy", 0644, NULL);
		if( proc_entry == NULL ) {
			printk(KERN_INFO"firewall: COULDNOT CREATE PROC ENTRY\n");
			vfree(rules);
		} else {
			printk(KERN_INFO"firewall: PROC ENTRY CREATED\n");
			
			rule_index = 0;
			next_rule = 0;
			/* Setting the reader functions for the proc entry */
			proc_entry->read_proc = firewall_read;
			/* Setting the writer functions for the proc entry */
			proc_entry->write_proc = firewall_write;
			
			/* Setting Incoming net filter hook option struct */
			in_nfho.hook = in_hook_func;
			in_nfho.hooknum = NF_INET_LOCAL_IN;
			in_nfho.pf = PF_INET;
			in_nfho.priority = NF_IP_PRI_FIRST;
			
			/* Setting Outgoing net filter hook option struct*/
			out_nfho.hook = out_hook_func;
			out_nfho.hooknum = NF_INET_LOCAL_OUT;
			out_nfho.pf = PF_INET;
			out_nfho.priority = NF_IP_PRI_FIRST;
			
			/* Registering hooks*/
			nf_register_hook(&in_nfho);
			nf_register_hook(&out_nfho);
		}
	}
	return 0;
}

/**
 * Module exit function
 */
void firewall_cleanup(void)
{
	/* Delete the proc_entry */
	remove_proc_entry("fwpolicy", NULL);
	/* Free the allocated memory for rules */
	vfree(rules);
	/* Unregister netfilter hook functions */
	nf_unregister_hook(&in_nfho);
	nf_unregister_hook(&out_nfho);
	
	printk(KERN_INFO "firewall: firewall_cleanup called.  Module is now unloaded.\n");
	return;
}

/**
 * Write function for the proc entry
 */
ssize_t firewall_write(struct file* fp, const char __user* buff, unsigned long len, void* data) {
	int space_available = (PAGE_SIZE-rule_index)+1;
	printk(KERN_INFO "firewall: firewall_write called with %s\n", buff);	
	if (len > space_available) {
		printk(KERN_INFO "firewall: rules is full!\n");
		return -ENOSPC;
	}
	if (copy_from_user( &rules[rule_index], buff, len )) {
		return -EFAULT;
	}
	rule_index += len;
	processRule((char*)buff, T_RULES, ruleCount);
	ruleCount++;
	rules[rule_index-1] = 0;
	
	return len;
}

/**
 * Function to process the rule from user-space. 
 * Extracts the rule fields and populated into the data structure used by the LKM
 * @param prule - rule to be set
 */
void processRule (char* prule, struct t_rule rules[], int index) {
	char temp[25];
	memset(temp, 0, 10);
	/* Set pkt field - either 0 or 1 corresponding to OUT and IN resp. */
	strncpy(temp, prule+3, 3);
	temp[3] = '\0';
	if(strncmp(temp, "OUT", 3) == 0){
		rules[index].pkt = 0; 
	} else if(strncmp(temp, "INC", 3) == 0){
		rules[index].pkt = 1;
	} else {
		rules[index].pkt = 2;  //error value
	}
	printk(KERN_INFO"firewall: pkt %s encoded to %d\n", temp, rules[index].pkt);

	/* Set protocol field  0 - all, 1 - tcp, 2 - udp */
	memset(temp, 0, 10);
	strncpy(temp, strstr(prule,"PROTO")+5, (strstr(prule,"SRCPT")-strstr(prule,"PROTO"))-5);
	temp[(strstr(prule,"SRCPT")-strstr(prule,"PROTO"))-5] = '\0';
	if(strncmp(temp, "ALL", 3) == 0){
		rules[index].proto = 0;
	} else if(strncmp(temp, "TCP", 3) == 0){
		rules[index].proto = 1;
	} else if(strncmp(temp, "UDP", 3) == 0){
		rules[index].proto = 2;
	} else {
		rules[index].proto = 3; //error value  
	}
	printk(KERN_INFO"firewall: proto %s encoded to %d\n",temp, rules[index].proto);


	/* Set block field - 0 or 1 corresponding to UNBLOCK and BLOCK resp. */
	memset(temp, 0, 10);
	strncpy(temp, strstr(prule,"ACT")+3, (strstr(prule,"SRCIP")-strstr(prule,"ACT"))-3 );
	temp[(strstr(prule,"SRCIP")-strstr(prule,"ACT"))-3] = '\0';
	if(strncmp(temp, "BLOCK", 5) == 0){
			rules[index].block = 1; 
	} else if(strncmp(temp, "UNBLOCK", 7) == 0){
		rules[index].block = 0;
	} else {
		rules[index].block = 2;  //error value
	}
	printk(KERN_INFO"firewall: act %s encoded to %d\n", temp, rules[index].block);

	/* Set source IP address field */
	memset(temp, 0, 10);
	strncpy(temp, strstr(prule,"SRCIP")+5, (strstr(prule,"DSTIP")-strstr(prule,"SRCIP"))-5);
	temp[(strstr(prule,"DSTIP")-strstr(prule,"SRCIP"))-5] = '\0';
	rules[index].srcip = str_to_ip(temp, strlen(temp));
	printk(KERN_INFO"firewall: srcip %s encoded to %d\n", temp, rules[index].srcip);


	/*  Set destination IP address field */
	memset(temp, 0, 10);
	strncpy(temp, strstr(prule,"DSTIP")+5, (strstr(prule,"PROTO")-strstr(prule,"DSTIP"))-5);
	temp[(strstr(prule,"PROTO")-strstr(prule,"DSTIP"))-5] = '\0';
	rules[index].dstip = str_to_ip(temp, strlen(temp));
	printk(KERN_INFO"firewall: dstip %s encoded to %d\n", temp, rules[index].dstip);

	/* Set source port field */
	memset(temp, 0, 10);
	strncpy(temp, strstr(prule,"SRCPT")+5, (strstr(prule,"DSTPT")-strstr(prule,"SRCPT"))-5);
	temp[(strstr(prule,"DSTPT")-strstr(prule,"SRCPT"))-5] = '\0';
	rules[index].srcpt = str_to_port(temp);
	printk(KERN_INFO"firewall: srcpt %s encoded to %d \n", temp, rules[index].srcpt);

	/* Set destination port field */
	memset(temp, 0, 10);
	strcpy(temp, strstr(prule,"DSTPT")+5);
	strcat(temp, "\0");
	rules[index].dstpt = str_to_port(temp);
	printk(KERN_INFO"firewall: dstpt %s encoded to %d\n", temp, rules[index].dstpt);
}

