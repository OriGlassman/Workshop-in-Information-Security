#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/slab.h>


#include "firewall_implentation.h"
#include "rule_table.h"
#include "logs_implementation.h"
#include "fw.h"
#include "stateful_fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ori Glassman");


static int log_major_number;
static int rules_major_number;
static int conns_major_number;
static int failure_occured = 0;

static struct class* sysfs_class = NULL;
static struct device* rules_sysfs_device = NULL;
static struct device* log_sysfs_device = NULL;
static struct device* fw_log_device = NULL;
static struct device* conns_device = NULL;

log_row_t* dynamic_log = NULL;
log_row_t single_entry_log;
size_t log_count = 0;
size_t total_alloc_size_log = 0;

rule_t rule_table[MAX_RULES];
size_t rules_count = 0;

struct kmem_cache* conn_cache = NULL;

static struct nf_hook_ops pre_routing_hook;
static struct nf_hook_ops local_out_hook;

/*
* Utility to destroy all the devices
*/
static void destroy_devices(int major_number[], int minor_number[]){
    int i;
    for (i = 0; i < 4; i++){
        device_destroy(sysfs_class, MKDEV(major_number[i], minor_number[i]));
    }
}

/*
* Utility to unregister all the char devices
*/
static void unregister_chrdevices(int majors[]){
    int i;
    for (i = 0; i < 3; i++){
        unregister_chrdev(majors[i], CLASS_NAME);
    }
}

/*
* Utility to unregister all the hooks
*/
static void unregister_hooks(void) {
    nf_unregister_hook(&pre_routing_hook);
    nf_unregister_hook(&local_out_hook);
}

/*
** A utility function to assign nf_hook_ops struct with the right values
*/
static void prepare_hook(struct nf_hook_ops* hook_ops, unsigned int hook_num, nf_hookfn hook_func, u_int8_t pf){
    hook_ops->hooknum = hook_num;
    hook_ops->hook = hook_func;
    hook_ops->pf = pf;
}

/*
** Calls the function to init everything before showing the log
*/
int my_logs_open(struct inode *_inode, struct file *_file){
    return logs_open(&single_entry_log, dynamic_log, log_count, _inode, _file);
}

/*
** Calls the function to send the log to the user space
*/
ssize_t my_logs_read(struct file *filp, char *buff, size_t length, loff_t *offp){
    return logs_read(filp, buff, length, offp);
}

static struct file_operations fops = {
        .owner = THIS_MODULE,
        .open = my_logs_open,
        .read = my_logs_read
};

/*
** sysfs show implementation to pass to the user space the rule table
*/
ssize_t sysfs_show_rule_table(struct device *dev, struct device_attribute *attr, char *buf)	
{
    return print_rule_table(rule_table, rules_count, buf, PAGE_SIZE);
}

/*
** sysfs store implementation to load rule table from user to kernel
*/
ssize_t sysfs_load_rule_table(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    return load_rule_table(rule_table, &rules_count, buf, count);
}

/*
** Calls the function that handles firewall logic
*/
unsigned int my_firewall(unsigned int hooknum,
                                          struct sk_buff *skb,
                                          const struct net_device *in,
                                          const struct net_device *out,
                                          int (*okfn)(struct sk_buff*)){ 
    return firewall(&dynamic_log, &single_entry_log, &log_count, &total_alloc_size_log, rule_table, rules_count, in, skb);
}


/*
** Checks if user wrote anything - if so, reset log
*/
ssize_t sysfs_reset_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    if (count > 0){
        
        reset_log(&dynamic_log, &single_entry_log, &log_count);
        return count;
    }
    else{
        return 0;
    }
}

/*
* Wrapper to pass the user the connection table
*/
ssize_t sysfs_show_conn_table(struct device *dev, struct device_attribute *attr, char *buf)
{
    return show_connection_table(buf);
}

static DEVICE_ATTR(rules, S_IRWXO , sysfs_show_rule_table, sysfs_load_rule_table);
static DEVICE_ATTR(reset, S_IWUSR | S_IWGRP | S_IWOTH , NULL, sysfs_reset_log);
static DEVICE_ATTR(conns, S_IRWXG , sysfs_show_conn_table, NULL);
static DEVICE_ATTR(conns_mitm, S_IRWXO , NULL, sysfs_handle_conn_table);

static int maj_chrdevices[3] = {0};
static int maj_devices[4] = {0};
static int min_devices[4] = {0};

/*
* Utility to remove all the file attributes
*/
static void remove_attribute_files(int len){
    device_remove_file(rules_sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr);
    device_remove_file(log_sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr);
    if (len<3) return;
    device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
    if (len<4) return;
    device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns_mitm.attr);
}

static int __init sysfs_init_mod(void)
{
    int ret_value;     

    prepare_hook(&pre_routing_hook,
            NF_INET_PRE_ROUTING,
                my_firewall,  
                PF_INET);

    prepare_hook(&local_out_hook,
                NF_INET_LOCAL_OUT,
                fix_packet_fields,
                PF_INET);

    ret_value = nf_register_hook(&pre_routing_hook);
    if (ret_value){
        failure_occured = 1;
        return -1;
    }

    ret_value = nf_register_hook(&local_out_hook);
    if (ret_value){
        failure_occured = 1;
        return -1;
    }
        
    log_major_number = register_chrdev(0, CLASS_NAME, &fops);
	if (log_major_number < 0){
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }
    
    rules_major_number = register_chrdev(0, CLASS_NAME, &fops);
	if (rules_major_number < 0){
        unregister_chrdev(log_major_number, CLASS_NAME);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }

    conns_major_number = register_chrdev(0, CLASS_NAME, &fops);
    if (rules_major_number < 0){
        unregister_chrdev(log_major_number, CLASS_NAME);
        unregister_chrdev(rules_major_number, CLASS_NAME);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }
    maj_chrdevices[0]=log_major_number,maj_chrdevices[1]=rules_major_number,maj_chrdevices[2]=conns_major_number;

    //create sysfs class
    sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(sysfs_class))
    {
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }

    //create rules sysfs device
    rules_sysfs_device = device_create(sysfs_class, NULL, MKDEV(rules_major_number, MINOR_RULES), NULL, DEVICE_NAME_RULES);
    if (IS_ERR(rules_sysfs_device)){
        class_destroy(sysfs_class);
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }
    
    //create log sysfs device
    log_sysfs_device = device_create(sysfs_class, NULL, MKDEV(log_major_number, MINOR_LOG), NULL, DEVICE_NAME_LOG);
    if (IS_ERR(log_sysfs_device)){
        device_destroy(sysfs_class, MKDEV(rules_major_number, MINOR_RULES));
        class_destroy(sysfs_class);
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }
    
    //create fw_log device
    fw_log_device = device_create(sysfs_class, NULL, MKDEV(log_major_number, MINOR_FW_LOG), NULL, FW_LOG_DEVICE);
    if (IS_ERR(fw_log_device)){
        device_destroy(sysfs_class, MKDEV(rules_major_number, MINOR_RULES));
        device_destroy(sysfs_class, MKDEV(log_major_number, MINOR_LOG));
        class_destroy(sysfs_class);
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }

    //create conns device
    conns_device = device_create(sysfs_class, NULL, MKDEV(conns_major_number, MINOR_CONNS), NULL, CONNS_TABLE_DEVICE);
    if (IS_ERR(conns_device)){        
        device_destroy(sysfs_class, MKDEV(rules_major_number, MINOR_RULES));
        device_destroy(sysfs_class, MKDEV(log_major_number, MINOR_LOG));
        device_destroy(sysfs_class, MKDEV(log_major_number, MINOR_FW_LOG));
        class_destroy(sysfs_class);
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }
    
    
    maj_devices[0]=rules_major_number, maj_devices[1]=log_major_number,maj_devices[2]=log_major_number,maj_devices[3]=conns_major_number;
    min_devices[0]=MINOR_RULES,min_devices[1]=MINOR_LOG,min_devices[2]=MINOR_FW_LOG,min_devices[3]=MINOR_CONNS;
    
    //create rules file attribute
    if (device_create_file(rules_sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr)){
        destroy_devices(maj_devices, min_devices);        
        class_destroy(sysfs_class);
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }
    
    //create reset (log) file attribute
    if (device_create_file(log_sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr)){
        device_remove_file(rules_sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr);
        destroy_devices(maj_devices, min_devices);         
        class_destroy(sysfs_class);
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }

    //create conns file attribute
    if (device_create_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr)){
        remove_attribute_files(2);
        destroy_devices(maj_devices, min_devices); 
        class_destroy(sysfs_class);
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }

    //create conns_mitm file attribute
    if (device_create_file(conns_device, (const struct device_attribute *)&dev_attr_conns_mitm.attr)){
        remove_attribute_files(3);
        destroy_devices(maj_devices, min_devices); 
        class_destroy(sysfs_class);
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }
    
    conn_cache = kmem_cache_create("connection_table", sizeof(struct conn_t_lst), 0, 0, NULL);
    if (conn_cache == NULL){
        remove_attribute_files(4);
        destroy_devices(maj_devices, min_devices); 
        class_destroy(sysfs_class);
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();
        failure_occured = 1;
        return -1;
    }

    return 0;
}

static void __exit sysfs_clean_mod(void)
{
    if (failure_occured == 0){ // means no failure happened
        remove_attribute_files(4);
        destroy_devices(maj_devices, min_devices); 
        class_destroy(sysfs_class);
        unregister_chrdevices(maj_chrdevices);
        unregister_hooks();

        if (dynamic_log != NULL){
            kfree(dynamic_log);
        }
        conn_table_clean_up();
    }
}

module_init(sysfs_init_mod);
module_exit(sysfs_clean_mod);