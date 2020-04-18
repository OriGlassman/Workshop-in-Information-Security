#ifndef _LOGS_H_
#define _LOGS_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#include "fw.h"

int logs_open(log_row_t* single_entry_log, log_row_t* dynamic_log, size_t log_count, struct inode *_inode, struct file *_file);

ssize_t logs_read(struct file *filp, char *buff, size_t length, loff_t *offp);

ssize_t reset_log(log_row_t** dynamic_log, log_row_t* single_entry_log, size_t* log_count);

int write_to_log(log_row_t** dynamic_log, log_row_t* single_entry_log, size_t* log_count,               
                        size_t* total_alloc_size_log, unsigned long timestamp,
                        unsigned char protocol, unsigned char action,
                        __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason);

int check_if_hit(log_row_t* log_rows, size_t log_count, __be32 src_ip, __be32 dst_ip, __be16 src_port,                              __be16 dst_port, unsigned char protocol);

void assign_log_row(log_row_t* log, unsigned long timestamp, unsigned char protocol, unsigned char action, __be32 src_ip,
                           __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason, unsigned int count);
#endif