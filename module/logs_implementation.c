#include "logs_implementation.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>

#define MAX_LOG_LINE_LENGTH (200) // an upper bound to a single max line length

char* buffer_index = NULL; 
char* ptr_to_buffer_index = NULL;
static int str_len;
static int wrote_to_buffer_index = 0;

/*
* Init and load the buffer to pass the data to user, minimum data as possible
*/
int logs_open(log_row_t* single_entry_log, log_row_t* dynamic_log, size_t log_count, struct inode *_inode, struct file *_file)
{
    int tot_written = 0, i, buff_size;
    if (log_count == 0){
        str_len = 0;
    }
    else if (log_count == 1){
        buff_size = MAX_LOG_LINE_LENGTH * sizeof(char);
        buffer_index = vmalloc(buff_size); 
        memset(buffer_index, 0 , buff_size);
                
        if (buffer_index == NULL){
            str_len = 0;
            return -EFAULT;
        }
        str_len = scnprintf(buffer_index, buff_size, "%lu %u %u %u %u %u %u %d %u\n",
                                    single_entry_log->timestamp,
                                    single_entry_log->src_ip,
                                    single_entry_log->dst_ip,
                                    single_entry_log->src_port,
                                    single_entry_log->dst_port,
                                    single_entry_log->protocol,
                                    single_entry_log->action,
                                    single_entry_log->reason,
                                    single_entry_log->count
                                    );
        if (str_len > 0){
            wrote_to_buffer_index = 1;
        }
    }
    else{
        buff_size = MAX_LOG_LINE_LENGTH * log_count * sizeof(char);
        buffer_index = vmalloc(buff_size);
        memset(buffer_index, 0 , buff_size);
        
        if (buffer_index == NULL){
            str_len = 0;
            return -EFAULT;
        }
        for (i=0; i < log_count; i++){
            str_len = scnprintf(buffer_index + tot_written, buff_size-tot_written, "%lu %u %u %u %u %u %u %d %u\n",
                                    (dynamic_log + i)->timestamp,
                                    (dynamic_log + i)->src_ip,
                                    (dynamic_log + i)->dst_ip,
                                    (dynamic_log + i)->src_port,
                                    (dynamic_log + i)->dst_port,
                                    (dynamic_log + i)->protocol,
                                    (dynamic_log + i)->action,
                                    (dynamic_log + i)->reason,
                                    (dynamic_log + i)->count
                                    );
            tot_written += str_len;
            
        }
        if (tot_written > 0) {
            wrote_to_buffer_index = 1;
            ptr_to_buffer_index = buffer_index;
        }
        str_len = tot_written;
    }
	return 0;
}

/*
* Pass the log data to the user
*/
ssize_t logs_read(struct file *filp, char *buff, size_t length, loff_t *offp) {
    
	ssize_t num_of_bytes;
	num_of_bytes = (str_len < length) ? str_len : length;
    
    if (num_of_bytes == 0) { // We check to see if there's anything to write to the user
    	if (wrote_to_buffer_index == 1) {
            if (ptr_to_buffer_index != NULL){
                vfree(ptr_to_buffer_index);
                ptr_to_buffer_index = NULL;
            }
        
            wrote_to_buffer_index = 0; 
        }
        str_len = 0;
        return 0;
	}
    if (copy_to_user(buff, buffer_index, num_of_bytes)) { // Send the data to the user through 'copy_to_user'
        if (ptr_to_buffer_index != NULL){
            vfree(ptr_to_buffer_index);
            ptr_to_buffer_index = NULL;
        }
        wrote_to_buffer_index = 0;
        str_len = 0;
        return -EFAULT;
    } else { // function succeed, we just sent the user 'num_of_bytes' bytes, so we updating the counter and the string pointer index
        str_len -= num_of_bytes;
        buffer_index += num_of_bytes;
        return num_of_bytes;
    }
	return -EFAULT; // Should never reach here
}

// log sysfs store implementation
ssize_t reset_log(log_row_t** dynamic_log, log_row_t* single_entry_log, size_t* log_count){
    if (*log_count == 0){
        
    }
    else if (*log_count == 1){
        assign_log_row(single_entry_log, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
    else{
        kfree(*dynamic_log);
        *dynamic_log = NULL;
    }
    *log_count = 0;
    return 1;
    
}

/*
* Handels log writings - checks if the entry is already in the log (if so increase its count), else make new entry
*/
int write_to_log(log_row_t** dynamic_log, log_row_t* single_entry_log,
                    size_t* log_count, size_t*  total_alloc_size_log,
                        unsigned long timestamp, unsigned char protocol, unsigned char action,
                        __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason){
    log_row_t* temp;
    int hit;

 
    if (*log_count == 0){
        (*log_count)++;
        assign_log_row(single_entry_log, timestamp, protocol, action,
                       src_ip, dst_ip, src_port, dst_port, reason, 1);
    }
    else if (*log_count == 1){
        //increments count (of existing log entry) if hit
        hit = check_if_hit(single_entry_log, *log_count, src_ip, dst_ip, src_port, dst_port, protocol); 
        if (hit){
            return 0;
        }
        *dynamic_log = kmalloc(2 * 2 * sizeof(log_row_t), GFP_ATOMIC); 
        if (dynamic_log == NULL){
            return -EINVAL;
        }
        *total_alloc_size_log = 4;
        assign_log_row((*dynamic_log), single_entry_log->timestamp, single_entry_log->protocol, single_entry_log->action,  single_entry_log->src_ip, single_entry_log->dst_ip, single_entry_log->src_port, single_entry_log->dst_port, single_entry_log->reason, single_entry_log->count);
        
        (*log_count)++;
        assign_log_row((*dynamic_log) + 1, timestamp, protocol, action,
                       src_ip, dst_ip, src_port, dst_port, reason, 1);
        return 0;
    }
    else {
        hit = check_if_hit(*dynamic_log, *log_count, src_ip, dst_ip, src_port, dst_port, protocol);
        if (hit) {
            return 0;
        }
        
        // Allocate  x2 size of current size
        (*log_count)++;
        if (*log_count == *total_alloc_size_log){
            *total_alloc_size_log = (*log_count) * 2 ; // twice the size
            temp = krealloc(*dynamic_log, *total_alloc_size_log * sizeof(log_row_t) , GFP_ATOMIC);
            if (temp == NULL){
                printk(KERN_INFO "Error: krealloc failed in write_to_log\n");
                kfree(*dynamic_log);
                *dynamic_log = NULL;
                *log_count = 0;
                *total_alloc_size_log = 0;
                return -EINVAL;
            }
            *dynamic_log = temp;
        }
        
        assign_log_row((*dynamic_log) + (*log_count) - 1, timestamp, protocol, action,
                       src_ip, dst_ip, src_port, dst_port, reason, 1);
        return 0;
    }
    return 0;
}

/*
* Gets a five tuple and checks if a rule already exists. Increments count if hit
*/
int check_if_hit(log_row_t* log_rows, size_t log_count, __be32 src_ip, __be32 dst_ip, __be16 src_port,                              __be16 dst_port, unsigned char protocol){
    int i;
    struct timespec ts;
    
    for (i = 0; i < log_count; i ++){
        if ((log_rows+i)->src_ip == src_ip && (log_rows+i)->dst_ip == dst_ip && // check for five tuple match
            (log_rows+i)->src_port == src_port && (log_rows+i)->dst_port == dst_port &&
                    (log_rows+i)->protocol == protocol){
            getnstimeofday(&ts);
            ((log_rows+i)->count)++;
            ((log_rows+i)->timestamp) = ts.tv_sec;
            return 1;
        } 
    }
    return 0;
}

/*
* Assign values in a row in the log
*/
void assign_log_row(log_row_t* log, unsigned long timestamp, unsigned char protocol,                                  unsigned char action, __be32 src_ip,
                           __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason, unsigned int count){
    
    log->timestamp = timestamp;
    log->protocol = protocol;
    log->action = action;
    log->src_ip = src_ip;
    log->dst_ip = dst_ip;
    log->src_port = src_port;
    log->dst_port = dst_port;
    log->reason = reason;
    log->count = count;   
}